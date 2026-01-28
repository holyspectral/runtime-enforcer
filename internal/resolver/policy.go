package resolver

import (
	"fmt"

	"github.com/rancher-sandbox/runtime-enforcer/api/v1alpha1"
	"github.com/rancher-sandbox/runtime-enforcer/internal/bpf"
	"github.com/rancher-sandbox/runtime-enforcer/internal/types/policymode"
	"k8s.io/client-go/tools/cache"
)

type PolicyID = uint64
type policyByContainer = map[ContainerName]PolicyID
type namespacedPolicyName = string

const (
	// PolicyIDNone is used to indicate no policy associated with the cgroup.
	PolicyIDNone PolicyID = 0
)

// this must be called with the resolver lock held.
func (r *Resolver) allocPolicyID() PolicyID {
	id := r.nextPolicyID
	r.nextPolicyID++
	return id
}

// this must be called with the resolver lock held.
func (r *Resolver) applyPolicyToPod(state *podState, polByContainer policyByContainer) error {
	for _, container := range state.containers {
		polID, ok := polByContainer[container.name]
		if !ok {
			r.logger.Info("container unprotected",
				"namespace", state.podNamespace(),
				"pod name", state.podName(),
				"policy", state.policyLabel(),
				"container", container.name)
			continue
		}
		if err := r.cgroupToPolicyMapUpdateFunc(polID, []CgroupID{container.cgID}, bpf.AddPolicyToCgroups); err != nil {
			return fmt.Errorf("failed to update cgroup to policy map for pod %s, container %s, policy %s: %w",
				state.podName(), container.name, state.policyLabel(), err)
		}
	}
	return nil
}

// this must be called with the resolver lock held.
func (r *Resolver) applyPolicyToPodIfPresent(state *podState) error {
	policyName := state.policyLabel()

	// if the policy doesn't have the label we do nothing
	if policyName == "" {
		return nil
	}

	key := fmt.Sprintf("%s/%s", state.podNamespace(), policyName)
	pol, ok := r.wpState[key]
	if !ok {
		return fmt.Errorf(
			"pod has policy label but policy does not exist. pod-name: %s, pod-namespace: %s, policy-name: %s",
			state.podName(),
			state.podNamespace(),
			policyName,
		)
	}

	return r.applyPolicyToPod(state, pol)
}

// handleWPAdd adds a new workload policy into the resolver cache and applies the policies to all running pods that require it.
func (r *Resolver) handleWPAdd(wp *v1alpha1.WorkloadPolicy) error {
	r.logger.Info(
		"add-wp-policy",
		"name", wp.Name,
		"namespace", wp.Namespace,
	)
	r.mu.Lock()
	defer r.mu.Unlock()

	wpKey := wp.NamespacedName()
	if _, exists := r.wpState[wpKey]; exists {
		return fmt.Errorf("workload policy already exists in internal state: %s", wpKey)
	}

	r.wpState[wpKey] = make(policyByContainer, len(wp.Spec.RulesByContainer))

	for containerName, containerRules := range wp.Spec.RulesByContainer {
		polID := r.allocPolicyID()
		r.logger.Info("create policy", "id", polID,
			"wp", wpKey,
			"container", containerName)

		// Populate policy values
		if err := r.policyUpdateBinariesFunc(polID, containerRules.Executables.Allowed, bpf.AddValuesToPolicy); err != nil {
			return fmt.Errorf("failed to populate policy values for wp %s, container %s: %w", wpKey, containerName, err)
		}

		// Set policy mode
		mode := policymode.ParseMode(wp.Spec.Mode)
		if err := r.policyModeUpdateFunc(polID, mode, bpf.UpdateMode); err != nil {
			return fmt.Errorf("failed to set policy mode '%s' for wp %s, container %s: %w",
				mode.String(), wpKey, containerName, err)
		}

		// update the map with the policy ID
		r.wpState[wpKey][containerName] = polID
	}

	wpMap := r.wpState[wpKey]
	// Now we search for pods that match the policy
	for _, podState := range r.podCache {
		if !podState.matchPolicy(wp.Name) {
			continue
		}

		if err := r.applyPolicyToPod(podState, wpMap); err != nil {
			return err
		}
	}
	return nil
}

// getCgroupIDsForContainer returns all cgroup IDs for a specific container name
// across all pods that match the given policy name.
// This must be called with the resolver lock held.
func (r *Resolver) getCgroupIDsForContainer(policyName string, containerName ContainerName) []CgroupID {
	var cgroupIDs []CgroupID
	for _, podState := range r.podCache {
		if !podState.matchPolicy(policyName) {
			continue
		}
		for _, container := range podState.containers {
			if container.name == containerName {
				cgroupIDs = append(cgroupIDs, container.cgID)
			}
		}
	}
	return cgroupIDs
}

// handleContainerAddition handles adding a new container to an existing WorkloadPolicy.
// This must be called with the resolver lock held.
func (r *Resolver) handleContainerAddition(
	wpKey string,
	containerName ContainerName,
	newRules *v1alpha1.WorkloadPolicyRules,
	newWp *v1alpha1.WorkloadPolicy,
	state policyByContainer,
) error {
	r.logger.Info(
		"container added to policy",
		"container", containerName,
		"wp", wpKey,
	)

	polID := r.allocPolicyID()
	r.logger.Info("create policy for new container", "id", polID,
		"wp", wpKey,
		"container", containerName)

	if err := r.policyUpdateBinariesFunc(polID, newRules.Executables.Allowed, bpf.AddValuesToPolicy); err != nil {
		return fmt.Errorf("failed to populate policy values for wp %s, container %s: %w", wpKey, containerName, err)
	}

	mode := policymode.ParseMode(newWp.Spec.Mode)
	if err := r.policyModeUpdateFunc(polID, mode, bpf.UpdateMode); err != nil {
		return fmt.Errorf("failed to set policy mode '%s' for wp %s, container %s: %w",
			mode.String(), wpKey, containerName, err)
	}

	state[containerName] = polID

	wpMap := r.wpState[wpKey]
	for _, podState := range r.podCache {
		if !podState.matchPolicy(newWp.Name) {
			continue
		}
		if err := r.applyPolicyToPod(podState, wpMap); err != nil {
			return err
		}
	}

	return nil
}

// handleContainerRemoval handles removing a container from an existing WorkloadPolicy.
// This must be called with the resolver lock held.
func (r *Resolver) handleContainerRemoval(
	wpKey string,
	containerName ContainerName,
	policyID PolicyID,
	newWp *v1alpha1.WorkloadPolicy,
	state policyByContainer,
) error {
	r.logger.Info(
		"container removed from policy",
		"container", containerName,
		"wp", wpKey,
		"policyID", policyID,
	)

	cgroupIDs := r.getCgroupIDsForContainer(newWp.Name, containerName)

	if len(cgroupIDs) > 0 {
		if err := r.cgroupToPolicyMapUpdateFunc(PolicyIDNone, cgroupIDs, bpf.RemoveCgroups); err != nil {
			return fmt.Errorf("failed to remove cgroups for wp %s, container %s: %w",
				wpKey, containerName, err)
		}
	}

	if err := r.policyUpdateBinariesFunc(policyID, []string{}, bpf.RemoveValuesFromPolicy); err != nil {
		return fmt.Errorf("failed to remove policy values for wp %s, container %s: %w", wpKey, containerName, err)
	}

	if err := r.policyModeUpdateFunc(policyID, 0, bpf.DeleteMode); err != nil {
		return fmt.Errorf("failed to remove policy from policy mode map for wp %s, container %s: %w",
			wpKey, containerName, err)
	}

	delete(state, containerName)
	return nil
}

// updateExistingContainersExecutables updates the executable list for existing containers.
// This must be called with the resolver lock held.
func (r *Resolver) updateExistingContainersExecutables(
	wpKey string,
	oldWp, newWp *v1alpha1.WorkloadPolicy,
	state policyByContainer,
) error {
	for containerName, policyID := range state {
		oldRules := oldWp.Spec.RulesByContainer[containerName]
		newRules := newWp.Spec.RulesByContainer[containerName]

		// Skip if container doesn't exist in both (handle only existing containers)
		if oldRules == nil || newRules == nil {
			r.logger.Info(
				"non existing container, skipping",
				"container", containerName,
				"wp", wpKey,
			)
			continue
		}

		r.logger.Info(
			"setting executable list",
			"container", containerName,
			"wp", wpKey,
			"old-count", len(oldRules.Executables.Allowed),
			"new-count", len(newRules.Executables.Allowed),
		)

		// Atomically replace values in BPF maps
		if err := r.policyUpdateBinariesFunc(policyID, newRules.Executables.Allowed, bpf.ReplaceValuesInPolicy); err != nil {
			return fmt.Errorf("failed to replace policy values for wp %s, container %s: %w",
				wpKey, containerName, err)
		}
	}
	return nil
}

// handleWPUpdate listen for changes in the executable list and policy mode and applies them to the BPF maps.
// It also handles container additions and removals from the WorkloadPolicy.
func (r *Resolver) handleWPUpdate(oldWp, newWp *v1alpha1.WorkloadPolicy) error {
	r.logger.Info(
		"update-wp-policy",
		"name", newWp.Name,
		"namespace", newWp.Namespace,
	)
	r.mu.Lock()
	defer r.mu.Unlock()

	var exists bool
	var state policyByContainer
	wpKey := newWp.NamespacedName()
	state, exists = r.wpState[wpKey]
	if !exists {
		return fmt.Errorf("workload policy does not exist in internal state: %s", wpKey)
	}

	// Detect containers that were added (exist in newWp but not in oldWp)
	for containerName, newRules := range newWp.Spec.RulesByContainer {
		oldRules := oldWp.Spec.RulesByContainer[containerName]
		if oldRules == nil {
			if err := r.handleContainerAddition(wpKey, containerName, newRules, newWp, state); err != nil {
				return err
			}
		}
	}

	// Detect containers that were removed (exist in oldWp but not in newWp)
	for containerName, policyID := range state {
		if _, exists = newWp.Spec.RulesByContainer[containerName]; !exists {
			if err := r.handleContainerRemoval(wpKey, containerName, policyID, newWp, state); err != nil {
				return err
			}
		}
	}

	if err := r.updateExistingContainersExecutables(wpKey, oldWp, newWp, state); err != nil {
		return err
	}

	r.logger.Info(
		"setting policy mode",
		"old-mode", oldWp.Spec.Mode,
		"new-mode", newWp.Spec.Mode,
		"wp", newWp.Name,
	)

	mode := policymode.ParseMode(newWp.Spec.Mode)

	for containerName, policyID := range state {
		if err := r.policyModeUpdateFunc(policyID, mode, bpf.UpdateMode); err != nil {
			return fmt.Errorf("failed to set policy mode '%s' for wp %s, container %s: %w",
				mode.String(), newWp.Name, containerName, err)
		}
	}

	return nil
}

// handleWPDelete removes a workload policy from the resolver cache and updates the BPF maps accordingly.
func (r *Resolver) handleWPDelete(wp *v1alpha1.WorkloadPolicy) error {
	r.logger.Info(
		"delete-wp-policy",
		"name", wp.Name,
		"namespace", wp.Namespace,
	)
	r.mu.Lock()
	defer r.mu.Unlock()

	wpKey := wp.NamespacedName()
	state, exists := r.wpState[wpKey]
	if !exists {
		return fmt.Errorf("workload policy does not exist in internal state: %s", wpKey)
	}
	delete(r.wpState, wpKey)

	for containerName, policyID := range state {
		// First we remove the association cgroupID -> PolicyID and then we will remove the policy values and modes

		// iteration + deletion on the ebpf map
		if err := r.cgroupToPolicyMapUpdateFunc(policyID, []CgroupID{}, bpf.RemovePolicy); err != nil {
			return fmt.Errorf("failed to remove policy from cgroup map: %w", err)
		}

		if err := r.policyUpdateBinariesFunc(policyID, []string{}, bpf.RemoveValuesFromPolicy); err != nil {
			return fmt.Errorf("failed to remove policy values for wp %s, container %s: %w", wpKey, containerName, err)
		}

		if err := r.policyModeUpdateFunc(policyID, 0, bpf.DeleteMode); err != nil {
			return fmt.Errorf("failed to remove policy from policy mode map for wp %s, container %s: %w",
				wpKey, containerName, err)
		}
	}
	return nil
}

func resourceCheck(method string, obj interface{}) *v1alpha1.WorkloadPolicy {
	wp, ok := obj.(*v1alpha1.WorkloadPolicy)
	if !ok {
		panic(fmt.Sprintf("unexpected object type: method=%s, object=%v", method, obj))
	}
	return wp
}

func (r *Resolver) PolicyEventHandlers() cache.ResourceEventHandler {
	return cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			wp := resourceCheck("add-policy", obj)
			if wp == nil {
				return
			}
			if err := r.handleWPAdd(wp); err != nil {
				// todo!: we need to populate an internal status to report the failure to the user
				r.logger.Error("failed to add policy", "error", err)
				return
			}
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			newWp := resourceCheck("update-policy", newObj)
			if newWp == nil {
				return
			}
			oldWp := resourceCheck("update-policy", oldObj)
			if oldWp == nil {
				return
			}
			if err := r.handleWPUpdate(oldWp, newWp); err != nil {
				r.logger.Error("failed to update policy", "error", err)
				return
			}
		},
		DeleteFunc: func(obj interface{}) {
			wp := resourceCheck("delete-policy", obj)
			if wp == nil {
				return
			}
			if err := r.handleWPDelete(wp); err != nil {
				r.logger.Error("failed to delete policy", "error", err)
				return
			}
		},
	}
}

// ListPolicies returns a list of all workload policies info.
func (r *Resolver) ListPolicies() []string {
	r.mu.Lock()
	defer r.mu.Unlock()

	// todo!: in the future we should also provide the status of the policy not just the name
	policiesNames := make([]string, 0, len(r.wpState))
	for name := range r.wpState {
		policiesNames = append(policiesNames, name)
	}
	return policiesNames
}
