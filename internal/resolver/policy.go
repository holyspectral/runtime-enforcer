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

// syncWorkloadPolicyFromSpec ensures state and BPF maps match wp.Spec.RulesByContainer:
// allocates a policy ID for new containers, (re)applies binaries and mode for every container in the spec.
// This must be called with the resolver lock held.
func (r *Resolver) syncWorkloadPolicyFromSpec(wp *v1alpha1.WorkloadPolicy, state policyByContainer) error {
	wpKey := wp.NamespacedName()
	mode := policymode.ParseMode(wp.Spec.Mode)

	for containerName, containerRules := range wp.Spec.RulesByContainer {
		polID, ok := state[containerName]
		if !ok {
			polID = r.allocPolicyID()
			state[containerName] = polID
			r.logger.Info("create policy", "id", polID,
				"wp", wpKey,
				"container", containerName)
		}

		// Populate or replace policy values (Add for new policy ID, Replace for existing)
		op := bpf.ReplaceValuesInPolicy
		if !ok {
			op = bpf.AddValuesToPolicy
		}
		if err := r.policyUpdateBinariesFunc(polID, containerRules.Executables.Allowed, op); err != nil {
			return fmt.Errorf("failed to populate policy values for wp %s, container %s: %w", wpKey, containerName, err)
		}

		if err := r.policyModeUpdateFunc(polID, mode, bpf.UpdateMode); err != nil {
			return fmt.Errorf("failed to set policy mode '%s' for wp %s, container %s: %w",
				mode.String(), wpKey, containerName, err)
		}
	}
	return nil
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

	if err := r.syncWorkloadPolicyFromSpec(wp, r.wpState[wpKey]); err != nil {
		return err
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

// handleWPUpdate reinforces the workload policy from the current spec, removes containers
// that are no longer in the spec, then applies policy to all matching pods.
func (r *Resolver) handleWPUpdate(wp *v1alpha1.WorkloadPolicy) error {
	r.logger.Info(
		"update-wp-policy",
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

	// Sync state and BPF from current spec (add new containers, re-apply binaries and mode for all).
	if err := r.syncWorkloadPolicyFromSpec(wp, state); err != nil {
		return err
	}

	// Containers in state but not in the spec need to be removed.
	removedContainers := make(map[ContainerName]struct{}, len(state))
	for containerName := range state {
		removedContainers[containerName] = struct{}{}
	}
	for containerName := range wp.Spec.RulesByContainer {
		delete(removedContainers, containerName)
	}

	// Clean up removed containers: cgroups, policy values, mode, and state.
	for containerName := range removedContainers {
		policyID := state[containerName]
		cgroupIDs := r.getCgroupIDsForContainer(wp.Name, containerName)
		if len(cgroupIDs) > 0 {
			if err := r.cgroupToPolicyMapUpdateFunc(PolicyIDNone, cgroupIDs, bpf.RemoveCgroups); err != nil {
				return fmt.Errorf("failed to remove cgroups for wp %s, container %s: %w", wpKey, containerName, err)
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
	}

	for _, podState := range r.podCache {
		if !podState.matchPolicy(wp.Name) {
			continue
		}
		if err := r.applyPolicyToPod(podState, state); err != nil {
			return err
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
		UpdateFunc: func(_ interface{}, newObj interface{}) {
			wp := resourceCheck("update-policy", newObj)
			if wp == nil {
				return
			}
			if err := r.handleWPUpdate(wp); err != nil {
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
