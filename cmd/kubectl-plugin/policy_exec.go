package main

import (
	"context"
	"fmt"
	"io"
	"slices"
	"strings"

	apiv1alpha1 "github.com/rancher-sandbox/runtime-enforcer/api/v1alpha1"
	securityclient "github.com/rancher-sandbox/runtime-enforcer/pkg/generated/clientset/versioned/typed/api/v1alpha1"
	"github.com/spf13/cobra"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type policyExecAction string

const (
	policyExecActionAllow policyExecAction = "allow"
	policyExecActionDeny  policyExecAction = "deny"

	minPolicyExecArgs = 2
)

type policyExecOptions struct {
	commonOptions

	PolicyName     string
	Executables    []string
	ContainerNames []string
	Action         policyExecAction
}

func newPolicyExecCmd(action policyExecAction) *cobra.Command {
	use := fmt.Sprintf("%s POLICY_NAME <executables>", action)
	short := fmt.Sprintf("%s executables for a WorkloadPolicy", action)

	opts := &policyExecOptions{
		commonOptions: newCommonOptions(),
		Action:        action,
	}

	cmd := &cobra.Command{
		Use:   use,
		Short: short,
		Args:  cobra.MinimumNArgs(minPolicyExecArgs),
		RunE:  runPolicyExecCmd(opts),
	}

	cmd.SetUsageTemplate(subcommandUsageTemplate)

	// Standard kube flags (adds --namespace, --kubeconfig, --context, etc.)
	opts.configFlags.AddFlags(cmd.Flags())

	// Plugin-specific flags
	cmd.Flags().BoolVar(&opts.DryRun, "dry-run", false, "Show what would happen without making any changes")
	cmd.Flags().StringArrayVar(
		&opts.ContainerNames,
		"container",
		nil,
		"Limit updates to these containers (can be repeated or comma-separated)",
	)

	return cmd
}

func newPolicyExecAllowCmd() *cobra.Command {
	return newPolicyExecCmd(policyExecActionAllow)
}

func newPolicyExecDenyCmd() *cobra.Command {
	return newPolicyExecCmd(policyExecActionDeny)
}

func runPolicyExecCmd(opts *policyExecOptions) func(cmd *cobra.Command, args []string) error {
	return func(cmd *cobra.Command, args []string) error {
		opts.PolicyName = args[0]
		opts.Executables = args[1:]

		return withRuntimeEnforcerClient(cmd, &opts.commonOptions, func(
			ctx context.Context,
			securityClient securityclient.SecurityV1alpha1Interface,
		) error {
			return runPolicyExec(ctx, securityClient, opts, opts.ioStreams.Out)
		})
	}
}

func runPolicyExec(
	ctx context.Context,
	client securityclient.SecurityV1alpha1Interface,
	opts *policyExecOptions,
	out io.Writer,
) error {
	policy, err := client.WorkloadPolicies(opts.Namespace).Get(ctx, opts.PolicyName, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			return fmt.Errorf("workloadpolicy %q not found in namespace %q", opts.PolicyName, opts.Namespace)
		}
		return fmt.Errorf(
			"failed to get WorkloadPolicy %q in namespace %q: %w",
			opts.PolicyName,
			opts.Namespace,
			err,
		)
	}

	changed, err := applyExecutablesToPolicy(policy.Spec.RulesByContainer, opts)
	if err != nil {
		return err
	}

	if !changed {
		fmt.Fprintf(
			out,
			"No changes required for WorkloadPolicy %q in namespace %q.\n",
			policy.Name,
			policy.Namespace,
		)
		return nil
	}

	if opts.DryRun {
		fmt.Fprintf(
			out,
			"Would %s executables for WorkloadPolicy %q in namespace %q.\n",
			opts.Action,
			policy.Name,
			policy.Namespace,
		)
		for containerName, rules := range policy.Spec.RulesByContainer {
			fmt.Fprintf(
				out,
				"  Container %q final allowed executables: %v\n",
				containerName,
				rules.Executables.Allowed,
			)
		}
	}

	if err = updateWorkloadPolicy(ctx, client, opts, policy); err != nil {
		return err
	}

	fmt.Fprintf(
		out,
		"Successfully updated executables for WorkloadPolicy %q in namespace %q.\n",
		policy.Name,
		policy.Namespace,
	)

	return nil
}

func applyExecutablesToPolicy(
	rulesByContainer map[string]*apiv1alpha1.WorkloadPolicyRules,
	opts *policyExecOptions,
) (bool, error) {
	if rulesByContainer == nil {
		rulesByContainer = make(map[string]*apiv1alpha1.WorkloadPolicyRules)
	}

	targetContainers, err := parseTargetContainers(rulesByContainer, opts)
	if err != nil {
		return false, err
	}

	changed := false

	for containerName, rules := range rulesByContainer {
		if len(targetContainers) > 0 {
			if !slices.Contains(targetContainers, containerName) {
				continue
			}
		}

		if rules == nil {
			rules = &apiv1alpha1.WorkloadPolicyRules{}
			rulesByContainer[containerName] = rules
		}

		var updated []string
		var containerChanged bool
		switch opts.Action {
		case policyExecActionAllow:
			updated, containerChanged = allowExecutables(rules.Executables.Allowed, opts.Executables)
		case policyExecActionDeny:
			updated, containerChanged = denyExecutables(rules.Executables.Allowed, opts.Executables)
		default:
			return false, fmt.Errorf("unsupported action %q", opts.Action)
		}

		if containerChanged {
			rules.Executables.Allowed = updated
			changed = true
		}
	}

	return changed, nil
}

func parseTargetContainers(
	rulesByContainer map[string]*apiv1alpha1.WorkloadPolicyRules,
	opts *policyExecOptions,
) ([]string, error) {
	if len(opts.ContainerNames) == 0 {
		return nil, nil
	}

	var targetContainers []string

	for _, raw := range opts.ContainerNames {
		for cn := range strings.SplitSeq(raw, ",") {
			name := strings.TrimSpace(cn)
			if name != "" {
				targetContainers = append(targetContainers, name)
			}
		}
	}

	if len(targetContainers) > 0 {
		for _, name := range targetContainers {
			if _, ok := rulesByContainer[name]; !ok {
				return nil, fmt.Errorf("container %q not found in policy", name)
			}
		}
	} else {
		return nil, nil
	}

	return targetContainers, nil
}

func allowExecutables(executables []string, allowed []string) ([]string, bool) {
	changed := false

	for _, exec := range allowed {
		if !slices.Contains(executables, exec) {
			executables = append(executables, exec)
			changed = true
		}
	}

	return executables, changed
}

func denyExecutables(executables []string, denied []string) ([]string, bool) {
	if len(executables) == 0 {
		return executables, false
	}

	newExecutables := make([]string, 0, len(executables))
	changed := false

	for _, exec := range executables {
		if !slices.Contains(denied, exec) {
			newExecutables = append(newExecutables, exec)
		} else {
			changed = true
		}
	}

	return newExecutables, changed
}

func updateWorkloadPolicy(
	ctx context.Context,
	client securityclient.SecurityV1alpha1Interface,
	opts *policyExecOptions,
	policy *apiv1alpha1.WorkloadPolicy,
) error {
	updateOptions := metav1.UpdateOptions{}
	if opts.DryRun {
		updateOptions.DryRun = []string{metav1.DryRunAll}
	}

	if _, err := client.WorkloadPolicies(opts.Namespace).
		Update(ctx, policy, updateOptions); err != nil {
		if apierrors.IsConflict(err) {
			return fmt.Errorf(
				"WorkloadPolicy %q in namespace %q was modified concurrently",
				policy.Name,
				policy.Namespace,
			)
		}
		return fmt.Errorf(
			"failed to update WorkloadPolicy %q in namespace %q: %w",
			policy.Name,
			policy.Namespace,
			err,
		)
	}

	return nil
}
