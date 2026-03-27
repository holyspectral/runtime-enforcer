package main

import (
	"context"
	"fmt"
	"io"
	"slices"

	apiv1alpha1 "github.com/rancher-sandbox/runtime-enforcer/api/v1alpha1"
	securityclient "github.com/rancher-sandbox/runtime-enforcer/pkg/generated/clientset/versioned/typed/api/v1alpha1"
	"github.com/spf13/cobra"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	cmdutil "k8s.io/kubectl/pkg/cmd/util"
	"k8s.io/kubectl/pkg/util/completion"
)

type policyExecAction string

const (
	policyExecActionAllow policyExecAction = "allow"
	policyExecActionDeny  policyExecAction = "deny"

	minPolicyExecArgs = 3
)

type policyExecOptions struct {
	commonOptions

	PolicyName    string
	ContainerName string
	Executables   []string
	Action        policyExecAction
}

func newPolicyExecCmd(deps commonCmdDeps, action policyExecAction) *cobra.Command {
	use := fmt.Sprintf("%s POLICY_NAME <container-name> <executable-name> [<executable-name>...]", action)
	short := fmt.Sprintf("%s executables for a WorkloadPolicy container", action)

	opts := &policyExecOptions{
		commonOptions: newCommonOptions(deps),

		Action: action,
	}

	const (
		positionPolicyName      = 0
		positionContainerName   = 1
		positionFirstExecutable = 2
	)

	cmd := &cobra.Command{
		Use:   use,
		Short: short,
		Args:  cobra.MinimumNArgs(minPolicyExecArgs),
		RunE:  runPolicyExecCmd(opts),
		ValidArgsFunction: func(_ *cobra.Command, args []string, toComplete string) ([]cobra.Completion, cobra.ShellCompDirective) {
			switch {
			case len(args) == positionPolicyName:
				return completion.CompGetResource(
					deps.f,
					"workloadpolicies",
					toComplete,
				), cobra.ShellCompDirectiveNoFileComp
			case len(args) == positionContainerName:
				template := "{{ range $key, $value := .spec.rulesByContainer }}{{ $key }} {{end}}"
				return completion.CompGetFromTemplate(
					&template,
					deps.f,
					"",
					[]string{"workloadpolicies", args[0]},
					toComplete,
				), cobra.ShellCompDirectiveNoFileComp
			case len(args) >= positionFirstExecutable:
				switch action {
				case policyExecActionAllow:
					template := fmt.Sprintf(
						"{{ with .status.violations }}{{ range . }}{{ if eq .containerName \"%s\" }}{{ .executablePath }} {{end}}{{end}}{{end}}",
						args[1],
					)
					execs := completion.CompGetFromTemplate(
						&template,
						deps.f,
						"",
						[]string{"workloadpolicies", args[0]},
						toComplete,
					)
					execs = cmdutil.Difference(execs, args[2:])
					return execs, cobra.ShellCompDirectiveNoFileComp
				case policyExecActionDeny:
					template := fmt.Sprintf(
						"{{ with .spec.rulesByContainer }}{{ with index . \"%s\" }}{{ range $key, $value := .executables.allowed }}{{ $value }} {{end}}{{end}}{{end}}",
						args[1],
					)
					execs := completion.CompGetFromTemplate(
						&template,
						deps.f,
						"",
						[]string{"workloadpolicies", args[0]},
						toComplete,
					)
					execs = cmdutil.Difference(execs, args[2:])
					return execs, cobra.ShellCompDirectiveNoFileComp
				default:
					return nil, cobra.ShellCompDirectiveNoFileComp
				}
			default:
				return nil, cobra.ShellCompDirectiveNoFileComp
			}
		},
	}

	cmd.SetUsageTemplate(subcommandUsageTemplate)

	// Plugin-specific flags
	cmd.Flags().BoolVar(&opts.DryRun, "dry-run", false, "Show what would happen without making any changes")

	return cmd
}

func newPolicyExecAllowCmd(deps commonCmdDeps) *cobra.Command {
	return newPolicyExecCmd(deps, policyExecActionAllow)
}

func newPolicyExecDenyCmd(deps commonCmdDeps) *cobra.Command {
	return newPolicyExecCmd(deps, policyExecActionDeny)
}

func runPolicyExecCmd(opts *policyExecOptions) func(cmd *cobra.Command, args []string) error {
	return func(cmd *cobra.Command, args []string) error {
		opts.PolicyName = args[0]
		opts.ContainerName = args[1]
		opts.Executables = args[2:]

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

		rules := policy.Spec.RulesByContainer[opts.ContainerName]
		fmt.Fprintf(
			out,
			"  Container %q final allowed executables: %v\n",
			opts.ContainerName,
			rules.Executables.Allowed,
		)
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
		return false, fmt.Errorf("policy %q has no rules for containers", opts.PolicyName)
	}

	rules, ok := rulesByContainer[opts.ContainerName]
	if !ok {
		return false, fmt.Errorf("container %q not found in policy", opts.ContainerName)
	}

	if rules == nil {
		rules = &apiv1alpha1.WorkloadPolicyRules{}
		rulesByContainer[opts.ContainerName] = rules
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
	}

	return containerChanged, nil
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
