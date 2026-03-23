package main

import (
	"github.com/spf13/cobra"
	cmdutil "k8s.io/kubectl/pkg/cmd/util"
)

func newPolicyCmd(f cmdutil.Factory) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "policy",
		Short: "Manage WorkloadPolicy",
	}

	cmd.SetUsageTemplate(groupUsageTemplate)

	cmd.AddCommand(newPolicyModeProtectCmd(f))
	cmd.AddCommand(newPolicyModeMonitorCmd(f))
	cmd.AddCommand(newPolicyShowCmd())
	cmd.AddCommand(newPolicyExecAllowCmd(f))
	cmd.AddCommand(newPolicyExecDenyCmd(f))

	return cmd
}
