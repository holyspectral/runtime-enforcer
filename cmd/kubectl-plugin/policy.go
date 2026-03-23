package main

import "github.com/spf13/cobra"

func newPolicyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "policy",
		Short: "Manage WorkloadPolicy",
	}

	cmd.SetUsageTemplate(groupUsageTemplate)

	cmd.AddCommand(newPolicyModeProtectCmd())
	cmd.AddCommand(newPolicyModeMonitorCmd())
	cmd.AddCommand(newPolicyShowCmd())
	cmd.AddCommand(newPolicyExecAllowCmd())
	cmd.AddCommand(newPolicyExecDenyCmd())

	return cmd
}
