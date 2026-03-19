package main

import (
	"github.com/spf13/cobra"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	cmdutil "k8s.io/kubectl/pkg/cmd/util"
)

func newPolicyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "policy",
		Short: "Manage WorkloadPolicy",
	}

	cmd.SetUsageTemplate(groupUsageTemplate)

	f := cmdutil.NewFactory(genericclioptions.NewConfigFlags(true))

	cmd.AddCommand(newPolicyModeProtectCmd(f))
	cmd.AddCommand(newPolicyModeMonitorCmd(f))
	cmd.AddCommand(newPolicyExecAllowCmd(f))
	cmd.AddCommand(newPolicyExecDenyCmd(f))

	return cmd
}
