package main

import (
	"github.com/spf13/cobra"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	cmdutil "k8s.io/kubectl/pkg/cmd/util"
)

func newProposalCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "proposal",
		Short: "Manage WorkloadPolicyProposal",
	}

	cmd.SetUsageTemplate(groupUsageTemplate)

	f := cmdutil.NewFactory(genericclioptions.NewConfigFlags(true))

	cmd.AddCommand(newProposalPromoteCmd(f))

	return cmd
}
