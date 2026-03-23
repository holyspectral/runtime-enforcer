package main

import (
	"github.com/spf13/cobra"
	cmdutil "k8s.io/kubectl/pkg/cmd/util"
)

func newProposalCmd(f cmdutil.Factory) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "proposal",
		Short: "Manage WorkloadPolicyProposal",
	}

	cmd.SetUsageTemplate(groupUsageTemplate)

	cmd.AddCommand(newProposalPromoteCmd(f))

	return cmd
}
