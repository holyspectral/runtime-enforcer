package main

import "github.com/spf13/cobra"

func newProposalCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "proposal",
		Short: "Manage WorkloadPolicyProposal",
	}

	cmd.SetUsageTemplate(groupUsageTemplate)

	cmd.AddCommand(newProposalPromoteCmd())

	return cmd
}
