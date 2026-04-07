package kubectlplugin

import (
	"github.com/spf13/cobra"
)

func newProposalCmd(deps commonCmdDeps) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "proposal",
		Short: "Manage WorkloadPolicyProposal",
	}

	cmd.SetUsageTemplate(groupUsageTemplate)

	cmd.AddCommand(newProposalPromoteCmd(deps))

	return cmd
}
