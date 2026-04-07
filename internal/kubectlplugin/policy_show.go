package kubectlplugin

import (
	"github.com/spf13/cobra"
)

func newPolicyShowCmd(deps commonCmdDeps) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "show",
		Short: "Show WorkloadPolicy information",
	}

	cmd.SetUsageTemplate(groupUsageTemplate)

	cmd.AddCommand(newPolicyShowProtectionCmd(deps))

	return cmd
}
