package kubectlplugin

import (
	"os"

	"github.com/spf13/cobra"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/cli-runtime/pkg/genericiooptions"
	cmdutil "k8s.io/kubectl/pkg/cmd/util"
	utilcomp "k8s.io/kubectl/pkg/util/completion"
)

var version = "dev"

// Custom usage template: no "kubectl [command]" line.
const (
	rootUsageTemplate = `Usage:
  {{.UseLine}}

Available Commands:
{{range .Commands}}{{if (or .IsAvailableCommand (eq .Name "help"))}}  {{rpad .Name .NamePadding}} {{.Short}}
{{end}}{{end}}
Flags:
{{.LocalFlags.FlagUsages | trimTrailingWhitespaces}}
`
)

func registerCompletionFuncForGlobalFlags(cmd *cobra.Command, f cmdutil.Factory) {
	registerFlagCompletion := func(flagName string, completionFunc func(string) []string) {
		cmdutil.CheckErr(cmd.RegisterFlagCompletionFunc(
			flagName,
			func(_ *cobra.Command, _ []string, toComplete string) ([]string, cobra.ShellCompDirective) {
				return completionFunc(toComplete), cobra.ShellCompDirectiveNoFileComp
			}))
	}

	registerFlagCompletion("namespace", func(toComplete string) []string {
		return utilcomp.CompGetResource(f, "namespace", toComplete)
	})
	registerFlagCompletion("context", utilcomp.ListContextsInConfig)
	registerFlagCompletion("cluster", utilcomp.ListClustersInConfig)
	registerFlagCompletion("user", utilcomp.ListUsersInConfig)
}

// NewRootCmd builds the kubectl plugin command tree (runtime-enforcer).
func NewRootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "runtime-enforcer",
		Long:    "Kubernetes plugin for SUSE Security Runtime Enforcer",
		Version: version,
		Args:    cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return cmd.Help()
		},
	}

	cmd.DisableAutoGenTag = true
	cmd.SetUsageTemplate(rootUsageTemplate)

	streams := genericiooptions.IOStreams{In: os.Stdin, Out: os.Stdout, ErrOut: os.Stderr}

	configFlags := genericclioptions.NewConfigFlags(true).WithWarningPrinter(streams)
	configFlags.AddFlags(cmd.PersistentFlags())

	f := cmdutil.NewFactory(configFlags)
	utilcomp.SetFactoryForCompletion(f)

	registerCompletionFuncForGlobalFlags(cmd, f)

	deps := commonCmdDeps{f: f, ioStreams: streams}
	cmd.AddCommand(newProposalCmd(deps))
	cmd.AddCommand(newPolicyCmd(deps))

	return cmd
}
