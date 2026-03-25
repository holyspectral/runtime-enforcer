package main

import (
	"os"

	"github.com/spf13/cobra"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/cli-runtime/pkg/genericiooptions"
	_ "k8s.io/client-go/plugin/pkg/client/auth"
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

func newRootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "runtime-enforcer",
		Long:    "Kubernetes plugin for SUSE Security Runtime Enforcer",
		Version: version,
		Args:    cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return cmd.Help()
		},
	}

	cmd.SetUsageTemplate(rootUsageTemplate)

	// Create a shared iostream.
	streams := genericiooptions.IOStreams{In: os.Stdin, Out: os.Stdout, ErrOut: os.Stderr}

	// Add flags to persistent flags so they are inherited by all subcommands
	configFlags := genericclioptions.NewConfigFlags(true).WithWarningPrinter(streams)
	configFlags.AddFlags(cmd.PersistentFlags())

	// Create cmdutil.Factory for use in completion functions
	f := cmdutil.NewFactory(configFlags)
	utilcomp.SetFactoryForCompletion(f)

	// Register completion functions, so we can auto-complete global flags like --namespace, --context, etc.
	registerCompletionFuncForGlobalFlags(cmd, f)

	cmd.AddCommand(newProposalCmd(commonCmdDeps{f: f, ioStreams: streams}))
	cmd.AddCommand(newPolicyCmd(commonCmdDeps{f: f, ioStreams: streams}))

	return cmd
}

func main() {
	cmd := newRootCmd()
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
