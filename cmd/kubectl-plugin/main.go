package main

import (
	"os"

	"github.com/spf13/cobra"
	"k8s.io/cli-runtime/pkg/genericclioptions"
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

	opts := newCommonOptions()

	configFlags := genericclioptions.NewConfigFlags(true).WithWarningPrinter(opts.ioStreams)
	configFlags.AddFlags(cmd.PersistentFlags())

	f := cmdutil.NewFactory(configFlags)

	utilcomp.SetFactoryForCompletion(f)

	cmd.AddCommand(newProposalCmd(f))
	cmd.AddCommand(newPolicyCmd(f))

	return cmd
}

func main() {
	cmd := newRootCmd()
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
