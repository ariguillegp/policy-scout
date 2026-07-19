/*
Copyright © 2024 Aristides Gonzalez <aristides@glezpol.com>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package cmd contains all the commands in this utility
package cmd

import (
	"context"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
)

// rootCmd represents the base command when called without any subcommands.
var rootCmd = &cobra.Command{
	Use:   "policy-scout",
	Short: "Inspect cloud organization policies from one CLI",
	Example: `  policy-scout aws auth status
  policy-scout aws auth status --output-format text
  policy-scout aws --account-id 123456789012
  policy-scout aws --account-id all --output-format text`,
	SilenceErrors: true,
	SilenceUsage:  true,
	Args:          noArgsValidator,
	RunE: func(cmd *cobra.Command, _ []string) error {
		return cmd.Help()
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() int {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	return executeCommandContext(ctx, rootCmd, os.Args[1:], os.Stdout, os.Stderr)
}

func executeCommand(command *cobra.Command, args []string, stdout, stderr io.Writer) int {
	return executeCommandContext(context.Background(), command, args, stdout, stderr)
}

func executeCommandContext(
	ctx context.Context,
	command *cobra.Command,
	args []string,
	stdout, stderr io.Writer,
) int {
	command.SetArgs(args)
	command.SetOut(stdout)
	command.SetErr(stderr)

	err := command.ExecuteContext(ctx)
	if err == nil {
		return exitSuccess
	}

	diagnostic := classifyError(err)
	if renderErr := writeError(stderr, diagnostic, errorFormatValue); renderErr != nil {
		return diagnostic.ExitCode
	}
	return diagnostic.ExitCode
}
