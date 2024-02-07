/*
Copyright © 2024 Aristides Gonzalez <aristides@glezpol.com>
*/

// Package cmd contains all the commands included in this utility
package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// gcpCmd represents the gcp command.
var gcpCmd = &cobra.Command{
	Use:   "gcp",
	Short: "Entrypoint for all GCP interactions",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("gcp called")
	},
}

func init() {
	rootCmd.AddCommand(gcpCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// gcpCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// gcpCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
