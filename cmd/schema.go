package cmd

import (
	"embed"
	"fmt"
	"io"

	"github.com/spf13/cobra"
)

const (
	authStatusJSONSchemaVersion = "1"
	errorJSONSchemaVersion      = "1"
)

//go:embed schemas/*.json
var schemaFiles embed.FS

var schemaCmd = &cobra.Command{
	Use:   "schema",
	Short: "Print JSON Schemas for machine-readable output",
	Args:  noArgsValidator,
}

func init() {
	rootCmd.AddCommand(schemaCmd)
	addSchemaCommand("organization", "Print the organization result JSON Schema", "schemas/organization-v1.json")
	addSchemaCommand("organization-v2", "Print the organization result v2 JSON Schema", "schemas/organization-v2.json")
	addSchemaCommand("auth-status", "Print the AWS auth-status JSON Schema", "schemas/auth-status-v1.json")
	addSchemaCommand("error", "Print the structured error JSON Schema", "schemas/error-v1.json")
	addSchemaCommand("search", "Print the AWS entity-search result JSON Schema", "schemas/search-v1.json")
	addSchemaCommand("policies", "Print the focused policies-query result JSON Schema", "schemas/policies-v1.json")
	addSchemaCommand("attachments", "Print the focused attachments-query result JSON Schema", "schemas/attachments-v1.json")
	addSchemaCommand("lint", "Print the SCP lint report JSON Schema", "schemas/lint-v1.json")
	addSchemaCommand("administrators", "Print the organization administrators result JSON Schema", "schemas/administrators-v1.json")
	addSchemaCommand("exemptions", "Print the SCP deny-exemptions result JSON Schema", "schemas/exemptions-v1.json")
	addSchemaCommand("coverage", "Print the SCP coverage-report JSON Schema", "schemas/coverage-v1.json")
	addSchemaCommand("changes", "Print the organization control-changes result JSON Schema", "schemas/changes-v1.json")
	addSchemaCommand("region-drift", "Print the Region drift report JSON Schema", "schemas/region-drift-v1.json")
}

func addSchemaCommand(name, short, path string) {
	schemaCmd.AddCommand(&cobra.Command{
		Use:   name,
		Short: short,
		Args:  noArgsValidator,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return writeSchema(cmd.OutOrStdout(), path)
		},
	})
}

func writeSchema(writer io.Writer, path string) error {
	document, err := schemaFiles.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read embedded JSON Schema: %w", err)
	}
	written, err := writer.Write(document)
	if err == nil && written != len(document) {
		err = io.ErrShortWrite
	}
	if err != nil {
		return fmt.Errorf("write JSON Schema: %w", err)
	}
	return nil
}
