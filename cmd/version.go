/*
Copyright © 2024 Aristides Gonzalez <aristides@glezpol.com>
*/

package cmd

import (
	encodingjson "encoding/json"
	"fmt"
	"io"

	"github.com/spf13/cobra"
)

var version = "dev"

type versionInfo struct {
	Version                     string   `json:"version"`
	OrganizationSchemaVersion   string   `json:"organization_schema_version"`
	OrganizationSchemaVersions  []string `json:"organization_schema_versions"`
	AuthStatusSchemaVersion     string   `json:"auth_status_schema_version"`
	ErrorSchemaVersion          string   `json:"error_schema_version"`
	SearchSchemaVersion         string   `json:"search_schema_version"`
	PoliciesSchemaVersion       string   `json:"policies_schema_version"`
	AttachmentsSchemaVersion    string   `json:"attachments_schema_version"`
	LintSchemaVersion           string   `json:"lint_schema_version"`
	AdministratorsSchemaVersion string   `json:"administrators_schema_version"`
	ExemptionsSchemaVersion     string   `json:"exemptions_schema_version"`
	CoverageSchemaVersion       string   `json:"coverage_schema_version"`
	ChangesSchemaVersion        string   `json:"changes_schema_version"`
}

var (
	versionFormat outputFormat = text
	versionCmd                 = &cobra.Command{
		Use:   "version",
		Short: "Print binary and JSON schema versions",
		Args:  noArgsValidator,
		RunE: func(cmd *cobra.Command, args []string) error {
			return printVersion(cmd.OutOrStdout(), versionFormat)
		},
	}
)

func init() {
	rootCmd.AddCommand(versionCmd)
	versionCmd.Flags().VarP(&versionFormat, "output-format", "o", `output format: "json" or "text"`)
	if err := versionCmd.RegisterFlagCompletionFunc("output-format", outputFormatCompletion); err != nil {
		panic(err)
	}
}

func printVersion(writer io.Writer, output outputFormat) error {
	info := versionInfo{
		Version:                     version,
		OrganizationSchemaVersion:   organizationJSONSchemaVersion,
		OrganizationSchemaVersions:  []string{organizationJSONSchemaVersion, organizationPolicyDocumentsJSONSchemaVersion},
		AuthStatusSchemaVersion:     authStatusJSONSchemaVersion,
		ErrorSchemaVersion:          errorJSONSchemaVersion,
		SearchSchemaVersion:         awsSearchJSONSchemaVersion,
		PoliciesSchemaVersion:       policiesQuerySchemaVersion,
		AttachmentsSchemaVersion:    attachmentsQuerySchemaVersion,
		LintSchemaVersion:           lintSchemaVersion,
		AdministratorsSchemaVersion: administratorsSchemaVersion,
		ExemptionsSchemaVersion:     exemptionsQuerySchemaVersion,
		CoverageSchemaVersion:       coverageSchemaVersion,
		ChangesSchemaVersion:        changesSchemaVersion,
	}
	if output == json {
		encoder := encodingjson.NewEncoder(writer)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(info); err != nil {
			return fmt.Errorf("encode version as JSON: %w", err)
		}
		return nil
	}

	_, err := fmt.Fprintf(writer, "policy-scout %s\n", info.Version)
	return err
}
