package cmd

import (
	"bytes"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// renderHelp writes the cobra help for the given command into a buffer.
// Help rendering mutates the command's output writer, so these tests are
// intentionally not parallel.
func renderHelp(t *testing.T, command *cobra.Command) string {
	t.Helper()
	var help bytes.Buffer
	command.SetOut(&help)
	t.Cleanup(func() { command.SetOut(nil) })
	if err := command.Help(); err != nil {
		t.Fatalf("render %s help: %v", command.Name(), err)
	}
	return help.String()
}

func TestRootHelpAdvertisesCommandsAndErrorFormat(t *testing.T) {
	output := renderHelp(t, rootCmd)

	for _, expected := range []string{
		"Inspect cloud organization policies from one CLI",
		"aws",
		"version",
		"Show AWS paths and localized SCP attachments for OUs and accounts",
		"Print binary and JSON schema versions",
		"--error-format human|json",
		`"human" or "json"`,
		"(default human)",
	} {
		if !strings.Contains(output, expected) {
			t.Errorf("root help missing %q:\n%s", expected, output)
		}
	}
	for _, hidden := range []string{"gcp", "toggle"} {
		if strings.Contains(output, hidden) {
			t.Errorf("root help unexpectedly advertises %q:\n%s", hidden, output)
		}
	}
}

func TestAWSHelpDocumentsOutputFormatMetavarAndDefault(t *testing.T) {
	output := renderHelp(t, awsCmd)

	for _, expected := range []string{
		"JSON output is used by default",
		"Inspect AWS authentication",
		"Find AWS accounts and OUs by exact name",
		"--output-format text|json",
		`"json" or "text"`,
		"(default json)",
		"--timeout",
		"--max-retries",
		"policy-scout aws --account-id 123456789012",
		"policy-scout aws --ou-id ou-abcd-12345678",
	} {
		if !strings.Contains(output, expected) {
			t.Errorf("aws help missing %q:\n%s", expected, output)
		}
	}
}

func TestAWSAuthStatusHelpDocumentsOutputFormat(t *testing.T) {
	output := renderHelp(t, authStatusCmd)

	for _, expected := range []string{
		"Resolve credentials from the AWS SDK default credential chain",
		"--output-format text|json",
		`"json" or "text"`,
		"(default json)",
		"policy-scout aws auth status --output-format text",
	} {
		if !strings.Contains(output, expected) {
			t.Errorf("auth status help missing %q:\n%s", expected, output)
		}
	}
}

func TestAWSQueryHelpDocumentsVersionedFocusedContracts(t *testing.T) {
	policiesHelp := renderHelp(t, awsPoliciesCmd)
	for _, expected := range []string{
		"one compact, versioned result",
		"--account-id",
		"--ou-id",
		"--output-format text|json",
		"--timeout",
		"--max-retries",
	} {
		if !strings.Contains(policiesHelp, expected) {
			t.Errorf("policies help missing %q:\n%s", expected, policiesHelp)
		}
	}

	attachmentsHelp := renderHelp(t, awsAttachmentsCmd)
	for _, expected := range []string{
		"one compact, versioned result",
		"--policy-id",
		"Management accounts can appear as",
		"never as affected targets",
		"--output-format text|json",
	} {
		if !strings.Contains(attachmentsHelp, expected) {
			t.Errorf("attachments help missing %q:\n%s", expected, attachmentsHelp)
		}
	}
}

func TestVersionHelpDocumentsOutputFormat(t *testing.T) {
	output := renderHelp(t, versionCmd)

	for _, expected := range []string{
		"Print binary and JSON schema versions",
		"--output-format text|json",
		`"json" or "text"`,
		"(default text)",
	} {
		if !strings.Contains(output, expected) {
			t.Errorf("version help missing %q:\n%s", expected, output)
		}
	}
}

func TestOutputFormatCompletionDescribesJSONAndTextBased(t *testing.T) {
	t.Parallel()

	completions, directive := outputFormatCompletion(nil, nil, "")
	if directive != cobra.ShellCompDirectiveDefault {
		t.Fatalf("got directive %v, want %v", directive, cobra.ShellCompDirectiveDefault)
	}
	joined := strings.Join(completions, "\n")
	for _, expected := range []string{
		"json\t",
		"text\t",
		"formatted as JSON",
		"text-based tree",
	} {
		if !strings.Contains(joined, expected) {
			t.Errorf("output format completion missing %q: %q", expected, joined)
		}
	}
	if strings.Contains(joined, "text based") {
		t.Errorf("output format completion uses unhyphenated \"text based\": %q", joined)
	}
	if strings.Contains(strings.ToLower(joined), "in json") {
		t.Errorf("output format completion uses lowercase \"in json\": %q", joined)
	}
}
