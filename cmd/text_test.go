package cmd

import (
	"bytes"
	encodingjson "encoding/json"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/credentials/ssocreds"
)

func TestDisplayTextEscapesTerminalControls(t *testing.T) {
	t.Parallel()

	input := "nul\x00 bell\a backspace\b tab\t newline\n vertical\v form\f return\r esc\x1b del\x7f c1\u0080 csi\u009b ansi\x1b[31m osc\x1b]0;title\a quote\" slash\\ Unicode café 東京 🙂"
	want := "nul\\x00 bell\\a backspace\\b tab\\t newline\\n vertical\\v form\\f return\\r esc\\x1b del\\x7f c1\\u0080 csi\\u009b ansi\\x1b[31m osc\\x1b]0;title\\a quote\" slash\\ Unicode café 東京 🙂"
	if got := displayText(input); got != want {
		t.Fatalf("displayText() = %q, want %q", got, want)
	}

	var controls strings.Builder
	for character := rune(0); character <= '\x1f'; character++ {
		controls.WriteRune(character)
	}
	for character := rune('\x7f'); character <= '\u009f'; character++ {
		controls.WriteRune(character)
	}
	assertNoDisplayControls(t, displayText(controls.String()))
}

func TestOrganizationTextEscapesValuesWithoutChangingStructuredOutput(t *testing.T) {
	t.Parallel()

	name := "Finance\n\x1b[31m\u009bred\" 東京"
	policyName := "Deny\t\x1b]0;owned\a"
	root := organizationNode{
		SchemaVersion: organizationJSONSchemaVersion,
		Selection:     organizationSelection{Type: allSelectionType},
		Type:          rootEntityType,
		ID:            "r-root",
		Name:          name,
		Children: []organizationNode{{
			Type: organizationalUnitEntityType,
			ID:   "ou-root-12345678",
			Name: name,
			SCPAttachments: []scpAttachment{{
				PolicyID: "p-12345678", PolicyName: policyName,
				AttachedTo: scpAttachmentTarget{Type: rootEntityType, ID: "r-root", Name: name},
				Inherited:  true,
			}},
		}},
	}

	textOutput := renderOrganizationTreeText(root)
	for _, escaped := range []string{displayText(name), displayText(policyName)} {
		if !strings.Contains(textOutput, escaped) {
			t.Fatalf("text output %q does not contain escaped value %q", textOutput, escaped)
		}
	}
	assertNoDisplayControls(t, textOutput)

	jsonOutput, err := renderOrganizationTreeJSON(root)
	if err != nil {
		t.Fatalf("render JSON: %v", err)
	}
	var decoded organizationJSONNode
	if err := encodingjson.Unmarshal(jsonOutput, &decoded); err != nil {
		t.Fatalf("decode JSON: %v", err)
	}
	if decoded.Name != name || len(*decoded.Children) != 1 || (*decoded.Children)[0].Name != name {
		t.Fatalf("JSON values changed: %#v", decoded)
	}
	if htmlOutput := string(renderOrganizationTreeHTML(root)); !strings.Contains(htmlOutput, escapeHTML(name)) {
		t.Fatalf("HTML rendering no longer preserves its existing value handling: %q", htmlOutput)
	}
}

func TestOrganizationSearchTextEscapesValuesAndJSONPreservesThem(t *testing.T) {
	t.Parallel()

	value := "prod\r\n\x1b[2J\x1b]0;owned\a\u009b31m\" 東京"
	result := organizationSearchResult{
		SchemaVersion: awsSearchJSONSchemaVersion,
		Query:         organizationSearchQuery{Name: value},
		Matches: []organizationSearchMatch{{
			Type: accountEntityType, ID: "123456789012", Name: value,
			Path: []organizationSearchPathEntity{{Type: rootEntityType, ID: "r-root", Name: value}},
		}},
	}

	textOutput, err := renderOrganizationSearch(result, text)
	if err != nil {
		t.Fatalf("render text: %v", err)
	}
	if count := strings.Count(string(textOutput), displayText(value)); count != 3 {
		t.Fatalf("escaped value appears %d times, want 3: %q", count, textOutput)
	}
	assertNoDisplayControls(t, string(textOutput))

	jsonOutput, err := renderOrganizationSearch(result, json)
	if err != nil {
		t.Fatalf("render JSON: %v", err)
	}
	var decoded organizationSearchResult
	if err := encodingjson.Unmarshal(jsonOutput, &decoded); err != nil {
		t.Fatalf("decode JSON: %v", err)
	}
	if decoded.Query.Name != value || decoded.Matches[0].Name != value {
		t.Fatalf("JSON values changed: %#v", decoded)
	}
}

func TestAuthStatusAndDiagnosticsEscapeOnlyHumanOutput(t *testing.T) {
	t.Parallel()

	value := "AWS\tvalue\r\n\x1b[31m\x1b]0;owned\a\u009b31m\x7f\" 東京"
	status := awsAuthStatus{
		OK: true, Authenticated: true,
		Identity:      awsAuthIdentity{AccountID: value, ARN: value},
		Credentials:   awsAuthCredentials{Source: value, CanExpire: true, ExpiresAt: value},
		Organizations: awsOrganizationsAuthStatus{Accessible: true, OrganizationID: value, ManagementAccountID: value},
	}
	var humanStatus bytes.Buffer
	if err := writeAWSAuthStatus(&humanStatus, status, text); err != nil {
		t.Fatalf("write text status: %v", err)
	}
	assertNoDisplayControls(t, humanStatus.String())
	if !strings.Contains(humanStatus.String(), displayText(value)) {
		t.Fatalf("text status lacks escaped value: %q", humanStatus.String())
	}

	var jsonStatus bytes.Buffer
	if err := writeAWSAuthStatus(&jsonStatus, status, json); err != nil {
		t.Fatalf("write JSON status: %v", err)
	}
	var decodedStatus awsAuthStatus
	if err := encodingjson.Unmarshal(jsonStatus.Bytes(), &decodedStatus); err != nil {
		t.Fatalf("decode JSON status: %v", err)
	}
	if decodedStatus.Identity.ARN != value || decodedStatus.Credentials.Source != value {
		t.Fatalf("JSON status values changed: %#v", decodedStatus)
	}

	diagnostic := classifiedError{Code: value, Message: value, Operation: value, RequestID: value, Remediation: value}
	var humanError bytes.Buffer
	if err := writeError(&humanError, diagnostic, errorFormatHuman); err != nil {
		t.Fatalf("write human diagnostic: %v", err)
	}
	assertNoDisplayControls(t, humanError.String())

	var jsonError bytes.Buffer
	if err := writeError(&jsonError, diagnostic, errorFormatJSON); err != nil {
		t.Fatalf("write JSON diagnostic: %v", err)
	}
	var decodedError classifiedError
	if err := encodingjson.Unmarshal(jsonError.Bytes(), &decodedError); err != nil {
		t.Fatalf("decode JSON diagnostic: %v", err)
	}
	if decodedError.Code != value || decodedError.Message != value || decodedError.RequestID != value {
		t.Fatalf("JSON diagnostic values changed: %#v", decodedError)
	}
}

func TestHumanSSORemediationPreservesShellQuoting(t *testing.T) {
	t.Parallel()

	profile := "dev'$(printf INJECTED)'team\\profile"
	diagnostic := classifyError(addSSORemediation(
		newCredentialsError("RetrieveCredentials", &ssocreds.InvalidTokenError{}),
		profile,
	))
	var output bytes.Buffer
	if err := writeError(&output, diagnostic, errorFormatHuman); err != nil {
		t.Fatalf("write human SSO diagnostic: %v", err)
	}

	wantCommand := "aws sso login --profile=" + shellQuote(profile)
	if !strings.Contains(output.String(), wantCommand) {
		t.Fatalf("human remediation changed shell quoting:\n%s\nwant command:\n%s", output.String(), wantCommand)
	}
	assertNoDisplayControls(t, output.String())
}

func TestAWSQueryTextEscapesValuesAndJSONPreservesThem(t *testing.T) {
	t.Parallel()

	value := "AWS\n\x1b[31m\x1b]0;owned\a\u009b31m\" 東京"
	policies := policiesQueryResult{
		Target:   queryTarget{Type: accountEntityType, ID: "123456789012", Name: value, SCPApplicable: true},
		Path:     []scpAttachmentTarget{{Type: rootEntityType, ID: "r-root", Name: value}},
		Policies: []scpAttachment{{PolicyID: "p-12345678", PolicyName: value}},
	}
	var policiesText bytes.Buffer
	if err := writePoliciesQuery(&policiesText, policies, text); err != nil {
		t.Fatalf("write policies text: %v", err)
	}
	assertNoDisplayControls(t, policiesText.String())

	attachments := attachmentsQueryResult{
		PolicyID: "p-12345678", PolicyName: value,
		DirectTargets:   []queryTarget{{Type: accountEntityType, ID: "123456789012", Name: value}},
		AffectedTargets: []affectedTarget{{Target: queryTarget{Type: accountEntityType, ID: "123456789012", Name: value}}},
	}
	var attachmentsText bytes.Buffer
	if err := writeAttachmentsQuery(&attachmentsText, attachments, text); err != nil {
		t.Fatalf("write attachments text: %v", err)
	}
	assertNoDisplayControls(t, attachmentsText.String())

	var attachmentsJSON bytes.Buffer
	if err := writeAttachmentsQuery(&attachmentsJSON, attachments, json); err != nil {
		t.Fatalf("write attachments JSON: %v", err)
	}
	var decoded attachmentsQueryResult
	if err := encodingjson.Unmarshal(attachmentsJSON.Bytes(), &decoded); err != nil {
		t.Fatalf("decode attachments JSON: %v", err)
	}
	if decoded.PolicyName != value || decoded.DirectTargets[0].Name != value {
		t.Fatalf("JSON query values changed: %#v", decoded)
	}
}

func assertNoDisplayControls(t *testing.T, output string) {
	t.Helper()
	for _, character := range output {
		if character == '\n' {
			continue
		}
		if character < ' ' || (character >= '\x7f' && character <= '\u009f') {
			t.Fatalf("output contains terminal control U+%04X: %q", character, output)
		}
	}
}
