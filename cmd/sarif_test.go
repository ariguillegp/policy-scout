package cmd

import (
	"bytes"
	"context"
	encodingjson "encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// compileSARIFSchema compiles the official OASIS SARIF 2.1.0 schema (errata 01),
// stored verbatim in testdata.
func compileSARIFSchema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	document, err := os.ReadFile("testdata/sarif-schema-2.1.0.json")
	if err != nil {
		t.Fatal(err)
	}
	var decoded any
	if err := encodingjson.Unmarshal(document, &decoded); err != nil {
		t.Fatal(err)
	}
	compiler := jsonschema.NewCompiler()
	compiler.AssertFormat()
	if err := compiler.AddResource(sarifSchemaURI, decoded); err != nil {
		t.Fatal(err)
	}
	schema, err := compiler.Compile(sarifSchemaURI)
	if err != nil {
		t.Fatalf("compile SARIF schema: %v", err)
	}
	return schema
}

// decodeValidSARIF validates output against the SARIF schema and the GitHub
// code scanning requirements the schema leaves optional.
func decodeValidSARIF(t *testing.T, schema *jsonschema.Schema, output []byte) sarifLog {
	t.Helper()
	if err := validateJSONDocument(t, schema, output); err != nil {
		t.Fatalf("output is not valid SARIF 2.1.0: %v\n%s", err, output)
	}
	var log sarifLog
	if err := encodingjson.Unmarshal(output, &log); err != nil {
		t.Fatal(err)
	}
	if len(log.Runs) != 1 || !strings.HasSuffix(log.Runs[0].AutomationDetails.ID, "/") {
		t.Fatalf("want one run with an automationDetails category: %+v", log.Runs)
	}
	run := log.Runs[0]
	fingerprints := map[string]bool{}
	for _, result := range run.Results {
		if rule := run.Tool.Driver.Rules[result.RuleIndex]; rule.ID != result.RuleID {
			t.Errorf("result rule %s has ruleIndex of %s", result.RuleID, rule.ID)
		}
		if len(result.Locations) != 1 || result.Locations[0].PhysicalLocation.Region.StartLine != 1 ||
			!strings.HasPrefix(result.Locations[0].PhysicalLocation.ArtifactLocation.URI, sarifURIPrefix+"/r-root/") {
			t.Errorf("result lacks a repository-relative physical location: %+v", result.Locations)
		}
		fingerprint := result.PartialFingerprints["primaryLocationLineHash"]
		if fingerprint == "" || fingerprints[fingerprint] {
			t.Errorf("result fingerprint %q is missing or not unique: %s", fingerprint, result.Message.Text)
		}
		fingerprints[fingerprint] = true
	}
	return log
}

func lintFixtureSARIF(t *testing.T, fixture lintFixture) []byte {
	t.Helper()
	var output bytes.Buffer
	if err := writeLintReport(&output, buildLintFixtureReport(t, fixture), sarif); err != nil {
		t.Fatalf("write SARIF lint report: %v", err)
	}
	return output.Bytes()
}

func TestLintSARIFMapsChecksToRulesAndSeveritiesToLevels(t *testing.T) {
	t.Parallel()
	schema := compileSARIFSchema(t)
	log := decodeValidSARIF(t, schema, lintFixtureSARIF(t, newLintFixture()))
	run := log.Runs[0]

	if len(run.Tool.Driver.Rules) != len(lintChecks) {
		t.Fatalf("rules = %d, want one per check (%d)", len(run.Tool.Driver.Rules), len(lintChecks))
	}
	for index, rule := range run.Tool.Driver.Rules {
		if rule.ID != "aws-lint/"+lintChecks[index] || rule.FullDescription.Text != lintRationales[lintChecks[index]] ||
			rule.ShortDescription.Text == "" || rule.Help.Text == "" {
			t.Errorf("rule %d = %+v", index, rule)
		}
	}
	levels := map[string]string{}
	for _, rule := range run.Tool.Driver.Rules {
		levels[rule.ID] = rule.DefaultConfiguration.Level
	}
	if levels["aws-lint/root_account_full_access_only"] != "error" || levels["aws-lint/allow_not_action"] != "warning" ||
		levels["aws-lint/unattached_policy"] != "note" {
		t.Errorf("rule default levels = %v", levels)
	}

	// The attachment_limit check is medium at the limit and low near it, so
	// the two results of one rule carry different levels.
	type key struct{ rule, level, uri string }
	got := map[key]bool{}
	for _, result := range run.Results {
		got[key{result.RuleID, result.Level, result.Locations[0].PhysicalLocation.ArtifactLocation.URI}] = true
	}
	for _, want := range []key{
		{"aws-lint/attachment_limit", "warning", "aws-organizations/r-root/account/" + lintApp},
		{"aws-lint/attachment_limit", "note", "aws-organizations/r-root/organizational_unit/" + lintProdOU},
		{"aws-lint/root_account_full_access_only", "error", "aws-organizations/r-root/account/" + lintSandbox},
		{"aws-lint/unattached_policy", "note", "aws-organizations/r-root/policy/" + lintUnused},
	} {
		if !got[want] {
			t.Errorf("missing result %+v in %v", want, got)
		}
	}
	if len(run.Results) != 12 {
		t.Errorf("results = %d, want one per finding (12)", len(run.Results))
	}
}

func TestLintSARIFFingerprintsIgnoreNamesAndSeverity(t *testing.T) {
	t.Parallel()
	fingerprints := func(fixture lintFixture) map[string]string {
		var log sarifLog
		if err := encodingjson.Unmarshal(lintFixtureSARIF(t, fixture), &log); err != nil {
			t.Fatal(err)
		}
		byLocation := map[string]string{}
		for _, result := range log.Runs[0].Results {
			location := result.RuleID + " " + result.Locations[0].PhysicalLocation.ArtifactLocation.URI
			byLocation[location] += result.Level + " " + result.PartialFingerprints["primaryLocationLineHash"] + ","
		}
		return byLocation
	}
	before := fingerprints(newLintFixture())

	// Renaming entities and policies and moving App from the attachment limit
	// (medium) to near it (low) must keep every alert's identity.
	renamed := newLintFixture()
	for id := range renamed.names {
		renamed.names[id] += "-renamed"
	}
	for id := range renamed.entityNames {
		renamed.entityNames[id] += "-renamed"
	}
	renamed.direct[lintApp] = []string{fullAWSAccessPolicyID, lintDenyRegions, lintAllowList, lintDenyCopy}
	after := fingerprints(renamed)
	appLimit := "aws-lint/attachment_limit aws-organizations/r-root/account/" + lintApp
	if !strings.HasPrefix(before[appLimit], "warning ") || !strings.HasPrefix(after[appLimit], "note ") {
		t.Fatalf("fixture change did not lower App's severity: %q -> %q", before[appLimit], after[appLimit])
	}
	if len(after) != len(before) {
		t.Fatalf("result locations changed: %v -> %v", before, after)
	}
	for location, results := range before {
		fingerprintsOnly := func(value string) string {
			for _, level := range []string{"error ", "warning ", "note "} {
				value = strings.ReplaceAll(value, level, "")
			}
			return value
		}
		if fingerprintsOnly(after[location]) != fingerprintsOnly(results) {
			t.Errorf("fingerprints for %s changed from %q to %q", location, results, after[location])
		}
	}
}

func TestCoverageSARIFReportsGapsAndKeepsGapExitStatus(t *testing.T) {
	t.Parallel()
	schema := compileSARIFSchema(t)
	query := coverageQuery{Type: coverageQueryTypeAction, Action: "cloudtrail:StopLogging"}

	var output bytes.Buffer
	err := displayCoverageReport(context.Background(), &output, coverageFixtureClient(), query, coverageRootID, "Root", coverageManagement, sarif, true)
	var gapErr *coverageGapError
	if !errors.As(err, &gapErr) || gapErr.uncovered != 1 {
		t.Fatalf("error = %v, want coverageGapError for 1 uncovered account", err)
	}
	log := decodeValidSARIF(t, schema, output.Bytes())
	run := log.Runs[0]
	if run.AutomationDetails.ID != "policy-scout/aws-coverage/r-root/action/cloudtrail:stoplogging/" {
		t.Errorf("category = %q", run.AutomationDetails.ID)
	}
	type key struct{ rule, level, account string }
	var got []key
	for _, result := range run.Results {
		got = append(got, key{result.RuleID, result.Level, result.Locations[0].LogicalLocations[0].Name})
	}
	want := []key{
		{"aws-coverage/uncovered_account", "error", coverageUncovered},
		{"aws-coverage/conditionally_covered_account", "warning", coverageConditional},
	}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("results = %v, want %v (covered and excluded accounts are not findings)", got, want)
	}
	// Condition JSON in the message must not be read as SARIF placeholders.
	if message := run.Results[1].Message.Text; !strings.Contains(message, `Condition {{"ArnNotLike":{{`) {
		t.Errorf("conditional message does not escape braces: %s", message)
	}

	// Action names are case-insensitive, so alert identity ignores casing.
	output.Reset()
	upper := coverageQuery{Type: coverageQueryTypeAction, Action: "CloudTrail:StopLogging"}
	if err := displayCoverageReport(context.Background(), &output, coverageFixtureClient(), upper, coverageRootID, "Root", coverageManagement, sarif, false); err != nil {
		t.Fatal(err)
	}
	upperLog := decodeValidSARIF(t, schema, output.Bytes())
	if upperLog.Runs[0].Results[0].PartialFingerprints["primaryLocationLineHash"] != run.Results[0].PartialFingerprints["primaryLocationLineHash"] ||
		upperLog.Runs[0].AutomationDetails.ID != run.AutomationDetails.ID {
		t.Error("action casing changed the SARIF category or alert fingerprint")
	}

	// A policy query without gaps is an empty, still valid run in its own category.
	output.Reset()
	policyQuery := coverageQuery{Type: coverageQueryTypePolicy, PolicyID: coverageAllowPolicy}
	if err := displayCoverageReport(context.Background(), &output, coverageFixtureClient(), policyQuery, coverageRootID, "Root", coverageManagement, sarif, true); err != nil {
		t.Fatalf("policy coverage without gaps returned %v", err)
	}
	policyLog := decodeValidSARIF(t, schema, output.Bytes())
	if len(policyLog.Runs[0].Results) != 0 ||
		policyLog.Runs[0].AutomationDetails.ID != "policy-scout/aws-coverage/r-root/policy/p-FullAWSAccess/" {
		t.Errorf("policy run = %+v", policyLog.Runs[0])
	}
}
