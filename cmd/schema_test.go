package cmd

import (
	"bytes"
	"context"
	encodingjson "encoding/json"
	"errors"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"github.com/aws/smithy-go"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

const jsonSchemaDraft202012 = "https://json-schema.org/draft/2020-12/schema"

func compilePublishedSchema(t *testing.T, path string) *jsonschema.Schema {
	t.Helper()
	document, err := schemaFiles.ReadFile(path)
	if err != nil {
		t.Fatalf("read schema %s: %v", path, err)
	}
	var decoded any
	if err := encodingjson.Unmarshal(document, &decoded); err != nil {
		t.Fatalf("decode schema %s: %v", path, err)
	}
	compiler := jsonschema.NewCompiler()
	compiler.AssertFormat()
	if err := compiler.AddResource(path, decoded); err != nil {
		t.Fatalf("add schema resource %s: %v", path, err)
	}
	schema, err := compiler.Compile(path)
	if err != nil {
		t.Fatalf("compile schema %s: %v", path, err)
	}
	return schema
}

func validateJSONDocument(t *testing.T, schema *jsonschema.Schema, document []byte) error {
	t.Helper()
	var decoded any
	decoder := encodingjson.NewDecoder(bytes.NewReader(document))
	decoder.UseNumber()
	if err := decoder.Decode(&decoded); err != nil {
		t.Fatalf("decode JSON document %q: %v", document, err)
	}
	return schema.Validate(decoded)
}

func assertValidDocument(t *testing.T, schema *jsonschema.Schema, document string) {
	t.Helper()
	if err := validateJSONDocument(t, schema, []byte(document)); err != nil {
		t.Fatalf("document should satisfy schema: %v\n%s", err, document)
	}
}

func assertInvalidDocument(t *testing.T, schema *jsonschema.Schema, document string) {
	t.Helper()
	if err := validateJSONDocument(t, schema, []byte(document)); err == nil {
		t.Fatalf("document unexpectedly satisfies schema:\n%s", document)
	}
}

// assertFieldsDeclared keeps forward-compatible schemas from silently missing
// newly emitted producer fields: unknown fields remain valid for consumers, but
// every field Policy Scout itself emits must still be documented in properties.
func assertFieldsDeclared(t *testing.T, path, definition string, document []byte) {
	t.Helper()
	schemaDocument, err := schemaFiles.ReadFile(path)
	if err != nil {
		t.Fatalf("read schema %s: %v", path, err)
	}
	var schemaObject map[string]any
	if err := encodingjson.Unmarshal(schemaDocument, &schemaObject); err != nil {
		t.Fatalf("decode schema %s: %v", path, err)
	}
	if definition != "" {
		definitions := schemaObject["$defs"].(map[string]any)
		schemaObject = definitions[definition].(map[string]any)
	}
	properties := schemaObject["properties"].(map[string]any)
	var outputObject map[string]any
	if err := encodingjson.Unmarshal(document, &outputObject); err != nil {
		t.Fatalf("decode producer document: %v", err)
	}
	for field := range outputObject {
		if _, declared := properties[field]; !declared {
			t.Errorf("producer field %q is missing from %s properties", field, path)
		}
	}
}

func TestPublishedSchemasUseDraft202012AndStableIdentity(t *testing.T) {
	t.Parallel()
	wantIDs := map[string]string{
		"schemas/organization-v1.json":   "https://policy-scout.dev/schemas/organization/v1",
		"schemas/organization-v2.json":   "https://policy-scout.dev/schemas/organization/v2",
		"schemas/auth-status-v1.json":    "https://policy-scout.dev/schemas/auth-status/v1",
		"schemas/error-v1.json":          "https://policy-scout.dev/schemas/error/v1",
		"schemas/search-v1.json":         "https://policy-scout.dev/schemas/search/v1",
		"schemas/policies-v1.json":       "https://policy-scout.dev/schemas/policies/v1",
		"schemas/attachments-v1.json":    "https://policy-scout.dev/schemas/attachments/v1",
		"schemas/lint-v1.json":           "https://policy-scout.dev/schemas/lint/v1",
		"schemas/administrators-v1.json": "https://policy-scout.dev/schemas/administrators/v1",
		"schemas/exemptions-v1.json":     "https://policy-scout.dev/schemas/exemptions/v1",
		"schemas/coverage-v1.json":       "https://policy-scout.dev/schemas/coverage/v1",
		"schemas/changes-v1.json":        "https://policy-scout.dev/schemas/changes/v1",
		"schemas/region-drift-v1.json":   "https://policy-scout.dev/schemas/region-drift/v1",
	}
	for path, wantID := range wantIDs {
		document, err := schemaFiles.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		if len(document) == 0 || document[len(document)-1] != '\n' {
			t.Errorf("%s is not newline-terminated", path)
		}
		var metadata struct {
			Schema string `json:"$schema"`
			ID     string `json:"$id"`
		}
		if err := encodingjson.Unmarshal(document, &metadata); err != nil {
			t.Fatalf("decode %s metadata: %v", path, err)
		}
		if metadata.Schema != jsonSchemaDraft202012 || metadata.ID != wantID {
			t.Errorf("%s metadata = %#v, want draft %q and ID %q", path, metadata, jsonSchemaDraft202012, wantID)
		}
		compilePublishedSchema(t, path)
	}
}

func TestOrganizationSchemaValidatesProducerVariants(t *testing.T) {
	t.Parallel()
	schema := compilePublishedSchema(t, "schemas/organization-v1.json")
	root := organizationNode{
		SchemaVersion: organizationJSONSchemaVersion,
		Selection:     organizationSelection{Type: allSelectionType},
		Type:          rootEntityType,
		ID:            "r-root",
		Children: []organizationNode{
			{
				Type: organizationalUnitEntityType, ID: "ou-root-12345678", Name: "Production",
				SCPs: []string{"DenyRegions"},
				SCPAttachments: []scpAttachment{{
					PolicyID: "p-policy1", PolicyName: "DenyRegions", Inherited: true,
					AttachedTo: scpAttachmentTarget{Type: rootEntityType, ID: "r-root"},
				}},
				Children: []organizationNode{{Type: accountEntityType, ID: "222222222222", Name: "Member"}},
			},
			{Type: accountEntityType, ID: "111111111111", Name: "Management", ManagementAccount: true},
		},
	}
	document, err := renderOrganizationTreeJSON(root)
	if err != nil {
		t.Fatalf("render organization: %v", err)
	}
	if err := validateJSONDocument(t, schema, document); err != nil {
		t.Fatalf("producer output does not satisfy organization schema: %v\n%s", err, document)
	}
	assertFieldsDeclared(t, "schemas/organization-v1.json", "root", document)

	for _, selection := range []string{
		`{"type":"all"}`,
		`{"type":"account","target_id":"123456789012"}`,
		`{"type":"organizational_unit","target_id":"ou-root-12345678"}`,
	} {
		assertValidDocument(t, schema, `{"schema_version":"1","selection":`+selection+`,"type":"root","id":"r-root","children":[]}`)
	}
}

func TestOrganizationSchemaRejectsContractDrift(t *testing.T) {
	t.Parallel()
	schema := compilePublishedSchema(t, "schemas/organization-v1.json")
	for _, document := range []string{
		`{"schema_version":"2","selection":{"type":"all"},"type":"root","id":"r-root","children":[]}`,
		`{"schema_version":"1","selection":{"type":"all"},"type":"root","id":"r-root","policies":[],"children":[]}`,
		`{"schema_version":"1","selection":{"type":"all","target_id":"unexpected"},"type":"root","id":"r-root","children":[]}`,
		`{"schema_version":"1","selection":{"type":"all"},"type":"root","id":"r-root","children":[{"type":"organizational_unit","id":"ou-root-12345678","name":"Production","scps":[],"children":[]}]}`,
		`{"schema_version":"1","selection":{"type":"all"},"type":"root","id":"r-root","children":[{"type":"account","id":"111111111111","name":"Management","management_account":true,"scps":[],"scp_attachments":[]}]}`,
		`{"schema_version":"1","selection":{"type":"all"},"type":"root","id":"r-root","children":[{"type":"account","id":"222222222222","name":"Member","management_account":false}]}`,
	} {
		assertInvalidDocument(t, schema, document)
	}
}

func TestOrganizationV2SchemaValidatesPolicyCatalog(t *testing.T) {
	t.Parallel()
	schema := compilePublishedSchema(t, "schemas/organization-v2.json")
	root := organizationNode{
		SchemaVersion: organizationPolicyDocumentsJSONSchemaVersion,
		Selection:     organizationSelection{Type: allSelectionType},
		Type:          rootEntityType,
		ID:            "r-root",
		Policies: []organizationPolicy{{
			ID: "p-policy1", Name: "Guardrail", Description: "Example", ARN: "arn:example",
			AWSManaged: false, Content: encodingjson.RawMessage(`{"Version":"2012-10-17","Statement":[]}`),
		}},
		Children: []organizationNode{{Type: accountEntityType, ID: "222222222222", Name: "Member"}},
	}
	document, err := renderOrganizationTreeJSON(root)
	if err != nil {
		t.Fatalf("render organization v2: %v", err)
	}
	if err := validateJSONDocument(t, schema, document); err != nil {
		t.Fatalf("producer output does not satisfy organization v2 schema: %v\n%s", err, document)
	}
	assertFieldsDeclared(t, "schemas/organization-v2.json", "root", document)
	for _, invalid := range []string{
		`{"schema_version":"2","selection":{"type":"all"},"type":"root","id":"r-root","children":[]}`,
		`{"schema_version":"1","selection":{"type":"all"},"type":"root","id":"r-root","policies":[],"children":[]}`,
		`{"schema_version":"2","selection":{"type":"all"},"type":"root","id":"r-root","policies":[{"id":"p-policy1","name":"Guardrail","aws_managed":false,"content":[]}],"children":[]}`,
	} {
		assertInvalidDocument(t, schema, invalid)
	}
}

func TestSearchSchemaValidatesProducerAndRejectsInvalidPaths(t *testing.T) {
	t.Parallel()
	schema := compilePublishedSchema(t, "schemas/search-v1.json")
	result := organizationSearchResult{
		SchemaVersion: awsSearchJSONSchemaVersion,
		Query:         organizationSearchQuery{Name: "production", Type: accountEntityType},
		Matches: []organizationSearchMatch{{
			Type: accountEntityType, ID: "123456789012", Name: "production",
			Path: []organizationSearchPathEntity{
				{Type: rootEntityType, ID: "r-root", Name: "Root"},
				{Type: accountEntityType, ID: "123456789012", Name: "production"},
			},
		}},
	}
	document, err := renderOrganizationSearch(result, json)
	if err != nil {
		t.Fatalf("render search result: %v", err)
	}
	if err := validateJSONDocument(t, schema, document); err != nil {
		t.Fatalf("producer output does not satisfy search schema: %v\n%s", err, document)
	}
	assertFieldsDeclared(t, "schemas/search-v1.json", "", document)
	assertValidDocument(t, schema, `{"schema_version":"1","query":{"name":"missing"},"matches":[]}`)
	for _, invalid := range []string{
		`{"schema_version":"1","query":{},"matches":[]}`,
		`{"schema_version":"1","query":{"name":"production"},"matches":[{"type":"account","id":"123456789012","name":"production","path":[{"type":"account","id":"123456789012","name":"production"}]}]}`,
	} {
		assertInvalidDocument(t, schema, invalid)
	}
}

func TestFocusedQuerySchemasValidateProducerVariants(t *testing.T) {
	t.Parallel()
	policiesSchema := compilePublishedSchema(t, "schemas/policies-v1.json")
	policies, err := buildPoliciesQuery(
		context.Background(), queryFixtureClient(false), queryInheritedAccount,
		queryRootID, "Root", queryManagementAccount,
	)
	if err != nil {
		t.Fatalf("build policies query: %v", err)
	}
	var policiesOutput bytes.Buffer
	if err := writePoliciesQuery(&policiesOutput, policies, json); err != nil {
		t.Fatalf("write policies query: %v", err)
	}
	if err := validateJSONDocument(t, policiesSchema, policiesOutput.Bytes()); err != nil {
		t.Fatalf("producer output does not satisfy policies schema: %v\n%s", err, policiesOutput.String())
	}
	assertFieldsDeclared(t, "schemas/policies-v1.json", "", policiesOutput.Bytes())
	assertInvalidDocument(t, policiesSchema, `{"schema_version":"1","target":{"type":"account","id":"111111111111","name":"Management","management_account":true,"scp_applicable":true},"path":[{"type":"root","id":"r-root"},{"type":"account","id":"111111111111","name":"Management"}],"policies":[]}`)
	assertInvalidDocument(t, policiesSchema, `{"schema_version":"1","target":{"type":"organizational_unit","id":"ou-root-12345678","name":"Production","scp_applicable":true},"path":[]}`)

	attachmentsSchema := compilePublishedSchema(t, "schemas/attachments-v1.json")
	attachments, err := buildAttachmentsQuery(
		context.Background(), queryFixtureClient(false), queryPolicyID,
		queryRootID, "Root", queryManagementAccount,
	)
	if err != nil {
		t.Fatalf("build attachments query: %v", err)
	}
	var attachmentsOutput bytes.Buffer
	if err := writeAttachmentsQuery(&attachmentsOutput, attachments, json); err != nil {
		t.Fatalf("write attachments query: %v", err)
	}
	if err := validateJSONDocument(t, attachmentsSchema, attachmentsOutput.Bytes()); err != nil {
		t.Fatalf("producer output does not satisfy attachments schema: %v\n%s", err, attachmentsOutput.String())
	}
	assertFieldsDeclared(t, "schemas/attachments-v1.json", "", attachmentsOutput.Bytes())
	assertValidDocument(t, attachmentsSchema, `{"schema_version":"1","policy_id":"p-unknown1","policy_name":"","direct_targets":[],"affected_targets":[]}`)
	assertInvalidDocument(t, attachmentsSchema, `{"schema_version":"1","policy_id":"p-policy1","policy_name":"","direct_targets":[{"type":"root","id":"r-root","name":"Root","scp_applicable":true}],"affected_targets":[]}`)
	assertInvalidDocument(t, attachmentsSchema, `{"schema_version":"1","policy_id":"p-policy1","policy_name":"Guardrail","direct_targets":[],"affected_targets":[{"target":{"type":"account","id":"111111111111","name":"Management","management_account":true,"scp_applicable":false},"provenance":[{"attached_to":{"type":"account","id":"111111111111","name":"Management"},"inherited":false}]}]}`)
}

func TestLintSchemaValidatesProducerAndRejectsContractDrift(t *testing.T) {
	t.Parallel()
	schema := compilePublishedSchema(t, "schemas/lint-v1.json")
	report := buildLintFixtureReport(t, newLintFixture())
	var output bytes.Buffer
	if err := writeLintReport(&output, report, json); err != nil {
		t.Fatalf("write lint report: %v", err)
	}
	if err := validateJSONDocument(t, schema, output.Bytes()); err != nil {
		t.Fatalf("producer output does not satisfy lint schema: %v\n%s", err, output.String())
	}
	assertFieldsDeclared(t, "schemas/lint-v1.json", "", output.Bytes())
	for _, finding := range report.Findings {
		encoded, err := encodingjson.Marshal(finding)
		if err != nil {
			t.Fatal(err)
		}
		assertFieldsDeclared(t, "schemas/lint-v1.json", "finding", encoded)
		evidence, err := encodingjson.Marshal(finding.Evidence)
		if err != nil {
			t.Fatal(err)
		}
		assertFieldsDeclared(t, "schemas/lint-v1.json", "evidence", evidence)
	}

	const header = `{"schema_version":"1","root":{"type":"root","id":"r-root"},"limits":{"policies_per_target":10,"policy_document_characters":10240},"checks":["unattached_policy"],"summary":{"total":0,"high":0,"medium":0,"low":0},"findings":`
	assertValidDocument(t, schema, header+`[]}`)
	for _, invalid := range []string{
		header + `[{"check":"unknown_check","severity":"low","message":"m","rationale":"r","evidence":{}}]}`,
		header + `[{"check":"attachment_limit","severity":"medium","message":"m","rationale":"r","target":{"type":"root","id":"r-root"},"evidence":{}}]}`,
		header + `[{"check":"allow_not_action","severity":"medium","message":"m","rationale":"r","policy":{"id":"p-policy01","name":"P","aws_managed":false},"evidence":{}}]}`,
		header + `[{"check":"redundant_attachment","severity":"low","message":"m","rationale":"r","target":{"type":"root","id":"r-root"},"policy":{"id":"p-policy01","name":"P","aws_managed":false},"evidence":{"inherited_from":[{"type":"root","id":"r-root"}]}}]}`,
		header + `[{"check":"unattached_policy","severity":"high","message":"m","rationale":"r","policy":{"id":"p-policy01","name":"P","aws_managed":false},"evidence":{}}]}`,
		`{"schema_version":"1","root":{"type":"account","id":"111111111111"},"limits":{"policies_per_target":10,"policy_document_characters":10240},"checks":[],"summary":{"total":0,"high":0,"medium":0,"low":0},"findings":[]}`,
	} {
		assertInvalidDocument(t, schema, invalid)
	}
}

func TestAdministratorsSchemaValidatesProducerVariants(t *testing.T) {
	t.Parallel()
	schema := compilePublishedSchema(t, "schemas/administrators-v1.json")
	result, err := buildAdministrators(context.Background(), administratorsFixtureClient(false))
	if err != nil {
		t.Fatalf("build administrators: %v", err)
	}
	var output bytes.Buffer
	if err := writeAdministrators(&output, result, json); err != nil {
		t.Fatalf("write administrators: %v", err)
	}
	if err := validateJSONDocument(t, schema, output.Bytes()); err != nil {
		t.Fatalf("producer output does not satisfy administrators schema: %v\n%s", err, output.String())
	}
	assertFieldsDeclared(t, "schemas/administrators-v1.json", "", output.Bytes())

	assertValidDocument(t, schema, `{"schema_version":"1","organization":{"id":"o-example"},"management_account":{"id":"111111111111"},"resource_policy":null,"delegated_administrators":[],"trusted_services":[]}`)
	for _, invalid := range []string{
		`{"schema_version":"1","organization":{"id":"o-example"},"management_account":{"id":"111111111111"},"delegated_administrators":[],"trusted_services":[]}`,
		`{"schema_version":"1","organization":{"id":"o-example"},"management_account":{"id":"1111"},"resource_policy":null,"delegated_administrators":[],"trusted_services":[]}`,
		`{"schema_version":"1","organization":{"id":"o-example"},"management_account":{"id":"111111111111"},"resource_policy":{"id":"rp-1","content":"{}"},"delegated_administrators":[],"trusted_services":[]}`,
		`{"schema_version":"1","organization":{"id":"o-example"},"management_account":{"id":"111111111111"},"resource_policy":null,"delegated_administrators":[{"id":"222222222222"}],"trusted_services":[]}`,
		`{"schema_version":"1","organization":{"id":"o-example"},"management_account":{"id":"111111111111"},"resource_policy":null,"delegated_administrators":[],"trusted_services":[{"service_principal":"sso.amazonaws.com","date_enabled":"yesterday"}]}`,
	} {
		assertInvalidDocument(t, schema, invalid)
	}
}

func TestExemptionsSchemaValidatesProducerVariantsAndRejectsDrift(t *testing.T) {
	t.Parallel()
	schema := compilePublishedSchema(t, "schemas/exemptions-v1.json")
	var describeCalls atomic.Int32
	client := exemptionsFixtureClient(&describeCalls)
	client.describePolicyFn = func(context.Context, *organizations.DescribePolicyInput) (*organizations.DescribePolicyOutput, error) {
		return &organizations.DescribePolicyOutput{Policy: &types.Policy{
			PolicySummary: &types.PolicySummary{
				Id: aws.String(queryPolicyID), Name: aws.String("Guardrail"), Type: types.PolicyTypeServiceControlPolicy,
			},
			Content: aws.String(securityBaselineSCP),
		}}, nil
	}
	target, err := buildTargetExemptionsQuery(context.Background(), client, queryInheritedAccount, queryRootID, "Root", queryManagementAccount)
	if err != nil {
		t.Fatalf("build target exemptions: %v", err)
	}
	management, err := buildTargetExemptionsQuery(context.Background(), client, queryManagementAccount, queryRootID, "Root", queryManagementAccount)
	if err != nil {
		t.Fatalf("build management exemptions: %v", err)
	}
	policy, err := buildPolicyExemptionsQuery(context.Background(), client, queryPolicyID)
	if err != nil {
		t.Fatalf("build policy exemptions: %v", err)
	}
	for _, result := range []exemptionsQueryResult{target, management, policy} {
		var output bytes.Buffer
		if err := writeExemptionsQuery(&output, result, json); err != nil {
			t.Fatalf("write exemptions: %v", err)
		}
		if err := validateJSONDocument(t, schema, output.Bytes()); err != nil {
			t.Fatalf("producer output does not satisfy exemptions schema: %v\n%s", err, output.String())
		}
		assertFieldsDeclared(t, "schemas/exemptions-v1.json", "", output.Bytes())
	}
	var policyOutput bytes.Buffer
	if err := writeExemptionsQuery(&policyOutput, target, json); err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		Policies []struct {
			DenyStatements []struct {
				Exemptions []encodingjson.RawMessage `json:"exemptions"`
			} `json:"deny_statements"`
		} `json:"policies"`
	}
	if err := encodingjson.Unmarshal(policyOutput.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	for _, statement := range decoded.Policies[0].DenyStatements {
		for _, item := range statement.Exemptions {
			assertFieldsDeclared(t, "schemas/exemptions-v1.json", "exemption", item)
		}
	}

	const policySelection = `"selection":{"type":"policy","policy_id":"p-policy1"}`
	const statementPrefix = `"policies":[{"policy_id":"p-policy1","policy_name":"Guardrail","deny_statements":[{"index":0,"exemptions":[`
	assertValidDocument(t, schema, `{"schema_version":"1",`+policySelection+`,`+statementPrefix+`]}]}]}`)
	for _, invalid := range []string{
		// Policy selections carry no target, path, or provenance.
		`{"schema_version":"1",` + policySelection + `,"target":{"type":"organizational_unit","id":"ou-root-12345678","name":"Production","scp_applicable":true},"policies":[]}`,
		`{"schema_version":"1",` + policySelection + `,"policies":[{"policy_id":"p-policy1","policy_name":"Guardrail","provenance":[{"attached_to":{"type":"root","id":"r-root"},"inherited":true}],"deny_statements":[]}]}`,
		// Target selections require a target and path.
		`{"schema_version":"1","selection":{"type":"account","target_id":"222222222222"},"policies":[]}`,
		// Interpreted conditions state when they exempt; uninterpretable ones never do.
		`{"schema_version":"1",` + policySelection + `,` + statementPrefix + `{"source":"condition","category":"region","operator":"StringNotEquals","key":"aws:RequestedRegion","values":["us-east-1"],"interpretable":true}]}]}]}`,
		`{"schema_version":"1",` + policySelection + `,` + statementPrefix + `{"source":"condition","operator":"NumericLessThan","key":"aws:MultiFactorAuthAge","values":["1"],"exempt_when":"matches_values","interpretable":false,"reason":"not interpreted"}]}]}]}`,
		`{"schema_version":"1",` + policySelection + `,` + statementPrefix + `{"source":"not_action","values":["iam:*"],"exempt_when":"does_not_match_values","interpretable":true}]}]}]}`,
	} {
		assertInvalidDocument(t, schema, invalid)
	}
}

func TestCoverageSchemaValidatesProducerVariantsAndRejectsDrift(t *testing.T) {
	t.Parallel()
	schema := compilePublishedSchema(t, "schemas/coverage-v1.json")
	for _, query := range []coverageQuery{
		{Type: coverageQueryTypePolicy, PolicyID: coverageGuardPolicy},
		{Type: coverageQueryTypeAction, Action: "cloudtrail:StopLogging"},
	} {
		result, err := buildCoverageReport(context.Background(), coverageFixtureClient(), query, coverageRootID, "Root", coverageManagement)
		if err != nil {
			t.Fatalf("build %s coverage report: %v", query.Type, err)
		}
		var output bytes.Buffer
		if err := writeCoverageReport(&output, result, json); err != nil {
			t.Fatalf("write coverage report: %v", err)
		}
		if err := validateJSONDocument(t, schema, output.Bytes()); err != nil {
			t.Fatalf("producer output does not satisfy coverage schema: %v\n%s", err, output.String())
		}
		assertFieldsDeclared(t, "schemas/coverage-v1.json", "", output.Bytes())
	}

	account := `{"account":{"id":"222222222222","name":"Member","state":"ACTIVE"},"path":[{"type":"root","id":"r-root"},{"type":"account","id":"222222222222","name":"Member"}]`
	summary := `"summary":{"accounts":1,"covered":0,"conditionally_covered":0,"uncovered":1,"excluded":0}`
	conditionalEvidence := `"evidence":[{"policy_id":"p-cond0001","policy_name":"Cond","attached_to":{"type":"root","id":"r-root"},"inherited":true,` +
		`"statement":{"index":0,"matched_by":"action","condition":{"Bool":{"aws:ViaAWSService":"false"}}}}]}`
	assertValidDocument(t, schema, `{"schema_version":"1","query":{"type":"action","action":"cloudtrail:StopLogging"},`+summary+
		`,"uncovered_accounts":[`+account+`,"evidence":[]}],"conditionally_covered_accounts":[`+account+`,`+conditionalEvidence+
		`],"covered_accounts":[],"excluded_accounts":[]}`)
	for _, invalid := range []string{
		// Uncovered accounts carry no evidence.
		`{"schema_version":"1","query":{"type":"policy","policy_id":"p-guard001","policy_name":"Guard"},` + summary +
			`,"uncovered_accounts":[` + account + `,"evidence":[{"policy_id":"p-guard001","policy_name":"Guard","attached_to":{"type":"root","id":"r-root"},"inherited":true}]}],"conditionally_covered_accounts":[],"covered_accounts":[],"excluded_accounts":[]}`,
		// Policy mode never reports conditional coverage.
		`{"schema_version":"1","query":{"type":"policy","policy_id":"p-guard001","policy_name":"Guard"},` + summary +
			`,"uncovered_accounts":[],"conditionally_covered_accounts":[` + account + `,` + conditionalEvidence + `],"covered_accounts":[],"excluded_accounts":[]}`,
		// Conditional evidence cannot be reported as unconditional action coverage.
		`{"schema_version":"1","query":{"type":"action","action":"cloudtrail:StopLogging"},` + summary +
			`,"uncovered_accounts":[],"conditionally_covered_accounts":[],"covered_accounts":[` + account + `,` + conditionalEvidence + `],"excluded_accounts":[]}`,
		`{"schema_version":"1","query":{"type":"action","action":"cloudtrail:StopLogging"},` + summary +
			`,"uncovered_accounts":[],"conditionally_covered_accounts":[],"covered_accounts":[],"excluded_accounts":[` + account + `,"reason":"suspended"}]}`,
	} {
		assertInvalidDocument(t, schema, invalid)
	}
}

func TestChangesSchemaValidatesProducerAndRejectsContractDrift(t *testing.T) {
	t.Parallel()
	schema := compilePublishedSchema(t, "schemas/changes-v1.json")
	query := changesFixtureQuery()
	query.PolicyID, query.TargetID = changesOtherPolicy, changesWorkloadAccount
	for _, query := range []changesQuery{changesFixtureQuery(), query} {
		result, err := buildChanges(context.Background(), changesSTSClient(), changesFixtureClient(), query, 0)
		if err != nil {
			t.Fatalf("build changes: %v", err)
		}
		var output bytes.Buffer
		if err := writeChanges(&output, result, json); err != nil {
			t.Fatalf("write changes: %v", err)
		}
		if err := validateJSONDocument(t, schema, output.Bytes()); err != nil {
			t.Fatalf("producer output does not satisfy changes schema: %v\n%s", err, output.String())
		}
		assertFieldsDeclared(t, "schemas/changes-v1.json", "", output.Bytes())
		var decoded struct {
			Events []encodingjson.RawMessage `json:"events"`
		}
		if err := encodingjson.Unmarshal(output.Bytes(), &decoded); err != nil {
			t.Fatal(err)
		}
		for _, event := range decoded.Events {
			assertFieldsDeclared(t, "schemas/changes-v1.json", "event", event)
		}
	}

	envelope := `"schema_version":"1","source":"cloudtrail:LookupEvents","account_id":"111111111111","region":"us-east-1","start_time":"2026-10-01T00:00:00Z","end_time":"2026-11-01T00:00:00Z","event_names":["AttachPolicy"]`
	event := `"event_id":"e1","event_time":"2026-10-02T00:00:00Z","event_name":"AttachPolicy","caller":{"type":"Root"}`
	assertValidDocument(t, schema, `{`+envelope+`,"events":[]}`)
	assertValidDocument(t, schema, `{`+envelope+`,"events":[{`+event+`}]}`)
	for _, invalid := range []string{
		`{` + envelope + `}`,
		`{` + strings.Replace(envelope, `"111111111111"`, `"1111"`, 1) + `,"events":[]}`,
		`{` + strings.Replace(envelope, `"2026-10-01T00:00:00Z"`, `"last week"`, 1) + `,"events":[]}`,
		`{` + envelope + `,"policy_id":"rp-example1","events":[]}`,
		`{` + envelope + `,"events":[{"event_id":"e1","event_name":"AttachPolicy","caller":{}}]}`,
		`{` + envelope + `,"events":[{` + event + `,"target":{"type":"policy","id":"p-a1b2c3d4"}}]}`,
		`{` + envelope + `,"events":[{` + event + `,"policy":{}}]}`,
	} {
		assertInvalidDocument(t, schema, invalid)
	}
}

func TestRegionDriftSchemaValidatesProducerAndRejectsDrift(t *testing.T) {
	t.Parallel()
	schema := compilePublishedSchema(t, "schemas/region-drift-v1.json")
	result, _ := buildRegionDriftFixture(t)
	var output bytes.Buffer
	if err := writeRegionDriftReport(&output, result, json); err != nil {
		t.Fatalf("write region drift report: %v", err)
	}
	if err := validateJSONDocument(t, schema, output.Bytes()); err != nil {
		t.Fatalf("producer output does not satisfy region-drift schema: %v\n%s", err, output.String())
	}
	assertFieldsDeclared(t, "schemas/region-drift-v1.json", "", output.Bytes())

	summary := `"summary":{"accounts":1,"restricted":1,"unrestricted":0,"with_blind_spots":0,"with_uninterpretable_restrictions":0,"excluded":0}`
	account := `{"account":{"id":"222222222222","name":"Member","state":"ACTIVE"},"path":[{"type":"root","id":"r-root"},{"type":"account","id":"222222222222","name":"Member"}],` +
		`"enabled_regions":[{"region":"us-east-1","opt_status":"ENABLED_BY_DEFAULT"}],"blind_spot_regions":[],"enabled_denied_regions":[],"allowed_disabled_regions":[],"uninterpretable_restrictions":[],`
	restriction := func(operator string) string {
		return `{"policy_id":"p-regions01","policy_name":"Regions","attached_to":{"type":"root","id":"r-root"},"inherited":true,"statement_index":0,` +
			`"kind":"allow_list","operator":"` + operator + `","regions":["us-east-1"],"carve_outs":[]}`
	}
	document := func(entry string) string {
		return `{"schema_version":"1",` + summary + `,"accounts":[` + account + entry + `}],"excluded_accounts":[]}`
	}
	assertValidDocument(t, schema, document(`"no_region_restriction":false,"enabled_allowed_regions":["us-east-1"],"restrictions":[`+restriction("StringNotEquals")+`]`))
	for _, invalid := range []string{
		// A restricted account names at least one restriction.
		document(`"no_region_restriction":false,"enabled_allowed_regions":["us-east-1"],"restrictions":[]`),
		// An unrestricted account cannot allow Regions.
		document(`"no_region_restriction":true,"enabled_allowed_regions":["us-east-1"],"restrictions":[]`),
		// An allow list uses a negated string operator.
		document(`"no_region_restriction":false,"enabled_allowed_regions":["us-east-1"],"restrictions":[` + restriction("StringEquals") + `]`),
	} {
		assertInvalidDocument(t, schema, invalid)
	}
}

func TestAuthStatusSchemaValidatesProducerAndFailureVariant(t *testing.T) {
	t.Parallel()
	schema := compilePublishedSchema(t, "schemas/auth-status-v1.json")
	status := awsAuthStatus{
		OK: true, Authenticated: true,
		Identity:      awsAuthIdentity{AccountID: "123456789012", ARN: "arn:aws:iam::123456789012:user/test", UserID: "AIDATEST"},
		Credentials:   awsAuthCredentials{Source: "EnvConfigCredentials"},
		Organizations: awsOrganizationsAuthStatus{Accessible: true, OrganizationID: "o-example", ManagementAccountID: "123456789012"},
	}
	var output bytes.Buffer
	if err := writeAWSAuthStatus(&output, status, json); err != nil {
		t.Fatalf("write auth status: %v", err)
	}
	if err := validateJSONDocument(t, schema, output.Bytes()); err != nil {
		t.Fatalf("producer output does not satisfy auth-status schema: %v\n%s", err, output.String())
	}
	assertFieldsDeclared(t, "schemas/auth-status-v1.json", "", output.Bytes())

	assertValidDocument(t, schema, `{"schema_version":"1","ok":false,"authenticated":true,"identity":{"account_id":"123456789012","arn":"arn:example","user_id":"user"},"credentials":{"source":"provider","can_expire":true,"expires_at":"2026-07-18T16:42:00Z"},"organizations":{"accessible":false,"error":"AccessDeniedException","message":"AWS denied the Organizations request."}}`)
	for _, invalid := range []string{
		`{"schema_version":"1","ok":true,"authenticated":false,"identity":{"account_id":"1","arn":"a","user_id":"u"},"credentials":{"source":"provider","can_expire":false},"organizations":{"accessible":true}}`,
		`{"schema_version":"1","ok":true,"authenticated":true,"identity":{"account_id":"1","arn":"a","user_id":"u"},"credentials":{"source":"provider","can_expire":true},"organizations":{"accessible":true}}`,
		`{"schema_version":"1","ok":false,"authenticated":true,"identity":{"account_id":"1","arn":"a","user_id":"u"},"credentials":{"source":"provider","can_expire":false},"organizations":{"accessible":false}}`,
	} {
		assertInvalidDocument(t, schema, invalid)
	}
}

func TestErrorSchemaValidatesEveryClassification(t *testing.T) {
	t.Parallel()
	schema := compilePublishedSchema(t, "schemas/error-v1.json")
	for _, err := range []error{
		newInvalidInvocationError(errors.New("bad invocation")),
		newCredentialsError("RetrieveCredentials", errors.New("bad credentials")),
		awsOperationError("ListRoots", "AccessDeniedException", smithy.FaultClient),
		awsOperationError("ListRoots", "ThrottlingException", smithy.FaultClient),
		errors.New("unexpected"),
	} {
		var output bytes.Buffer
		if writeErr := writeError(&output, classifyError(err), errorFormatJSON); writeErr != nil {
			t.Fatalf("write structured error: %v", writeErr)
		}
		if validationErr := validateJSONDocument(t, schema, output.Bytes()); validationErr != nil {
			t.Fatalf("producer output does not satisfy error schema: %v\n%s", validationErr, output.String())
		}
		assertFieldsDeclared(t, "schemas/error-v1.json", "", output.Bytes())
	}
	for _, invalid := range []string{
		`{"schema_version":"1","code":"unknown","message":"message","retryable":false,"remediation":"fix it"}`,
		`{"schema_version":"1","code":"unexpected","message":"message","remediation":"fix it"}`,
		`{"schema_version":"1","code":"unexpected","message":"message","retryable":false,"remediation":"fix it","exit_code":1}`,
	} {
		assertInvalidDocument(t, schema, invalid)
	}
}
