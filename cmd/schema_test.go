package cmd

import (
	"bytes"
	"context"
	encodingjson "encoding/json"
	"errors"
	"testing"

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
		"schemas/organization-v1.json": "https://policy-scout.dev/schemas/organization/v1",
		"schemas/organization-v2.json": "https://policy-scout.dev/schemas/organization/v2",
		"schemas/auth-status-v1.json":  "https://policy-scout.dev/schemas/auth-status/v1",
		"schemas/error-v1.json":        "https://policy-scout.dev/schemas/error/v1",
		"schemas/search-v1.json":       "https://policy-scout.dev/schemas/search/v1",
		"schemas/policies-v1.json":     "https://policy-scout.dev/schemas/policies/v1",
		"schemas/attachments-v1.json":  "https://policy-scout.dev/schemas/attachments/v1",
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
