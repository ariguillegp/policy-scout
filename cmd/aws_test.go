package cmd

import (
	"bytes"
	"context"
	"embed"
	encodingjson "encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsretry "github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/ssocreds"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/aws/aws-sdk-go-v2/service/organizations/types"
	ssotypes "github.com/aws/aws-sdk-go-v2/service/sso/types"
	ssooidctypes "github.com/aws/aws-sdk-go-v2/service/ssooidc/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"
	"github.com/spf13/cobra"
)

//go:embed testdata/organization-text/*.golden
var organizationTextGoldens embed.FS

func organizationTextGolden(t *testing.T, name string) string {
	t.Helper()
	content, err := organizationTextGoldens.ReadFile("testdata/organization-text/" + name + ".golden")
	if err != nil {
		t.Fatalf("read organization text golden %q: %v", name, err)
	}
	return string(content)
}

type fakeSTSClient struct {
	getCallerIdentityFn func(context.Context, *sts.GetCallerIdentityInput) (*sts.GetCallerIdentityOutput, error)
}

func (fake *fakeSTSClient) GetCallerIdentity(
	ctx context.Context,
	input *sts.GetCallerIdentityInput,
	_ ...func(*sts.Options),
) (*sts.GetCallerIdentityOutput, error) {
	return fake.getCallerIdentityFn(ctx, input)
}

type fakeOrganizationsClient struct {
	listChildrenFn             func(context.Context, *organizations.ListChildrenInput) (*organizations.ListChildrenOutput, error)
	listParentsFn              func(context.Context, *organizations.ListParentsInput) (*organizations.ListParentsOutput, error)
	listPoliciesForTargetFn    func(context.Context, *organizations.ListPoliciesForTargetInput) (*organizations.ListPoliciesForTargetOutput, error)
	listRootsFn                func(context.Context, *organizations.ListRootsInput) (*organizations.ListRootsOutput, error)
	describeAccountFn          func(context.Context, *organizations.DescribeAccountInput) (*organizations.DescribeAccountOutput, error)
	describeOrganizationalUnit func(context.Context, *organizations.DescribeOrganizationalUnitInput) (*organizations.DescribeOrganizationalUnitOutput, error)
	describeOrganizationFn     func(context.Context, *organizations.DescribeOrganizationInput) (*organizations.DescribeOrganizationOutput, error)
	describePolicyFn           func(context.Context, *organizations.DescribePolicyInput) (*organizations.DescribePolicyOutput, error)
}

func (fake *fakeOrganizationsClient) ListChildren(
	ctx context.Context,
	input *organizations.ListChildrenInput,
	_ ...func(*organizations.Options),
) (*organizations.ListChildrenOutput, error) {
	if fake.listChildrenFn == nil {
		return &organizations.ListChildrenOutput{}, nil
	}
	return fake.listChildrenFn(ctx, input)
}

func (fake *fakeOrganizationsClient) ListParents(
	ctx context.Context,
	input *organizations.ListParentsInput,
	_ ...func(*organizations.Options),
) (*organizations.ListParentsOutput, error) {
	if fake.listParentsFn == nil {
		return &organizations.ListParentsOutput{}, nil
	}
	return fake.listParentsFn(ctx, input)
}

func (fake *fakeOrganizationsClient) ListPoliciesForTarget(
	ctx context.Context,
	input *organizations.ListPoliciesForTargetInput,
	_ ...func(*organizations.Options),
) (*organizations.ListPoliciesForTargetOutput, error) {
	if fake.listPoliciesForTargetFn == nil {
		return &organizations.ListPoliciesForTargetOutput{}, nil
	}
	return fake.listPoliciesForTargetFn(ctx, input)
}

func (fake *fakeOrganizationsClient) ListRoots(
	ctx context.Context,
	input *organizations.ListRootsInput,
	_ ...func(*organizations.Options),
) (*organizations.ListRootsOutput, error) {
	if fake.listRootsFn == nil {
		return &organizations.ListRootsOutput{}, nil
	}
	return fake.listRootsFn(ctx, input)
}

func (fake *fakeOrganizationsClient) DescribeAccount(
	ctx context.Context,
	input *organizations.DescribeAccountInput,
	_ ...func(*organizations.Options),
) (*organizations.DescribeAccountOutput, error) {
	if fake.describeAccountFn == nil {
		return &organizations.DescribeAccountOutput{}, nil
	}
	return fake.describeAccountFn(ctx, input)
}

func (fake *fakeOrganizationsClient) DescribeOrganizationalUnit(
	ctx context.Context,
	input *organizations.DescribeOrganizationalUnitInput,
	_ ...func(*organizations.Options),
) (*organizations.DescribeOrganizationalUnitOutput, error) {
	if fake.describeOrganizationalUnit == nil {
		return &organizations.DescribeOrganizationalUnitOutput{}, nil
	}
	return fake.describeOrganizationalUnit(ctx, input)
}

func (fake *fakeOrganizationsClient) DescribeOrganization(
	ctx context.Context,
	input *organizations.DescribeOrganizationInput,
	_ ...func(*organizations.Options),
) (*organizations.DescribeOrganizationOutput, error) {
	if fake.describeOrganizationFn == nil {
		return &organizations.DescribeOrganizationOutput{}, nil
	}
	return fake.describeOrganizationFn(ctx, input)
}

func (fake *fakeOrganizationsClient) DescribePolicy(
	ctx context.Context,
	input *organizations.DescribePolicyInput,
	_ ...func(*organizations.Options),
) (*organizations.DescribePolicyOutput, error) {
	if fake.describePolicyFn == nil {
		return nil, errors.New("unexpected DescribePolicy call")
	}
	return fake.describePolicyFn(ctx, input)
}

func TestPolicyDocumentCatalogIsDeduplicatedParsedAndDeterministic(t *testing.T) {
	t.Parallel()

	root := organizationNode{
		SchemaVersion: organizationJSONSchemaVersion,
		Selection:     organizationSelection{Type: allSelectionType},
		Type:          rootEntityType,
		ID:            "r-root",
		Children: []organizationNode{
			{Type: accountEntityType, ID: "111111111111", SCPAttachments: []scpAttachment{
				{PolicyID: "p-zzzzzzzz", PolicyName: "Zulu"},
				{PolicyID: "p-aaaaaaaa", PolicyName: "Alpha"},
			}},
			{Type: organizationalUnitEntityType, ID: "ou-root-12345678", SCPAttachments: []scpAttachment{
				{PolicyID: "p-aaaaaaaa", PolicyName: "Alpha"},
			}},
		},
	}
	var mu sync.Mutex
	calls := make(map[string]int)
	client := &fakeOrganizationsClient{describePolicyFn: func(
		_ context.Context,
		input *organizations.DescribePolicyInput,
	) (*organizations.DescribePolicyOutput, error) {
		policyID := aws.ToString(input.PolicyId)
		mu.Lock()
		calls[policyID]++
		mu.Unlock()
		name := map[string]string{"p-aaaaaaaa": "Alpha", "p-zzzzzzzz": "Zulu"}[policyID]
		content := `{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}`
		return &organizations.DescribePolicyOutput{Policy: &types.Policy{
			Content: aws.String(content),
			PolicySummary: &types.PolicySummary{
				Id: aws.String(policyID), Name: aws.String(name), Description: aws.String(name + " description"),
				Arn: aws.String("arn:aws:organizations::aws:policy/" + policyID), AwsManaged: policyID == "p-zzzzzzzz",
				Type: types.PolicyTypeServiceControlPolicy,
			},
		}}, nil
	}}

	policies, err := describeApplicablePolicies(context.Background(), client, root)
	if err != nil {
		t.Fatalf("describe applicable policies: %v", err)
	}
	root.SchemaVersion = organizationPolicyDocumentsJSONSchemaVersion
	root.Policies = policies
	output, err := renderOrganizationTreeJSON(root)
	if err != nil {
		t.Fatalf("render policy catalog: %v", err)
	}
	if len(policies) != 2 || policies[0].ID != "p-aaaaaaaa" || policies[1].ID != "p-zzzzzzzz" {
		t.Fatalf("policies are not sorted and deduplicated: %+v", policies)
	}
	if calls["p-aaaaaaaa"] != 1 || calls["p-zzzzzzzz"] != 1 {
		t.Fatalf("DescribePolicy calls = %v, want one per policy ID", calls)
	}
	var decoded struct {
		SchemaVersion string `json:"schema_version"`
		Policies      []struct {
			Content any `json:"content"`
		} `json:"policies"`
	}
	if err := encodingjson.Unmarshal(output, &decoded); err != nil {
		t.Fatalf("decode catalog JSON: %v", err)
	}
	if decoded.SchemaVersion != "2" || len(decoded.Policies) != 2 {
		t.Fatalf("unexpected schema/catalog: %+v", decoded)
	}
	if _, ok := decoded.Policies[0].Content.(map[string]any); !ok {
		t.Fatalf("policy content has type %T, want JSON object", decoded.Policies[0].Content)
	}
}

func TestMalformedPolicyContentProducesNoPartialOutput(t *testing.T) {
	t.Parallel()

	for name, content := range map[string]string{
		"invalid JSON":   `{"Statement":`,
		"null":           `null`,
		"array":          `[]`,
		"number":         `42`,
		"encoded string": `"{}"`,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			var output bytes.Buffer
			err := displayOrganizationTree(
				context.Background(), &output, newPolicyDocumentTestClient(content),
				"all", "r-root", "Root", "999999999999", json, true,
			)
			if err == nil || !strings.Contains(err.Error(), "malformed JSON content") {
				t.Fatalf("unexpected error: %v", err)
			}
			if output.Len() != 0 {
				t.Fatalf("stdout contains partial output: %q", output.String())
			}
		})
	}
}

func newPolicyDocumentTestClient(content string) *fakeOrganizationsClient {
	const accountID = "123456789012"
	return &fakeOrganizationsClient{
		listChildrenFn: func(_ context.Context, input *organizations.ListChildrenInput) (*organizations.ListChildrenOutput, error) {
			if input.ChildType == types.ChildTypeAccount {
				return &organizations.ListChildrenOutput{Children: []types.Child{{Id: aws.String(accountID), Type: types.ChildTypeAccount}}}, nil
			}
			return &organizations.ListChildrenOutput{}, nil
		},
		describeAccountFn: func(context.Context, *organizations.DescribeAccountInput) (*organizations.DescribeAccountOutput, error) {
			return &organizations.DescribeAccountOutput{Account: &types.Account{Id: aws.String(accountID), Name: aws.String("Application")}}, nil
		},
		listPoliciesForTargetFn: func(_ context.Context, input *organizations.ListPoliciesForTargetInput) (*organizations.ListPoliciesForTargetOutput, error) {
			if aws.ToString(input.TargetId) == "r-root" {
				return &organizations.ListPoliciesForTargetOutput{Policies: []types.PolicySummary{{
					Id: aws.String("p-aaaaaaaa"), Name: aws.String("Broken"), Type: types.PolicyTypeServiceControlPolicy,
				}}}, nil
			}
			return &organizations.ListPoliciesForTargetOutput{}, nil
		},
		describePolicyFn: func(context.Context, *organizations.DescribePolicyInput) (*organizations.DescribePolicyOutput, error) {
			return &organizations.DescribePolicyOutput{Policy: &types.Policy{
				Content: aws.String(content),
				PolicySummary: &types.PolicySummary{
					Id: aws.String("p-aaaaaaaa"), Name: aws.String("Broken"), Type: types.PolicyTypeServiceControlPolicy,
				},
			}}, nil
		},
	}
}

func TestDefaultOrganizationOutputDoesNotDescribePolicies(t *testing.T) {
	t.Parallel()

	describeCalls := 0
	client := newPolicyDocumentTestClient(`{"Statement":[]}`)
	client.describePolicyFn = func(context.Context, *organizations.DescribePolicyInput) (*organizations.DescribePolicyOutput, error) {
		describeCalls++
		return nil, errors.New("DescribePolicy must not be called by default")
	}
	var output bytes.Buffer
	if err := displayOrganizationTree(
		context.Background(), &output, client, "all", "r-root", "Root", "999999999999", json,
	); err != nil {
		t.Fatalf("display default organization: %v", err)
	}
	if describeCalls != 0 {
		t.Fatalf("DescribePolicy called %d times by default", describeCalls)
	}
	if strings.Contains(output.String(), "\"policies\"") || !strings.Contains(output.String(), `"schema_version": "1"`) {
		t.Fatalf("default schema changed:\n%s", output.String())
	}
}

func TestValidateAccountID(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		value   string
		wantErr bool
	}{
		"account ID":     {value: "123456789012"},
		"all lowercase":  {value: "all"},
		"all mixed case": {value: "AlL"},
		"too short":      {value: "1234", wantErr: true},
		"letters":        {value: "12345678901x", wantErr: true},
		"spaces":         {value: "12345678901 ", wantErr: true},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			err := validateAccountID(test.value)
			if test.wantErr && err == nil {
				t.Fatal("expected an error")
			}
			if !test.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestSelectedAWSTargetValidatesAccountAndOrganizationalUnitFlags(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		accountID  string
		accountSet bool
		ouID       string
		ouSet      bool
		want       string
		wantErr    string
	}{
		"account":              {accountID: "123456789012", accountSet: true, want: "123456789012"},
		"all":                  {accountID: "all", accountSet: true, want: "all"},
		"organizational unit":  {ouID: "ou-abcd-12345678", ouSet: true, want: "ou-abcd-12345678"},
		"neither":              {wantErr: "invalid --account-id"},
		"stale account value":  {accountID: "123456789012", wantErr: "invalid --account-id"},
		"empty account":        {accountSet: true, wantErr: "invalid --account-id"},
		"empty OU":             {ouSet: true, wantErr: "invalid --ou-id"},
		"both":                 {accountID: "123456789012", accountSet: true, ouID: "ou-abcd-12345678", ouSet: true, wantErr: "mutually exclusive"},
		"account and empty OU": {accountID: "123456789012", accountSet: true, ouSet: true, wantErr: "mutually exclusive"},
		"empty account and OU": {accountSet: true, ouID: "ou-abcd-12345678", ouSet: true, wantErr: "mutually exclusive"},
		"invalid OU prefix":    {ouID: "xx-abcd-12345678", ouSet: true, wantErr: "invalid --ou-id"},
		"short OU unique part": {ouID: "ou-abcd-1234567", ouSet: true, wantErr: "invalid --ou-id"},
		"uppercase OU":         {ouID: "ou-abcd-1234567A", ouSet: true, wantErr: "invalid --ou-id"},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got, err := selectedAWSTarget(test.accountID, test.accountSet, test.ouID, test.ouSet)
			if test.wantErr == "" {
				if err != nil || got != test.want {
					t.Fatalf("selected target = %q, error %v; want %q", got, err, test.want)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("error = %v, want it to contain %q", err, test.wantErr)
			}
			if diagnostic := classifyError(err); diagnostic.Code != errorCodeInvalidInvocation {
				t.Fatalf("diagnostic = %#v, want invalid invocation", diagnostic)
			}
		})
	}
}

func TestOutputFormatSupportsTextAndJSONOnly(t *testing.T) {
	t.Parallel()

	for _, value := range []string{"text", "json"} {
		var output outputFormat
		if err := output.Set(value); err != nil {
			t.Fatalf("set output format %q: %v", value, err)
		}
		if output.String() != value {
			t.Fatalf("got output format %q, want %q", output.String(), value)
		}
	}

	var output outputFormat
	if err := output.Set("dot"); err == nil {
		t.Fatal("expected dot output format to be rejected")
	}
}

func TestOrganizationJSONViewPreservesSCPsFieldName(t *testing.T) {
	t.Parallel()

	data, err := encodingjson.Marshal(newOrganizationJSONNode(organizationNode{
		Type: "account",
		ID:   "123456789012",
		SCPs: []string{"DenyS3"},
	}))
	if err != nil {
		t.Fatalf("encode account: %v", err)
	}
	var fields map[string]encodingjson.RawMessage
	if err := encodingjson.Unmarshal(data, &fields); err != nil {
		t.Fatalf("decode account fields: %v", err)
	}
	if _, found := fields["scps"]; !found {
		t.Fatalf("JSON account does not contain compatibility field %q: %s", "scps", data)
	}
}

func TestOrganizationJSONViewPreservesLegacySCPsAndAddsAttachments(t *testing.T) {
	t.Parallel()

	node := organizationNode{
		Type: "account",
		ID:   "123456789012",
		Name: "Application",
		SCPs: []string{"DenyS3"},
		SCPAttachments: []scpAttachment{{
			PolicyID:   "p-deny0001",
			PolicyName: "DenyS3",
			AttachedTo: scpAttachmentTarget{
				Type: "account",
				ID:   "123456789012",
				Name: "Application",
			},
			Inherited: false,
		}},
	}

	encoded, err := encodingjson.Marshal(newOrganizationJSONNode(node))
	if err != nil {
		t.Fatalf("encode account node: %v", err)
	}
	want := `{"type":"account","id":"123456789012","name":"Application","management_account":false,"scps":["DenyS3"],` +
		`"scp_attachments":[{"policy_id":"p-deny0001","policy_name":"DenyS3",` +
		`"attached_to":{"type":"account","id":"123456789012","name":"Application"},"inherited":false}]}`
	if string(encoded) != want {
		t.Fatalf("got JSON\n%s\nwant\n%s", encoded, want)
	}

	managementNode, err := encodingjson.Marshal(newOrganizationJSONNode(organizationNode{
		Type:              "account",
		ID:                "111111111111",
		Name:              "Management",
		ManagementAccount: true,
	}))
	if err != nil {
		t.Fatalf("encode management account node: %v", err)
	}
	managementWant := `{"type":"account","id":"111111111111","name":"Management","management_account":true}`
	if string(managementNode) != managementWant {
		t.Fatalf("got management JSON\n%s\nwant\n%s", managementNode, managementWant)
	}
}

func TestOrganizationJSONSelectionMetadataIsExplicitAndPrettyPrinted(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		selection organizationSelection
		want      string
	}{
		"all": {
			selection: organizationSelection{Type: allSelectionType},
			want: `{
  "schema_version": "1",
  "selection": {
    "type": "all"
  },
  "type": "root",
  "id": "r-root",
  "name": "Organization Root",
  "children": []
}
`,
		},
		"account": {
			selection: organizationSelection{Type: accountEntityType, TargetID: "123456789012"},
			want: `{
  "schema_version": "1",
  "selection": {
    "type": "account",
    "target_id": "123456789012"
  },
  "type": "root",
  "id": "r-root",
  "name": "Organization Root",
  "children": []
}
`,
		},
		"organizational unit": {
			selection: organizationSelection{Type: organizationalUnitEntityType, TargetID: "ou-root-12345678"},
			want: `{
  "schema_version": "1",
  "selection": {
    "type": "organizational_unit",
    "target_id": "ou-root-12345678"
  },
  "type": "root",
  "id": "r-root",
  "name": "Organization Root",
  "children": []
}
`,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			output, err := renderOrganizationTreeJSON(organizationNode{
				SchemaVersion: organizationJSONSchemaVersion,
				Selection:     test.selection,
				Type:          rootEntityType,
				ID:            "r-root",
				Name:          "Organization Root",
			})
			if err != nil {
				t.Fatalf("render organization JSON: %v", err)
			}
			if string(output) != test.want {
				t.Fatalf("got JSON\n%s\nwant\n%s", output, test.want)
			}
		})
	}
}

func TestOrganizationJSONViewUsesTypeSpecificFieldPresence(t *testing.T) {
	t.Parallel()

	root := organizationNode{
		SchemaVersion: organizationJSONSchemaVersion,
		Selection:     organizationSelection{Type: allSelectionType},
		Type:          rootEntityType,
		ID:            "r-root",
		Children: []organizationNode{
			{Type: organizationalUnitEntityType, ID: "ou-root-12345678", Name: "Empty OU"},
			{Type: accountEntityType, ID: "222222222222", Name: "Empty member"},
			{Type: accountEntityType, ID: "111111111111", Name: "Management", ManagementAccount: true},
		},
	}
	encoded, err := renderOrganizationTreeJSON(root)
	if err != nil {
		t.Fatalf("render organization JSON: %v", err)
	}

	var document struct {
		Children []map[string]encodingjson.RawMessage `json:"children"`
	}
	if err := encodingjson.Unmarshal(encoded, &document); err != nil {
		t.Fatalf("decode organization JSON: %v", err)
	}
	var rootFields map[string]encodingjson.RawMessage
	if err := encodingjson.Unmarshal(encoded, &rootFields); err != nil {
		t.Fatalf("decode root fields: %v", err)
	}
	if len(document.Children) != 3 {
		t.Fatalf("children = %d, want 3", len(document.Children))
	}

	assertFields := func(nodeName string, fields map[string]encodingjson.RawMessage, want ...string) {
		t.Helper()
		got := make([]string, 0, len(fields))
		for field := range fields {
			got = append(got, field)
		}
		sort.Strings(got)
		sort.Strings(want)
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("%s fields = %v, want %v; JSON: %v", nodeName, got, want, fields)
		}
	}

	assertFields(
		"root",
		rootFields,
		"schema_version", "selection", "type", "id", "children",
	)
	assertFields(
		"organizational unit",
		document.Children[0],
		"type", "id", "name", "scps", "scp_attachments", "children",
	)
	assertFields(
		"member account",
		document.Children[1],
		"type", "id", "name", "management_account", "scps", "scp_attachments",
	)
	assertFields(
		"management account",
		document.Children[2],
		"type", "id", "name", "management_account",
	)
	if string(document.Children[0]["scps"]) != "[]" ||
		string(document.Children[0]["scp_attachments"]) != "[]" ||
		string(document.Children[0]["children"]) != "[]" ||
		string(document.Children[1]["management_account"]) != "false" ||
		string(document.Children[1]["scps"]) != "[]" ||
		string(document.Children[1]["scp_attachments"]) != "[]" ||
		string(document.Children[2]["management_account"]) != "true" {
		t.Fatalf("unexpected type-specific values: %s", encoded)
	}
}

func TestOrganizationTextRenderingDoesNotMutateJSONDocument(t *testing.T) {
	t.Parallel()

	tree := organizationNode{
		SchemaVersion: organizationJSONSchemaVersion,
		Selection:     organizationSelection{Type: accountEntityType, TargetID: "123456789012"},
		Type:          rootEntityType,
		ID:            "r-root",
		Name:          "Organization Root",
		Children: []organizationNode{{
			Type: accountEntityType,
			ID:   "123456789012",
			Name: "Application",
			SCPs: []string{"DenyRegions"},
			SCPAttachments: []scpAttachment{{
				PolicyID:   "p-regions01",
				PolicyName: "DenyRegions",
				AttachedTo: scpAttachmentTarget{
					Type: accountEntityType,
					ID:   "123456789012",
					Name: "Application",
				},
			}},
		}},
	}
	want, err := renderOrganizationTreeJSON(tree)
	if err != nil {
		t.Fatalf("render JSON baseline: %v", err)
	}

	beforeText := append([]byte(nil), want...)
	_ = renderOrganizationTreeText(tree)
	afterText, err := renderOrganizationTreeJSON(tree)
	if err != nil {
		t.Fatalf("render JSON after text: %v", err)
	}
	if !bytes.Equal(afterText, beforeText) {
		t.Fatalf("text rendering mutated JSON output:\nbefore:\n%s\nafter:\n%s", beforeText, afterText)
	}
}

func TestAttachmentTargetTextUsesHumanEntityTypesAndPreservesNames(t *testing.T) {
	t.Parallel()

	tests := []struct {
		target scpAttachmentTarget
		want   string
	}{
		{target: scpAttachmentTarget{Type: rootEntityType, ID: "r-root", Name: "Root"}, want: "Root [r-root]"},
		{target: scpAttachmentTarget{Type: rootEntityType, ID: "r-root", Name: "Organization Root"}, want: "Root Organization Root [r-root]"},
		{target: scpAttachmentTarget{Type: organizationalUnitEntityType, ID: "ou-root-12345678", Name: "Finance"}, want: "OU Finance [ou-root-12345678]"},
		{target: scpAttachmentTarget{Type: organizationalUnitEntityType, ID: "ou-root-87654321", Name: "OU"}, want: "OU OU [ou-root-87654321]"},
		{target: scpAttachmentTarget{Type: accountEntityType, ID: "123456789012", Name: "Account"}, want: "Account Account [123456789012]"},
	}
	for _, test := range tests {
		if got := attachmentTargetText(test.target); got != test.want {
			t.Errorf("attachment target %+v rendered as %q, want %q", test.target, got, test.want)
		}
	}
}

func TestCommandContractIsAutomationFriendly(t *testing.T) {
	profileFlag := awsCmd.PersistentFlags().Lookup("profile")
	if profileFlag == nil {
		t.Fatal("profile flag is not registered as a persistent AWS flag")
	}
	if profileFlag.DefValue != "" {
		t.Fatalf("profile default is %q, want empty", profileFlag.DefValue)
	}

	outputFlag := awsCmd.Flags().Lookup("output-format")
	if outputFlag == nil {
		t.Fatal("output format flag is not registered")
	}
	if outputFlag.DefValue != "json" {
		t.Fatalf("output format default is %q, want json", outputFlag.DefValue)
	}

	if err := awsCmd.Args(awsCmd, []string{"unexpected"}); err == nil {
		t.Fatal("expected positional arguments to be rejected")
	}

	err := describeAccount(context.Background(), &bytes.Buffer{}, "invalid", "")
	if err == nil || !strings.Contains(err.Error(), `invalid --account-id "invalid"`) {
		t.Fatalf("unexpected account validation error: %v", err)
	}

	var help bytes.Buffer
	awsCmd.SetOut(&help)
	defer awsCmd.SetOut(nil)
	if err := awsCmd.Help(); err != nil {
		t.Fatalf("render AWS help: %v", err)
	}
	for _, expected := range []string{
		"exactly 12 digits",
		`or "all"`,
		"JSON output is used by default",
		"AWS SDK default",
		"--profile security-audit",
		"overrides AWS_PROFILE",
		"credential chain are unchanged",
		"--timeout",
		"--max-retries",
		"does not prompt for input or start an",
		"aws sso login --profile=<name>",
		"every OU and member account",
		"direct attachments and attachments inherited",
		"--include-policy-documents",
		"top-level policy catalog",
		"SCP Allow/Deny",
		"IAM policies",
		"resource policies",
		"permission boundaries",
		"session policies",
		"effective identity permissions",
		"policy-scout aws --account-id 123456789012",
	} {
		if !strings.Contains(help.String(), expected) {
			t.Errorf("AWS help does not contain %q:\n%s", expected, help.String())
		}
	}

	help.Reset()
	rootCmd.SetOut(&help)
	defer rootCmd.SetOut(nil)
	if err := rootCmd.Help(); err != nil {
		t.Fatalf("render root help: %v", err)
	}
	if !strings.Contains(help.String(), "aws") {
		t.Errorf("root help does not advertise AWS:\n%s", help.String())
	}
	for _, hidden := range []string{"gcp", "toggle"} {
		if strings.Contains(help.String(), hidden) {
			t.Errorf("root help unexpectedly advertises %q:\n%s", hidden, help.String())
		}
	}

	if !rootCmd.SilenceUsage {
		t.Fatal("runtime errors must not be followed by usage output")
	}
}

func TestRootHelpSurfacesAWSAndAuthStatusExamples(t *testing.T) {
	// Help rendering mutates the command's output writer, so this test is
	// intentionally not parallel (matches cmd/help_test.go conventions).
	var help bytes.Buffer
	rootCmd.SetOut(&help)
	defer rootCmd.SetOut(nil)
	if err := rootCmd.Help(); err != nil {
		t.Fatalf("render root help: %v", err)
	}
	output := help.String()

	for _, expected := range []string{
		"Inspect cloud organization policies from one CLI",
		"policy-scout aws auth status",
		"policy-scout aws auth status --output-format text",
		"policy-scout aws --account-id 123456789012",
		"policy-scout aws --account-id all --output-format text",
	} {
		if !strings.Contains(output, expected) {
			t.Errorf("root help does not surface %q:\n%s", expected, output)
		}
	}

	for _, hidden := range []string{"multi-cloud", "gcp", "azure"} {
		if strings.Contains(output, hidden) {
			t.Errorf("root help unexpectedly advertises %q:\n%s", hidden, output)
		}
	}
}

func TestAddSSORemediation(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		err      error
		profile  string
		wantHint bool
	}{
		"typed expired token": {
			err: &ssocreds.InvalidTokenError{}, profile: "engineering", wantHint: true,
		},
		"modern expired session cannot refresh": {
			err:     errors.New("refresh cached SSO token failed, cached SSO token is expired, or not present, and cannot be refreshed"),
			profile: "team dev", wantHint: true,
		},
		"missing SSO cache": {
			err: fmt.Errorf("failed to read cached SSO token file: %w", fs.ErrNotExist), profile: "default", wantHint: true,
		},
		"typed SSO unauthorized": {
			err: &ssotypes.UnauthorizedException{}, profile: "dev's profile", wantHint: true,
		},
		"typed invalid refresh grant": {
			err: &ssooidctypes.InvalidGrantException{}, profile: "-prod", wantHint: true,
		},
		"refresh network failure": {
			err: errors.New("refresh cached SSO token failed, unable to refresh SSO token: connection reset"), profile: "dev",
		},
		"cache permission failure": {
			err: fmt.Errorf("failed to read cached SSO token file: %w", fs.ErrPermission), profile: "dev",
		},
		"cache parse failure": {
			err: errors.New("failed to parse cached SSO token file: invalid character"), profile: "dev",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			original := newCredentialsError("RetrieveCredentials", test.err)
			got := addSSORemediation(original, test.profile)
			if !errors.Is(got, original) {
				t.Fatal("remediation must preserve the original error in its error chain")
			}
			var remediation *ssoRemediationError
			if errors.As(got, &remediation) != test.wantHint {
				t.Fatalf("unexpected SSO remediation wrapper: %v", got)
			}
		})
	}
}

func TestResolvedAWSProfile(t *testing.T) {
	t.Run("explicit profile takes precedence", func(t *testing.T) {
		t.Setenv("AWS_PROFILE", "environment")
		t.Setenv("AWS_DEFAULT_PROFILE", "fallback")
		if got := resolvedAWSProfile("flag"); got != "flag" {
			t.Fatalf("resolved profile is %q, want flag", got)
		}
	})

	t.Run("AWS_PROFILE takes environment precedence", func(t *testing.T) {
		t.Setenv("AWS_PROFILE", "environment")
		t.Setenv("AWS_DEFAULT_PROFILE", "fallback")
		if got := resolvedAWSProfile(""); got != "environment" {
			t.Fatalf("resolved profile is %q, want environment", got)
		}
	})

	t.Run("AWS_DEFAULT_PROFILE and default are fallbacks", func(t *testing.T) {
		t.Setenv("AWS_PROFILE", "")
		t.Setenv("AWS_DEFAULT_PROFILE", "fallback")
		if got := resolvedAWSProfile(""); got != "fallback" {
			t.Fatalf("resolved profile is %q, want fallback", got)
		}
		t.Setenv("AWS_DEFAULT_PROFILE", "")
		if got := resolvedAWSProfile(""); got != "default" {
			t.Fatalf("resolved profile is %q, want default", got)
		}
	})
}

func TestAWSExecutionControlFlags(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		args    []string
		want    awsExecutionControls
		wantErr string
	}{
		"omitted preserves SDK defaults": {},
		"timeout": {
			args: []string{"--timeout", "30s"},
			want: awsExecutionControls{timeout: 30 * time.Second, timeoutSet: true},
		},
		"timeout must not be zero": {
			args:    []string{"--timeout", "0s"},
			wantErr: "invalid --timeout",
		},
		"timeout must not be negative": {
			args:    []string{"--timeout", "-1s"},
			wantErr: "invalid --timeout",
		},
		"timeout must be a duration": {
			args:    []string{"--timeout", "soon"},
			wantErr: "invalid argument",
		},
		"zero retries": {
			args: []string{"--max-retries", "0"},
			want: awsExecutionControls{maxRetries: 0, maxRetriesSet: true},
		},
		"three retries": {
			args: []string{"--max-retries", "3"},
			want: awsExecutionControls{maxRetries: 3, maxRetriesSet: true},
		},
		"retries must not be negative": {
			args:    []string{"--max-retries", "-1"},
			wantErr: "invalid --max-retries",
		},
		"retries have a safe upper bound": {
			args:    []string{"--max-retries", "11"},
			wantErr: "invalid --max-retries",
		},
		"retries must be an integer": {
			args:    []string{"--max-retries", "many"},
			wantErr: "invalid argument",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			command := &cobra.Command{Use: "test"}
			addAWSExecutionFlags(command)
			err := command.ParseFlags(test.args)
			var got awsExecutionControls
			if err == nil {
				got, err = awsExecutionControlsFromCommand(command)
			}
			if test.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantErr) {
					t.Fatalf("got error %v, want one containing %q", err, test.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("parse execution controls: %v", err)
			}
			if got != test.want {
				t.Fatalf("got controls %+v, want %+v", got, test.want)
			}
		})
	}
}

func TestAWSExecutionControlsConfigureContextAndSDKRetries(t *testing.T) {
	t.Parallel()

	parent := context.Background()
	omitted := awsExecutionControls{}
	ctx, cancel := omitted.context(parent)
	defer cancel()
	if ctx != parent {
		t.Fatal("omitted timeout must preserve the parent context")
	}
	if options := omitted.configLoadOptions(); options != nil {
		t.Fatalf("omitted retry flag produced %d AWS configuration options", len(options))
	}

	controls := awsExecutionControls{
		timeout:       30 * time.Second,
		timeoutSet:    true,
		maxRetries:    3,
		maxRetriesSet: true,
	}
	ctx, cancel = controls.context(parent)
	defer cancel()
	deadline, ok := ctx.Deadline()
	if !ok {
		t.Fatal("configured timeout did not create a context deadline")
	}
	if remaining := time.Until(deadline); remaining <= 29*time.Second || remaining > 30*time.Second {
		t.Fatalf("context deadline has unexpected remaining duration %s", remaining)
	}

	options := controls.configLoadOptions()
	if len(options) != 1 {
		t.Fatalf("got %d AWS configuration options, want 1", len(options))
	}
	var loadOptions config.LoadOptions
	if err := options[0](&loadOptions); err != nil {
		t.Fatalf("apply AWS retry configuration: %v", err)
	}
	if loadOptions.RetryMaxAttempts != 4 {
		t.Fatalf("got %d maximum attempts, want 4", loadOptions.RetryMaxAttempts)
	}
}

func TestAWSExecutionControlsExplainStructuredErrors(t *testing.T) {
	t.Parallel()

	timeoutControls := awsExecutionControls{timeout: 30 * time.Second, timeoutSet: true}
	timeoutError := timeoutControls.explainError(fmt.Errorf("list roots: %w", context.DeadlineExceeded))
	if !errors.Is(timeoutError, context.DeadlineExceeded) || !strings.Contains(timeoutError.Error(), "exceeded --timeout 30s") {
		t.Fatalf("unexpected timeout error: %v", timeoutError)
	}
	timeoutDiagnostic := classifyError(timeoutError)
	if timeoutDiagnostic.Code != errorCodeTransient || timeoutDiagnostic.Message != "AWS execution exceeded --timeout 30s." {
		t.Fatalf("unexpected timeout diagnostic: %#v", timeoutDiagnostic)
	}

	cancellationError := (awsExecutionControls{}).explainError(fmt.Errorf("list roots: %w", context.Canceled))
	if !errors.Is(cancellationError, context.Canceled) || classifyError(cancellationError).Message != "Policy Scout execution was canceled." {
		t.Fatalf("unexpected cancellation diagnostic: %v", cancellationError)
	}

	retryControls := awsExecutionControls{maxRetries: 3, maxRetriesSet: true}
	retryError := retryControls.explainError(&awsretry.MaxAttemptsError{Attempt: 4, Err: errors.New("throttled")})
	if !strings.Contains(retryError.Error(), "--max-retries 3 (4 total attempts)") {
		t.Fatalf("unexpected retry error: %v", retryError)
	}
	retryDiagnostic := classifyError(retryError)
	if retryDiagnostic.Code != errorCodeTransient || retryDiagnostic.Message != "AWS request exhausted --max-retries 3 (4 total attempts)." {
		t.Fatalf("unexpected retry diagnostic: %#v", retryDiagnostic)
	}
}

func TestAWSAuthStatusExecutionControlFlagsAndValidation(t *testing.T) {
	for _, name := range []string{"timeout", "max-retries"} {
		if authStatusCmd.Flags().Lookup(name) == nil {
			t.Errorf("auth status flag --%s is not registered", name)
		}
	}

	var help bytes.Buffer
	authStatusCmd.SetOut(&help)
	t.Cleanup(func() { authStatusCmd.SetOut(nil) })
	if err := authStatusCmd.Help(); err != nil {
		t.Fatalf("render auth status help: %v", err)
	}
	for _, expected := range []string{
		"--timeout",
		"--max-retries",
		"configuration and credential loading",
		"policy-scout aws auth status --timeout 30s --max-retries 3",
	} {
		if !strings.Contains(help.String(), expected) {
			t.Errorf("auth status help does not contain %q:\n%s", expected, help.String())
		}
	}

	for name, controls := range map[string]awsExecutionControls{
		"zero timeout":     {timeoutSet: true},
		"negative retries": {maxRetries: -1, maxRetriesSet: true},
		"too many retries": {maxRetries: maxAllowedRetries + 1, maxRetriesSet: true},
	} {
		t.Run(name, func(t *testing.T) {
			if err := controls.validate(); err == nil {
				t.Fatal("expected execution controls to be rejected")
			}
		})
	}
}

func TestAWSAuthStatusDeadlineCoversConfigCredentialsAndAPIs(t *testing.T) {
	t.Parallel()

	deadline := time.Now().Add(time.Minute)
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	assertDeadline := func(stage string, got context.Context) {
		t.Helper()
		gotDeadline, ok := got.Deadline()
		if !ok || !gotDeadline.Equal(deadline) {
			t.Fatalf("%s received deadline %s (present: %t), want %s", stage, gotDeadline, ok, deadline)
		}
	}

	loader := func(got context.Context, _ ...func(*config.LoadOptions) error) (aws.Config, error) {
		assertDeadline("configuration loader", got)
		return aws.Config{Credentials: aws.CredentialsProviderFunc(func(got context.Context) (aws.Credentials, error) {
			assertDeadline("credential provider", got)
			return aws.Credentials{Source: "test"}, nil
		})}, nil
	}
	clients := func(aws.Config) (stsClient, authStatusOrganizationsClient) {
		return &fakeSTSClient{getCallerIdentityFn: func(got context.Context, _ *sts.GetCallerIdentityInput) (*sts.GetCallerIdentityOutput, error) {
				assertDeadline("STS", got)
				return &sts.GetCallerIdentityOutput{
					Account: aws.String("123456789012"),
					Arn:     aws.String("arn:aws:iam::123456789012:user/test"),
					UserId:  aws.String("AIDATEST"),
				}, nil
			}}, &fakeOrganizationsClient{describeOrganizationFn: func(got context.Context, _ *organizations.DescribeOrganizationInput) (*organizations.DescribeOrganizationOutput, error) {
				assertDeadline("Organizations", got)
				return &organizations.DescribeOrganizationOutput{Organization: &types.Organization{
					Id: aws.String("o-example"), MasterAccountId: aws.String("123456789012"),
				}}, nil
			}}
	}

	if err := displayAWSAuthStatusWithDependencies(ctx, &bytes.Buffer{}, "", loader, clients); err != nil {
		t.Fatalf("display AWS authentication status: %v", err)
	}
}

func TestAWSAuthStatusTimeoutAndCancellation(t *testing.T) {
	t.Parallel()

	t.Run("timeout during credential retrieval", func(t *testing.T) {
		t.Parallel()
		controls := awsExecutionControls{timeout: 10 * time.Millisecond, timeoutSet: true}
		ctx, cancel := controls.context(context.Background())
		defer cancel()
		loader := func(context.Context, ...func(*config.LoadOptions) error) (aws.Config, error) {
			return aws.Config{Credentials: aws.CredentialsProviderFunc(func(ctx context.Context) (aws.Credentials, error) {
				<-ctx.Done()
				return aws.Credentials{}, ctx.Err()
			})}, nil
		}

		err := displayAWSAuthStatusWithDependencies(ctx, &bytes.Buffer{}, "", loader, nil)
		err = controls.explainError(err)
		if !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "exceeded --timeout 10ms") {
			t.Fatalf("unexpected timeout error: %v", err)
		}
	})

	t.Run("cancellation during Organizations call", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := getAWSAuthStatus(
			ctx,
			aws.Credentials{Source: "test"},
			&fakeSTSClient{getCallerIdentityFn: func(context.Context, *sts.GetCallerIdentityInput) (*sts.GetCallerIdentityOutput, error) {
				return &sts.GetCallerIdentityOutput{
					Account: aws.String("123456789012"), Arn: aws.String("arn:test"), UserId: aws.String("user"),
				}, nil
			}},
			&fakeOrganizationsClient{describeOrganizationFn: func(got context.Context, _ *organizations.DescribeOrganizationInput) (*organizations.DescribeOrganizationOutput, error) {
				return nil, got.Err()
			}},
		)
		err = (awsExecutionControls{}).explainError(err)
		if !errors.Is(err, context.Canceled) || classifyError(err).Message != "Policy Scout execution was canceled." {
			t.Fatalf("unexpected cancellation error: %v", err)
		}
	})
}

func TestAWSAuthStatusAppliesRetryOptionAndExplainsExhaustion(t *testing.T) {
	t.Parallel()

	controls := awsExecutionControls{maxRetries: 3, maxRetriesSet: true}
	loader := func(_ context.Context, options ...func(*config.LoadOptions) error) (aws.Config, error) {
		var loadOptions config.LoadOptions
		for _, option := range options {
			if err := option(&loadOptions); err != nil {
				return aws.Config{}, err
			}
		}
		if loadOptions.RetryMaxAttempts != 4 {
			t.Fatalf("auth status configured %d maximum attempts, want 4", loadOptions.RetryMaxAttempts)
		}
		return aws.Config{Credentials: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
			return aws.Credentials{Source: "test"}, nil
		})}, nil
	}
	clients := func(aws.Config) (stsClient, authStatusOrganizationsClient) {
		return &fakeSTSClient{getCallerIdentityFn: func(context.Context, *sts.GetCallerIdentityInput) (*sts.GetCallerIdentityOutput, error) {
				return &sts.GetCallerIdentityOutput{
					Account: aws.String("123456789012"), Arn: aws.String("arn:test"), UserId: aws.String("user"),
				}, nil
			}}, &fakeOrganizationsClient{describeOrganizationFn: func(context.Context, *organizations.DescribeOrganizationInput) (*organizations.DescribeOrganizationOutput, error) {
				return nil, &awsretry.MaxAttemptsError{Attempt: 4, Err: errors.New("throttled")}
			}}
	}

	var output bytes.Buffer
	err := displayAWSAuthStatusWithDependencies(
		context.Background(), &output, "", loader, clients, controls.configLoadOptions()...,
	)
	err = controls.explainError(err)
	if !strings.Contains(err.Error(), "--max-retries 3 (4 total attempts)") {
		t.Fatalf("unexpected retry exhaustion error: %v", err)
	}
	if output.Len() != 0 {
		t.Fatalf("retry exhaustion wrote authentication status: %q", output.String())
	}
}

func TestAWSCallsPropagateContextDeadline(t *testing.T) {
	t.Parallel()

	deadline := time.Now().Add(time.Minute)
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()

	assertDeadline := func(got context.Context) {
		t.Helper()
		gotDeadline, ok := got.Deadline()
		if !ok || !gotDeadline.Equal(deadline) {
			t.Fatalf("AWS call received deadline %s (present: %t), want %s", gotDeadline, ok, deadline)
		}
	}

	client := &fakeOrganizationsClient{
		listChildrenFn: func(got context.Context, _ *organizations.ListChildrenInput) (*organizations.ListChildrenOutput, error) {
			assertDeadline(got)
			return &organizations.ListChildrenOutput{}, nil
		},
		listParentsFn: func(got context.Context, _ *organizations.ListParentsInput) (*organizations.ListParentsOutput, error) {
			assertDeadline(got)
			return &organizations.ListParentsOutput{Parents: []types.Parent{{Id: aws.String("r-root"), Type: types.ParentTypeRoot}}}, nil
		},
		listPoliciesForTargetFn: func(got context.Context, _ *organizations.ListPoliciesForTargetInput) (*organizations.ListPoliciesForTargetOutput, error) {
			assertDeadline(got)
			return &organizations.ListPoliciesForTargetOutput{}, nil
		},
		listRootsFn: func(got context.Context, _ *organizations.ListRootsInput) (*organizations.ListRootsOutput, error) {
			assertDeadline(got)
			return &organizations.ListRootsOutput{Roots: []types.Root{{Id: aws.String("r-root")}}}, nil
		},
		describeAccountFn: func(got context.Context, input *organizations.DescribeAccountInput) (*organizations.DescribeAccountOutput, error) {
			assertDeadline(got)
			return &organizations.DescribeAccountOutput{Account: &types.Account{Id: input.AccountId, Name: aws.String("Account")}}, nil
		},
		describeOrganizationalUnit: func(got context.Context, input *organizations.DescribeOrganizationalUnitInput) (*organizations.DescribeOrganizationalUnitOutput, error) {
			assertDeadline(got)
			return &organizations.DescribeOrganizationalUnitOutput{OrganizationalUnit: &types.OrganizationalUnit{
				Id: input.OrganizationalUnitId, Name: aws.String("OU"),
			}}, nil
		},
		describeOrganizationFn: func(got context.Context, _ *organizations.DescribeOrganizationInput) (*organizations.DescribeOrganizationOutput, error) {
			assertDeadline(got)
			return &organizations.DescribeOrganizationOutput{Organization: &types.Organization{MasterAccountId: aws.String("999999999999")}}, nil
		},
	}

	if _, err := listChildren(ctx, client, "r-root", types.ChildTypeAccount); err != nil {
		t.Fatalf("list children: %v", err)
	}
	if _, err := listParents(ctx, client, "123456789012"); err != nil {
		t.Fatalf("list parents: %v", err)
	}
	if _, err := listSCPsForTarget(ctx, client, "123456789012"); err != nil {
		t.Fatalf("list SCPs: %v", err)
	}
	if _, _, err := getRoot(ctx, client); err != nil {
		t.Fatalf("get root: %v", err)
	}
	if _, err := getAccount(ctx, client, "123456789012"); err != nil {
		t.Fatalf("get account: %v", err)
	}
	if _, err := getOU(ctx, client, "ou-root-12345678"); err != nil {
		t.Fatalf("get OU: %v", err)
	}
	if _, err := getManagementAccountID(ctx, client); err != nil {
		t.Fatalf("get management account: %v", err)
	}
}

func TestAWSCancellationReachesPaginatorCalls(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	client := &fakeOrganizationsClient{
		listChildrenFn: func(got context.Context, _ *organizations.ListChildrenInput) (*organizations.ListChildrenOutput, error) {
			if !errors.Is(got.Err(), context.Canceled) {
				t.Fatalf("AWS call context error is %v, want context canceled", got.Err())
			}
			return nil, got.Err()
		},
	}
	_, err := listChildren(ctx, client, "r-root", types.ChildTypeAccount)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("got error %v, want context canceled", err)
	}
}

func TestLoadAWSConfigWithExplicitProfile(t *testing.T) {
	t.Parallel()

	loader := func(_ context.Context, options ...func(*config.LoadOptions) error) (aws.Config, error) {
		if len(options) != 1 {
			t.Fatalf("got %d load options, want 1", len(options))
		}
		loadOptions := config.LoadOptions{}
		if err := options[0](&loadOptions); err != nil {
			t.Fatalf("apply load option: %v", err)
		}
		if loadOptions.SharedConfigProfile != "security-audit" {
			t.Fatalf("shared config profile is %q, want security-audit", loadOptions.SharedConfigProfile)
		}
		return aws.Config{}, nil
	}

	if _, err := loadAWSConfig(context.Background(), "security-audit", loader); err != nil {
		t.Fatalf("load AWS config: %v", err)
	}
}

func TestLoadAWSConfigWithoutProfileUsesDefaultChain(t *testing.T) {
	t.Parallel()

	loader := func(_ context.Context, options ...func(*config.LoadOptions) error) (aws.Config, error) {
		if len(options) != 0 {
			t.Fatalf("got %d load options, want none", len(options))
		}
		return aws.Config{}, nil
	}

	if _, err := loadAWSConfig(context.Background(), "", loader); err != nil {
		t.Fatalf("load AWS config: %v", err)
	}
}

func TestLoadAWSConfigCombinesProfileAndRetryOptions(t *testing.T) {
	t.Parallel()

	loader := func(_ context.Context, options ...func(*config.LoadOptions) error) (aws.Config, error) {
		if len(options) != 2 {
			t.Fatalf("got %d load options, want 2", len(options))
		}
		loadOptions := config.LoadOptions{}
		for _, option := range options {
			if err := option(&loadOptions); err != nil {
				t.Fatalf("apply load option: %v", err)
			}
		}
		if loadOptions.SharedConfigProfile != "security-audit" || loadOptions.RetryMaxAttempts != 4 {
			t.Fatalf("unexpected load options: profile %q, retry attempts %d", loadOptions.SharedConfigProfile, loadOptions.RetryMaxAttempts)
		}
		return aws.Config{}, nil
	}

	controls := awsExecutionControls{maxRetries: 3, maxRetriesSet: true}
	if _, err := loadAWSConfig(
		context.Background(), "security-audit", loader, controls.configLoadOptions()...,
	); err != nil {
		t.Fatalf("load AWS config: %v", err)
	}
}

func TestGetAWSAuthStatus(t *testing.T) {
	t.Parallel()

	expires := time.Date(2026, time.July, 18, 18, 42, 0, 0, time.FixedZone("test", 2*60*60))
	stsClient := &fakeSTSClient{
		getCallerIdentityFn: func(context.Context, *sts.GetCallerIdentityInput) (*sts.GetCallerIdentityOutput, error) {
			return &sts.GetCallerIdentityOutput{
				Account: aws.String("123456789012"),
				Arn:     aws.String("arn:aws:sts::123456789012:assumed-role/AuditRole/test"),
				UserId:  aws.String("AROATEST:test"),
			}, nil
		},
	}
	organizationsClient := &fakeOrganizationsClient{
		describeOrganizationFn: func(context.Context, *organizations.DescribeOrganizationInput) (*organizations.DescribeOrganizationOutput, error) {
			return &organizations.DescribeOrganizationOutput{Organization: &types.Organization{
				Id:              aws.String("o-exampleorgid"),
				MasterAccountId: aws.String("123456789012"),
			}}, nil
		},
	}

	status, err := getAWSAuthStatus(context.Background(), aws.Credentials{
		Source:    "SharedConfigCredentials: /home/test/.aws/credentials",
		CanExpire: true,
		Expires:   expires,
	}, stsClient, organizationsClient)
	if err != nil {
		t.Fatalf("get authentication status: %v", err)
	}
	if !status.OK || !status.Authenticated || !status.Organizations.Accessible {
		t.Fatalf("unexpected unsuccessful status: %#v", status)
	}
	if status.Identity.AccountID != "123456789012" || status.Organizations.OrganizationID != "o-exampleorgid" {
		t.Fatalf("unexpected authentication status: %#v", status)
	}
	if status.Credentials.ExpiresAt != "2026-07-18T16:42:00Z" {
		t.Fatalf("expiration is %q, want UTC RFC3339", status.Credentials.ExpiresAt)
	}
}

func TestGetAWSAuthStatusReportsOrganizationsDenial(t *testing.T) {
	t.Parallel()

	stsClient := &fakeSTSClient{
		getCallerIdentityFn: func(context.Context, *sts.GetCallerIdentityInput) (*sts.GetCallerIdentityOutput, error) {
			return &sts.GetCallerIdentityOutput{
				Account: aws.String("123456789012"),
				Arn:     aws.String("arn:aws:iam::123456789012:user/test"),
				UserId:  aws.String("AIDATEST"),
			}, nil
		},
	}
	organizationsClient := &fakeOrganizationsClient{
		describeOrganizationFn: func(context.Context, *organizations.DescribeOrganizationInput) (*organizations.DescribeOrganizationOutput, error) {
			return nil, &smithy.OperationError{
				ServiceID: "Organizations", OperationName: "DescribeOrganization",
				Err: &types.AccessDeniedException{Message: aws.String("unsafe provider detail")},
			}
		},
	}

	status, err := getAWSAuthStatus(
		context.Background(),
		aws.Credentials{Source: "EnvConfigCredentials"},
		stsClient,
		organizationsClient,
	)
	if err == nil {
		t.Fatal("get authentication status succeeded, want Organizations denial")
	}
	var apiErr smithy.APIError
	if !errors.As(err, &apiErr) || apiErr.ErrorCode() != "AccessDeniedException" {
		t.Fatalf("Organizations error did not preserve typed AWS error: %v", err)
	}
	if status.OK || !status.Authenticated || status.Organizations.Accessible {
		t.Fatalf("unexpected status: %#v", status)
	}
	if status.Organizations.Error != "AccessDeniedException" {
		t.Fatalf("Organizations error is %q", status.Organizations.Error)
	}
	if status.Organizations.Message != "AWS denied the Organizations request." {
		t.Fatalf("Organizations message is %q", status.Organizations.Message)
	}

	var output bytes.Buffer
	if writeErr := writeAWSAuthStatus(&output, status, json); writeErr != nil {
		t.Fatalf("write authentication status: %v", writeErr)
	}
	if strings.Contains(output.String(), "unsafe provider detail") {
		t.Fatalf("authentication status exposes AWS error detail: %s", output.String())
	}
}

func TestAWSAuthStatusOrganizationsFailurePreservesStdoutAndClassification(t *testing.T) {
	tests := map[string]struct {
		awsErr            error
		wantCode          string
		wantStatusError   string
		wantStatusMessage string
		wantExit          int
	}{
		"access denied": {
			awsErr: &smithy.OperationError{
				ServiceID: "Organizations", OperationName: "DescribeOrganization",
				Err: &types.AccessDeniedException{Message: aws.String("unsafe provider detail")},
			},
			wantCode:          errorCodeAuthorization,
			wantStatusError:   "AccessDeniedException",
			wantStatusMessage: "AWS denied the Organizations request.",
			wantExit:          exitAuthorization,
		},
		"transient server failure": {
			awsErr:            awsOperationError("DescribeOrganization", "InternalServerError", smithy.FaultServer),
			wantCode:          errorCodeTransient,
			wantStatusError:   "InternalServerError",
			wantStatusMessage: "AWS is temporarily unavailable or the request was throttled.",
			wantExit:          exitTransient,
		},
		"empty Smithy code": {
			awsErr: &smithy.OperationError{
				ServiceID: "Organizations", OperationName: "DescribeOrganization",
				Err: &smithy.GenericAPIError{Message: "unsafe provider detail", Fault: smithy.FaultClient},
			},
			wantCode:          errorCodeUnexpected,
			wantStatusError:   errorCodeUnexpected,
			wantStatusMessage: "Policy Scout could not complete the request.",
			wantExit:          exitUnexpected,
		},
		"whitespace Smithy code": {
			awsErr:            awsOperationError("DescribeOrganization", " \t ", smithy.FaultClient),
			wantCode:          errorCodeUnexpected,
			wantStatusError:   errorCodeUnexpected,
			wantStatusMessage: "Policy Scout could not complete the request.",
			wantExit:          exitUnexpected,
		},
		"missing organization details": {
			wantCode:          errorCodeUnexpected,
			wantStatusError:   errorCodeUnexpected,
			wantStatusMessage: "Policy Scout could not complete the request.",
			wantExit:          exitUnexpected,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			previousFormat := errorFormatValue
			errorFormatValue = errorFormatJSON
			t.Cleanup(func() { errorFormatValue = previousFormat })

			command := &cobra.Command{
				Use:           "status",
				SilenceErrors: true,
				SilenceUsage:  true,
				RunE: func(cmd *cobra.Command, _ []string) error {
					return runAWSAuthStatus(
						cmd.Context(),
						cmd.OutOrStdout(),
						aws.Credentials{Source: "EnvConfigCredentials"},
						&fakeSTSClient{getCallerIdentityFn: func(context.Context, *sts.GetCallerIdentityInput) (*sts.GetCallerIdentityOutput, error) {
							return &sts.GetCallerIdentityOutput{
								Account: aws.String("123456789012"),
								Arn:     aws.String("arn:aws:iam::123456789012:user/test"),
								UserId:  aws.String("AIDATEST"),
							}, nil
						}},
						&fakeOrganizationsClient{describeOrganizationFn: func(context.Context, *organizations.DescribeOrganizationInput) (*organizations.DescribeOrganizationOutput, error) {
							return nil, test.awsErr
						}},
						json,
					)
				},
			}

			var stdout, stderr bytes.Buffer
			if exitCode := executeCommand(command, nil, &stdout, &stderr); exitCode != test.wantExit {
				t.Fatalf("exit code = %d, want %d", exitCode, test.wantExit)
			}
			if !encodingjson.Valid(stdout.Bytes()) || strings.Contains(stdout.String(), "unsafe provider detail") {
				t.Fatalf("stdout is not sanitized status JSON: %q", stdout.String())
			}
			var status awsAuthStatus
			if err := encodingjson.Unmarshal(stdout.Bytes(), &status); err != nil {
				t.Fatalf("decode stdout status: %v", err)
			}
			if !status.Authenticated || status.Organizations.Accessible ||
				status.Organizations.Error != test.wantStatusError ||
				status.Organizations.Message != test.wantStatusMessage {
				t.Fatalf("stdout status does not preserve useful identity diagnostics: %#v", status)
			}
			var diagnostic classifiedError
			if err := encodingjson.Unmarshal(stderr.Bytes(), &diagnostic); err != nil {
				t.Fatalf("decode stderr diagnostic %q: %v", stderr.String(), err)
			}
			if diagnostic.Code != test.wantCode {
				t.Fatalf("stderr diagnostic = %#v, want code %q", diagnostic, test.wantCode)
			}
			if strings.Contains(stderr.String(), "unsafe provider detail") {
				t.Fatalf("stderr exposes AWS error detail: %q", stderr.String())
			}
		})
	}
}

func TestRunAWSAuthStatusReturnsWriteErrorBeforeOrganizationsError(t *testing.T) {
	t.Parallel()

	writeErr := errors.New("write failed")
	err := runAWSAuthStatus(
		context.Background(),
		&failingWriter{err: writeErr},
		aws.Credentials{Source: "EnvConfigCredentials"},
		&fakeSTSClient{getCallerIdentityFn: func(context.Context, *sts.GetCallerIdentityInput) (*sts.GetCallerIdentityOutput, error) {
			return &sts.GetCallerIdentityOutput{
				Account: aws.String("123456789012"),
				Arn:     aws.String("arn:aws:iam::123456789012:user/test"),
				UserId:  aws.String("AIDATEST"),
			}, nil
		}},
		&fakeOrganizationsClient{describeOrganizationFn: func(context.Context, *organizations.DescribeOrganizationInput) (*organizations.DescribeOrganizationOutput, error) {
			return nil, &types.AccessDeniedException{Message: aws.String("unsafe provider detail")}
		}},
		json,
	)
	if !errors.Is(err, writeErr) {
		t.Fatalf("run authentication status error = %v, want write error", err)
	}
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		t.Fatalf("run authentication status returned Organizations error instead of write error: %v", err)
	}
}

func TestWriteAWSAuthStatusJSON(t *testing.T) {
	t.Parallel()

	status := awsAuthStatus{
		OK:            true,
		Authenticated: true,
		Identity:      awsAuthIdentity{AccountID: "123456789012", ARN: "arn:example", UserID: "user"},
		Credentials:   awsAuthCredentials{Source: "EnvConfigCredentials"},
		Organizations: awsOrganizationsAuthStatus{Accessible: true, OrganizationID: "o-example"},
	}
	var output bytes.Buffer
	if err := writeAWSAuthStatus(&output, status, json); err != nil {
		t.Fatalf("write JSON authentication status: %v", err)
	}

	var decoded awsAuthStatus
	if err := encodingjson.Unmarshal(output.Bytes(), &decoded); err != nil {
		t.Fatalf("decode authentication status: %v", err)
	}
	if !decoded.OK || decoded.Identity.AccountID != "123456789012" {
		t.Fatalf("unexpected JSON authentication status: %#v", decoded)
	}
}

func TestListChildrenPaginatesAndSortsByID(t *testing.T) {
	t.Parallel()

	client := &fakeOrganizationsClient{
		listChildrenFn: func(_ context.Context, input *organizations.ListChildrenInput) (*organizations.ListChildrenOutput, error) {
			if input.NextToken == nil {
				return &organizations.ListChildrenOutput{
					Children: []types.Child{
						{Id: aws.String("333333333333"), Type: types.ChildTypeAccount},
						{Id: aws.String("111111111111"), Type: types.ChildTypeAccount},
					},
					NextToken: aws.String("next"),
				}, nil
			}
			return &organizations.ListChildrenOutput{Children: []types.Child{
				{Id: aws.String("222222222222"), Type: types.ChildTypeAccount},
				{Id: aws.String("111111111111"), Type: types.ChildTypeAccount},
			}}, nil
		},
	}

	children, err := listChildren(context.Background(), client, "r-root", types.ChildTypeAccount)
	if err != nil {
		t.Fatalf("list children: %v", err)
	}
	got := make([]string, len(children))
	for index, child := range children {
		got[index] = aws.ToString(child.Id)
	}
	want := []string{"111111111111", "222222222222", "333333333333"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("children are %v, want %v", got, want)
	}
}

func TestFullOrganizationOutputIsByteStableAcrossPaginatedChildOrder(t *testing.T) {
	t.Parallel()

	const (
		rootID            = "r-root"
		managementAccount = "111111111111"
	)

	newClient := func(scrambled bool) *fakeOrganizationsClient {
		pages := map[string][][]string{
			rootID + ":ACCOUNT": {
				{"333333333333", managementAccount},
				{"222222222222"},
			},
			rootID + ":ORGANIZATIONAL_UNIT": {
				{"ou-root-bbbb2222"},
				{"ou-root-aaaa1111"},
			},
			"ou-root-aaaa1111:ACCOUNT": {
				{"555555555555"},
				{"444444444444"},
			},
			"ou-root-aaaa1111:ORGANIZATIONAL_UNIT": {
				{"ou-root-dddd4444"},
				{"ou-root-cccc3333"},
			},
			"ou-root-bbbb2222:ACCOUNT":             {{}},
			"ou-root-bbbb2222:ORGANIZATIONAL_UNIT": {{}},
			"ou-root-cccc3333:ACCOUNT":             {{}},
			"ou-root-cccc3333:ORGANIZATIONAL_UNIT": {{}},
			"ou-root-dddd4444:ACCOUNT":             {{}},
			"ou-root-dddd4444:ORGANIZATIONAL_UNIT": {{}},
		}
		if scrambled {
			pages[rootID+":ACCOUNT"] = [][]string{{"222222222222"}, {managementAccount, "333333333333"}}
			pages[rootID+":ORGANIZATIONAL_UNIT"] = [][]string{{"ou-root-aaaa1111"}, {"ou-root-bbbb2222"}}
			pages["ou-root-aaaa1111:ACCOUNT"] = [][]string{{"444444444444"}, {"555555555555"}}
			pages["ou-root-aaaa1111:ORGANIZATIONAL_UNIT"] = [][]string{{"ou-root-cccc3333"}, {"ou-root-dddd4444"}}
		}

		return &fakeOrganizationsClient{
			listChildrenFn: func(_ context.Context, input *organizations.ListChildrenInput) (*organizations.ListChildrenOutput, error) {
				key := aws.ToString(input.ParentId) + ":" + string(input.ChildType)
				responsePages, ok := pages[key]
				if !ok {
					return nil, fmt.Errorf("unexpected children lookup %s", key)
				}
				pageIndex := 0
				if input.NextToken != nil {
					expectedToken := key + ":1"
					if aws.ToString(input.NextToken) != expectedToken {
						return nil, fmt.Errorf("unexpected pagination token %q for %s", aws.ToString(input.NextToken), key)
					}
					pageIndex = 1
				}
				if pageIndex >= len(responsePages) {
					return nil, fmt.Errorf("unexpected page %d for %s", pageIndex, key)
				}
				children := make([]types.Child, 0, len(responsePages[pageIndex]))
				for _, id := range responsePages[pageIndex] {
					children = append(children, types.Child{Id: aws.String(id), Type: input.ChildType})
				}
				output := &organizations.ListChildrenOutput{Children: children}
				if pageIndex+1 < len(responsePages) {
					output.NextToken = aws.String(key + ":1")
				}
				return output, nil
			},
			describeAccountFn: func(_ context.Context, input *organizations.DescribeAccountInput) (*organizations.DescribeAccountOutput, error) {
				id := aws.ToString(input.AccountId)
				name := map[string]string{
					"111111111111": "Management",
					"222222222222": "Audit",
					"333333333333": "Shared Services",
					"444444444444": "Payments",
					"555555555555": "Reporting",
				}[id]
				return &organizations.DescribeAccountOutput{Account: &types.Account{Id: input.AccountId, Name: aws.String(name)}}, nil
			},
			describeOrganizationalUnit: func(_ context.Context, input *organizations.DescribeOrganizationalUnitInput) (*organizations.DescribeOrganizationalUnitOutput, error) {
				id := aws.ToString(input.OrganizationalUnitId)
				name := map[string]string{
					"ou-root-aaaa1111": "Finance",
					"ou-root-bbbb2222": "Security",
					"ou-root-cccc3333": "Payroll",
					"ou-root-dddd4444": "Tax",
				}[id]
				return &organizations.DescribeOrganizationalUnitOutput{OrganizationalUnit: &types.OrganizationalUnit{
					Id: input.OrganizationalUnitId, Name: aws.String(name),
				}}, nil
			},
			listPoliciesForTargetFn: func(context.Context, *organizations.ListPoliciesForTargetInput) (*organizations.ListPoliciesForTargetOutput, error) {
				return &organizations.ListPoliciesForTargetOutput{}, nil
			},
		}
	}

	wantJSON := `{
  "schema_version": "1",
  "selection": {
    "type": "all"
  },
  "type": "root",
  "id": "r-root",
  "name": "Root",
  "children": [
    {
      "type": "account",
      "id": "111111111111",
      "name": "Management",
      "management_account": true
    },
    {
      "type": "account",
      "id": "222222222222",
      "name": "Audit",
      "management_account": false,
      "scps": [],
      "scp_attachments": []
    },
    {
      "type": "account",
      "id": "333333333333",
      "name": "Shared Services",
      "management_account": false,
      "scps": [],
      "scp_attachments": []
    },
    {
      "type": "organizational_unit",
      "id": "ou-root-aaaa1111",
      "name": "Finance",
      "scps": [],
      "scp_attachments": [],
      "children": [
        {
          "type": "account",
          "id": "444444444444",
          "name": "Payments",
          "management_account": false,
          "scps": [],
          "scp_attachments": []
        },
        {
          "type": "account",
          "id": "555555555555",
          "name": "Reporting",
          "management_account": false,
          "scps": [],
          "scp_attachments": []
        },
        {
          "type": "organizational_unit",
          "id": "ou-root-cccc3333",
          "name": "Payroll",
          "scps": [],
          "scp_attachments": [],
          "children": []
        },
        {
          "type": "organizational_unit",
          "id": "ou-root-dddd4444",
          "name": "Tax",
          "scps": [],
          "scp_attachments": [],
          "children": []
        }
      ]
    },
    {
      "type": "organizational_unit",
      "id": "ou-root-bbbb2222",
      "name": "Security",
      "scps": [],
      "scp_attachments": [],
      "children": []
    }
  ]
}
`
	wantText := organizationTextGolden(t, "full-organization")

	tests := []struct {
		format outputFormat
		want   string
	}{
		{format: json, want: wantJSON},
		{format: text, want: wantText},
	}
	for _, test := range tests {
		test := test
		t.Run(string(test.format), func(t *testing.T) {
			t.Parallel()

			var first bytes.Buffer
			var second bytes.Buffer
			if err := displayOrganizationTree(
				context.Background(), &first, newClient(false), "all", rootID, "Root", managementAccount, test.format,
			); err != nil {
				t.Fatalf("render first %s output: %v", test.format, err)
			}
			if err := displayOrganizationTree(
				context.Background(), &second, newClient(true), "all", rootID, "Root", managementAccount, test.format,
			); err != nil {
				t.Fatalf("render second %s output: %v", test.format, err)
			}
			if first.String() != test.want {
				t.Fatalf("first %s output:\n%s\nwant:\n%s", test.format, first.String(), test.want)
			}
			if second.String() != test.want {
				t.Fatalf("second %s output:\n%s\nwant:\n%s", test.format, second.String(), test.want)
			}
			if !bytes.Equal(first.Bytes(), second.Bytes()) {
				t.Fatalf("%s output changed with AWS child order:\nfirst:\n%s\nsecond:\n%s", test.format, first.Bytes(), second.Bytes())
			}
		})
	}
}

func TestListChildrenRejectsMissingID(t *testing.T) {
	t.Parallel()

	client := &fakeOrganizationsClient{
		listChildrenFn: func(context.Context, *organizations.ListChildrenInput) (*organizations.ListChildrenOutput, error) {
			return &organizations.ListChildrenOutput{Children: []types.Child{{}}}, nil
		},
	}
	_, err := listChildren(context.Background(), client, "r-root", types.ChildTypeAccount)
	if err == nil || !strings.Contains(err.Error(), "without an ID") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestListChildrenRejectsMismatchedType(t *testing.T) {
	t.Parallel()

	client := &fakeOrganizationsClient{
		listChildrenFn: func(context.Context, *organizations.ListChildrenInput) (*organizations.ListChildrenOutput, error) {
			return &organizations.ListChildrenOutput{Children: []types.Child{{
				Id:   aws.String("123456789012"),
				Type: types.ChildTypeOrganizationalUnit,
			}}}, nil
		},
	}
	_, err := listChildren(context.Background(), client, "r-root", types.ChildTypeAccount)
	if err == nil || !strings.Contains(err.Error(), "expected ACCOUNT") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestPaginationRejectsImmediatelyRepeatedToken(t *testing.T) {
	t.Parallel()

	calls := 0
	client := &fakeOrganizationsClient{
		listChildrenFn: func(context.Context, *organizations.ListChildrenInput) (*organizations.ListChildrenOutput, error) {
			calls++
			if calls > 2 {
				return nil, errors.New("unexpected third pagination request")
			}
			return &organizations.ListChildrenOutput{NextToken: aws.String("repeated")}, nil
		},
	}
	_, err := listChildren(context.Background(), client, "r-root", types.ChildTypeAccount)
	if err == nil || !strings.Contains(err.Error(), "repeated pagination token") {
		t.Fatalf("unexpected error: %v", err)
	}
	if calls != 2 {
		t.Fatalf("API called %d times, want 2", calls)
	}
}

func TestPaginationRejectsNonAdjacentTokenCycle(t *testing.T) {
	t.Parallel()

	calls := 0
	tokens := []string{"token-a", "token-b", "token-a"}
	client := &fakeOrganizationsClient{
		listParentsFn: func(context.Context, *organizations.ListParentsInput) (*organizations.ListParentsOutput, error) {
			if calls >= len(tokens) {
				return nil, errors.New("unexpected extra pagination request")
			}
			token := tokens[calls]
			calls++
			return &organizations.ListParentsOutput{NextToken: aws.String(token)}, nil
		},
	}
	_, err := listParents(context.Background(), client, "123456789012")
	if err == nil || !strings.Contains(err.Error(), "repeated pagination token") {
		t.Fatalf("unexpected error: %v", err)
	}
	if calls != 3 {
		t.Fatalf("API called %d times, want 3", calls)
	}
}

func TestListOperationsPaginate(t *testing.T) {
	t.Parallel()

	client := &fakeOrganizationsClient{
		listParentsFn: func(_ context.Context, input *organizations.ListParentsInput) (*organizations.ListParentsOutput, error) {
			if input.NextToken == nil {
				return &organizations.ListParentsOutput{NextToken: aws.String("next")}, nil
			}
			return &organizations.ListParentsOutput{Parents: []types.Parent{{Id: aws.String("r-root"), Type: types.ParentTypeRoot}}}, nil
		},
		listPoliciesForTargetFn: func(_ context.Context, input *organizations.ListPoliciesForTargetInput) (*organizations.ListPoliciesForTargetOutput, error) {
			if input.NextToken == nil {
				return &organizations.ListPoliciesForTargetOutput{Policies: []types.PolicySummary{{Id: aws.String("p-00000001"), Name: aws.String("PolicyOne"), Type: types.PolicyTypeServiceControlPolicy}}, NextToken: aws.String("next")}, nil
			}
			return &organizations.ListPoliciesForTargetOutput{Policies: []types.PolicySummary{{Id: aws.String("p-00000002"), Name: aws.String("PolicyTwo"), Type: types.PolicyTypeServiceControlPolicy}}}, nil
		},
		listRootsFn: func(_ context.Context, input *organizations.ListRootsInput) (*organizations.ListRootsOutput, error) {
			if input.NextToken == nil {
				return &organizations.ListRootsOutput{NextToken: aws.String("next")}, nil
			}
			return &organizations.ListRootsOutput{Roots: []types.Root{{
				Id: aws.String("r-root"), Name: aws.String("Organization Root"),
			}}}, nil
		},
	}

	parents, err := listParents(context.Background(), client, "123456789012")
	if err != nil || len(parents) != 1 {
		t.Fatalf("parents: got %d, error %v", len(parents), err)
	}
	policies, err := listSCPsForTarget(context.Background(), client, "123456789012")
	if err != nil || len(policies) != 2 {
		t.Fatalf("policies: got %d, error %v", len(policies), err)
	}
	rootID, rootName, err := getRoot(context.Background(), client)
	if err != nil || rootID != "r-root" || rootName != "Organization Root" {
		t.Fatalf("root: got %q (%q), error %v", rootID, rootName, err)
	}
}

func TestHierarchyOperationsRejectMalformedAWSIdentifiers(t *testing.T) {
	t.Parallel()

	t.Run("root", func(t *testing.T) {
		t.Parallel()
		client := &fakeOrganizationsClient{listRootsFn: func(context.Context, *organizations.ListRootsInput) (*organizations.ListRootsOutput, error) {
			return &organizations.ListRootsOutput{Roots: []types.Root{{Id: aws.String("ou-root-12345678")}}}, nil
		}}
		if _, _, err := getRoot(context.Background(), client); err == nil || !strings.Contains(err.Error(), "invalid organization root ID") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("OU parent", func(t *testing.T) {
		t.Parallel()
		client := &fakeOrganizationsClient{listParentsFn: func(context.Context, *organizations.ListParentsInput) (*organizations.ListParentsOutput, error) {
			return &organizations.ListParentsOutput{Parents: []types.Parent{{
				Id: aws.String("ou-x-12345678"), Type: types.ParentTypeOrganizationalUnit,
			}}}, nil
		}}
		if _, err := listParents(context.Background(), client, "123456789012"); err == nil || !strings.Contains(err.Error(), "invalid ID") {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

func TestBuildOrganizationTreeAccountPathWalksUpwardAndListsInheritedPolicies(t *testing.T) {
	t.Parallel()

	const (
		rootID    = "r-root"
		ouID      = "ou-root-12345678"
		accountID = "123456789012"
	)
	listChildrenCalls := 0
	client := &fakeOrganizationsClient{
		listChildrenFn: func(context.Context, *organizations.ListChildrenInput) (*organizations.ListChildrenOutput, error) {
			listChildrenCalls++
			return nil, errors.New("single-account lookup must not list children")
		},
		describeAccountFn: func(context.Context, *organizations.DescribeAccountInput) (*organizations.DescribeAccountOutput, error) {
			return &organizations.DescribeAccountOutput{Account: &types.Account{Id: aws.String(accountID), Name: aws.String("Application")}}, nil
		},
		describeOrganizationalUnit: func(context.Context, *organizations.DescribeOrganizationalUnitInput) (*organizations.DescribeOrganizationalUnitOutput, error) {
			return &organizations.DescribeOrganizationalUnitOutput{OrganizationalUnit: &types.OrganizationalUnit{Id: aws.String(ouID), Name: aws.String("Production")}}, nil
		},
		listParentsFn: func(_ context.Context, input *organizations.ListParentsInput) (*organizations.ListParentsOutput, error) {
			switch aws.ToString(input.ChildId) {
			case accountID:
				return &organizations.ListParentsOutput{Parents: []types.Parent{{Id: aws.String(ouID), Type: types.ParentTypeOrganizationalUnit}}}, nil
			case ouID:
				return &organizations.ListParentsOutput{Parents: []types.Parent{{Id: aws.String(rootID), Type: types.ParentTypeRoot}}}, nil
			default:
				return nil, errors.New("unexpected parent lookup")
			}
		},
		listPoliciesForTargetFn: func(_ context.Context, input *organizations.ListPoliciesForTargetInput) (*organizations.ListPoliciesForTargetOutput, error) {
			switch aws.ToString(input.TargetId) {
			case accountID:
				return &organizations.ListPoliciesForTargetOutput{Policies: []types.PolicySummary{{Id: aws.String("p-deny0001"), Name: aws.String("DenyS3"), Type: types.PolicyTypeServiceControlPolicy}}}, nil
			case ouID:
				return &organizations.ListPoliciesForTargetOutput{Policies: []types.PolicySummary{
					{Id: aws.String("p-full0001"), Name: aws.String("FullAWSAccess"), Type: types.PolicyTypeServiceControlPolicy},
					{Id: aws.String("p-second01"), Name: aws.String("SameName"), Type: types.PolicyTypeServiceControlPolicy},
				}}, nil
			case rootID:
				return &organizations.ListPoliciesForTargetOutput{Policies: []types.PolicySummary{
					{Id: aws.String("p-full0001"), Name: aws.String("FullAWSAccess"), Type: types.PolicyTypeServiceControlPolicy},
					{Id: aws.String("p-first001"), Name: aws.String("SameName"), Type: types.PolicyTypeServiceControlPolicy},
				}}, nil
			default:
				return nil, errors.New("unexpected policy lookup")
			}
		},
	}

	tree, err := buildOrganizationTree(
		context.Background(),
		client,
		accountID,
		rootID,
		"Organization Root",
		"999999999999",
	)
	if err != nil {
		t.Fatalf("build path: %v", err)
	}
	if tree.Selection != (organizationSelection{Type: accountEntityType, TargetID: accountID}) {
		t.Fatalf("account selection = %+v", tree.Selection)
	}
	if tree.Name != "Organization Root" {
		t.Fatalf("root name = %q, want %q", tree.Name, "Organization Root")
	}
	if listChildrenCalls != 0 {
		t.Fatalf("list children called %d times", listChildrenCalls)
	}
	output := renderOrganizationTreeText(tree)
	want := organizationTextGolden(t, "single-account")
	if output != want {
		t.Fatalf("unexpected output:\n%s\nwant:\n%s", output, want)
	}
}

func TestBuildOrganizationTreeOrganizationalUnitPathWalksUpwardAndListsInheritedPolicies(t *testing.T) {
	t.Parallel()

	const (
		rootID   = "r-root"
		parentID = "ou-root-11111111"
		targetID = "ou-root-22222222"
	)
	listChildrenCalls := 0
	client := &fakeOrganizationsClient{
		listChildrenFn: func(context.Context, *organizations.ListChildrenInput) (*organizations.ListChildrenOutput, error) {
			listChildrenCalls++
			return nil, errors.New("single-OU lookup must not list children")
		},
		describeAccountFn: func(context.Context, *organizations.DescribeAccountInput) (*organizations.DescribeAccountOutput, error) {
			return nil, errors.New("single-OU lookup must not describe accounts")
		},
		describeOrganizationalUnit: func(_ context.Context, input *organizations.DescribeOrganizationalUnitInput) (*organizations.DescribeOrganizationalUnitOutput, error) {
			name := map[string]string{parentID: "Production", targetID: "Workloads"}[aws.ToString(input.OrganizationalUnitId)]
			return &organizations.DescribeOrganizationalUnitOutput{OrganizationalUnit: &types.OrganizationalUnit{
				Id: input.OrganizationalUnitId, Name: aws.String(name),
			}}, nil
		},
		listParentsFn: func(_ context.Context, input *organizations.ListParentsInput) (*organizations.ListParentsOutput, error) {
			switch aws.ToString(input.ChildId) {
			case targetID:
				return &organizations.ListParentsOutput{Parents: []types.Parent{{Id: aws.String(parentID), Type: types.ParentTypeOrganizationalUnit}}}, nil
			case parentID:
				return &organizations.ListParentsOutput{Parents: []types.Parent{{Id: aws.String(rootID), Type: types.ParentTypeRoot}}}, nil
			default:
				return nil, errors.New("unexpected parent lookup")
			}
		},
		listPoliciesForTargetFn: func(_ context.Context, input *organizations.ListPoliciesForTargetInput) (*organizations.ListPoliciesForTargetOutput, error) {
			policies := map[string]types.PolicySummary{
				rootID:   {Id: aws.String("p-root0001"), Name: aws.String("RootPolicy"), Type: types.PolicyTypeServiceControlPolicy},
				parentID: {Id: aws.String("p-parent01"), Name: aws.String("ParentPolicy"), Type: types.PolicyTypeServiceControlPolicy},
				targetID: {Id: aws.String("p-target01"), Name: aws.String("TargetPolicy"), Type: types.PolicyTypeServiceControlPolicy},
			}
			return &organizations.ListPoliciesForTargetOutput{Policies: []types.PolicySummary{policies[aws.ToString(input.TargetId)]}}, nil
		},
	}

	tree, err := buildOrganizationTree(context.Background(), client, targetID, rootID, "Organization Root", "999999999999")
	if err != nil {
		t.Fatalf("build OU path: %v", err)
	}
	if tree.Selection != (organizationSelection{Type: organizationalUnitEntityType, TargetID: targetID}) {
		t.Fatalf("organizational-unit selection = %+v", tree.Selection)
	}
	if tree.Name != "Organization Root" {
		t.Fatalf("root name = %q, want %q", tree.Name, "Organization Root")
	}
	if listChildrenCalls != 0 {
		t.Fatalf("list children called %d times", listChildrenCalls)
	}
	if len(tree.Children) != 1 || len(tree.Children[0].Children) != 1 {
		t.Fatalf("unexpected OU path: %+v", tree)
	}
	parent := tree.Children[0]
	target := parent.Children[0]
	if parent.ID != parentID || target.ID != targetID || len(target.Children) != 0 {
		t.Fatalf("unexpected OU path nodes: parent=%+v target=%+v", parent, target)
	}
	if strings.Join(target.SCPs, ",") != "ParentPolicy,RootPolicy,TargetPolicy" {
		t.Fatalf("target OU SCPs = %v", target.SCPs)
	}
	wantInherited := map[string]bool{"RootPolicy": true, "ParentPolicy": true, "TargetPolicy": false}
	for _, attachment := range target.SCPAttachments {
		if attachment.Inherited != wantInherited[attachment.PolicyName] {
			t.Fatalf("attachment %+v has unexpected inheritance", attachment)
		}
	}
	if output := renderOrganizationTreeText(tree); output != organizationTextGolden(t, "single-ou") {
		t.Fatalf("unexpected output:\n%s\nwant:\n%s", output, organizationTextGolden(t, "single-ou"))
	}
}

func TestInspectOrganizationalUnitDirectlyUnderRootSkipsDescribeOrganization(t *testing.T) {
	t.Parallel()

	const (
		rootID   = "r-root"
		targetID = "ou-root-12345678"
	)
	describeOrganizationCalls := 0
	client := &fakeOrganizationsClient{
		describeOrganizationFn: func(context.Context, *organizations.DescribeOrganizationInput) (*organizations.DescribeOrganizationOutput, error) {
			describeOrganizationCalls++
			return nil, errors.New("OU inspection must not describe the organization")
		},
		describeOrganizationalUnit: func(context.Context, *organizations.DescribeOrganizationalUnitInput) (*organizations.DescribeOrganizationalUnitOutput, error) {
			return &organizations.DescribeOrganizationalUnitOutput{OrganizationalUnit: &types.OrganizationalUnit{
				Id: aws.String(targetID), Name: aws.String("Production"),
			}}, nil
		},
		listParentsFn: func(context.Context, *organizations.ListParentsInput) (*organizations.ListParentsOutput, error) {
			return &organizations.ListParentsOutput{Parents: []types.Parent{{
				Id: aws.String(rootID), Type: types.ParentTypeRoot,
			}}}, nil
		},
	}

	var output bytes.Buffer
	if err := inspectOrganizationTarget(
		context.Background(), &output, client, targetID, rootID, "Organization Root", json,
	); err != nil {
		t.Fatalf("inspect OU: %v", err)
	}
	if describeOrganizationCalls != 0 {
		t.Fatalf("DescribeOrganization called %d times, want 0", describeOrganizationCalls)
	}

	var tree organizationNode
	if err := encodingjson.Unmarshal(output.Bytes(), &tree); err != nil {
		t.Fatalf("decode output: %v", err)
	}
	var metadata struct {
		Selection organizationJSONSelection `json:"selection"`
	}
	if err := encodingjson.Unmarshal(output.Bytes(), &metadata); err != nil {
		t.Fatalf("decode selection metadata: %v", err)
	}
	if metadata.Selection != (organizationJSONSelection{Type: organizationalUnitEntityType, TargetID: targetID}) {
		t.Fatalf("selection metadata = %+v", metadata.Selection)
	}
	if tree.Name != "Organization Root" {
		t.Fatalf("root name = %q, want %q", tree.Name, "Organization Root")
	}
	if len(tree.Children) != 1 || tree.Children[0].ID != targetID || len(tree.Children[0].Children) != 0 {
		t.Fatalf("unexpected direct-child OU path: %+v", tree)
	}
}

func TestInspectAccountAndFullOrganizationDescribeOrganization(t *testing.T) {
	t.Parallel()

	sentinel := errors.New("stop after DescribeOrganization")
	for _, targetID := range []string{"123456789012", "all"} {
		targetID := targetID
		t.Run(targetID, func(t *testing.T) {
			t.Parallel()
			describeOrganizationCalls := 0
			client := &fakeOrganizationsClient{describeOrganizationFn: func(context.Context, *organizations.DescribeOrganizationInput) (*organizations.DescribeOrganizationOutput, error) {
				describeOrganizationCalls++
				return nil, sentinel
			}}

			err := inspectOrganizationTarget(
				context.Background(), &bytes.Buffer{}, client, targetID, "r-root", "Organization Root", json,
			)
			if !errors.Is(err, sentinel) {
				t.Fatalf("error = %v, want sentinel error", err)
			}
			if describeOrganizationCalls != 1 {
				t.Fatalf("DescribeOrganization called %d times, want 1", describeOrganizationCalls)
			}
		})
	}
}

func TestBuildOrganizationalUnitPathRejectsInvalidRootRelationshipsWithoutPanic(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		targetID string
		rootID   string
		wantErr  string
	}{
		"target reported as root": {
			targetID: "ou-root-12345678", rootID: "ou-root-12345678", wantErr: "invalid root ID",
		},
		"OU belongs to another root": {
			targetID: "ou-other-12345678", rootID: "r-root", wantErr: "does not belong to root",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := buildOrganizationalUnitPath(
				context.Background(),
				&fakeOrganizationsClient{},
				test.targetID,
				test.rootID,
				newOrganizationCache(test.rootID, ""),
			)
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("error = %v, want it to contain %q", err, test.wantErr)
			}
		})
	}
}

func TestBuildOrganizationTreeAllLocalizesPoliciesOnOrganizationalUnits(t *testing.T) {
	t.Parallel()

	const (
		rootID   = "r-root"
		ouID     = "ou-root-12345678"
		policyID = "p-full0001"
	)
	policyCalls := make(map[string]int)
	client := &fakeOrganizationsClient{
		listChildrenFn: func(_ context.Context, input *organizations.ListChildrenInput) (*organizations.ListChildrenOutput, error) {
			parentID := aws.ToString(input.ParentId)
			if parentID == rootID && input.ChildType == types.ChildTypeOrganizationalUnit {
				return &organizations.ListChildrenOutput{Children: []types.Child{{
					Id: aws.String(ouID), Type: types.ChildTypeOrganizationalUnit,
				}}}, nil
			}
			if (parentID == rootID && input.ChildType == types.ChildTypeAccount) || parentID == ouID {
				return &organizations.ListChildrenOutput{}, nil
			}
			return nil, fmt.Errorf("unexpected children lookup for %s/%s", parentID, input.ChildType)
		},
		describeOrganizationalUnit: func(context.Context, *organizations.DescribeOrganizationalUnitInput) (*organizations.DescribeOrganizationalUnitOutput, error) {
			return &organizations.DescribeOrganizationalUnitOutput{OrganizationalUnit: &types.OrganizationalUnit{
				Id: aws.String(ouID), Name: aws.String("Production"),
			}}, nil
		},
		listPoliciesForTargetFn: func(_ context.Context, input *organizations.ListPoliciesForTargetInput) (*organizations.ListPoliciesForTargetOutput, error) {
			targetID := aws.ToString(input.TargetId)
			policyCalls[targetID]++
			if targetID != rootID && targetID != ouID {
				return nil, fmt.Errorf("unexpected policy lookup for %s", targetID)
			}
			return &organizations.ListPoliciesForTargetOutput{Policies: []types.PolicySummary{{
				Id: aws.String(policyID), Name: aws.String("FullAWSAccess"), Type: types.PolicyTypeServiceControlPolicy,
			}}}, nil
		},
	}

	tree, err := buildOrganizationTree(context.Background(), client, "all", rootID, "Organization Root", "999999999999")
	if err != nil {
		t.Fatalf("build full organization: %v", err)
	}
	if len(tree.Children) != 1 {
		t.Fatalf("root children = %d, want 1", len(tree.Children))
	}
	ou := tree.Children[0]
	wantAttachments := []scpAttachment{
		{
			PolicyID:   policyID,
			PolicyName: "FullAWSAccess",
			AttachedTo: scpAttachmentTarget{Type: rootEntityType, ID: rootID, Name: "Organization Root"},
			Inherited:  true,
		},
		{
			PolicyID:   policyID,
			PolicyName: "FullAWSAccess",
			AttachedTo: scpAttachmentTarget{Type: organizationalUnitEntityType, ID: ouID, Name: "Production"},
			Inherited:  false,
		},
	}
	if ou.Type != organizationalUnitEntityType || ou.ID != ouID || ou.Name != "Production" ||
		!reflect.DeepEqual(ou.SCPs, []string{"FullAWSAccess"}) ||
		!reflect.DeepEqual(ou.SCPAttachments, wantAttachments) {
		t.Fatalf("unexpected organizational unit: %+v", ou)
	}
	for _, targetID := range []string{rootID, ouID} {
		if policyCalls[targetID] != 1 {
			t.Fatalf("policies for %s listed %d times, want once", targetID, policyCalls[targetID])
		}
	}
}

func TestDisplayOrganizationTreeReturnsLookupErrorWithoutOutput(t *testing.T) {
	t.Parallel()

	client := &fakeOrganizationsClient{
		describeAccountFn: func(context.Context, *organizations.DescribeAccountInput) (*organizations.DescribeAccountOutput, error) {
			return nil, errors.New("account not found")
		},
	}
	var output bytes.Buffer
	err := displayOrganizationTree(
		context.Background(), &output, client, "123456789012", "r-root", "", "999999999999", text,
	)
	if err == nil || !strings.Contains(err.Error(), "describe account 123456789012") {
		t.Fatalf("unexpected error: %v", err)
	}
	if output.Len() != 0 {
		t.Fatalf("discovery error emitted partial output: %q", output.String())
	}
}

func TestDisplayOrganizationTreeDoesNotEmitPartialDocumentOnTraversalError(t *testing.T) {
	t.Parallel()

	const accountID = "123456789012"
	for _, outputFormat := range []outputFormat{text, json} {
		outputFormat := outputFormat
		t.Run(string(outputFormat), func(t *testing.T) {
			t.Parallel()

			client := &fakeOrganizationsClient{
				listChildrenFn: func(_ context.Context, input *organizations.ListChildrenInput) (*organizations.ListChildrenOutput, error) {
					if input.ChildType == types.ChildTypeAccount {
						return &organizations.ListChildrenOutput{Children: []types.Child{{
							Id: aws.String(accountID), Type: types.ChildTypeAccount,
						}}}, nil
					}
					return nil, errors.New("organizational units unavailable")
				},
				describeAccountFn: func(context.Context, *organizations.DescribeAccountInput) (*organizations.DescribeAccountOutput, error) {
					return &organizations.DescribeAccountOutput{Account: &types.Account{
						Id: aws.String(accountID), Name: aws.String("Application"),
					}}, nil
				},
			}

			var output bytes.Buffer
			err := displayOrganizationTree(
				context.Background(), &output, client, "all", "r-root", "", "999999999999", outputFormat,
			)
			if err == nil || !strings.Contains(err.Error(), "list organizational units for r-root") {
				t.Fatalf("unexpected error: %v", err)
			}
			if output.Len() != 0 {
				t.Fatalf("discovery error emitted partial %s document: %q", outputFormat, output.String())
			}
		})
	}
}

func TestDescribeResponsesRequireMatchingIDsAndNames(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		account *types.Account
		want    string
	}{
		"missing ID":    {account: &types.Account{Name: aws.String("Account")}, want: "returned account ID"},
		"mismatched ID": {account: &types.Account{Id: aws.String("999999999999"), Name: aws.String("Account")}, want: "returned account ID"},
		"missing name":  {account: &types.Account{Id: aws.String("123456789012")}, want: "no name"},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			client := &fakeOrganizationsClient{
				describeAccountFn: func(context.Context, *organizations.DescribeAccountInput) (*organizations.DescribeAccountOutput, error) {
					return &organizations.DescribeAccountOutput{Account: test.account}, nil
				},
			}
			_, err := getAccount(context.Background(), client, "123456789012")
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestListSCPsForPathPreservesUnambiguousAttachmentProvenance(t *testing.T) {
	t.Parallel()

	const (
		rootID    = "r-root"
		ouID      = "ou-root-12345678"
		accountID = "123456789012"
	)
	policyCalls := make(map[string]int)
	client := &fakeOrganizationsClient{
		listPoliciesForTargetFn: func(_ context.Context, input *organizations.ListPoliciesForTargetInput) (*organizations.ListPoliciesForTargetOutput, error) {
			targetID := aws.ToString(input.TargetId)
			policyCalls[targetID]++
			switch targetID {
			case rootID:
				return &organizations.ListPoliciesForTargetOutput{Policies: []types.PolicySummary{
					{Id: aws.String("p-shared01"), Name: aws.String("Shared"), Type: types.PolicyTypeServiceControlPolicy},
					{Id: aws.String("p-first001"), Name: aws.String("SameName"), Type: types.PolicyTypeServiceControlPolicy},
				}}, nil
			case ouID:
				return &organizations.ListPoliciesForTargetOutput{Policies: []types.PolicySummary{
					{Id: aws.String("p-shared01"), Name: aws.String("Shared"), Type: types.PolicyTypeServiceControlPolicy},
					{Id: aws.String("p-second01"), Name: aws.String("SameName"), Type: types.PolicyTypeServiceControlPolicy},
				}}, nil
			case accountID:
				return &organizations.ListPoliciesForTargetOutput{Policies: []types.PolicySummary{
					{Id: aws.String("p-direct001"), Name: aws.String("Direct"), Type: types.PolicyTypeServiceControlPolicy},
					{Id: aws.String("p-direct001"), Name: aws.String("Direct"), Type: types.PolicyTypeServiceControlPolicy},
					{Id: aws.String("p-shared01"), Name: aws.String("Shared"), Type: types.PolicyTypeServiceControlPolicy},
				}}, nil
			default:
				return nil, errors.New("unexpected policy lookup")
			}
		},
	}

	cache := newOrganizationCache(rootID, "Organization Root")
	cache.entityNames[ouID] = "Production"
	cache.entityNames[accountID] = "Application"
	names, attachments, err := listSCPsForPath(
		context.Background(),
		client,
		[]string{rootID, ouID, accountID},
		cache,
	)
	if err != nil {
		t.Fatalf("list policies: %v", err)
	}
	wantNames := []string{"Direct", "SameName", "Shared"}
	if !reflect.DeepEqual(names, wantNames) {
		t.Fatalf("got names %v, want %v", names, wantNames)
	}
	wantAttachments := []scpAttachment{
		{
			PolicyID:   "p-direct001",
			PolicyName: "Direct",
			AttachedTo: scpAttachmentTarget{Type: "account", ID: accountID, Name: "Application"},
			Inherited:  false,
		},
		{
			PolicyID:   "p-first001",
			PolicyName: "SameName",
			AttachedTo: scpAttachmentTarget{Type: "root", ID: rootID, Name: "Organization Root"},
			Inherited:  true,
		},
		{
			PolicyID:   "p-second01",
			PolicyName: "SameName",
			AttachedTo: scpAttachmentTarget{Type: "organizational_unit", ID: ouID, Name: "Production"},
			Inherited:  true,
		},
		{
			PolicyID:   "p-shared01",
			PolicyName: "Shared",
			AttachedTo: scpAttachmentTarget{Type: "root", ID: rootID, Name: "Organization Root"},
			Inherited:  true,
		},
		{
			PolicyID:   "p-shared01",
			PolicyName: "Shared",
			AttachedTo: scpAttachmentTarget{Type: "organizational_unit", ID: ouID, Name: "Production"},
			Inherited:  true,
		},
		{
			PolicyID:   "p-shared01",
			PolicyName: "Shared",
			AttachedTo: scpAttachmentTarget{Type: "account", ID: accountID, Name: "Application"},
			Inherited:  false,
		},
	}
	if !reflect.DeepEqual(attachments, wantAttachments) {
		t.Fatalf("got attachments\n%+v\nwant\n%+v", attachments, wantAttachments)
	}
	for _, targetID := range []string{rootID, ouID, accountID} {
		if policyCalls[targetID] != 1 {
			t.Fatalf("policies for %s listed %d times, want once", targetID, policyCalls[targetID])
		}
	}
}

func TestListSCPsForPathRejectsConflictingSummaries(t *testing.T) {
	t.Parallel()

	tests := map[string]map[string][]types.PolicySummary{
		"same ID with different names": {
			"r-root":       {{Id: aws.String("p-00000001"), Name: aws.String("First"), Type: types.PolicyTypeServiceControlPolicy}},
			"123456789012": {{Id: aws.String("p-00000001"), Name: aws.String("Second"), Type: types.PolicyTypeServiceControlPolicy}},
		},
	}
	for name, cache := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, _, err := listSCPsForPath(
				context.Background(),
				&fakeOrganizationsClient{},
				[]string{"r-root", "123456789012"},
				&organizationCache{policiesByTarget: cache, entityNames: map[string]string{}},
			)
			if err == nil || !strings.Contains(err.Error(), "conflicting") {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestListSCPsRejectsMissingFields(t *testing.T) {
	t.Parallel()

	tests := map[string]types.PolicySummary{
		"missing ID":     {Name: aws.String("Policy"), Type: types.PolicyTypeServiceControlPolicy},
		"missing name":   {Id: aws.String("p-00000001"), Type: types.PolicyTypeServiceControlPolicy},
		"invalid ID":     {Id: aws.String("p-short"), Name: aws.String("Policy"), Type: types.PolicyTypeServiceControlPolicy},
		"non-SCP policy": {Id: aws.String("p-00000001"), Name: aws.String("Policy"), Type: types.PolicyType("RESOURCE_CONTROL_POLICY")},
	}
	for name, policy := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			client := &fakeOrganizationsClient{
				listPoliciesForTargetFn: func(context.Context, *organizations.ListPoliciesForTargetInput) (*organizations.ListPoliciesForTargetOutput, error) {
					return &organizations.ListPoliciesForTargetOutput{Policies: []types.PolicySummary{policy}}, nil
				},
			}
			_, err := listSCPsForTarget(context.Background(), client, "r-root")
			if err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

func TestManagementAccountIDMustBeAnAccountID(t *testing.T) {
	t.Parallel()

	client := &fakeOrganizationsClient{
		describeOrganizationFn: func(context.Context, *organizations.DescribeOrganizationInput) (*organizations.DescribeOrganizationOutput, error) {
			return &organizations.DescribeOrganizationOutput{Organization: &types.Organization{MasterAccountId: aws.String("all")}}, nil
		},
	}
	_, err := getManagementAccountID(context.Background(), client)
	if err == nil || !strings.Contains(err.Error(), "invalid management account ID") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestBuildManagementAccountDoesNotListSCPs(t *testing.T) {
	t.Parallel()

	policyCalls := 0
	client := &fakeOrganizationsClient{
		listPoliciesForTargetFn: func(context.Context, *organizations.ListPoliciesForTargetInput) (*organizations.ListPoliciesForTargetOutput, error) {
			policyCalls++
			return nil, errors.New("SCPs must not be queried for the management account")
		},
	}
	node, err := buildAccountNode(
		context.Background(),
		client,
		"123456789012",
		"Management",
		"123456789012",
		[]string{"r-root", "123456789012"},
		newOrganizationCache("r-root", "Organization Root"),
	)
	if err != nil {
		t.Fatalf("print account: %v", err)
	}
	if policyCalls != 0 {
		t.Fatalf("policy API called %d times", policyCalls)
	}
	node.Selection = organizationSelection{Type: accountEntityType, TargetID: node.ID}
	want := "Organization path to Account Management [123456789012] (management account)\n" +
		"Account Management [123456789012] (management account)\n" +
		"`-- SCPs do not affect its users or roles.\n"
	if output := renderOrganizationTreeText(node); output != want {
		t.Fatalf("unexpected output: %s, want: %s", output, want)
	}
}

func TestOrganizationTreeRenderersStayInParityWithoutAdditionalAWSCalls(t *testing.T) {
	t.Parallel()

	const (
		rootID            = "r-root"
		ouID              = "ou-root-12345678"
		managementAccount = "111111111111"
		memberAccount     = "222222222222"
		secondMember      = "333333333333"
	)
	listCalls := make(map[string]int)
	policyCalls := make(map[string]int)
	var policyCallsMu sync.Mutex
	client := &fakeOrganizationsClient{
		listChildrenFn: func(_ context.Context, input *organizations.ListChildrenInput) (*organizations.ListChildrenOutput, error) {
			key := aws.ToString(input.ParentId) + ":" + string(input.ChildType)
			listCalls[key]++
			switch key {
			case rootID + ":ACCOUNT":
				return &organizations.ListChildrenOutput{Children: []types.Child{{Id: aws.String(managementAccount), Type: types.ChildTypeAccount}}}, nil
			case rootID + ":ORGANIZATIONAL_UNIT":
				return &organizations.ListChildrenOutput{Children: []types.Child{{Id: aws.String(ouID), Type: types.ChildTypeOrganizationalUnit}}}, nil
			case ouID + ":ACCOUNT":
				return &organizations.ListChildrenOutput{Children: []types.Child{
					{Id: aws.String(memberAccount), Type: types.ChildTypeAccount},
					{Id: aws.String(secondMember), Type: types.ChildTypeAccount},
				}}, nil
			case ouID + ":ORGANIZATIONAL_UNIT":
				return &organizations.ListChildrenOutput{}, nil
			default:
				return nil, errors.New("unexpected children lookup")
			}
		},
		describeAccountFn: func(_ context.Context, input *organizations.DescribeAccountInput) (*organizations.DescribeAccountOutput, error) {
			name := "Management"
			if aws.ToString(input.AccountId) != managementAccount {
				name = "Member"
			}
			return &organizations.DescribeAccountOutput{Account: &types.Account{Id: input.AccountId, Name: aws.String(name)}}, nil
		},
		describeOrganizationalUnit: func(context.Context, *organizations.DescribeOrganizationalUnitInput) (*organizations.DescribeOrganizationalUnitOutput, error) {
			return &organizations.DescribeOrganizationalUnitOutput{OrganizationalUnit: &types.OrganizationalUnit{Id: aws.String(ouID), Name: aws.String("Production")}}, nil
		},
		listParentsFn: func(_ context.Context, input *organizations.ListParentsInput) (*organizations.ListParentsOutput, error) {
			switch aws.ToString(input.ChildId) {
			case memberAccount:
				return &organizations.ListParentsOutput{Parents: []types.Parent{{Id: aws.String(ouID), Type: types.ParentTypeOrganizationalUnit}}}, nil
			case ouID:
				return &organizations.ListParentsOutput{Parents: []types.Parent{{Id: aws.String(rootID), Type: types.ParentTypeRoot}}}, nil
			default:
				return nil, errors.New("unexpected parent lookup")
			}
		},
		listPoliciesForTargetFn: func(_ context.Context, input *organizations.ListPoliciesForTargetInput) (*organizations.ListPoliciesForTargetOutput, error) {
			targetID := aws.ToString(input.TargetId)
			policyCallsMu.Lock()
			defer policyCallsMu.Unlock()
			policyCalls[targetID]++
			return &organizations.ListPoliciesForTargetOutput{}, nil
		},
	}

	tree, err := buildOrganizationTree(context.Background(), client, "all", rootID, "", managementAccount)
	if err != nil {
		t.Fatalf("build organization: %v", err)
	}
	textOutput := renderOrganizationTreeText(tree)
	want := "Full organization\n" +
		"Root [r-root]\n" +
		"|-- Account Management [111111111111] (management account)\n" +
		"|   `-- SCPs do not affect its users or roles.\n" +
		"`-- OU Production [ou-root-12345678]\n" +
		"    |-- SCPs: none\n" +
		"    |-- Account Member [222222222222]\n" +
		"    |   `-- SCPs: none\n" +
		"    `-- Account Member [333333333333]\n" +
		"        `-- SCPs: none\n"
	if textOutput != want {
		t.Fatalf("unexpected output:\n%s\nwant:\n%s", textOutput, want)
	}

	jsonOutput, err := renderOrganizationTreeJSON(tree)
	if err != nil {
		t.Fatalf("render organization as JSON: %v", err)
	}
	var result organizationNode
	if err := encodingjson.Unmarshal(jsonOutput, &result); err != nil {
		t.Fatalf("decode organization JSON: %v", err)
	}
	if result.SchemaVersion != organizationJSONSchemaVersion {
		t.Fatalf("schema version is %q, want %q", result.SchemaVersion, organizationJSONSchemaVersion)
	}
	if len(result.Children) != 2 || !result.Children[0].ManagementAccount {
		t.Fatalf("unexpected root children: %+v", result.Children)
	}
	if result.Children[0].SCPs != nil || result.Children[0].SCPAttachments != nil {
		t.Fatalf("management account contains SCP data: %+v", result.Children[0])
	}
	organizationalUnit := result.Children[1]
	if organizationalUnit.ID != ouID || len(organizationalUnit.Children) != 2 {
		t.Fatalf("unexpected organizational unit: %+v", organizationalUnit)
	}

	var hierarchyIDs func(organizationNode) []string
	hierarchyIDs = func(node organizationNode) []string {
		ids := []string{node.ID}
		for _, child := range node.Children {
			ids = append(ids, hierarchyIDs(child)...)
		}
		return ids
	}
	var textIDs []string
	for _, line := range strings.Split(textOutput, "\n") {
		line = strings.TrimLeft(line, " |`-")
		if !strings.HasPrefix(line, "Root ") &&
			!strings.HasPrefix(line, "OU ") &&
			!strings.HasPrefix(line, "Account ") {
			continue
		}
		open := strings.IndexByte(line, '[')
		close := strings.IndexByte(line[open:], ']')
		textIDs = append(textIDs, line[open+1:open+close])
	}
	if jsonIDs := hierarchyIDs(result); !reflect.DeepEqual(textIDs, jsonIDs) {
		t.Fatalf("text hierarchy IDs %v do not match JSON hierarchy IDs %v", textIDs, jsonIDs)
	}

	for key, calls := range listCalls {
		if calls != 1 {
			t.Fatalf("children lookup %s called %d times", key, calls)
		}
	}
	if len(listCalls) != 4 {
		t.Fatalf("got %d children lookups, want 4", len(listCalls))
	}
	policyCallsMu.Lock()
	managementPolicyCalls := policyCalls[managementAccount]
	rootPolicyCalls := policyCalls[rootID]
	ouPolicyCalls := policyCalls[ouID]
	memberPolicyCalls := policyCalls[memberAccount]
	secondMemberPolicyCalls := policyCalls[secondMember]
	policyCallsMu.Unlock()
	if managementPolicyCalls != 0 {
		t.Fatalf("management account policies queried %d times", managementPolicyCalls)
	}
	if rootPolicyCalls != 1 || ouPolicyCalls != 1 || memberPolicyCalls != 1 || secondMemberPolicyCalls != 1 {
		t.Fatalf(
			"policy calls: root=%d OU=%d first member=%d second member=%d, want 1 each",
			rootPolicyCalls, ouPolicyCalls, memberPolicyCalls, secondMemberPolicyCalls,
		)
	}
}

func TestFullOrganizationInspectionUsesBoundedConcurrencyAndDeterministicOrder(t *testing.T) {
	t.Parallel()

	const (
		rootID       = "r-root"
		accountCount = 64
	)
	accountIDs := make([]string, accountCount)
	accountChildren := make([]types.Child, accountCount)
	for index := range accountCount {
		accountIDs[index] = fmt.Sprintf("%012d", 100000000000+index)
		accountChildren[index] = types.Child{Id: aws.String(accountIDs[index]), Type: types.ChildTypeAccount}
	}

	entered := make(chan struct{}, accountCount)
	release := make(chan struct{})
	policyCalls := make(map[string]int, accountCount+1)
	var callsMu sync.Mutex
	activeCalls := 0
	peakCalls := 0
	client := &fakeOrganizationsClient{
		listChildrenFn: func(_ context.Context, input *organizations.ListChildrenInput) (*organizations.ListChildrenOutput, error) {
			if aws.ToString(input.ParentId) != rootID {
				return nil, errors.New("unexpected parent")
			}
			if input.ChildType == types.ChildTypeAccount {
				return &organizations.ListChildrenOutput{Children: accountChildren}, nil
			}
			return &organizations.ListChildrenOutput{}, nil
		},
		describeAccountFn: func(ctx context.Context, input *organizations.DescribeAccountInput) (*organizations.DescribeAccountOutput, error) {
			callsMu.Lock()
			activeCalls++
			peakCalls = max(peakCalls, activeCalls)
			callsMu.Unlock()
			defer func() {
				callsMu.Lock()
				activeCalls--
				callsMu.Unlock()
			}()

			entered <- struct{}{}
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-release:
				accountID := aws.ToString(input.AccountId)
				return &organizations.DescribeAccountOutput{Account: &types.Account{
					Id: input.AccountId, Name: aws.String("Account " + accountID),
				}}, nil
			}
		},
		listPoliciesForTargetFn: func(_ context.Context, input *organizations.ListPoliciesForTargetInput) (*organizations.ListPoliciesForTargetOutput, error) {
			callsMu.Lock()
			policyCalls[aws.ToString(input.TargetId)]++
			callsMu.Unlock()
			return &organizations.ListPoliciesForTargetOutput{}, nil
		},
	}

	var output bytes.Buffer
	done := make(chan error, 1)
	go func() {
		done <- displayOrganizationTree(
			context.Background(), &output, client, "all", rootID, "Organization Root", "999999999999", json,
		)
	}()

	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	for range organizationInspectionConcurrency {
		select {
		case <-entered:
		case <-timer.C:
			close(release)
			t.Fatal("full-organization inspection did not issue concurrent account calls")
		}
	}
	close(release)
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("inspect organization: %v", err)
		}
	case <-timer.C:
		t.Fatal("full-organization inspection did not finish")
	}

	callsMu.Lock()
	gotPeakCalls := peakCalls
	gotActiveCalls := activeCalls
	gotPolicyCalls := make(map[string]int, len(policyCalls))
	for targetID, calls := range policyCalls {
		gotPolicyCalls[targetID] = calls
	}
	callsMu.Unlock()
	if gotPeakCalls != organizationInspectionConcurrency {
		t.Fatalf("peak concurrent AWS calls = %d, want fixed bound %d", gotPeakCalls, organizationInspectionConcurrency)
	}
	if gotActiveCalls != 0 {
		t.Fatalf("active AWS calls after completion = %d, want 0", gotActiveCalls)
	}
	if gotPolicyCalls[rootID] != 1 {
		t.Fatalf("root policies listed %d times, want once", gotPolicyCalls[rootID])
	}
	for _, accountID := range accountIDs {
		if gotPolicyCalls[accountID] != 1 {
			t.Fatalf("account %s policies listed %d times, want once", accountID, gotPolicyCalls[accountID])
		}
	}

	var result organizationNode
	if err := encodingjson.Unmarshal(output.Bytes(), &result); err != nil {
		t.Fatalf("decode organization JSON: %v", err)
	}
	if len(result.Children) != accountCount {
		t.Fatalf("organization contains %d accounts, want %d", len(result.Children), accountCount)
	}
	for index, node := range result.Children {
		if node.ID != accountIDs[index] {
			t.Fatalf("account at output index %d is %s, want %s", index, node.ID, accountIDs[index])
		}
	}
}

func TestFullOrganizationInspectionCancelsOnFailureWithoutPartialText(t *testing.T) {
	t.Parallel()

	const rootID = "r-root"
	accountChildren := make([]types.Child, 16)
	for index := range accountChildren {
		accountID := fmt.Sprintf("%012d", 200000000000+index)
		accountChildren[index] = types.Child{Id: aws.String(accountID), Type: types.ChildTypeAccount}
	}
	failingAccountID := aws.ToString(accountChildren[0].Id)
	inspectionFailure := errors.New("account inspection failed")
	entered := make(chan string, len(accountChildren))
	canceled := make(chan string, len(accountChildren))
	proceed := make(chan struct{})
	var releaseOnce sync.Once
	releaseWorkers := func() {
		releaseOnce.Do(func() { close(proceed) })
	}
	defer releaseWorkers()

	client := &fakeOrganizationsClient{
		listChildrenFn: func(_ context.Context, input *organizations.ListChildrenInput) (*organizations.ListChildrenOutput, error) {
			if input.ChildType == types.ChildTypeAccount {
				return &organizations.ListChildrenOutput{Children: accountChildren}, nil
			}
			return &organizations.ListChildrenOutput{}, nil
		},
		describeAccountFn: func(ctx context.Context, input *organizations.DescribeAccountInput) (*organizations.DescribeAccountOutput, error) {
			accountID := aws.ToString(input.AccountId)
			entered <- accountID
			select {
			case <-ctx.Done():
				canceled <- accountID
				return nil, ctx.Err()
			case <-proceed:
			}
			if accountID == failingAccountID {
				return nil, inspectionFailure
			}
			<-ctx.Done()
			canceled <- accountID
			return nil, ctx.Err()
		},
		listPoliciesForTargetFn: func(context.Context, *organizations.ListPoliciesForTargetInput) (*organizations.ListPoliciesForTargetOutput, error) {
			return nil, errors.New("policy lookup must not start before account descriptions finish")
		},
	}

	var output bytes.Buffer
	done := make(chan error, 1)
	go func() {
		done <- displayOrganizationTree(
			context.Background(), &output, client, "all", rootID, "Organization Root", "999999999999", text,
		)
	}()

	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	started := make(map[string]bool, organizationInspectionConcurrency)
	for range organizationInspectionConcurrency {
		select {
		case accountID := <-entered:
			started[accountID] = true
		case <-timer.C:
			t.Fatal("full-organization inspection did not fill its worker bound")
		}
	}
	if !started[failingAccountID] {
		t.Fatalf("failing account %s was not among initial workers: %v", failingAccountID, started)
	}
	releaseWorkers()

	select {
	case err := <-done:
		if !errors.Is(err, inspectionFailure) {
			t.Fatalf("inspection error = %v, want %v", err, inspectionFailure)
		}
	case <-timer.C:
		t.Fatal("full-organization inspection did not cancel in-flight calls")
	}
	if len(canceled) != organizationInspectionConcurrency-1 {
		t.Fatalf("canceled in-flight account calls = %d, want %d", len(canceled), organizationInspectionConcurrency-1)
	}
	if output.Len() != 0 {
		t.Fatalf("failed inspection wrote partial output: %q", output.String())
	}
}

func TestDisplayOrganizationTreeTextDoesNotWriteOutputOnLateTraversalFailure(t *testing.T) {
	t.Parallel()

	const (
		rootID            = "r-root"
		ouID              = "ou-root-12345678"
		managementAccount = "111111111111"
	)
	client := &fakeOrganizationsClient{
		listChildrenFn: func(_ context.Context, input *organizations.ListChildrenInput) (*organizations.ListChildrenOutput, error) {
			switch aws.ToString(input.ParentId) + ":" + string(input.ChildType) {
			case rootID + ":ACCOUNT":
				return &organizations.ListChildrenOutput{Children: []types.Child{{
					Id: aws.String(managementAccount), Type: types.ChildTypeAccount,
				}}}, nil
			case rootID + ":ORGANIZATIONAL_UNIT":
				return &organizations.ListChildrenOutput{Children: []types.Child{{
					Id: aws.String(ouID), Type: types.ChildTypeOrganizationalUnit,
				}}}, nil
			case ouID + ":ACCOUNT":
				return nil, errors.New("late traversal failure")
			default:
				return nil, errors.New("unexpected children lookup")
			}
		},
		describeAccountFn: func(context.Context, *organizations.DescribeAccountInput) (*organizations.DescribeAccountOutput, error) {
			return &organizations.DescribeAccountOutput{Account: &types.Account{
				Id: aws.String(managementAccount), Name: aws.String("Management"),
			}}, nil
		},
		describeOrganizationalUnit: func(context.Context, *organizations.DescribeOrganizationalUnitInput) (*organizations.DescribeOrganizationalUnitOutput, error) {
			return &organizations.DescribeOrganizationalUnitOutput{OrganizationalUnit: &types.OrganizationalUnit{
				Id: aws.String(ouID), Name: aws.String("Production"),
			}}, nil
		},
	}

	var output bytes.Buffer
	err := displayOrganizationTree(context.Background(), &output, client, "all", rootID, "", managementAccount, text)
	if err == nil || !strings.Contains(err.Error(), "late traversal failure") {
		t.Fatalf("unexpected error: %v", err)
	}
	if output.Len() != 0 {
		t.Fatalf("stdout contains partial hierarchy data: %q", output.String())
	}
}

func TestDisplayOrganizationTreeTextDoesNotWriteAccountPathOnLateTraversalFailure(t *testing.T) {
	t.Parallel()

	const (
		rootID    = "r-root"
		ouID      = "ou-root-12345678"
		accountID = "123456789012"
	)
	client := &fakeOrganizationsClient{
		describeAccountFn: func(context.Context, *organizations.DescribeAccountInput) (*organizations.DescribeAccountOutput, error) {
			return &organizations.DescribeAccountOutput{Account: &types.Account{
				Id: aws.String(accountID), Name: aws.String("Application"),
			}}, nil
		},
		describeOrganizationalUnit: func(context.Context, *organizations.DescribeOrganizationalUnitInput) (*organizations.DescribeOrganizationalUnitOutput, error) {
			return &organizations.DescribeOrganizationalUnitOutput{OrganizationalUnit: &types.OrganizationalUnit{
				Id: aws.String(ouID), Name: aws.String("Production"),
			}}, nil
		},
		listParentsFn: func(_ context.Context, input *organizations.ListParentsInput) (*organizations.ListParentsOutput, error) {
			switch aws.ToString(input.ChildId) {
			case accountID:
				return &organizations.ListParentsOutput{Parents: []types.Parent{{
					Id: aws.String(ouID), Type: types.ParentTypeOrganizationalUnit,
				}}}, nil
			case ouID:
				return &organizations.ListParentsOutput{Parents: []types.Parent{{
					Id: aws.String(rootID), Type: types.ParentTypeRoot,
				}}}, nil
			default:
				return nil, errors.New("unexpected parent lookup")
			}
		},
		listPoliciesForTargetFn: func(context.Context, *organizations.ListPoliciesForTargetInput) (*organizations.ListPoliciesForTargetOutput, error) {
			return nil, errors.New("late traversal failure")
		},
	}

	var output bytes.Buffer
	err := displayOrganizationTree(context.Background(), &output, client, accountID, rootID, "", "999999999999", text)
	if err == nil || !strings.Contains(err.Error(), "late traversal failure") {
		t.Fatalf("unexpected error: %v", err)
	}
	if output.Len() != 0 {
		t.Fatalf("stdout contains partial hierarchy data: %q", output.String())
	}
}

func TestDisplayOrganizationTreeReturnsFinalWriteError(t *testing.T) {
	t.Parallel()

	for _, outputFormat := range []outputFormat{text, json} {
		outputFormat := outputFormat
		t.Run(string(outputFormat), func(t *testing.T) {
			t.Parallel()

			err := displayOrganizationTree(
				context.Background(),
				&failingWriter{err: io.ErrClosedPipe},
				&fakeOrganizationsClient{},
				"all",
				"r-root",
				"",
				"111111111111",
				outputFormat,
			)
			if !errors.Is(err, io.ErrClosedPipe) {
				t.Fatalf("got error %v, want closed pipe", err)
			}
			if outputFormat == json && !strings.Contains(err.Error(), "encode organization as JSON") {
				t.Fatalf("JSON write error lacks operation context: %v", err)
			}
		})
	}
}

func TestDisplayOrganizationTreeJSONBuildsAccountPath(t *testing.T) {
	t.Parallel()

	const (
		rootID    = "r-root"
		ouID      = "ou-root-12345678"
		accountID = "123456789012"
	)
	client := &fakeOrganizationsClient{
		describeAccountFn: func(context.Context, *organizations.DescribeAccountInput) (*organizations.DescribeAccountOutput, error) {
			return &organizations.DescribeAccountOutput{Account: &types.Account{
				Id: aws.String(accountID), Name: aws.String("Application"),
			}}, nil
		},
		describeOrganizationalUnit: func(context.Context, *organizations.DescribeOrganizationalUnitInput) (*organizations.DescribeOrganizationalUnitOutput, error) {
			return &organizations.DescribeOrganizationalUnitOutput{OrganizationalUnit: &types.OrganizationalUnit{
				Id: aws.String(ouID), Name: aws.String("Production"),
			}}, nil
		},
		listParentsFn: func(_ context.Context, input *organizations.ListParentsInput) (*organizations.ListParentsOutput, error) {
			switch aws.ToString(input.ChildId) {
			case accountID:
				return &organizations.ListParentsOutput{Parents: []types.Parent{{
					Id: aws.String(ouID), Type: types.ParentTypeOrganizationalUnit,
				}}}, nil
			case ouID:
				return &organizations.ListParentsOutput{Parents: []types.Parent{{
					Id: aws.String(rootID), Type: types.ParentTypeRoot,
				}}}, nil
			default:
				return nil, errors.New("unexpected parent lookup")
			}
		},
		listPoliciesForTargetFn: func(_ context.Context, input *organizations.ListPoliciesForTargetInput) (*organizations.ListPoliciesForTargetOutput, error) {
			switch aws.ToString(input.TargetId) {
			case rootID:
				return &organizations.ListPoliciesForTargetOutput{Policies: []types.PolicySummary{{
					Id: aws.String("p-full0001"), Name: aws.String("FullAWSAccess"), Type: types.PolicyTypeServiceControlPolicy,
				}}}, nil
			case ouID:
				return &organizations.ListPoliciesForTargetOutput{Policies: []types.PolicySummary{{
					Id: aws.String("p-regions01"), Name: aws.String("DenyRegions"), Type: types.PolicyTypeServiceControlPolicy,
				}}}, nil
			case accountID:
				return &organizations.ListPoliciesForTargetOutput{Policies: []types.PolicySummary{{
					Id: aws.String("p-deny0001"), Name: aws.String("DenyS3"), Type: types.PolicyTypeServiceControlPolicy,
				}}}, nil
			default:
				return nil, errors.New("unexpected policy lookup")
			}
		},
	}

	var output bytes.Buffer
	if err := displayOrganizationTree(
		context.Background(), &output, client, accountID, rootID, "Organization Root", "999999999999", json,
	); err != nil {
		t.Fatalf("display JSON: %v", err)
	}
	wantPrefix := "{\n" +
		"  \"schema_version\": \"1\",\n" +
		"  \"selection\": {\n" +
		"    \"type\": \"account\",\n" +
		"    \"target_id\": \"123456789012\"\n" +
		"  },\n"
	if !strings.HasPrefix(output.String(), wantPrefix) || !strings.HasSuffix(output.String(), "}\n") {
		t.Fatalf("JSON indentation or document framing changed:\n%s", output.String())
	}

	var result organizationNode
	if err := encodingjson.Unmarshal(output.Bytes(), &result); err != nil {
		t.Fatalf("decode JSON: %v", err)
	}
	if result.Type != "root" || result.ID != rootID || result.Name != "Organization Root" || len(result.Children) != 1 {
		t.Fatalf("unexpected root: %+v", result)
	}
	ou := result.Children[0]
	if ou.Type != "organizational_unit" || ou.ID != ouID || ou.Name != "Production" || len(ou.Children) != 1 {
		t.Fatalf("unexpected organizational unit: %+v", ou)
	}
	wantOUAttachments := []scpAttachment{
		{
			PolicyID:   "p-regions01",
			PolicyName: "DenyRegions",
			AttachedTo: scpAttachmentTarget{Type: "organizational_unit", ID: ouID, Name: "Production"},
			Inherited:  false,
		},
		{
			PolicyID:   "p-full0001",
			PolicyName: "FullAWSAccess",
			AttachedTo: scpAttachmentTarget{Type: "root", ID: rootID, Name: "Organization Root"},
			Inherited:  true,
		},
	}
	if strings.Join(ou.SCPs, ",") != "DenyRegions,FullAWSAccess" ||
		!reflect.DeepEqual(ou.SCPAttachments, wantOUAttachments) {
		t.Fatalf("unexpected OU policies: %+v", ou)
	}
	account := ou.Children[0]
	if account.Type != "account" || account.ID != accountID || account.Name != "Application" ||
		strings.Join(account.SCPs, ",") != "DenyRegions,DenyS3,FullAWSAccess" {
		t.Fatalf("unexpected account: %+v", account)
	}
	wantAttachments := []scpAttachment{
		{
			PolicyID:   "p-regions01",
			PolicyName: "DenyRegions",
			AttachedTo: scpAttachmentTarget{Type: "organizational_unit", ID: ouID, Name: "Production"},
			Inherited:  true,
		},
		{
			PolicyID:   "p-deny0001",
			PolicyName: "DenyS3",
			AttachedTo: scpAttachmentTarget{Type: "account", ID: accountID, Name: "Application"},
			Inherited:  false,
		},
		{
			PolicyID:   "p-full0001",
			PolicyName: "FullAWSAccess",
			AttachedTo: scpAttachmentTarget{Type: "root", ID: rootID, Name: "Organization Root"},
			Inherited:  true,
		},
	}
	if !reflect.DeepEqual(account.SCPAttachments, wantAttachments) {
		t.Fatalf("got attachments\n%+v\nwant\n%+v", account.SCPAttachments, wantAttachments)
	}
}
