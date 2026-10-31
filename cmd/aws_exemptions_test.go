package cmd

import (
	"bytes"
	"context"
	encodingjson "encoding/json"
	"errors"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/aws/aws-sdk-go-v2/service/organizations/types"
)

// regionGuardrailSCP follows the AWS-documented pattern for denying requests
// outside approved Regions while carving out global services and break-glass roles.
const regionGuardrailSCP = `{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyAllOutsideApprovedRegions",
      "Effect": "Deny",
      "NotAction": ["iam:*", "organizations:*", "route53:*", "cloudfront:*", "support:*", "sts:*"],
      "Resource": "*",
      "Condition": {
        "StringNotEquals": {"aws:RequestedRegion": ["us-east-1", "us-west-2"]},
        "ArnNotLike": {
          "aws:PrincipalArn": [
            "arn:aws:iam::*:role/BreakGlass",
            "arn:aws:iam::*:role/OrganizationAccountAccessRole"
          ]
        }
      }
    }
  ]
}`

// securityBaselineSCP combines several common guardrails, including conditions
// that Policy Scout must report as uninterpretable rather than guess about.
const securityBaselineSCP = `{
  "Version": "2012-10-17",
  "Statement": [
    {"Sid": "AllowAll", "Effect": "Allow", "Action": "*", "Resource": "*"},
    {
      "Sid": "ProtectSecurityRoles",
      "Effect": "Deny",
      "Action": ["iam:DeleteRole", "iam:UpdateAssumeRolePolicy"],
      "Resource": "arn:aws:iam::*:role/security-*",
      "Condition": {"StringNotEqualsIfExists": {"aws:PrincipalTag/team": "security"}}
    },
    {"Sid": "DenyLeaveOrganization", "Effect": "Deny", "Action": "organizations:LeaveOrganization", "Resource": "*"},
    {
      "Sid": "RequireCostCenterTag",
      "Effect": "Deny",
      "Action": "ec2:RunInstances",
      "Resource": "arn:aws:ec2:*:*:instance/*",
      "Condition": {"Null": {"aws:RequestTag/CostCenter": "true"}}
    },
    {
      "Sid": "DenyS3OutsideOrganization",
      "Effect": "Deny",
      "Action": "s3:*",
      "NotResource": ["arn:aws:s3:::org-audit-logs", "arn:aws:s3:::org-audit-logs/*"],
      "Condition": {
        "StringNotEquals": {"aws:ResourceOrgID": "o-a1b2c3d4e5", "aws:PrincipalAccount": ["111122223333"]}
      }
    },
    {
      "Sid": "ProtectTaggedInstances",
      "Effect": "Deny",
      "Action": "ec2:TerminateInstances",
      "Resource": "*",
      "Condition": {
        "StringEquals": {"ec2:ResourceTag/protected": "true"},
        "Bool": {"aws:MultiFactorAuthPresent": false}
      }
    },
    {
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*",
      "Condition": {
        "ForAnyValue:StringNotLike": {"aws:TagKeys": "team"},
        "NumericGreaterThan": {"aws:MultiFactorAuthAge": 3600},
        "StringNotEquals": {"aws:PrincipalOrgID": {"unexpected": "object"}}
      }
    }
  ]
}`

func TestExtractDenyExemptionsInterpretsRegionGuardrail(t *testing.T) {
	t.Parallel()

	statements, err := extractDenyExemptions(encodingjson.RawMessage(regionGuardrailSCP))
	if err != nil {
		t.Fatalf("extract exemptions: %v", err)
	}
	want := []denyStatement{{
		Index: 0,
		Sid:   "DenyAllOutsideApprovedRegions",
		Exemptions: []exemption{
			{
				Source: exemptionSourceNotAction, ExemptWhen: exemptWhenMatchesValues, Interpretable: true,
				Values: []string{"iam:*", "organizations:*", "route53:*", "cloudfront:*", "support:*", "sts:*"},
			},
			{
				Source: exemptionSourceCondition, Category: "principal", Operator: "ArnNotLike", Key: "aws:PrincipalArn",
				Values:     []string{"arn:aws:iam::*:role/BreakGlass", "arn:aws:iam::*:role/OrganizationAccountAccessRole"},
				ExemptWhen: exemptWhenMatchesValues, ExemptIfKeyAbsent: boolPointer(false), Interpretable: true,
			},
			{
				Source: exemptionSourceCondition, Category: "region", Operator: "StringNotEquals", Key: "aws:RequestedRegion",
				Values:     []string{"us-east-1", "us-west-2"},
				ExemptWhen: exemptWhenMatchesValues, ExemptIfKeyAbsent: boolPointer(false), Interpretable: true,
			},
		},
	}}
	if !reflect.DeepEqual(statements, want) {
		got, _ := encodingjson.MarshalIndent(statements, "", "  ")
		t.Fatalf("statements =\n%s", got)
	}
}

func TestExtractDenyExemptionsDistinguishesOperatorSemantics(t *testing.T) {
	t.Parallel()

	statements, err := extractDenyExemptions(encodingjson.RawMessage(securityBaselineSCP))
	if err != nil {
		t.Fatalf("extract exemptions: %v", err)
	}
	gotIndexes := make([]int, len(statements))
	for index, statement := range statements {
		gotIndexes[index] = statement.Index
	}
	// The Allow statement at index 0 is not a guardrail and is omitted.
	if !reflect.DeepEqual(gotIndexes, []int{1, 2, 3, 4, 5, 6}) {
		t.Fatalf("deny statement indexes = %v", gotIndexes)
	}
	if len(statements[1].Exemptions) != 0 || statements[1].Sid != "DenyLeaveOrganization" {
		t.Fatalf("unconditional deny reports exemptions: %+v", statements[1])
	}

	tests := []struct {
		name      string
		statement int
		want      []exemption
	}{
		{
			name:      "IfExists negated operator keeps deny when key is absent",
			statement: 0,
			want: []exemption{{
				Source: exemptionSourceCondition, Category: "principal_tag", Operator: "StringNotEqualsIfExists", Key: "aws:PrincipalTag/team",
				Values: []string{"security"}, ExemptWhen: exemptWhenMatchesValues, ExemptIfKeyAbsent: boolPointer(false), Interpretable: true,
			}},
		},
		{
			name:      "Null true exempts requests that supply the key",
			statement: 2,
			want: []exemption{{
				Source: exemptionSourceCondition, Category: "request_tag", Operator: "Null", Key: "aws:RequestTag/CostCenter",
				Values: []string{"true"}, ExemptWhen: exemptWhenKeyPresent, ExemptIfKeyAbsent: boolPointer(false), Interpretable: true,
			}},
		},
		{
			name:      "NotResource and each key of one operator are separate exemptions",
			statement: 3,
			want: []exemption{
				{
					Source: exemptionSourceNotResource, ExemptWhen: exemptWhenMatchesValues, Interpretable: true,
					Values: []string{"arn:aws:s3:::org-audit-logs", "arn:aws:s3:::org-audit-logs/*"},
				},
				{
					Source: exemptionSourceCondition, Category: "principal_account", Operator: "StringNotEquals", Key: "aws:PrincipalAccount",
					Values: []string{"111122223333"}, ExemptWhen: exemptWhenMatchesValues, ExemptIfKeyAbsent: boolPointer(false), Interpretable: true,
				},
				{
					Source: exemptionSourceCondition, Category: "resource_owner", Operator: "StringNotEquals", Key: "aws:ResourceOrgID",
					Values: []string{"o-a1b2c3d4e5"}, ExemptWhen: exemptWhenMatchesValues, ExemptIfKeyAbsent: boolPointer(false), Interpretable: true,
				},
			},
		},
		{
			name:      "matching operators exempt non-matching or absent values",
			statement: 4,
			want: []exemption{
				{
					Source: exemptionSourceCondition, Category: "other", Operator: "Bool", Key: "aws:MultiFactorAuthPresent",
					Values: []string{"false"}, ExemptWhen: exemptWhenDoesNotMatchValues, ExemptIfKeyAbsent: boolPointer(true), Interpretable: true,
				},
				{
					Source: exemptionSourceCondition, Category: "resource_tag", Operator: "StringEquals", Key: "ec2:ResourceTag/protected",
					Values: []string{"true"}, ExemptWhen: exemptWhenDoesNotMatchValues, ExemptIfKeyAbsent: boolPointer(true), Interpretable: true,
				},
			},
		},
		{
			name:      "ambiguous conditions are reported without interpretation",
			statement: 5,
			want: []exemption{
				{
					Source: exemptionSourceCondition, Category: "other", Operator: "ForAnyValue:StringNotLike", Key: "aws:TagKeys",
					Values: []string{"team"}, Interpretable: false,
					Reason: "set operator qualifiers ForAnyValue and ForAllValues are not interpreted",
				},
				{
					Source: exemptionSourceCondition, Category: "other", Operator: "NumericGreaterThan", Key: "aws:MultiFactorAuthAge",
					Values: []string{"3600"}, Interpretable: false,
					Reason: "numeric, date, and binary comparison operators are not interpreted",
				},
				{
					Source: exemptionSourceCondition, Category: "principal_organization", Operator: "StringNotEquals", Key: "aws:PrincipalOrgID",
					Interpretable: false,
					Reason:        "condition values are not a string, boolean, number, or non-empty array of them",
				},
			},
		},
	}
	for _, test := range tests {
		if got := statements[test.statement].Exemptions; !reflect.DeepEqual(got, test.want) {
			encoded, _ := encodingjson.MarshalIndent(got, "", "  ")
			t.Errorf("%s: exemptions =\n%s", test.name, encoded)
		}
	}
}

func TestExtractDenyExemptionsReportsUninterpretableStatements(t *testing.T) {
	t.Parallel()

	statements, err := extractDenyExemptions(encodingjson.RawMessage(`{
  "Version": "2012-10-17",
  "Statement": [
    "not-an-object",
    {"Sid": "LowercaseEffect", "Effect": "deny", "Action": "*", "Resource": "*"},
    {"Sid": "WithPrincipal", "Effect": "Deny", "Principal": "*", "Action": "*", "Resource": "*", "Condition": []}
  ]
}`))
	if err != nil {
		t.Fatalf("extract exemptions: %v", err)
	}
	want := []denyStatement{
		{Index: 0, Exemptions: []exemption{{Source: exemptionSourceStatement, Reason: "statement is not a JSON object"}}},
		{Index: 1, Sid: "LowercaseEffect", Exemptions: []exemption{{Source: exemptionSourceStatement, Reason: `statement Effect is not "Allow" or "Deny"`}}},
		{Index: 2, Sid: "WithPrincipal", Exemptions: []exemption{
			{Source: exemptionSourceStatement, Reason: "Principal is not supported in SCPs and is not interpreted"},
			{Source: exemptionSourceCondition, Reason: "Condition is not a JSON object"},
		}},
	}
	if !reflect.DeepEqual(statements, want) {
		got, _ := encodingjson.MarshalIndent(statements, "", "  ")
		t.Fatalf("statements =\n%s", got)
	}

	single, err := extractDenyExemptions(encodingjson.RawMessage(`{"Statement":{"Effect":"Deny","Action":"*","Resource":"*"}}`))
	if err != nil || len(single) != 1 || single[0].Index != 0 || len(single[0].Exemptions) != 0 {
		t.Fatalf("single statement object = %+v, %v", single, err)
	}
}

func exemptionsFixtureClient(describeCalls *atomic.Int32) *fakeOrganizationsClient {
	client := queryFixtureClient(false)
	client.describePolicyFn = func(_ context.Context, input *organizations.DescribePolicyInput) (*organizations.DescribePolicyOutput, error) {
		describeCalls.Add(1)
		if aws.ToString(input.PolicyId) != queryPolicyID {
			return nil, errors.New("unexpected policy")
		}
		return &organizations.DescribePolicyOutput{Policy: &types.Policy{
			PolicySummary: &types.PolicySummary{
				Id: aws.String(queryPolicyID), Name: aws.String("Guardrail"), Type: types.PolicyTypeServiceControlPolicy,
			},
			Content: aws.String(regionGuardrailSCP),
		}}, nil
	}
	return client
}

func TestTargetExemptionsMergeProvenanceAndDescribeEachPolicyOnce(t *testing.T) {
	t.Parallel()

	var describeCalls atomic.Int32
	result, err := buildTargetExemptionsQuery(
		context.Background(), exemptionsFixtureClient(&describeCalls), queryInheritedAccount,
		queryRootID, "Root", queryManagementAccount,
	)
	if err != nil {
		t.Fatalf("build target exemptions: %v", err)
	}
	if describeCalls.Load() != 1 {
		t.Fatalf("DescribePolicy calls = %d, want 1", describeCalls.Load())
	}
	if result.Selection != (exemptionsSelection{Type: accountEntityType, TargetID: queryInheritedAccount}) ||
		result.Target == nil || result.Target.ID != queryInheritedAccount || len(result.Path) != 3 {
		t.Fatalf("unexpected result header: %+v", result)
	}
	if len(result.Policies) != 1 {
		t.Fatalf("policies = %+v, want one merged policy", result.Policies)
	}
	policy := result.Policies[0]
	wantProvenance := []attachmentProvenance{
		{AttachedTo: scpAttachmentTarget{Type: rootEntityType, ID: queryRootID, Name: "Root"}, Inherited: true},
		{AttachedTo: scpAttachmentTarget{Type: organizationalUnitEntityType, ID: queryOUID, Name: "Production"}, Inherited: true},
	}
	if policy.PolicyID != queryPolicyID || policy.PolicyName != "Guardrail" || !reflect.DeepEqual(policy.Provenance, wantProvenance) {
		t.Fatalf("policy provenance = %+v", policy)
	}
	if len(policy.DenyStatements) != 1 || len(policy.DenyStatements[0].Exemptions) != 3 {
		t.Fatalf("deny statements = %+v", policy.DenyStatements)
	}

	var output bytes.Buffer
	if err := writeExemptionsQuery(&output, result, text); err != nil {
		t.Fatalf("write text: %v", err)
	}
	for _, expected := range []string{
		"Target: Account Inherited [333333333333]\n",
		"SCP Guardrail [p-query001] — inherited from Root [r-root], inherited from OU Production [ou-root-12345678]\n",
		"  Deny statement 0 (DenyAllOutsideApprovedRegions):\n",
		"    - exempt actions (NotAction): iam:*, organizations:*, route53:*, cloudfront:*, support:*, sts:*\n",
		"    - principal exempt when aws:PrincipalArn matches arn:aws:iam::*:role/BreakGlass, arn:aws:iam::*:role/OrganizationAccountAccessRole [ArnNotLike]\n",
		"    - region exempt when aws:RequestedRegion matches us-east-1, us-west-2 [StringNotEquals]\n",
	} {
		if !strings.Contains(output.String(), expected) {
			t.Errorf("text output missing %q:\n%s", expected, output.String())
		}
	}
}

func TestTargetExemptionsManagementAccountSkipsPolicyDocuments(t *testing.T) {
	t.Parallel()

	var describeCalls atomic.Int32
	result, err := buildTargetExemptionsQuery(
		context.Background(), exemptionsFixtureClient(&describeCalls), queryManagementAccount,
		queryRootID, "Root", queryManagementAccount,
	)
	if err != nil {
		t.Fatalf("build management exemptions: %v", err)
	}
	if describeCalls.Load() != 0 || result.Target.SCPApplicable {
		t.Fatalf("management account result described policies or claims applicability: %+v", result)
	}
	encoded, err := encodingjson.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), `"policies":[]`) {
		t.Fatalf("management result omits explicit empty policies: %s", encoded)
	}
}

func TestPolicyExemptionsUsesOnlyDescribePolicy(t *testing.T) {
	t.Parallel()

	var describeCalls atomic.Int32
	client := exemptionsFixtureClient(&describeCalls)
	client.listPoliciesForTargetFn = func(context.Context, *organizations.ListPoliciesForTargetInput) (*organizations.ListPoliciesForTargetOutput, error) {
		return nil, errors.New("policy exemptions must not list attachments")
	}
	result, err := buildPolicyExemptionsQuery(context.Background(), client, queryPolicyID)
	if err != nil {
		t.Fatalf("build policy exemptions: %v", err)
	}
	if result.Selection != (exemptionsSelection{Type: policySelectionType, PolicyID: queryPolicyID}) ||
		result.Target != nil || len(result.Policies) != 1 || result.Policies[0].Provenance != nil {
		t.Fatalf("unexpected policy result: %+v", result)
	}

	client.describePolicyFn = func(context.Context, *organizations.DescribePolicyInput) (*organizations.DescribePolicyOutput, error) {
		return nil, errors.New("late describe failure")
	}
	if _, err := buildPolicyExemptionsQuery(context.Background(), client, queryPolicyID); err == nil ||
		!strings.Contains(err.Error(), "late describe failure") {
		t.Fatalf("error = %v, want describe failure", err)
	}
}

func TestSelectedExemptionsQueryRequiresOneExactSelector(t *testing.T) {
	t.Parallel()

	tests := []struct {
		policy, account, ou          string
		policySet, accountSet, ouSet bool
		want                         string
	}{
		{want: "exactly one of --policy-id"},
		{policy: "p-bad", policySet: true, want: "invalid --policy-id"},
		{policy: queryPolicyID, policySet: true, account: queryDirectAccount, accountSet: true, want: "mutually exclusive"},
		{account: "all", accountSet: true, want: "exemptions requires one exact account"},
		{account: queryDirectAccount, accountSet: true, ou: queryOUID, ouSet: true, want: "mutually exclusive"},
		{ou: "ou-bad", ouSet: true, want: "invalid --ou-id"},
	}
	for _, test := range tests {
		_, err := selectedExemptionsQuery(test.policy, test.policySet, test.account, test.accountSet, test.ou, test.ouSet)
		if err == nil || !strings.Contains(err.Error(), test.want) || classifyError(err).Code != errorCodeInvalidInvocation {
			t.Errorf("error = %v, want invalid_invocation containing %q", err, test.want)
		}
	}
	selection, err := selectedExemptionsQuery("", false, "", false, queryOUID, true)
	if err != nil || selection != (exemptionsSelection{Type: organizationalUnitEntityType, TargetID: queryOUID}) {
		t.Fatalf("OU selection = %+v, %v", selection, err)
	}
}
