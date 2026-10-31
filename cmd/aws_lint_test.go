package cmd

import (
	"bytes"
	"context"
	encodingjson "encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"github.com/spf13/cobra"
)

const (
	lintRootID      = "r-root"
	lintManagement  = "111111111111"
	lintSandbox     = "222222222222"
	lintApp         = "333333333333"
	lintShared      = "444444444444"
	lintProdOU      = "ou-root-12345678"
	lintDenyRegions = "p-denyregn"
	lintDenyCopy    = "p-dupdeny1"
	lintAllowList   = "p-allowmix"
	lintUnused      = "p-unused01"
	lintBigDocument = "p-bigdocmt"
)

var lintTestLimits = lintLimits{PoliciesPerTarget: 5, PolicyDocumentCharacters: 400}

type lintFixture struct {
	names       map[string]string
	contents    map[string]string
	direct      map[string][]string
	children    map[string][]string
	entityNames map[string]string
}

// padDocument pads to a length in characters, which is how AWS measures SCPs.
func padDocument(document string, length int) string {
	return document + strings.Repeat(" ", length-utf8.RuneCountInString(document))
}

// newLintFixture models an organization in which every check fires exactly
// where expected and nearby look-alikes (Allow policies repeated at each
// level, accounts inside OUs, FullAWSAccess on the management account) do not.
func newLintFixture() lintFixture {
	denyRegions := `{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"StringNotEquals":{"aws:RequestedRegion":["us-east-1"]}}}]}`
	return lintFixture{
		names: map[string]string{
			fullAWSAccessPolicyID: "FullAWSAccess",
			lintDenyRegions:       "DenyRegions",
			lintDenyCopy:          "DenyRegionsCopy",
			lintAllowList:         "AllowList",
			lintUnused:            "Unused",
			lintBigDocument:       "BigDocument",
		},
		contents: map[string]string{
			fullAWSAccessPolicyID: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`,
			lintDenyRegions:       denyRegions,
			// Same document with different whitespace and key order.
			lintDenyCopy: `{ "Statement":[{"Resource":"*","Action":"*","Effect":"Deny","Condition":{"StringNotEquals":{"aws:RequestedRegion":["us-east-1"]}}}],"Version":"2012-10-17" }`,
			lintAllowList: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"},` +
				`{"Sid":"AllowListed","Effect":"Allow","NotAction":["iam:*"],"Resource":"*"},` +
				`{"Effect":"Deny","NotAction":"ec2:*","NotResource":"arn:aws:ec2:*:*:vpc/vpc-1"}]}`,
			// 340 characters but 420 UTF-8 bytes: near the 400-character test
			// limit, not at it.
			lintUnused: padDocument(
				`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"ec2:*","NotResource":"arn:aws:ec2:*:*:vpc/équipe-`+
					strings.Repeat("é", 79)+`"}]}`, 340,
			),
			lintBigDocument: padDocument(
				`{"Version":"2012-10-17","Statement":{"Effect":"Deny","Action":"s3:DeleteBucket","Resource":"*"}}`, 400,
			),
		},
		direct: map[string][]string{
			lintRootID:     {fullAWSAccessPolicyID},
			lintManagement: {fullAWSAccessPolicyID, lintBigDocument},
			lintSandbox:    {fullAWSAccessPolicyID, fullAWSAccessPolicyID},
			lintShared:     {fullAWSAccessPolicyID, lintDenyCopy},
			lintProdOU:     {fullAWSAccessPolicyID, lintDenyRegions, lintAllowList, lintDenyCopy},
			lintApp:        {fullAWSAccessPolicyID, lintDenyRegions, lintAllowList, lintBigDocument, lintDenyCopy},
		},
		children: map[string][]string{
			lintRootID + ":ACCOUNT":             {lintShared, lintManagement, lintSandbox},
			lintRootID + ":ORGANIZATIONAL_UNIT": {lintProdOU},
			lintProdOU + ":ACCOUNT":             {lintApp},
			lintProdOU + ":ORGANIZATIONAL_UNIT": {},
		},
		entityNames: map[string]string{
			lintManagement: "Management", lintSandbox: "Sandbox", lintApp: "App", lintShared: "Shared", lintProdOU: "Prod",
		},
	}
}

func (fixture lintFixture) client() *fakeOrganizationsClient {
	summary := func(id string) types.PolicySummary {
		return types.PolicySummary{
			Id: aws.String(id), Name: aws.String(fixture.names[id]), Type: types.PolicyTypeServiceControlPolicy,
			AwsManaged: id == fullAWSAccessPolicyID,
		}
	}
	return &fakeOrganizationsClient{
		listChildrenFn: func(_ context.Context, input *organizations.ListChildrenInput) (*organizations.ListChildrenOutput, error) {
			key := aws.ToString(input.ParentId) + ":" + string(input.ChildType)
			ids, found := fixture.children[key]
			if !found {
				return nil, fmt.Errorf("unexpected children lookup %s", key)
			}
			result := make([]types.Child, len(ids))
			for index, id := range ids {
				result[index] = types.Child{Id: aws.String(id), Type: input.ChildType}
			}
			return &organizations.ListChildrenOutput{Children: result}, nil
		},
		describeAccountFn: func(_ context.Context, input *organizations.DescribeAccountInput) (*organizations.DescribeAccountOutput, error) {
			return &organizations.DescribeAccountOutput{Account: &types.Account{
				Id: input.AccountId, Name: aws.String(fixture.entityNames[aws.ToString(input.AccountId)]),
			}}, nil
		},
		describeOrganizationalUnit: func(_ context.Context, input *organizations.DescribeOrganizationalUnitInput) (*organizations.DescribeOrganizationalUnitOutput, error) {
			return &organizations.DescribeOrganizationalUnitOutput{OrganizationalUnit: &types.OrganizationalUnit{
				Id: input.OrganizationalUnitId, Name: aws.String(fixture.entityNames[aws.ToString(input.OrganizationalUnitId)]),
			}}, nil
		},
		listPoliciesForTargetFn: func(_ context.Context, input *organizations.ListPoliciesForTargetInput) (*organizations.ListPoliciesForTargetOutput, error) {
			ids, found := fixture.direct[aws.ToString(input.TargetId)]
			if !found {
				return nil, fmt.Errorf("unexpected policy lookup %s", aws.ToString(input.TargetId))
			}
			output := &organizations.ListPoliciesForTargetOutput{}
			for _, id := range ids {
				output.Policies = append(output.Policies, summary(id))
			}
			return output, nil
		},
		listPoliciesFn: func(_ context.Context, input *organizations.ListPoliciesInput) (*organizations.ListPoliciesOutput, error) {
			if input.Filter != types.PolicyTypeServiceControlPolicy {
				return nil, fmt.Errorf("unexpected policy filter %s", input.Filter)
			}
			output := &organizations.ListPoliciesOutput{}
			for id := range fixture.names {
				output.Policies = append(output.Policies, summary(id))
			}
			return output, nil
		},
		describePolicyFn: func(_ context.Context, input *organizations.DescribePolicyInput) (*organizations.DescribePolicyOutput, error) {
			id := aws.ToString(input.PolicyId)
			policySummary := summary(id)
			return &organizations.DescribePolicyOutput{Policy: &types.Policy{
				PolicySummary: &policySummary, Content: aws.String(fixture.contents[id]),
			}}, nil
		},
	}
}

func buildLintFixtureReport(t *testing.T, fixture lintFixture) lintReport {
	t.Helper()
	report, err := buildLintReport(context.Background(), fixture.client(), lintRootID, "Root", lintManagement, lintTestLimits)
	if err != nil {
		t.Fatalf("build lint report: %v", err)
	}
	return report
}

func TestLintReportFlagsEachCheckOnlyWhereItApplies(t *testing.T) {
	t.Parallel()

	report := buildLintFixtureReport(t, newLintFixture())
	type key struct{ severity, check, target, policy string }
	got := make([]key, len(report.Findings))
	for index, finding := range report.Findings {
		got[index] = key{severity: finding.Severity, check: finding.Check}
		if finding.Target != nil {
			got[index].target = finding.Target.ID
		}
		if finding.Policy != nil {
			got[index].policy = finding.Policy.ID
		}
		if finding.Message == "" || finding.Rationale == "" {
			t.Errorf("finding lacks what or why: %+v", finding)
		}
	}
	want := []key{
		{lintSeverityHigh, lintCheckRootAccountFullAccessOnly, lintSandbox, ""},
		{lintSeverityMedium, lintCheckAllowNotAction, "", lintAllowList},
		{lintSeverityMedium, lintCheckAllowNotResource, "", lintUnused},
		{lintSeverityMedium, lintCheckAttachmentLimit, lintApp, ""},
		{lintSeverityMedium, lintCheckPolicySizeLimit, "", lintBigDocument},
		{lintSeverityLow, lintCheckAttachmentLimit, lintProdOU, ""},
		{lintSeverityLow, lintCheckDuplicatePolicyDocument, "", lintDenyRegions},
		{lintSeverityLow, lintCheckManagementAccountAttachment, lintManagement, lintBigDocument},
		{lintSeverityLow, lintCheckPolicySizeLimit, "", lintUnused},
		{lintSeverityLow, lintCheckRedundantAttachment, lintApp, lintDenyRegions},
		{lintSeverityLow, lintCheckRedundantAttachment, lintApp, lintDenyCopy},
		{lintSeverityLow, lintCheckUnattachedPolicy, "", lintUnused},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("findings =\n%v\nwant\n%v", got, want)
	}
	if report.Summary != (lintSummary{Total: 12, High: 1, Medium: 4, Low: 7}) {
		t.Fatalf("summary = %+v", report.Summary)
	}

	notAction := report.Findings[1]
	if notAction.Evidence.StatementIndex == nil || *notAction.Evidence.StatementIndex != 1 ||
		notAction.Evidence.StatementSID != "AllowListed" {
		t.Errorf("NotAction finding does not locate the Allow statement: %+v", notAction.Evidence)
	}
	atLimit := report.Findings[3]
	if atLimit.Evidence.AttachedPolicyCount != 5 || atLimit.Evidence.Limit != 5 || len(atLimit.Evidence.AttachedPolicies) != 5 {
		t.Errorf("attachment limit evidence = %+v", atLimit.Evidence)
	}
	if size := report.Findings[8].Evidence; size.DocumentCharacters != 340 || size.Limit != 400 {
		t.Errorf("near-size evidence = %+v", size)
	}
	if duplicates := report.Findings[6].Evidence.DuplicatePolicies; len(duplicates) != 1 || duplicates[0].ID != lintDenyCopy {
		t.Errorf("duplicate evidence = %+v", duplicates)
	}
	redundant := report.Findings[9].Evidence.InheritedFrom
	if !reflect.DeepEqual(redundant, []scpAttachmentTarget{{Type: organizationalUnitEntityType, ID: lintProdOU, Name: "Prod"}}) {
		t.Errorf("redundant attachment provenance = %+v", redundant)
	}
}

func TestLintReportIsStableAndCleanOrganizationHasEmptyFindings(t *testing.T) {
	t.Parallel()

	first, second := buildLintFixtureReport(t, newLintFixture()), buildLintFixtureReport(t, newLintFixture())
	firstJSON, _ := encodingjson.Marshal(first)
	secondJSON, _ := encodingjson.Marshal(second)
	if !bytes.Equal(firstJSON, secondJSON) {
		t.Fatalf("lint report order is unstable:\n%s\n%s", firstJSON, secondJSON)
	}

	// An account inside an OU with only FullAWSAccess is not a root-level account,
	// and FullAWSAccess repeated at every level is required, not redundant.
	fixture := newLintFixture()
	fixture.names = map[string]string{fullAWSAccessPolicyID: "FullAWSAccess"}
	fixture.direct = map[string][]string{
		lintRootID: {fullAWSAccessPolicyID}, lintManagement: {fullAWSAccessPolicyID},
		lintProdOU: {fullAWSAccessPolicyID}, lintApp: {fullAWSAccessPolicyID},
	}
	fixture.children[lintRootID+":ACCOUNT"] = []string{lintManagement}
	report := buildLintFixtureReport(t, fixture)
	var output bytes.Buffer
	if err := writeLintReport(&output, report, json); err != nil {
		t.Fatalf("write lint report: %v", err)
	}
	if !strings.Contains(output.String(), `"findings": []`) || report.Summary.Total != 0 {
		t.Fatalf("clean organization report:\n%s", output.String())
	}
}

func TestLintReportRejectsAttachedPolicyMissingFromInventory(t *testing.T) {
	t.Parallel()

	fixture := newLintFixture()
	client := fixture.client()
	listPolicies := client.listPoliciesFn
	client.listPoliciesFn = func(ctx context.Context, input *organizations.ListPoliciesInput) (*organizations.ListPoliciesOutput, error) {
		output, err := listPolicies(ctx, input)
		if err != nil {
			return nil, err
		}
		kept := output.Policies[:0]
		for _, policy := range output.Policies {
			if aws.ToString(policy.Id) != lintDenyRegions {
				kept = append(kept, policy)
			}
		}
		output.Policies = kept
		return output, nil
	}
	_, err := buildLintReport(context.Background(), client, lintRootID, "Root", lintManagement, lintTestLimits)
	if err == nil || !strings.Contains(err.Error(), lintDenyRegions) {
		t.Fatalf("error = %v, want missing inventory error naming %s", err, lintDenyRegions)
	}
}

func TestLintTextReportExplainsEachFinding(t *testing.T) {
	t.Parallel()

	report := buildLintFixtureReport(t, newLintFixture())
	var output bytes.Buffer
	if err := writeLintReport(&output, report, text); err != nil {
		t.Fatalf("write text lint report: %v", err)
	}
	for _, expected := range []string{
		"SCP lint for Root [r-root]: 12 findings (1 high, 4 medium, 7 low)\n",
		"\n[high] root_account_full_access_only: Account Sandbox [222222222222] is directly under the root and only FullAWSAccess applies to it.\n" +
			"  Where: Account Sandbox [222222222222]\n  Why: ",
		"[medium] allow_not_action: SCP AllowList [p-allowmix] statement 1 (Sid \"AllowListed\") is an Allow statement that uses NotAction.\n" +
			"  Policy: SCP AllowList [p-allowmix]\n",
		"[low] redundant_attachment: SCP DenyRegions [p-denyregn] is attached directly to Account App [333333333333] and also inherited from OU Prod [ou-root-12345678].\n",
	} {
		if !strings.Contains(output.String(), expected) {
			t.Errorf("text report missing %q:\n%s", expected, output.String())
		}
	}
}

func TestLintFailOnThresholdSetsFindingsExitWithoutDiagnostic(t *testing.T) {
	report := lintReport{Findings: []lintFinding{{Severity: lintSeverityMedium}, {Severity: lintSeverityLow}}}
	for threshold, wantCount := range map[string]int{
		lintFailOnNone: 0, lintSeverityLow: 2, lintSeverityMedium: 1, lintSeverityHigh: 0,
	} {
		err := lintThresholdError(report, threshold)
		if wantCount == 0 {
			if err != nil {
				t.Errorf("--fail-on %s returned %v, want nil", threshold, err)
			}
			continue
		}
		command := &cobra.Command{
			Use: "lint", SilenceErrors: true, SilenceUsage: true,
			RunE: func(cmd *cobra.Command, _ []string) error {
				_, _ = cmd.OutOrStdout().Write([]byte("{}\n"))
				return err
			},
		}
		var stdout, stderr bytes.Buffer
		if exitCode := executeCommand(command, nil, &stdout, &stderr); exitCode != exitFindings {
			t.Errorf("--fail-on %s exit = %d, want %d", threshold, exitCode, exitFindings)
		}
		if stdout.String() != "{}\n" || stderr.Len() != 0 {
			t.Errorf("--fail-on %s stdout = %q, stderr = %q; want report only", threshold, stdout.String(), stderr.String())
		}
		if !strings.Contains(err.Error(), fmt.Sprintf("%d SCP lint findings", wantCount)) {
			t.Errorf("--fail-on %s error = %v, want count %d", threshold, err, wantCount)
		}
	}
}
