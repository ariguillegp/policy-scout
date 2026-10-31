package cmd

import (
	"bytes"
	"context"
	encodingjson "encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/aws/aws-sdk-go-v2/service/organizations/types"
)

const (
	coverageRootID          = "r-root"
	coverageSecurityOU      = "ou-root-security"
	coverageNestedOU        = "ou-root-nested01"
	coverageManagement      = "111111111111"
	coverageInheritedMember = "222222222222" // in Security; inherits DenyCloudTrail
	coverageNestedMember    = "333333333333" // in Security > Nested; inherits DenyCloudTrail twice removed
	coverageConditional     = "444444444444" // direct Deny with a Condition and a resource-scoped Deny
	coverageNotAction       = "555555555555" // direct Deny NotAction iam:*
	coverageUncovered       = "666666666666" // only Allow and an unrelated S3 Deny
	coverageSuspended       = "777777777777" // suspended, under root
	coverageGuardPolicy     = "p-guard001"
	coverageAllowPolicy     = "p-FullAWSAccess"
)

// coverageFixtureClient models an organization in which DenyCloudTrail is
// attached only to the Security OU, so its two member accounts are covered
// through inheritance and every account outside it is not.
func coverageFixtureClient() *fakeOrganizationsClient {
	documents := map[string]string{
		coverageAllowPolicy: `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}`,
		coverageGuardPolicy: `{"Version":"2012-10-17","Statement":[{"Sid":"DenyCloudTrail","Effect":"Deny","Action":["CloudTrail:*"],"Resource":"*"}]}`,
		"p-cond0001": `{"Version":"2012-10-17","Statement":[{"Sid":"BreakGlass","Effect":"Deny","Action":"cloudtrail:StopLogging","Resource":"*",` +
			`"Condition":{"ArnNotLike":{"aws:PrincipalArn":"arn:aws:iam::*:role/BreakGlass"}}},` +
			`{"Effect":"Deny","Action":"cloudtrail:*","Resource":"arn:aws:cloudtrail:*:*:trail/org-trail"}]}`,
		"p-notact01": `{"Version":"2012-10-17","Statement":[{"Effect":"Deny","NotAction":["iam:*","sts:*"],"Resource":"*"}]}`,
		"p-bucket01": `{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"s3:*","Resource":"*"}]}`,
		"p-unused01": `{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}`,
	}
	names := map[string]string{
		coverageAllowPolicy: "FullAWSAccess", coverageGuardPolicy: "DenyCloudTrail", "p-cond0001": "DenyStopLoggingExceptBreakGlass",
		"p-notact01": "DenyAllButIAM", "p-bucket01": "DenyLogBucket", "p-unused01": "Unused",
	}
	attached := map[string][]string{
		coverageRootID:          {coverageAllowPolicy},
		coverageSecurityOU:      {coverageGuardPolicy},
		coverageNestedOU:        {},
		coverageManagement:      {coverageGuardPolicy},
		coverageInheritedMember: {},
		coverageNestedMember:    {},
		coverageConditional:     {"p-cond0001"},
		coverageNotAction:       {"p-notact01"},
		coverageUncovered:       {"p-bucket01"},
		coverageSuspended:       {},
	}
	accounts := map[string][]string{
		coverageRootID:     {coverageManagement, coverageConditional, coverageNotAction, coverageUncovered, coverageSuspended},
		coverageSecurityOU: {coverageInheritedMember},
		coverageNestedOU:   {coverageNestedMember},
	}
	ous := map[string][]types.OrganizationalUnit{
		coverageRootID:     {{Id: aws.String(coverageSecurityOU), Name: aws.String("Security")}},
		coverageSecurityOU: {{Id: aws.String(coverageNestedOU), Name: aws.String("Nested")}},
		coverageNestedOU:   {},
	}
	summary := func(id string) types.PolicySummary {
		return types.PolicySummary{Id: aws.String(id), Name: aws.String(names[id]), Type: types.PolicyTypeServiceControlPolicy}
	}
	return &fakeOrganizationsClient{
		listAccountsForParentFn: func(_ context.Context, input *organizations.ListAccountsForParentInput) (*organizations.ListAccountsForParentOutput, error) {
			ids, found := accounts[aws.ToString(input.ParentId)]
			if !found {
				return nil, fmt.Errorf("unexpected account lookup %s", aws.ToString(input.ParentId))
			}
			output := &organizations.ListAccountsForParentOutput{}
			for _, id := range ids {
				state := types.AccountStateActive
				if id == coverageSuspended {
					state = types.AccountStateSuspended
				}
				output.Accounts = append(output.Accounts, types.Account{Id: aws.String(id), Name: aws.String("acct-" + id[:3]), State: state})
			}
			return output, nil
		},
		listOUsForParentFn: func(_ context.Context, input *organizations.ListOrganizationalUnitsForParentInput) (*organizations.ListOrganizationalUnitsForParentOutput, error) {
			children, found := ous[aws.ToString(input.ParentId)]
			if !found {
				return nil, fmt.Errorf("unexpected OU lookup %s", aws.ToString(input.ParentId))
			}
			return &organizations.ListOrganizationalUnitsForParentOutput{OrganizationalUnits: children}, nil
		},
		listPoliciesForTargetFn: func(_ context.Context, input *organizations.ListPoliciesForTargetInput) (*organizations.ListPoliciesForTargetOutput, error) {
			ids, found := attached[aws.ToString(input.TargetId)]
			if !found {
				return nil, fmt.Errorf("unexpected policy lookup %s", aws.ToString(input.TargetId))
			}
			output := &organizations.ListPoliciesForTargetOutput{}
			for _, id := range ids {
				output.Policies = append(output.Policies, summary(id))
			}
			return output, nil
		},
		describePolicyFn: func(_ context.Context, input *organizations.DescribePolicyInput) (*organizations.DescribePolicyOutput, error) {
			id := aws.ToString(input.PolicyId)
			document, found := documents[id]
			if !found {
				return nil, &types.PolicyNotFoundException{Message: aws.String("not found")}
			}
			policySummary := summary(id)
			return &organizations.DescribePolicyOutput{Policy: &types.Policy{PolicySummary: &policySummary, Content: aws.String(document)}}, nil
		},
	}
}

func buildCoverageFixture(t *testing.T, query coverageQuery) coverageResult {
	t.Helper()
	result, err := buildCoverageReport(context.Background(), coverageFixtureClient(), query, coverageRootID, "Root", coverageManagement)
	if err != nil {
		t.Fatalf("build coverage report: %v", err)
	}
	return result
}

func coverageAccountIDs(accounts []coverageAccountResult) []string {
	ids := make([]string, len(accounts))
	for index, account := range accounts {
		ids[index] = account.Account.ID
	}
	return ids
}

func TestCoverageByPolicyCountsInheritanceAndExcludesManagementAndSuspended(t *testing.T) {
	t.Parallel()
	result := buildCoverageFixture(t, coverageQuery{Type: coverageQueryTypePolicy, PolicyID: coverageGuardPolicy})

	if result.Query.PolicyName != "DenyCloudTrail" {
		t.Fatalf("policy name = %q, want DenyCloudTrail", result.Query.PolicyName)
	}
	if got, want := coverageAccountIDs(result.CoveredAccounts), []string{coverageInheritedMember, coverageNestedMember}; !reflect.DeepEqual(got, want) {
		t.Fatalf("covered = %v, want %v", got, want)
	}
	if got, want := coverageAccountIDs(result.UncoveredAccounts), []string{coverageConditional, coverageNotAction, coverageUncovered}; !reflect.DeepEqual(got, want) {
		t.Fatalf("uncovered = %v, want %v", got, want)
	}
	if len(result.ConditionallyCoveredAccounts) != 0 {
		t.Fatalf("policy mode reported conditional coverage: %+v", result.ConditionallyCoveredAccounts)
	}
	nested := result.CoveredAccounts[1]
	wantEvidence := []coverageEvidence{{
		PolicyID: coverageGuardPolicy, PolicyName: "DenyCloudTrail", Inherited: true,
		AttachedTo: scpAttachmentTarget{Type: organizationalUnitEntityType, ID: coverageSecurityOU, Name: "Security"},
	}}
	if !reflect.DeepEqual(nested.Evidence, wantEvidence) {
		t.Fatalf("nested evidence = %+v, want %+v", nested.Evidence, wantEvidence)
	}
	wantPath := []string{coverageRootID, coverageSecurityOU, coverageNestedOU, coverageNestedMember}
	gotPath := make([]string, len(nested.Path))
	for index, entity := range nested.Path {
		gotPath[index] = entity.ID
	}
	if !reflect.DeepEqual(gotPath, wantPath) {
		t.Fatalf("nested path = %v, want %v", gotPath, wantPath)
	}

	// The management account has the policy attached directly, but SCPs never
	// restrict it, so it is excluded rather than counted as covered.
	wantExcluded := []coverageExcludedAccount{
		{Account: coverageAccountInfo{ID: coverageManagement, Name: "acct-111", State: "ACTIVE"}, Reason: coverageExcludedManagementAccount},
		{Account: coverageAccountInfo{ID: coverageSuspended, Name: "acct-777", State: "SUSPENDED"}, Reason: coverageExcludedInactiveAccount},
	}
	for index := range result.ExcludedAccounts {
		result.ExcludedAccounts[index].Path = nil
	}
	if !reflect.DeepEqual(result.ExcludedAccounts, wantExcluded) {
		t.Fatalf("excluded = %+v, want %+v", result.ExcludedAccounts, wantExcluded)
	}
	if result.Summary != (coverageSummary{Accounts: 7, Covered: 2, Uncovered: 3, Excluded: 2}) {
		t.Fatalf("summary = %+v", result.Summary)
	}
}

func TestCoverageByActionMatchesWildcardsNotActionAndConditions(t *testing.T) {
	t.Parallel()
	result := buildCoverageFixture(t, coverageQuery{Type: coverageQueryTypeAction, Action: "cloudtrail:StopLogging"})

	if got, want := coverageAccountIDs(result.CoveredAccounts), []string{coverageInheritedMember, coverageNestedMember, coverageNotAction}; !reflect.DeepEqual(got, want) {
		t.Fatalf("covered = %v, want %v", got, want)
	}
	if got, want := coverageAccountIDs(result.UncoveredAccounts), []string{coverageUncovered}; !reflect.DeepEqual(got, want) {
		t.Fatalf("uncovered = %v, want %v", got, want)
	}
	if got := result.CoveredAccounts[2].Evidence[0].Statement; got == nil || got.MatchedBy != coverageMatchedByNotAction {
		t.Fatalf("NotAction coverage statement = %+v", got)
	}
	if got := result.CoveredAccounts[0].Evidence[0].Statement; got == nil || got.MatchedBy != coverageMatchedByAction || got.Sid != "DenyCloudTrail" {
		t.Fatalf("wildcard coverage statement = %+v", got)
	}

	if got, want := coverageAccountIDs(result.ConditionallyCoveredAccounts), []string{coverageConditional}; !reflect.DeepEqual(got, want) {
		t.Fatalf("conditional = %v, want %v", got, want)
	}
	evidence := result.ConditionallyCoveredAccounts[0].Evidence
	if len(evidence) != 2 || evidence[0].PolicyID != "p-cond0001" || evidence[0].Inherited || evidence[0].Statement == nil ||
		evidence[0].Statement.Index != 0 || evidence[0].Statement.Sid != "BreakGlass" || evidence[0].Statement.Resource != nil ||
		!strings.Contains(string(evidence[0].Statement.Condition), "aws:PrincipalArn") {
		t.Fatalf("conditional evidence = %+v", evidence)
	}
	if scoped := evidence[1].Statement; scoped == nil || scoped.Index != 1 || scoped.Condition != nil ||
		!reflect.DeepEqual(scoped.Resource, []string{"arn:aws:cloudtrail:*:*:trail/org-trail"}) {
		t.Fatalf("resource-scoped evidence = %+v", evidence[1].Statement)
	}

	// For iam:CreateUser, the NotAction Deny exempts iam:*, so nothing covers it.
	other := buildCoverageFixture(t, coverageQuery{Type: coverageQueryTypeAction, Action: "iam:CreateUser"})
	if other.Summary != (coverageSummary{Accounts: 7, Uncovered: 5, Excluded: 2}) {
		t.Fatalf("iam:CreateUser summary = %+v", other.Summary)
	}
}

func TestCoverageStatementDenyMatching(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name          string
		statement     string
		action        string
		wantMatch     string
		unconditional bool
	}{
		{"global wildcard", `{"Effect":"Deny","Action":"*","Resource":"*"}`, "cloudtrail:StopLogging", "action", true},
		{"service wildcard is case-insensitive", `{"Effect":"Deny","Action":"CLOUDTRAIL:*"}`, "cloudtrail:StopLogging", "action", true},
		{"prefix wildcard", `{"Effect":"Deny","Action":["s3:*","cloudtrail:Stop*"]}`, "cloudtrail:StopLogging", "action", true},
		{"single-character wildcard", `{"Effect":"Deny","Action":"cloudtrail:Stop?ogging"}`, "cloudtrail:StopLogging", "action", true},
		{"different action prefix", `{"Effect":"Deny","Action":"cloudtrail:Start*"}`, "cloudtrail:StopLogging", "", false},
		{"pattern must match the whole action", `{"Effect":"Deny","Action":"cloudtrail:Stop"}`, "cloudtrail:StopLogging", "", false},
		{"service prefix is not a substring match", `{"Effect":"Deny","Action":"cloud*:StopLogging"}`, "cloudtrail:StopLogging", "action", true},
		{"allow never covers", `{"Effect":"Allow","Action":"*"}`, "cloudtrail:StopLogging", "", false},
		{"NotAction excluding the action", `{"Effect":"Deny","NotAction":"cloudtrail:*"}`, "cloudtrail:StopLogging", "", false},
		{"NotAction excluding other services", `{"Effect":"Deny","NotAction":["iam:*"]}`, "cloudtrail:StopLogging", "not_action", true},
		{"condition", `{"Effect":"Deny","Action":"*","Condition":{"StringNotEquals":{"aws:RequestedRegion":"us-east-1"}}}`, "cloudtrail:StopLogging", "action", false},
		{"empty condition is unconditional", `{"Effect":"Deny","Action":"*","Condition":{}}`, "cloudtrail:StopLogging", "action", true},
		{"resource scope", `{"Effect":"Deny","Action":"*","Resource":"arn:aws:cloudtrail:*:*:trail/org"}`, "cloudtrail:StopLogging", "action", false},
		{"not resource scope", `{"Effect":"Deny","Action":"*","NotResource":"arn:aws:s3:::x"}`, "cloudtrail:StopLogging", "action", false},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			statements, err := parseCoverageStatements(encodingjson.RawMessage(`{"Statement":` + testCase.statement + `}`))
			if err != nil {
				t.Fatalf("parse statement: %v", err)
			}
			match, unconditional := statements[0].denies(testCase.action)
			if match != testCase.wantMatch || unconditional != testCase.unconditional {
				t.Fatalf("denies(%q) = %q, %v; want %q, %v", testCase.action, match, unconditional, testCase.wantMatch, testCase.unconditional)
			}
		})
	}
}

func TestCoverageRejectsMalformedStatements(t *testing.T) {
	t.Parallel()
	for _, document := range []string{
		`{}`,
		`{"Statement":{"Effect":"deny","Action":"*"}}`,
		`{"Statement":{"Effect":"Deny"}}`,
		`{"Statement":{"Effect":"Deny","Action":"*","NotAction":"iam:*"}}`,
		`{"Statement":{"Effect":"Deny","Action":7}}`,
	} {
		if _, err := parseCoverageStatements(encodingjson.RawMessage(document)); err == nil {
			t.Errorf("parseCoverageStatements(%s) succeeded, want error", document)
		}
	}
}

func TestCoverageUnknownPolicyFailsWithoutOutput(t *testing.T) {
	t.Parallel()
	var output bytes.Buffer
	err := displayCoverageReport(
		context.Background(), &output, coverageFixtureClient(),
		coverageQuery{Type: coverageQueryTypePolicy, PolicyID: "p-missing1"},
		coverageRootID, "Root", coverageManagement, json, true,
	)
	var notFound *types.PolicyNotFoundException
	if !errors.As(err, &notFound) {
		t.Fatalf("error = %v, want PolicyNotFoundException", err)
	}
	if output.Len() != 0 {
		t.Fatalf("failed report wrote partial output: %s", output.String())
	}
}

func TestCoverageFailOnGapsWritesReportThenReturnsGapStatus(t *testing.T) {
	t.Parallel()
	query := coverageQuery{Type: coverageQueryTypeAction, Action: "cloudtrail:StopLogging"}

	var output bytes.Buffer
	err := displayCoverageReport(context.Background(), &output, coverageFixtureClient(), query, coverageRootID, "Root", coverageManagement, json, true)
	var gapErr *coverageGapError
	if !errors.As(err, &gapErr) || gapErr.uncovered != 1 {
		t.Fatalf("error = %v, want coverageGapError for 1 uncovered account", err)
	}
	var decoded coverageResult
	if err := encodingjson.Unmarshal(output.Bytes(), &decoded); err != nil || decoded.Summary.Uncovered != 1 {
		t.Fatalf("report was not written before the gap status: %v\n%s", err, output.String())
	}

	if err := displayCoverageReport(context.Background(), &bytes.Buffer{}, coverageFixtureClient(), query, coverageRootID, "Root", coverageManagement, json, false); err != nil {
		t.Fatalf("report with gaps but without --fail-on-gaps returned %v", err)
	}
	// Conditional coverage alone does not fail the gate.
	client := coverageFixtureClient()
	describe := client.describePolicyFn
	client.describePolicyFn = func(ctx context.Context, input *organizations.DescribePolicyInput) (*organizations.DescribePolicyOutput, error) {
		if aws.ToString(input.PolicyId) == "p-bucket01" {
			policySummary := types.PolicySummary{Id: input.PolicyId, Name: aws.String("DenyLogBucket"), Type: types.PolicyTypeServiceControlPolicy}
			return &organizations.DescribePolicyOutput{Policy: &types.Policy{
				PolicySummary: &policySummary,
				Content:       aws.String(`{"Statement":{"Effect":"Deny","Action":"cloudtrail:*","Resource":"*","Condition":{"Bool":{"aws:ViaAWSService":"false"}}}}`),
			}}, nil
		}
		return describe(ctx, input)
	}
	if err := displayCoverageReport(context.Background(), &bytes.Buffer{}, client, query, coverageRootID, "Root", coverageManagement, json, true); err != nil {
		t.Fatalf("conditional-only report returned %v", err)
	}
}

func TestCoverageTextReportsEveryBucket(t *testing.T) {
	t.Parallel()
	result := buildCoverageFixture(t, coverageQuery{Type: coverageQueryTypeAction, Action: "cloudtrail:StopLogging"})
	var output bytes.Buffer
	if err := writeCoverageReport(&output, result, text); err != nil {
		t.Fatalf("write text report: %v", err)
	}
	for _, expected := range []string{
		"Coverage of Deny for action cloudtrail:StopLogging\n",
		"Accounts: 7 (3 covered, 1 conditionally covered, 1 uncovered, 2 excluded)\n",
		"Uncovered accounts:\n- Account acct-666 [666666666666] in Root [r-root]\n",
		`SCP DenyStopLoggingExceptBreakGlass [p-cond0001] statement 0 (BreakGlass) — direct; Condition {"ArnNotLike":{"aws:PrincipalArn":"arn:aws:iam::*:role/BreakGlass"}}`,
		"SCP DenyCloudTrail [p-guard001] statement 0 (DenyCloudTrail) — inherited from OU Security [ou-root-security]",
		"SCP DenyAllButIAM [p-notact01] statement 0 via NotAction — direct",
		"- Account acct-111 [111111111111] in Root [r-root] — management account; SCPs do not apply\n",
		"- Account acct-777 [777777777777] in Root [r-root] — account state SUSPENDED\n",
	} {
		if !strings.Contains(output.String(), expected) {
			t.Errorf("text report missing %q:\n%s", expected, output.String())
		}
	}
}

func TestSelectedCoverageQueryRequiresOneExactSelector(t *testing.T) {
	t.Parallel()
	for _, testCase := range []struct {
		policyID, action     string
		policySet, actionSet bool
	}{
		{},
		{policyID: coverageGuardPolicy, policySet: true, action: "cloudtrail:StopLogging", actionSet: true},
		{policyID: "guard", policySet: true},
		{action: "cloudtrail:*", actionSet: true},
		{action: "*", actionSet: true},
		{action: "StopLogging", actionSet: true},
	} {
		_, err := selectedCoverageQuery(testCase.policyID, testCase.policySet, testCase.action, testCase.actionSet)
		if diagnostic := classifyError(err); diagnostic.ExitCode != exitInvocation {
			t.Errorf("selectedCoverageQuery(%+v) diagnostic = %+v, want invalid invocation", testCase, diagnostic)
		}
	}
	query, err := selectedCoverageQuery("", false, "cloudtrail:StopLogging", true)
	if err != nil || query != (coverageQuery{Type: coverageQueryTypeAction, Action: "cloudtrail:StopLogging"}) {
		t.Fatalf("action query = %+v, %v", query, err)
	}
}
