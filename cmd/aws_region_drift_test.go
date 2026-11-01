package cmd

import (
	"bytes"
	"context"
	encodingjson "encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/account"
	accounttypes "github.com/aws/aws-sdk-go-v2/service/account/types"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"github.com/aws/smithy-go"
	"github.com/spf13/cobra"
)

const (
	driftRootID       = "r-root"
	driftWorkloadsOU  = "ou-root-workload"
	driftNestedOU     = "ou-root-nested01"
	driftManagement   = "111111111111" // Region allow list attached directly, but SCPs never apply
	driftNested       = "222222222222" // Workloads > Nested; inherits the allow list from Workloads
	driftIntersection = "333333333333" // in Workloads; a second, wildcard allow list attached directly
	driftDenyList     = "444444444444" // under root; Deny only for ap-east-1
	driftUnclear      = "555555555555" // under root; only uninterpretable Region conditions
	driftUnrestricted = "666666666666" // under root; only FullAWSAccess
	driftSuspended    = "777777777777" // suspended, under root
)

type fakeRegionsClient struct {
	mu      sync.Mutex
	regions map[string][][]accounttypes.Region // pages per account
	denied  string                             // account whose ListRegions request AWS denies
	calls   []string
}

func (fake *fakeRegionsClient) ListRegions(
	_ context.Context, input *account.ListRegionsInput, _ ...func(*account.Options),
) (*account.ListRegionsOutput, error) {
	accountID := aws.ToString(input.AccountId)
	fake.mu.Lock()
	fake.calls = append(fake.calls, accountID)
	fake.mu.Unlock()
	if accountID == fake.denied {
		return nil, &smithy.OperationError{
			ServiceID: "Account", OperationName: "ListRegions",
			Err: &accounttypes.AccessDeniedException{Message: aws.String("not authorized")},
		}
	}
	pages, found := fake.regions[accountID]
	if !found {
		return nil, fmt.Errorf("unexpected ListRegions for account %q", accountID)
	}
	page := 0
	if input.NextToken != nil {
		if _, err := fmt.Sscanf(aws.ToString(input.NextToken), "page-%d", &page); err != nil {
			return nil, err
		}
	}
	output := &account.ListRegionsOutput{Regions: pages[page]}
	if page+1 < len(pages) {
		output.NextToken = aws.String(fmt.Sprintf("page-%d", page+1))
	}
	return output, nil
}

func driftRegions(statuses ...string) []accounttypes.Region {
	regions := make([]accounttypes.Region, 0, len(statuses))
	for _, entry := range statuses {
		name, status, _ := strings.Cut(entry, "=")
		regions = append(regions, accounttypes.Region{RegionName: aws.String(name), RegionOptStatus: accounttypes.RegionOptStatus(status)})
	}
	return regions
}

// regionDriftFixture models an organization whose approved-Regions SCP is
// attached to the Workloads OU only, following the AWS-documented pattern with
// a NotAction carve-out for global services and an exempt administrator role.
func regionDriftFixture() (*fakeOrganizationsClient, *fakeRegionsClient, map[string][]string) {
	documents := map[string]string{
		"p-FullAWSAccess": `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}`,
		"p-regions01": `{"Version":"2012-10-17","Statement":[{"Sid":"DenyOutsideApproved","Effect":"Deny",` +
			`"NotAction":["iam:*","organizations:*","route53:*","cloudfront:*","sts:*","support:*"],"Resource":"*",` +
			`"Condition":{"StringNotEquals":{"aws:RequestedRegion":["us-east-1","eu-west-1"]},` +
			`"ArnNotLike":{"aws:PrincipalArn":"arn:aws:iam::*:role/OrgAdmin"}}}]}`,
		"p-euonly01": `{"Version":"2012-10-17","Statement":{"Effect":"Deny","Action":"*","Resource":"*",` +
			`"Condition":{"StringNotLike":{"aws:RequestedRegion":"eu-*"}}}}`,
		"p-denyhk01": `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"},` +
			`{"Sid":"DenyHongKong","Effect":"Deny","Action":"*","Condition":{"StringEquals":{"aws:RequestedRegion":"ap-east-1"}}}]}`,
		"p-unclear1": `{"Version":"2012-10-17","Statement":[` +
			`{"Sid":"SetOperator","Effect":"Deny","Action":"*","Resource":"*","Condition":{"ForAnyValue:StringNotEquals":{"aws:RequestedRegion":["us-east-1"]}}},` +
			`{"Sid":"OnlyEC2","Effect":"Deny","Action":["ec2:*"],"Resource":"*","Condition":{"StringNotEquals":{"aws:RequestedRegion":"us-east-1"}}},` +
			`{"Sid":"Variable","Effect":"Deny","Action":"*","Resource":"*","Condition":{"StringNotEquals":{"aws:RequestedRegion":"${aws:PrincipalTag/home-region}"}}},` +
			`{"Sid":"S3Unrelated","Effect":"Deny","Action":"s3:DeleteBucket","Resource":"*"}]}`,
	}
	names := map[string]string{
		"p-FullAWSAccess": "FullAWSAccess", "p-regions01": "DenyOutsideApprovedRegions", "p-euonly01": "EUOnly",
		"p-denyhk01": "DenyHongKong", "p-unclear1": "UnclearRegions",
	}
	attached := map[string][]string{
		driftRootID:       {"p-FullAWSAccess"},
		driftWorkloadsOU:  {"p-regions01"},
		driftNestedOU:     {},
		driftManagement:   {"p-regions01"},
		driftNested:       {},
		driftIntersection: {"p-euonly01"},
		driftDenyList:     {"p-denyhk01"},
		driftUnclear:      {"p-unclear1"},
		driftUnrestricted: {},
		driftSuspended:    {},
	}
	accounts := map[string][]string{
		driftRootID:      {driftManagement, driftDenyList, driftUnclear, driftUnrestricted, driftSuspended},
		driftWorkloadsOU: {driftIntersection},
		driftNestedOU:    {driftNested},
	}
	ous := map[string][]types.OrganizationalUnit{
		driftRootID:      {{Id: aws.String(driftWorkloadsOU), Name: aws.String("Workloads")}},
		driftWorkloadsOU: {{Id: aws.String(driftNestedOU), Name: aws.String("Nested")}},
		driftNestedOU:    {},
	}
	summary := func(id string) types.PolicySummary {
		return types.PolicySummary{Id: aws.String(id), Name: aws.String(names[id]), Type: types.PolicyTypeServiceControlPolicy}
	}
	organizationsClient := &fakeOrganizationsClient{
		listAccountsForParentFn: func(_ context.Context, input *organizations.ListAccountsForParentInput) (*organizations.ListAccountsForParentOutput, error) {
			output := &organizations.ListAccountsForParentOutput{}
			for _, id := range accounts[aws.ToString(input.ParentId)] {
				state := types.AccountStateActive
				if id == driftSuspended {
					state = types.AccountStateSuspended
				}
				output.Accounts = append(output.Accounts, types.Account{Id: aws.String(id), Name: aws.String("acct-" + id[:3]), State: state})
			}
			return output, nil
		},
		listOUsForParentFn: func(_ context.Context, input *organizations.ListOrganizationalUnitsForParentInput) (*organizations.ListOrganizationalUnitsForParentOutput, error) {
			return &organizations.ListOrganizationalUnitsForParentOutput{OrganizationalUnits: ous[aws.ToString(input.ParentId)]}, nil
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
			policySummary := summary(id)
			return &organizations.DescribePolicyOutput{Policy: &types.Policy{PolicySummary: &policySummary, Content: aws.String(documents[id])}}, nil
		},
	}
	regionsClient := &fakeRegionsClient{regions: map[string][][]accounttypes.Region{
		// Two pages, transitional states, and an allowed Region that is disabled.
		driftNested: {
			driftRegions("us-west-2=ENABLED_BY_DEFAULT", "us-east-1=ENABLED_BY_DEFAULT"),
			driftRegions("ap-east-1=DISABLING", "me-south-1=DISABLED", "eu-west-1=DISABLED"),
		},
		driftIntersection: {driftRegions("us-east-1=ENABLED_BY_DEFAULT", "eu-west-1=ENABLED_BY_DEFAULT", "eu-central-1=ENABLED", "eu-south-1=DISABLED")},
		driftDenyList:     {driftRegions("us-east-1=ENABLED_BY_DEFAULT", "ap-east-1=ENABLED", "me-south-1=DISABLED")},
		driftUnclear:      {driftRegions("us-east-1=ENABLED_BY_DEFAULT", "ap-east-1=ENABLING")},
		driftUnrestricted: {driftRegions("us-east-1=ENABLED_BY_DEFAULT", "us-west-2=ENABLED_BY_DEFAULT", "ap-east-1=DISABLED")},
	}}
	return organizationsClient, regionsClient, accounts
}

func buildRegionDriftFixture(t *testing.T) (regionDriftResult, *fakeRegionsClient) {
	t.Helper()
	client, regionsClient, _ := regionDriftFixture()
	result, err := buildRegionDriftReport(context.Background(), client, regionsClient, driftRootID, "Root", driftManagement)
	if err != nil {
		t.Fatalf("build region drift report: %v", err)
	}
	return result, regionsClient
}

func driftAccount(t *testing.T, result regionDriftResult, accountID string) regionDriftAccount {
	t.Helper()
	for _, entry := range result.Accounts {
		if entry.Account.ID == accountID {
			return entry
		}
	}
	t.Fatalf("account %s missing from report", accountID)
	return regionDriftAccount{}
}

type driftBuckets struct{ allowed, blind, denied, allowedDisabled []string }

func assertDriftBuckets(t *testing.T, entry regionDriftAccount, want driftBuckets) {
	t.Helper()
	got := driftBuckets{entry.EnabledAllowedRegions, entry.BlindSpotRegions, entry.EnabledDeniedRegions, entry.AllowedDisabledRegions}
	normalize := func(values []string) []string {
		if values == nil {
			return []string{}
		}
		return values
	}
	want = driftBuckets{normalize(want.allowed), normalize(want.blind), normalize(want.denied), normalize(want.allowedDisabled)}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("account %s buckets (allowed, blind spots, denied, allowed but disabled) = %v, want %v", entry.Account.ID, got, want)
	}
}

func TestRegionDriftComparesEnabledRegionsWithInheritedAllowLists(t *testing.T) {
	t.Parallel()
	result, regionsClient := buildRegionDriftFixture(t)

	// The allow list is inherited two levels down; ap-east-1 is DISABLING and
	// still counts as enabled, so the SCP denying it is reported.
	nested := driftAccount(t, result, driftNested)
	assertDriftBuckets(t, nested, driftBuckets{
		allowed: []string{"us-east-1"}, denied: []string{"ap-east-1", "us-west-2"}, allowedDisabled: []string{"eu-west-1"},
	})
	if nested.NoRegionRestriction || len(nested.Restrictions) != 1 || len(nested.UninterpretableRestrictions) != 0 {
		t.Fatalf("nested restrictions = %+v / %+v", nested.Restrictions, nested.UninterpretableRestrictions)
	}
	restriction := nested.Restrictions[0]
	wantSource := regionDriftSource{
		PolicyID: "p-regions01", PolicyName: "DenyOutsideApprovedRegions", Inherited: true, Statement: 0, Sid: "DenyOutsideApproved",
		AttachedTo: scpAttachmentTarget{Type: organizationalUnitEntityType, ID: driftWorkloadsOU, Name: "Workloads"},
	}
	if restriction.regionDriftSource != wantSource || restriction.Kind != regionRestrictionAllowList ||
		restriction.Operator != "StringNotEquals" || !reflect.DeepEqual(restriction.Regions, []string{"us-east-1", "eu-west-1"}) {
		t.Fatalf("nested restriction = %+v", restriction)
	}
	// The NotAction for global services and the exempt role are carve-outs of
	// the restriction, not reasons to discard it.
	if len(restriction.CarveOuts) != 2 || restriction.CarveOuts[0].Source != exemptionSourceNotAction ||
		restriction.CarveOuts[0].Values[0] != "iam:*" || restriction.CarveOuts[1].Category != "principal" {
		t.Fatalf("nested carve-outs = %+v", restriction.CarveOuts)
	}
	wantEnabled := []regionDriftEnabledRegion{
		{"ap-east-1", "DISABLING"}, {"us-east-1", "ENABLED_BY_DEFAULT"}, {"us-west-2", "ENABLED_BY_DEFAULT"},
	}
	if !reflect.DeepEqual(nested.EnabledRegions, wantEnabled) {
		t.Fatalf("nested enabled Regions = %+v", nested.EnabledRegions)
	}

	// Two allow lists intersect: only eu-west-1 is in both, and the wildcard
	// eu-* list does not widen the inherited one.
	assertDriftBuckets(t, driftAccount(t, result, driftIntersection), driftBuckets{
		allowed: []string{"eu-west-1"}, denied: []string{"eu-central-1", "us-east-1"},
	})

	// A deny list restricts, but enabled Regions it does not name are blind spots.
	denyList := driftAccount(t, result, driftDenyList)
	assertDriftBuckets(t, denyList, driftBuckets{blind: []string{"us-east-1"}, denied: []string{"ap-east-1"}})
	if denyList.NoRegionRestriction || denyList.Restrictions[0].Kind != regionRestrictionDenyList || denyList.Restrictions[0].Statement != 1 {
		t.Fatalf("deny-list account = %+v", denyList)
	}

	unrestricted := driftAccount(t, result, driftUnrestricted)
	assertDriftBuckets(t, unrestricted, driftBuckets{blind: []string{"us-east-1", "us-west-2"}})
	if !unrestricted.NoRegionRestriction {
		t.Fatal("account with only FullAWSAccess reported a Region restriction")
	}

	// The management account has the allow list attached directly, but SCPs
	// never restrict it; it and the suspended account are excluded without a
	// ListRegions call.
	wantExcluded := []coverageExcludedAccount{
		{Account: coverageAccountInfo{ID: driftManagement, Name: "acct-111", State: "ACTIVE"}, Reason: coverageExcludedManagementAccount},
		{Account: coverageAccountInfo{ID: driftSuspended, Name: "acct-777", State: "SUSPENDED"}, Reason: coverageExcludedInactiveAccount},
	}
	for index := range result.ExcludedAccounts {
		result.ExcludedAccounts[index].Path = nil
	}
	if !reflect.DeepEqual(result.ExcludedAccounts, wantExcluded) {
		t.Fatalf("excluded = %+v, want %+v", result.ExcludedAccounts, wantExcluded)
	}
	for _, called := range regionsClient.calls {
		if called == driftManagement || called == driftSuspended {
			t.Fatalf("ListRegions was called for excluded account %s", called)
		}
	}
	if len(regionsClient.calls) != 6 { // five applicable accounts, one with two pages
		t.Fatalf("ListRegions calls = %v", regionsClient.calls)
	}
	want := regionDriftSummary{Accounts: 7, Restricted: 3, Unrestricted: 2, WithBlindSpots: 3, WithUninterpretableRestrictions: 1, Excluded: 2}
	if result.Summary != want {
		t.Fatalf("summary = %+v, want %+v", result.Summary, want)
	}
}

func TestRegionDriftReportsUninterpretableRegionConditionsWithoutGuessing(t *testing.T) {
	t.Parallel()
	result, _ := buildRegionDriftFixture(t)
	entry := driftAccount(t, result, driftUnclear)

	// Nothing interpretable restricts the account, so every enabled Region,
	// including the ENABLING one, is a blind spot.
	assertDriftBuckets(t, entry, driftBuckets{blind: []string{"ap-east-1", "us-east-1"}})
	if !entry.NoRegionRestriction || len(entry.Restrictions) != 0 {
		t.Fatalf("restrictions = %+v, want none", entry.Restrictions)
	}
	type unclear struct {
		statement int
		sid       string
		operator  string
		reason    string
	}
	var got []unclear
	for _, item := range entry.UninterpretableRestrictions {
		if item.PolicyID != "p-unclear1" || item.Inherited || item.Key != "aws:RequestedRegion" {
			t.Fatalf("uninterpretable source = %+v", item)
		}
		got = append(got, unclear{item.Statement, item.Sid, item.Operator, item.Reason})
	}
	want := []unclear{
		{0, "SetOperator", "ForAnyValue:StringNotEquals", "set operator qualifiers ForAnyValue and ForAllValues are not interpreted"},
		{1, "OnlyEC2", "StringNotEquals", "Deny applies only to actions ec2:*, not to every action"},
		{2, "Variable", "StringNotEquals", "policy variables in aws:RequestedRegion values are not interpreted"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("uninterpretable = %+v, want %+v", got, want)
	}
}

func TestRegionRulesClassifyOperatorsAndScope(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name      string
		statement string
		kind      string
		reason    string
		denied    []string // of us-east-1, US-EAST-1, eu-west-1
	}{
		{
			"case-sensitive equality", `{"Effect":"Deny","Action":"*","Condition":{"StringNotEquals":{"aws:RequestedRegion":"US-EAST-1"}}}`,
			regionRestrictionAllowList, "",
			[]string{"us-east-1", "eu-west-1"},
		},
		{
			"ignore case", `{"Effect":"Deny","Action":"*","Condition":{"StringNotEqualsIgnoreCase":{"aws:requestedregion":"US-EAST-1"}}}`,
			regionRestrictionAllowList, "",
			[]string{"eu-west-1"},
		},
		{
			"IfExists deny list", `{"Effect":"Deny","Action":"*","Resource":["*"],"Condition":{"StringLikeIfExists":{"aws:RequestedRegion":"eu-*"}}}`,
			regionRestrictionDenyList, "",
			[]string{"eu-west-1"},
		},
		{
			"NotResource carve-out", `{"Effect":"Deny","Action":"*","NotResource":"arn:aws:s3:::logs/*","Condition":{"StringNotEquals":{"aws:RequestedRegion":"eu-west-1"}}}`,
			regionRestrictionAllowList, "",
			[]string{"us-east-1", "US-EAST-1"},
		},
		{
			"resource scope", `{"Effect":"Deny","Action":"*","Resource":"arn:aws:s3:::logs","Condition":{"StringNotEquals":{"aws:RequestedRegion":"eu-west-1"}}}`,
			"", "Deny applies only to resources arn:aws:s3:::logs, not to every resource", nil,
		},
		{
			"non-string operator", `{"Effect":"Deny","Action":"*","Condition":{"ArnNotLike":{"aws:RequestedRegion":"eu-west-1"}}}`,
			"", "only string operators are interpreted for aws:RequestedRegion", nil,
		},
		{
			"two Region conditions", `{"Effect":"Deny","Action":"*","Condition":{"StringNotEquals":{"aws:RequestedRegion":"eu-west-1"},"StringNotLike":{"aws:RequestedRegion":"us-*"}}}`,
			"", "statement has more than one aws:RequestedRegion condition, which is not interpreted", nil,
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			rules, err := extractRegionRules(organizationPolicy{ID: "p-test0001", Content: encodingjson.RawMessage(`{"Statement":` + testCase.statement + `}`)})
			if err != nil {
				t.Fatalf("extract: %v", err)
			}
			if testCase.reason != "" {
				if len(rules.rules) != 0 || len(rules.unclear) == 0 || rules.unclear[0].reason != testCase.reason {
					t.Fatalf("rules = %+v, want uninterpretable %q", rules, testCase.reason)
				}
				return
			}
			if len(rules.rules) != 1 || len(rules.unclear) != 0 || rules.rules[0].kind != testCase.kind {
				t.Fatalf("rules = %+v, want one %s", rules, testCase.kind)
			}
			var denied []string
			for _, region := range []string{"us-east-1", "US-EAST-1", "eu-west-1"} {
				if rules.rules[0].denies(region) {
					denied = append(denied, region)
				}
			}
			if !reflect.DeepEqual(denied, testCase.denied) {
				t.Fatalf("denied = %v, want %v", denied, testCase.denied)
			}
		})
	}
}

func TestRegionDriftFailOnBlindSpotsWritesReportThenReturnsFindingStatus(t *testing.T) {
	t.Parallel()
	client, regionsClient, _ := regionDriftFixture()
	var output bytes.Buffer
	err := displayRegionDriftReport(context.Background(), &output, client, regionsClient, driftRootID, "Root", driftManagement, json, true)
	var blindSpotErr *regionDriftBlindSpotError
	if !errors.As(err, &blindSpotErr) || blindSpotErr.accounts != 3 {
		t.Fatalf("error = %v, want regionDriftBlindSpotError for 3 accounts", err)
	}
	var decoded regionDriftResult
	if err := encodingjson.Unmarshal(output.Bytes(), &decoded); err != nil || decoded.Summary.WithBlindSpots != 3 {
		t.Fatalf("report was not written before the blind-spot status: %v\n%s", err, output.String())
	}

	client, regionsClient, _ = regionDriftFixture()
	if err := displayRegionDriftReport(context.Background(), &bytes.Buffer{}, client, regionsClient, driftRootID, "Root", driftManagement, json, false); err != nil {
		t.Fatalf("report without --fail-on-blind-spots returned %v", err)
	}

	// Restricted accounts without blind spots pass the gate.
	client, regionsClient, accounts := regionDriftFixture()
	accounts[driftRootID] = []string{driftManagement, driftSuspended}
	if err := displayRegionDriftReport(context.Background(), &bytes.Buffer{}, client, regionsClient, driftRootID, "Root", driftManagement, json, true); err != nil {
		t.Fatalf("report without blind spots returned %v", err)
	}
}

func TestRegionDriftBlindSpotStatusExitsSixWithEmptyStderr(t *testing.T) {
	t.Parallel()
	command := &cobra.Command{Use: "region-drift", SilenceErrors: true, SilenceUsage: true, RunE: func(cmd *cobra.Command, _ []string) error {
		_, _ = cmd.OutOrStdout().Write([]byte("{}\n"))
		return &regionDriftBlindSpotError{accounts: 1}
	}}
	var stdout, stderr bytes.Buffer
	if status := executeCommand(command, nil, &stdout, &stderr); status != exitFindings {
		t.Fatalf("exit status = %d, want %d", status, exitFindings)
	}
	if stdout.String() != "{}\n" || stderr.Len() != 0 {
		t.Fatalf("stdout = %q, stderr = %q; want the report and empty stderr", stdout.String(), stderr.String())
	}
}

func TestRegionDriftListRegionsDeniedFailsWithoutOutput(t *testing.T) {
	t.Parallel()
	client, regionsClient, _ := regionDriftFixture()
	regionsClient.denied = driftUnrestricted
	var output bytes.Buffer
	err := displayRegionDriftReport(context.Background(), &output, client, regionsClient, driftRootID, "Root", driftManagement, json, false)
	diagnostic := classifyError(err)
	if diagnostic.ExitCode != exitAuthorization || diagnostic.Operation != "ListRegions" ||
		!strings.Contains(diagnostic.Remediation, "account:ListRegions") {
		t.Fatalf("diagnostic = %+v, want access denied for ListRegions", diagnostic)
	}
	if output.Len() != 0 {
		t.Fatalf("failed report wrote partial output: %s", output.String())
	}
}

func TestRegionDriftTextReportsEveryBucket(t *testing.T) {
	t.Parallel()
	result, _ := buildRegionDriftFixture(t)
	var output bytes.Buffer
	if err := writeRegionDriftReport(&output, result, text); err != nil {
		t.Fatalf("write text report: %v", err)
	}
	for _, expected := range []string{
		"Accounts: 7 (3 restricted, 2 unrestricted, 3 with blind spots, 1 with uninterpretable restrictions, 2 excluded)\n",
		"\nAccount acct-222 [222222222222] in Root [r-root] > OU Workloads [ou-root-workload] > OU Nested [ou-root-nested01]\n" +
			"  SCP DenyOutsideApprovedRegions [p-regions01] statement 0 (DenyOutsideApproved), inherited from OU Workloads [ou-root-workload]: allows only us-east-1, eu-west-1 [StringNotEquals]\n" +
			"      carve-out: exempt actions (NotAction): iam:*, organizations:*, route53:*, cloudfront:*, sts:*, support:*\n" +
			"      carve-out: principal exempt when aws:PrincipalArn matches arn:aws:iam::*:role/OrgAdmin [ArnNotLike]\n" +
			"  Enabled and allowed: us-east-1\n" +
			"  Blind spots (enabled, not denied): none\n" +
			"  Enabled but denied: ap-east-1, us-west-2\n" +
			"  Allowed but disabled: eu-west-1\n",
		"  SCP DenyHongKong [p-denyhk01] statement 1 (DenyHongKong), direct: denies ap-east-1 [StringEquals]\n",
		"  SCP UnclearRegions [p-unclear1] statement 1 (OnlyEC2), direct: not interpretable: StringNotEquals aws:RequestedRegion us-east-1: Deny applies only to actions ec2:*, not to every action\n",
		"\nAccount acct-666 [666666666666] in Root [r-root]\n  Region restrictions: none\n  Enabled and allowed: none\n  Blind spots (enabled, not denied): us-east-1, us-west-2\n",
		"- Account acct-111 [111111111111] in Root [r-root] — management account; SCPs do not apply\n",
		"- Account acct-777 [777777777777] in Root [r-root] — account state SUSPENDED\n",
	} {
		if !strings.Contains(output.String(), expected) {
			t.Errorf("text report missing %q:\n%s", expected, output.String())
		}
	}
}
