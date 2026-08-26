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
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/aws/aws-sdk-go-v2/service/organizations/types"
)

const (
	queryRootID            = "r-root"
	queryManagementAccount = "111111111111"
	queryDirectAccount     = "222222222222"
	queryInheritedAccount  = "333333333333"
	queryOUID              = "ou-root-12345678"
	queryPolicyID          = "p-query001"
)

func queryFixtureClient(scrambled bool) *fakeOrganizationsClient {
	children := map[string][]string{
		queryRootID + ":ACCOUNT":             {queryDirectAccount, queryManagementAccount},
		queryRootID + ":ORGANIZATIONAL_UNIT": {queryOUID},
		queryOUID + ":ACCOUNT":               {queryInheritedAccount},
		queryOUID + ":ORGANIZATIONAL_UNIT":   {},
	}
	if scrambled {
		children[queryRootID+":ACCOUNT"] = []string{queryManagementAccount, queryDirectAccount}
	}
	policy := types.PolicySummary{
		Id: aws.String(queryPolicyID), Name: aws.String("Guardrail"), Type: types.PolicyTypeServiceControlPolicy,
	}
	targets := []types.PolicyTargetSummary{
		{TargetId: aws.String(queryOUID), Name: aws.String("Production"), Type: types.TargetTypeOrganizationalUnit},
		{TargetId: aws.String(queryDirectAccount), Name: aws.String("Direct"), Type: types.TargetTypeAccount},
		{TargetId: aws.String(queryRootID), Name: aws.String("Root"), Type: types.TargetTypeRoot},
		{TargetId: aws.String(queryManagementAccount), Name: aws.String("Management"), Type: types.TargetTypeAccount},
		{TargetId: aws.String(queryOUID), Name: aws.String("Production"), Type: types.TargetTypeOrganizationalUnit},
	}
	if scrambled {
		targets[0], targets[2] = targets[2], targets[0]
	}
	return &fakeOrganizationsClient{
		listTargetsForPolicyFn: func(_ context.Context, input *organizations.ListTargetsForPolicyInput) (*organizations.ListTargetsForPolicyOutput, error) {
			if aws.ToString(input.PolicyId) != queryPolicyID {
				return &organizations.ListTargetsForPolicyOutput{}, nil
			}
			return &organizations.ListTargetsForPolicyOutput{Targets: targets}, nil
		},
		listChildrenFn: func(_ context.Context, input *organizations.ListChildrenInput) (*organizations.ListChildrenOutput, error) {
			key := aws.ToString(input.ParentId) + ":" + string(input.ChildType)
			ids, found := children[key]
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
			id := aws.ToString(input.AccountId)
			name := map[string]string{
				queryManagementAccount: "Management",
				queryDirectAccount:     "Direct",
				queryInheritedAccount:  "Inherited",
			}[id]
			return &organizations.DescribeAccountOutput{Account: &types.Account{Id: input.AccountId, Name: aws.String(name)}}, nil
		},
		describeOrganizationalUnit: func(_ context.Context, input *organizations.DescribeOrganizationalUnitInput) (*organizations.DescribeOrganizationalUnitOutput, error) {
			return &organizations.DescribeOrganizationalUnitOutput{OrganizationalUnit: &types.OrganizationalUnit{
				Id: input.OrganizationalUnitId, Name: aws.String("Production"),
			}}, nil
		},
		listParentsFn: func(_ context.Context, input *organizations.ListParentsInput) (*organizations.ListParentsOutput, error) {
			switch aws.ToString(input.ChildId) {
			case queryDirectAccount, queryManagementAccount:
				return &organizations.ListParentsOutput{Parents: []types.Parent{{Id: aws.String(queryRootID), Type: types.ParentTypeRoot}}}, nil
			case queryInheritedAccount:
				return &organizations.ListParentsOutput{Parents: []types.Parent{{Id: aws.String(queryOUID), Type: types.ParentTypeOrganizationalUnit}}}, nil
			case queryOUID:
				return &organizations.ListParentsOutput{Parents: []types.Parent{{Id: aws.String(queryRootID), Type: types.ParentTypeRoot}}}, nil
			default:
				return nil, fmt.Errorf("unexpected parent lookup %s", aws.ToString(input.ChildId))
			}
		},
		listPoliciesForTargetFn: func(_ context.Context, input *organizations.ListPoliciesForTargetInput) (*organizations.ListPoliciesForTargetOutput, error) {
			switch aws.ToString(input.TargetId) {
			case queryRootID, queryManagementAccount, queryDirectAccount, queryOUID:
				return &organizations.ListPoliciesForTargetOutput{Policies: []types.PolicySummary{policy, policy}}, nil
			case queryInheritedAccount:
				return &organizations.ListPoliciesForTargetOutput{}, nil
			default:
				return nil, fmt.Errorf("unexpected policy lookup %s", aws.ToString(input.TargetId))
			}
		},
	}
}

func TestPoliciesQueryReturnsOnlyTargetPathAndApplicablePolicies(t *testing.T) {
	t.Parallel()

	client := queryFixtureClient(false)
	client.listChildrenFn = func(context.Context, *organizations.ListChildrenInput) (*organizations.ListChildrenOutput, error) {
		return nil, errors.New("focused policies query must not list children")
	}
	result, err := buildPoliciesQuery(
		context.Background(), client, queryInheritedAccount,
		queryRootID, "Root", queryManagementAccount,
	)
	if err != nil {
		t.Fatalf("build policies query: %v", err)
	}
	if result.SchemaVersion != "1" || result.Target.ID != queryInheritedAccount || !result.Target.SCPApplicable {
		t.Fatalf("unexpected result header: %+v", result)
	}
	wantPath := []string{queryRootID, queryOUID, queryInheritedAccount}
	gotPath := make([]string, len(result.Path))
	for index := range result.Path {
		gotPath[index] = result.Path[index].ID
	}
	if !reflect.DeepEqual(gotPath, wantPath) {
		t.Fatalf("path = %v, want %v", gotPath, wantPath)
	}
	if len(result.Policies) != 2 || result.Policies[0].AttachedTo.ID != queryRootID ||
		result.Policies[1].AttachedTo.ID != queryOUID || !result.Policies[0].Inherited || !result.Policies[1].Inherited {
		t.Fatalf("unexpected policy provenance: %+v", result.Policies)
	}

	var output bytes.Buffer
	if err := writePoliciesQuery(&output, result, json); err != nil {
		t.Fatalf("write policies query: %v", err)
	}
	if strings.Contains(output.String(), queryDirectAccount) || !strings.HasSuffix(output.String(), "}\n") {
		t.Fatalf("output contains unrelated organization data or invalid framing:\n%s", output.String())
	}
}

func TestPoliciesQueryManagementAccountHasExplicitEmptyNonApplicableResult(t *testing.T) {
	t.Parallel()

	result, err := buildPoliciesQuery(
		context.Background(), queryFixtureClient(false), queryManagementAccount,
		queryRootID, "Root", queryManagementAccount,
	)
	if err != nil {
		t.Fatalf("build management account query: %v", err)
	}
	if result.Target.ManagementAccount == nil || !*result.Target.ManagementAccount || result.Target.SCPApplicable || len(result.Policies) != 0 {
		t.Fatalf("management account result implies SCP applicability: %+v", result)
	}
	encoded, err := encodingjson.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), `"policies":[]`) {
		t.Fatalf("management result omits explicit empty policies: %s", encoded)
	}
}

func TestAttachmentsQueryDeduplicatesLocationsExcludesManagementFromAffectedAndIsStable(t *testing.T) {
	t.Parallel()

	first, err := buildAttachmentsQuery(
		context.Background(), queryFixtureClient(false), queryPolicyID,
		queryRootID, "Root", queryManagementAccount,
	)
	if err != nil {
		t.Fatalf("build attachments query: %v", err)
	}
	second, err := buildAttachmentsQuery(
		context.Background(), queryFixtureClient(true), queryPolicyID,
		queryRootID, "Root", queryManagementAccount,
	)
	if err != nil {
		t.Fatalf("build scrambled attachments query: %v", err)
	}
	firstJSON, _ := encodingjson.Marshal(first)
	secondJSON, _ := encodingjson.Marshal(second)
	if !bytes.Equal(firstJSON, secondJSON) {
		t.Fatalf("query order is unstable:\n%s\n%s", firstJSON, secondJSON)
	}

	wantDirect := []string{queryRootID, queryManagementAccount, queryDirectAccount, queryOUID}
	gotDirect := make([]string, len(first.DirectTargets))
	for index, target := range first.DirectTargets {
		gotDirect[index] = target.ID
		if target.ID == queryManagementAccount && target.SCPApplicable {
			t.Fatal("management direct attachment marked applicable")
		}
	}
	if !reflect.DeepEqual(gotDirect, wantDirect) {
		t.Fatalf("direct targets = %v, want %v", gotDirect, wantDirect)
	}
	wantAffected := []string{queryDirectAccount, queryInheritedAccount, queryOUID}
	gotAffected := make([]string, len(first.AffectedTargets))
	for index, target := range first.AffectedTargets {
		gotAffected[index] = target.Target.ID
		if target.Target.ID == queryManagementAccount {
			t.Fatal("management account included among affected targets")
		}
	}
	if !reflect.DeepEqual(gotAffected, wantAffected) {
		t.Fatalf("affected targets = %v, want %v", gotAffected, wantAffected)
	}
	if len(first.AffectedTargets[1].Provenance) != 2 ||
		first.AffectedTargets[1].Provenance[0].AttachedTo.ID != queryRootID ||
		first.AffectedTargets[1].Provenance[1].AttachedTo.ID != queryOUID {
		t.Fatalf("inherited account provenance = %+v", first.AffectedTargets[1].Provenance)
	}
}

func TestAttachmentsQueryUnattachedPolicyUsesExplicitEmptyArrays(t *testing.T) {
	t.Parallel()

	result, err := buildAttachmentsQuery(
		context.Background(), queryFixtureClient(false), "p-unknown1",
		queryRootID, "Root", queryManagementAccount,
	)
	if err != nil {
		t.Fatalf("build empty attachments query: %v", err)
	}
	encoded, err := encodingjson.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{`"policy_name":""`, `"direct_targets":[]`, `"affected_targets":[]`} {
		if !strings.Contains(string(encoded), expected) {
			t.Fatalf("empty result %s lacks %s", encoded, expected)
		}
	}
}

func TestAttachmentsQueryFailureWritesNoPartialOutput(t *testing.T) {
	t.Parallel()

	client := queryFixtureClient(false)
	client.listChildrenFn = func(_ context.Context, input *organizations.ListChildrenInput) (*organizations.ListChildrenOutput, error) {
		if aws.ToString(input.ParentId) == queryOUID {
			return nil, errors.New("late traversal failure")
		}
		if input.ChildType == types.ChildTypeAccount {
			return &organizations.ListChildrenOutput{Children: []types.Child{{Id: aws.String(queryManagementAccount), Type: input.ChildType}}}, nil
		}
		return &organizations.ListChildrenOutput{Children: []types.Child{{Id: aws.String(queryOUID), Type: input.ChildType}}}, nil
	}
	var output bytes.Buffer
	err := displayAttachmentsQuery(
		context.Background(), &output, client, queryPolicyID,
		queryRootID, "Root", queryManagementAccount, json,
	)
	if err == nil || !strings.Contains(err.Error(), "late traversal failure") {
		t.Fatalf("unexpected error: %v", err)
	}
	if output.Len() != 0 {
		t.Fatalf("stdout contains partial result: %q", output.String())
	}
}

func TestPoliciesQueryFailureWritesNoPartialOutput(t *testing.T) {
	t.Parallel()

	client := queryFixtureClient(false)
	client.listPoliciesForTargetFn = func(_ context.Context, input *organizations.ListPoliciesForTargetInput) (*organizations.ListPoliciesForTargetOutput, error) {
		if aws.ToString(input.TargetId) == queryInheritedAccount {
			return nil, errors.New("late policy failure")
		}
		return &organizations.ListPoliciesForTargetOutput{}, nil
	}
	var output bytes.Buffer
	err := displayPoliciesQuery(
		context.Background(), &output, client, queryInheritedAccount,
		queryRootID, "Root", queryManagementAccount, json,
	)
	if err == nil || !strings.Contains(err.Error(), "late policy failure") {
		t.Fatalf("unexpected error: %v", err)
	}
	if output.Len() != 0 {
		t.Fatalf("stdout contains partial result: %q", output.String())
	}
}

func TestAttachmentsQueryDirectAccountAvoidsHierarchyTraversal(t *testing.T) {
	t.Parallel()

	policy := types.PolicySummary{Id: aws.String(queryPolicyID), Name: aws.String("Guardrail"), Type: types.PolicyTypeServiceControlPolicy}
	client := &fakeOrganizationsClient{
		listTargetsForPolicyFn: func(context.Context, *organizations.ListTargetsForPolicyInput) (*organizations.ListTargetsForPolicyOutput, error) {
			return &organizations.ListTargetsForPolicyOutput{Targets: []types.PolicyTargetSummary{{
				TargetId: aws.String(queryDirectAccount), Name: aws.String("Direct"), Type: types.TargetTypeAccount,
			}}}, nil
		},
		listPoliciesForTargetFn: func(context.Context, *organizations.ListPoliciesForTargetInput) (*organizations.ListPoliciesForTargetOutput, error) {
			return &organizations.ListPoliciesForTargetOutput{Policies: []types.PolicySummary{policy}}, nil
		},
		listChildrenFn: func(context.Context, *organizations.ListChildrenInput) (*organizations.ListChildrenOutput, error) {
			return nil, errors.New("direct account lookup must not traverse children")
		},
		describeAccountFn: func(context.Context, *organizations.DescribeAccountInput) (*organizations.DescribeAccountOutput, error) {
			return nil, errors.New("direct target summary must avoid DescribeAccount")
		},
	}
	result, err := buildAttachmentsQuery(
		context.Background(), client, queryPolicyID, queryRootID, "Root", queryManagementAccount,
	)
	if err != nil {
		t.Fatalf("build direct-account query: %v", err)
	}
	if len(result.DirectTargets) != 1 || len(result.AffectedTargets) != 1 || result.AffectedTargets[0].Target.ID != queryDirectAccount {
		t.Fatalf("unexpected direct account result: %+v", result)
	}
}

func TestListTargetsForPolicyPaginatesDeduplicatesAndSorts(t *testing.T) {
	t.Parallel()

	client := &fakeOrganizationsClient{
		listTargetsForPolicyFn: func(_ context.Context, input *organizations.ListTargetsForPolicyInput) (*organizations.ListTargetsForPolicyOutput, error) {
			account := types.PolicyTargetSummary{TargetId: aws.String(queryDirectAccount), Name: aws.String("Direct"), Type: types.TargetTypeAccount}
			ou := types.PolicyTargetSummary{TargetId: aws.String(queryOUID), Name: aws.String("Production"), Type: types.TargetTypeOrganizationalUnit}
			if input.NextToken == nil {
				return &organizations.ListTargetsForPolicyOutput{Targets: []types.PolicyTargetSummary{ou, account}, NextToken: aws.String("next")}, nil
			}
			return &organizations.ListTargetsForPolicyOutput{Targets: []types.PolicyTargetSummary{account}}, nil
		},
	}
	targets, err := listTargetsForPolicy(context.Background(), client, queryPolicyID)
	if err != nil {
		t.Fatalf("list targets: %v", err)
	}
	want := []scpAttachmentTarget{
		{Type: accountEntityType, ID: queryDirectAccount, Name: "Direct"},
		{Type: organizationalUnitEntityType, ID: queryOUID, Name: "Production"},
	}
	if !reflect.DeepEqual(targets, want) {
		t.Fatalf("targets = %+v, want %+v", targets, want)
	}
}

func TestSelectedQueryTargetRequiresOneExactTarget(t *testing.T) {
	t.Parallel()

	tests := []struct {
		account    string
		accountSet bool
		ou         string
		ouSet      bool
		want       string
	}{
		{want: "invalid --account-id"},
		{account: "all", accountSet: true, want: "one exact account"},
		{account: queryDirectAccount, accountSet: true, ou: queryOUID, ouSet: true, want: "mutually exclusive"},
	}
	for _, test := range tests {
		_, err := selectedQueryTarget(test.account, test.accountSet, test.ou, test.ouSet)
		if err == nil || !strings.Contains(err.Error(), test.want) || classifyError(err).Code != errorCodeInvalidInvocation {
			t.Fatalf("error = %v, want invalid_invocation containing %q", err, test.want)
		}
	}
}

func TestAttachmentReachRunsOUBranchesWithinBound(t *testing.T) {
	t.Parallel()
	const branchCount = 8
	organizationalUnits := make([]types.OrganizationalUnit, branchCount)
	for index := range organizationalUnits {
		id := fmt.Sprintf("ou-root-%08d", index)
		organizationalUnits[index] = types.OrganizationalUnit{Id: aws.String(id), Name: aws.String(id)}
	}
	entered := make(chan struct{}, branchCount)
	release := make(chan struct{})
	client := &fakeOrganizationsClient{
		listTargetsForPolicyFn: func(context.Context, *organizations.ListTargetsForPolicyInput) (*organizations.ListTargetsForPolicyOutput, error) {
			return &organizations.ListTargetsForPolicyOutput{Targets: []types.PolicyTargetSummary{{
				TargetId: aws.String(queryRootID), Name: aws.String("Root"), Type: types.TargetTypeRoot,
			}}}, nil
		},
		listPoliciesForTargetFn: func(context.Context, *organizations.ListPoliciesForTargetInput) (*organizations.ListPoliciesForTargetOutput, error) {
			return &organizations.ListPoliciesForTargetOutput{Policies: []types.PolicySummary{{
				Id: aws.String(queryPolicyID), Name: aws.String("Guardrail"), Type: types.PolicyTypeServiceControlPolicy,
			}}}, nil
		},
		listAccountsForParentFn: func(ctx context.Context, input *organizations.ListAccountsForParentInput) (*organizations.ListAccountsForParentOutput, error) {
			if aws.ToString(input.ParentId) == queryRootID {
				return &organizations.ListAccountsForParentOutput{}, nil
			}
			entered <- struct{}{}
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-release:
				return &organizations.ListAccountsForParentOutput{}, nil
			}
		},
		listOUsForParentFn: func(_ context.Context, input *organizations.ListOrganizationalUnitsForParentInput) (*organizations.ListOrganizationalUnitsForParentOutput, error) {
			if aws.ToString(input.ParentId) == queryRootID {
				return &organizations.ListOrganizationalUnitsForParentOutput{OrganizationalUnits: organizationalUnits}, nil
			}
			return &organizations.ListOrganizationalUnitsForParentOutput{}, nil
		},
	}
	done := make(chan error, 1)
	go func() {
		_, err := buildAttachmentsQuery(
			context.Background(), client, queryPolicyID, queryRootID, "Root", queryManagementAccount,
		)
		done <- err
	}()
	for range organizationInspectionConcurrency {
		select {
		case <-entered:
		case <-time.After(5 * time.Second):
			close(release)
			t.Fatal("attachment traversal did not fill its concurrency bound")
		}
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatalf("build attachment reach: %v", err)
	}
}
