package cmd

import (
	"bytes"
	"context"
	encodingjson "encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/aws/aws-sdk-go-v2/service/organizations/types"
)

func TestValidateOrganizationSearchInvocation(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		name       string
		nameSet    bool
		entityType searchEntityType
		typeSet    bool
		wantErr    string
	}{
		"name only":        {name: "production", nameSet: true},
		"account":          {name: "production", nameSet: true, entityType: searchAccounts, typeSet: true},
		"OU":               {name: "production", nameSet: true, entityType: searchOrganizationalUnits, typeSet: true},
		"missing name":     {wantErr: "--name"},
		"empty name":       {nameSet: true, wantErr: "--name"},
		"invalid type":     {name: "production", nameSet: true, entityType: "root", typeSet: true, wantErr: "--type"},
		"stale type value": {name: "production", nameSet: true, entityType: "root"},
	}

	for testName, test := range tests {
		t.Run(testName, func(t *testing.T) {
			t.Parallel()
			name, entityType, err := validateOrganizationSearchInvocation(
				test.name, test.nameSet, test.entityType, test.typeSet,
			)
			if test.wantErr == "" {
				if err != nil || name != test.name || entityType != test.entityType {
					t.Fatalf("validation = (%q, %q, %v), want (%q, %q, nil)", name, entityType, err, test.name, test.entityType)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("error = %v, want it to contain %q", err, test.wantErr)
			}
			if diagnostic := classifyError(err); diagnostic.Code != errorCodeInvalidInvocation {
				t.Fatalf("diagnostic = %#v, want invalid_invocation", diagnostic)
			}
		})
	}
}

func TestDiscoverOrganizationEntitiesReturnsAllExactMatchesWithPathsAndStableOrder(t *testing.T) {
	t.Parallel()

	const (
		rootID     = "r-root"
		firstOUID  = "ou-root-aaaaaaaa"
		secondOUID = "ou-root-zzzzzzzz"
	)
	accountNames := map[string]string{
		"111111111111": "Production",
		"222222222222": "production",
		"333333333333": "production",
	}
	ouNames := map[string]string{
		firstOUID:  "Engineering",
		secondOUID: "production",
	}
	policyCalls := 0
	client := &fakeOrganizationsClient{
		listRootsFn: func(context.Context, *organizations.ListRootsInput) (*organizations.ListRootsOutput, error) {
			return &organizations.ListRootsOutput{Roots: []types.Root{{
				Id: aws.String(rootID), Name: aws.String("Organization Root"),
			}}}, nil
		},
		listChildrenFn: func(_ context.Context, input *organizations.ListChildrenInput) (*organizations.ListChildrenOutput, error) {
			parentID := aws.ToString(input.ParentId)
			switch {
			case parentID == rootID && input.ChildType == types.ChildTypeAccount && input.NextToken == nil:
				return &organizations.ListChildrenOutput{
					Children:  []types.Child{{Id: aws.String("333333333333"), Type: types.ChildTypeAccount}},
					NextToken: aws.String("accounts-next"),
				}, nil
			case parentID == rootID && input.ChildType == types.ChildTypeAccount:
				return &organizations.ListChildrenOutput{Children: []types.Child{{
					Id: aws.String("111111111111"), Type: types.ChildTypeAccount,
				}}}, nil
			case parentID == rootID && input.ChildType == types.ChildTypeOrganizationalUnit:
				return &organizations.ListChildrenOutput{Children: []types.Child{
					{Id: aws.String(secondOUID), Type: types.ChildTypeOrganizationalUnit},
					{Id: aws.String(firstOUID), Type: types.ChildTypeOrganizationalUnit},
				}}, nil
			case parentID == firstOUID && input.ChildType == types.ChildTypeAccount:
				return &organizations.ListChildrenOutput{Children: []types.Child{{
					Id: aws.String("222222222222"), Type: types.ChildTypeAccount,
				}}}, nil
			default:
				return &organizations.ListChildrenOutput{}, nil
			}
		},
		describeAccountFn: func(_ context.Context, input *organizations.DescribeAccountInput) (*organizations.DescribeAccountOutput, error) {
			id := aws.ToString(input.AccountId)
			return &organizations.DescribeAccountOutput{Account: &types.Account{
				Id: input.AccountId, Name: aws.String(accountNames[id]),
			}}, nil
		},
		describeOrganizationalUnit: func(_ context.Context, input *organizations.DescribeOrganizationalUnitInput) (*organizations.DescribeOrganizationalUnitOutput, error) {
			id := aws.ToString(input.OrganizationalUnitId)
			return &organizations.DescribeOrganizationalUnitOutput{OrganizationalUnit: &types.OrganizationalUnit{
				Id: input.OrganizationalUnitId, Name: aws.String(ouNames[id]),
			}}, nil
		},
		listPoliciesForTargetFn: func(context.Context, *organizations.ListPoliciesForTargetInput) (*organizations.ListPoliciesForTargetOutput, error) {
			policyCalls++
			return &organizations.ListPoliciesForTargetOutput{}, nil
		},
	}

	result, err := discoverOrganizationEntities(context.Background(), client, "production", "")
	if err != nil {
		t.Fatalf("discover entities: %v", err)
	}
	if policyCalls != 0 {
		t.Fatalf("search made %d policy attachment calls, want none", policyCalls)
	}
	if result.SchemaVersion != "1" || result.Query != (organizationSearchQuery{Name: "production"}) {
		t.Fatalf("unexpected result metadata: %+v", result)
	}
	gotIDs := make([]string, len(result.Matches))
	for index := range result.Matches {
		gotIDs[index] = result.Matches[index].ID
	}
	wantIDs := []string{"222222222222", "333333333333", secondOUID}
	if !reflect.DeepEqual(gotIDs, wantIDs) {
		t.Fatalf("match IDs = %v, want %v", gotIDs, wantIDs)
	}
	if got := result.Matches[0].Path; !reflect.DeepEqual(got, []organizationSearchPathEntity{
		{Type: rootEntityType, ID: rootID, Name: "Organization Root"},
		{Type: organizationalUnitEntityType, ID: firstOUID, Name: "Engineering"},
		{Type: accountEntityType, ID: "222222222222", Name: "production"},
	}) {
		t.Fatalf("nested account path = %+v", got)
	}
	if result.Matches[2].Type != organizationalUnitEntityType || len(result.Matches[2].Path) != 2 {
		t.Fatalf("unexpected OU match: %+v", result.Matches[2])
	}
}

func TestDiscoverOrganizationEntitiesTypeFilteringAndNoMatches(t *testing.T) {
	t.Parallel()

	const ouID = "ou-root-aaaaaaaa"
	accountCalls := 0
	client := &fakeOrganizationsClient{
		listRootsFn: func(context.Context, *organizations.ListRootsInput) (*organizations.ListRootsOutput, error) {
			return &organizations.ListRootsOutput{Roots: []types.Root{{Id: aws.String("r-root")}}}, nil
		},
		listChildrenFn: func(_ context.Context, input *organizations.ListChildrenInput) (*organizations.ListChildrenOutput, error) {
			if aws.ToString(input.ParentId) == "r-root" && input.ChildType == types.ChildTypeAccount {
				return &organizations.ListChildrenOutput{Children: []types.Child{{Id: aws.String("111111111111"), Type: types.ChildTypeAccount}}}, nil
			}
			if aws.ToString(input.ParentId) == "r-root" && input.ChildType == types.ChildTypeOrganizationalUnit {
				return &organizations.ListChildrenOutput{Children: []types.Child{{Id: aws.String(ouID), Type: types.ChildTypeOrganizationalUnit}}}, nil
			}
			return &organizations.ListChildrenOutput{}, nil
		},
		describeAccountFn: func(context.Context, *organizations.DescribeAccountInput) (*organizations.DescribeAccountOutput, error) {
			accountCalls++
			return &organizations.DescribeAccountOutput{Account: &types.Account{Id: aws.String("111111111111"), Name: aws.String("production")}}, nil
		},
		describeOrganizationalUnit: func(context.Context, *organizations.DescribeOrganizationalUnitInput) (*organizations.DescribeOrganizationalUnitOutput, error) {
			return &organizations.DescribeOrganizationalUnitOutput{OrganizationalUnit: &types.OrganizationalUnit{Id: aws.String(ouID), Name: aws.String("production")}}, nil
		},
	}

	ouResult, err := discoverOrganizationEntities(context.Background(), client, "production", searchOrganizationalUnits)
	if err != nil {
		t.Fatalf("search OUs: %v", err)
	}
	if accountCalls != 0 {
		t.Fatalf("OU-only search described %d accounts, want none", accountCalls)
	}
	if len(ouResult.Matches) != 1 || ouResult.Matches[0].Type != organizationalUnitEntityType {
		t.Fatalf("unexpected OU-only matches: %+v", ouResult.Matches)
	}

	noMatches, err := discoverOrganizationEntities(context.Background(), client, "missing", searchAccounts)
	if err != nil {
		t.Fatalf("search accounts: %v", err)
	}
	if noMatches.Matches == nil || len(noMatches.Matches) != 0 {
		t.Fatalf("no-match result must contain an explicit empty array: %#v", noMatches.Matches)
	}
	document, err := renderOrganizationSearch(noMatches, json)
	if err != nil {
		t.Fatalf("render no-match result: %v", err)
	}
	if !strings.Contains(string(document), `"matches": []`) {
		t.Fatalf("no-match JSON lacks explicit empty matches: %s", document)
	}
}

func TestOrganizationSearchJSONContractAndTextOutput(t *testing.T) {
	t.Parallel()

	result := organizationSearchResult{
		SchemaVersion: "1",
		Query:         organizationSearchQuery{Name: "production", Type: accountEntityType},
		Matches: []organizationSearchMatch{{
			Type: accountEntityType, ID: "123456789012", Name: "production",
			Path: []organizationSearchPathEntity{
				{Type: rootEntityType, ID: "r-root", Name: "Root"},
				{Type: accountEntityType, ID: "123456789012", Name: "production"},
			},
		}},
	}
	jsonDocument, err := renderOrganizationSearch(result, json)
	if err != nil {
		t.Fatalf("render JSON: %v", err)
	}
	wantJSON := `{
  "schema_version": "1",
  "query": {
    "name": "production",
    "type": "account"
  },
  "matches": [
    {
      "type": "account",
      "id": "123456789012",
      "name": "production",
      "path": [
        {
          "type": "root",
          "id": "r-root",
          "name": "Root"
        },
        {
          "type": "account",
          "id": "123456789012",
          "name": "production"
        }
      ]
    }
  ]
}
`
	if string(jsonDocument) != wantJSON {
		t.Fatalf("JSON contract changed:\n%s\nwant:\n%s", jsonDocument, wantJSON)
	}
	var decoded organizationSearchResult
	if err := encodingjson.Unmarshal(jsonDocument, &decoded); err != nil {
		t.Fatalf("decode JSON contract: %v", err)
	}

	textDocument, err := renderOrganizationSearch(result, text)
	if err != nil {
		t.Fatalf("render text: %v", err)
	}
	wantText := "Exact matches for \"production\": 1\n" +
		"Account production [123456789012]\n" +
		"  Path: Root [r-root] / production [123456789012]\n"
	if string(textDocument) != wantText {
		t.Fatalf("text output = %q, want %q", textDocument, wantText)
	}
}

func TestDisplayOrganizationSearchDoesNotWritePartialOutputOnPaginationError(t *testing.T) {
	t.Parallel()

	client := &fakeOrganizationsClient{
		listRootsFn: func(context.Context, *organizations.ListRootsInput) (*organizations.ListRootsOutput, error) {
			return &organizations.ListRootsOutput{Roots: []types.Root{{Id: aws.String("r-root")}}}, nil
		},
		listChildrenFn: func(_ context.Context, input *organizations.ListChildrenInput) (*organizations.ListChildrenOutput, error) {
			if input.ChildType == types.ChildTypeAccount {
				return &organizations.ListChildrenOutput{}, nil
			}
			if input.NextToken == nil {
				return &organizations.ListChildrenOutput{NextToken: aws.String("next")}, nil
			}
			return nil, errors.New("second page unavailable")
		},
	}

	var output bytes.Buffer
	err := displayOrganizationSearch(context.Background(), &output, client, "production", "", json)
	if err == nil || !strings.Contains(err.Error(), "second page unavailable") {
		t.Fatalf("unexpected search error: %v", err)
	}
	if output.Len() != 0 {
		t.Fatalf("failed search wrote partial output: %q", output.String())
	}
}

type organizationSearchShortWriter struct{}

func (organizationSearchShortWriter) Write(document []byte) (int, error) {
	return len(document) - 1, nil
}

func TestDisplayOrganizationSearchRejectsShortWrite(t *testing.T) {
	t.Parallel()

	client := &fakeOrganizationsClient{
		listRootsFn: func(context.Context, *organizations.ListRootsInput) (*organizations.ListRootsOutput, error) {
			return &organizations.ListRootsOutput{Roots: []types.Root{{Id: aws.String("r-root")}}}, nil
		},
	}
	err := displayOrganizationSearch(
		context.Background(), organizationSearchShortWriter{}, client, "missing", searchOrganizationalUnits, json,
	)
	if !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("short write error = %v, want io.ErrShortWrite", err)
	}
}

func TestAWSSearchHelpDocumentsMachineSafeContract(t *testing.T) {
	output := renderHelp(t, awsSearchCmd)
	for _, expected := range []string{
		"Find every AWS account or organizational unit",
		"case-sensitive",
		"never selects one automatically",
		"--name",
		"--type account|organizational_unit",
		"--output-format text|json",
		"(default json)",
		"--timeout",
		"--max-retries",
		"policy-scout aws search --name production --type account",
		"does not list policy attachments or retrieve policy documents",
	} {
		if !strings.Contains(output, expected) {
			t.Errorf("search help missing %q:\n%s", expected, output)
		}
	}
}

func TestOrganizationSearchRunsOUSubtreesWithinBound(t *testing.T) {
	t.Parallel()
	const rootID = "r-root"
	organizationalUnits := make([]types.OrganizationalUnit, 8)
	for index := range organizationalUnits {
		id := fmt.Sprintf("ou-root-%08d", index)
		organizationalUnits[index] = types.OrganizationalUnit{Id: aws.String(id), Name: aws.String(id)}
	}
	entered := make(chan struct{}, len(organizationalUnits))
	release := make(chan struct{})
	client := &fakeOrganizationsClient{
		listRootsFn: func(context.Context, *organizations.ListRootsInput) (*organizations.ListRootsOutput, error) {
			return &organizations.ListRootsOutput{Roots: []types.Root{{Id: aws.String(rootID)}}}, nil
		},
		listAccountsForParentFn: func(ctx context.Context, input *organizations.ListAccountsForParentInput) (*organizations.ListAccountsForParentOutput, error) {
			if aws.ToString(input.ParentId) == rootID {
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
			if aws.ToString(input.ParentId) == rootID {
				return &organizations.ListOrganizationalUnitsForParentOutput{OrganizationalUnits: organizationalUnits}, nil
			}
			return &organizations.ListOrganizationalUnitsForParentOutput{}, nil
		},
	}
	done := make(chan error, 1)
	go func() {
		_, err := discoverOrganizationEntities(context.Background(), client, "missing", searchAccounts)
		done <- err
	}()
	for range organizationInspectionConcurrency {
		select {
		case <-entered:
		case <-time.After(5 * time.Second):
			close(release)
			t.Fatal("search did not fill its concurrency bound")
		}
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatalf("search organization: %v", err)
	}
}
