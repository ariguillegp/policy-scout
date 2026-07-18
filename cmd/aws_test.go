package cmd

import (
	"bytes"
	"context"
	encodingjson "encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/aws/aws-sdk-go-v2/service/organizations/types"
)

type fakeOrganizationsClient struct {
	listChildrenFn             func(context.Context, *organizations.ListChildrenInput) (*organizations.ListChildrenOutput, error)
	listParentsFn              func(context.Context, *organizations.ListParentsInput) (*organizations.ListParentsOutput, error)
	listPoliciesForTargetFn    func(context.Context, *organizations.ListPoliciesForTargetInput) (*organizations.ListPoliciesForTargetOutput, error)
	listRootsFn                func(context.Context, *organizations.ListRootsInput) (*organizations.ListRootsOutput, error)
	describeAccountFn          func(context.Context, *organizations.DescribeAccountInput) (*organizations.DescribeAccountOutput, error)
	describeOrganizationalUnit func(context.Context, *organizations.DescribeOrganizationalUnitInput) (*organizations.DescribeOrganizationalUnitOutput, error)
	describeOrganizationFn     func(context.Context, *organizations.DescribeOrganizationInput) (*organizations.DescribeOrganizationOutput, error)
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

func TestListChildrenPaginates(t *testing.T) {
	t.Parallel()

	client := &fakeOrganizationsClient{
		listChildrenFn: func(_ context.Context, input *organizations.ListChildrenInput) (*organizations.ListChildrenOutput, error) {
			if input.NextToken == nil {
				return &organizations.ListChildrenOutput{
					Children:  []types.Child{{Id: aws.String("111111111111"), Type: types.ChildTypeAccount}},
					NextToken: aws.String("next"),
				}, nil
			}
			return &organizations.ListChildrenOutput{Children: []types.Child{{Id: aws.String("222222222222"), Type: types.ChildTypeAccount}}}, nil
		},
	}

	children, err := listChildren(context.Background(), client, "r-root", types.ChildTypeAccount)
	if err != nil {
		t.Fatalf("list children: %v", err)
	}
	if len(children) != 2 {
		t.Fatalf("got %d children, want 2", len(children))
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
			return &organizations.ListRootsOutput{Roots: []types.Root{{Id: aws.String("r-root")}}}, nil
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
	rootID, err := getRootID(context.Background(), client)
	if err != nil || rootID != "r-root" {
		t.Fatalf("root: got %q, error %v", rootID, err)
	}
}

func TestPrintPathToAccountWalksUpwardAndListsInheritedPolicies(t *testing.T) {
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
				return &organizations.ListPoliciesForTargetOutput{Policies: []types.PolicySummary{{Id: aws.String("p-full0001"), Name: aws.String("FullAWSAccess"), Type: types.PolicyTypeServiceControlPolicy}}}, nil
			case rootID:
				return &organizations.ListPoliciesForTargetOutput{Policies: []types.PolicySummary{{Id: aws.String("p-full0001"), Name: aws.String("FullAWSAccess"), Type: types.PolicyTypeServiceControlPolicy}}}, nil
			default:
				return nil, errors.New("unexpected policy lookup")
			}
		},
	}

	var output bytes.Buffer
	err := printPathToAccount(context.Background(), &output, client, rootID, accountID, "999999999999")
	if err != nil {
		t.Fatalf("print path: %v", err)
	}
	if listChildrenCalls != 0 {
		t.Fatalf("list children called %d times", listChildrenCalls)
	}
	want := "|-- Root: [r-root]\n" +
		"    |-- OU: Production [ou-root-12345678]\n" +
		"        |-- Account: Application [123456789012] (SCPs: DenyS3, FullAWSAccess)\n"
	if output.String() != want {
		t.Fatalf("unexpected output:\n%s\nwant:\n%s", output.String(), want)
	}
}

func TestPrintPathToAccountReturnsLookupError(t *testing.T) {
	t.Parallel()

	client := &fakeOrganizationsClient{
		describeAccountFn: func(context.Context, *organizations.DescribeAccountInput) (*organizations.DescribeAccountOutput, error) {
			return nil, errors.New("account not found")
		},
	}
	err := printPathToAccount(context.Background(), &bytes.Buffer{}, client, "r-root", "123456789012", "999999999999")
	if err == nil || !strings.Contains(err.Error(), "describe account 123456789012") {
		t.Fatalf("unexpected error: %v", err)
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

func TestListSCPsForPathDeduplicatesOnlyByID(t *testing.T) {
	t.Parallel()

	client := &fakeOrganizationsClient{
		listPoliciesForTargetFn: func(_ context.Context, input *organizations.ListPoliciesForTargetInput) (*organizations.ListPoliciesForTargetOutput, error) {
			if aws.ToString(input.TargetId) == "r-root" {
				return &organizations.ListPoliciesForTargetOutput{Policies: []types.PolicySummary{
					{Id: aws.String("p-shared01"), Name: aws.String("Shared"), Type: types.PolicyTypeServiceControlPolicy},
					{Id: aws.String("p-first001"), Name: aws.String("FirstPolicy"), Type: types.PolicyTypeServiceControlPolicy},
				}}, nil
			}
			return &organizations.ListPoliciesForTargetOutput{Policies: []types.PolicySummary{
				{Id: aws.String("p-shared01"), Name: aws.String("Shared"), Type: types.PolicyTypeServiceControlPolicy},
				{Id: aws.String("p-second01"), Name: aws.String("SecondPolicy"), Type: types.PolicyTypeServiceControlPolicy},
			}}, nil
		},
	}

	names, err := listSCPsForPath(
		context.Background(),
		client,
		[]string{"r-root", "123456789012"},
		map[string][]types.PolicySummary{},
	)
	if err != nil {
		t.Fatalf("list policies: %v", err)
	}
	want := []string{"FirstPolicy", "SecondPolicy", "Shared"}
	if strings.Join(names, ",") != strings.Join(want, ",") {
		t.Fatalf("got %v, want %v", names, want)
	}
}

func TestListSCPsForPathRejectsConflictingSummaries(t *testing.T) {
	t.Parallel()

	tests := map[string]map[string][]types.PolicySummary{
		"same ID with different names": {
			"r-root":       {{Id: aws.String("p-00000001"), Name: aws.String("First"), Type: types.PolicyTypeServiceControlPolicy}},
			"123456789012": {{Id: aws.String("p-00000001"), Name: aws.String("Second"), Type: types.PolicyTypeServiceControlPolicy}},
		},
		"same name with different IDs": {
			"r-root":       {{Id: aws.String("p-00000001"), Name: aws.String("Policy"), Type: types.PolicyTypeServiceControlPolicy}},
			"123456789012": {{Id: aws.String("p-00000002"), Name: aws.String("Policy"), Type: types.PolicyTypeServiceControlPolicy}},
		},
	}
	for name, cache := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := listSCPsForPath(
				context.Background(),
				&fakeOrganizationsClient{},
				[]string{"r-root", "123456789012"},
				cache,
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

func TestManagementAccountDoesNotListSCPs(t *testing.T) {
	t.Parallel()

	policyCalls := 0
	client := &fakeOrganizationsClient{
		listPoliciesForTargetFn: func(context.Context, *organizations.ListPoliciesForTargetInput) (*organizations.ListPoliciesForTargetOutput, error) {
			policyCalls++
			return nil, errors.New("SCPs must not be queried for the management account")
		},
	}
	var output bytes.Buffer
	err := printAccount(
		context.Background(),
		&output,
		client,
		"",
		"123456789012",
		"Management",
		"123456789012",
		[]string{"r-root", "123456789012"},
		map[string][]types.PolicySummary{},
	)
	if err != nil {
		t.Fatalf("print account: %v", err)
	}
	if policyCalls != 0 {
		t.Fatalf("policy API called %d times", policyCalls)
	}
	want := "|-- Account: Management (Management Account) [123456789012] (SCPs: not enforced)\n"
	if output.String() != want {
		t.Fatalf("unexpected output: %s, want: %s", output.String(), want)
	}
}

func TestPrintEntireOrgVisitsEachParentOnce(t *testing.T) {
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
			policyCalls[targetID]++
			return &organizations.ListPoliciesForTargetOutput{}, nil
		},
	}

	var output bytes.Buffer
	err := displayOrganizationTreeText(context.Background(), &output, client, "all", rootID, managementAccount)
	if err != nil {
		t.Fatalf("print organization: %v", err)
	}
	for key, calls := range listCalls {
		if calls != 1 {
			t.Fatalf("children lookup %s called %d times", key, calls)
		}
	}
	if len(listCalls) != 4 {
		t.Fatalf("got %d children lookups, want 4", len(listCalls))
	}
	if policyCalls[managementAccount] != 0 {
		t.Fatalf("management account policies queried %d times", policyCalls[managementAccount])
	}
	if policyCalls[rootID] != 1 || policyCalls[ouID] != 1 {
		t.Fatalf("shared ancestor policy calls: root=%d OU=%d, want 1 each", policyCalls[rootID], policyCalls[ouID])
	}
	want := "|-- Root: [r-root]\n" +
		"    |-- Account: Management (Management Account) [111111111111] (SCPs: not enforced)\n" +
		"    |-- OU: Production [ou-root-12345678]\n" +
		"        |-- Account: Member [222222222222] (SCPs: )\n" +
		"        |-- Account: Member [333333333333] (SCPs: )\n"
	if output.String() != want {
		t.Fatalf("unexpected output:\n%s\nwant:\n%s", output.String(), want)
	}

	output.Reset()
	err = displayOrganizationTreeJSON(context.Background(), &output, client, "all", rootID, managementAccount)
	if err != nil {
		t.Fatalf("display organization as JSON: %v", err)
	}
	var result organizationJSONNode
	if err := encodingjson.Unmarshal(output.Bytes(), &result); err != nil {
		t.Fatalf("decode organization JSON: %v", err)
	}
	if len(result.Children) != 2 || !result.Children[0].ManagementAccount {
		t.Fatalf("unexpected root children: %+v", result.Children)
	}
	organizationalUnit := result.Children[1]
	if organizationalUnit.ID != ouID || len(organizationalUnit.Children) != 2 {
		t.Fatalf("unexpected organizational unit: %+v", organizationalUnit)
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
			if aws.ToString(input.TargetId) == accountID {
				return &organizations.ListPoliciesForTargetOutput{Policies: []types.PolicySummary{{
					Id: aws.String("p-deny0001"), Name: aws.String("DenyS3"), Type: types.PolicyTypeServiceControlPolicy,
				}}}, nil
			}
			return &organizations.ListPoliciesForTargetOutput{}, nil
		},
	}

	var output bytes.Buffer
	if err := displayOrganizationTreeJSON(
		context.Background(), &output, client, accountID, rootID, "999999999999",
	); err != nil {
		t.Fatalf("display JSON: %v", err)
	}

	var result organizationJSONNode
	if err := encodingjson.Unmarshal(output.Bytes(), &result); err != nil {
		t.Fatalf("decode JSON: %v", err)
	}
	if result.Type != "root" || result.ID != rootID || len(result.Children) != 1 {
		t.Fatalf("unexpected root: %+v", result)
	}
	ou := result.Children[0]
	if ou.Type != "organizational_unit" || ou.ID != ouID || ou.Name != "Production" || len(ou.Children) != 1 {
		t.Fatalf("unexpected organizational unit: %+v", ou)
	}
	account := ou.Children[0]
	if account.Type != "account" || account.ID != accountID || account.Name != "Application" ||
		strings.Join(account.SCPs, ",") != "DenyS3" {
		t.Fatalf("unexpected account: %+v", account)
	}
}
