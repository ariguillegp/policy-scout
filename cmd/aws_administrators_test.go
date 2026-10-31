package cmd

import (
	"bytes"
	"context"
	encodingjson "encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"github.com/aws/smithy-go"
)

const (
	adminManagementAccount = "111111111111"
	adminSecurityAccount   = "222222222222"
	adminLoggingAccount    = "333333333333"
	adminDelegationPolicy  = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::222222222222:root"},"Action":["organizations:UpdatePolicy"],"Resource":"*"}]}`
)

type fakeAdministratorsClient struct {
	describeOrganizationFn   func(context.Context) (*organizations.DescribeOrganizationOutput, error)
	describeResourcePolicyFn func(context.Context) (*organizations.DescribeResourcePolicyOutput, error)
	listAdministratorsFn     func(context.Context, *organizations.ListDelegatedAdministratorsInput) (*organizations.ListDelegatedAdministratorsOutput, error)
	listServicesFn           func(context.Context, *organizations.ListDelegatedServicesForAccountInput) (*organizations.ListDelegatedServicesForAccountOutput, error)
	listServiceAccessFn      func(context.Context, *organizations.ListAWSServiceAccessForOrganizationInput) (*organizations.ListAWSServiceAccessForOrganizationOutput, error)
}

func (fake *fakeAdministratorsClient) DescribeOrganization(
	ctx context.Context, _ *organizations.DescribeOrganizationInput, _ ...func(*organizations.Options),
) (*organizations.DescribeOrganizationOutput, error) {
	return fake.describeOrganizationFn(ctx)
}

func (fake *fakeAdministratorsClient) DescribeResourcePolicy(
	ctx context.Context, _ *organizations.DescribeResourcePolicyInput, _ ...func(*organizations.Options),
) (*organizations.DescribeResourcePolicyOutput, error) {
	return fake.describeResourcePolicyFn(ctx)
}

func (fake *fakeAdministratorsClient) ListDelegatedAdministrators(
	ctx context.Context, input *organizations.ListDelegatedAdministratorsInput, _ ...func(*organizations.Options),
) (*organizations.ListDelegatedAdministratorsOutput, error) {
	return fake.listAdministratorsFn(ctx, input)
}

func (fake *fakeAdministratorsClient) ListDelegatedServicesForAccount(
	ctx context.Context, input *organizations.ListDelegatedServicesForAccountInput, _ ...func(*organizations.Options),
) (*organizations.ListDelegatedServicesForAccountOutput, error) {
	return fake.listServicesFn(ctx, input)
}

func (fake *fakeAdministratorsClient) ListAWSServiceAccessForOrganization(
	ctx context.Context, input *organizations.ListAWSServiceAccessForOrganizationInput, _ ...func(*organizations.Options),
) (*organizations.ListAWSServiceAccessForOrganizationOutput, error) {
	return fake.listServiceAccessFn(ctx, input)
}

// administratorsFixtureClient returns two pages of every list, including a
// duplicate entry, so callers observe pagination, deduplication, and sorting.
// When scrambled is true each page is returned in the opposite order.
func administratorsFixtureClient(scrambled bool) *fakeAdministratorsClient {
	enabled := time.Date(2025, 3, 4, 5, 6, 7, 0, time.FixedZone("EST", -5*60*60))
	pages := func(token *string, first, second []int) []int {
		if scrambled {
			first, second = second, first
		}
		if token == nil {
			return first
		}
		return second
	}
	nextToken := func(token *string) *string {
		if token == nil {
			return aws.String("page-2")
		}
		return nil
	}
	admins := []types.DelegatedAdministrator{
		{Id: aws.String(adminSecurityAccount), Name: aws.String("Security"), Arn: aws.String("arn:security"), State: types.AccountStateActive, DelegationEnabledDate: &enabled},
		{Id: aws.String(adminLoggingAccount), Name: aws.String("Logging"), State: types.AccountStateSuspended},
	}
	servicesByAccount := map[string][]types.DelegatedService{
		adminSecurityAccount: {
			{ServicePrincipal: aws.String("securityhub.amazonaws.com"), DelegationEnabledDate: &enabled},
			{ServicePrincipal: aws.String("guardduty.amazonaws.com")},
		},
		adminLoggingAccount: {{ServicePrincipal: aws.String("cloudtrail.amazonaws.com")}},
	}
	trusted := []types.EnabledServicePrincipal{
		{ServicePrincipal: aws.String("sso.amazonaws.com"), DateEnabled: &enabled},
		{ServicePrincipal: aws.String("guardduty.amazonaws.com")},
	}
	return &fakeAdministratorsClient{
		describeOrganizationFn: func(context.Context) (*organizations.DescribeOrganizationOutput, error) {
			return &organizations.DescribeOrganizationOutput{Organization: &types.Organization{
				Id: aws.String("o-example"), Arn: aws.String("arn:org"), FeatureSet: types.OrganizationFeatureSetAll,
				MasterAccountId: aws.String(adminManagementAccount), MasterAccountArn: aws.String("arn:management"),
				MasterAccountEmail: aws.String("root@example.com"),
			}}, nil
		},
		describeResourcePolicyFn: func(context.Context) (*organizations.DescribeResourcePolicyOutput, error) {
			return &organizations.DescribeResourcePolicyOutput{ResourcePolicy: &types.ResourcePolicy{
				Content:               aws.String(adminDelegationPolicy),
				ResourcePolicySummary: &types.ResourcePolicySummary{Id: aws.String("rp-example1"), Arn: aws.String("arn:rp")},
			}}, nil
		},
		listAdministratorsFn: func(_ context.Context, input *organizations.ListDelegatedAdministratorsInput) (*organizations.ListDelegatedAdministratorsOutput, error) {
			var page []types.DelegatedAdministrator
			for _, index := range pages(input.NextToken, []int{0}, []int{1, 0}) {
				page = append(page, admins[index])
			}
			return &organizations.ListDelegatedAdministratorsOutput{DelegatedAdministrators: page, NextToken: nextToken(input.NextToken)}, nil
		},
		listServicesFn: func(_ context.Context, input *organizations.ListDelegatedServicesForAccountInput) (*organizations.ListDelegatedServicesForAccountOutput, error) {
			services := servicesByAccount[aws.ToString(input.AccountId)]
			if input.NextToken != nil {
				return &organizations.ListDelegatedServicesForAccountOutput{DelegatedServices: services[len(services)-1:]}, nil
			}
			ordered := append([]types.DelegatedService(nil), services...)
			if scrambled {
				for left, right := 0, len(ordered)-1; left < right; left, right = left+1, right-1 {
					ordered[left], ordered[right] = ordered[right], ordered[left]
				}
			}
			return &organizations.ListDelegatedServicesForAccountOutput{DelegatedServices: ordered, NextToken: aws.String("page-2")}, nil
		},
		listServiceAccessFn: func(_ context.Context, input *organizations.ListAWSServiceAccessForOrganizationInput) (*organizations.ListAWSServiceAccessForOrganizationOutput, error) {
			var page []types.EnabledServicePrincipal
			for _, index := range pages(input.NextToken, []int{0}, []int{1, 0}) {
				page = append(page, trusted[index])
			}
			return &organizations.ListAWSServiceAccessForOrganizationOutput{EnabledServicePrincipals: page, NextToken: nextToken(input.NextToken)}, nil
		},
	}
}

func TestAdministratorsReportsEveryControlSourceDeterministically(t *testing.T) {
	t.Parallel()

	first, err := buildAdministrators(context.Background(), administratorsFixtureClient(false))
	if err != nil {
		t.Fatalf("build administrators: %v", err)
	}
	second, err := buildAdministrators(context.Background(), administratorsFixtureClient(true))
	if err != nil {
		t.Fatalf("build scrambled administrators: %v", err)
	}
	firstJSON, _ := encodingjson.Marshal(first)
	secondJSON, _ := encodingjson.Marshal(second)
	if !bytes.Equal(firstJSON, secondJSON) {
		t.Fatalf("result order is unstable:\n%s\n%s", firstJSON, secondJSON)
	}

	want := administratorsResult{
		SchemaVersion:     "1",
		Organization:      administratorsOrganization{ID: "o-example", ARN: "arn:org", FeatureSet: "ALL"},
		ManagementAccount: administratorsManagementAccount{ID: adminManagementAccount, ARN: "arn:management"},
		ResourcePolicy: &administratorsResourcePolicy{
			ID: "rp-example1", ARN: "arn:rp", Content: encodingjson.RawMessage(adminDelegationPolicy),
		},
		DelegatedAdministrators: []delegatedAdministrator{
			{
				ID: adminSecurityAccount, Name: "Security", ARN: "arn:security", State: "ACTIVE",
				DelegationEnabledDate: "2025-03-04T10:06:07Z",
				Services: []delegatedService{
					{ServicePrincipal: "guardduty.amazonaws.com"},
					{ServicePrincipal: "securityhub.amazonaws.com", DelegationEnabledDate: "2025-03-04T10:06:07Z"},
				},
			},
			{
				ID: adminLoggingAccount, Name: "Logging", State: "SUSPENDED",
				Services: []delegatedService{{ServicePrincipal: "cloudtrail.amazonaws.com"}},
			},
		},
		TrustedServices: []trustedService{
			{ServicePrincipal: "guardduty.amazonaws.com"},
			{ServicePrincipal: "sso.amazonaws.com", DateEnabled: "2025-03-04T10:06:07Z"},
		},
	}
	if !reflect.DeepEqual(first, want) {
		t.Fatalf("administrators =\n%+v\nwant\n%+v", first, want)
	}
	if strings.Contains(string(firstJSON), "root@example.com") {
		t.Fatalf("result exposes the management account email: %s", firstJSON)
	}
}

func TestAdministratorsWithoutDelegationUsesExplicitEmptyValues(t *testing.T) {
	t.Parallel()

	client := administratorsFixtureClient(false)
	client.describeResourcePolicyFn = func(context.Context) (*organizations.DescribeResourcePolicyOutput, error) {
		return nil, &types.ResourcePolicyNotFoundException{Message: aws.String("no policy")}
	}
	client.listAdministratorsFn = func(context.Context, *organizations.ListDelegatedAdministratorsInput) (*organizations.ListDelegatedAdministratorsOutput, error) {
		return &organizations.ListDelegatedAdministratorsOutput{}, nil
	}
	client.listServicesFn = func(context.Context, *organizations.ListDelegatedServicesForAccountInput) (*organizations.ListDelegatedServicesForAccountOutput, error) {
		return nil, errors.New("no delegated administrator should be queried")
	}
	client.listServiceAccessFn = func(context.Context, *organizations.ListAWSServiceAccessForOrganizationInput) (*organizations.ListAWSServiceAccessForOrganizationOutput, error) {
		return &organizations.ListAWSServiceAccessForOrganizationOutput{}, nil
	}

	var output bytes.Buffer
	if err := displayAdministrators(context.Background(), &output, client, json); err != nil {
		t.Fatalf("display administrators: %v", err)
	}
	compact := strings.Join(strings.Fields(output.String()), "")
	for _, expected := range []string{`"resource_policy":null`, `"delegated_administrators":[]`, `"trusted_services":[]`} {
		if !strings.Contains(compact, expected) {
			t.Fatalf("empty result lacks %s:\n%s", expected, output.String())
		}
	}

	var textOutput bytes.Buffer
	result, err := buildAdministrators(context.Background(), client)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeAdministrators(&textOutput, result, text); err != nil {
		t.Fatalf("write text: %v", err)
	}
	for _, expected := range []string{"Delegation policy: none\n", "Delegated administrators: none\n", "Trusted access: none\n"} {
		if !strings.Contains(textOutput.String(), expected) {
			t.Fatalf("text output lacks %q:\n%s", expected, textOutput.String())
		}
	}
}

func TestAdministratorsSkipsAccountsDeregisteredDuringInspection(t *testing.T) {
	t.Parallel()

	tests := map[string]error{
		"no longer delegated":   &types.AccountNotRegisteredException{Message: aws.String("not registered")},
		"left the organization": &types.AccountNotFoundException{Message: aws.String("not found")},
	}
	for name, deregistrationErr := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			client := administratorsFixtureClient(false)
			listServices := client.listServicesFn
			client.listServicesFn = func(ctx context.Context, input *organizations.ListDelegatedServicesForAccountInput) (*organizations.ListDelegatedServicesForAccountOutput, error) {
				// Fail on the second page so a partially listed account is still dropped.
				if aws.ToString(input.AccountId) == adminSecurityAccount && input.NextToken != nil {
					return nil, &smithy.OperationError{
						ServiceID: "Organizations", OperationName: "ListDelegatedServicesForAccount", Err: deregistrationErr,
					}
				}
				return listServices(ctx, input)
			}
			result, err := buildAdministrators(context.Background(), client)
			if err != nil {
				t.Fatalf("build administrators: %v", err)
			}
			want := []delegatedAdministrator{{
				ID: adminLoggingAccount, Name: "Logging", State: "SUSPENDED",
				Services: []delegatedService{{ServicePrincipal: "cloudtrail.amazonaws.com"}},
			}}
			if !reflect.DeepEqual(result.DelegatedAdministrators, want) {
				t.Fatalf("delegated administrators = %+v, want only the still-registered account %+v", result.DelegatedAdministrators, want)
			}
		})
	}
}

func TestAdministratorsFailuresWriteNoPartialOutput(t *testing.T) {
	t.Parallel()

	tests := map[string]func(*fakeAdministratorsClient){
		"delegated services failure": func(client *fakeAdministratorsClient) {
			client.listServicesFn = func(_ context.Context, input *organizations.ListDelegatedServicesForAccountInput) (*organizations.ListDelegatedServicesForAccountOutput, error) {
				if aws.ToString(input.AccountId) == adminLoggingAccount {
					return nil, errors.New("late services failure")
				}
				return &organizations.ListDelegatedServicesForAccountOutput{}, nil
			}
		},
		"resource policy access denied": func(client *fakeAdministratorsClient) {
			client.describeResourcePolicyFn = func(context.Context) (*organizations.DescribeResourcePolicyOutput, error) {
				return nil, &types.AccessDeniedException{Message: aws.String("denied")}
			}
		},
		"malformed resource policy": func(client *fakeAdministratorsClient) {
			client.describeResourcePolicyFn = func(context.Context) (*organizations.DescribeResourcePolicyOutput, error) {
				return &organizations.DescribeResourcePolicyOutput{ResourcePolicy: &types.ResourcePolicy{
					Content:               aws.String(`["not an object"]`),
					ResourcePolicySummary: &types.ResourcePolicySummary{Id: aws.String("rp-example1")},
				}}, nil
			}
		},
		"invalid delegated administrator ID": func(client *fakeAdministratorsClient) {
			client.listAdministratorsFn = func(context.Context, *organizations.ListDelegatedAdministratorsInput) (*organizations.ListDelegatedAdministratorsOutput, error) {
				return &organizations.ListDelegatedAdministratorsOutput{DelegatedAdministrators: []types.DelegatedAdministrator{{Id: aws.String("12345")}}}, nil
			}
		},
		"repeated trusted access token": func(client *fakeAdministratorsClient) {
			client.listServiceAccessFn = func(context.Context, *organizations.ListAWSServiceAccessForOrganizationInput) (*organizations.ListAWSServiceAccessForOrganizationOutput, error) {
				return &organizations.ListAWSServiceAccessForOrganizationOutput{NextToken: aws.String("same")}, nil
			}
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			client := administratorsFixtureClient(false)
			mutate(client)
			var output bytes.Buffer
			if err := displayAdministrators(context.Background(), &output, client, json); err == nil {
				t.Fatal("expected an error")
			}
			if output.Len() != 0 {
				t.Fatalf("stdout contains partial result: %q", output.String())
			}
		})
	}
}

func TestAdministratorsAccessDeniedIsClassified(t *testing.T) {
	t.Parallel()

	client := administratorsFixtureClient(false)
	client.listAdministratorsFn = func(context.Context, *organizations.ListDelegatedAdministratorsInput) (*organizations.ListDelegatedAdministratorsOutput, error) {
		return nil, awsOperationError("ListDelegatedAdministrators", "AccessDeniedException", smithy.FaultClient)
	}
	_, err := buildAdministrators(context.Background(), client)
	diagnostic := classifyError(err)
	if diagnostic.Code != errorCodeAuthorization || diagnostic.Operation != "ListDelegatedAdministrators" {
		t.Fatalf("diagnostic = %#v, want aws_access_denied for ListDelegatedAdministrators", diagnostic)
	}
}

func TestAdministratorsTextOutputEscapesUntrustedValues(t *testing.T) {
	t.Parallel()

	result, err := buildAdministrators(context.Background(), administratorsFixtureClient(false))
	if err != nil {
		t.Fatal(err)
	}
	result.DelegatedAdministrators[0].Name = "Sec\x1b[31murity"
	result.ResourcePolicy.Content = encodingjson.RawMessage(`{"Sid":"a` + "\u009b" + `b"}`)
	var output bytes.Buffer
	if err := writeAdministrators(&output, result, text); err != nil {
		t.Fatalf("write text: %v", err)
	}
	got := output.String()
	if strings.ContainsAny(got, "\x1b\u009b") {
		t.Fatalf("text output contains raw terminal controls: %q", got)
	}
	for _, expected := range []string{
		"Organization [o-example] (feature set ALL)\n",
		"Management account [111111111111]: can manage organization policies and settings\n",
		"Delegation policy [rp-example1]:\n",
		`Account Sec\x1b[31murity [222222222222] (ACTIVE)`,
		"    - securityhub.amazonaws.com (since 2025-03-04T10:06:07Z)\n",
		"Trusted access:\n- guardduty.amazonaws.com\n- sso.amazonaws.com (since 2025-03-04T10:06:07Z)\n",
		"Configuration only:",
	} {
		if !strings.Contains(got, expected) {
			t.Errorf("text output lacks %q:\n%s", expected, got)
		}
	}
}
