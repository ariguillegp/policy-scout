package cmd

import (
	"bytes"
	"context"
	encodingjson "encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"github.com/spf13/cobra"
)

const administratorsSchemaVersion = "1"

var (
	administratorsFormat outputFormat = json

	awsAdministratorsCmd = &cobra.Command{
		Use:   "administrators",
		Short: "Show which accounts and services can administer the organization",
		Long: `Return one compact, versioned result describing who can change organization
controls: the management account, the Organizations resource-based delegation
policy, delegated administrator accounts with the services each is delegated
for, and AWS services with trusted access enabled. JSON output is used by
default.

The management account can always manage organization policies. The
delegation policy document is returned as AWS stores it; Policy Scout does not
interpret its statements, conditions, or principals. This command reports
Organizations configuration only. It does not evaluate IAM policies, SCPs,
permission boundaries, session policies, or the effective permissions of any
identity.

AWS permits these requests only from the management account or a delegated
administrator account.`,
		Example: `  policy-scout aws administrators
  policy-scout aws administrators --output-format text
  policy-scout aws administrators --output-format json --timeout 30s --max-retries 3`,
		Args: noArgsValidator,
		RunE: runAWSAdministratorsCommand,
	}
)

func init() {
	awsAdministratorsCmd.Flags().VarP(&administratorsFormat, "output-format", "o", `output format: "json" or "text"`)
	if err := awsAdministratorsCmd.RegisterFlagCompletionFunc("output-format", outputFormatCompletion); err != nil {
		panic(err)
	}
	addAWSExecutionFlags(awsAdministratorsCmd)
}

type administratorsClient interface {
	organizations.ListDelegatedAdministratorsAPIClient
	organizations.ListDelegatedServicesForAccountAPIClient
	organizations.ListAWSServiceAccessForOrganizationAPIClient
	DescribeOrganization(context.Context, *organizations.DescribeOrganizationInput, ...func(*organizations.Options)) (*organizations.DescribeOrganizationOutput, error)
	DescribeResourcePolicy(context.Context, *organizations.DescribeResourcePolicyInput, ...func(*organizations.Options)) (*organizations.DescribeResourcePolicyOutput, error)
}

type administratorsOrganization struct {
	ID         string `json:"id"`
	ARN        string `json:"arn,omitempty"`
	FeatureSet string `json:"feature_set,omitempty"`
}

type administratorsManagementAccount struct {
	ID  string `json:"id"`
	ARN string `json:"arn,omitempty"`
}

type administratorsResourcePolicy struct {
	ID      string                  `json:"id"`
	ARN     string                  `json:"arn,omitempty"`
	Content encodingjson.RawMessage `json:"content"`
}

type delegatedService struct {
	ServicePrincipal      string `json:"service_principal"`
	DelegationEnabledDate string `json:"delegation_enabled_date,omitempty"`
}

type delegatedAdministrator struct {
	ID                    string             `json:"id"`
	Name                  string             `json:"name,omitempty"`
	ARN                   string             `json:"arn,omitempty"`
	State                 string             `json:"state,omitempty"`
	DelegationEnabledDate string             `json:"delegation_enabled_date,omitempty"`
	Services              []delegatedService `json:"services"`
}

type trustedService struct {
	ServicePrincipal string `json:"service_principal"`
	DateEnabled      string `json:"date_enabled,omitempty"`
}

type administratorsResult struct {
	SchemaVersion           string                          `json:"schema_version"`
	Organization            administratorsOrganization      `json:"organization"`
	ManagementAccount       administratorsManagementAccount `json:"management_account"`
	ResourcePolicy          *administratorsResourcePolicy   `json:"resource_policy"`
	DelegatedAdministrators []delegatedAdministrator        `json:"delegated_administrators"`
	TrustedServices         []trustedService                `json:"trusted_services"`
}

func runAWSAdministratorsCommand(cmd *cobra.Command, _ []string) error {
	controls, err := awsExecutionControlsFromCommand(cmd)
	if err != nil {
		return err
	}
	ctx, cancel := controls.context(cmd.Context())
	defer cancel()
	err = inspectAWSAdministrators(ctx, cmd.OutOrStdout(), profile, administratorsFormat, controls.configLoadOptions()...)
	return controls.explainError(err)
}

func inspectAWSAdministrators(
	ctx context.Context,
	writer io.Writer,
	selectedProfile string,
	outputFormat outputFormat,
	configOptions ...func(*config.LoadOptions) error,
) (err error) {
	defer func() { err = addSSORemediation(err, selectedProfile) }()
	cfg, err := loadAWSConfig(ctx, selectedProfile, config.LoadDefaultConfig, configOptions...)
	if err != nil {
		return newCredentialsError("LoadDefaultConfig", err)
	}
	if _, err := cfg.Credentials.Retrieve(ctx); err != nil {
		return newCredentialsError("RetrieveCredentials", err)
	}
	return displayAdministrators(ctx, writer, organizations.NewFromConfig(cfg), outputFormat)
}

func displayAdministrators(ctx context.Context, writer io.Writer, client administratorsClient, outputFormat outputFormat) error {
	result, err := buildAdministrators(ctx, client)
	if err != nil {
		return err
	}
	return writeAdministrators(writer, result, outputFormat)
}

func buildAdministrators(ctx context.Context, client administratorsClient) (administratorsResult, error) {
	result := administratorsResult{SchemaVersion: administratorsSchemaVersion}
	err := runOrganizationJobs(ctx, 4, func(ctx context.Context, index int) error {
		var err error
		switch index {
		case 0:
			result.Organization, result.ManagementAccount, err = describeAdministeredOrganization(ctx, client)
		case 1:
			result.ResourcePolicy, err = describeOrganizationResourcePolicy(ctx, client)
		case 2:
			result.DelegatedAdministrators, err = listDelegatedAdministrators(ctx, client)
		case 3:
			result.TrustedServices, err = listTrustedServices(ctx, client)
		}
		return err
	})
	if err != nil {
		return administratorsResult{}, err
	}

	admins := result.DelegatedAdministrators
	deregistered := make([]bool, len(admins))
	err = runOrganizationJobs(ctx, len(admins), func(ctx context.Context, index int) error {
		services, err := listDelegatedServices(ctx, client, admins[index].ID)
		if err != nil {
			// The account stopped being a delegated administrator, or left the
			// organization, after ListDelegatedAdministrators returned it.
			var notRegistered *types.AccountNotRegisteredException
			var notFound *types.AccountNotFoundException
			if errors.As(err, &notRegistered) || errors.As(err, &notFound) {
				deregistered[index] = true
				return nil
			}
			return fmt.Errorf("list delegated services for account %s: %w", admins[index].ID, err)
		}
		admins[index].Services = services
		return nil
	})
	if err != nil {
		return administratorsResult{}, err
	}
	result.DelegatedAdministrators = make([]delegatedAdministrator, 0, len(admins))
	for index, admin := range admins {
		if !deregistered[index] {
			result.DelegatedAdministrators = append(result.DelegatedAdministrators, admin)
		}
	}
	return result, nil
}

func describeAdministeredOrganization(
	ctx context.Context,
	client administratorsClient,
) (administratorsOrganization, administratorsManagementAccount, error) {
	output, err := client.DescribeOrganization(ctx, &organizations.DescribeOrganizationInput{})
	if err != nil {
		return administratorsOrganization{}, administratorsManagementAccount{}, fmt.Errorf("describe organization: %w", err)
	}
	if output == nil || output.Organization == nil {
		return administratorsOrganization{}, administratorsManagementAccount{}, errors.New("AWS returned no organization details")
	}
	organization := output.Organization
	if aws.ToString(organization.Id) == "" {
		return administratorsOrganization{}, administratorsManagementAccount{}, errors.New("AWS returned no organization ID")
	}
	managementAccountID := aws.ToString(organization.MasterAccountId)
	if err := validateStrictAccountID(managementAccountID); err != nil {
		return administratorsOrganization{}, administratorsManagementAccount{}, fmt.Errorf("AWS returned invalid management account ID %q: %w", managementAccountID, err)
	}
	return administratorsOrganization{
			ID: aws.ToString(organization.Id), ARN: aws.ToString(organization.Arn), FeatureSet: string(organization.FeatureSet),
		}, administratorsManagementAccount{
			ID: managementAccountID, ARN: aws.ToString(organization.MasterAccountArn),
		}, nil
}

// describeOrganizationResourcePolicy returns nil when the organization has no
// resource-based delegation policy.
func describeOrganizationResourcePolicy(ctx context.Context, client administratorsClient) (*administratorsResourcePolicy, error) {
	output, err := client.DescribeResourcePolicy(ctx, &organizations.DescribeResourcePolicyInput{})
	if err != nil {
		var notFound *types.ResourcePolicyNotFoundException
		if errors.As(err, &notFound) {
			return nil, nil
		}
		return nil, fmt.Errorf("describe resource policy: %w", err)
	}
	if output == nil || output.ResourcePolicy == nil || output.ResourcePolicy.ResourcePolicySummary == nil {
		return nil, errors.New("AWS returned no resource policy details")
	}
	summary := output.ResourcePolicy.ResourcePolicySummary
	policyID := aws.ToString(summary.Id)
	if policyID == "" {
		return nil, errors.New("AWS returned a resource policy without an ID")
	}
	content := encodingjson.RawMessage(strings.TrimSpace(aws.ToString(output.ResourcePolicy.Content)))
	var document map[string]encodingjson.RawMessage
	if err := encodingjson.Unmarshal(content, &document); err != nil || document == nil {
		return nil, fmt.Errorf("AWS returned malformed JSON content for resource policy %s", policyID)
	}
	return &administratorsResourcePolicy{ID: policyID, ARN: aws.ToString(summary.Arn), Content: content}, nil
}

func listDelegatedAdministrators(
	ctx context.Context,
	client organizations.ListDelegatedAdministratorsAPIClient,
) ([]delegatedAdministrator, error) {
	paginator := organizations.NewListDelegatedAdministratorsPaginator(client, &organizations.ListDelegatedAdministratorsInput{})
	byID := make(map[string]delegatedAdministrator)
	seenTokens := make(map[string]bool)
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("list delegated administrators: %w", err)
		}
		if err := rejectRepeatedToken(seenTokens, page.NextToken, "ListDelegatedAdministrators"); err != nil {
			return nil, err
		}
		for _, admin := range page.DelegatedAdministrators {
			accountID := aws.ToString(admin.Id)
			if err := validateStrictAccountID(accountID); err != nil {
				return nil, fmt.Errorf("AWS returned delegated administrator with invalid account ID %q: %w", accountID, err)
			}
			value := delegatedAdministrator{
				ID:                    accountID,
				Name:                  aws.ToString(admin.Name),
				ARN:                   aws.ToString(admin.Arn),
				State:                 string(admin.State),
				DelegationEnabledDate: formatAWSTime(admin.DelegationEnabledDate),
				Services:              []delegatedService{},
			}
			if existing, found := byID[accountID]; found && !equalDelegatedAdministrators(existing, value) {
				return nil, fmt.Errorf("AWS returned conflicting summaries for delegated administrator %s", accountID)
			}
			byID[accountID] = value
		}
	}
	admins := make([]delegatedAdministrator, 0, len(byID))
	for _, admin := range byID {
		admins = append(admins, admin)
	}
	sort.Slice(admins, func(i, j int) bool { return admins[i].ID < admins[j].ID })
	return admins, nil
}

func equalDelegatedAdministrators(left, right delegatedAdministrator) bool {
	return left.ID == right.ID && left.Name == right.Name && left.ARN == right.ARN &&
		left.State == right.State && left.DelegationEnabledDate == right.DelegationEnabledDate
}

func listDelegatedServices(
	ctx context.Context,
	client organizations.ListDelegatedServicesForAccountAPIClient,
	accountID string,
) ([]delegatedService, error) {
	paginator := organizations.NewListDelegatedServicesForAccountPaginator(
		client, &organizations.ListDelegatedServicesForAccountInput{AccountId: &accountID},
	)
	byPrincipal := make(map[string]delegatedService)
	seenTokens := make(map[string]bool)
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		if err := rejectRepeatedToken(seenTokens, page.NextToken, "ListDelegatedServicesForAccount"); err != nil {
			return nil, err
		}
		for _, service := range page.DelegatedServices {
			value := delegatedService{
				ServicePrincipal:      aws.ToString(service.ServicePrincipal),
				DelegationEnabledDate: formatAWSTime(service.DelegationEnabledDate),
			}
			if value.ServicePrincipal == "" {
				return nil, fmt.Errorf("AWS returned a delegated service without a service principal for account %s", accountID)
			}
			if existing, found := byPrincipal[value.ServicePrincipal]; found && existing != value {
				return nil, fmt.Errorf("AWS returned conflicting delegations of %s to account %s", value.ServicePrincipal, accountID)
			}
			byPrincipal[value.ServicePrincipal] = value
		}
	}
	services := make([]delegatedService, 0, len(byPrincipal))
	for _, service := range byPrincipal {
		services = append(services, service)
	}
	sort.Slice(services, func(i, j int) bool { return services[i].ServicePrincipal < services[j].ServicePrincipal })
	return services, nil
}

func listTrustedServices(
	ctx context.Context,
	client organizations.ListAWSServiceAccessForOrganizationAPIClient,
) ([]trustedService, error) {
	paginator := organizations.NewListAWSServiceAccessForOrganizationPaginator(
		client, &organizations.ListAWSServiceAccessForOrganizationInput{},
	)
	byPrincipal := make(map[string]trustedService)
	seenTokens := make(map[string]bool)
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("list AWS service access: %w", err)
		}
		if err := rejectRepeatedToken(seenTokens, page.NextToken, "ListAWSServiceAccessForOrganization"); err != nil {
			return nil, err
		}
		for _, principal := range page.EnabledServicePrincipals {
			value := trustedService{
				ServicePrincipal: aws.ToString(principal.ServicePrincipal),
				DateEnabled:      formatAWSTime(principal.DateEnabled),
			}
			if value.ServicePrincipal == "" {
				return nil, errors.New("AWS returned a trusted service without a service principal")
			}
			if existing, found := byPrincipal[value.ServicePrincipal]; found && existing != value {
				return nil, fmt.Errorf("AWS returned conflicting trusted access details for %s", value.ServicePrincipal)
			}
			byPrincipal[value.ServicePrincipal] = value
		}
	}
	services := make([]trustedService, 0, len(byPrincipal))
	for _, service := range byPrincipal {
		services = append(services, service)
	}
	sort.Slice(services, func(i, j int) bool { return services[i].ServicePrincipal < services[j].ServicePrincipal })
	return services, nil
}

func formatAWSTime(value *time.Time) string {
	if value == nil {
		return ""
	}
	return value.UTC().Format(time.RFC3339)
}

func writeAdministrators(writer io.Writer, result administratorsResult, outputFormat outputFormat) error {
	if outputFormat != text {
		return writeJSONDocument(writer, result, "administrators query")
	}

	var output strings.Builder
	organization := "Organization [" + displayText(result.Organization.ID) + "]"
	if result.Organization.FeatureSet != "" {
		organization += " (feature set " + displayText(result.Organization.FeatureSet) + ")"
	}
	fmt.Fprintln(&output, organization)
	fmt.Fprintf(&output, "Management account [%s]: can manage organization policies and settings\n", displayText(result.ManagementAccount.ID))

	if result.ResourcePolicy == nil {
		output.WriteString("Delegation policy: none\n")
	} else {
		fmt.Fprintf(&output, "Delegation policy [%s]:\n", displayText(result.ResourcePolicy.ID))
		var document bytes.Buffer
		if err := encodingjson.Indent(&document, result.ResourcePolicy.Content, "", "  "); err != nil {
			return fmt.Errorf("format resource policy %s: %w", result.ResourcePolicy.ID, err)
		}
		for _, line := range strings.Split(document.String(), "\n") {
			fmt.Fprintf(&output, "%s%s\n", indent, displayText(line))
		}
	}

	if len(result.DelegatedAdministrators) == 0 {
		output.WriteString("Delegated administrators: none\n")
	} else {
		output.WriteString("Delegated administrators:\n")
		for _, admin := range result.DelegatedAdministrators {
			label := attachmentTargetText(scpAttachmentTarget{Type: accountEntityType, ID: admin.ID, Name: admin.Name})
			if admin.State != "" {
				label += " (" + admin.State + ")"
			}
			fmt.Fprintf(&output, "- %s\n", displayText(label))
			if len(admin.Services) == 0 {
				fmt.Fprintf(&output, "%sServices: none\n", indent)
			}
			for _, service := range admin.Services {
				fmt.Fprintf(&output, "%s- %s\n", indent, displayText(datedText(service.ServicePrincipal, service.DelegationEnabledDate)))
			}
		}
	}

	if len(result.TrustedServices) == 0 {
		output.WriteString("Trusted access: none\n")
	} else {
		output.WriteString("Trusted access:\n")
		for _, service := range result.TrustedServices {
			fmt.Fprintf(&output, "- %s\n", displayText(datedText(service.ServicePrincipal, service.DateEnabled)))
		}
	}
	output.WriteString("Configuration only: effective IAM permissions and delegation policy statements are not evaluated.\n")
	return writeDocument(writer, []byte(output.String()), "administrators query")
}

func datedText(value, date string) string {
	if date == "" {
		return value
	}
	return value + " (since " + date + ")"
}
