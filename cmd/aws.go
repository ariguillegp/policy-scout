/*
Copyright © 2024 Aristides Gonzalez <aristides@glezpol.com>
*/

// Package cmd contains all the commands included in this utility
package cmd

import (
	"context"
	encodingjson "encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"slices"
	"sort"
	"strings"
	"sync"
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

// Default indentation increment to build a tree like output.
const (
	indent                            string = "    "
	maxAllowedRetries                 int    = 10
	organizationInspectionConcurrency int    = 4
)

// Organization schema v1 is the default contract. Schema v2 adds the opt-in policy catalog.
const (
	organizationJSONSchemaVersion                = "1"
	organizationPolicyDocumentsJSONSchemaVersion = "2"
)

const (
	rootEntityType               = "root"
	accountEntityType            = "account"
	organizationalUnitEntityType = "organizational_unit"
	allSelectionType             = "all"
)

// Defining a custom enum to restrict output format values.
type outputFormat string

const (
	text outputFormat = "text" //nolint:unused
	json outputFormat = "json" //nolint:unused
)

// String is used both by fmt.Print and by Cobra in help text.
func (e *outputFormat) String() string {
	return string(*e)
}

// Set must have pointer receiver so it doesn't change the value of a copy.
func (e *outputFormat) Set(value string) error {
	switch value {
	case string(text), string(json):
		*e = outputFormat(value)
		return nil
	default:
		return errors.New(`must be one of "text" or "json"`)
	}
}

// Type is only used in help text.
func (e *outputFormat) Type() string {
	return "text|json"
}

func outputFormatCompletion(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) { //nolint:unused
	return []string{
		"json\tdisplays results formatted as JSON",
		"text\tdisplays results as a text-based tree in your terminal",
	}, cobra.ShellCompDirectiveDefault
}

type hierarchyListClient interface {
	organizations.ListAccountsForParentAPIClient
	organizations.ListChildrenAPIClient
	organizations.ListOrganizationalUnitsForParentAPIClient
	DescribeAccount(context.Context, *organizations.DescribeAccountInput, ...func(*organizations.Options)) (*organizations.DescribeAccountOutput, error)
	DescribeOrganizationalUnit(context.Context, *organizations.DescribeOrganizationalUnitInput, ...func(*organizations.Options)) (*organizations.DescribeOrganizationalUnitOutput, error)
}

type organizationsClient interface {
	hierarchyListClient
	organizations.ListParentsAPIClient
	organizations.ListPoliciesForTargetAPIClient
	organizations.ListRootsAPIClient
	organizations.ListTargetsForPolicyAPIClient
	DescribeOrganization(context.Context, *organizations.DescribeOrganizationInput, ...func(*organizations.Options)) (*organizations.DescribeOrganizationOutput, error)
	DescribePolicy(context.Context, *organizations.DescribePolicyInput, ...func(*organizations.Options)) (*organizations.DescribePolicyOutput, error)
}

type accountDescriber interface {
	DescribeAccount(context.Context, *organizations.DescribeAccountInput, ...func(*organizations.Options)) (*organizations.DescribeAccountOutput, error)
}

type organizationalUnitDescriber interface {
	DescribeOrganizationalUnit(context.Context, *organizations.DescribeOrganizationalUnitInput, ...func(*organizations.Options)) (*organizations.DescribeOrganizationalUnitOutput, error)
}

type stsClient interface {
	GetCallerIdentity(context.Context, *sts.GetCallerIdentityInput, ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error)
}

type authStatusOrganizationsClient interface {
	DescribeOrganization(context.Context, *organizations.DescribeOrganizationInput, ...func(*organizations.Options)) (*organizations.DescribeOrganizationOutput, error)
}

var (
	accountID              string
	organizationalUnitID   string
	includePolicyDocuments bool
	format                 outputFormat = json
	profile                string
	authStatusFormat       outputFormat = json
	awsCmd                              = &cobra.Command{
		Use:   "aws (--account-id <12-digit-id|all> | --ou-id <ou-id>)",
		Short: "Show AWS paths and localized SCP attachments for OUs and accounts",
		Long: `Show the AWS Organizations hierarchy and names from service control
policy (SCP) summaries returned for every OU and member account. Each entity
shows its direct attachments and attachments inherited from its root/OU
ancestors. Inspect one account or OU path, or the entire organization.

JSON output is used by default.

Use --include-policy-documents with JSON output to retrieve each unique
applicable SCP once in a top-level policy catalog. Policy Scout does not
evaluate SCP Allow/Deny semantics, IAM policies, resource policies, permission boundaries,
session policies, or effective identity permissions.

Credentials and region configuration are loaded from the AWS SDK default
configuration chain. Use --profile to select a named AWS shared-config profile;
it takes precedence over AWS_PROFILE for profile selection. When omitted, the
SDK's default profile selection and credential chain are unchanged. The SDK's
configured retry behavior is also unchanged. The selected identity needs read
access to AWS Organizations. This command does not prompt for input or start an
AWS SSO login. If SSO credentials are missing or expired, run the suggested
"aws sso login --profile=<name>" command separately in an interactive terminal.`,
		Example: `  policy-scout aws --account-id 123456789012
  policy-scout aws --ou-id ou-abcd-12345678
  policy-scout aws --profile security-audit --account-id 123456789012
  policy-scout aws --account-id 123456789012 --output-format json
  policy-scout aws --account-id 123456789012 --timeout 30s --max-retries 3
  policy-scout aws --account-id 123456789012 --include-policy-documents --output-format json
  policy-scout aws --account-id all --output-format json > organization.json
  policy-scout aws --account-id all --output-format text`,
		Args: noArgsValidator,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runAWSCommand(cmd)
		},
	}
	authCmd = &cobra.Command{
		Use:   "auth",
		Short: "Inspect AWS authentication",
	}
	authStatusCmd = &cobra.Command{
		Use:   "status",
		Short: "Show the resolved AWS identity and Organizations access",
		Long: `Resolve credentials from the AWS SDK default credential chain, identify
the caller with AWS STS, and verify access to AWS Organizations. No secret
credential values are displayed. This command does not prompt for input or
start an AWS SSO login. Missing or expired SSO credentials produce a copyable
login command for an operator to run separately. Use --timeout to bound the
entire operation, including configuration and credential loading, and
--max-retries to override retries for each AWS API request.`,
		Example: `  policy-scout aws auth status
  policy-scout aws auth status --output-format text
  policy-scout aws auth status --timeout 30s --max-retries 3`,
		Args: noArgsValidator,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runAWSAuthStatusCommand(cmd)
		},
	}
)

func init() {
	rootCmd.AddCommand(awsCmd)
	awsCmd.AddCommand(authCmd)
	awsCmd.AddCommand(awsSearchCmd)
	awsCmd.AddCommand(awsPoliciesCmd)
	awsCmd.AddCommand(awsAttachmentsCmd)
	authCmd.AddCommand(authStatusCmd)

	awsCmd.PersistentFlags().StringVar(&profile, "profile", "", "AWS shared-config profile to use (overrides AWS_PROFILE)")

	awsCmd.Flags().StringVar(&accountID, "account-id", "", `AWS account ID to inspect (exactly 12 digits), or "all" for the entire organization`)
	awsCmd.Flags().StringVar(&organizationalUnitID, "ou-id", "", "AWS organizational unit ID to inspect")
	awsCmd.Flags().BoolVar(&includePolicyDocuments, "include-policy-documents", false, "include a deduplicated SCP document catalog in JSON output (requires organizations:DescribePolicy)")

	awsCmd.Flags().VarP(&format, "output-format", "o", `output format: "json" or "text"`)
	if err := awsCmd.RegisterFlagCompletionFunc("output-format", outputFormatCompletion); err != nil {
		panic(err)
	}
	addAWSExecutionFlags(awsCmd)

	authStatusCmd.Flags().VarP(&authStatusFormat, "output-format", "o", `output format: "json" or "text"`)
	if err := authStatusCmd.RegisterFlagCompletionFunc("output-format", outputFormatCompletion); err != nil {
		panic(err)
	}
	addAWSExecutionFlags(authStatusCmd)
}

type awsExecutionControls struct {
	timeout       time.Duration
	maxRetries    int
	timeoutSet    bool
	maxRetriesSet bool
}

func addAWSExecutionFlags(cmd *cobra.Command) {
	cmd.Flags().Duration("timeout", 0, "overall timeout for AWS configuration and credential loading plus API calls (for example, 30s)")
	cmd.Flags().Int("max-retries", 0, fmt.Sprintf("maximum retries per AWS API request, after the initial attempt (0-%d)", maxAllowedRetries))
}

func awsExecutionControlsFromCommand(cmd *cobra.Command) (awsExecutionControls, error) {
	timeout, err := cmd.Flags().GetDuration("timeout")
	if err != nil {
		return awsExecutionControls{}, fmt.Errorf("read --timeout: %w", err)
	}
	maxRetries, err := cmd.Flags().GetInt("max-retries")
	if err != nil {
		return awsExecutionControls{}, fmt.Errorf("read --max-retries: %w", err)
	}

	controls := awsExecutionControls{
		timeout:       timeout,
		maxRetries:    maxRetries,
		timeoutSet:    cmd.Flags().Changed("timeout"),
		maxRetriesSet: cmd.Flags().Changed("max-retries"),
	}
	if err := controls.validate(); err != nil {
		return awsExecutionControls{}, newInvalidInvocationError(err)
	}
	return controls, nil
}

func (controls awsExecutionControls) validate() error {
	if controls.timeoutSet && controls.timeout <= 0 {
		return errors.New("invalid --timeout: must be greater than zero")
	}
	if controls.maxRetriesSet && (controls.maxRetries < 0 || controls.maxRetries > maxAllowedRetries) {
		return fmt.Errorf("invalid --max-retries: must be between 0 and %d", maxAllowedRetries)
	}
	return nil
}

func (controls awsExecutionControls) context(parent context.Context) (context.Context, context.CancelFunc) {
	if !controls.timeoutSet {
		return parent, func() {}
	}
	return context.WithTimeout(parent, controls.timeout)
}

func (controls awsExecutionControls) configLoadOptions() []func(*config.LoadOptions) error {
	if !controls.maxRetriesSet {
		return nil
	}

	// AWS counts the initial request as an attempt; the CLI flag counts only
	// retries so that --max-retries 0 has the expected no-retry behavior.
	return []func(*config.LoadOptions) error{config.WithRetryMaxAttempts(controls.maxRetries + 1)}
}

func (controls awsExecutionControls) explainError(err error) error {
	if err == nil {
		return nil
	}
	if controls.timeoutSet && errors.Is(err, context.DeadlineExceeded) {
		return newExecutionTimeoutError(controls.timeout, err)
	}
	if errors.Is(err, context.Canceled) {
		return newExecutionCanceledError(err)
	}
	if controls.maxRetriesSet {
		var maxAttemptsError *awsretry.MaxAttemptsError
		if errors.As(err, &maxAttemptsError) {
			return newRetryExhaustedError(controls.maxRetries, err)
		}
	}
	return err
}

func runAWSCommand(cmd *cobra.Command) error {
	controls, err := awsExecutionControlsFromCommand(cmd)
	if err != nil {
		return err
	}

	ctx, cancel := controls.context(cmd.Context())
	defer cancel()

	targetID, err := selectedAWSTarget(
		accountID,
		cmd.Flags().Changed("account-id"),
		organizationalUnitID,
		cmd.Flags().Changed("ou-id"),
	)
	if err != nil {
		return err
	}
	if includePolicyDocuments && format != json {
		return newInvalidInvocationError(errors.New("--include-policy-documents requires --output-format json"))
	}
	err = describeTargetWithPolicyDocuments(ctx, cmd.OutOrStdout(), targetID, profile, includePolicyDocuments, controls.configLoadOptions()...)
	return controls.explainError(err)
}

func runAWSAuthStatusCommand(cmd *cobra.Command) error {
	controls, err := awsExecutionControlsFromCommand(cmd)
	if err != nil {
		return err
	}

	ctx, cancel := controls.context(cmd.Context())
	defer cancel()

	err = displayAWSAuthStatus(ctx, cmd.OutOrStdout(), profile, controls.configLoadOptions()...)
	return controls.explainError(err)
}

type awsAuthStatus struct {
	SchemaVersion string                     `json:"schema_version"`
	OK            bool                       `json:"ok"`
	Authenticated bool                       `json:"authenticated"`
	Identity      awsAuthIdentity            `json:"identity"`
	Credentials   awsAuthCredentials         `json:"credentials"`
	Organizations awsOrganizationsAuthStatus `json:"organizations"`
}

type awsAuthIdentity struct {
	AccountID string `json:"account_id"`
	ARN       string `json:"arn"`
	UserID    string `json:"user_id"`
}

type awsAuthCredentials struct {
	Source    string `json:"source"`
	CanExpire bool   `json:"can_expire"`
	ExpiresAt string `json:"expires_at,omitempty"`
}

type awsOrganizationsAuthStatus struct {
	Accessible          bool   `json:"accessible"`
	OrganizationID      string `json:"organization_id,omitempty"`
	ManagementAccountID string `json:"management_account_id,omitempty"`
	Error               string `json:"error,omitempty"`
	Message             string `json:"message,omitempty"`
}

type awsAuthStatusClientFactory func(aws.Config) (stsClient, authStatusOrganizationsClient)

func displayAWSAuthStatus(
	ctx context.Context,
	writer io.Writer,
	selectedProfile string,
	configOptions ...func(*config.LoadOptions) error,
) error {
	return displayAWSAuthStatusWithDependencies(
		ctx,
		writer,
		selectedProfile,
		config.LoadDefaultConfig,
		func(cfg aws.Config) (stsClient, authStatusOrganizationsClient) {
			return sts.NewFromConfig(cfg), organizations.NewFromConfig(cfg)
		},
		configOptions...,
	)
}

func displayAWSAuthStatusWithDependencies(
	ctx context.Context,
	writer io.Writer,
	selectedProfile string,
	configLoader awsConfigLoader,
	clientFactory awsAuthStatusClientFactory,
	configOptions ...func(*config.LoadOptions) error,
) (err error) {
	defer func() {
		err = addSSORemediation(err, selectedProfile)
	}()

	cfg, err := loadAWSConfig(ctx, selectedProfile, configLoader, configOptions...)
	if err != nil {
		return newCredentialsError("LoadDefaultConfig", err)
	}
	credentials, err := cfg.Credentials.Retrieve(ctx)
	if err != nil {
		return newCredentialsError("RetrieveCredentials", err)
	}
	stsClient, organizationsClient := clientFactory(cfg)

	return runAWSAuthStatus(
		ctx,
		writer,
		credentials,
		stsClient,
		organizationsClient,
		authStatusFormat,
	)
}

func runAWSAuthStatus(
	ctx context.Context,
	writer io.Writer,
	credentials aws.Credentials,
	stsClient stsClient,
	organizationsClient authStatusOrganizationsClient,
	outputFormat outputFormat,
) error {
	status, err := getAWSAuthStatus(
		ctx,
		credentials,
		stsClient,
		organizationsClient,
	)
	if err != nil && !status.Authenticated {
		return err
	}
	if writeErr := writeAWSAuthStatus(writer, status, outputFormat); writeErr != nil {
		return writeErr
	}
	return err
}

func getAWSAuthStatus(
	ctx context.Context,
	credentials aws.Credentials,
	stsClient stsClient,
	organizationsClient authStatusOrganizationsClient,
) (awsAuthStatus, error) {
	type identityResult struct {
		identity *sts.GetCallerIdentityOutput
		err      error
	}
	type organizationResult struct {
		organization *organizations.DescribeOrganizationOutput
		err          error
	}
	requestCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	identityResults := make(chan identityResult, 1)
	organizationResults := make(chan organizationResult, 1)
	go func() {
		identity, err := stsClient.GetCallerIdentity(requestCtx, &sts.GetCallerIdentityInput{})
		identityResults <- identityResult{identity: identity, err: err}
	}()
	go func() {
		organization, err := organizationsClient.DescribeOrganization(
			requestCtx, &organizations.DescribeOrganizationInput{},
		)
		organizationResults <- organizationResult{organization: organization, err: err}
	}()

	var identityResponse identityResult
	var organizationResponse organizationResult
	for identityResults != nil || organizationResults != nil {
		select {
		case identityResponse = <-identityResults:
			identityResults = nil
			if identityResponse.err != nil {
				cancel()
				if organizationResults != nil {
					<-organizationResults
				}
				return awsAuthStatus{}, fmt.Errorf("get AWS caller identity: %w", identityResponse.err)
			}
			identity := identityResponse.identity
			if identity == nil || aws.ToString(identity.Account) == "" || aws.ToString(identity.Arn) == "" || aws.ToString(identity.UserId) == "" {
				cancel()
				if organizationResults != nil {
					<-organizationResults
				}
				return awsAuthStatus{}, errors.New("AWS returned an incomplete caller identity")
			}
		case organizationResponse = <-organizationResults:
			organizationResults = nil
			var maxAttemptsError *awsretry.MaxAttemptsError
			if errors.Is(organizationResponse.err, context.Canceled) ||
				errors.Is(organizationResponse.err, context.DeadlineExceeded) ||
				errors.As(organizationResponse.err, &maxAttemptsError) {
				cancel()
				if identityResults != nil {
					<-identityResults
				}
				return awsAuthStatus{}, fmt.Errorf("describe AWS organization: %w", organizationResponse.err)
			}
		}
	}
	identity := identityResponse.identity

	status := awsAuthStatus{
		SchemaVersion: authStatusJSONSchemaVersion,
		Authenticated: true,
		Identity: awsAuthIdentity{
			AccountID: aws.ToString(identity.Account),
			ARN:       aws.ToString(identity.Arn),
			UserID:    aws.ToString(identity.UserId),
		},
		Credentials: awsAuthCredentials{
			Source:    credentials.Source,
			CanExpire: credentials.CanExpire,
		},
	}
	if credentials.CanExpire {
		status.Credentials.ExpiresAt = credentials.Expires.UTC().Format(time.RFC3339)
	}

	organization, organizationsErr := organizationResponse.organization, organizationResponse.err
	if organizationsErr != nil {
		diagnostic := classifyError(organizationsErr)
		status.Organizations.Error = diagnostic.Code
		status.Organizations.Message = diagnostic.Message
		var apiErr smithy.APIError
		if errors.As(organizationsErr, &apiErr) {
			if code := strings.TrimSpace(apiErr.ErrorCode()); code != "" {
				status.Organizations.Error = code
			}
		}
		return status, fmt.Errorf("describe AWS organization: %w", organizationsErr)
	}
	if organization == nil || organization.Organization == nil {
		organizationsErr := errors.New("AWS returned no organization details")
		diagnostic := classifyError(organizationsErr)
		status.Organizations.Error = diagnostic.Code
		status.Organizations.Message = diagnostic.Message
		return status, organizationsErr
	}
	status.OK = true
	status.Organizations.Accessible = true
	status.Organizations.OrganizationID = aws.ToString(organization.Organization.Id)
	status.Organizations.ManagementAccountID = aws.ToString(organization.Organization.MasterAccountId)
	return status, nil
}

func writeAWSAuthStatus(writer io.Writer, status awsAuthStatus, outputFormat outputFormat) error {
	if outputFormat == text {
		if err := writeOutput(writer, "AWS credentials: valid\n"); err != nil {
			return err
		}
		if err := writeOutput(writer, "Identity: %s\nAccount: %s\nCredential source: %s\n", status.Identity.ARN, status.Identity.AccountID, status.Credentials.Source); err != nil {
			return err
		}
		if status.Credentials.CanExpire {
			if err := writeOutput(writer, "Expires: %s\n", status.Credentials.ExpiresAt); err != nil {
				return err
			}
		}
		if status.Organizations.Accessible {
			return writeOutput(writer, "AWS Organizations: accessible\nOrganization: %s\nManagement account: %s\n", status.Organizations.OrganizationID, status.Organizations.ManagementAccountID)
		}
		return writeOutput(writer, "AWS Organizations: not accessible\nError: %s\nMessage: %s\n", status.Organizations.Error, status.Organizations.Message)
	}

	status.SchemaVersion = authStatusJSONSchemaVersion
	encoder := encodingjson.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(status); err != nil {
		return fmt.Errorf("encode AWS authentication status as JSON: %w", err)
	}
	return nil
}

type awsConfigLoader func(context.Context, ...func(*config.LoadOptions) error) (aws.Config, error)

func loadAWSConfig(
	ctx context.Context,
	selectedProfile string,
	loader awsConfigLoader,
	options ...func(*config.LoadOptions) error,
) (aws.Config, error) {
	if selectedProfile != "" {
		options = append([]func(*config.LoadOptions) error{config.WithSharedConfigProfile(selectedProfile)}, options...)
	}
	return loader(ctx, options...)
}

// describeAccount computes the information requested from the target AWS account.
func describeAccount(
	ctx context.Context,
	writer io.Writer,
	targetAccountID, selectedProfile string,
	configOptions ...func(*config.LoadOptions) error,
) error {
	if err := validateAccountID(targetAccountID); err != nil {
		return newInvalidInvocationError(fmt.Errorf("invalid --account-id %q: must be \"all\" or exactly 12 decimal digits", targetAccountID))
	}
	return describeTarget(ctx, writer, targetAccountID, selectedProfile, configOptions...)
}

func describeTarget(
	ctx context.Context,
	writer io.Writer,
	targetID, selectedProfile string,
	configOptions ...func(*config.LoadOptions) error,
) (err error) {
	return describeTargetWithPolicyDocuments(ctx, writer, targetID, selectedProfile, false, configOptions...)
}

func describeTargetWithPolicyDocuments(
	ctx context.Context,
	writer io.Writer,
	targetID, selectedProfile string,
	includeDocuments bool,
	configOptions ...func(*config.LoadOptions) error,
) (err error) {
	defer func() {
		err = addSSORemediation(err, selectedProfile)
	}()

	cfg, err := loadAWSConfig(ctx, selectedProfile, config.LoadDefaultConfig, configOptions...)
	if err != nil {
		return newCredentialsError("LoadDefaultConfig", err)
	}
	if _, err := cfg.Credentials.Retrieve(ctx); err != nil {
		return newCredentialsError("RetrieveCredentials", err)
	}
	client := organizations.NewFromConfig(cfg)

	rootID, rootName, managementAccountID, err := getRootAndManagementAccount(
		ctx, client, !strings.HasPrefix(targetID, "ou-"),
	)
	if err != nil {
		return err
	}
	return displayOrganizationTree(
		ctx, writer, client, targetID, rootID, rootName, managementAccountID, format, includeDocuments,
	)
}

type scpAttachmentTarget struct {
	Type string `json:"type"`
	ID   string `json:"id"`
	Name string `json:"name,omitempty"`
}

type scpAttachment struct {
	PolicyID   string              `json:"policy_id"`
	PolicyName string              `json:"policy_name"`
	AttachedTo scpAttachmentTarget `json:"attached_to"`
	Inherited  bool                `json:"inherited"`
}

type ssoRemediationError struct {
	profile string
	err     error
}

func (err *ssoRemediationError) Error() string { return err.err.Error() }
func (err *ssoRemediationError) Unwrap() error { return err.err }

func resolvedAWSProfile(selectedProfile string) string {
	if selectedProfile != "" {
		return selectedProfile
	}
	if profile := os.Getenv("AWS_PROFILE"); profile != "" {
		return profile
	}
	if profile := os.Getenv("AWS_DEFAULT_PROFILE"); profile != "" {
		return profile
	}
	return "default"
}

func addSSORemediation(err error, selectedProfile string) error {
	if err == nil || !isSSOCredentialError(err) {
		return err
	}
	return &ssoRemediationError{profile: resolvedAWSProfile(selectedProfile), err: err}
}

func isSSOCredentialError(err error) bool {
	var invalidToken *ssocreds.InvalidTokenError
	if errors.As(err, &invalidToken) {
		return invalidToken.Err == nil || errors.Is(invalidToken.Err, fs.ErrNotExist)
	}

	message := err.Error()
	if strings.Contains(message, "failed to read cached SSO token file") && errors.Is(err, fs.ErrNotExist) {
		return true
	}
	if strings.Contains(message, "cached SSO token is expired, or not present, and cannot be refreshed") {
		return true
	}

	var invalidGrant *ssooidctypes.InvalidGrantException
	if errors.As(err, &invalidGrant) {
		return true
	}

	var unauthorized *ssotypes.UnauthorizedException
	return errors.As(err, &unauthorized)
}

func shellQuote(value string) string {
	if value != "" && strings.IndexFunc(value, func(r rune) bool {
		return (r < 'a' || r > 'z') &&
			(r < 'A' || r > 'Z') &&
			(r < '0' || r > '9') &&
			!strings.ContainsRune("_+=,.@-/", r)
	}) == -1 {
		return value
	}
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

type organizationSelection struct {
	Type     string
	TargetID string
}

// organizationNode is the canonical hierarchy produced by AWS discovery and consumed by every renderer.
type organizationNode struct {
	SchemaVersion     string                `json:"schema_version,omitempty"`
	Selection         organizationSelection `json:"-"`
	Type              string                `json:"type"`
	ID                string                `json:"id"`
	Name              string                `json:"name,omitempty"`
	ManagementAccount bool                  `json:"management_account,omitempty"`
	SCPs              []string              `json:"scps,omitempty"`
	SCPAttachments    []scpAttachment       `json:"scp_attachments,omitempty"`
	Children          []organizationNode    `json:"children,omitempty"`
	Policies          []organizationPolicy  `json:"policies,omitempty"`
}

type organizationPolicy struct {
	ID          string                  `json:"id"`
	Name        string                  `json:"name"`
	Description string                  `json:"description,omitempty"`
	ARN         string                  `json:"arn,omitempty"`
	AWSManaged  bool                    `json:"aws_managed"`
	Content     encodingjson.RawMessage `json:"content"`
}

type organizationJSONSelection struct {
	Type     string `json:"type"`
	TargetID string `json:"target_id,omitempty"`
}

// organizationJSONNode is the type-specific JSON view of the canonical hierarchy.
// Pointer fields distinguish applicable empty collections and false values from
// fields that are intentionally inapplicable to a node type.
type organizationJSONNode struct {
	SchemaVersion     string                     `json:"schema_version,omitempty"`
	Selection         *organizationJSONSelection `json:"selection,omitempty"`
	Type              string                     `json:"type"`
	ID                string                     `json:"id"`
	Name              string                     `json:"name,omitempty"`
	ManagementAccount *bool                      `json:"management_account,omitempty"`
	SCPs              *[]string                  `json:"scps,omitempty"`
	SCPAttachments    *[]scpAttachment           `json:"scp_attachments,omitempty"`
	Children          *[]organizationJSONNode    `json:"children,omitempty"`
	Policies          *[]organizationPolicy      `json:"policies,omitempty"`
}

type organizationCache struct {
	mu               sync.Mutex
	policiesByTarget map[string][]types.PolicySummary
	entityNames      map[string]string
	policyLoads      map[string]*organizationPolicyLoad
}

type organizationPolicyLoad struct {
	done     chan struct{}
	policies []types.PolicySummary
	err      error
}

func newOrganizationCache(rootID, rootName string) *organizationCache {
	cache := &organizationCache{
		policiesByTarget: map[string][]types.PolicySummary{},
		entityNames:      map[string]string{},
	}
	if rootName != "" {
		cache.entityNames[rootID] = rootName
	}
	return cache
}

func (cache *organizationCache) setEntityName(entityID, name string) {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	cache.entityNames[entityID] = name
}

func (cache *organizationCache) entityName(entityID string) string {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	return cache.entityNames[entityID]
}

func (cache *organizationCache) policiesForTarget(
	ctx context.Context,
	client organizations.ListPoliciesForTargetAPIClient,
	targetID string,
) ([]types.PolicySummary, error) {
	cache.mu.Lock()
	if policies, found := cache.policiesByTarget[targetID]; found {
		cache.mu.Unlock()
		return policies, nil
	}
	if load, found := cache.policyLoads[targetID]; found {
		cache.mu.Unlock()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-load.done:
			return load.policies, load.err
		}
	}
	if cache.policyLoads == nil {
		cache.policyLoads = make(map[string]*organizationPolicyLoad)
	}
	load := &organizationPolicyLoad{done: make(chan struct{})}
	cache.policyLoads[targetID] = load
	cache.mu.Unlock()

	load.policies, load.err = listSCPsForTarget(ctx, client, targetID)

	cache.mu.Lock()
	if load.err == nil {
		if cache.policiesByTarget == nil {
			cache.policiesByTarget = make(map[string][]types.PolicySummary)
		}
		cache.policiesByTarget[targetID] = load.policies
	}
	delete(cache.policyLoads, targetID)
	close(load.done)
	cache.mu.Unlock()
	return load.policies, load.err
}

func displayOrganizationTree(
	ctx context.Context,
	writer io.Writer,
	client organizationsClient,
	targetAccountID, rootID, rootName, managementAccountID string,
	outputFormat outputFormat,
	includePolicyDocuments ...bool,
) error {
	root, err := buildOrganizationTree(ctx, client, targetAccountID, rootID, rootName, managementAccountID)
	if err != nil {
		return err
	}
	if len(includePolicyDocuments) > 0 && includePolicyDocuments[0] {
		root.Policies, err = describeApplicablePolicies(ctx, client, root)
		if err != nil {
			return err
		}
		root.SchemaVersion = organizationPolicyDocumentsJSONSchemaVersion
	}
	return writeOrganizationTree(writer, root, outputFormat)
}

func describeApplicablePolicies(
	ctx context.Context,
	client organizationsClient,
	root organizationNode,
) ([]organizationPolicy, error) {
	namesByID := make(map[string]string)
	if err := collectPolicyAttachments(root, namesByID); err != nil {
		return nil, err
	}
	policyIDs := make([]string, 0, len(namesByID))
	for policyID := range namesByID {
		policyIDs = append(policyIDs, policyID)
	}
	sort.Strings(policyIDs)

	policies := make([]organizationPolicy, len(policyIDs))
	err := runOrganizationJobs(ctx, len(policyIDs), func(jobCtx context.Context, index int) error {
		policy, err := describePolicy(jobCtx, client, policyIDs[index])
		if err != nil {
			return fmt.Errorf("describe policy %s: %w", policyIDs[index], err)
		}
		if policy.Name != namesByID[policy.ID] {
			return fmt.Errorf(
				"DescribePolicy returned name %q for policy %s, but attachment discovery returned %q",
				policy.Name,
				policy.ID,
				namesByID[policy.ID],
			)
		}
		policies[index] = policy
		return nil
	})
	if err != nil {
		return nil, err
	}
	return policies, nil
}

func collectPolicyAttachments(node organizationNode, namesByID map[string]string) error {
	for _, attachment := range node.SCPAttachments {
		if name, found := namesByID[attachment.PolicyID]; found && name != attachment.PolicyName {
			return fmt.Errorf(
				"SCP %s has conflicting names %q and %q",
				attachment.PolicyID,
				name,
				attachment.PolicyName,
			)
		}
		namesByID[attachment.PolicyID] = attachment.PolicyName
	}
	for _, child := range node.Children {
		if err := collectPolicyAttachments(child, namesByID); err != nil {
			return err
		}
	}
	return nil
}

func describePolicy(
	ctx context.Context,
	client organizationsClient,
	policyID string,
) (organizationPolicy, error) {
	result, err := client.DescribePolicy(ctx, &organizations.DescribePolicyInput{PolicyId: &policyID})
	if err != nil {
		return organizationPolicy{}, err
	}
	if result == nil || result.Policy == nil || result.Policy.PolicySummary == nil {
		return organizationPolicy{}, errors.New("AWS returned no policy details")
	}
	summary := result.Policy.PolicySummary
	if aws.ToString(summary.Id) != policyID {
		return organizationPolicy{}, fmt.Errorf(
			"AWS returned policy ID %q for requested policy %s",
			aws.ToString(summary.Id),
			policyID,
		)
	}
	if aws.ToString(summary.Name) == "" {
		return organizationPolicy{}, fmt.Errorf("AWS returned no name for policy %s", policyID)
	}
	if summary.Type != types.PolicyTypeServiceControlPolicy {
		return organizationPolicy{}, fmt.Errorf(
			"AWS returned policy %s with type %s, expected SERVICE_CONTROL_POLICY",
			policyID,
			summary.Type,
		)
	}
	if result.Policy.Content == nil || strings.TrimSpace(aws.ToString(result.Policy.Content)) == "" {
		return organizationPolicy{}, fmt.Errorf("AWS returned no content for policy %s", policyID)
	}
	content := encodingjson.RawMessage(aws.ToString(result.Policy.Content))
	var document map[string]encodingjson.RawMessage
	if err := encodingjson.Unmarshal(content, &document); err != nil || document == nil {
		return organizationPolicy{}, fmt.Errorf("AWS returned malformed JSON content for policy %s", policyID)
	}

	return organizationPolicy{
		ID:          policyID,
		Name:        aws.ToString(summary.Name),
		Description: aws.ToString(summary.Description),
		ARN:         aws.ToString(summary.Arn),
		AWSManaged:  summary.AwsManaged,
		Content:     content,
	}, nil
}

func inspectOrganizationTarget(
	ctx context.Context,
	writer io.Writer,
	client organizationsClient,
	targetID, rootID, rootName string,
	outputFormat outputFormat,
) error {
	return inspectOrganizationTargetWithPolicyDocuments(ctx, writer, client, targetID, rootID, rootName, outputFormat, false)
}

func inspectOrganizationTargetWithPolicyDocuments(
	ctx context.Context,
	writer io.Writer,
	client organizationsClient,
	targetID, rootID, rootName string,
	outputFormat outputFormat,
	includeDocuments bool,
) error {
	managementAccountID := ""
	if !strings.HasPrefix(targetID, "ou-") {
		var err error
		managementAccountID, err = getManagementAccountID(ctx, client)
		if err != nil {
			return err
		}
	}
	return displayOrganizationTree(ctx, writer, client, targetID, rootID, rootName, managementAccountID, outputFormat, includeDocuments)
}

func buildOrganizationTree(
	ctx context.Context,
	client organizationsClient,
	targetID, rootID, rootName, managementAccountID string,
) (organizationNode, error) {
	selection := organizationSelection{Type: accountEntityType, TargetID: targetID}
	if strings.EqualFold(targetID, allSelectionType) {
		selection = organizationSelection{Type: allSelectionType}
	} else if strings.HasPrefix(targetID, "ou-") {
		selection.Type = organizationalUnitEntityType
	}
	root := organizationNode{
		SchemaVersion: organizationJSONSchemaVersion,
		Selection:     selection,
		Type:          rootEntityType,
		ID:            rootID,
		Name:          rootName,
	}
	cache := newOrganizationCache(rootID, rootName)

	var err error
	switch selection.Type {
	case allSelectionType:
		err = runOrganizationTraversal(ctx, []organizationTraversalJob{
			newOrganizationTreeJob(client, &root, managementAccountID, []string{rootID}, cache),
		})
	case organizationalUnitEntityType:
		root.Children, err = buildOrganizationalUnitPath(ctx, client, targetID, rootID, cache)
	case accountEntityType:
		root.Children, err = buildAccountPath(ctx, client, targetID, rootID, managementAccountID, cache)
	}
	if err != nil {
		return organizationNode{}, err
	}
	return root, nil
}

func buildAccountPath(
	ctx context.Context,
	client organizationsClient,
	targetAccountID, rootID, managementAccountID string,
	cache *organizationCache,
) ([]organizationNode, error) {
	var account *types.Account
	var accountPath []string
	if err := runOrganizationJobs(ctx, 2, func(ctx context.Context, index int) error {
		if index == 0 {
			var err error
			account, err = getAccount(ctx, client, targetAccountID)
			if err != nil {
				return fmt.Errorf("describe account %s: %w", targetAccountID, err)
			}
			return nil
		}
		var err error
		accountPath, err = buildAncestorPath(ctx, client, targetAccountID, rootID)
		return err
	}); err != nil {
		return nil, err
	}
	cache.setEntityName(targetAccountID, aws.ToString(account.Name))

	ouIDs := accountPath[1 : len(accountPath)-1]
	var policyTargetIDs []string
	if targetAccountID != managementAccountID {
		policyTargetIDs = accountPath
	} else if len(ouIDs) > 0 {
		policyTargetIDs = accountPath[:len(accountPath)-1]
	}
	if err := loadFocusedPathData(ctx, client, ouIDs, policyTargetIDs, cache); err != nil {
		return nil, err
	}

	ouNodes := make([]organizationNode, 0, len(accountPath)-2)
	for index := 1; index < len(accountPath)-1; index++ {
		ouID := accountPath[index]
		ouName := cache.entityName(ouID)
		ouNode, err := buildOrganizationalUnitNode(ctx, client, ouID, ouName, accountPath[:index+1], cache)
		if err != nil {
			return nil, err
		}
		ouNodes = append(ouNodes, ouNode)
	}

	accountNode, err := buildAccountNode(
		ctx, client, targetAccountID, aws.ToString(account.Name), managementAccountID, accountPath, cache,
	)
	if err != nil {
		return nil, err
	}

	child := accountNode
	for index := len(ouNodes) - 1; index >= 0; index-- {
		ouNodes[index].Children = []organizationNode{child}
		child = ouNodes[index]
	}
	return []organizationNode{child}, nil
}

func buildOrganizationalUnitPath(
	ctx context.Context,
	client organizationsClient,
	targetOrganizationalUnitID, rootID string,
	cache *organizationCache,
) ([]organizationNode, error) {
	path, err := buildAncestorPath(ctx, client, targetOrganizationalUnitID, rootID)
	if err != nil {
		return nil, err
	}
	if len(path) < 2 || path[0] != rootID || path[len(path)-1] != targetOrganizationalUnitID {
		return nil, fmt.Errorf("invalid organizational unit path from root %s to %s", rootID, targetOrganizationalUnitID)
	}
	if err := loadFocusedPathData(ctx, client, path[1:], path, cache); err != nil {
		return nil, err
	}

	ouNodes := make([]organizationNode, 0, len(path)-1)
	for index := 1; index < len(path); index++ {
		ouID := path[index]
		ouName := cache.entityName(ouID)
		ouNode, err := buildOrganizationalUnitNode(ctx, client, ouID, ouName, path[:index+1], cache)
		if err != nil {
			return nil, err
		}
		ouNodes = append(ouNodes, ouNode)
	}

	child := ouNodes[len(ouNodes)-1]
	for index := len(ouNodes) - 2; index >= 0; index-- {
		ouNodes[index].Children = []organizationNode{child}
		child = ouNodes[index]
	}
	return []organizationNode{child}, nil
}

func loadFocusedPathData(
	ctx context.Context,
	client organizationsClient,
	ouIDs, policyTargetIDs []string,
	cache *organizationCache,
) error {
	type pathJob struct {
		entityID   string
		describeOU bool
	}
	jobs := make([]pathJob, 0, len(ouIDs)+len(policyTargetIDs))
	for index := range max(len(ouIDs), len(policyTargetIDs)) {
		if index < len(ouIDs) {
			jobs = append(jobs, pathJob{entityID: ouIDs[index], describeOU: true})
		}
		if index < len(policyTargetIDs) {
			jobs = append(jobs, pathJob{entityID: policyTargetIDs[index]})
		}
	}
	return runOrganizationJobs(ctx, len(jobs), func(ctx context.Context, index int) error {
		job := jobs[index]
		if job.describeOU {
			ou, err := getOU(ctx, client, job.entityID)
			if err != nil {
				return fmt.Errorf("get organizational unit %s: %w", job.entityID, err)
			}
			cache.setEntityName(job.entityID, aws.ToString(ou.Name))
			return nil
		}
		if _, err := cache.policiesForTarget(ctx, client, job.entityID); err != nil {
			return fmt.Errorf("list SCPs for %s: %w", job.entityID, err)
		}
		return nil
	})
}

func buildAncestorPath(
	ctx context.Context,
	client organizations.ListParentsAPIClient,
	targetID, rootID string,
) ([]string, error) {
	if strings.HasPrefix(targetID, "ou-") {
		if err := validateOrganizationalUnitForRoot(targetID, rootID); err != nil {
			return nil, err
		}
	}
	path := []string{targetID}
	visited := map[string]bool{targetID: true}
	for childID := targetID; childID != rootID; {
		parents, err := listParents(ctx, client, childID)
		if err != nil {
			return nil, fmt.Errorf("list parents for %s: %w", childID, err)
		}
		if len(parents) != 1 {
			return nil, fmt.Errorf("expected exactly one parent for %s, got %d", childID, len(parents))
		}
		parentID := aws.ToString(parents[0].Id)
		if parents[0].Type == types.ParentTypeRoot && parentID != rootID {
			return nil, fmt.Errorf("AWS returned root parent %s, expected %s", parentID, rootID)
		}
		if parents[0].Type == types.ParentTypeOrganizationalUnit {
			if err := validateOrganizationalUnitForRoot(parentID, rootID); err != nil {
				return nil, fmt.Errorf("AWS returned invalid organizational unit parent %s for %s: %w", parentID, childID, err)
			}
		}
		if visited[parentID] {
			return nil, fmt.Errorf("cycle detected in organization hierarchy at %s", parentID)
		}
		visited[parentID] = true
		path = append(path, parentID)
		childID = parentID
	}

	result := make([]string, len(path))
	for index := range path {
		result[len(path)-1-index] = path[index]
	}
	return result, nil
}

func newOrganizationTreeJob(
	client organizationsClient,
	node *organizationNode,
	managementAccountID string,
	ancestors []string,
	cache *organizationCache,
) organizationTraversalJob {
	return organizationTraversalJob{
		id:        node.ID,
		ancestors: ancestors,
		run: func(ctx context.Context) ([]organizationTraversalJob, error) {
			if node.Type == accountEntityType {
				cache.setEntityName(node.ID, node.Name)
				built, err := buildAccountNode(
					ctx, client, node.ID, node.Name, managementAccountID, ancestors, cache,
				)
				if err != nil {
					return nil, err
				}
				*node = built
				return nil, nil
			}
			if node.Type == organizationalUnitEntityType {
				cache.setEntityName(node.ID, node.Name)
				built, err := buildOrganizationalUnitNode(ctx, client, node.ID, node.Name, ancestors, cache)
				if err != nil {
					return nil, err
				}
				*node = built
			}

			accounts, err := listAccountsForParent(ctx, client, node.ID)
			if err != nil {
				return nil, fmt.Errorf("list accounts for %s: %w", node.ID, err)
			}
			organizationalUnits, err := listOrganizationalUnitsForParent(ctx, client, node.ID)
			if err != nil {
				return nil, fmt.Errorf("list organizational units for %s: %w", node.ID, err)
			}

			node.Children = make([]organizationNode, len(accounts)+len(organizationalUnits))
			children := make([]organizationTraversalJob, 0, len(node.Children))
			for index, account := range accounts {
				accountID := aws.ToString(account.Id)
				node.Children[index] = organizationNode{
					Type: accountEntityType, ID: accountID, Name: aws.ToString(account.Name),
				}
				children = append(children, newOrganizationTreeJob(
					client, &node.Children[index], managementAccountID, appendPath(ancestors, accountID), cache,
				))
			}
			for index, ou := range organizationalUnits {
				ouID := aws.ToString(ou.Id)
				childIndex := len(accounts) + index
				node.Children[childIndex] = organizationNode{
					Type: organizationalUnitEntityType, ID: ouID, Name: aws.ToString(ou.Name),
				}
				children = append(children, newOrganizationTreeJob(
					client, &node.Children[childIndex], managementAccountID, appendPath(ancestors, ouID), cache,
				))
			}
			return children, nil
		},
	}
}

type organizationTraversalJob struct {
	id        string
	ancestors []string
	run       func(context.Context) ([]organizationTraversalJob, error)
}

type organizationTraversalResult struct {
	children []organizationTraversalJob
	err      error
}

// runOrganizationTraversal centrally schedules discovered work so workers never wait for descendants.
func runOrganizationTraversal(ctx context.Context, initial []organizationTraversalJob) error {
	jobCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	jobs := make(chan organizationTraversalJob)
	results := make(chan organizationTraversalResult, organizationInspectionConcurrency)
	var workers sync.WaitGroup
	workers.Add(organizationInspectionConcurrency)
	for range organizationInspectionConcurrency {
		go func() {
			defer workers.Done()
			for job := range jobs {
				children, err := job.run(jobCtx)
				results <- organizationTraversalResult{children: children, err: err}
			}
		}()
	}

	queue := append([]organizationTraversalJob(nil), initial...)
	seen := make(map[string]bool)
	for _, job := range initial {
		seen[job.id] = true
	}
	active := 0
	var firstError error
	done := jobCtx.Done()
	for len(queue) > 0 || active > 0 {
		var ready chan organizationTraversalJob
		var next organizationTraversalJob
		if firstError == nil && len(queue) > 0 {
			ready = jobs
			next = queue[0]
		}
		select {
		case ready <- next:
			queue = queue[1:]
			active++
		case result := <-results:
			active--
			if result.err != nil && firstError == nil {
				firstError = result.err
				queue = nil
				cancel()
				done = nil
				continue
			}
			if firstError != nil {
				continue
			}
			for _, child := range result.children {
				if slices.Contains(child.ancestors[:len(child.ancestors)-1], child.id) {
					firstError = fmt.Errorf("cycle detected in organization hierarchy at %s", child.id)
					queue = nil
					cancel()
					done = nil
					break
				}
				if seen[child.id] {
					firstError = fmt.Errorf("duplicate entity detected in organization hierarchy at %s", child.id)
					queue = nil
					cancel()
					done = nil
					break
				}
				seen[child.id] = true
				queue = append(queue, child)
			}
		case <-done:
			if firstError == nil {
				firstError = ctx.Err()
				queue = nil
			}
			done = nil
		}
	}
	close(jobs)
	workers.Wait()
	return firstError
}

func runOrganizationJobs(ctx context.Context, jobCount int, job func(context.Context, int) error) error {
	if jobCount == 0 {
		return nil
	}

	workerCount := min(jobCount, organizationInspectionConcurrency)
	jobCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	jobs := make(chan int)
	var workers sync.WaitGroup
	var firstError error
	var firstErrorOnce sync.Once
	workers.Add(workerCount)
	for range workerCount {
		go func() {
			defer workers.Done()
			for {
				select {
				case <-jobCtx.Done():
					return
				case index, open := <-jobs:
					if !open || jobCtx.Err() != nil {
						return
					}
					if err := job(jobCtx, index); err != nil {
						firstErrorOnce.Do(func() {
							firstError = err
							cancel()
						})
						return
					}
				}
			}
		}()
	}

sendJobs:
	for index := range jobCount {
		select {
		case <-jobCtx.Done():
			break sendJobs
		case jobs <- index:
		}
	}
	close(jobs)
	workers.Wait()
	if firstError != nil {
		return firstError
	}
	return ctx.Err()
}

func buildAccountNode(
	ctx context.Context,
	client organizationsClient,
	accountID, accountName, managementAccountID string,
	path []string,
	cache *organizationCache,
) (organizationNode, error) {
	node := organizationNode{Type: accountEntityType, ID: accountID, Name: accountName}
	if accountID == managementAccountID {
		node.ManagementAccount = true
		return node, nil
	}

	scpNames, attachments, err := listSCPsForPath(ctx, client, path, cache)
	if err != nil {
		return organizationNode{}, fmt.Errorf("get SCPs for account %s: %w", accountID, err)
	}
	node.SCPs = scpNames
	node.SCPAttachments = attachments
	return node, nil
}

func buildOrganizationalUnitNode(
	ctx context.Context,
	client organizationsClient,
	ouID, ouName string,
	path []string,
	cache *organizationCache,
) (organizationNode, error) {
	node := organizationNode{Type: organizationalUnitEntityType, ID: ouID, Name: ouName}
	scpNames, attachments, err := listSCPsForPath(ctx, client, path, cache)
	if err != nil {
		return organizationNode{}, fmt.Errorf("get SCPs for organizational unit %s: %w", ouID, err)
	}
	node.SCPs = scpNames
	node.SCPAttachments = attachments
	return node, nil
}

func writeOutput(writer io.Writer, outputFormat string, values ...any) error {
	_, err := fmt.Fprintf(writer, outputFormat, values...)
	return err
}

func appendPath(path []string, entityID string) []string {
	result := make([]string, len(path), len(path)+1)
	copy(result, path)
	return append(result, entityID)
}

func writeOrganizationTree(writer io.Writer, root organizationNode, outputFormat outputFormat) error {
	var document []byte
	if outputFormat == json {
		encoded, err := renderOrganizationTreeJSON(root)
		if err != nil {
			return err
		}
		document = encoded
	} else {
		document = []byte(renderOrganizationTreeText(root))
	}

	written, err := writer.Write(document)
	if err == nil && written != len(document) {
		err = io.ErrShortWrite
	}
	if err != nil && outputFormat == json {
		return fmt.Errorf("encode organization as JSON: %w", err)
	}
	return err
}

func renderOrganizationTreeJSON(root organizationNode) ([]byte, error) {
	encoded, err := encodingjson.MarshalIndent(newOrganizationJSONNode(root), "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode organization as JSON: %w", err)
	}
	return append(encoded, '\n'), nil
}

func newOrganizationJSONNode(node organizationNode) organizationJSONNode {
	view := organizationJSONNode{
		SchemaVersion: node.SchemaVersion,
		Type:          node.Type,
		ID:            node.ID,
		Name:          node.Name,
	}

	switch node.Type {
	case rootEntityType:
		selection := organizationJSONSelection{
			Type:     node.Selection.Type,
			TargetID: node.Selection.TargetID,
		}
		children := newOrganizationJSONChildren(node.Children)
		view.Selection = &selection
		view.Children = &children
		if node.SchemaVersion == organizationPolicyDocumentsJSONSchemaVersion {
			policies := nonNilSlice(node.Policies)
			view.Policies = &policies
		}
	case organizationalUnitEntityType:
		scps := nonNilSlice(node.SCPs)
		attachments := nonNilSlice(node.SCPAttachments)
		children := newOrganizationJSONChildren(node.Children)
		view.SCPs = &scps
		view.SCPAttachments = &attachments
		view.Children = &children
	case accountEntityType:
		managementAccount := node.ManagementAccount
		view.ManagementAccount = &managementAccount
		if !managementAccount {
			scps := nonNilSlice(node.SCPs)
			attachments := nonNilSlice(node.SCPAttachments)
			view.SCPs = &scps
			view.SCPAttachments = &attachments
		}
	}

	return view
}

func newOrganizationJSONChildren(children []organizationNode) []organizationJSONNode {
	result := make([]organizationJSONNode, len(children))
	for index, child := range children {
		result[index] = newOrganizationJSONNode(child)
	}
	return result
}

func nonNilSlice[T any](values []T) []T {
	if values == nil {
		return []T{}
	}
	return values
}

func renderOrganizationTreeText(root organizationNode) string {
	var output strings.Builder
	if root.Selection.Type == allSelectionType {
		output.WriteString("Full organization\n")
	} else if target := findOrganizationNode(root, root.Selection.TargetID); target != nil {
		fmt.Fprintf(&output, "Organization path to %s\n", organizationTextLabel(*target))
	} else {
		output.WriteString("Organization path\n")
	}
	renderOrganizationTextNode(&output, root, "", true, true)
	return output.String()
}

func findOrganizationNode(node organizationNode, targetID string) *organizationNode {
	if node.ID == targetID {
		return &node
	}
	for index := range node.Children {
		if target := findOrganizationNode(node.Children[index], targetID); target != nil {
			return target
		}
	}
	return nil
}

func renderOrganizationTextNode(output *strings.Builder, node organizationNode, prefix string, last, root bool) {
	label := organizationTextLabel(node)
	childPrefix := prefix
	if root {
		fmt.Fprintln(output, label)
	} else {
		renderOrganizationTextLine(output, prefix, last, label)
		if last {
			childPrefix += indent
		} else {
			childPrefix += "|   "
		}
	}

	detailCount := 0
	switch node.Type {
	case accountEntityType:
		if node.ManagementAccount {
			detailCount = 1
		} else {
			detailCount = max(1, len(node.SCPAttachments))
		}
	case organizationalUnitEntityType:
		detailCount = max(1, len(node.SCPAttachments))
	}

	totalChildren := detailCount + len(node.Children)
	renderedChildren := 0
	if detailCount > 0 {
		switch {
		case node.ManagementAccount:
			renderedChildren++
			renderOrganizationTextLine(
				output,
				childPrefix,
				renderedChildren == totalChildren,
				"SCPs do not affect its users or roles.",
			)
		case len(node.SCPAttachments) == 0:
			renderedChildren++
			policies := "none"
			if len(node.SCPs) > 0 {
				policies = strings.Join(node.SCPs, ", ")
			}
			renderOrganizationTextLine(
				output,
				childPrefix,
				renderedChildren == totalChildren,
				"SCPs: "+policies,
			)
		default:
			for _, attachment := range node.SCPAttachments {
				renderedChildren++
				renderOrganizationTextLine(
					output,
					childPrefix,
					renderedChildren == totalChildren,
					scpAttachmentText(attachment),
				)
			}
		}
	}

	for _, child := range node.Children {
		renderedChildren++
		renderOrganizationTextNode(
			output,
			child,
			childPrefix,
			renderedChildren == totalChildren,
			false,
		)
	}
}

func renderOrganizationTextLine(output *strings.Builder, prefix string, last bool, text string) {
	connector := "|-- "
	if last {
		connector = "`-- "
	}
	fmt.Fprintf(output, "%s%s%s\n", prefix, connector, text)
}

func organizationTextLabel(node organizationNode) string {
	label := attachmentTargetText(scpAttachmentTarget{Type: node.Type, ID: node.ID, Name: node.Name})
	if node.ManagementAccount {
		label += " (management account)"
	}
	return label
}

func scpAttachmentText(attachment scpAttachment) string {
	text := fmt.Sprintf("SCP %s [%s] — direct", attachment.PolicyName, attachment.PolicyID)
	if attachment.Inherited {
		text = fmt.Sprintf(
			"SCP %s [%s] — inherited from %s",
			attachment.PolicyName,
			attachment.PolicyID,
			attachmentTargetText(attachment.AttachedTo),
		)
	}
	return text
}

func attachmentTargetText(target scpAttachmentTarget) string {
	typeLabel := "Entity"
	switch target.Type {
	case rootEntityType:
		typeLabel = "Root"
	case organizationalUnitEntityType:
		typeLabel = "OU"
	case accountEntityType:
		typeLabel = "Account"
	}
	if target.Name == "" || (target.Type == rootEntityType && strings.EqualFold(target.Name, typeLabel)) {
		return fmt.Sprintf("%s [%s]", typeLabel, target.ID)
	}
	return fmt.Sprintf("%s %s [%s]", typeLabel, target.Name, target.ID)
}

// listAccountsForParent lists account metadata across every response page,
// deduplicated and sorted by ID so callers do not depend on AWS response ordering.
func listAccountsForParent(
	ctx context.Context,
	client hierarchyListClient,
	parentID string,
) ([]types.Account, error) {
	paginator := organizations.NewListAccountsForParentPaginator(
		client,
		&organizations.ListAccountsForParentInput{ParentId: &parentID},
	)
	accountsByID := make(map[string]types.Account)
	seenTokens := make(map[string]bool)
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			if isAccessDeniedException(err) {
				return listAccountsForParentLegacy(ctx, client, parentID)
			}
			return nil, err
		}
		if err := rejectRepeatedToken(seenTokens, page.NextToken, "ListAccountsForParent"); err != nil {
			return nil, err
		}
		for _, account := range page.Accounts {
			accountID := aws.ToString(account.Id)
			if accountID == "" {
				return nil, fmt.Errorf("AWS returned an account without an ID for parent %s", parentID)
			}
			accountName := aws.ToString(account.Name)
			if accountName == "" {
				return nil, fmt.Errorf("AWS returned no name for account %s", accountID)
			}
			if existing, found := accountsByID[accountID]; found {
				if aws.ToString(existing.Name) != accountName {
					return nil, fmt.Errorf(
						"account %s has conflicting names %q and %q",
						accountID, aws.ToString(existing.Name), accountName,
					)
				}
				continue
			}
			accountsByID[accountID] = account
		}
	}
	accounts := make([]types.Account, 0, len(accountsByID))
	for _, account := range accountsByID {
		accounts = append(accounts, account)
	}
	sort.Slice(accounts, func(left, right int) bool {
		return aws.ToString(accounts[left].Id) < aws.ToString(accounts[right].Id)
	})
	return accounts, nil
}

func listAccountsForParentLegacy(
	ctx context.Context,
	client hierarchyListClient,
	parentID string,
) ([]types.Account, error) {
	children, err := listChildren(ctx, client, parentID, types.ChildTypeAccount)
	if err != nil {
		return nil, err
	}
	accounts := make([]types.Account, len(children))
	for index, child := range children {
		account, err := getAccount(ctx, client, aws.ToString(child.Id))
		if err != nil {
			return nil, fmt.Errorf("describe account %s: %w", aws.ToString(child.Id), err)
		}
		accounts[index] = *account
	}
	return accounts, nil
}

// listOrganizationalUnitsForParent lists OU metadata across every response page,
// deduplicated and sorted by ID so callers do not depend on AWS response ordering.
func listOrganizationalUnitsForParent(
	ctx context.Context,
	client hierarchyListClient,
	parentID string,
) ([]types.OrganizationalUnit, error) {
	paginator := organizations.NewListOrganizationalUnitsForParentPaginator(
		client,
		&organizations.ListOrganizationalUnitsForParentInput{ParentId: &parentID},
	)
	organizationalUnitsByID := make(map[string]types.OrganizationalUnit)
	seenTokens := make(map[string]bool)
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			if isAccessDeniedException(err) {
				return listOrganizationalUnitsForParentLegacy(ctx, client, parentID)
			}
			return nil, err
		}
		if err := rejectRepeatedToken(seenTokens, page.NextToken, "ListOrganizationalUnitsForParent"); err != nil {
			return nil, err
		}
		for _, ou := range page.OrganizationalUnits {
			ouID := aws.ToString(ou.Id)
			if ouID == "" {
				return nil, fmt.Errorf("AWS returned an organizational unit without an ID for parent %s", parentID)
			}
			ouName := aws.ToString(ou.Name)
			if ouName == "" {
				return nil, fmt.Errorf("AWS returned no name for organizational unit %s", ouID)
			}
			if existing, found := organizationalUnitsByID[ouID]; found {
				if aws.ToString(existing.Name) != ouName {
					return nil, fmt.Errorf(
						"organizational unit %s has conflicting names %q and %q",
						ouID, aws.ToString(existing.Name), ouName,
					)
				}
				continue
			}
			organizationalUnitsByID[ouID] = ou
		}
	}
	organizationalUnits := make([]types.OrganizationalUnit, 0, len(organizationalUnitsByID))
	for _, ou := range organizationalUnitsByID {
		organizationalUnits = append(organizationalUnits, ou)
	}
	sort.Slice(organizationalUnits, func(left, right int) bool {
		return aws.ToString(organizationalUnits[left].Id) < aws.ToString(organizationalUnits[right].Id)
	})
	return organizationalUnits, nil
}

func listOrganizationalUnitsForParentLegacy(
	ctx context.Context,
	client hierarchyListClient,
	parentID string,
) ([]types.OrganizationalUnit, error) {
	children, err := listChildren(ctx, client, parentID, types.ChildTypeOrganizationalUnit)
	if err != nil {
		return nil, err
	}
	organizationalUnits := make([]types.OrganizationalUnit, len(children))
	for index, child := range children {
		ou, err := getOU(ctx, client, aws.ToString(child.Id))
		if err != nil {
			return nil, fmt.Errorf("describe organizational unit %s: %w", aws.ToString(child.Id), err)
		}
		organizationalUnits[index] = *ou
	}
	return organizationalUnits, nil
}

func listChildren(
	ctx context.Context,
	client organizations.ListChildrenAPIClient,
	parentID string,
	childType types.ChildType,
) ([]types.Child, error) {
	input := &organizations.ListChildrenInput{ParentId: &parentID, ChildType: childType}
	paginator := organizations.NewListChildrenPaginator(client, input)

	var children []types.Child
	seen := make(map[string]bool)
	seenTokens := make(map[string]bool)
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		if err := rejectRepeatedToken(seenTokens, page.NextToken, "ListChildren"); err != nil {
			return nil, err
		}
		for _, child := range page.Children {
			childID := aws.ToString(child.Id)
			if childID == "" {
				return nil, fmt.Errorf("AWS returned a %s child without an ID for parent %s", childType, parentID)
			}
			if child.Type != childType {
				return nil, fmt.Errorf("AWS returned child %s with type %s, expected %s", childID, child.Type, childType)
			}
			if !seen[childID] {
				seen[childID] = true
				children = append(children, child)
			}
		}
	}
	sort.Slice(children, func(left, right int) bool {
		return aws.ToString(children[left].Id) < aws.ToString(children[right].Id)
	})
	return children, nil
}

func isAccessDeniedException(err error) bool {
	var apiErr smithy.APIError
	return errors.As(err, &apiErr) && strings.EqualFold(apiErr.ErrorCode(), "AccessDeniedException")
}

func getAccount(ctx context.Context, client accountDescriber, targetAccountID string) (*types.Account, error) {
	result, err := client.DescribeAccount(ctx, &organizations.DescribeAccountInput{AccountId: &targetAccountID})
	if err != nil {
		return nil, err
	}
	if result == nil || result.Account == nil {
		return nil, errors.New("AWS returned no account details")
	}
	if aws.ToString(result.Account.Id) != targetAccountID {
		return nil, fmt.Errorf("AWS returned account ID %q for requested account %s", aws.ToString(result.Account.Id), targetAccountID)
	}
	if aws.ToString(result.Account.Name) == "" {
		return nil, fmt.Errorf("AWS returned no name for account %s", targetAccountID)
	}
	return result.Account, nil
}

func getOU(ctx context.Context, client organizationalUnitDescriber, ouID string) (*types.OrganizationalUnit, error) {
	result, err := client.DescribeOrganizationalUnit(ctx, &organizations.DescribeOrganizationalUnitInput{OrganizationalUnitId: &ouID})
	if err != nil {
		return nil, err
	}
	if result == nil || result.OrganizationalUnit == nil {
		return nil, errors.New("AWS returned no organizational unit details")
	}
	if aws.ToString(result.OrganizationalUnit.Id) != ouID {
		return nil, fmt.Errorf(
			"AWS returned organizational unit ID %q for requested organizational unit %s",
			aws.ToString(result.OrganizationalUnit.Id),
			ouID,
		)
	}
	if aws.ToString(result.OrganizationalUnit.Name) == "" {
		return nil, fmt.Errorf("AWS returned no name for organizational unit %s", ouID)
	}
	return result.OrganizationalUnit, nil
}

// listSCPsForTarget lists all SCPs directly attached to targetID across every response page.
func listSCPsForTarget(ctx context.Context, client organizations.ListPoliciesForTargetAPIClient, targetID string) ([]types.PolicySummary, error) {
	input := &organizations.ListPoliciesForTargetInput{TargetId: &targetID, Filter: types.PolicyTypeServiceControlPolicy}
	paginator := organizations.NewListPoliciesForTargetPaginator(client, input)

	var policies []types.PolicySummary
	seenTokens := make(map[string]bool)
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		if err := rejectRepeatedToken(seenTokens, page.NextToken, "ListPoliciesForTarget"); err != nil {
			return nil, err
		}
		for _, policy := range page.Policies {
			if aws.ToString(policy.Id) == "" {
				return nil, fmt.Errorf("AWS returned an SCP without an ID for target %s", targetID)
			}
			if !validPolicyID(aws.ToString(policy.Id)) {
				return nil, fmt.Errorf("AWS returned SCP with invalid ID %q for target %s", aws.ToString(policy.Id), targetID)
			}
			if aws.ToString(policy.Name) == "" {
				return nil, fmt.Errorf("AWS returned SCP %s without a name for target %s", aws.ToString(policy.Id), targetID)
			}
			if policy.Type != types.PolicyTypeServiceControlPolicy {
				return nil, fmt.Errorf("AWS returned policy %s with type %s, expected SERVICE_CONTROL_POLICY", aws.ToString(policy.Id), policy.Type)
			}
			policies = append(policies, policy)
		}
	}
	return policies, nil
}

func getManagementAccountID(ctx context.Context, client organizationsClient) (string, error) {
	result, err := client.DescribeOrganization(ctx, &organizations.DescribeOrganizationInput{})
	if err != nil {
		return "", fmt.Errorf("describe organization: %w", err)
	}
	if result == nil || result.Organization == nil || aws.ToString(result.Organization.MasterAccountId) == "" {
		return "", errors.New("AWS returned no management account ID")
	}
	managementAccountID := aws.ToString(result.Organization.MasterAccountId)
	if err := validateStrictAccountID(managementAccountID); err != nil {
		return "", fmt.Errorf("AWS returned invalid management account ID %q: %w", managementAccountID, err)
	}
	return managementAccountID, nil
}

func getRootAndManagementAccount(
	ctx context.Context,
	client organizationsClient,
	includeManagementAccount bool,
) (string, string, string, error) {
	if !includeManagementAccount {
		rootID, rootName, err := getRoot(ctx, client)
		if err != nil {
			return "", "", "", fmt.Errorf("get organization root ID: %w", err)
		}
		return rootID, rootName, "", nil
	}
	type rootResult struct {
		id, name string
		err      error
	}
	type managementResult struct {
		id  string
		err error
	}
	requestCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	rootResults := make(chan rootResult, 1)
	managementResults := make(chan managementResult, 1)
	go func() {
		id, name, err := getRoot(requestCtx, client)
		rootResults <- rootResult{id: id, name: name, err: err}
	}()
	go func() {
		id, err := getManagementAccountID(requestCtx, client)
		managementResults <- managementResult{id: id, err: err}
	}()
	var root rootResult
	var management managementResult
	for rootResults != nil || managementResults != nil {
		select {
		case root = <-rootResults:
			rootResults = nil
			if root.err != nil {
				cancel()
				if managementResults != nil {
					<-managementResults
				}
				return "", "", "", fmt.Errorf("get organization root ID: %w", root.err)
			}
		case management = <-managementResults:
			managementResults = nil
			if management.err != nil {
				cancel()
				if rootResults != nil {
					<-rootResults
				}
				return "", "", "", management.err
			}
		}
	}
	return root.id, root.name, management.id, nil
}

// getRoot returns the organization's only root after consuming all response pages.
func getRoot(ctx context.Context, client organizations.ListRootsAPIClient) (string, string, error) {
	paginator := organizations.NewListRootsPaginator(client, &organizations.ListRootsInput{})

	rootNamesByID := make(map[string]string)
	seenTokens := make(map[string]bool)
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return "", "", err
		}
		if err := rejectRepeatedToken(seenTokens, page.NextToken, "ListRoots"); err != nil {
			return "", "", err
		}
		for _, root := range page.Roots {
			rootID := aws.ToString(root.Id)
			if err := validateRootID(rootID); err != nil {
				return "", "", fmt.Errorf("AWS returned invalid organization root ID %q: %w", rootID, err)
			}
			rootName := aws.ToString(root.Name)
			if existingName, found := rootNamesByID[rootID]; found && existingName != "" && rootName != "" && existingName != rootName {
				return "", "", fmt.Errorf("organization root %s has conflicting names %q and %q", rootID, existingName, rootName)
			}
			if _, found := rootNamesByID[rootID]; !found || rootNamesByID[rootID] == "" {
				rootNamesByID[rootID] = rootName
			}
		}
	}
	if len(rootNamesByID) != 1 {
		return "", "", fmt.Errorf("expected exactly one organization root, got %d", len(rootNamesByID))
	}
	for rootID, rootName := range rootNamesByID {
		return rootID, rootName, nil
	}
	return "", "", errors.New("no roots found in the organization")
}

// listParents consumes every response page for the target entity.
func listParents(ctx context.Context, client organizations.ListParentsAPIClient, entityID string) ([]types.Parent, error) {
	paginator := organizations.NewListParentsPaginator(client, &organizations.ListParentsInput{ChildId: &entityID})

	var parents []types.Parent
	seen := make(map[string]bool)
	seenTokens := make(map[string]bool)
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		if err := rejectRepeatedToken(seenTokens, page.NextToken, "ListParents"); err != nil {
			return nil, err
		}
		for _, parent := range page.Parents {
			parentID := aws.ToString(parent.Id)
			if parentID == "" {
				return nil, fmt.Errorf("AWS returned a parent without an ID for %s", entityID)
			}
			switch parent.Type {
			case types.ParentTypeRoot:
				if err := validateRootID(parentID); err != nil {
					return nil, fmt.Errorf("AWS returned root parent with invalid ID %s for %s: %w", parentID, entityID, err)
				}
			case types.ParentTypeOrganizationalUnit:
				if err := validateOrganizationalUnitID(parentID); err != nil {
					return nil, fmt.Errorf("AWS returned organizational unit parent with invalid ID %s for %s: %w", parentID, entityID, err)
				}
			default:
				return nil, fmt.Errorf("AWS returned parent %s with invalid type %s for %s", parentID, parent.Type, entityID)
			}
			if !seen[parentID] {
				seen[parentID] = true
				parents = append(parents, parent)
			}
		}
	}
	return parents, nil
}

// listSCPsForPath lists SCP summary names and attachment provenance along one known hierarchy path.
func listSCPsForPath(
	ctx context.Context,
	client organizationsClient,
	path []string,
	cache *organizationCache,
) ([]string, []scpAttachment, error) {
	namesByID := make(map[string]string)
	legacyNames := make(map[string]bool)
	seenAttachments := make(map[[2]string]bool)
	pathIndexes := make(map[string]int, len(path))
	attachments := make([]scpAttachment, 0)
	for index, entityID := range path {
		pathIndexes[entityID] = index
	}
	targetID := path[len(path)-1]
	for _, entityID := range path {
		policies, err := cache.policiesForTarget(ctx, client, entityID)
		if err != nil {
			return nil, nil, fmt.Errorf("list SCPs for %s: %w", entityID, err)
		}
		for _, policy := range policies {
			policyID := aws.ToString(policy.Id)
			policyName := aws.ToString(policy.Name)
			if existingName, found := namesByID[policyID]; found && existingName != policyName {
				return nil, nil, fmt.Errorf("SCP %s has conflicting names %q and %q", policyID, existingName, policyName)
			}
			if _, found := namesByID[policyID]; !found {
				namesByID[policyID] = policyName
			}
			legacyNames[policyName] = true

			attachmentKey := [2]string{policyID, entityID}
			if seenAttachments[attachmentKey] {
				continue
			}
			seenAttachments[attachmentKey] = true
			attachments = append(attachments, scpAttachment{
				PolicyID:   policyID,
				PolicyName: policyName,
				AttachedTo: scpAttachmentTarget{
					Type: entityType(entityID),
					ID:   entityID,
					Name: cache.entityName(entityID),
				},
				Inherited: entityID != targetID,
			})
		}
	}
	scpNames := make([]string, 0, len(legacyNames))
	for policyName := range legacyNames {
		scpNames = append(scpNames, policyName)
	}
	sort.Strings(scpNames)
	sort.Slice(attachments, func(left, right int) bool {
		if attachments[left].PolicyName != attachments[right].PolicyName {
			return attachments[left].PolicyName < attachments[right].PolicyName
		}
		if attachments[left].PolicyID != attachments[right].PolicyID {
			return attachments[left].PolicyID < attachments[right].PolicyID
		}
		leftPathIndex := pathIndexes[attachments[left].AttachedTo.ID]
		rightPathIndex := pathIndexes[attachments[right].AttachedTo.ID]
		if leftPathIndex != rightPathIndex {
			return leftPathIndex < rightPathIndex
		}
		return attachments[left].AttachedTo.ID < attachments[right].AttachedTo.ID
	})
	return scpNames, attachments, nil
}

func entityType(entityID string) string {
	switch {
	case strings.HasPrefix(entityID, "r-"):
		return rootEntityType
	case strings.HasPrefix(entityID, "ou-"):
		return organizationalUnitEntityType
	default:
		return accountEntityType
	}
}

func validateAccountID(value string) error {
	if strings.EqualFold(value, "all") {
		return nil
	}
	return validateStrictAccountID(value)
}

func selectedAWSTarget(
	targetAccountID string,
	accountIDSet bool,
	targetOrganizationalUnitID string,
	organizationalUnitIDSet bool,
) (string, error) {
	if accountIDSet && organizationalUnitIDSet {
		return "", newInvalidInvocationError(errors.New("--account-id and --ou-id are mutually exclusive"))
	}
	if organizationalUnitIDSet {
		if err := validateOrganizationalUnitID(targetOrganizationalUnitID); err != nil {
			return "", newInvalidInvocationError(fmt.Errorf("invalid --ou-id %q: %w", targetOrganizationalUnitID, err))
		}
		return targetOrganizationalUnitID, nil
	}
	if accountIDSet {
		if err := validateAccountID(targetAccountID); err != nil {
			return "", newInvalidInvocationError(fmt.Errorf("invalid --account-id %q: must be \"all\" or exactly 12 decimal digits", targetAccountID))
		}
		return targetAccountID, nil
	}
	return "", newInvalidInvocationError(errors.New("invalid --account-id \"\": must be \"all\" or exactly 12 decimal digits"))
}

func validateRootID(value string) error {
	if !strings.HasPrefix(value, "r-") || len(value) < 6 || len(value) > 34 {
		return errors.New("must match r-<4-32 lowercase letters or digits>")
	}
	for _, character := range value[2:] {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') {
			return errors.New("must match r-<4-32 lowercase letters or digits>")
		}
	}
	return nil
}

func validateOrganizationalUnitID(value string) error {
	parts := strings.Split(value, "-")
	if len(parts) != 3 || parts[0] != "ou" || len(parts[1]) < 4 || len(parts[1]) > 32 || len(parts[2]) < 8 || len(parts[2]) > 32 {
		return errors.New("must match ou-<4-32 lowercase letters or digits>-<8-32 lowercase letters or digits>")
	}
	for _, part := range parts[1:] {
		for _, character := range part {
			if (character < 'a' || character > 'z') && (character < '0' || character > '9') {
				return errors.New("must match ou-<4-32 lowercase letters or digits>-<8-32 lowercase letters or digits>")
			}
		}
	}
	return nil
}

func validateOrganizationalUnitForRoot(organizationalUnitID, rootID string) error {
	if err := validateOrganizationalUnitID(organizationalUnitID); err != nil {
		return fmt.Errorf("invalid organizational unit ID %q: %w", organizationalUnitID, err)
	}
	if err := validateRootID(rootID); err != nil {
		return fmt.Errorf("invalid root ID %q: %w", rootID, err)
	}
	rootComponent := strings.TrimPrefix(rootID, "r-")
	if !strings.HasPrefix(organizationalUnitID, "ou-"+rootComponent+"-") {
		return fmt.Errorf("organizational unit %s does not belong to root %s", organizationalUnitID, rootID)
	}
	return nil
}

func validateStrictAccountID(value string) error {
	if len(value) != 12 {
		return errors.New("account ID must be exactly 12 digits")
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return errors.New("account ID must be exactly 12 digits")
		}
	}
	return nil
}

func rejectRepeatedToken(seen map[string]bool, token *string, operation string) error {
	value := aws.ToString(token)
	if value == "" {
		return nil
	}
	if seen[value] {
		return fmt.Errorf("%s returned repeated pagination token %q", operation, value)
	}
	seen[value] = true
	return nil
}

func validPolicyID(policyID string) bool {
	if !strings.HasPrefix(policyID, "p-") || len(policyID) < 10 || len(policyID) > 130 {
		return false
	}
	for _, character := range policyID[2:] {
		if (character < '0' || character > '9') &&
			(character < 'A' || character > 'Z') &&
			(character < 'a' || character > 'z') &&
			character != '_' {
			return false
		}
	}
	return true
}
