package cmd

import (
	"bytes"
	"context"
	encodingjson "encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"reflect"
	"strings"
	"sync"
	"testing"
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
	"github.com/spf13/cobra"
)

type fakeSTSClient struct {
	getCallerIdentityFn func(context.Context, *sts.GetCallerIdentityInput) (*sts.GetCallerIdentityOutput, error)
}

func (fake *fakeSTSClient) GetCallerIdentity(
	ctx context.Context,
	input *sts.GetCallerIdentityInput,
	_ ...func(*sts.Options),
) (*sts.GetCallerIdentityOutput, error) {
	return fake.getCallerIdentityFn(ctx, input)
}

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

func TestOrganizationJSONNodePreservesSCPsFieldName(t *testing.T) {
	t.Parallel()

	data, err := encodingjson.Marshal(organizationJSONNode{Type: "account", ID: "123456789012", SCPs: []string{"DenyS3"}})
	if err != nil {
		t.Fatalf("encode account: %v", err)
	}
	var fields map[string]encodingjson.RawMessage
	if err := encodingjson.Unmarshal(data, &fields); err != nil {
		t.Fatalf("decode account fields: %v", err)
	}
	if _, found := fields["scps"]; !found {
		t.Fatalf("JSON account does not contain compatibility field %q: %s", "scps", data)
	}
}

func TestOrganizationJSONNodeSchemaPreservesLegacySCPsAndAddsAttachments(t *testing.T) {
	t.Parallel()

	node := organizationJSONNode{
		Type: "account",
		ID:   "123456789012",
		Name: "Application",
		SCPs: []string{"DenyS3"},
		SCPAttachments: []scpAttachment{{
			PolicyID:   "p-deny0001",
			PolicyName: "DenyS3",
			AttachedTo: scpAttachmentTarget{
				Type: "account",
				ID:   "123456789012",
				Name: "Application",
			},
			Inherited: false,
		}},
	}

	encoded, err := encodingjson.Marshal(node)
	if err != nil {
		t.Fatalf("encode account node: %v", err)
	}
	want := `{"type":"account","id":"123456789012","name":"Application","scps":["DenyS3"],` +
		`"scp_attachments":[{"policy_id":"p-deny0001","policy_name":"DenyS3",` +
		`"attached_to":{"type":"account","id":"123456789012","name":"Application"},"inherited":false}]}`
	if string(encoded) != want {
		t.Fatalf("got JSON\n%s\nwant\n%s", encoded, want)
	}

	managementNode, err := encodingjson.Marshal(organizationJSONNode{
		Type:              "account",
		ID:                "111111111111",
		Name:              "Management",
		ManagementAccount: true,
	})
	if err != nil {
		t.Fatalf("encode management account node: %v", err)
	}
	managementWant := `{"type":"account","id":"111111111111","name":"Management","management_account":true}`
	if string(managementNode) != managementWant {
		t.Fatalf("got management JSON\n%s\nwant\n%s", managementNode, managementWant)
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
		"--timeout",
		"--max-retries",
		"does not prompt for input or start an",
		"aws sso login --profile=<name>",
		"direct attachments to an account",
		"root/OU in its ancestor path",
		"does not retrieve policy documents",
		"SCP Allow/Deny",
		"IAM policies",
		"resource policies",
		"permission boundaries",
		"session policies",
		"effective identity permissions",
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

func TestRootHelpSurfacesAWSAndAuthStatusExamples(t *testing.T) {
	// Help rendering mutates the command's output writer, so this test is
	// intentionally not parallel (matches cmd/help_test.go conventions).
	var help bytes.Buffer
	rootCmd.SetOut(&help)
	defer rootCmd.SetOut(nil)
	if err := rootCmd.Help(); err != nil {
		t.Fatalf("render root help: %v", err)
	}
	output := help.String()

	for _, expected := range []string{
		"Inspect cloud organization policies from one CLI",
		"policy-scout aws auth status",
		"policy-scout aws auth status --output-format text",
		"policy-scout aws --account-id 123456789012",
		"policy-scout aws --account-id all --output-format text",
	} {
		if !strings.Contains(output, expected) {
			t.Errorf("root help does not surface %q:\n%s", expected, output)
		}
	}

	for _, hidden := range []string{"multi-cloud", "gcp", "azure"} {
		if strings.Contains(output, hidden) {
			t.Errorf("root help unexpectedly advertises %q:\n%s", hidden, output)
		}
	}
}

func TestAddSSORemediation(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		err      error
		profile  string
		wantHint bool
	}{
		"typed expired token": {
			err: &ssocreds.InvalidTokenError{}, profile: "engineering", wantHint: true,
		},
		"modern expired session cannot refresh": {
			err:     errors.New("refresh cached SSO token failed, cached SSO token is expired, or not present, and cannot be refreshed"),
			profile: "team dev", wantHint: true,
		},
		"missing SSO cache": {
			err: fmt.Errorf("failed to read cached SSO token file: %w", fs.ErrNotExist), profile: "default", wantHint: true,
		},
		"typed SSO unauthorized": {
			err: &ssotypes.UnauthorizedException{}, profile: "dev's profile", wantHint: true,
		},
		"typed invalid refresh grant": {
			err: &ssooidctypes.InvalidGrantException{}, profile: "-prod", wantHint: true,
		},
		"refresh network failure": {
			err: errors.New("refresh cached SSO token failed, unable to refresh SSO token: connection reset"), profile: "dev",
		},
		"cache permission failure": {
			err: fmt.Errorf("failed to read cached SSO token file: %w", fs.ErrPermission), profile: "dev",
		},
		"cache parse failure": {
			err: errors.New("failed to parse cached SSO token file: invalid character"), profile: "dev",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			original := newCredentialsError("RetrieveCredentials", test.err)
			got := addSSORemediation(original, test.profile)
			if !errors.Is(got, original) {
				t.Fatal("remediation must preserve the original error in its error chain")
			}
			var remediation *ssoRemediationError
			if errors.As(got, &remediation) != test.wantHint {
				t.Fatalf("unexpected SSO remediation wrapper: %v", got)
			}
		})
	}
}

func TestResolvedAWSProfile(t *testing.T) {
	t.Run("explicit profile takes precedence", func(t *testing.T) {
		t.Setenv("AWS_PROFILE", "environment")
		t.Setenv("AWS_DEFAULT_PROFILE", "fallback")
		if got := resolvedAWSProfile("flag"); got != "flag" {
			t.Fatalf("resolved profile is %q, want flag", got)
		}
	})

	t.Run("AWS_PROFILE takes environment precedence", func(t *testing.T) {
		t.Setenv("AWS_PROFILE", "environment")
		t.Setenv("AWS_DEFAULT_PROFILE", "fallback")
		if got := resolvedAWSProfile(""); got != "environment" {
			t.Fatalf("resolved profile is %q, want environment", got)
		}
	})

	t.Run("AWS_DEFAULT_PROFILE and default are fallbacks", func(t *testing.T) {
		t.Setenv("AWS_PROFILE", "")
		t.Setenv("AWS_DEFAULT_PROFILE", "fallback")
		if got := resolvedAWSProfile(""); got != "fallback" {
			t.Fatalf("resolved profile is %q, want fallback", got)
		}
		t.Setenv("AWS_DEFAULT_PROFILE", "")
		if got := resolvedAWSProfile(""); got != "default" {
			t.Fatalf("resolved profile is %q, want default", got)
		}
	})
}

func TestAWSExecutionControlFlags(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		args    []string
		want    awsExecutionControls
		wantErr string
	}{
		"omitted preserves SDK defaults": {},
		"timeout": {
			args: []string{"--timeout", "30s"},
			want: awsExecutionControls{timeout: 30 * time.Second, timeoutSet: true},
		},
		"timeout must not be zero": {
			args:    []string{"--timeout", "0s"},
			wantErr: "invalid --timeout",
		},
		"timeout must not be negative": {
			args:    []string{"--timeout", "-1s"},
			wantErr: "invalid --timeout",
		},
		"timeout must be a duration": {
			args:    []string{"--timeout", "soon"},
			wantErr: "invalid argument",
		},
		"zero retries": {
			args: []string{"--max-retries", "0"},
			want: awsExecutionControls{maxRetries: 0, maxRetriesSet: true},
		},
		"three retries": {
			args: []string{"--max-retries", "3"},
			want: awsExecutionControls{maxRetries: 3, maxRetriesSet: true},
		},
		"retries must not be negative": {
			args:    []string{"--max-retries", "-1"},
			wantErr: "invalid --max-retries",
		},
		"retries have a safe upper bound": {
			args:    []string{"--max-retries", "11"},
			wantErr: "invalid --max-retries",
		},
		"retries must be an integer": {
			args:    []string{"--max-retries", "many"},
			wantErr: "invalid argument",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			command := &cobra.Command{Use: "test"}
			addAWSExecutionFlags(command)
			err := command.ParseFlags(test.args)
			var got awsExecutionControls
			if err == nil {
				got, err = awsExecutionControlsFromCommand(command)
			}
			if test.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantErr) {
					t.Fatalf("got error %v, want one containing %q", err, test.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("parse execution controls: %v", err)
			}
			if got != test.want {
				t.Fatalf("got controls %+v, want %+v", got, test.want)
			}
		})
	}
}

func TestAWSExecutionControlsConfigureContextAndSDKRetries(t *testing.T) {
	t.Parallel()

	parent := context.Background()
	omitted := awsExecutionControls{}
	ctx, cancel := omitted.context(parent)
	defer cancel()
	if ctx != parent {
		t.Fatal("omitted timeout must preserve the parent context")
	}
	if options := omitted.configLoadOptions(); options != nil {
		t.Fatalf("omitted retry flag produced %d AWS configuration options", len(options))
	}

	controls := awsExecutionControls{
		timeout:       30 * time.Second,
		timeoutSet:    true,
		maxRetries:    3,
		maxRetriesSet: true,
	}
	ctx, cancel = controls.context(parent)
	defer cancel()
	deadline, ok := ctx.Deadline()
	if !ok {
		t.Fatal("configured timeout did not create a context deadline")
	}
	if remaining := time.Until(deadline); remaining <= 29*time.Second || remaining > 30*time.Second {
		t.Fatalf("context deadline has unexpected remaining duration %s", remaining)
	}

	options := controls.configLoadOptions()
	if len(options) != 1 {
		t.Fatalf("got %d AWS configuration options, want 1", len(options))
	}
	var loadOptions config.LoadOptions
	if err := options[0](&loadOptions); err != nil {
		t.Fatalf("apply AWS retry configuration: %v", err)
	}
	if loadOptions.RetryMaxAttempts != 4 {
		t.Fatalf("got %d maximum attempts, want 4", loadOptions.RetryMaxAttempts)
	}
}

func TestAWSExecutionControlsExplainStructuredErrors(t *testing.T) {
	t.Parallel()

	timeoutControls := awsExecutionControls{timeout: 30 * time.Second, timeoutSet: true}
	timeoutError := timeoutControls.explainError(fmt.Errorf("list roots: %w", context.DeadlineExceeded))
	if !errors.Is(timeoutError, context.DeadlineExceeded) || !strings.Contains(timeoutError.Error(), "exceeded --timeout 30s") {
		t.Fatalf("unexpected timeout error: %v", timeoutError)
	}
	timeoutDiagnostic := classifyError(timeoutError)
	if timeoutDiagnostic.Code != errorCodeTransient || timeoutDiagnostic.Message != "AWS execution exceeded --timeout 30s." {
		t.Fatalf("unexpected timeout diagnostic: %#v", timeoutDiagnostic)
	}

	cancellationError := (awsExecutionControls{}).explainError(fmt.Errorf("list roots: %w", context.Canceled))
	if !errors.Is(cancellationError, context.Canceled) || classifyError(cancellationError).Message != "Policy Scout execution was canceled." {
		t.Fatalf("unexpected cancellation diagnostic: %v", cancellationError)
	}

	retryControls := awsExecutionControls{maxRetries: 3, maxRetriesSet: true}
	retryError := retryControls.explainError(&awsretry.MaxAttemptsError{Attempt: 4, Err: errors.New("throttled")})
	if !strings.Contains(retryError.Error(), "--max-retries 3 (4 total attempts)") {
		t.Fatalf("unexpected retry error: %v", retryError)
	}
	retryDiagnostic := classifyError(retryError)
	if retryDiagnostic.Code != errorCodeTransient || retryDiagnostic.Message != "AWS request exhausted --max-retries 3 (4 total attempts)." {
		t.Fatalf("unexpected retry diagnostic: %#v", retryDiagnostic)
	}
}

func TestAWSAuthStatusExecutionControlFlagsAndValidation(t *testing.T) {
	for _, name := range []string{"timeout", "max-retries"} {
		if authStatusCmd.Flags().Lookup(name) == nil {
			t.Errorf("auth status flag --%s is not registered", name)
		}
	}

	var help bytes.Buffer
	authStatusCmd.SetOut(&help)
	t.Cleanup(func() { authStatusCmd.SetOut(nil) })
	if err := authStatusCmd.Help(); err != nil {
		t.Fatalf("render auth status help: %v", err)
	}
	for _, expected := range []string{
		"--timeout",
		"--max-retries",
		"configuration and credential loading",
		"policy-scout aws auth status --timeout 30s --max-retries 3",
	} {
		if !strings.Contains(help.String(), expected) {
			t.Errorf("auth status help does not contain %q:\n%s", expected, help.String())
		}
	}

	for name, controls := range map[string]awsExecutionControls{
		"zero timeout":     {timeoutSet: true},
		"negative retries": {maxRetries: -1, maxRetriesSet: true},
		"too many retries": {maxRetries: maxAllowedRetries + 1, maxRetriesSet: true},
	} {
		t.Run(name, func(t *testing.T) {
			if err := controls.validate(); err == nil {
				t.Fatal("expected execution controls to be rejected")
			}
		})
	}
}

func TestAWSAuthStatusDeadlineCoversConfigCredentialsAndAPIs(t *testing.T) {
	t.Parallel()

	deadline := time.Now().Add(time.Minute)
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	assertDeadline := func(stage string, got context.Context) {
		t.Helper()
		gotDeadline, ok := got.Deadline()
		if !ok || !gotDeadline.Equal(deadline) {
			t.Fatalf("%s received deadline %s (present: %t), want %s", stage, gotDeadline, ok, deadline)
		}
	}

	loader := func(got context.Context, _ ...func(*config.LoadOptions) error) (aws.Config, error) {
		assertDeadline("configuration loader", got)
		return aws.Config{Credentials: aws.CredentialsProviderFunc(func(got context.Context) (aws.Credentials, error) {
			assertDeadline("credential provider", got)
			return aws.Credentials{Source: "test"}, nil
		})}, nil
	}
	clients := func(aws.Config) (stsClient, authStatusOrganizationsClient) {
		return &fakeSTSClient{getCallerIdentityFn: func(got context.Context, _ *sts.GetCallerIdentityInput) (*sts.GetCallerIdentityOutput, error) {
				assertDeadline("STS", got)
				return &sts.GetCallerIdentityOutput{
					Account: aws.String("123456789012"),
					Arn:     aws.String("arn:aws:iam::123456789012:user/test"),
					UserId:  aws.String("AIDATEST"),
				}, nil
			}}, &fakeOrganizationsClient{describeOrganizationFn: func(got context.Context, _ *organizations.DescribeOrganizationInput) (*organizations.DescribeOrganizationOutput, error) {
				assertDeadline("Organizations", got)
				return &organizations.DescribeOrganizationOutput{Organization: &types.Organization{
					Id: aws.String("o-example"), MasterAccountId: aws.String("123456789012"),
				}}, nil
			}}
	}

	if err := displayAWSAuthStatusWithDependencies(ctx, &bytes.Buffer{}, "", loader, clients); err != nil {
		t.Fatalf("display AWS authentication status: %v", err)
	}
}

func TestAWSAuthStatusTimeoutAndCancellation(t *testing.T) {
	t.Parallel()

	t.Run("timeout during credential retrieval", func(t *testing.T) {
		t.Parallel()
		controls := awsExecutionControls{timeout: 10 * time.Millisecond, timeoutSet: true}
		ctx, cancel := controls.context(context.Background())
		defer cancel()
		loader := func(context.Context, ...func(*config.LoadOptions) error) (aws.Config, error) {
			return aws.Config{Credentials: aws.CredentialsProviderFunc(func(ctx context.Context) (aws.Credentials, error) {
				<-ctx.Done()
				return aws.Credentials{}, ctx.Err()
			})}, nil
		}

		err := displayAWSAuthStatusWithDependencies(ctx, &bytes.Buffer{}, "", loader, nil)
		err = controls.explainError(err)
		if !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "exceeded --timeout 10ms") {
			t.Fatalf("unexpected timeout error: %v", err)
		}
	})

	t.Run("cancellation during Organizations call", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := getAWSAuthStatus(
			ctx,
			aws.Credentials{Source: "test"},
			&fakeSTSClient{getCallerIdentityFn: func(context.Context, *sts.GetCallerIdentityInput) (*sts.GetCallerIdentityOutput, error) {
				return &sts.GetCallerIdentityOutput{
					Account: aws.String("123456789012"), Arn: aws.String("arn:test"), UserId: aws.String("user"),
				}, nil
			}},
			&fakeOrganizationsClient{describeOrganizationFn: func(got context.Context, _ *organizations.DescribeOrganizationInput) (*organizations.DescribeOrganizationOutput, error) {
				return nil, got.Err()
			}},
		)
		err = (awsExecutionControls{}).explainError(err)
		if !errors.Is(err, context.Canceled) || classifyError(err).Message != "Policy Scout execution was canceled." {
			t.Fatalf("unexpected cancellation error: %v", err)
		}
	})
}

func TestAWSAuthStatusAppliesRetryOptionAndExplainsExhaustion(t *testing.T) {
	t.Parallel()

	controls := awsExecutionControls{maxRetries: 3, maxRetriesSet: true}
	loader := func(_ context.Context, options ...func(*config.LoadOptions) error) (aws.Config, error) {
		var loadOptions config.LoadOptions
		for _, option := range options {
			if err := option(&loadOptions); err != nil {
				return aws.Config{}, err
			}
		}
		if loadOptions.RetryMaxAttempts != 4 {
			t.Fatalf("auth status configured %d maximum attempts, want 4", loadOptions.RetryMaxAttempts)
		}
		return aws.Config{Credentials: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
			return aws.Credentials{Source: "test"}, nil
		})}, nil
	}
	clients := func(aws.Config) (stsClient, authStatusOrganizationsClient) {
		return &fakeSTSClient{getCallerIdentityFn: func(context.Context, *sts.GetCallerIdentityInput) (*sts.GetCallerIdentityOutput, error) {
				return &sts.GetCallerIdentityOutput{
					Account: aws.String("123456789012"), Arn: aws.String("arn:test"), UserId: aws.String("user"),
				}, nil
			}}, &fakeOrganizationsClient{describeOrganizationFn: func(context.Context, *organizations.DescribeOrganizationInput) (*organizations.DescribeOrganizationOutput, error) {
				return nil, &awsretry.MaxAttemptsError{Attempt: 4, Err: errors.New("throttled")}
			}}
	}

	err := displayAWSAuthStatusWithDependencies(
		context.Background(), &bytes.Buffer{}, "", loader, clients, controls.configLoadOptions()...,
	)
	err = controls.explainError(err)
	if !strings.Contains(err.Error(), "--max-retries 3 (4 total attempts)") {
		t.Fatalf("unexpected retry exhaustion error: %v", err)
	}
}

func TestAWSCallsPropagateContextDeadline(t *testing.T) {
	t.Parallel()

	deadline := time.Now().Add(time.Minute)
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()

	assertDeadline := func(got context.Context) {
		t.Helper()
		gotDeadline, ok := got.Deadline()
		if !ok || !gotDeadline.Equal(deadline) {
			t.Fatalf("AWS call received deadline %s (present: %t), want %s", gotDeadline, ok, deadline)
		}
	}

	client := &fakeOrganizationsClient{
		listChildrenFn: func(got context.Context, _ *organizations.ListChildrenInput) (*organizations.ListChildrenOutput, error) {
			assertDeadline(got)
			return &organizations.ListChildrenOutput{}, nil
		},
		listParentsFn: func(got context.Context, _ *organizations.ListParentsInput) (*organizations.ListParentsOutput, error) {
			assertDeadline(got)
			return &organizations.ListParentsOutput{Parents: []types.Parent{{Id: aws.String("r-root"), Type: types.ParentTypeRoot}}}, nil
		},
		listPoliciesForTargetFn: func(got context.Context, _ *organizations.ListPoliciesForTargetInput) (*organizations.ListPoliciesForTargetOutput, error) {
			assertDeadline(got)
			return &organizations.ListPoliciesForTargetOutput{}, nil
		},
		listRootsFn: func(got context.Context, _ *organizations.ListRootsInput) (*organizations.ListRootsOutput, error) {
			assertDeadline(got)
			return &organizations.ListRootsOutput{Roots: []types.Root{{Id: aws.String("r-root")}}}, nil
		},
		describeAccountFn: func(got context.Context, input *organizations.DescribeAccountInput) (*organizations.DescribeAccountOutput, error) {
			assertDeadline(got)
			return &organizations.DescribeAccountOutput{Account: &types.Account{Id: input.AccountId, Name: aws.String("Account")}}, nil
		},
		describeOrganizationalUnit: func(got context.Context, input *organizations.DescribeOrganizationalUnitInput) (*organizations.DescribeOrganizationalUnitOutput, error) {
			assertDeadline(got)
			return &organizations.DescribeOrganizationalUnitOutput{OrganizationalUnit: &types.OrganizationalUnit{
				Id: input.OrganizationalUnitId, Name: aws.String("OU"),
			}}, nil
		},
		describeOrganizationFn: func(got context.Context, _ *organizations.DescribeOrganizationInput) (*organizations.DescribeOrganizationOutput, error) {
			assertDeadline(got)
			return &organizations.DescribeOrganizationOutput{Organization: &types.Organization{MasterAccountId: aws.String("999999999999")}}, nil
		},
	}

	if _, err := listChildren(ctx, client, "r-root", types.ChildTypeAccount); err != nil {
		t.Fatalf("list children: %v", err)
	}
	if _, err := listParents(ctx, client, "123456789012"); err != nil {
		t.Fatalf("list parents: %v", err)
	}
	if _, err := listSCPsForTarget(ctx, client, "123456789012"); err != nil {
		t.Fatalf("list SCPs: %v", err)
	}
	if _, _, err := getRoot(ctx, client); err != nil {
		t.Fatalf("get root: %v", err)
	}
	if _, err := getAccount(ctx, client, "123456789012"); err != nil {
		t.Fatalf("get account: %v", err)
	}
	if _, err := getOU(ctx, client, "ou-root-12345678"); err != nil {
		t.Fatalf("get OU: %v", err)
	}
	if _, err := getManagementAccountID(ctx, client); err != nil {
		t.Fatalf("get management account: %v", err)
	}
}

func TestAWSCancellationReachesPaginatorCalls(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	client := &fakeOrganizationsClient{
		listChildrenFn: func(got context.Context, _ *organizations.ListChildrenInput) (*organizations.ListChildrenOutput, error) {
			if !errors.Is(got.Err(), context.Canceled) {
				t.Fatalf("AWS call context error is %v, want context canceled", got.Err())
			}
			return nil, got.Err()
		},
	}
	_, err := listChildren(ctx, client, "r-root", types.ChildTypeAccount)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("got error %v, want context canceled", err)
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

func TestLoadAWSConfigCombinesProfileAndRetryOptions(t *testing.T) {
	t.Parallel()

	loader := func(_ context.Context, options ...func(*config.LoadOptions) error) (aws.Config, error) {
		if len(options) != 2 {
			t.Fatalf("got %d load options, want 2", len(options))
		}
		loadOptions := config.LoadOptions{}
		for _, option := range options {
			if err := option(&loadOptions); err != nil {
				t.Fatalf("apply load option: %v", err)
			}
		}
		if loadOptions.SharedConfigProfile != "security-audit" || loadOptions.RetryMaxAttempts != 4 {
			t.Fatalf("unexpected load options: profile %q, retry attempts %d", loadOptions.SharedConfigProfile, loadOptions.RetryMaxAttempts)
		}
		return aws.Config{}, nil
	}

	controls := awsExecutionControls{maxRetries: 3, maxRetriesSet: true}
	if _, err := loadAWSConfig(
		context.Background(), "security-audit", loader, controls.configLoadOptions()...,
	); err != nil {
		t.Fatalf("load AWS config: %v", err)
	}
}

func TestGetAWSAuthStatus(t *testing.T) {
	t.Parallel()

	expires := time.Date(2026, time.July, 18, 18, 42, 0, 0, time.FixedZone("test", 2*60*60))
	stsClient := &fakeSTSClient{
		getCallerIdentityFn: func(context.Context, *sts.GetCallerIdentityInput) (*sts.GetCallerIdentityOutput, error) {
			return &sts.GetCallerIdentityOutput{
				Account: aws.String("123456789012"),
				Arn:     aws.String("arn:aws:sts::123456789012:assumed-role/AuditRole/test"),
				UserId:  aws.String("AROATEST:test"),
			}, nil
		},
	}
	organizationsClient := &fakeOrganizationsClient{
		describeOrganizationFn: func(context.Context, *organizations.DescribeOrganizationInput) (*organizations.DescribeOrganizationOutput, error) {
			return &organizations.DescribeOrganizationOutput{Organization: &types.Organization{
				Id:              aws.String("o-exampleorgid"),
				MasterAccountId: aws.String("123456789012"),
			}}, nil
		},
	}

	status, err := getAWSAuthStatus(context.Background(), aws.Credentials{
		Source:    "SharedConfigCredentials: /home/test/.aws/credentials",
		CanExpire: true,
		Expires:   expires,
	}, stsClient, organizationsClient)
	if err != nil {
		t.Fatalf("get authentication status: %v", err)
	}
	if !status.OK || !status.Authenticated || !status.Organizations.Accessible {
		t.Fatalf("unexpected unsuccessful status: %#v", status)
	}
	if status.Identity.AccountID != "123456789012" || status.Organizations.OrganizationID != "o-exampleorgid" {
		t.Fatalf("unexpected authentication status: %#v", status)
	}
	if status.Credentials.ExpiresAt != "2026-07-18T16:42:00Z" {
		t.Fatalf("expiration is %q, want UTC RFC3339", status.Credentials.ExpiresAt)
	}
}

func TestGetAWSAuthStatusReportsOrganizationsDenial(t *testing.T) {
	t.Parallel()

	stsClient := &fakeSTSClient{
		getCallerIdentityFn: func(context.Context, *sts.GetCallerIdentityInput) (*sts.GetCallerIdentityOutput, error) {
			return &sts.GetCallerIdentityOutput{
				Account: aws.String("123456789012"),
				Arn:     aws.String("arn:aws:iam::123456789012:user/test"),
				UserId:  aws.String("AIDATEST"),
			}, nil
		},
	}
	organizationsClient := &fakeOrganizationsClient{
		describeOrganizationFn: func(context.Context, *organizations.DescribeOrganizationInput) (*organizations.DescribeOrganizationOutput, error) {
			return nil, errors.New("AccessDeniedException")
		},
	}

	status, err := getAWSAuthStatus(
		context.Background(),
		aws.Credentials{Source: "EnvConfigCredentials"},
		stsClient,
		organizationsClient,
	)
	if err != nil {
		t.Fatalf("get authentication status: %v", err)
	}
	if status.OK || !status.Authenticated || status.Organizations.Accessible {
		t.Fatalf("unexpected status: %#v", status)
	}
	if status.Organizations.Error != "AccessDeniedException" {
		t.Fatalf("Organizations error is %q", status.Organizations.Error)
	}
}

func TestWriteAWSAuthStatusJSON(t *testing.T) {
	t.Parallel()

	status := awsAuthStatus{
		OK:            true,
		Authenticated: true,
		Identity:      awsAuthIdentity{AccountID: "123456789012", ARN: "arn:example", UserID: "user"},
		Credentials:   awsAuthCredentials{Source: "EnvConfigCredentials"},
		Organizations: awsOrganizationsAuthStatus{Accessible: true, OrganizationID: "o-example"},
	}
	var output bytes.Buffer
	if err := writeAWSAuthStatus(&output, status, json); err != nil {
		t.Fatalf("write JSON authentication status: %v", err)
	}

	var decoded awsAuthStatus
	if err := encodingjson.Unmarshal(output.Bytes(), &decoded); err != nil {
		t.Fatalf("decode authentication status: %v", err)
	}
	if !decoded.OK || decoded.Identity.AccountID != "123456789012" {
		t.Fatalf("unexpected JSON authentication status: %#v", decoded)
	}
}

func TestListChildrenPaginatesAndSortsByID(t *testing.T) {
	t.Parallel()

	client := &fakeOrganizationsClient{
		listChildrenFn: func(_ context.Context, input *organizations.ListChildrenInput) (*organizations.ListChildrenOutput, error) {
			if input.NextToken == nil {
				return &organizations.ListChildrenOutput{
					Children: []types.Child{
						{Id: aws.String("333333333333"), Type: types.ChildTypeAccount},
						{Id: aws.String("111111111111"), Type: types.ChildTypeAccount},
					},
					NextToken: aws.String("next"),
				}, nil
			}
			return &organizations.ListChildrenOutput{Children: []types.Child{
				{Id: aws.String("222222222222"), Type: types.ChildTypeAccount},
				{Id: aws.String("111111111111"), Type: types.ChildTypeAccount},
			}}, nil
		},
	}

	children, err := listChildren(context.Background(), client, "r-root", types.ChildTypeAccount)
	if err != nil {
		t.Fatalf("list children: %v", err)
	}
	got := make([]string, len(children))
	for index, child := range children {
		got[index] = aws.ToString(child.Id)
	}
	want := []string{"111111111111", "222222222222", "333333333333"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("children are %v, want %v", got, want)
	}
}

func TestFullOrganizationOutputIsByteStableAcrossPaginatedChildOrder(t *testing.T) {
	t.Parallel()

	const (
		rootID            = "r-root"
		managementAccount = "111111111111"
	)

	newClient := func(scrambled bool) *fakeOrganizationsClient {
		pages := map[string][][]string{
			rootID + ":ACCOUNT": {
				{"333333333333", managementAccount},
				{"222222222222"},
			},
			rootID + ":ORGANIZATIONAL_UNIT": {
				{"ou-root-bbbb2222"},
				{"ou-root-aaaa1111"},
			},
			"ou-root-aaaa1111:ACCOUNT": {
				{"555555555555"},
				{"444444444444"},
			},
			"ou-root-aaaa1111:ORGANIZATIONAL_UNIT": {
				{"ou-root-dddd4444"},
				{"ou-root-cccc3333"},
			},
			"ou-root-bbbb2222:ACCOUNT":             {{}},
			"ou-root-bbbb2222:ORGANIZATIONAL_UNIT": {{}},
			"ou-root-cccc3333:ACCOUNT":             {{}},
			"ou-root-cccc3333:ORGANIZATIONAL_UNIT": {{}},
			"ou-root-dddd4444:ACCOUNT":             {{}},
			"ou-root-dddd4444:ORGANIZATIONAL_UNIT": {{}},
		}
		if scrambled {
			pages[rootID+":ACCOUNT"] = [][]string{{"222222222222"}, {managementAccount, "333333333333"}}
			pages[rootID+":ORGANIZATIONAL_UNIT"] = [][]string{{"ou-root-aaaa1111"}, {"ou-root-bbbb2222"}}
			pages["ou-root-aaaa1111:ACCOUNT"] = [][]string{{"444444444444"}, {"555555555555"}}
			pages["ou-root-aaaa1111:ORGANIZATIONAL_UNIT"] = [][]string{{"ou-root-cccc3333"}, {"ou-root-dddd4444"}}
		}

		return &fakeOrganizationsClient{
			listChildrenFn: func(_ context.Context, input *organizations.ListChildrenInput) (*organizations.ListChildrenOutput, error) {
				key := aws.ToString(input.ParentId) + ":" + string(input.ChildType)
				responsePages, ok := pages[key]
				if !ok {
					return nil, fmt.Errorf("unexpected children lookup %s", key)
				}
				pageIndex := 0
				if input.NextToken != nil {
					expectedToken := key + ":1"
					if aws.ToString(input.NextToken) != expectedToken {
						return nil, fmt.Errorf("unexpected pagination token %q for %s", aws.ToString(input.NextToken), key)
					}
					pageIndex = 1
				}
				if pageIndex >= len(responsePages) {
					return nil, fmt.Errorf("unexpected page %d for %s", pageIndex, key)
				}
				children := make([]types.Child, 0, len(responsePages[pageIndex]))
				for _, id := range responsePages[pageIndex] {
					children = append(children, types.Child{Id: aws.String(id), Type: input.ChildType})
				}
				output := &organizations.ListChildrenOutput{Children: children}
				if pageIndex+1 < len(responsePages) {
					output.NextToken = aws.String(key + ":1")
				}
				return output, nil
			},
			describeAccountFn: func(_ context.Context, input *organizations.DescribeAccountInput) (*organizations.DescribeAccountOutput, error) {
				id := aws.ToString(input.AccountId)
				return &organizations.DescribeAccountOutput{Account: &types.Account{Id: input.AccountId, Name: aws.String("Account " + id)}}, nil
			},
			describeOrganizationalUnit: func(_ context.Context, input *organizations.DescribeOrganizationalUnitInput) (*organizations.DescribeOrganizationalUnitOutput, error) {
				id := aws.ToString(input.OrganizationalUnitId)
				return &organizations.DescribeOrganizationalUnitOutput{OrganizationalUnit: &types.OrganizationalUnit{
					Id: input.OrganizationalUnitId, Name: aws.String("OU " + id),
				}}, nil
			},
			listPoliciesForTargetFn: func(context.Context, *organizations.ListPoliciesForTargetInput) (*organizations.ListPoliciesForTargetOutput, error) {
				return &organizations.ListPoliciesForTargetOutput{}, nil
			},
		}
	}

	wantJSON := `{
  "schema_version": "1",
  "type": "root",
  "id": "r-root",
  "children": [
    {
      "type": "account",
      "id": "111111111111",
      "name": "Account 111111111111",
      "management_account": true
    },
    {
      "type": "account",
      "id": "222222222222",
      "name": "Account 222222222222"
    },
    {
      "type": "account",
      "id": "333333333333",
      "name": "Account 333333333333"
    },
    {
      "type": "organizational_unit",
      "id": "ou-root-aaaa1111",
      "name": "OU ou-root-aaaa1111",
      "children": [
        {
          "type": "account",
          "id": "444444444444",
          "name": "Account 444444444444"
        },
        {
          "type": "account",
          "id": "555555555555",
          "name": "Account 555555555555"
        },
        {
          "type": "organizational_unit",
          "id": "ou-root-cccc3333",
          "name": "OU ou-root-cccc3333"
        },
        {
          "type": "organizational_unit",
          "id": "ou-root-dddd4444",
          "name": "OU ou-root-dddd4444"
        }
      ]
    },
    {
      "type": "organizational_unit",
      "id": "ou-root-bbbb2222",
      "name": "OU ou-root-bbbb2222"
    }
  ]
}
`
	wantText := "|-- Root: [r-root]\n" +
		"    |-- Account: Account 111111111111 (Management Account) [111111111111] (SCPs do not affect management-account users or roles)\n" +
		"    |-- Account: Account 222222222222 [222222222222] (SCP summary names from account/ancestor attachments: )\n" +
		"    |-- Account: Account 333333333333 [333333333333] (SCP summary names from account/ancestor attachments: )\n" +
		"    |-- OU: OU ou-root-aaaa1111 [ou-root-aaaa1111]\n" +
		"        |-- Account: Account 444444444444 [444444444444] (SCP summary names from account/ancestor attachments: )\n" +
		"        |-- Account: Account 555555555555 [555555555555] (SCP summary names from account/ancestor attachments: )\n" +
		"        |-- OU: OU ou-root-cccc3333 [ou-root-cccc3333]\n" +
		"        |-- OU: OU ou-root-dddd4444 [ou-root-dddd4444]\n" +
		"    |-- OU: OU ou-root-bbbb2222 [ou-root-bbbb2222]\n"

	tests := []struct {
		format outputFormat
		want   string
	}{
		{format: json, want: wantJSON},
		{format: text, want: wantText},
	}
	for _, test := range tests {
		test := test
		t.Run(string(test.format), func(t *testing.T) {
			t.Parallel()

			var first bytes.Buffer
			var second bytes.Buffer
			if test.format == json {
				if err := displayOrganizationTreeJSON(context.Background(), &first, newClient(false), "all", rootID, "Root", managementAccount); err != nil {
					t.Fatalf("render first JSON output: %v", err)
				}
				if err := displayOrganizationTreeJSON(context.Background(), &second, newClient(true), "all", rootID, "Root", managementAccount); err != nil {
					t.Fatalf("render second JSON output: %v", err)
				}
			} else {
				if err := displayOrganizationTreeText(context.Background(), &first, newClient(false), "all", rootID, "Root", managementAccount); err != nil {
					t.Fatalf("render first text output: %v", err)
				}
				if err := displayOrganizationTreeText(context.Background(), &second, newClient(true), "all", rootID, "Root", managementAccount); err != nil {
					t.Fatalf("render second text output: %v", err)
				}
			}
			if first.String() != test.want {
				t.Fatalf("first %s output:\n%s\nwant:\n%s", test.format, first.String(), test.want)
			}
			if second.String() != test.want {
				t.Fatalf("second %s output:\n%s\nwant:\n%s", test.format, second.String(), test.want)
			}
			if !bytes.Equal(first.Bytes(), second.Bytes()) {
				t.Fatalf("%s output changed with AWS child order:\nfirst:\n%s\nsecond:\n%s", test.format, first.Bytes(), second.Bytes())
			}
		})
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
			return &organizations.ListRootsOutput{Roots: []types.Root{{
				Id: aws.String("r-root"), Name: aws.String("Organization Root"),
			}}}, nil
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
	rootID, rootName, err := getRoot(context.Background(), client)
	if err != nil || rootID != "r-root" || rootName != "Organization Root" {
		t.Fatalf("root: got %q (%q), error %v", rootID, rootName, err)
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
	err := printPathToAccount(
		context.Background(),
		&output,
		client,
		rootID,
		accountID,
		"999999999999",
		newOrganizationCache(rootID, "Organization Root"),
	)
	if err != nil {
		t.Fatalf("print path: %v", err)
	}
	if listChildrenCalls != 0 {
		t.Fatalf("list children called %d times", listChildrenCalls)
	}
	want := "|-- Root: [r-root]\n" +
		"    |-- OU: Production [ou-root-12345678]\n" +
		"        |-- Account: Application [123456789012] (SCP summary names from account/ancestor attachments: DenyS3, FullAWSAccess)\n" +
		"            |-- SCP: DenyS3 [p-deny0001] (Attached to: account Application [123456789012]; Inherited: false)\n" +
		"            |-- SCP: FullAWSAccess [p-full0001] (Attached to: root Organization Root [r-root]; Inherited: true)\n" +
		"            |-- SCP: FullAWSAccess [p-full0001] (Attached to: organizational_unit Production [ou-root-12345678]; Inherited: true)\n"
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
	err := printPathToAccount(
		context.Background(),
		&bytes.Buffer{},
		client,
		"r-root",
		"123456789012",
		"999999999999",
		newOrganizationCache("r-root", ""),
	)
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

func TestListSCPsForPathPreservesUnambiguousAttachmentProvenance(t *testing.T) {
	t.Parallel()

	const (
		rootID    = "r-root"
		ouID      = "ou-root-12345678"
		accountID = "123456789012"
	)
	policyCalls := make(map[string]int)
	client := &fakeOrganizationsClient{
		listPoliciesForTargetFn: func(_ context.Context, input *organizations.ListPoliciesForTargetInput) (*organizations.ListPoliciesForTargetOutput, error) {
			targetID := aws.ToString(input.TargetId)
			policyCalls[targetID]++
			switch targetID {
			case rootID:
				return &organizations.ListPoliciesForTargetOutput{Policies: []types.PolicySummary{
					{Id: aws.String("p-shared01"), Name: aws.String("Shared"), Type: types.PolicyTypeServiceControlPolicy},
					{Id: aws.String("p-first001"), Name: aws.String("SameName"), Type: types.PolicyTypeServiceControlPolicy},
				}}, nil
			case ouID:
				return &organizations.ListPoliciesForTargetOutput{Policies: []types.PolicySummary{
					{Id: aws.String("p-shared01"), Name: aws.String("Shared"), Type: types.PolicyTypeServiceControlPolicy},
					{Id: aws.String("p-second01"), Name: aws.String("SameName"), Type: types.PolicyTypeServiceControlPolicy},
				}}, nil
			case accountID:
				return &organizations.ListPoliciesForTargetOutput{Policies: []types.PolicySummary{
					{Id: aws.String("p-direct001"), Name: aws.String("Direct"), Type: types.PolicyTypeServiceControlPolicy},
					{Id: aws.String("p-direct001"), Name: aws.String("Direct"), Type: types.PolicyTypeServiceControlPolicy},
					{Id: aws.String("p-shared01"), Name: aws.String("Shared"), Type: types.PolicyTypeServiceControlPolicy},
				}}, nil
			default:
				return nil, errors.New("unexpected policy lookup")
			}
		},
	}

	cache := newOrganizationCache(rootID, "Organization Root")
	cache.entityNames[ouID] = "Production"
	cache.entityNames[accountID] = "Application"
	names, attachments, err := listSCPsForPath(
		context.Background(),
		client,
		[]string{rootID, ouID, accountID},
		cache,
	)
	if err != nil {
		t.Fatalf("list policies: %v", err)
	}
	wantNames := []string{"Direct", "SameName", "Shared"}
	if !reflect.DeepEqual(names, wantNames) {
		t.Fatalf("got names %v, want %v", names, wantNames)
	}
	wantAttachments := []scpAttachment{
		{
			PolicyID:   "p-direct001",
			PolicyName: "Direct",
			AttachedTo: scpAttachmentTarget{Type: "account", ID: accountID, Name: "Application"},
			Inherited:  false,
		},
		{
			PolicyID:   "p-first001",
			PolicyName: "SameName",
			AttachedTo: scpAttachmentTarget{Type: "root", ID: rootID, Name: "Organization Root"},
			Inherited:  true,
		},
		{
			PolicyID:   "p-second01",
			PolicyName: "SameName",
			AttachedTo: scpAttachmentTarget{Type: "organizational_unit", ID: ouID, Name: "Production"},
			Inherited:  true,
		},
		{
			PolicyID:   "p-shared01",
			PolicyName: "Shared",
			AttachedTo: scpAttachmentTarget{Type: "root", ID: rootID, Name: "Organization Root"},
			Inherited:  true,
		},
		{
			PolicyID:   "p-shared01",
			PolicyName: "Shared",
			AttachedTo: scpAttachmentTarget{Type: "organizational_unit", ID: ouID, Name: "Production"},
			Inherited:  true,
		},
		{
			PolicyID:   "p-shared01",
			PolicyName: "Shared",
			AttachedTo: scpAttachmentTarget{Type: "account", ID: accountID, Name: "Application"},
			Inherited:  false,
		},
	}
	if !reflect.DeepEqual(attachments, wantAttachments) {
		t.Fatalf("got attachments\n%+v\nwant\n%+v", attachments, wantAttachments)
	}
	for _, targetID := range []string{rootID, ouID, accountID} {
		if policyCalls[targetID] != 1 {
			t.Fatalf("policies for %s listed %d times, want once", targetID, policyCalls[targetID])
		}
	}
}

func TestListSCPsForPathRejectsConflictingSummaries(t *testing.T) {
	t.Parallel()

	tests := map[string]map[string][]types.PolicySummary{
		"same ID with different names": {
			"r-root":       {{Id: aws.String("p-00000001"), Name: aws.String("First"), Type: types.PolicyTypeServiceControlPolicy}},
			"123456789012": {{Id: aws.String("p-00000001"), Name: aws.String("Second"), Type: types.PolicyTypeServiceControlPolicy}},
		},
	}
	for name, cache := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, _, err := listSCPsForPath(
				context.Background(),
				&fakeOrganizationsClient{},
				[]string{"r-root", "123456789012"},
				&organizationCache{policiesByTarget: cache, entityNames: map[string]string{}},
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
		newOrganizationCache("r-root", "Organization Root"),
	)
	if err != nil {
		t.Fatalf("print account: %v", err)
	}
	if policyCalls != 0 {
		t.Fatalf("policy API called %d times", policyCalls)
	}
	want := "|-- Account: Management (Management Account) [123456789012] (SCPs do not affect management-account users or roles)\n"
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
	var policyCallsMu sync.Mutex
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
			policyCallsMu.Lock()
			defer policyCallsMu.Unlock()
			policyCalls[targetID]++
			return &organizations.ListPoliciesForTargetOutput{}, nil
		},
	}

	var output bytes.Buffer
	err := displayOrganizationTreeText(context.Background(), &output, client, "all", rootID, "", managementAccount)
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
	policyCallsMu.Lock()
	managementPolicyCalls := policyCalls[managementAccount]
	rootPolicyCalls := policyCalls[rootID]
	ouPolicyCalls := policyCalls[ouID]
	policyCallsMu.Unlock()
	if managementPolicyCalls != 0 {
		t.Fatalf("management account policies queried %d times", managementPolicyCalls)
	}
	if rootPolicyCalls != 1 || ouPolicyCalls != 1 {
		t.Fatalf("shared ancestor policy calls: root=%d OU=%d, want 1 each", rootPolicyCalls, ouPolicyCalls)
	}
	want := "|-- Root: [r-root]\n" +
		"    |-- Account: Management (Management Account) [111111111111] (SCPs do not affect management-account users or roles)\n" +
		"    |-- OU: Production [ou-root-12345678]\n" +
		"        |-- Account: Member [222222222222] (SCP summary names from account/ancestor attachments: )\n" +
		"        |-- Account: Member [333333333333] (SCP summary names from account/ancestor attachments: )\n"
	if output.String() != want {
		t.Fatalf("unexpected output:\n%s\nwant:\n%s", output.String(), want)
	}

	output.Reset()
	err = displayOrganizationTreeJSON(context.Background(), &output, client, "all", rootID, "", managementAccount)
	if err != nil {
		t.Fatalf("display organization as JSON: %v", err)
	}
	var result organizationJSONNode
	if err := encodingjson.Unmarshal(output.Bytes(), &result); err != nil {
		t.Fatalf("decode organization JSON: %v", err)
	}
	if result.SchemaVersion != organizationJSONSchemaVersion {
		t.Fatalf("schema version is %q, want %q", result.SchemaVersion, organizationJSONSchemaVersion)
	}
	if len(result.Children) != 2 || !result.Children[0].ManagementAccount {
		t.Fatalf("unexpected root children: %+v", result.Children)
	}
	if result.Children[0].SCPs != nil || result.Children[0].SCPAttachments != nil {
		t.Fatalf("management account contains SCP data: %+v", result.Children[0])
	}
	organizationalUnit := result.Children[1]
	if organizationalUnit.ID != ouID || len(organizationalUnit.Children) != 2 {
		t.Fatalf("unexpected organizational unit: %+v", organizationalUnit)
	}
}

func TestFullOrganizationInspectionUsesBoundedConcurrencyAndDeterministicOrder(t *testing.T) {
	t.Parallel()

	const (
		rootID       = "r-root"
		accountCount = 64
	)
	accountIDs := make([]string, accountCount)
	accountChildren := make([]types.Child, accountCount)
	for index := range accountCount {
		accountIDs[index] = fmt.Sprintf("%012d", 100000000000+index)
		accountChildren[index] = types.Child{Id: aws.String(accountIDs[index]), Type: types.ChildTypeAccount}
	}

	entered := make(chan struct{}, accountCount)
	release := make(chan struct{})
	policyCalls := make(map[string]int, accountCount+1)
	var callsMu sync.Mutex
	activeCalls := 0
	peakCalls := 0
	client := &fakeOrganizationsClient{
		listChildrenFn: func(_ context.Context, input *organizations.ListChildrenInput) (*organizations.ListChildrenOutput, error) {
			if aws.ToString(input.ParentId) != rootID {
				return nil, errors.New("unexpected parent")
			}
			if input.ChildType == types.ChildTypeAccount {
				return &organizations.ListChildrenOutput{Children: accountChildren}, nil
			}
			return &organizations.ListChildrenOutput{}, nil
		},
		describeAccountFn: func(ctx context.Context, input *organizations.DescribeAccountInput) (*organizations.DescribeAccountOutput, error) {
			callsMu.Lock()
			activeCalls++
			peakCalls = max(peakCalls, activeCalls)
			callsMu.Unlock()
			defer func() {
				callsMu.Lock()
				activeCalls--
				callsMu.Unlock()
			}()

			entered <- struct{}{}
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-release:
				accountID := aws.ToString(input.AccountId)
				return &organizations.DescribeAccountOutput{Account: &types.Account{
					Id: input.AccountId, Name: aws.String("Account " + accountID),
				}}, nil
			}
		},
		listPoliciesForTargetFn: func(_ context.Context, input *organizations.ListPoliciesForTargetInput) (*organizations.ListPoliciesForTargetOutput, error) {
			callsMu.Lock()
			policyCalls[aws.ToString(input.TargetId)]++
			callsMu.Unlock()
			return &organizations.ListPoliciesForTargetOutput{}, nil
		},
	}

	var output bytes.Buffer
	done := make(chan error, 1)
	go func() {
		done <- displayOrganizationTreeJSON(
			context.Background(), &output, client, "all", rootID, "Organization Root", "999999999999",
		)
	}()

	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	for range organizationInspectionConcurrency {
		select {
		case <-entered:
		case <-timer.C:
			close(release)
			t.Fatal("full-organization inspection did not issue concurrent account calls")
		}
	}
	close(release)
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("inspect organization: %v", err)
		}
	case <-timer.C:
		t.Fatal("full-organization inspection did not finish")
	}

	callsMu.Lock()
	gotPeakCalls := peakCalls
	gotActiveCalls := activeCalls
	gotPolicyCalls := make(map[string]int, len(policyCalls))
	for targetID, calls := range policyCalls {
		gotPolicyCalls[targetID] = calls
	}
	callsMu.Unlock()
	if gotPeakCalls != organizationInspectionConcurrency {
		t.Fatalf("peak concurrent AWS calls = %d, want fixed bound %d", gotPeakCalls, organizationInspectionConcurrency)
	}
	if gotActiveCalls != 0 {
		t.Fatalf("active AWS calls after completion = %d, want 0", gotActiveCalls)
	}
	if gotPolicyCalls[rootID] != 1 {
		t.Fatalf("root policies listed %d times, want once", gotPolicyCalls[rootID])
	}
	for _, accountID := range accountIDs {
		if gotPolicyCalls[accountID] != 1 {
			t.Fatalf("account %s policies listed %d times, want once", accountID, gotPolicyCalls[accountID])
		}
	}

	var result organizationJSONNode
	if err := encodingjson.Unmarshal(output.Bytes(), &result); err != nil {
		t.Fatalf("decode organization JSON: %v", err)
	}
	if len(result.Children) != accountCount {
		t.Fatalf("organization contains %d accounts, want %d", len(result.Children), accountCount)
	}
	for index, node := range result.Children {
		if node.ID != accountIDs[index] {
			t.Fatalf("account at output index %d is %s, want %s", index, node.ID, accountIDs[index])
		}
	}
}

func TestFullOrganizationInspectionCancelsOnFailureWithoutPartialText(t *testing.T) {
	t.Parallel()

	const rootID = "r-root"
	accountChildren := make([]types.Child, 16)
	for index := range accountChildren {
		accountID := fmt.Sprintf("%012d", 200000000000+index)
		accountChildren[index] = types.Child{Id: aws.String(accountID), Type: types.ChildTypeAccount}
	}
	failingAccountID := aws.ToString(accountChildren[0].Id)
	inspectionFailure := errors.New("account inspection failed")
	entered := make(chan string, len(accountChildren))
	canceled := make(chan string, len(accountChildren))
	proceed := make(chan struct{})
	var releaseOnce sync.Once
	releaseWorkers := func() {
		releaseOnce.Do(func() { close(proceed) })
	}
	defer releaseWorkers()

	client := &fakeOrganizationsClient{
		listChildrenFn: func(_ context.Context, input *organizations.ListChildrenInput) (*organizations.ListChildrenOutput, error) {
			if input.ChildType == types.ChildTypeAccount {
				return &organizations.ListChildrenOutput{Children: accountChildren}, nil
			}
			return &organizations.ListChildrenOutput{}, nil
		},
		describeAccountFn: func(ctx context.Context, input *organizations.DescribeAccountInput) (*organizations.DescribeAccountOutput, error) {
			accountID := aws.ToString(input.AccountId)
			entered <- accountID
			select {
			case <-ctx.Done():
				canceled <- accountID
				return nil, ctx.Err()
			case <-proceed:
			}
			if accountID == failingAccountID {
				return nil, inspectionFailure
			}
			<-ctx.Done()
			canceled <- accountID
			return nil, ctx.Err()
		},
		listPoliciesForTargetFn: func(context.Context, *organizations.ListPoliciesForTargetInput) (*organizations.ListPoliciesForTargetOutput, error) {
			return nil, errors.New("policy lookup must not start before account descriptions finish")
		},
	}

	var output bytes.Buffer
	done := make(chan error, 1)
	go func() {
		done <- displayOrganizationTreeText(
			context.Background(), &output, client, "all", rootID, "Organization Root", "999999999999",
		)
	}()

	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	started := make(map[string]bool, organizationInspectionConcurrency)
	for range organizationInspectionConcurrency {
		select {
		case accountID := <-entered:
			started[accountID] = true
		case <-timer.C:
			t.Fatal("full-organization inspection did not fill its worker bound")
		}
	}
	if !started[failingAccountID] {
		t.Fatalf("failing account %s was not among initial workers: %v", failingAccountID, started)
	}
	releaseWorkers()

	select {
	case err := <-done:
		if !errors.Is(err, inspectionFailure) {
			t.Fatalf("inspection error = %v, want %v", err, inspectionFailure)
		}
	case <-timer.C:
		t.Fatal("full-organization inspection did not cancel in-flight calls")
	}
	if len(canceled) != organizationInspectionConcurrency-1 {
		t.Fatalf("canceled in-flight account calls = %d, want %d", len(canceled), organizationInspectionConcurrency-1)
	}
	if output.Len() != 0 {
		t.Fatalf("failed inspection wrote partial output: %q", output.String())
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
			switch aws.ToString(input.TargetId) {
			case rootID:
				return &organizations.ListPoliciesForTargetOutput{Policies: []types.PolicySummary{{
					Id: aws.String("p-full0001"), Name: aws.String("FullAWSAccess"), Type: types.PolicyTypeServiceControlPolicy,
				}}}, nil
			case ouID:
				return &organizations.ListPoliciesForTargetOutput{Policies: []types.PolicySummary{{
					Id: aws.String("p-regions01"), Name: aws.String("DenyRegions"), Type: types.PolicyTypeServiceControlPolicy,
				}}}, nil
			case accountID:
				return &organizations.ListPoliciesForTargetOutput{Policies: []types.PolicySummary{{
					Id: aws.String("p-deny0001"), Name: aws.String("DenyS3"), Type: types.PolicyTypeServiceControlPolicy,
				}}}, nil
			default:
				return nil, errors.New("unexpected policy lookup")
			}
		},
	}

	var output bytes.Buffer
	if err := displayOrganizationTreeJSON(
		context.Background(), &output, client, accountID, rootID, "Organization Root", "999999999999",
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
		strings.Join(account.SCPs, ",") != "DenyRegions,DenyS3,FullAWSAccess" {
		t.Fatalf("unexpected account: %+v", account)
	}
	wantAttachments := []scpAttachment{
		{
			PolicyID:   "p-regions01",
			PolicyName: "DenyRegions",
			AttachedTo: scpAttachmentTarget{Type: "organizational_unit", ID: ouID, Name: "Production"},
			Inherited:  true,
		},
		{
			PolicyID:   "p-deny0001",
			PolicyName: "DenyS3",
			AttachedTo: scpAttachmentTarget{Type: "account", ID: accountID, Name: "Application"},
			Inherited:  false,
		},
		{
			PolicyID:   "p-full0001",
			PolicyName: "FullAWSAccess",
			AttachedTo: scpAttachmentTarget{Type: "root", ID: rootID, Name: "Organization Root"},
			Inherited:  true,
		},
	}
	if !reflect.DeepEqual(account.SCPAttachments, wantAttachments) {
		t.Fatalf("got attachments\n%+v\nwant\n%+v", account.SCPAttachments, wantAttachments)
	}
}
