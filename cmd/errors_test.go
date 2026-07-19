package cmd

import (
	"bytes"
	"context"
	encodingjson "encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/credentials/ssocreds"
	"github.com/aws/smithy-go"
	"github.com/spf13/cobra"
)

type requestIDError struct {
	requestID string
	err       error
}

func (err *requestIDError) Error() string            { return err.err.Error() }
func (err *requestIDError) Unwrap() error            { return err.err }
func (err *requestIDError) ServiceRequestID() string { return err.requestID }

func TestClassifyError(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		err       error
		wantCode  string
		wantExit  int
		retryable bool
	}{
		"invalid invocation": {
			err: newInvalidInvocationError(errors.New("bad flag")), wantCode: errorCodeInvalidInvocation, wantExit: exitInvocation,
		},
		"credential provider": {
			err: newCredentialsError("RetrieveCredentials", errors.New("provider failed")), wantCode: errorCodeCredentials, wantExit: exitCredentials,
		},
		"expired credentials": {
			err: awsOperationError("ListRoots", "ExpiredToken", smithy.FaultClient), wantCode: errorCodeCredentials, wantExit: exitCredentials,
		},
		"authorization": {
			err: awsOperationError("ListRoots", "AccessDeniedException", smithy.FaultClient), wantCode: errorCodeAuthorization, wantExit: exitAuthorization,
		},
		"throttling": {
			err: awsOperationError("ListRoots", "ThrottlingException", smithy.FaultClient), wantCode: errorCodeTransient, wantExit: exitTransient, retryable: true,
		},
		"server failure": {
			err: awsOperationError("ListRoots", "NewServerError", smithy.FaultServer), wantCode: errorCodeTransient, wantExit: exitTransient, retryable: true,
		},
		"network timeout": {
			err: context.DeadlineExceeded, wantCode: errorCodeTransient, wantExit: exitTransient, retryable: true,
		},
		"unexpected": {
			err: errors.New("broken response"), wantCode: errorCodeUnexpected, wantExit: exitUnexpected,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got := classifyError(test.err)
			if got.Code != test.wantCode || got.ExitCode != test.wantExit || got.Retryable != test.retryable {
				t.Fatalf("classify error = %#v, want code %q, exit %d, retryable %t", got, test.wantCode, test.wantExit, test.retryable)
			}
		})
	}
}

func TestJSONErrorIncludesStableAutomationFields(t *testing.T) {
	t.Parallel()

	err := &requestIDError{
		requestID: "request-123",
		err:       awsOperationError("ListPoliciesForTarget", "AccessDeniedException", smithy.FaultClient),
	}
	diagnostic := classifyError(err)

	var output bytes.Buffer
	if err := writeError(&output, diagnostic, errorFormatJSON); err != nil {
		t.Fatalf("write JSON error: %v", err)
	}

	var got map[string]any
	if err := encodingjson.Unmarshal(output.Bytes(), &got); err != nil {
		t.Fatalf("decode JSON error: %v", err)
	}
	for key, want := range map[string]any{
		"code":       errorCodeAuthorization,
		"operation":  "ListPoliciesForTarget",
		"retryable":  false,
		"request_id": "request-123",
	} {
		if got[key] != want {
			t.Errorf("field %q = %#v, want %#v", key, got[key], want)
		}
	}
	if got["message"] == "" || got["remediation"] == "" {
		t.Fatalf("JSON error lacks message or remediation: %s", output.String())
	}
	if _, exists := got["ExitCode"]; exists {
		t.Fatalf("JSON error exposes internal exit code: %s", output.String())
	}
}

func TestExecuteCommandWritesOnlyErrorsToStderr(t *testing.T) {
	previousFormat := errorFormatValue
	errorFormatValue = errorFormatJSON
	t.Cleanup(func() { errorFormatValue = previousFormat })

	command := &cobra.Command{
		Use:           "test",
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(*cobra.Command, []string) error {
			return awsOperationError("ListRoots", "ThrottlingException", smithy.FaultClient)
		},
	}
	var stdout, stderr bytes.Buffer
	exitCode := executeCommand(command, nil, &stdout, &stderr)
	if exitCode != exitTransient {
		t.Fatalf("exit code = %d, want %d", exitCode, exitTransient)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout contains error output: %q", stdout.String())
	}
	if !encodingjson.Valid(stderr.Bytes()) {
		t.Fatalf("stderr is not JSON: %q", stderr.String())
	}
}

func TestExecuteCommandPreservesSuccessfulStdout(t *testing.T) {
	previousFormat := errorFormatValue
	errorFormatValue = errorFormatHuman
	t.Cleanup(func() { errorFormatValue = previousFormat })

	command := &cobra.Command{
		Use: "test",
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, err := cmd.OutOrStdout().Write([]byte("successful data\n"))
			return err
		},
	}
	var stdout, stderr bytes.Buffer
	if exitCode := executeCommand(command, nil, &stdout, &stderr); exitCode != exitSuccess {
		t.Fatalf("exit code = %d, want %d", exitCode, exitSuccess)
	}
	if stdout.String() != "successful data\n" || stderr.Len() != 0 {
		t.Fatalf("stdout = %q, stderr = %q", stdout.String(), stderr.String())
	}
}

func TestExecuteCommandContextPreservesExitCodeOnStderrWriteFailure(t *testing.T) {
	previousFormat := errorFormatValue
	errorFormatValue = errorFormatHuman
	t.Cleanup(func() { errorFormatValue = previousFormat })

	command := &cobra.Command{
		Use:           "test",
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(*cobra.Command, []string) error {
			return awsOperationError("ListRoots", "ThrottlingException", smithy.FaultClient)
		},
	}
	var stdout bytes.Buffer
	failingStderr := &failingWriter{err: errors.New("stderr closed")}
	exitCode := executeCommandContext(context.Background(), command, nil, &stdout, failingStderr)
	if exitCode != exitTransient {
		t.Fatalf("exit code = %d, want %d (stderr write failure must not obscure the original operation status)",
			exitCode, exitTransient)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout contains error output: %q", stdout.String())
	}
	if calls := failingStderr.writeCalls; calls == 0 {
		t.Fatalf("expected at least one stderr write attempt, got %d", calls)
	}
}

func TestExecuteCommandContextPropagatesCancellation(t *testing.T) {
	previousFormat := errorFormatValue
	errorFormatValue = errorFormatHuman
	t.Cleanup(func() { errorFormatValue = previousFormat })

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	command := &cobra.Command{
		Use:           "test",
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return cmd.Context().Err()
		},
	}
	var stdout, stderr bytes.Buffer
	if exitCode := executeCommandContext(ctx, command, nil, &stdout, &stderr); exitCode != exitUnexpected {
		t.Fatalf("exit code = %d, want %d", exitCode, exitUnexpected)
	}
	if stdout.Len() != 0 || !strings.Contains(stderr.String(), "execution was canceled") {
		t.Fatalf("stdout = %q, stderr = %q", stdout.String(), stderr.String())
	}
}

func TestExecuteCommandClassifiesUnknownCommandAndHonorsJSONFormat(t *testing.T) {
	previousFormat := errorFormatValue
	errorFormatValue = errorFormatHuman
	t.Cleanup(func() { errorFormatValue = previousFormat })

	command := &cobra.Command{
		Use: "test", SilenceErrors: true, SilenceUsage: true,
		Args: func(cmd *cobra.Command, args []string) error {
			if err := cobra.NoArgs(cmd, args); err != nil {
				return newInvalidInvocationError(err)
			}
			return nil
		},
		Run: func(*cobra.Command, []string) {},
	}
	command.PersistentFlags().Var(&errorFormatValue, "error-format", "error format")
	command.AddCommand(&cobra.Command{Use: "aws"})
	var stdout, stderr bytes.Buffer
	exitCode := executeCommand(command, []string{"--error-format", "json", "unknown"}, &stdout, &stderr)
	if exitCode != exitInvocation {
		t.Fatalf("exit code = %d, want %d", exitCode, exitInvocation)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout contains error output: %q", stdout.String())
	}
	var diagnostic classifiedError
	if err := encodingjson.Unmarshal(stderr.Bytes(), &diagnostic); err != nil {
		t.Fatalf("stderr is not JSON: %q: %v", stderr.String(), err)
	}
	if diagnostic.Code != errorCodeInvalidInvocation {
		t.Fatalf("error code = %q, want %q", diagnostic.Code, errorCodeInvalidInvocation)
	}
}

func TestCredentialProviderTransientFailureRemainsRetryable(t *testing.T) {
	t.Parallel()

	diagnostic := classifyError(newCredentialsError("RetrieveCredentials", awsOperationError(
		"AssumeRole", "ThrottlingException", smithy.FaultClient,
	)))
	if diagnostic.Code != errorCodeTransient || diagnostic.ExitCode != exitTransient || !diagnostic.Retryable {
		t.Fatalf("classify provider throttling = %#v", diagnostic)
	}
	if diagnostic.Operation != "AssumeRole" {
		t.Fatalf("operation = %q, want AssumeRole", diagnostic.Operation)
	}
}

func TestSSORemediationSupportsHumanAndJSONErrors(t *testing.T) {
	t.Parallel()

	err := addSSORemediation(
		newCredentialsError("RetrieveCredentials", &ssocreds.InvalidTokenError{}),
		"dev;$(touch nope)",
	)
	diagnostic := classifyError(err)
	if diagnostic.Code != errorCodeCredentials || diagnostic.ExitCode != exitCredentials || diagnostic.Retryable {
		t.Fatalf("unexpected SSO diagnostic: %#v", diagnostic)
	}
	if diagnostic.Operation != "RetrieveCredentials" {
		t.Fatalf("operation is %q, want RetrieveCredentials", diagnostic.Operation)
	}
	if !strings.Contains(diagnostic.Remediation, "aws sso login --profile='dev;$(touch nope)'") ||
		!strings.Contains(diagnostic.Remediation, "did not run this command automatically") {
		t.Fatalf("unexpected SSO remediation: %q", diagnostic.Remediation)
	}

	for _, format := range []errorFormat{errorFormatHuman, errorFormatJSON} {
		var output bytes.Buffer
		if err := writeError(&output, diagnostic, format); err != nil {
			t.Fatalf("write %s SSO diagnostic: %v", format, err)
		}
		if format == errorFormatJSON && !encodingjson.Valid(output.Bytes()) {
			t.Fatalf("JSON SSO diagnostic is invalid: %q", output.String())
		}
		if strings.Count(output.String(), "aws sso login") != 1 {
			t.Fatalf("SSO command should appear once in %s diagnostic: %q", format, output.String())
		}
	}
}

func TestHumanErrorIsConciseAndActionable(t *testing.T) {
	t.Parallel()

	diagnostic := classifyError(awsOperationError("ListRoots", "AccessDeniedException", smithy.FaultClient))
	var output bytes.Buffer
	if err := writeError(&output, diagnostic, errorFormatHuman); err != nil {
		t.Fatalf("write human error: %v", err)
	}
	want := "Error [aws_access_denied]: AWS denied the Organizations request.\n" +
		"Operation: ListRoots\n" +
		"Remediation: Grant the selected identity the required AWS Organizations read permissions, then retry.\n"
	if output.String() != want {
		t.Fatalf("human error = %q, want %q", output.String(), want)
	}
}

func awsOperationError(operation, code string, fault smithy.ErrorFault) error {
	return &smithy.OperationError{
		ServiceID: "Organizations", OperationName: operation,
		Err: &smithy.GenericAPIError{Code: code, Message: "unsafe provider detail", Fault: fault},
	}
}

// failingWriter is an io.Writer that always returns a non-nil error and
// records how many write attempts were made.
type failingWriter struct {
	err        error
	writeCalls int
}

func (w *failingWriter) Write(p []byte) (int, error) {
	w.writeCalls++
	return 0, w.err
}
