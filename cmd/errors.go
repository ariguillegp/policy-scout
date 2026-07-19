package cmd

import (
	"context"
	encodingjson "encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/aws/smithy-go"
	"github.com/spf13/cobra"
)

const (
	exitSuccess       = 0
	exitUnexpected    = 1
	exitInvocation    = 2
	exitCredentials   = 3
	exitAuthorization = 4
	exitTransient     = 5
)

const (
	errorCodeInvalidInvocation = "invalid_invocation"
	errorCodeCredentials       = "aws_credentials"
	errorCodeAuthorization     = "aws_access_denied"
	errorCodeTransient         = "aws_transient"
	errorCodeUnexpected        = "unexpected"
)

type errorFormat string

const (
	errorFormatHuman errorFormat = "human"
	errorFormatJSON  errorFormat = "json"
)

var errorFormatValue errorFormat = errorFormatHuman

func (value *errorFormat) String() string { return string(*value) }

func (value *errorFormat) Set(raw string) error {
	switch errorFormat(raw) {
	case errorFormatHuman, errorFormatJSON:
		*value = errorFormat(raw)
		return nil
	default:
		return errors.New(`must be one of "human" or "json"`)
	}
}

func (value *errorFormat) Type() string { return "human|json" }

type classifiedError struct {
	Code        string `json:"code"`
	Message     string `json:"message"`
	Operation   string `json:"operation,omitempty"`
	Retryable   bool   `json:"retryable"`
	RequestID   string `json:"request_id,omitempty"`
	Remediation string `json:"remediation"`
	ExitCode    int    `json:"-"`
}

type errorKind int

const (
	errorKindInvocation errorKind = iota
	errorKindCredentials
	errorKindExecutionTimeout
	errorKindExecutionCanceled
	errorKindRetryExhausted
)

type commandError struct {
	kind       errorKind
	operation  string
	timeout    time.Duration
	maxRetries int
	err        error
}

func (err *commandError) Error() string { return err.err.Error() }
func (err *commandError) Unwrap() error { return err.err }

func newInvalidInvocationError(err error) error {
	return &commandError{kind: errorKindInvocation, err: err}
}

func newCredentialsError(operation string, err error) error {
	return &commandError{kind: errorKindCredentials, operation: operation, err: err}
}

func newExecutionTimeoutError(timeout time.Duration, err error) error {
	return &commandError{
		kind: errorKindExecutionTimeout, timeout: timeout,
		err: fmt.Errorf("AWS execution exceeded --timeout %s: %w", timeout, err),
	}
}

func newExecutionCanceledError(err error) error {
	return &commandError{kind: errorKindExecutionCanceled, err: fmt.Errorf("AWS execution canceled: %w", err)}
}

func newRetryExhaustedError(maxRetries int, err error) error {
	return &commandError{
		kind: errorKindRetryExhausted, maxRetries: maxRetries,
		err: fmt.Errorf(
			"AWS request exhausted --max-retries %d (%d total attempts): %w",
			maxRetries,
			maxRetries+1,
			err,
		),
	}
}

func init() {
	rootCmd.PersistentFlags().Var(
		&errorFormatValue,
		"error-format",
		`error output format on stderr: "human" or "json"`,
	)
	rootCmd.SetFlagErrorFunc(func(_ *cobra.Command, err error) error {
		return newInvalidInvocationError(err)
	})
}

func classifyError(err error) classifiedError {
	var ssoErr *ssoRemediationError
	if errors.As(err, &ssoErr) {
		diagnostic := classifyError(ssoErr.err)
		diagnostic.Code = errorCodeCredentials
		diagnostic.Message = fmt.Sprintf(
			"AWS IAM Identity Center (SSO) credentials for profile %q are missing or expired.",
			ssoErr.profile,
		)
		diagnostic.Retryable = false
		diagnostic.Remediation = fmt.Sprintf(
			"Run aws sso login --profile=%s in an interactive terminal, then retry. Policy Scout did not run this command automatically.",
			shellQuote(ssoErr.profile),
		)
		diagnostic.ExitCode = exitCredentials
		return diagnostic
	}

	operation := operationName(err)
	requestIDValue := requestID(err)

	var commandErr *commandError
	if errors.As(err, &commandErr) {
		switch commandErr.kind {
		case errorKindInvocation:
			return classifiedError{
				Code: errorCodeInvalidInvocation, Message: commandErr.Error(), Retryable: false,
				Remediation: "Correct the command arguments and retry. Run policy-scout --help for usage.", ExitCode: exitInvocation,
			}
		case errorKindCredentials:
			innerDiagnostic := classifyError(commandErr.err)
			if innerDiagnostic.Code == errorCodeTransient {
				if innerDiagnostic.Operation == "" {
					innerDiagnostic.Operation = commandErr.operation
				}
				return innerDiagnostic
			}
			operation := operationName(commandErr.err)
			if operation == "" {
				operation = commandErr.operation
			}
			diagnostic := credentialsDiagnostic(operation)
			diagnostic.RequestID = requestID(commandErr.err)
			return diagnostic
		case errorKindExecutionTimeout:
			return classifiedError{
				Code: errorCodeTransient, Message: fmt.Sprintf("AWS execution exceeded --timeout %s.", commandErr.timeout),
				Operation: operationName(commandErr.err), Retryable: true, RequestID: requestID(commandErr.err),
				Remediation: "Increase --timeout or reduce the requested traversal scope, then retry.", ExitCode: exitTransient,
			}
		case errorKindExecutionCanceled:
			return canceledDiagnostic(operationName(commandErr.err), requestID(commandErr.err))
		case errorKindRetryExhausted:
			return classifiedError{
				Code: errorCodeTransient,
				Message: fmt.Sprintf(
					"AWS request exhausted --max-retries %d (%d total attempts).",
					commandErr.maxRetries,
					commandErr.maxRetries+1,
				),
				Operation: operationName(commandErr.err), Retryable: true, RequestID: requestID(commandErr.err),
				Remediation: "Increase --max-retries within its allowed range or retry later after checking AWS service health.",
				ExitCode:    exitTransient,
			}
		}
	}

	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		code := strings.ToLower(apiErr.ErrorCode())
		switch code {
		case "expiredtoken", "expiredtokenexception", "invalidaccesskeyid", "invalidclienttokenid", "invalidsignatureexception",
			"requestexpired", "signaturedoesnotmatch", "unrecognizedclientexception":
			diagnostic := credentialsDiagnostic(operation)
			diagnostic.RequestID = requestIDValue
			return diagnostic
		case "accessdenied", "accessdeniedexception", "authorizationerror", "forbiddenexception", "notauthorizedexception", "unauthorizedoperation":
			return classifiedError{
				Code: errorCodeAuthorization, Message: "AWS denied the Organizations request.", Operation: operation,
				Retryable: false, RequestID: requestIDValue,
				Remediation: "Grant the selected identity the required AWS Organizations read permissions, then retry.", ExitCode: exitAuthorization,
			}
		case "internalfailure", "internalservererror", "requestlimitexceeded", "serviceunavailable", "slowdown",
			"throttling", "throttlingexception", "toomanyrequestsexception":
			return transientDiagnostic(operation, requestIDValue)
		}
		if apiErr.ErrorFault() == smithy.FaultServer {
			return transientDiagnostic(operation, requestIDValue)
		}
	}

	if errors.Is(err, context.Canceled) {
		return canceledDiagnostic(operation, requestIDValue)
	}

	var networkErr net.Error
	if errors.As(err, &networkErr) || errors.Is(err, context.DeadlineExceeded) {
		return transientDiagnostic(operation, requestIDValue)
	}

	return classifiedError{
		Code: errorCodeUnexpected, Message: "Policy Scout could not complete the request.", Operation: operation,
		Retryable: false, RequestID: requestIDValue,
		Remediation: "Review the command and environment, then rerun with current credentials. Report the request ID if the failure persists.", ExitCode: exitUnexpected,
	}
}

func credentialsDiagnostic(operation string) classifiedError {
	return classifiedError{
		Code: errorCodeCredentials, Message: "AWS credentials are missing, invalid, or expired.", Operation: operation,
		Retryable:   false,
		Remediation: "Configure or refresh the selected AWS profile or credential provider, then retry.", ExitCode: exitCredentials,
	}
}

func transientDiagnostic(operation, requestID string) classifiedError {
	return classifiedError{
		Code: errorCodeTransient, Message: "AWS is temporarily unavailable or the request was throttled.", Operation: operation,
		Retryable: true, RequestID: requestID,
		Remediation: "Retry with exponential backoff. Check network connectivity and AWS service health if the failure persists.", ExitCode: exitTransient,
	}
}

func canceledDiagnostic(operation, requestID string) classifiedError {
	return classifiedError{
		Code: errorCodeUnexpected, Message: "Policy Scout execution was canceled.", Operation: operation,
		Retryable: false, RequestID: requestID,
		Remediation: "Rerun the command when ready.", ExitCode: exitUnexpected,
	}
}

func operationName(err error) string {
	var operationErr *smithy.OperationError
	if errors.As(err, &operationErr) {
		return operationErr.Operation()
	}
	return ""
}

func requestID(err error) string {
	var requestErr interface{ ServiceRequestID() string }
	if errors.As(err, &requestErr) {
		return requestErr.ServiceRequestID()
	}
	return ""
}

func writeError(writer io.Writer, diagnostic classifiedError, format errorFormat) error {
	if format == errorFormatJSON {
		return encodingjson.NewEncoder(writer).Encode(diagnostic)
	}

	if _, err := fmt.Fprintf(writer, "Error [%s]: %s\n", diagnostic.Code, diagnostic.Message); err != nil {
		return err
	}
	if diagnostic.Operation != "" {
		if _, err := fmt.Fprintf(writer, "Operation: %s\n", diagnostic.Operation); err != nil {
			return err
		}
	}
	if diagnostic.RequestID != "" {
		if _, err := fmt.Fprintf(writer, "AWS request ID: %s\n", diagnostic.RequestID); err != nil {
			return err
		}
	}
	_, err := fmt.Fprintf(writer, "Remediation: %s\n", diagnostic.Remediation)
	return err
}
