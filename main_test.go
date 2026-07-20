package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

const contractTestVersion = "process-contract-test"

const processTimeout = 10 * time.Second

var contractTestBinary string

func TestMain(m *testing.M) {
	buildDir, err := os.MkdirTemp("", "policy-scout-contract-test-")
	if err != nil {
		fmt.Fprintf(os.Stderr, "create contract test build directory: %v\n", err)
		os.Exit(1)
	}

	binaryName := "policy-scout"
	if runtime.GOOS == "windows" {
		binaryName += ".exe"
	}
	contractTestBinary = filepath.Join(buildDir, binaryName)
	// The test intentionally executes the Go toolchain to build the process under test.
	build := exec.Command( //nolint:gosec
		"go", "build",
		"-ldflags", "-X github.com/ariguillegp/policy-scout/cmd.version="+contractTestVersion,
		"-o", contractTestBinary,
		".",
	)
	if output, buildErr := build.CombinedOutput(); buildErr != nil {
		fmt.Fprintf(os.Stderr, "build policy-scout for contract tests: %v\n%s", buildErr, output)
		_ = os.RemoveAll(buildDir)
		os.Exit(1)
	}

	exitCode := m.Run()
	if removeErr := os.RemoveAll(buildDir); removeErr != nil {
		fmt.Fprintf(os.Stderr, "remove contract test build directory: %v\n", removeErr)
		if exitCode == 0 {
			exitCode = 1
		}
	}
	os.Exit(exitCode)
}

func TestRootNoArgumentsMatchesRootHelp(t *testing.T) {
	noArgs := runCLI(t)
	help := runCLI(t, "--help")

	assertSuccessfulProcess(t, noArgs, "no arguments")
	assertSuccessfulProcess(t, help, "root help")
	if noArgs.stdout != help.stdout {
		t.Fatalf("no-argument stdout differs from --help\nno arguments:\n%s\n--help:\n%s", noArgs.stdout, help.stdout)
	}
	for _, expected := range []string{
		"Inspect cloud organization policies from one CLI",
		"Usage:\n  policy-scout [flags]\n  policy-scout [command]",
		"Show AWS paths and localized SCP attachments",
		"Print binary and JSON schema versions",
		"--error-format",
	} {
		if !strings.Contains(help.stdout, expected) {
			t.Errorf("root help does not contain %q:\n%s", expected, help.stdout)
		}
	}
}

func TestAWSSubcommandHelpIsPublicAndAWSFree(t *testing.T) {
	result := runCLI(t, "aws", "--help")

	assertSuccessfulProcess(t, result, "AWS help")
	for _, expected := range []string{
		"Usage:\n  policy-scout aws (--account-id <12-digit-id|all> | --ou-id <ou-id>) [flags]",
		"--account-id",
		"--ou-id",
		"--output-format",
		"--profile",
		"--timeout",
		"Inspect AWS authentication",
	} {
		if !strings.Contains(result.stdout, expected) {
			t.Errorf("AWS help does not contain %q:\n%s", expected, result.stdout)
		}
	}
}

func TestInvalidInvocationsUseStderrAndStableExitStatuses(t *testing.T) {
	tests := []struct {
		name            string
		args            []string
		wantStatus      int
		wantCode        string
		wantMessagePart string
	}{
		{
			name: "unknown command", args: []string{"unknown"}, wantStatus: 2,
			wantCode: "invalid_invocation", wantMessagePart: "unknown",
		},
		{
			name: "unknown flag", args: []string{"--unknown"}, wantStatus: 2,
			wantCode: "invalid_invocation", wantMessagePart: "--unknown",
		},
		{
			name: "extra AWS positional argument",
			args: []string{"aws", "--account-id", "123456789012", "extra"}, wantStatus: 2,
			wantCode: "invalid_invocation", wantMessagePart: "extra",
		},
		{
			name: "empty OU ID",
			args: []string{"aws", "--ou-id="}, wantStatus: 2,
			wantCode: "invalid_invocation", wantMessagePart: "--ou-id",
		},
		{
			name: "empty account ID",
			args: []string{"aws", "--account-id="}, wantStatus: 2,
			wantCode: "invalid_invocation", wantMessagePart: "--account-id",
		},
		{
			name: "both AWS target flags including empty OU",
			args: []string{"aws", "--account-id", "123456789012", "--ou-id="}, wantStatus: 2,
			wantCode: "invalid_invocation", wantMessagePart: "mutually exclusive",
		},
		{
			name: "empty account ID and OU ID",
			args: []string{"aws", "--account-id=", "--ou-id", "ou-abcd-12345678"}, wantStatus: 2,
			wantCode: "invalid_invocation", wantMessagePart: "mutually exclusive",
		},
		{
			// Extra positional arguments to version are classified as invalid_invocation,
			// matching root, aws, and aws auth status.
			name: "extra version positional argument", args: []string{"version", "extra"}, wantStatus: 2,
			wantCode: "invalid_invocation", wantMessagePart: "unknown",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			args := append([]string{"--error-format", "json"}, test.args...)
			result := runCLI(t, args...)
			if result.status != test.wantStatus {
				t.Fatalf("exit status = %d, want %d\nstderr: %s", result.status, test.wantStatus, result.stderr)
			}
			if result.stdout != "" {
				t.Fatalf("stdout contains error output: %q", result.stdout)
			}

			var diagnostic struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			}
			if err := json.Unmarshal([]byte(result.stderr), &diagnostic); err != nil {
				t.Fatalf("stderr is not a JSON diagnostic: %q: %v", result.stderr, err)
			}
			if diagnostic.Code != test.wantCode || !strings.Contains(diagnostic.Message, test.wantMessagePart) {
				t.Fatalf("diagnostic = %#v, want code %q and message containing %q", diagnostic, test.wantCode, test.wantMessagePart)
			}
		})
	}
}

func TestVersionTextAndJSON(t *testing.T) {
	t.Run("text", func(t *testing.T) {
		result := runCLI(t, "version")
		assertSuccessfulProcess(t, result, "text version")
		if result.stdout != "policy-scout "+contractTestVersion+"\n" {
			t.Fatalf("stdout = %q, want embedded version text", result.stdout)
		}
	})

	t.Run("JSON", func(t *testing.T) {
		result := runCLI(t, "version", "--output-format", "json")
		assertSuccessfulProcess(t, result, "JSON version")

		var info struct {
			Version                   string `json:"version"`
			OrganizationSchemaVersion string `json:"organization_schema_version"`
		}
		if err := json.Unmarshal([]byte(result.stdout), &info); err != nil {
			t.Fatalf("stdout is not version JSON: %q: %v", result.stdout, err)
		}
		if info.Version != contractTestVersion || info.OrganizationSchemaVersion != "1" {
			t.Fatalf("version JSON = %#v, want version %q and organization schema version 1", info, contractTestVersion)
		}
	})
}

func TestMissingAWSCredentialsAreClassifiedWithoutDeveloperCredentials(t *testing.T) {
	result := runCLI(t, "--error-format", "json", "aws", "--account-id", "123456789012")
	if result.status != 3 {
		t.Fatalf("exit status = %d, want 3\nstderr: %s", result.status, result.stderr)
	}
	if result.stdout != "" {
		t.Fatalf("stdout contains error output: %q", result.stdout)
	}

	var diagnostic struct {
		Code      string `json:"code"`
		Retryable bool   `json:"retryable"`
	}
	if err := json.Unmarshal([]byte(result.stderr), &diagnostic); err != nil {
		t.Fatalf("stderr is not a JSON diagnostic: %q: %v", result.stderr, err)
	}
	if diagnostic.Code != "aws_credentials" || diagnostic.Retryable {
		t.Fatalf("diagnostic = %#v, want non-retryable aws_credentials", diagnostic)
	}
}

type processResult struct {
	status int
	stdout string
	stderr string
}

func runCLI(t *testing.T, args ...string) processResult {
	t.Helper()

	home := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), processTimeout)
	defer cancel()

	// The binary path is generated by TestMain, and arguments are fixed by each test.
	command := exec.CommandContext(ctx, contractTestBinary, args...) //nolint:gosec
	command.Env = []string{
		"HOME=" + home,
		"AWS_CONFIG_FILE=" + filepath.Join(home, "config"),
		"AWS_SHARED_CREDENTIALS_FILE=" + filepath.Join(home, "credentials"),
		"AWS_EC2_METADATA_DISABLED=true",
	}
	var stdout, stderr strings.Builder
	command.Stdout = &stdout
	command.Stderr = &stderr

	err := command.Run()
	if ctx.Err() != nil {
		t.Fatalf("policy-scout %q did not finish within %s: %v", args, processTimeout, ctx.Err())
	}
	status := 0
	if err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			t.Fatalf("execute policy-scout: %v", err)
		}
		status = exitErr.ExitCode()
	}
	return processResult{status: status, stdout: stdout.String(), stderr: stderr.String()}
}

func assertSuccessfulProcess(t *testing.T, result processResult, description string) {
	t.Helper()
	if result.status != 0 || result.stderr != "" {
		t.Fatalf(
			"%s: exit status = %d, stderr = %q; want status 0 and empty stderr",
			description, result.status, result.stderr,
		)
	}
}
