package cmd

import (
	"bytes"
	encodingjson "encoding/json"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestNoArgsValidatorClassifiesExtraArgsAsInvalidInvocation(t *testing.T) {
	t.Parallel()

	cmd := &cobra.Command{Use: "test"}
	if err := noArgsValidator(cmd, nil); err != nil {
		t.Fatalf("noArgsValidator with no args returned error: %v", err)
	}
	err := noArgsValidator(cmd, []string{"extra"})
	if err == nil {
		t.Fatal("expected error for extra positional argument")
	}
	diagnostic := classifyError(err)
	if diagnostic.Code != errorCodeInvalidInvocation || diagnostic.ExitCode != exitInvocation {
		t.Fatalf("diagnostic = %#v, want code %q and exit %d", diagnostic, errorCodeInvalidInvocation, exitInvocation)
	}
}

// TestExtraPositionalArgumentsProduceInvalidInvocation runs the real command
// tree through executeCommand so the silence/usage/error contract exercised by
// the binary is honored end to end. Extra positional arguments to root, aws,
// aws auth status, and version must all surface invalid_invocation with exit
// code 2, no stdout, and a formatted stderr diagnostic.
func TestExtraPositionalArgumentsProduceInvalidInvocation(t *testing.T) {
	cases := map[string][]string{
		"root":            {"unexpected"},
		"aws":             {"aws", "unexpected"},
		"aws auth status": {"aws", "auth", "status", "unexpected"},
		"version":         {"version", "unexpected"},
	}

	t.Run("human", func(t *testing.T) {
		for name, args := range cases {
			name, args := name, args
			t.Run(name, func(t *testing.T) {
				stdout, stderr, exitCode := runWithExtraArgs(t, args, errorFormatHuman)
				if exitCode != exitInvocation {
					t.Fatalf("exit code = %d, want %d (stdout=%q stderr=%q)", exitCode, exitInvocation, stdout, stderr)
				}
				if stdout != "" {
					t.Fatalf("stdout = %q, want empty", stdout)
				}
				if !strings.Contains(stderr, "Error [invalid_invocation]:") {
					t.Fatalf("stderr = %q, want it to contain %q", stderr, "Error [invalid_invocation]:")
				}
				if !strings.Contains(stderr, "Remediation:") {
					t.Fatalf("stderr missing remediation: %q", stderr)
				}
			})
		}
	})

	t.Run("json", func(t *testing.T) {
		for name, args := range cases {
			name, args := name, args
			t.Run(name, func(t *testing.T) {
				stdout, stderr, exitCode := runWithExtraArgs(t, args, errorFormatJSON)
				if exitCode != exitInvocation {
					t.Fatalf("exit code = %d, want %d (stdout=%q stderr=%q)", exitCode, exitInvocation, stdout, stderr)
				}
				if stdout != "" {
					t.Fatalf("stdout = %q, want empty", stdout)
				}
				var diagnostic classifiedError
				if err := encodingjson.Unmarshal([]byte(stderr), &diagnostic); err != nil {
					t.Fatalf("stderr is not valid JSON: %q: %v", stderr, err)
				}
				if diagnostic.Code != errorCodeInvalidInvocation {
					t.Fatalf("JSON error code = %q, want %q", diagnostic.Code, errorCodeInvalidInvocation)
				}
				if diagnostic.Remediation == "" {
					t.Fatalf("JSON error missing remediation: %s", stderr)
				}
			})
		}
	})
}

func runWithExtraArgs(t *testing.T, args []string, format errorFormat) (string, string, int) {
	t.Helper()

	previousFormat := errorFormatValue
	errorFormatValue = format
	t.Cleanup(func() { errorFormatValue = previousFormat })

	// executeCommand mutates rootCmd's output and args; restore them so other
	// tests that use the global command tree are unaffected.
	rootCmd.SetOut(nil)
	rootCmd.SetErr(nil)
	t.Cleanup(func() {
		rootCmd.SetOut(nil)
		rootCmd.SetErr(nil)
		rootCmd.SetArgs(nil)
	})

	var stdout, stderr bytes.Buffer
	exitCode := executeCommand(rootCmd, args, &stdout, &stderr)
	return stdout.String(), stderr.String(), exitCode
}

func TestExtraPositionalArgumentsDoNotReachCommandRun(t *testing.T) {
	t.Parallel()

	commands := map[string]*cobra.Command{
		"root":            rootCmd,
		"aws":             awsCmd,
		"aws auth status": authStatusCmd,
		"version":         versionCmd,
	}
	for name, command := range commands {
		name, command := name, command
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if err := command.Args(command, []string{"unexpected"}); err == nil {
				t.Fatal("expected Args validator to reject extra positional arguments")
			}
			if err := command.Args(command, nil); err != nil {
				t.Fatalf("expected Args validator to accept no args, got: %v", err)
			}
		})
	}
}
