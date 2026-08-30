package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/torjan0/cirewind/internal/casegen"
)

func TestHelpAndVersion(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{name: "help", args: []string{"--help"}, want: "cirewind investigate"},
		{name: "command help", args: []string{"help", "investigate"}, want: "Parent-run discovery"},
		{name: "archive raw help", args: []string{"help", "archive"}, want: "[--raw-logs]"},
		{name: "replay raw help", args: []string{"help", "replay"}, want: "[--raw-logs]"},
		{name: "demo help", args: []string{"help", "demo"}, want: "without credentials or"},
		{name: "pack validate help", args: []string{"help", "pack"}, want: "declarative incident pack"},
		{name: "version", args: []string{"version"}, want: "cirewind dev"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var out, errOut bytes.Buffer
			if code := Run(context.Background(), tc.args, &out, &errOut); code != 0 {
				t.Fatalf("Run() code = %d, stderr = %q", code, errOut.String())
			}
			if !strings.Contains(out.String(), tc.want) {
				t.Fatalf("stdout %q does not contain %q", out.String(), tc.want)
			}
		})
	}
}

func TestCLIErrorBoundaryRedactsInjectedPrivateStagingPath(t *testing.T) {
	t.Parallel()
	parent := t.TempDir()
	staging := filepath.Join(parent, ".cirewind-case-injected-private-name")
	injected := fmt.Errorf("generate synthetic demo: inspect %s: permission denied", filepath.Join(staging, "report.html"))
	var stderr bytes.Buffer
	if code := writeCLIError(&stderr, injected); code != 1 {
		t.Fatalf("injected operational failure exit=%d stderr=%q", code, stderr.String())
	}
	diagnostic := stderr.String()
	if strings.Contains(diagnostic, filepath.Base(staging)) || strings.Contains(diagnostic, staging) || strings.Contains(diagnostic, parent) {
		t.Fatalf("CLI diagnostic exposed private staging path: %q", diagnostic)
	}
	if !strings.Contains(diagnostic, "case operation failed in private staging") || !strings.Contains(diagnostic, "private path withheld") {
		t.Fatalf("CLI diagnostic lost safe operational context: %q", diagnostic)
	}
}

func TestCLIErrorBoundaryPreservesCleanupFailureAfterCancellation(t *testing.T) {
	t.Parallel()
	privateFailure := fmt.Errorf("%w: remove /private/.cirewind-case-random", casegen.ErrStagedCaseCleanup)
	var stderr bytes.Buffer
	if code := writeCLIError(&stderr, errors.Join(context.Canceled, privateFailure)); code != 130 {
		t.Fatalf("cancellation exit=%d stderr=%q", code, stderr.String())
	}
	diagnostic := stderr.String()
	if !strings.Contains(diagnostic, "operation canceled") || !strings.Contains(diagnostic, "cleanup also failed") {
		t.Fatalf("cancellation hid cleanup failure: %q", diagnostic)
	}
	if strings.Contains(diagnostic, ".cirewind-case-") || strings.Contains(diagnostic, "/private") {
		t.Fatalf("cancellation diagnostic exposed private staging: %q", diagnostic)
	}
}

func TestTerminalValuePreservesLegitimateStagingLikeOutputName(t *testing.T) {
	t.Parallel()
	input := filepath.Join("review", ".cirewind-case-legitimate")
	if got := sanitizeTerminalValue(input); got != input {
		t.Fatalf("successful output path = %q, want %q", got, input)
	}
}

func TestCommandHelpDocumentsRegisteredFlags(t *testing.T) {
	t.Parallel()
	tests := []struct {
		command string
		flags   []string
	}{
		{command: "investigate", flags: []string{"-concurrency", "-from", "-incident", "-org", "-out", "-quiet", "-raw-logs", "-repo", "-to", "-verbose"}},
		{command: "archive", flags: []string{"-concurrency", "-from", "-import-fixture", "-org", "-quiet", "-raw-logs", "-repo", "-since", "-store", "-to", "-verbose"}},
		{command: "replay", flags: []string{"-archive", "-fixed-collection-time", "-incident", "-out", "-raw-logs"}},
		{command: "demo", flags: []string{"-out"}},
	}
	for _, test := range tests {
		t.Run(test.command, func(t *testing.T) {
			t.Parallel()
			var stdout, stderr bytes.Buffer
			if code := Run(context.Background(), []string{test.command, "--help"}, &stdout, &stderr); code != 0 {
				t.Fatalf("Run() code = %d, stderr = %q", code, stderr.String())
			}
			for _, name := range test.flags {
				if !strings.Contains(stdout.String(), name) {
					t.Errorf("help omitted registered flag %s:\n%s", name, stdout.String())
				}
			}
			if !strings.Contains(stdout.String(), "Flags:") {
				t.Errorf("help omitted flag section:\n%s", stdout.String())
			}
		})
	}
}

func TestDemoHelpFormsAreIdenticalAndExposeOnlyOut(t *testing.T) {
	t.Parallel()
	var direct, directErr, topic, topicErr bytes.Buffer
	if code := Run(context.Background(), []string{"demo", "--help"}, &direct, &directErr); code != 0 {
		t.Fatalf("demo --help code=%d stderr=%q", code, directErr.String())
	}
	if code := Run(context.Background(), []string{"help", "demo"}, &topic, &topicErr); code != 0 {
		t.Fatalf("help demo code=%d stderr=%q", code, topicErr.String())
	}
	if directErr.Len() != 0 || topicErr.Len() != 0 {
		t.Fatalf("help wrote stderr: direct=%q topic=%q", directErr.String(), topicErr.String())
	}
	if direct.String() != topic.String() {
		t.Fatalf("help forms differ:\ndemo --help:\n%s\nhelp demo:\n%s", direct.String(), topic.String())
	}
	help := direct.String()
	for _, text := range []string{
		"Usage:\n  cirewind demo --out CASE_DIR",
		"without credentials or\nnetwork access",
		"The destination must not already exist",
		"No raw logs are retained",
		"  -out string",
		"new synthetic case output directory",
	} {
		if !strings.Contains(help, text) {
			t.Errorf("demo help omitted %q:\n%s", text, help)
		}
	}
	for _, forbidden := range []string{
		"-force", "-raw-logs", "-incident", "-archive", "-fixture", "-token",
		"-browser", "-clock", "-count", "-from", "-to", "-repo", "-org",
	} {
		if strings.Contains(help, forbidden) {
			t.Errorf("demo help exposes prohibited flag %q:\n%s", forbidden, help)
		}
	}
}

func TestDemoUsageErrorsUseExitCodeTwo(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		args []string
	}{
		{name: "missing out", args: []string{"demo"}},
		{name: "missing out value", args: []string{"demo", "--out"}},
		{name: "empty out equals", args: []string{"demo", "--out="}},
		{name: "ASCII whitespace out", args: []string{"demo", "--out", " \t\r\n"}},
		{name: "Unicode whitespace out", args: []string{"demo", "--out", "\u2003\u00a0"}},
		{name: "positional only", args: []string{"demo", "case"}},
		{name: "positional after out", args: []string{"demo", "--out", "case", "extra"}},
		{name: "unknown flag", args: []string{"demo", "--not-a-demo-flag"}},
	}
	for _, flagName := range []string{
		"force", "raw-logs", "incident", "archive", "fixture", "token", "browser",
		"clock", "count", "from", "to", "repo", "org", "fixed-collection-time",
	} {
		tests = append(tests, struct {
			name string
			args []string
		}{name: "prohibited --" + flagName, args: []string{"demo", "--" + flagName + "=synthetic-value", "--out", "case"}})
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var out, errOut bytes.Buffer
			if code := Run(context.Background(), tc.args, &out, &errOut); code != 2 {
				t.Fatalf("Run(%q) code = %d, stdout = %q, stderr = %q", tc.args, code, out.String(), errOut.String())
			}
			if out.Len() != 0 {
				t.Fatalf("invalid demo syntax wrote stdout %q", out.String())
			}
			if !strings.HasPrefix(errOut.String(), "cirewind: ") {
				t.Fatalf("invalid demo syntax emitted malformed diagnostic %q", errOut.String())
			}
		})
	}
}

func TestRootHelpDescribesDemoAsOfflineAndCredentialFree(t *testing.T) {
	t.Parallel()
	var stdout, stderr bytes.Buffer
	if code := Run(context.Background(), []string{"--help"}, &stdout, &stderr); code != 0 {
		t.Fatalf("root help code=%d stderr=%q", code, stderr.String())
	}
	for _, phrase := range []string{
		"cirewind demo --out CASE_DIR   generate a verified synthetic case offline",
		"the demo make no network\nrequests",
	} {
		if !strings.Contains(stdout.String(), phrase) {
			t.Errorf("root help omitted %q:\n%s", phrase, stdout.String())
		}
	}
}

func TestDemoFlagParserDoesNotWriteHostileTokenDirectly(t *testing.T) {
	t.Parallel()
	input := "--bad\x1b[2J\nforged\u202e\u2066" + strings.Repeat("x", maxCLIDiagnosticBytes*2)
	var out, errOut bytes.Buffer
	if code := Run(context.Background(), []string{"demo", input}, &out, &errOut); code != 2 {
		t.Fatalf("Run() code=%d stdout=%q stderr=%q", code, out.String(), errOut.String())
	}
	diagnostic := errOut.String()
	if strings.Contains(diagnostic, "\x1b") || strings.Contains(diagnostic, "\nforged") || strings.ContainsAny(diagnostic, "\u202e\u2066") {
		t.Fatalf("flag parser emitted an unsafe diagnostic %q", diagnostic)
	}
	if len(diagnostic) > maxCLIDiagnosticBytes+len("cirewind: \n") {
		t.Fatalf("flag diagnostic has %d bytes", len(diagnostic))
	}
}

func TestDemoFlagDiagnosticsRemainSingleLineAndBounded(t *testing.T) {
	t.Parallel()
	tests := []string{
		"--out=case\x1b[2J\nforged\u202e\u2066" + strings.Repeat("x", maxCLIDiagnosticBytes*2),
		"--unknown\r\nforged=\x1b]8;;https://example.invalid\a",
	}
	for index, input := range tests {
		t.Run(fmt.Sprintf("hostile-%d", index), func(t *testing.T) {
			t.Parallel()
			var stdout, stderr bytes.Buffer
			if code := Run(context.Background(), []string{"demo", input, "positional"}, &stdout, &stderr); code != 2 {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
			}
			diagnostic := stderr.String()
			if strings.ContainsAny(diagnostic, "\x1b\r") || strings.Contains(diagnostic, "\nforged") || strings.ContainsAny(diagnostic, "\u202e\u2066") {
				t.Fatalf("unsafe diagnostic %q", diagnostic)
			}
			if strings.Count(diagnostic, "\n") != 1 || len(diagnostic) > maxCLIDiagnosticBytes+len("cirewind: \n") {
				t.Fatalf("diagnostic is not one bounded line: bytes=%d value=%q", len(diagnostic), diagnostic)
			}
		})
	}
}

func TestUsageErrorUsesExitCodeTwo(t *testing.T) {
	t.Parallel()
	var out, errOut bytes.Buffer
	if code := Run(context.Background(), []string{"verify"}, &out, &errOut); code != 2 {
		t.Fatalf("Run() code = %d, stderr = %q", code, errOut.String())
	}
}

func TestVerifyRejectsEmptyManifestAsIncompleteCase(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "manifest.sha256"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	if code := Run(context.Background(), []string{"verify", dir}, &out, &errOut); code != 1 {
		t.Fatalf("Run() code = %d, stdout = %q, stderr = %q", code, out.String(), errOut.String())
	}
	if strings.Contains(out.String(), "verified") || !strings.Contains(errOut.String(), "required case file") {
		t.Fatalf("unexpected verify output stdout=%q stderr=%q", out.String(), errOut.String())
	}
}

func TestUnknownCommandSanitizesDiagnostic(t *testing.T) {
	t.Parallel()
	var out, errOut bytes.Buffer
	input := "bad\x1b[2J\nname\u202e\u2066" + strings.Repeat("x", maxCLIDiagnosticBytes*2)
	if code := Run(context.Background(), []string{input}, &out, &errOut); code != 2 {
		t.Fatalf("Run() code = %d", code)
	}
	if strings.Contains(errOut.String(), "\x1b") || strings.Contains(errOut.String(), "\nname") ||
		strings.ContainsAny(errOut.String(), "\u202e\u2066") {
		t.Fatalf("unsafe diagnostic %q", errOut.String())
	}
	if got := sanitizeDiagnostic(input); len(got) > maxCLIDiagnosticBytes {
		t.Fatalf("sanitized diagnostic has %d bytes, max %d", len(got), maxCLIDiagnosticBytes)
	}
}
