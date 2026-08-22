package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
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

func TestCommandHelpDocumentsRegisteredFlags(t *testing.T) {
	t.Parallel()
	tests := []struct {
		command string
		flags   []string
	}{
		{command: "investigate", flags: []string{"-concurrency", "-from", "-incident", "-org", "-out", "-quiet", "-raw-logs", "-repo", "-to", "-verbose"}},
		{command: "archive", flags: []string{"-concurrency", "-from", "-import-fixture", "-org", "-quiet", "-raw-logs", "-repo", "-since", "-store", "-to", "-verbose"}},
		{command: "replay", flags: []string{"-archive", "-fixed-collection-time", "-incident", "-out", "-raw-logs"}},
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
