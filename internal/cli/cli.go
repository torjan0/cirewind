// Package cli defines CIRewind's command-line contract.
package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/torjan0/cirewind/internal/buildinfo"
	"github.com/torjan0/cirewind/internal/sanitize"
)

const maxCLIDiagnosticBytes = 4096

const usage = `CIRewind reconstructs historical GitHub Actions execution evidence.

Usage:
  cirewind investigate [flags]   collect GitHub-hosted incident evidence
  cirewind archive [flags]       preserve a compact execution ledger
  cirewind replay [flags]        apply an incident pack to an archive offline
  cirewind demo --out CASE_DIR   generate a verified synthetic case offline
  cirewind pack validate FILE    validate an incident pack offline
  cirewind verify CASE_DIR       verify a case manifest offline
  cirewind version               print build version
  cirewind help [command]        show help

GitHub authentication for networked commands is read, in order, from
CIREWIND_GITHUB_TOKEN, GITHUB_TOKEN, then GH_TOKEN. Tokens are never printed or
stored. Pack validation, replay, verification, and the demo make no network
requests.
`

// Run executes the CLI and returns a process exit code.
func Run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	return runWithDependencies(ctx, args, stdout, stderr, productionCommandDependencies())
}

func runWithDependencies(ctx context.Context, args []string, stdout, stderr io.Writer, dependencies commandDependencies) int {
	if len(args) == 0 {
		fmt.Fprint(stdout, usage)
		return 0
	}

	var err error
	switch args[0] {
	case "help":
		if len(args) == 1 {
			fmt.Fprint(stdout, usage)
			return 0
		}
		if len(args) != 2 {
			fmt.Fprintln(stderr, "cirewind: help accepts at most one command")
			return 2
		}
		switch args[1] {
		case "investigate", "archive", "replay", "demo", "pack", "verify":
			err = runCommandWithDependencies(ctx, []string{args[1], "--help"}, stdout, stdout, dependencies)
		case "version":
			fmt.Fprintln(stdout, "Usage:\n  cirewind version\n\nPrints the build version, source revision, and build time.")
			return 0
		default:
			fmt.Fprintf(stderr, "cirewind: unknown help topic %q\n", sanitizeDiagnostic(args[1]))
			return 2
		}
	case "--help", "-h":
		fmt.Fprint(stdout, usage)
		return 0
	case "version", "--version":
		fmt.Fprintf(stdout, "cirewind %s (commit %s, built %s)\n", buildinfo.Version, buildinfo.Commit, buildinfo.Date)
		return 0
	case "investigate", "archive", "replay", "demo", "pack", "verify":
		commandErrors := stderr
		if len(args) == 2 && (args[1] == "--help" || args[1] == "-h") {
			commandErrors = stdout
		}
		err = runCommandWithDependencies(ctx, args, stdout, commandErrors, dependencies)
	default:
		fmt.Fprintf(stderr, "cirewind: unknown command %q\n\n%s", sanitizeDiagnostic(args[0]), usage)
		return 2
	}

	return writeCLIError(stderr, err)
}

func writeCLIError(stderr io.Writer, err error) int {
	if err == nil {
		return 0
	}
	if errors.Is(err, flag.ErrHelp) {
		return 0
	}
	if errors.Is(err, errUsage) {
		fmt.Fprintf(stderr, "cirewind: %s\n", sanitizeDiagnostic(err.Error()))
		return 2
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		fmt.Fprintln(stderr, "cirewind: operation canceled")
		return 130
	}
	fmt.Fprintf(stderr, "cirewind: %s\n", sanitizeDiagnostic(err.Error()))
	return 1
}

func sanitizeDiagnostic(value string) string {
	if strings.Contains(value, ".cirewind-case-") {
		// A post-builder filesystem or SQLite error may include the randomized
		// owner-only staging path. Keep a useful operational category without
		// publishing private path or temporary-parent details to the terminal.
		value = "case operation failed in private staging; private path withheld"
	}
	return sanitize.Terminal(value, maxCLIDiagnosticBytes)
}
