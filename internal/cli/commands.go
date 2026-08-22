package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"path/filepath"

	"github.com/torjan0/cirewind/internal/casefile"
	"github.com/torjan0/cirewind/internal/incident"
)

func runCommand(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	switch args[0] {
	case "pack":
		return runPack(ctx, args[1:], stdout)
	case "verify":
		return runVerify(ctx, args[1:], stdout)
	case "investigate":
		return runInvestigate(ctx, args[1:], stdout, stderr)
	case "archive":
		return runArchive(ctx, args[1:], stdout, stderr)
	case "replay":
		return runReplay(ctx, args[1:], stdout, stderr)
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

const packUsage = `Usage:
  cirewind pack validate FILE

Validates one declarative incident pack without network access. Validation is
strict, deterministic, and does not follow URLs or execute pack content.
`

func runPack(ctx context.Context, args []string, stdout io.Writer) error {
	if (len(args) == 1 && (args[0] == "--help" || args[0] == "-h")) ||
		(len(args) == 2 && args[0] == "validate" && (args[1] == "--help" || args[1] == "-h")) {
		fmt.Fprint(stdout, packUsage)
		return nil
	}
	if len(args) != 2 || args[0] != "validate" {
		return fmt.Errorf("%w: expected `cirewind pack validate FILE`", errUsage)
	}
	path := filepath.Clean(args[1])
	f, err := openRegular(path)
	if err != nil {
		return fmt.Errorf("open incident pack: %w", err)
	}
	defer f.Close()
	validated, err := incident.ValidateReader(ctx, f)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "valid incident pack %s (%s)\ncanonical sha256: %s\nsource sha256: %s\n",
		validated.Pack.Metadata.ID, validated.Pack.Metadata.PackVersion,
		validated.CanonicalSHA256, validated.OriginalSHA256)
	return nil
}

const verifyUsage = `Usage:
  cirewind verify CASE_DIR

Verifies the SHA-256 manifest and exact file set without GitHub access. This is
an integrity check, not an authenticity signature or legal certification.
`

func runVerify(ctx context.Context, args []string, stdout io.Writer) error {
	if len(args) == 1 && (args[0] == "--help" || args[0] == "-h") {
		fmt.Fprint(stdout, verifyUsage)
		return nil
	}
	if len(args) != 1 {
		return fmt.Errorf("%w: expected `cirewind verify CASE_DIR`", errUsage)
	}
	if err := casefile.VerifyManifest(ctx, args[0]); err != nil {
		return fmt.Errorf("case verification failed: %w", err)
	}
	fmt.Fprintln(stdout, "case manifest verified")
	return nil
}

var errUsage = errors.New("invalid command usage")
