// Command publiclab builds, verifies, and operates the inert exportable
// CIRewind public laboratory. It is maintainer tooling, not part of cirewind.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/torjan0/cirewind/internal/publiclab"
	"github.com/torjan0/cirewind/internal/sanitize"
)

const usage = `Usage:
  publiclab build --source DIR --out DIR [--repository OWNER/REPO]
  publiclab verify --source DIR --artifact-dir DIR
  publiclab validate-record --schema-dir DIR --kind KIND --record FILE [--source DIR --artifact-dir DIR] [--pack-input-record FILE] [--run-record FILE]
  publiclab render-pack-input --source DIR --schema-dir DIR --artifact-dir DIR --install-record FILE --restore-record FILE --created-at TIME --out FILE
  publiclab render-pack --source DIR --schema-dir DIR --artifact-dir DIR --record FILE --install-record FILE --restore-record FILE --record-source-url URL --record-source-worktree DIR --out FILE [--git PATH]
  publiclab plan-v1 --worktree DIR --repository OWNER/REPO --assert-repository-id ID --remote URL --reviewed-main SHA --commit-a SHA --commit-b SHA --fixture-a-tag-object SHA --fixture-b-tag-object SHA --expected-old SHA --new-target SHA --ack TEXT
  publiclab move-v1 [plan-v1 flags] --observation-out FILE [--git PATH]

Record kinds are tag-move-record, pack-input-record, run-record, reproduction-record,
reproductions-index, and expected-findings-seed. Pack-input, run, and reproduction records require --source and
--artifact-dir so validation is bound to the regenerated reviewed artifact.

build, verify, validate-record, render-pack-input, render-pack, and plan-v1
perform no network requests and never execute embedded Action code. move-v1 is
the only command that contacts an explicitly supplied Git remote. It accepts
only the reviewed refs/tags/v1 A-to-B or B-to-A transition and requires an exact
acknowledgement. Its isolated Git boundary discards credential helpers and
prompts, so SSH is the practical authenticated production transport; an HTTPS
push has no credential source and fails closed before any ref changes. The
database ID flag is an operator assertion that must later
match GitHub API/run evidence; the Git transport cannot independently observe
it. Output never prints the remote URL. A failed record write or unsafe B
readback prints the derived B-to-A recovery acknowledgement.
`

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		_, _ = io.WriteString(stdout, usage)
		return 0
	}
	var (
		message string
		err     error
	)
	switch args[0] {
	case "build":
		message, err = runBuild(ctx, args[1:])
	case "verify":
		message, err = runVerify(ctx, args[1:])
	case "validate-record":
		message, err = runValidateRecord(ctx, args[1:])
	case "render-pack-input":
		message, err = runRenderPackInput(ctx, args[1:])
	case "render-pack":
		message, err = runRenderPack(ctx, args[1:])
	case "plan-v1":
		message, err = runPlanV1(ctx, args[1:])
	case "move-v1":
		message, err = runMoveV1(ctx, args[1:])
	default:
		fmt.Fprintf(stderr, "unknown operation %q\n", sanitize.Terminal(args[0], 128))
		return 2
	}
	if err != nil {
		fmt.Fprintln(stderr, sanitize.Terminal(err.Error(), 2048))
		if errors.Is(err, context.Canceled) {
			return 130
		}
		if errors.Is(err, flag.ErrHelp) {
			return 2
		}
		return 1
	}
	if _, err := fmt.Fprintln(stdout, sanitize.Terminal(message, 4096)); err != nil {
		return 1
	}
	return 0
}

func runRenderPackInput(ctx context.Context, args []string) (string, error) {
	flags := quietFlagSet("render-pack-input")
	source := flags.String("source", "", "reviewed source-overlay directory")
	schemaDir := flags.String("schema-dir", "", "reviewed local schema directory")
	artifactDir := flags.String("artifact-dir", "", "artifact directory")
	installPath := flags.String("install-record", "", "confirmed A-to-B tag-move record")
	restorePath := flags.String("restore-record", "", "confirmed B-to-A tag-move record")
	createdAtText := flags.String("created-at", "", "canonical UTC record creation time")
	out := flags.String("out", "", "new manifest-bound pack-input record")
	if err := flags.Parse(args); err != nil {
		return "", err
	}
	if flags.NArg() != 0 || *source == "" || *schemaDir == "" || *artifactDir == "" || *installPath == "" || *restorePath == "" || *createdAtText == "" || *out == "" {
		return "", flag.ErrHelp
	}
	createdAt, err := time.Parse(time.RFC3339Nano, *createdAtText)
	if err != nil || !strings.HasSuffix(*createdAtText, "Z") {
		return "", errors.New("created-at must be a canonical UTC RFC3339 timestamp")
	}
	install, err := publiclab.ReadTagMoveRecord(ctx, *schemaDir, *installPath)
	if err != nil {
		return "", fmt.Errorf("read install record: %w", err)
	}
	restore, err := publiclab.ReadTagMoveRecord(ctx, *schemaDir, *restorePath)
	if err != nil {
		return "", fmt.Errorf("read restore record: %w", err)
	}
	artifact, err := publiclab.LoadArtifact(ctx, *artifactDir)
	if err != nil {
		return "", err
	}
	packInput, err := publiclab.GeneratePackInputRecord(ctx, *source, *schemaDir, artifact, install, restore, createdAt)
	if err != nil {
		return "", err
	}
	if err := writeNewRegularFile(ctx, *out, packInput); err != nil {
		return "", fmt.Errorf("write generated pack-input record: %w", err)
	}
	return "manifest-bound pack-input record generated from exact A-to-B-to-A remote readbacks", nil
}

func runBuild(ctx context.Context, args []string) (string, error) {
	flags := quietFlagSet("build")
	source := flags.String("source", "", "reviewed source-overlay directory")
	out := flags.String("out", "", "new artifact directory")
	repository := flags.String("repository", publiclab.RepositoryName, "exact destination owner/repository")
	if err := flags.Parse(args); err != nil {
		return "", err
	}
	if flags.NArg() != 0 || *source == "" || *out == "" {
		return "", flag.ErrHelp
	}
	artifact, err := publiclab.BuildForRepository(ctx, *source, *repository)
	if err != nil {
		return "", err
	}
	if err := os.Mkdir(*out, 0o700); err != nil {
		return "", fmt.Errorf("create output directory: %w", err)
	}
	if err := publiclab.WriteArtifact(ctx, *out, artifact); err != nil {
		return "", err
	}
	if err := publiclab.VerifyArtifact(ctx, *source, artifact.Bundle, artifact.Manifest); err != nil {
		return "", err
	}
	return "public lab artifact built and verified from deterministic inert source data", nil
}

func runVerify(ctx context.Context, args []string) (string, error) {
	flags := quietFlagSet("verify")
	source := flags.String("source", "", "reviewed source-overlay directory")
	artifactDir := flags.String("artifact-dir", "", "artifact directory")
	if err := flags.Parse(args); err != nil {
		return "", err
	}
	if flags.NArg() != 0 || *source == "" || *artifactDir == "" {
		return "", flag.ErrHelp
	}
	artifact, err := publiclab.LoadArtifact(ctx, *artifactDir)
	if err != nil {
		return "", err
	}
	if err := publiclab.VerifyArtifact(ctx, *source, artifact.Bundle, artifact.Manifest); err != nil {
		return "", err
	}
	return "public lab artifact verified against deterministic inert source data", nil
}

func runValidateRecord(ctx context.Context, args []string) (string, error) {
	flags := quietFlagSet("validate-record")
	schemaDir := flags.String("schema-dir", "", "reviewed local schema directory")
	kindName := flags.String("kind", "", "reviewed public-lab record kind")
	recordPath := flags.String("record", "", "bounded JSON record file")
	runRecordPath := flags.String("run-record", "", "exact referenced run-record file for reproduction validation")
	packInputPath := flags.String("pack-input-record", "", "exact manifest-bound pack-input file for run or reproduction qualification")
	source := flags.String("source", "", "reviewed source-overlay directory")
	artifactDir := flags.String("artifact-dir", "", "artifact directory")
	if err := flags.Parse(args); err != nil {
		return "", err
	}
	if flags.NArg() != 0 || *schemaDir == "" || *kindName == "" || *recordPath == "" {
		return "", flag.ErrHelp
	}
	kind, err := parseRecordKind(*kindName)
	if err != nil {
		return "", err
	}
	record, err := publiclab.ReadAndValidateRecord(ctx, *schemaDir, kind, *recordPath)
	if err != nil {
		return "", err
	}
	var artifact publiclab.Artifact
	if kind == publiclab.RecordTagMove || kind == publiclab.RecordPackInput || kind == publiclab.RecordRun || kind == publiclab.RecordReproduction {
		if *source == "" || *artifactDir == "" {
			return "", errors.New("tag-move, pack-input, run, and reproduction records require --source and --artifact-dir")
		}
		var loadErr error
		artifact, loadErr = publiclab.LoadArtifact(ctx, *artifactDir)
		if loadErr != nil {
			return "", loadErr
		}
	}
	if kind == publiclab.RecordRun || kind == publiclab.RecordReproduction {
		if *packInputPath == "" {
			return "", errors.New("run and reproduction records require --pack-input-record for exact repository and A-to-B-to-A binding")
		}
		packInput, err := publiclab.ReadAndValidateRecord(ctx, *schemaDir, publiclab.RecordPackInput, *packInputPath)
		if err != nil {
			return "", fmt.Errorf("read exact pack-input record: %w", err)
		}
		if kind == publiclab.RecordRun {
			if err := publiclab.ValidateRunRecordAgainstPackInput(ctx, *source, *schemaDir, record, packInput, artifact); err != nil {
				return "", err
			}
		} else {
			if *runRecordPath == "" {
				return "", errors.New("reproduction records require --run-record for exact content and public-run binding")
			}
			runRecord, err := publiclab.ReadAndValidateRecord(ctx, *schemaDir, publiclab.RecordRun, *runRecordPath)
			if err != nil {
				return "", fmt.Errorf("read referenced run record: %w", err)
			}
			if err := publiclab.ValidateReproductionAgainstRunRecord(ctx, *source, *schemaDir, record, runRecord, packInput, artifact); err != nil {
				return "", err
			}
		}
	} else if kind == publiclab.RecordTagMove || kind == publiclab.RecordPackInput {
		if err := publiclab.ValidateRecordAgainstArtifact(ctx, *source, *schemaDir, kind, record, artifact); err != nil {
			return "", err
		}
	}
	return "public lab " + string(kind) + " validated without network access", nil
}

func runRenderPack(ctx context.Context, args []string) (string, error) {
	flags := quietFlagSet("render-pack")
	source := flags.String("source", "", "reviewed source-overlay directory")
	schemaDir := flags.String("schema-dir", "", "reviewed local schema directory")
	artifactDir := flags.String("artifact-dir", "", "artifact directory")
	recordPath := flags.String("record", "", "manifest-bound pre-case pack-input record file")
	installPath := flags.String("install-record", "", "exact confirmed A-to-B tag-move derivation record")
	restorePath := flags.String("restore-record", "", "exact confirmed B-to-A tag-move derivation record")
	recordSourceURL := flags.String("record-source-url", "", "immutable public URL for the exact pack-input record")
	recordSourceWorktree := flags.String("record-source-worktree", "", "absolute local lab checkout whose observations ref contains the exact record")
	out := flags.String("out", "", "new synthetic incident-pack file")
	git := flags.String("git", "git", "Git executable or absolute path")
	if err := flags.Parse(args); err != nil {
		return "", err
	}
	if flags.NArg() != 0 || *source == "" || *schemaDir == "" || *artifactDir == "" || *recordPath == "" || *installPath == "" || *restorePath == "" || *recordSourceURL == "" || *recordSourceWorktree == "" || *out == "" {
		return "", flag.ErrHelp
	}
	record, err := publiclab.ReadAndValidateRecord(ctx, *schemaDir, publiclab.RecordPackInput, *recordPath)
	if err != nil {
		return "", err
	}
	installRecord, err := publiclab.ReadTagMoveRecord(ctx, *schemaDir, *installPath)
	if err != nil {
		return "", errors.New("read exact install derivation record")
	}
	restoreRecord, err := publiclab.ReadTagMoveRecord(ctx, *schemaDir, *restorePath)
	if err != nil {
		return "", errors.New("read exact restore derivation record")
	}
	artifact, err := publiclab.LoadArtifact(ctx, *artifactDir)
	if err != nil {
		return "", err
	}
	boundary, err := publiclab.NewLocalGitBoundary(*git)
	if err != nil {
		return "", err
	}
	if err := publiclab.VerifyPackInputSourceCommit(ctx, boundary, *recordSourceWorktree, artifact, record, installRecord, restoreRecord, *recordSourceURL); err != nil {
		return "", fmt.Errorf("verify immutable pack-input source: %w", err)
	}
	pack, err := publiclab.GenerateSyntheticIncidentPack(ctx, *source, *schemaDir, artifact, record, *recordSourceURL)
	if err != nil {
		return "", err
	}
	if err := writeNewRegularFile(ctx, *out, pack); err != nil {
		return "", fmt.Errorf("write generated synthetic incident pack: %w", err)
	}
	return "synthetic incident pack generated from manifest-bound observations; output was not fetched or published", nil
}

type tagCLIOptions struct {
	policy         publiclab.TagMovePolicy
	request        publiclab.TagMoveRequest
	git            string
	observationOut string
}

func parseTagOptions(operation string, args []string, acceptGit bool) (tagCLIOptions, error) {
	flags := quietFlagSet(operation)
	worktree := flags.String("worktree", "", "absolute canonical operator worktree")
	repository := flags.String("repository", "", "exact owner/repository identity")
	repositoryID := flags.Int64("assert-repository-id", 0, "operator-asserted GitHub repository database ID; later run evidence must cross-check it")
	remote := flags.String("remote", "", "exact reviewed Git remote URL")
	reviewedMain := flags.String("reviewed-main", "", "reviewed main commit SHA")
	commitA := flags.String("commit-a", "", "reviewed marker A commit SHA")
	commitB := flags.String("commit-b", "", "reviewed marker B commit SHA")
	fixtureATag := flags.String("fixture-a-tag-object", "", "fixture-a annotated tag object SHA")
	fixtureBTag := flags.String("fixture-b-tag-object", "", "fixture-b annotated tag object SHA")
	expectedOld := flags.String("expected-old", "", "exact expected current v1 commit SHA")
	newTarget := flags.String("new-target", "", "exact requested v1 commit SHA")
	ack := flags.String("ack", "", "exact literal tag-move acknowledgement")
	git := "git"
	observationOut := ""
	if acceptGit {
		flags.StringVar(&git, "git", "git", "Git executable or absolute path")
		flags.StringVar(&observationOut, "observation-out", "", "new machine-readable tag-move observation record")
	}
	if err := flags.Parse(args); err != nil {
		return tagCLIOptions{}, err
	}
	values := []string{*worktree, *repository, *remote, *reviewedMain, *commitA, *commitB, *fixtureATag, *fixtureBTag, *expectedOld, *newTarget, *ack}
	for _, value := range values {
		if value == "" {
			return tagCLIOptions{}, flag.ErrHelp
		}
	}
	if flags.NArg() != 0 || *repositoryID == 0 || acceptGit && observationOut == "" {
		return tagCLIOptions{}, flag.ErrHelp
	}
	policy := publiclab.TagMovePolicy{
		Repository:           *repository,
		RepositoryDatabaseID: *repositoryID,
		RemoteURL:            *remote,
		ReviewedMain:         *reviewedMain,
		CommitA:              *commitA,
		CommitB:              *commitB,
		FixtureATagObject:    *fixtureATag,
		FixtureBTagObject:    *fixtureBTag,
	}
	request := publiclab.TagMoveRequest{
		Worktree:             *worktree,
		Repository:           *repository,
		RepositoryDatabaseID: *repositoryID,
		RemoteURL:            *remote,
		Ref:                  publiclab.MutableV1Ref,
		ExpectedOld:          *expectedOld,
		NewTarget:            *newTarget,
		Acknowledgement:      *ack,
	}
	return tagCLIOptions{policy: policy, request: request, git: git, observationOut: observationOut}, nil
}

func runPlanV1(ctx context.Context, args []string) (string, error) {
	return runPlanV1WithRemotePolicy(ctx, args, false)
}

// runPlanV1WithRemotePolicy exists only so the test suite can exercise the
// exact command path against a disposable filesystem remote. Production calls
// always pass false; no CLI flag or environment variable enables local remotes.
func runPlanV1WithRemotePolicy(ctx context.Context, args []string, allowLocalTestRemote bool) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	options, err := parseTagOptions("plan-v1", args, false)
	if err != nil {
		return "", err
	}
	options.policy.TestOnlyAllowLocalRemote = allowLocalTestRemote
	plan, err := publiclab.PlanV1Move(options.policy, options.request)
	if err != nil {
		return "", err
	}
	return formatTagPlan("validated inert plan; no Git command or network request was performed", plan), nil
}

func runMoveV1(ctx context.Context, args []string) (string, error) {
	return runMoveV1WithReservation(ctx, args, reserveNewRegularFile, false)
}

type regularFileReservation interface {
	write(context.Context, []byte) error
	abort()
}

type reserveRegularFileFunc func(context.Context, string, string) (regularFileReservation, error)

func runMoveV1WithReservation(ctx context.Context, args []string, reserve reserveRegularFileFunc, allowLocalTestRemote bool) (string, error) {
	options, err := parseTagOptions("move-v1", args, true)
	if err != nil {
		return "", err
	}
	options.policy.TestOnlyAllowLocalRemote = allowLocalTestRemote
	if reserve == nil {
		return "", errors.New("machine-readable tag-move record reservation is unavailable")
	}
	observation, err := reserve(ctx, options.observationOut, options.request.Worktree)
	if err != nil {
		return "", fmt.Errorf("reserve machine-readable tag-move record before mutation: %w", err)
	}
	defer observation.abort()
	boundary, err := publiclab.NewLocalGitBoundary(options.git)
	if err != nil {
		return "", err
	}
	result, moveErr := publiclab.MoveV1(ctx, boundary, options.policy, options.request)
	if errors.Is(moveErr, publiclab.ErrTagMovePolicy) {
		// Policy rejection happens before any Git command runs, so there is no
		// local or remote observation to preserve and nothing to read back; the
		// deferred abort releases the pre-reserved output path.
		return "", fmt.Errorf("tag move was rejected before any Git command or remote contact; no observation record was written: %w", moveErr)
	}
	record, recordErr := publiclab.EncodeTagMoveRecord(options.policy, result, moveErr, time.Now())
	if recordErr != nil {
		return "", errors.Join(moveErr, tagRecordPersistenceError(options.policy, result, moveErr, "encoding failed"))
	}
	recordContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	if err := observation.write(recordContext, record); err != nil {
		return "", errors.Join(moveErr, tagRecordPersistenceError(options.policy, result, moveErr, "durable write failed"))
	}
	if moveErr != nil {
		if result.Recovery != nil && result.Recovery.Required {
			return "", fmt.Errorf("tag move did not complete safely; machine-readable observation was preserved; %s: %w", formatRecovery(result.Recovery), moveErr)
		}
		return "", fmt.Errorf("tag move did not complete safely; machine-readable observation was preserved: %w", moveErr)
	}
	return formatTagPlan("Git reported one forced v1 update; exact remote readback verified the requested target; a machine-readable observation was preserved", result.Plan) + "\nobserved before: " + result.Before + " at " + result.BeforeObservedAt + "\nobserved after: " + result.After + " at " + result.AfterObservedAt, nil
}

func tagRecordPersistenceError(policy publiclab.TagMovePolicy, result publiclab.TagMoveResult, moveErr error, failure string) error {
	prefix := "machine-readable tag-move record " + failure + "; no valid observation record was preserved"
	latest := result.After
	if latest == "" {
		latest = result.Before
	}
	if (result.Recovery != nil && result.Recovery.Required) || errors.Is(moveErr, publiclab.ErrTagMoveUnknown) {
		if latest == policy.CommitB {
			acknowledgement := publiclab.RequiredTagMoveAcknowledgement(policy.Repository, policy.CommitB, policy.CommitA)
			return fmt.Errorf("%s; latest exact remote readback is affected B %s; immediate recovery is required with expected-old %s, target %s, and acknowledgement %s", prefix, policy.CommitB, policy.CommitB, policy.CommitA, acknowledgement)
		}
		observed := latest
		if observed == "" {
			observed = "unavailable"
		}
		return fmt.Errorf("%s; latest exact remote readback was %s but the in-flight outcome remains unknown; a fresh remote readback is required before any retry", prefix, observed)
	}
	switch latest {
	case policy.CommitB:
		acknowledgement := publiclab.RequiredTagMoveAcknowledgement(policy.Repository, policy.CommitB, policy.CommitA)
		return fmt.Errorf("%s; exact post-operation remote readback is affected B %s; immediate recovery is required with expected-old %s, target %s, and acknowledgement %s", prefix, policy.CommitB, policy.CommitB, policy.CommitA, acknowledgement)
	case policy.CommitA:
		return fmt.Errorf("%s; exact post-operation remote readback is known-good A %s", prefix, policy.CommitA)
	default:
		return errors.New(prefix + "; post-operation remote state is unconfirmed and must be read back before any retry")
	}
}

func formatRecovery(recovery *publiclab.RecoveryPlan) string {
	observed := recovery.ObservedTarget
	if observed == "" {
		observed = "unavailable"
	}
	parts := []string{
		"recovery ref " + publiclab.MutableV1Ref,
		"observed target " + observed,
		"reviewed known-good target " + recovery.KnownGoodTarget,
		"fresh remote readback required before any retry",
	}
	if recovery.RestoreAcknowledgement != "" {
		parts = append(parts,
			"restore expected-old "+recovery.ObservedTarget,
			"restore target "+recovery.KnownGoodTarget,
			"required acknowledgement "+recovery.RestoreAcknowledgement,
		)
	}
	return strings.Join(parts, "; ")
}

func formatTagPlan(summary string, plan publiclab.TagMovePlan) string {
	return strings.Join([]string{
		summary,
		"repository: " + plan.Repository,
		fmt.Sprintf("operator-asserted repository database ID: %d", plan.RepositoryDatabaseID),
		"ref: " + plan.Ref,
		"expected old: " + plan.ExpectedOld,
		"new target: " + plan.NewTarget,
		"direction: " + string(plan.Direction),
	}, "\n")
}

func parseRecordKind(value string) (publiclab.RecordKind, error) {
	switch publiclab.RecordKind(value) {
	case publiclab.RecordTagMove, publiclab.RecordPackInput, publiclab.RecordRun, publiclab.RecordReproduction, publiclab.RecordReproductionsIdx, publiclab.RecordExpectedSeed:
		return publiclab.RecordKind(value), nil
	default:
		return "", errors.New("unsupported public-lab record kind")
	}
}

func writeNewRegularFile(ctx context.Context, path string, data []byte) error {
	reservation, err := reserveNewRegularFile(ctx, path, "")
	if err != nil {
		return err
	}
	defer reservation.abort()
	return reservation.write(ctx, data)
}

type reservedRegularFile struct {
	path       string
	parentPath string
	handle     *os.File
	parent     *os.File
	fileInfo   os.FileInfo
	parentInfo os.FileInfo
	committed  bool
}

func reserveNewRegularFile(ctx context.Context, path, forbiddenRoot string) (regularFileReservation, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if path == "" || filepath.Clean(path) != path || strings.IndexByte(path, 0) >= 0 {
		return nil, errors.New("output path must be nonempty and clean")
	}
	absolute, err := filepath.Abs(path)
	if err != nil || !filepath.IsAbs(absolute) {
		return nil, errors.New("output path could not be resolved")
	}
	parent := filepath.Dir(absolute)
	parentInfo, err := os.Lstat(parent)
	if err != nil || !parentInfo.IsDir() || parentInfo.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("output parent must be an existing real directory")
	}
	resolvedParent, err := filepath.EvalSymlinks(parent)
	if err != nil {
		return nil, errors.New("output parent could not be resolved")
	}
	if forbiddenRoot != "" {
		resolvedRoot, rootErr := filepath.EvalSymlinks(forbiddenRoot)
		if rootErr != nil {
			return nil, errors.New("tag-control worktree could not be resolved")
		}
		rootInfo, rootErr := os.Stat(resolvedRoot)
		if rootErr != nil || !rootInfo.IsDir() {
			return nil, errors.New("tag-control worktree is not a directory")
		}
		for current := resolvedParent; ; current = filepath.Dir(current) {
			currentInfo, statErr := os.Stat(current)
			if statErr != nil {
				return nil, errors.New("output ancestry could not be verified")
			}
			if os.SameFile(currentInfo, rootInfo) {
				return nil, errors.New("tag-move observation output must be outside the tag-control worktree")
			}
			next := filepath.Dir(current)
			if next == current {
				break
			}
		}
	}
	resolvedPath := filepath.Join(resolvedParent, filepath.Base(absolute))
	parentHandle, err := os.Open(resolvedParent)
	if err != nil {
		return nil, errors.New("output parent could not be opened for identity verification")
	}
	openedParent, err := parentHandle.Stat()
	if err != nil || !openedParent.IsDir() || !os.SameFile(parentInfo, openedParent) {
		_ = parentHandle.Close()
		return nil, errors.New("output parent changed before file reservation")
	}
	handle, err := os.OpenFile(resolvedPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		_ = parentHandle.Close()
		return nil, errors.New("new output file could not be reserved")
	}
	fileInfo, err := handle.Stat()
	if err != nil || !fileInfo.Mode().IsRegular() {
		_ = handle.Close()
		_ = parentHandle.Close()
		_ = os.Remove(resolvedPath)
		return nil, errors.New("new output reservation is not a regular file")
	}
	reservation := &reservedRegularFile{
		path:       resolvedPath,
		parentPath: resolvedParent,
		handle:     handle,
		parent:     parentHandle,
		fileInfo:   fileInfo,
		parentInfo: openedParent,
	}
	if err := reservation.verifyIdentity(); err != nil {
		reservation.abort()
		return nil, err
	}
	// Exercise allocation, synchronization, truncation, and positioning before a
	// remote mutation. A later device failure remains possible and is handled by
	// an explicit exact-state recovery diagnostic.
	if written, writeErr := handle.Write([]byte{0}); writeErr != nil || written != 1 {
		reservation.abort()
		return nil, errors.New("new output file failed its pre-mutation write check")
	}
	if err := handle.Sync(); err != nil {
		reservation.abort()
		return nil, errors.New("new output file failed its pre-mutation sync check")
	}
	if err := handle.Truncate(0); err != nil {
		reservation.abort()
		return nil, errors.New("new output file failed its pre-mutation truncate check")
	}
	if _, err := handle.Seek(0, io.SeekStart); err != nil {
		reservation.abort()
		return nil, errors.New("new output file failed its pre-mutation position check")
	}
	if err := handle.Sync(); err != nil {
		reservation.abort()
		return nil, errors.New("new output file failed its pre-mutation empty-state sync check")
	}
	if err := reservation.verifyIdentity(); err != nil {
		reservation.abort()
		return nil, err
	}
	if err := syncDirectory(parentHandle); err != nil {
		reservation.abort()
		return nil, errors.New("new output directory entry failed its pre-mutation sync check")
	}
	return reservation, nil
}

func (reservation *reservedRegularFile) write(ctx context.Context, data []byte) error {
	if reservation == nil || reservation.handle == nil || reservation.committed {
		return errors.New("output reservation is unavailable")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(data) == 0 || len(data) > 1<<20 {
		return errors.New("generated output is empty or exceeds the accepted byte limit")
	}
	if err := reservation.verifyIdentity(); err != nil {
		return err
	}
	written, err := reservation.handle.Write(data)
	if err != nil || written != len(data) {
		return errors.New("generated output could not be written completely")
	}
	if err := reservation.handle.Sync(); err != nil {
		return errors.New("generated output could not be synchronized")
	}
	if err := reservation.verifyIdentity(); err != nil {
		return err
	}
	if err := reservation.handle.Close(); err != nil {
		reservation.handle = nil
		return errors.New("generated output could not be closed")
	}
	reservation.handle = nil
	if err := syncDirectory(reservation.parent); err != nil {
		return errors.New("generated output directory entry could not be synchronized")
	}
	if err := reservation.verifyIdentity(); err != nil {
		return err
	}
	if err := reservation.parent.Close(); err != nil {
		reservation.parent = nil
		return errors.New("generated output parent could not be closed")
	}
	reservation.parent = nil
	reservation.committed = true
	return nil
}

func (reservation *reservedRegularFile) verifyIdentity() error {
	if reservation == nil || reservation.parent == nil {
		return errors.New("output reservation identity is unavailable")
	}
	openedParent, err := reservation.parent.Stat()
	if err != nil || !os.SameFile(openedParent, reservation.parentInfo) {
		return errors.New("output parent identity changed")
	}
	pathParent, err := os.Stat(reservation.parentPath)
	if err != nil || !os.SameFile(pathParent, reservation.parentInfo) {
		return errors.New("output parent path changed")
	}
	pathFile, err := os.Lstat(reservation.path)
	if err != nil || !pathFile.Mode().IsRegular() || pathFile.Mode()&os.ModeSymlink != 0 || !os.SameFile(pathFile, reservation.fileInfo) {
		return errors.New("output pathname no longer identifies the reserved regular file")
	}
	if reservation.handle != nil {
		openedFile, statErr := reservation.handle.Stat()
		if statErr != nil || !os.SameFile(openedFile, reservation.fileInfo) {
			return errors.New("output file descriptor identity changed")
		}
	}
	return nil
}

func syncDirectory(directory *os.File) error {
	if directory == nil {
		return errors.New("directory handle is unavailable")
	}
	if runtime.GOOS == "windows" {
		return nil
	}
	return directory.Sync()
}

func (reservation *reservedRegularFile) abort() {
	if reservation == nil || reservation.committed {
		return
	}
	if reservation.handle != nil {
		_ = reservation.handle.Close()
		reservation.handle = nil
	}
	if pathInfo, err := os.Lstat(reservation.path); err == nil && reservation.fileInfo != nil && os.SameFile(pathInfo, reservation.fileInfo) {
		_ = os.Remove(reservation.path)
		if reservation.parent != nil {
			_ = syncDirectory(reservation.parent)
		}
	}
	if reservation.parent != nil {
		_ = reservation.parent.Close()
		reservation.parent = nil
	}
}

func quietFlagSet(name string) *flag.FlagSet {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	return flags
}
