// Command packreview provides repository-maintainer-only, network-disabled
// incident-pack governance operations. It is intentionally separate from the
// shipped cirewind CLI.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"

	"github.com/torjan0/cirewind/internal/evidence"
	"github.com/torjan0/cirewind/internal/incident"
	"github.com/torjan0/cirewind/internal/packfixtures"
	"github.com/torjan0/cirewind/internal/packreview"
	"github.com/torjan0/cirewind/internal/sanitize"
)

const usage = `Usage:
  packreview validate-unit --root DIR --candidate-commit COMMIT
  packreview build-candidate-manifest --root DIR --out FILE
  packreview build-fixture-manifest --root DIR --out FILE
  packreview render-review --review FILE --out FILE
  packreview render-review-body --review FILE
  packreview normalize-platform-approvals --source FILE --out FILE --repository OWNER/REPO --pull-request N --candidate-commit COMMIT --observed-at RFC3339 --workflow-source-commit COMMIT --workflow-run-url URL --workflow-run-id N --workflow-run-attempt N
  packreview check-approvals --root DIR --candidate-commit COMMIT --candidate-manifest-sha256 SHA256 --platform-approvals FILE
  packreview promote --root DIR --repository-root DIR --candidate-commit COMMIT --candidate-manifest-sha256 SHA256 --platform-approvals FILE --promoted-at RFC3339
  packreview validate-candidate-tree --repository-root DIR --candidate-commit COMMIT
  packreview validate-governance --repository-root DIR
  packreview verify-registry --repository-root DIR --promotion-content-commit COMMIT
  packreview assemble-candidate --root DIR --repository-root DIR --review-policy-profile PROFILE --preparer LOGIN:ID --authors LOGIN:ID[,...] --source-transcribers LOGIN:ID[,...]

This maintainer tool validates deterministic local records. It performs no
network request, process execution, Git mutation, approval creation, or factual
certification. Git worktree cleanliness and platform-snapshot acquisition are
fixed caller/CI preconditions.
`

type commandResult struct {
	SchemaVersion string `json:"schemaVersion"`
	Operation     string `json:"operation"`
	IncidentID    string `json:"incidentId,omitempty"`
	PackVersion   string `json:"packVersion,omitempty"`
	SHA256        string `json:"sha256,omitempty"`
	Statement     string `json:"statement"`
}

type exactOutput []byte

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		fmt.Fprint(stdout, usage)
		return 0
	}
	var result any
	var err error
	switch args[0] {
	case "validate-unit":
		result, err = runValidateUnit(ctx, args[1:])
	case "build-candidate-manifest":
		result, err = runBuildManifest(ctx, args[1:], false)
	case "build-fixture-manifest":
		result, err = runBuildManifest(ctx, args[1:], true)
	case "render-review":
		result, err = runRenderReview(ctx, args[1:])
	case "render-review-body":
		result, err = runRenderReviewBody(ctx, args[1:])
	case "normalize-platform-approvals":
		result, err = runNormalizePlatformApprovals(ctx, args[1:])
	case "check-approvals":
		result, err = runCheckApprovals(ctx, args[1:])
	case "promote":
		result, err = runPromote(ctx, args[1:])
	case "validate-candidate-tree":
		result, err = runValidateCandidateTree(ctx, args[1:])
	case "validate-governance":
		result, err = runValidateGovernance(ctx, args[1:])
	case "verify-registry":
		result, err = runVerifyRegistry(ctx, args[1:])
	case "assemble-candidate":
		result, err = runAssembleCandidate(ctx, args[1:])
	default:
		fmt.Fprintf(stderr, "unknown operation %q\n", sanitize.Terminal(args[0], 128))
		return 2
	}
	if err != nil {
		writeError(stderr, err)
		if errors.Is(err, context.Canceled) {
			return 130
		}
		if packreview.IsValidation(err) || errors.Is(err, flag.ErrHelp) {
			return 2
		}
		return 1
	}
	if output, ok := result.(exactOutput); ok {
		if _, err := stdout.Write(output); err != nil {
			return 1
		}
		return 0
	}
	encoded, err := evidence.CanonicalJSON(result)
	if err != nil {
		fmt.Fprintf(stderr, "encode result: %s\n", sanitize.Terminal(err.Error(), 1024))
		return 1
	}
	encoded = append(encoded, '\n')
	if _, err := stdout.Write(encoded); err != nil {
		return 1
	}
	return 0
}

func runNormalizePlatformApprovals(ctx context.Context, args []string) (any, error) {
	fs, output := strictFlags("normalize-platform-approvals")
	source := fs.String("source", "", "bounded GitHub list-reviews JSON response")
	out := fs.String("out", "", "fixed platform-approvals.json output")
	repository := fs.String("repository", "", "GitHub owner/repository")
	pullRequest := fs.Int64("pull-request", 0, "pull request number")
	commit := fs.String("candidate-commit", "", "exact candidate commit C")
	observedAt := fs.String("observed-at", "", "canonical UTC observation time")
	workflowSourceCommit := fs.String("workflow-source-commit", "", "exact commit containing the capture workflow and normalizer")
	workflowURL := fs.String("workflow-run-url", "", "GitHub Actions workflow-run URL")
	workflowID := fs.Int64("workflow-run-id", 0, "GitHub Actions workflow-run ID")
	workflowAttempt := fs.Int64("workflow-run-attempt", 0, "GitHub Actions workflow-run attempt")
	if err := parseFlags(fs, output, args); err != nil {
		return nil, err
	}
	snapshot, canonical, err := packreview.WritePlatformSnapshot(ctx, *source, *out, packreview.PlatformSnapshotOptions{
		Repository: *repository, PullRequestNumber: *pullRequest, CandidateCommit: *commit, ObservedAt: *observedAt,
		WorkflowSourceCommit: *workflowSourceCommit, WorkflowRunURL: *workflowURL, WorkflowRunID: *workflowID, WorkflowRunAttempt: *workflowAttempt,
	})
	if err != nil {
		return nil, err
	}
	return commandResult{SchemaVersion: "cirewind.packreview-command/v1alpha1", Operation: "normalize-platform-approvals",
		IncidentID: "", PackVersion: "", SHA256: digest(canonical),
		Statement: fmt.Sprintf("normalized %d platform review observations; this record is not a human approval or factual certification", len(snapshot.Approvals))}, nil
}

func runValidateUnit(ctx context.Context, args []string) (any, error) {
	fs, output := strictFlags("validate-unit")
	root := fs.String("root", "", "review-unit root")
	commit := fs.String("candidate-commit", "", "exact frozen candidate commit")
	if err := parseFlags(fs, output, args); err != nil {
		return nil, err
	}
	unit, err := packreview.ValidateUnit(ctx, *root, *commit)
	if err != nil {
		return nil, err
	}
	return commandResult{SchemaVersion: "cirewind.packreview-command/v1alpha1", Operation: "validate-unit", IncidentID: unit.Pack.IncidentID, PackVersion: unit.Pack.PackVersion, SHA256: unit.CandidateManifestSHA256, Statement: "candidate review unit is structurally valid; factual truth and human approval are not established"}, nil
}

func runBuildManifest(ctx context.Context, args []string, fixture bool) (any, error) {
	operation := "build-candidate-manifest"
	if fixture {
		operation = "build-fixture-manifest"
	}
	fs, output := strictFlags(operation)
	root := fs.String("root", "", "manifested root")
	out := fs.String("out", "", "fixed manifest output path")
	if err := parseFlags(fs, output, args); err != nil {
		return nil, err
	}
	var data []byte
	var err error
	if fixture {
		data, err = packreview.BuildFixtureManifest(ctx, *root, *out)
	} else {
		data, err = packreview.BuildCandidateManifest(ctx, *root, *out)
	}
	if err != nil {
		return nil, err
	}
	return commandResult{SchemaVersion: "cirewind.packreview-command/v1alpha1", Operation: operation, SHA256: digest(data), Statement: "deterministic integrity manifest written; this is not an authenticity signature"}, nil
}

func runRenderReview(ctx context.Context, args []string) (any, error) {
	fs, output := strictFlags("render-review")
	review := fs.String("review", "", "canonical human-supplied review.json")
	out := fs.String("out", "", "fixed REVIEW.md sibling")
	if err := parseFlags(fs, output, args); err != nil {
		return nil, err
	}
	if err := packreview.RenderReviewFile(ctx, *review, *out); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(*out)
	if err != nil {
		return nil, err
	}
	return commandResult{SchemaVersion: "cirewind.packreview-command/v1alpha1", Operation: "render-review", SHA256: digest(data), Statement: "REVIEW.md deterministically reflects review.json; neither file certifies its own approval"}, nil
}

func runRenderReviewBody(ctx context.Context, args []string) (any, error) {
	fs, output := strictFlags("render-review-body")
	review := fs.String("review", "", "canonical human-authored review-assertion JSON")
	if err := parseFlags(fs, output, args); err != nil {
		return nil, err
	}
	binding, err := packreview.RenderReviewBodyFile(ctx, *review)
	if err != nil {
		return nil, err
	}
	return exactOutput(binding.Body), nil
}

func runCheckApprovals(ctx context.Context, args []string) (any, error) {
	fs, output := strictFlags("check-approvals")
	root := fs.String("root", "", "review-unit root")
	commit := fs.String("candidate-commit", "", "exact frozen candidate commit")
	manifest := fs.String("candidate-manifest-sha256", "", "SHA-256 of exact candidate manifest bytes")
	platform := fs.String("platform-approvals", "", "normalized platform-review snapshot")
	if err := parseFlags(fs, output, args); err != nil {
		return nil, err
	}
	return packreview.CheckApprovals(ctx, *root, *commit, *manifest, *platform)
}

func runPromote(ctx context.Context, args []string) (any, error) {
	fs, output := strictFlags("promote")
	root := fs.String("root", "", "review-unit root")
	repository := fs.String("repository-root", "", "explicit repository root")
	commit := fs.String("candidate-commit", "", "exact frozen candidate commit")
	manifest := fs.String("candidate-manifest-sha256", "", "SHA-256 of exact candidate manifest bytes")
	platform := fs.String("platform-approvals", "", "normalized platform-review snapshot")
	promotedAt := fs.String("promoted-at", "", "explicit canonical UTC promotion time")
	if err := parseFlags(fs, output, args); err != nil {
		return nil, err
	}
	return packreview.Promote(ctx, packreview.PromotionOptions{ReviewUnitRoot: *root, RepositoryRoot: *repository, CandidateCommit: *commit, CandidateManifest: *manifest, PlatformSnapshot: *platform, PromotedAt: *promotedAt})
}

func runVerifyRegistry(ctx context.Context, args []string) (any, error) {
	fs, output := strictFlags("verify-registry")
	repository := fs.String("repository-root", "", "explicit repository root")
	commit := fs.String("promotion-content-commit", "", "exact promotion content commit P")
	if err := parseFlags(fs, output, args); err != nil {
		return nil, err
	}
	if err := packreview.VerifyRegistry(ctx, *repository, *commit); err != nil {
		return nil, err
	}
	return commandResult{SchemaVersion: "cirewind.packreview-command/v1alpha1", Operation: "verify-registry", Statement: "append-only registry and exact promoted bytes verify; factual truth is not established"}, nil
}

func runValidateGovernance(ctx context.Context, args []string) (any, error) {
	fs, output := strictFlags("validate-governance")
	repository := fs.String("repository-root", "", "explicit repository root")
	if err := parseFlags(fs, output, args); err != nil {
		return nil, err
	}
	if err := packreview.ValidateGovernance(ctx, *repository); err != nil {
		return nil, err
	}
	return commandResult{SchemaVersion: "cirewind.packreview-command/v1alpha1", Operation: "validate-governance", Statement: "review policy, append-only registry, and reviewed tree are structurally valid; no factual review is established"}, nil
}

func runValidateCandidateTree(ctx context.Context, args []string) (any, error) {
	fs, output := strictFlags("validate-candidate-tree")
	repository := fs.String("repository-root", "", "explicit repository root")
	commit := fs.String("candidate-commit", "", "exact externally bound candidate commit C")
	if err := parseFlags(fs, output, args); err != nil {
		return nil, err
	}
	if err := packreview.ValidateCandidateTree(ctx, *repository, *commit); err != nil {
		return nil, err
	}
	return commandResult{SchemaVersion: "cirewind.packreview-command/v1alpha1", Operation: "validate-candidate-tree", Statement: "retained review units validate against registered identities or externally supplied candidate C; factual review is not established"}, nil
}

func strictFlags(name string) (*flag.FlagSet, *discardingOutput) {
	output := &discardingOutput{}
	set := flag.NewFlagSet(name, flag.ContinueOnError)
	set.SetOutput(output)
	return set, output
}

func parseFlags(set *flag.FlagSet, output *discardingOutput, args []string) error {
	if err := set.Parse(args); err != nil {
		return &packreview.ValidationError{Problems: []packreview.Problem{{Code: "FLAGS", Path: "/flags", Message: sanitize.Terminal(err.Error(), 512)}}}
	}
	if set.NArg() != 0 {
		return &packreview.ValidationError{Problems: []packreview.Problem{{Code: "POSITIONAL_ARGUMENT", Path: "/flags", Message: "unexpected positional argument"}}}
	}
	for _, required := range []string{"root", "out", "review", "source", "repository", "observed-at", "workflow-source-commit", "workflow-run-url", "repository-root", "candidate-commit", "candidate-manifest-sha256", "platform-approvals", "promoted-at", "promotion-content-commit"} {
		if found := set.Lookup(required); found != nil && found.Value.String() == "" {
			return &packreview.ValidationError{Problems: []packreview.Problem{{Code: "REQUIRED_FLAG", Path: "/flags/" + required, Message: "required flag is empty"}}}
		}
	}
	_ = output
	return nil
}

type discardingOutput struct{}

func (*discardingOutput) Write(data []byte) (int, error) { return len(data), nil }

func writeError(output io.Writer, err error) {
	var validation *packreview.ValidationError
	if errors.As(err, &validation) {
		for _, problem := range validation.Problems {
			fmt.Fprintf(output, "%s %s: %s\n", sanitize.Terminal(problem.Code, 128), sanitize.Terminal(problem.Path, 512), sanitize.Terminal(problem.Message, 1024))
		}
		return
	}
	fmt.Fprintln(output, sanitize.Terminal(err.Error(), 2048))
}

func digest(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

func runAssembleCandidate(ctx context.Context, args []string) (any, error) {
	fs, output := strictFlags("assemble-candidate")
	root := fs.String("root", "", "review-unit root (review-packets/INCIDENT_ID/PACK_VERSION)")
	repositoryRoot := fs.String("repository-root", "", "repository root holding pack-review-policy.json")
	profile := fs.String("review-policy-profile", "", "review policy profile identifier")
	preparer := fs.String("preparer", "", "preparer as LOGIN:DATABASE_ID")
	authors := fs.String("authors", "", "comma-separated authors as LOGIN:DATABASE_ID")
	transcribers := fs.String("source-transcribers", "", "comma-separated source transcribers as LOGIN:DATABASE_ID")
	if err := parseFlags(fs, output, args); err != nil {
		return nil, err
	}
	preparation, err := parsePreparation(*preparer, *authors, *transcribers)
	if err != nil {
		return nil, err
	}
	candidate := filepath.Join(*root, "candidate-content")
	packBytes, err := readBoundedFile(filepath.Join(candidate, "pack.yaml"), 1<<20)
	if err != nil {
		return nil, err
	}
	validated, err := incident.Validate(ctx, packBytes)
	if err != nil {
		return nil, err
	}
	generated, err := packfixtures.Generate(ctx, validated.Pack.Metadata.ID, validated.Pack.Metadata.PackVersion)
	if err != nil {
		return nil, err
	}
	scenarios := make([]packreview.AuthoredScenario, 0, len(generated))
	for _, scenario := range generated {
		forbidden := make([]packreview.ForbiddenExpectedFinding, 0, len(scenario.Forbidden))
		for _, state := range scenario.Forbidden {
			forbidden = append(forbidden, packreview.ForbiddenStateFor(scenario.ID, state.State, state.Rationale))
		}
		scenarios = append(scenarios, packreview.AuthoredScenario{ScenarioID: scenario.ID, Snapshot: scenario.Snapshot, AnalysisTime: scenario.AnalysisTime, Forbidden: forbidden})
	}
	packet, err := packreview.AssembleCandidate(ctx, packreview.AuthoringInput{
		CandidateContent: candidate, RepositoryPolicy: filepath.Join(*repositoryRoot, "pack-review-policy.json"),
		Scenarios: scenarios, ReviewPolicyProfile: *profile, Preparation: preparation,
	})
	if err != nil {
		return nil, err
	}
	return commandResult{SchemaVersion: "cirewind.packreview-command/v1alpha1", Operation: "assemble-candidate", IncidentID: packet.IncidentID, PackVersion: packet.PackVersion, SHA256: packet.CanonicalPackSHA256,
		Statement: fmt.Sprintf("candidate content assembled deterministically from hand-authored ledgers and %d generated fixture scenarios; no approval, candidate-commit binding, or factual certification is created", len(scenarios))}, nil
}

func parsePreparation(preparer, authors, transcribers string) (packreview.Preparation, error) {
	prepared, err := parseIdentity(preparer)
	if err != nil {
		return packreview.Preparation{}, fmt.Errorf("preparer: %w", err)
	}
	authorList, err := parseIdentityList(authors)
	if err != nil {
		return packreview.Preparation{}, fmt.Errorf("authors: %w", err)
	}
	transcriberList, err := parseIdentityList(transcribers)
	if err != nil {
		return packreview.Preparation{}, fmt.Errorf("source transcribers: %w", err)
	}
	return packreview.Preparation{Preparer: prepared, Authors: authorList, SourceTranscribers: transcriberList}, nil
}

func parseIdentityList(value string) ([]packreview.HumanIdentity, error) {
	if strings.TrimSpace(value) == "" {
		return nil, errors.New("at least one LOGIN:DATABASE_ID is required")
	}
	parts := strings.Split(value, ",")
	result := make([]packreview.HumanIdentity, 0, len(parts))
	for _, part := range parts {
		identity, err := parseIdentity(strings.TrimSpace(part))
		if err != nil {
			return nil, err
		}
		result = append(result, identity)
	}
	return result, nil
}

var identityLoginPattern = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$`)

func parseIdentity(value string) (packreview.HumanIdentity, error) {
	login, id, ok := strings.Cut(value, ":")
	if !ok || !identityLoginPattern.MatchString(login) {
		return packreview.HumanIdentity{}, fmt.Errorf("identity %q must be LOGIN:DATABASE_ID", sanitize.Terminal(value, 64))
	}
	databaseID, err := strconv.ParseInt(id, 10, 64)
	if err != nil || databaseID <= 0 {
		return packreview.HumanIdentity{}, fmt.Errorf("identity %q must carry a positive numeric database ID", sanitize.Terminal(value, 64))
	}
	return packreview.HumanIdentity{Login: login, DatabaseID: databaseID}, nil
}

func readBoundedFile(path string, limit int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > limit {
		return nil, fmt.Errorf("%s is not a bounded regular file", sanitize.Terminal(filepath.Base(path), 64))
	}
	return os.ReadFile(path)
}
