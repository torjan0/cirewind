package publiclab

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	tagRemoteName       = "origin"
	maxGitCommandOutput = 64 << 10
	reconcileTimeout    = 10 * time.Second
)

var (
	ErrTagMovePolicy       = errors.New("public-lab tag-move policy is invalid")
	ErrTagMovePrecondition = errors.New("public-lab tag-move precondition failed")
	ErrTagMoveFailed       = errors.New("public-lab tag move failed")
	ErrConcurrentTagMove   = errors.New("public-lab mutable tag changed concurrently")
	ErrTagMoveUnknown      = errors.New("public-lab tag-move outcome is unknown")
	ErrRestoreFailed       = errors.New("public-lab mutable tag restoration failed")
	ErrTagMoveUnconfirmed  = errors.New("public-lab remote reached the requested target but the tag-move command did not report success")
)

// GitCommandBoundary is the only process boundary used by MoveV1. A caller is
// responsible for invoking Git directly with the supplied arguments, imposing
// output limits, using the C locale, disabling prompts and transport/ref rewrite
// configuration from untrusted scopes, and ensuring that errors do not disclose
// environment variables, credentials, command output, or authentication
// material. The boundary must not invoke a shell. MoveV1 independently bounds
// and parses returned output and never includes it in an error.
type GitCommandBoundary interface {
	RunGit(ctx context.Context, worktree string, arguments ...string) ([]byte, error)
}

// TagMovePolicy binds one reviewed lab topology to one explicit repository and
// remote. The mutable operation is valid only between CommitA and CommitB.
// Fixture tag fields contain annotated tag object IDs, not peeled commit IDs.
type TagMovePolicy struct {
	Repository           string
	RepositoryDatabaseID int64
	RemoteURL            string
	ReviewedMain         string
	CommitA              string
	CommitB              string
	FixtureATagObject    string
	FixtureBTagObject    string
	// TestOnlyAllowLocalRemote permits disposable filesystem remotes in tests.
	// Production callers must leave it false because a local receive-pack can
	// execute repository-controlled receive hooks.
	TestOnlyAllowLocalRemote bool
}

// TagMoveRequest repeats all operator-controlled material needed for a move.
// Repeating the repository and remote prevents a caller from silently applying
// a policy selected for a different target.
type TagMoveRequest struct {
	Worktree             string
	Repository           string
	RepositoryDatabaseID int64
	RemoteURL            string
	Ref                  string
	ExpectedOld          string
	NewTarget            string
	Acknowledgement      string
}

// TagMoveDirection describes the only two accepted v1 transitions.
type TagMoveDirection string

const (
	InstallAffectedMarker TagMoveDirection = "INSTALL_AFFECTED_MARKER"
	RestoreKnownGood      TagMoveDirection = "RESTORE_KNOWN_GOOD"
)

// TagMovePlan is a validated, inert description. It intentionally omits the
// remote URL so callers do not accidentally log authentication-bearing input.
type TagMovePlan struct {
	Repository           string
	RepositoryDatabaseID int64
	Ref                  string
	ExpectedOld          string
	NewTarget            string
	Direction            TagMoveDirection
}

// RecoveryPlan is returned only when a failed or interrupted move may need
// operator recovery. Arguments are individual Git arguments, never a shell
// command. RestoreArguments is populated only when readback proves that v1 is
// exactly B; an unexpected target must be investigated rather than overwritten.
type RecoveryPlan struct {
	Required               bool
	ObservedTarget         string
	KnownGoodTarget        string
	ReadbackArguments      []string
	RestoreArguments       []string
	RestoreAcknowledgement string
}

// TagMoveResult records state observed through the exact remote ref before and
// after the attempted operation. Verified is true only when readback equals the
// requested new target; it does not by itself claim that this invocation caused
// the transition. A nil error additionally requires a forced-update porcelain
// record from this invocation.
type TagMoveResult struct {
	Plan             TagMovePlan
	Before           string
	BeforeObservedAt string
	After            string
	AfterObservedAt  string
	Verified         bool
	Recovery         *RecoveryPlan
}

type remoteTagState struct {
	main         string
	fixtureA     string
	fixtureAPeel string
	fixtureB     string
	fixtureBPeel string
	v1           string
}

// RequiredTagMoveAcknowledgement returns the exact text the operator must enter.
// MoveV1 does not trim, normalize, or case-fold an acknowledgement.
func RequiredTagMoveAcknowledgement(repository, oldTarget, newTarget string) string {
	return "I acknowledge moving " + repository + " " + MutableV1Ref + " from " + oldTarget + " to " + newTarget
}

// PlanV1Move validates an inert move without reading a repository or invoking
// Git. It accepts only A-to-B installation or B-to-A restoration.
func PlanV1Move(policy TagMovePolicy, request TagMoveRequest) (TagMovePlan, error) {
	if err := validateTagMovePolicy(policy); err != nil {
		return TagMovePlan{}, err
	}
	if request.Repository != policy.Repository || request.RepositoryDatabaseID != policy.RepositoryDatabaseID || request.RemoteURL != policy.RemoteURL {
		return TagMovePlan{}, fmt.Errorf("%w: explicit repository or remote binding differs", ErrTagMovePolicy)
	}
	if request.Ref != MutableV1Ref {
		return TagMovePlan{}, fmt.Errorf("%w: only the reviewed mutable v1 ref is accepted", ErrTagMovePolicy)
	}
	if !filepath.IsAbs(request.Worktree) || filepath.Clean(request.Worktree) != request.Worktree || strings.IndexByte(request.Worktree, 0) >= 0 {
		return TagMovePlan{}, fmt.Errorf("%w: worktree must be an absolute canonical path", ErrTagMovePolicy)
	}

	direction := TagMoveDirection("")
	switch {
	case request.ExpectedOld == policy.CommitA && request.NewTarget == policy.CommitB:
		direction = InstallAffectedMarker
	case request.ExpectedOld == policy.CommitB && request.NewTarget == policy.CommitA:
		direction = RestoreKnownGood
	default:
		return TagMovePlan{}, fmt.Errorf("%w: transition is not the exact reviewed A/B direction", ErrTagMovePolicy)
	}
	wantAcknowledgement := RequiredTagMoveAcknowledgement(policy.Repository, request.ExpectedOld, request.NewTarget)
	if request.Acknowledgement != wantAcknowledgement {
		return TagMovePlan{}, fmt.Errorf("%w: literal operator acknowledgement differs", ErrTagMovePolicy)
	}
	return TagMovePlan{
		Repository:           policy.Repository,
		RepositoryDatabaseID: policy.RepositoryDatabaseID,
		Ref:                  MutableV1Ref,
		ExpectedOld:          request.ExpectedOld,
		NewTarget:            request.NewTarget,
		Direction:            direction,
	}, nil
}

// MoveV1 verifies the reviewed local and remote topology, performs one
// force-with-lease push for refs/tags/v1, and reads the remote ref back. It never
// creates a tag, accepts an absent ref, discovers a repository from content, or
// mutates a branch, fixture tag, release tag, or wildcard ref.
func MoveV1(ctx context.Context, runner GitCommandBoundary, policy TagMovePolicy, request TagMoveRequest) (TagMoveResult, error) {
	return moveV1(ctx, runner, policy, request, time.Now)
}

func moveV1(ctx context.Context, runner GitCommandBoundary, policy TagMovePolicy, request TagMoveRequest, now func() time.Time) (TagMoveResult, error) {
	plan, err := PlanV1Move(policy, request)
	if err != nil {
		return TagMoveResult{}, err
	}
	result := TagMoveResult{Plan: plan}
	if runner == nil {
		return result, fmt.Errorf("%w: Git command boundary is absent", ErrTagMovePolicy)
	}
	if now == nil {
		return result, fmt.Errorf("%w: observation clock is absent", ErrTagMovePolicy)
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}

	if err := verifyLocalPreconditions(ctx, runner, request.Worktree, policy); err != nil {
		return result, err
	}
	before, err := readRemoteTopology(ctx, runner, request.Worktree, policy.RemoteURL)
	if err != nil {
		return result, err
	}
	if err := verifyRemoteTopology(before, policy); err != nil {
		return result, err
	}
	result.Before = before.v1
	result.BeforeObservedAt = canonicalObservationTime(now())
	if before.v1 != plan.ExpectedOld {
		if before.v1 == policy.CommitB {
			result.Recovery = recoveryPlan(policy, before.v1)
		}
		return result, fmt.Errorf("%w: remote v1 does not equal the exact expected-old object", ErrTagMovePrecondition)
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}

	pushArguments := exactPushArguments(plan.ExpectedOld, plan.NewTarget, policy.RemoteURL)
	pushOutput, pushErr := runBounded(ctx, runner, request.Worktree, pushArguments...)
	pushConfirmed := pushErr == nil && exactPushWasApplied(pushOutput, plan.NewTarget)
	interrupted := ctx.Err()
	if interrupted == nil && (errors.Is(pushErr, context.Canceled) || errors.Is(pushErr, context.DeadlineExceeded)) {
		interrupted = pushErr
	}

	readContext := ctx
	cancel := func() {}
	if interrupted != nil || ctx.Err() != nil {
		readContext, cancel = context.WithTimeout(context.WithoutCancel(ctx), reconcileTimeout)
	}
	defer cancel()
	after, readErr := readRemoteTopology(readContext, runner, request.Worktree, policy.RemoteURL)
	if readErr != nil {
		result.Recovery = recoveryPlan(policy, "")
		if interrupted != nil {
			return result, errors.Join(interrupted, ErrTagMoveUnknown)
		}
		if plan.Direction == RestoreKnownGood {
			return result, errors.Join(ErrRestoreFailed, ErrTagMoveUnknown)
		}
		return result, ErrTagMoveUnknown
	}
	result.After = after.v1
	result.AfterObservedAt = canonicalObservationTime(now())
	if topologyErr := verifyFixedRemoteTopology(after, policy); topologyErr != nil {
		result.Recovery = recoveryPlan(policy, after.v1)
		if interrupted != nil {
			return result, errors.Join(interrupted, ErrConcurrentTagMove)
		}
		return result, ErrConcurrentTagMove
	}

	switch after.v1 {
	case plan.NewTarget:
		result.Verified = true
		if interrupted != nil {
			if plan.NewTarget == policy.CommitB {
				result.Recovery = recoveryPlan(policy, after.v1)
			}
			return result, interrupted
		}
		if pushErr != nil || !pushConfirmed {
			if plan.NewTarget == policy.CommitB {
				result.Recovery = recoveryPlan(policy, after.v1)
			}
			return result, ErrTagMoveUnconfirmed
		}
		return result, nil
	case plan.ExpectedOld:
		if interrupted != nil {
			if plan.Direction == InstallAffectedMarker {
				// A single immediate A readback cannot prove a canceled client
				// process has quiesced the remote receive transaction. Require a
				// fresh readback/recovery decision instead of claiming unchanged.
				result.Recovery = recoveryPlan(policy, after.v1)
				return result, errors.Join(interrupted, ErrTagMoveUnknown)
			}
			result.Recovery = recoveryPlan(policy, after.v1)
			return result, errors.Join(interrupted, ErrRestoreFailed)
		}
		if plan.Direction == RestoreKnownGood {
			result.Recovery = recoveryPlan(policy, after.v1)
			return result, ErrRestoreFailed
		}
		return result, ErrTagMoveFailed
	default:
		result.Recovery = recoveryPlan(policy, after.v1)
		if interrupted != nil {
			return result, errors.Join(interrupted, ErrConcurrentTagMove)
		}
		return result, ErrConcurrentTagMove
	}
}

func canonicalObservationTime(value time.Time) string {
	return value.UTC().Format(time.RFC3339Nano)
}

func validateTagMovePolicy(policy TagMovePolicy) error {
	if !validRepositoryName(policy.Repository) {
		return fmt.Errorf("%w: repository name is not an exact owner/name", ErrTagMovePolicy)
	}
	if policy.RepositoryDatabaseID <= 0 || policy.RepositoryDatabaseID > 9007199254740991 {
		return fmt.Errorf("%w: repository database ID is outside the accepted range", ErrTagMovePolicy)
	}
	if err := validateAllowedRemote(policy.RemoteURL, policy.Repository, policy.TestOnlyAllowLocalRemote); err != nil {
		return fmt.Errorf("%w: remote URL is not accepted", ErrTagMovePolicy)
	}
	values := []string{policy.ReviewedMain, policy.CommitA, policy.CommitB, policy.FixtureATagObject, policy.FixtureBTagObject}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if !isSHA1(value) {
			return fmt.Errorf("%w: reviewed object identity is not a full lowercase SHA-1", ErrTagMovePolicy)
		}
		if _, duplicate := seen[value]; duplicate {
			return fmt.Errorf("%w: reviewed object identities are not distinct", ErrTagMovePolicy)
		}
		seen[value] = struct{}{}
	}
	return nil
}

func validRepositoryName(value string) bool {
	if len(value) < 3 || len(value) > 201 || strings.Count(value, "/") != 1 || strings.Contains(value, "..") || !utf8.ValidString(value) {
		return false
	}
	parts := strings.Split(value, "/")
	for _, part := range parts {
		if part == "" || part == "." || part == ".." || len(part) > 100 {
			return false
		}
		for _, character := range part {
			if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || character == '-' || character == '_' || character == '.' {
				continue
			}
			return false
		}
	}
	return true
}

func validateAllowedRemote(value, repository string, allowLocalTestRemote bool) error {
	if value == "" || len(value) > 2048 || !utf8.ValidString(value) || strings.ContainsAny(value, "\x00\r\n?#*[]") {
		return errors.New("invalid remote")
	}
	if strings.HasPrefix(value, "-") || strings.HasPrefix(strings.ToLower(value), "ext::") {
		return errors.New("invalid remote")
	}
	if filepath.IsAbs(value) {
		if !allowLocalTestRemote || filepath.Clean(value) != value {
			return errors.New("invalid remote")
		}
		return nil
	}
	parsed, err := url.Parse(value)
	if err == nil && parsed.Scheme != "" {
		switch strings.ToLower(parsed.Scheme) {
		case "https", "ssh":
		default:
			return errors.New("invalid remote")
		}
		if parsed.Opaque != "" || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Port() != "" || !strings.EqualFold(parsed.Hostname(), "github.com") || !remotePathNamesRepository(parsed.Path, repository) {
			return errors.New("invalid remote")
		}
		if parsed.User != nil {
			if _, hasPassword := parsed.User.Password(); hasPassword || strings.ToLower(parsed.Scheme) != "ssh" || parsed.User.Username() != "git" {
				return errors.New("invalid remote")
			}
		}
		return nil
	}
	// Git's familiar scp-like form is accepted only with the non-secret "git"
	// SSH user and a nonempty host/path. Other userinfo-shaped strings fail shut.
	at := strings.IndexByte(value, '@')
	colon := strings.IndexByte(value, ':')
	if at != 3 || value[:at] != "git" || colon <= at+1 || colon == len(value)-1 || !strings.EqualFold(value[at+1:colon], "github.com") || !remotePathNamesRepository(value[colon+1:], repository) {
		return errors.New("invalid remote")
	}
	return nil
}

func remotePathNamesRepository(path, repository string) bool {
	path = strings.TrimPrefix(path, "/")
	return path == repository || path == repository+".git"
}

func verifyLocalPreconditions(ctx context.Context, runner GitCommandBoundary, worktree string, policy TagMovePolicy) error {
	// Do not invoke status, diff, checkout, or any other command that examines
	// worktree content: repository-controlled attributes can make those commands
	// execute clean filters. The actual mutation borrows only the separately
	// validated object directory and pushes exact reviewed object IDs.
	branch, err := runBounded(ctx, runner, worktree, "symbolic-ref", "--quiet", "HEAD")
	if err != nil || trimOneLine(branch) != "refs/heads/main" {
		return fmt.Errorf("%w: local checkout is not the reviewed main branch", ErrTagMovePrecondition)
	}
	head, err := runBounded(ctx, runner, worktree, "rev-parse", "--verify", "HEAD")
	if err != nil || trimOneLine(head) != policy.ReviewedMain {
		return fmt.Errorf("%w: local HEAD differs from the reviewed main commit", ErrTagMovePrecondition)
	}
	for _, query := range []struct {
		oid string
		typ string
	}{
		{policy.ReviewedMain, "commit"},
		{policy.CommitA, "commit"},
		{policy.CommitB, "commit"},
		{policy.FixtureATagObject, "tag"},
		{policy.FixtureBTagObject, "tag"},
	} {
		output, typeErr := runBounded(ctx, runner, worktree, "cat-file", "-t", query.oid)
		if typeErr != nil || trimOneLine(output) != query.typ {
			return fmt.Errorf("%w: reviewed local Git object is absent or has the wrong type", ErrTagMovePrecondition)
		}
	}
	for _, ancestor := range []string{policy.CommitA, policy.CommitB} {
		output, ancestorErr := runBounded(ctx, runner, worktree, "merge-base", "--is-ancestor", ancestor, policy.ReviewedMain)
		if ancestorErr != nil || len(output) != 0 {
			return fmt.Errorf("%w: A/B commit is not in the reviewed history", ErrTagMovePrecondition)
		}
	}
	for _, args := range [][]string{
		{"remote", "get-url", "--all", tagRemoteName},
		{"remote", "get-url", "--push", "--all", tagRemoteName},
	} {
		output, remoteErr := runBounded(ctx, runner, worktree, args...)
		if remoteErr != nil || !oneExactLine(output, policy.RemoteURL) {
			return fmt.Errorf("%w: configured origin differs from the explicitly allowed remote", ErrTagMovePrecondition)
		}
	}
	return nil
}

func readRemoteTopology(ctx context.Context, runner GitCommandBoundary, worktree, allowedRemote string) (remoteTagState, error) {
	output, err := runBounded(ctx, runner, worktree,
		"ls-remote", allowedRemote,
		"refs/heads/main",
		"refs/tags/fixture-a", "refs/tags/fixture-a^{}",
		"refs/tags/fixture-b", "refs/tags/fixture-b^{}",
		MutableV1Ref,
	)
	if err != nil {
		return remoteTagState{}, fmt.Errorf("%w: remote refs could not be read", ErrTagMovePrecondition)
	}
	refs, err := parseRemoteRefs(output)
	if err != nil {
		return remoteTagState{}, fmt.Errorf("%w: remote ref response is malformed", ErrTagMovePrecondition)
	}
	want := []string{"refs/heads/main", "refs/tags/fixture-a", "refs/tags/fixture-a^{}", "refs/tags/fixture-b", "refs/tags/fixture-b^{}", MutableV1Ref}
	if len(refs) != len(want) {
		return remoteTagState{}, fmt.Errorf("%w: remote topology is incomplete", ErrTagMovePrecondition)
	}
	for _, name := range want {
		if _, ok := refs[name]; !ok {
			return remoteTagState{}, fmt.Errorf("%w: remote topology is incomplete", ErrTagMovePrecondition)
		}
	}
	return remoteTagState{
		main:         refs["refs/heads/main"],
		fixtureA:     refs["refs/tags/fixture-a"],
		fixtureAPeel: refs["refs/tags/fixture-a^{}"],
		fixtureB:     refs["refs/tags/fixture-b"],
		fixtureBPeel: refs["refs/tags/fixture-b^{}"],
		v1:           refs[MutableV1Ref],
	}, nil
}

func verifyRemoteTopology(state remoteTagState, policy TagMovePolicy) error {
	if err := verifyFixedRemoteTopology(state, policy); err != nil {
		return err
	}
	if state.v1 != policy.CommitA && state.v1 != policy.CommitB {
		return fmt.Errorf("%w: mutable v1 does not point directly to A or B", ErrTagMovePrecondition)
	}
	return nil
}

func verifyFixedRemoteTopology(state remoteTagState, policy TagMovePolicy) error {
	if state.main != policy.ReviewedMain || state.fixtureA != policy.FixtureATagObject || state.fixtureAPeel != policy.CommitA || state.fixtureB != policy.FixtureBTagObject || state.fixtureBPeel != policy.CommitB {
		return fmt.Errorf("%w: immutable remote topology differs from the reviewed policy", ErrTagMovePrecondition)
	}
	return nil
}

func exactPushArguments(oldTarget, newTarget, allowedRemote string) []string {
	return []string{
		"push", "--porcelain", "--no-verify",
		"--force-with-lease=" + MutableV1Ref + ":" + oldTarget,
		allowedRemote,
		newTarget + ":" + MutableV1Ref,
	}
}

func exactPushWasApplied(output []byte, newTarget string) bool {
	if len(output) == 0 || len(output) > maxGitCommandOutput || !utf8.Valid(output) || strings.IndexByte(string(output), 0) >= 0 {
		return false
	}
	wantRefspec := newTarget + ":" + MutableV1Ref
	statusCount := 0
	confirmed := false
	for _, line := range strings.Split(strings.ReplaceAll(string(output), "\r\n", "\n"), "\n") {
		fields := strings.Split(line, "\t")
		if len(fields) != 3 {
			continue
		}
		statusCount++
		if fields[0] == "+" && fields[1] == wantRefspec && strings.HasSuffix(fields[2], " (forced update)") {
			confirmed = true
		}
	}
	return statusCount == 1 && confirmed
}

func recoveryPlan(policy TagMovePolicy, observed string) *RecoveryPlan {
	plan := &RecoveryPlan{
		Required:          true,
		ObservedTarget:    observed,
		KnownGoodTarget:   policy.CommitA,
		ReadbackArguments: []string{"ls-remote", policy.RemoteURL, MutableV1Ref},
	}
	if observed == policy.CommitB {
		plan.RestoreArguments = exactPushArguments(policy.CommitB, policy.CommitA, policy.RemoteURL)
		plan.RestoreAcknowledgement = RequiredTagMoveAcknowledgement(policy.Repository, policy.CommitB, policy.CommitA)
	}
	return plan
}

func runBounded(ctx context.Context, runner GitCommandBoundary, worktree string, arguments ...string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	output, err := runner.RunGit(ctx, worktree, arguments...)
	if len(output) > maxGitCommandOutput {
		return nil, errors.New("Git command output exceeded the accepted bound")
	}
	if err != nil {
		if contextErr := ctx.Err(); contextErr != nil {
			return nil, contextErr
		}
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, err
		}
		return nil, errors.New("Git command failed")
	}
	return output, nil
}

func parseRemoteRefs(output []byte) (map[string]string, error) {
	if len(output) == 0 || len(output) > maxGitCommandOutput || !utf8.Valid(output) || strings.IndexByte(string(output), 0) >= 0 {
		return nil, errors.New("invalid ls-remote output")
	}
	text := strings.TrimSuffix(string(output), "\n")
	if strings.HasSuffix(text, "\r") {
		text = strings.TrimSuffix(text, "\r")
	}
	refs := make(map[string]string)
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSuffix(line, "\r")
		parts := strings.Split(line, "\t")
		if len(parts) != 2 || !isSHA1(parts[0]) || !validRemoteRefName(parts[1]) {
			return nil, errors.New("invalid ls-remote record")
		}
		if _, duplicate := refs[parts[1]]; duplicate {
			return nil, errors.New("duplicate ls-remote record")
		}
		refs[parts[1]] = parts[0]
	}
	return refs, nil
}

func validRemoteRefName(value string) bool {
	switch value {
	case "refs/heads/main", "refs/tags/fixture-a", "refs/tags/fixture-a^{}", "refs/tags/fixture-b", "refs/tags/fixture-b^{}", MutableV1Ref:
		return true
	default:
		return false
	}
}

func oneExactLine(output []byte, want string) bool {
	if len(output) == 0 || len(output) > 4096 || !utf8.Valid(output) || strings.IndexByte(string(output), 0) >= 0 {
		return false
	}
	return trimOneLine(output) == want && !strings.Contains(strings.TrimSuffix(strings.TrimSuffix(string(output), "\n"), "\r"), "\n")
}

func trimOneLine(output []byte) string {
	value := string(output)
	value = strings.TrimSuffix(value, "\n")
	value = strings.TrimSuffix(value, "\r")
	return value
}
