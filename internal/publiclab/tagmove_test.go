package publiclab

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

type execGitBoundary struct {
	executable string
	mu         sync.Mutex
	calls      [][]string
}

func (r *execGitBoundary) RunGit(ctx context.Context, worktree string, arguments ...string) ([]byte, error) {
	r.mu.Lock()
	r.calls = append(r.calls, append([]string(nil), arguments...))
	r.mu.Unlock()
	command := exec.CommandContext(ctx, r.executable, append([]string{"-C", worktree}, arguments...)...)
	command.Env = append(os.Environ(),
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_TERMINAL_PROMPT=0",
		"LC_ALL=C",
	)
	return command.CombinedOutput()
}

func (r *execGitBoundary) callSnapshot() [][]string {
	r.mu.Lock()
	defer r.mu.Unlock()
	result := make([][]string, len(r.calls))
	for index := range r.calls {
		result[index] = append([]string(nil), r.calls[index]...)
	}
	return result
}

type interceptGitBoundary struct {
	base      GitCommandBoundary
	intercept func(context.Context, string, []string) ([]byte, error, bool)
}

func (r interceptGitBoundary) RunGit(ctx context.Context, worktree string, arguments ...string) ([]byte, error) {
	if output, err, handled := r.intercept(ctx, worktree, append([]string(nil), arguments...)); handled {
		return output, err
	}
	return r.base.RunGit(ctx, worktree, arguments...)
}

type tagMoveFixture struct {
	git      string
	root     string
	remote   string
	worktree string
	policy   TagMovePolicy
	runner   *execGitBoundary
}

func newTagMoveFixture(t *testing.T) tagMoveFixture {
	t.Helper()
	git, err := exec.LookPath("git")
	if err != nil {
		t.Skip("Git executable is unavailable")
	}
	artifact, err := Build(context.Background(), sourceRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	bundle := filepath.Join(root, BundleFilename)
	if err := os.WriteFile(bundle, artifact.Bundle, 0o600); err != nil {
		t.Fatal(err)
	}
	remote := filepath.Join(root, "allowed-remote.git")
	worktree := filepath.Join(root, "operator-worktree")
	runGit(t, git, "clone", "--bare", "--quiet", bundle, remote)
	runGit(t, git, "clone", "--quiet", remote, worktree)

	return tagMoveFixture{
		git:      git,
		root:     root,
		remote:   remote,
		worktree: worktree,
		policy: TagMovePolicy{
			Repository:               "example/cirewind-lab",
			RepositoryDatabaseID:     101,
			RemoteURL:                remote,
			ReviewedMain:             artifact.Model.Commits[5].ObjectID,
			CommitA:                  artifact.Model.Commits[1].ObjectID,
			CommitB:                  artifact.Model.Commits[2].ObjectID,
			FixtureATagObject:        artifact.Model.Tags[0].ObjectID,
			FixtureBTagObject:        artifact.Model.Tags[1].ObjectID,
			TestOnlyAllowLocalRemote: true,
		},
		runner: &execGitBoundary{executable: git},
	}
}

func (f tagMoveFixture) request(oldTarget, newTarget string) TagMoveRequest {
	return TagMoveRequest{
		Worktree:             f.worktree,
		Repository:           f.policy.Repository,
		RepositoryDatabaseID: f.policy.RepositoryDatabaseID,
		RemoteURL:            f.policy.RemoteURL,
		Ref:                  MutableV1Ref,
		ExpectedOld:          oldTarget,
		NewTarget:            newTarget,
		Acknowledgement:      RequiredTagMoveAcknowledgement(f.policy.Repository, oldTarget, newTarget),
	}
}

func (f tagMoveFixture) remoteV1(t *testing.T) string {
	t.Helper()
	return strings.TrimSpace(runGit(t, f.git, "--git-dir", f.remote, "rev-parse", MutableV1Ref))
}

func TestMoveV1InstallsAndRestoresWithExactLease(t *testing.T) {
	fixture := newTagMoveFixture(t)
	install := fixture.request(fixture.policy.CommitA, fixture.policy.CommitB)
	result, err := MoveV1(context.Background(), fixture.runner, fixture.policy, install)
	if err != nil {
		t.Fatal(err)
	}
	if result.Before != fixture.policy.CommitA || result.After != fixture.policy.CommitB || !result.Verified || result.Recovery != nil {
		t.Fatalf("install result=%+v", result)
	}
	if got := fixture.remoteV1(t); got != fixture.policy.CommitB {
		t.Fatalf("remote v1=%s want B=%s", got, fixture.policy.CommitB)
	}
	wantInstall := exactPushArguments(fixture.policy.CommitA, fixture.policy.CommitB, fixture.policy.RemoteURL)
	assertOnlyExactPush(t, fixture.runner.callSnapshot(), wantInstall)

	fixture.runner.mu.Lock()
	fixture.runner.calls = nil
	fixture.runner.mu.Unlock()
	restore := fixture.request(fixture.policy.CommitB, fixture.policy.CommitA)
	result, err = MoveV1(context.Background(), fixture.runner, fixture.policy, restore)
	if err != nil {
		t.Fatal(err)
	}
	if result.Plan.Direction != RestoreKnownGood || result.Before != fixture.policy.CommitB || result.After != fixture.policy.CommitA || !result.Verified || result.Recovery != nil {
		t.Fatalf("restore result=%+v", result)
	}
	if got := fixture.remoteV1(t); got != fixture.policy.CommitA {
		t.Fatalf("remote v1=%s want A=%s", got, fixture.policy.CommitA)
	}
	assertOnlyExactPush(t, fixture.runner.callSnapshot(), exactPushArguments(fixture.policy.CommitB, fixture.policy.CommitA, fixture.policy.RemoteURL))
}

func assertOnlyExactPush(t *testing.T, calls [][]string, want []string) {
	t.Helper()
	var pushes [][]string
	for _, call := range calls {
		if len(call) > 0 && call[0] == "push" {
			pushes = append(pushes, call)
			for _, argument := range call {
				if argument == "--force" || argument == "-f" || strings.ContainsAny(argument, "*?[") || strings.HasPrefix(argument, "refs/heads/") {
					t.Fatalf("unsafe Git push argument in %q", call)
				}
			}
		}
	}
	if len(pushes) != 1 || !reflect.DeepEqual(pushes[0], want) {
		t.Fatalf("push calls=%q want exactly %q", pushes, want)
	}
}

func TestPlanV1MoveRejectsEveryOtherRefDirectionAndBinding(t *testing.T) {
	fixture := newTagMoveFixture(t)
	valid := fixture.request(fixture.policy.CommitA, fixture.policy.CommitB)
	if plan, err := PlanV1Move(fixture.policy, valid); err != nil || plan.Direction != InstallAffectedMarker {
		t.Fatalf("valid plan=%+v err=%v", plan, err)
	}

	tests := map[string]func(*TagMoveRequest){
		"branch ref":             func(r *TagMoveRequest) { r.Ref = "refs/heads/main" },
		"fixture tag":            func(r *TagMoveRequest) { r.Ref = "refs/tags/fixture-a" },
		"release tag":            func(r *TagMoveRequest) { r.Ref = "refs/tags/v0.2.0" },
		"wildcard ref":           func(r *TagMoveRequest) { r.Ref = "refs/tags/*" },
		"short old":              func(r *TagMoveRequest) { r.ExpectedOld = r.ExpectedOld[:12] },
		"unrelated direction":    func(r *TagMoveRequest) { r.NewTarget = fixture.policy.ReviewedMain },
		"same target":            func(r *TagMoveRequest) { r.NewTarget = r.ExpectedOld },
		"repository mismatch":    func(r *TagMoveRequest) { r.Repository = "other/cirewind-lab" },
		"repository ID mismatch": func(r *TagMoveRequest) { r.RepositoryDatabaseID++ },
		"remote mismatch":        func(r *TagMoveRequest) { r.RemoteURL = filepath.Join(fixture.root, "other.git") },
		"ack suffix":             func(r *TagMoveRequest) { r.Acknowledgement += " " },
		"ack wrong ref": func(r *TagMoveRequest) {
			r.Acknowledgement = strings.ReplaceAll(r.Acknowledgement, MutableV1Ref, "refs/heads/main")
		},
		"relative worktree": func(r *TagMoveRequest) { r.Worktree = "operator-worktree" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			request := valid
			mutate(&request)
			if _, err := PlanV1Move(fixture.policy, request); !errors.Is(err, ErrTagMovePolicy) {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

func TestMoveV1UsesReviewedObjectsAndExpectedOldReadback(t *testing.T) {
	t.Run("untracked worktree content is outside the exact-object mutation", func(t *testing.T) {
		fixture := newTagMoveFixture(t)
		if err := os.WriteFile(filepath.Join(fixture.worktree, "untracked"), []byte("not reviewed"), 0o600); err != nil {
			t.Fatal(err)
		}
		result, err := MoveV1(context.Background(), fixture.runner, fixture.policy, fixture.request(fixture.policy.CommitA, fixture.policy.CommitB))
		if err != nil || !result.Verified || fixture.remoteV1(t) != fixture.policy.CommitB {
			t.Fatalf("error=%v", err)
		}
		assertOnlyExactPush(t, fixture.runner.callSnapshot(), exactPushArguments(fixture.policy.CommitA, fixture.policy.CommitB, fixture.policy.RemoteURL))
	})

	t.Run("expected old mismatch", func(t *testing.T) {
		fixture := newTagMoveFixture(t)
		runGit(t, fixture.git, "--git-dir", fixture.remote, "update-ref", MutableV1Ref, fixture.policy.CommitB, fixture.policy.CommitA)
		_, err := MoveV1(context.Background(), fixture.runner, fixture.policy, fixture.request(fixture.policy.CommitA, fixture.policy.CommitB))
		if !errors.Is(err, ErrTagMovePrecondition) || fixture.remoteV1(t) != fixture.policy.CommitB {
			t.Fatalf("error=%v", err)
		}
		assertNoPush(t, fixture.runner.callSnapshot())
	})

	t.Run("missing mutable ref", func(t *testing.T) {
		fixture := newTagMoveFixture(t)
		runGit(t, fixture.git, "--git-dir", fixture.remote, "update-ref", "-d", MutableV1Ref, fixture.policy.CommitA)
		_, err := MoveV1(context.Background(), fixture.runner, fixture.policy, fixture.request(fixture.policy.CommitA, fixture.policy.CommitB))
		if !errors.Is(err, ErrTagMovePrecondition) {
			t.Fatalf("error=%v", err)
		}
		assertNoPush(t, fixture.runner.callSnapshot())
	})

	t.Run("immutable fixture changed", func(t *testing.T) {
		fixture := newTagMoveFixture(t)
		runGit(t, fixture.git, "--git-dir", fixture.remote, "update-ref", "refs/tags/fixture-a", fixture.policy.CommitA, fixture.policy.FixtureATagObject)
		_, err := MoveV1(context.Background(), fixture.runner, fixture.policy, fixture.request(fixture.policy.CommitA, fixture.policy.CommitB))
		if !errors.Is(err, ErrTagMovePrecondition) {
			t.Fatalf("error=%v", err)
		}
		assertNoPush(t, fixture.runner.callSnapshot())
	})

	t.Run("configured remote differs", func(t *testing.T) {
		fixture := newTagMoveFixture(t)
		other := filepath.Join(fixture.root, "other.git")
		runGit(t, fixture.git, "init", "--bare", "--initial-branch=main", other)
		runGit(t, fixture.git, "-C", fixture.worktree, "remote", "set-url", "origin", other)
		_, err := MoveV1(context.Background(), fixture.runner, fixture.policy, fixture.request(fixture.policy.CommitA, fixture.policy.CommitB))
		if !errors.Is(err, ErrTagMovePrecondition) || fixture.remoteV1(t) != fixture.policy.CommitA {
			t.Fatalf("error=%v", err)
		}
		assertNoPush(t, fixture.runner.callSnapshot())
	})

	t.Run("additional push target fails closed", func(t *testing.T) {
		fixture := newTagMoveFixture(t)
		other := filepath.Join(fixture.root, "other.git")
		runGit(t, fixture.git, "init", "--bare", "--initial-branch=main", other)
		runGit(t, fixture.git, "-C", fixture.worktree, "remote", "set-url", "--add", "--push", "origin", fixture.remote)
		runGit(t, fixture.git, "-C", fixture.worktree, "remote", "set-url", "--add", "--push", "origin", other)
		_, err := MoveV1(context.Background(), fixture.runner, fixture.policy, fixture.request(fixture.policy.CommitA, fixture.policy.CommitB))
		if !errors.Is(err, ErrTagMovePrecondition) || fixture.remoteV1(t) != fixture.policy.CommitA {
			t.Fatalf("error=%v", err)
		}
		assertNoPush(t, fixture.runner.callSnapshot())
	})
}

func assertNoPush(t *testing.T, calls [][]string) {
	t.Helper()
	for _, call := range calls {
		if len(call) > 0 && call[0] == "push" {
			t.Fatalf("unexpected push: %q", call)
		}
	}
}

func TestMoveV1ExactLeaseRejectsConcurrentMove(t *testing.T) {
	fixture := newTagMoveFixture(t)
	mutated := false
	runner := interceptGitBoundary{
		base: fixture.runner,
		intercept: func(ctx context.Context, worktree string, arguments []string) ([]byte, error, bool) {
			if !mutated && len(arguments) > 0 && arguments[0] == "push" {
				mutated = true
				runGit(t, fixture.git, "--git-dir", fixture.remote, "update-ref", MutableV1Ref, fixture.policy.ReviewedMain, fixture.policy.CommitA)
			}
			return nil, nil, false
		},
	}
	result, err := MoveV1(context.Background(), runner, fixture.policy, fixture.request(fixture.policy.CommitA, fixture.policy.CommitB))
	if !errors.Is(err, ErrConcurrentTagMove) {
		t.Fatalf("error=%v result=%+v", err, result)
	}
	if result.After != fixture.policy.ReviewedMain || result.Verified || result.Recovery == nil || len(result.Recovery.RestoreArguments) != 0 {
		t.Fatalf("concurrent result=%+v", result)
	}
	if got := fixture.remoteV1(t); got != fixture.policy.ReviewedMain {
		t.Fatalf("exact lease overwrote concurrent target: %s", got)
	}
	assertOnlyExactPush(t, fixture.runner.callSnapshot(), exactPushArguments(fixture.policy.CommitA, fixture.policy.CommitB, fixture.policy.RemoteURL))
}

func TestMoveV1DoesNotClaimCausationWhenConcurrentMoveReachesSameTarget(t *testing.T) {
	fixture := newTagMoveFixture(t)
	mutated := false
	runner := interceptGitBoundary{
		base: fixture.runner,
		intercept: func(_ context.Context, _ string, arguments []string) ([]byte, error, bool) {
			if !mutated && len(arguments) > 0 && arguments[0] == "push" {
				mutated = true
				runGit(t, fixture.git, "--git-dir", fixture.remote, "update-ref", MutableV1Ref, fixture.policy.CommitB, fixture.policy.CommitA)
			}
			return nil, nil, false
		},
	}
	result, err := MoveV1(context.Background(), runner, fixture.policy, fixture.request(fixture.policy.CommitA, fixture.policy.CommitB))
	if !errors.Is(err, ErrTagMoveUnconfirmed) || !result.Verified || result.After != fixture.policy.CommitB || result.Recovery == nil {
		t.Fatalf("error=%v result=%+v", err, result)
	}
	if strings.Contains(strings.ToLower(err.Error()), "was applied") || strings.Contains(strings.ToLower(err.Error()), "we moved") {
		t.Fatalf("ambiguous concurrent result overclaims causation: %q", err)
	}
	assertOnlyExactPush(t, fixture.runner.callSnapshot(), exactPushArguments(fixture.policy.CommitA, fixture.policy.CommitB, fixture.policy.RemoteURL))
}

func TestMoveV1UsesAllowedRemoteAfterOriginIsConcurrentlyReconfigured(t *testing.T) {
	fixture := newTagMoveFixture(t)
	other := filepath.Join(fixture.root, "redirected-remote.git")
	runGit(t, fixture.git, "clone", "--bare", "--quiet", filepath.Join(fixture.root, BundleFilename), other)
	changed := false
	runner := interceptGitBoundary{
		base: fixture.runner,
		intercept: func(_ context.Context, worktree string, arguments []string) ([]byte, error, bool) {
			if !changed && len(arguments) > 0 && arguments[0] == "push" {
				changed = true
				runGit(t, fixture.git, "-C", worktree, "remote", "set-url", "origin", other)
			}
			return nil, nil, false
		},
	}
	result, err := MoveV1(context.Background(), runner, fixture.policy, fixture.request(fixture.policy.CommitA, fixture.policy.CommitB))
	if err != nil || !result.Verified {
		t.Fatalf("error=%v result=%+v", err, result)
	}
	if got := fixture.remoteV1(t); got != fixture.policy.CommitB {
		t.Fatalf("allowed remote v1=%s want B=%s", got, fixture.policy.CommitB)
	}
	if got := strings.TrimSpace(runGit(t, fixture.git, "--git-dir", other, "rev-parse", MutableV1Ref)); got != fixture.policy.CommitA {
		t.Fatalf("reconfigured origin was mutated: v1=%s", got)
	}
	for _, call := range fixture.runner.callSnapshot() {
		if len(call) > 0 && call[0] == "ls-remote" && (len(call) < 2 || call[1] != fixture.policy.RemoteURL) {
			t.Fatalf("readback did not use the exact allowed remote: %q", call)
		}
	}
}

func TestMoveV1CancellationAndInterruptedReadback(t *testing.T) {
	t.Run("canceled before commands", func(t *testing.T) {
		fixture := newTagMoveFixture(t)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := MoveV1(ctx, fixture.runner, fixture.policy, fixture.request(fixture.policy.CommitA, fixture.policy.CommitB))
		if !errors.Is(err, context.Canceled) || len(fixture.runner.callSnapshot()) != 0 || fixture.remoteV1(t) != fixture.policy.CommitA {
			t.Fatalf("error=%v calls=%q", err, fixture.runner.callSnapshot())
		}
	})

	t.Run("push applied before cancellation", func(t *testing.T) {
		fixture := newTagMoveFixture(t)
		ctx, cancel := context.WithCancel(context.Background())
		runner := interceptGitBoundary{
			base: fixture.runner,
			intercept: func(_ context.Context, worktree string, arguments []string) ([]byte, error, bool) {
				if len(arguments) == 0 || arguments[0] != "push" {
					return nil, nil, false
				}
				output, err := fixture.runner.RunGit(context.Background(), worktree, arguments...)
				if err != nil {
					t.Fatalf("controlled push: %v: %s", err, output)
				}
				cancel()
				return nil, context.Canceled, true
			},
		}
		result, err := MoveV1(ctx, runner, fixture.policy, fixture.request(fixture.policy.CommitA, fixture.policy.CommitB))
		if !errors.Is(err, context.Canceled) || !result.Verified || result.After != fixture.policy.CommitB || result.Recovery == nil {
			t.Fatalf("error=%v result=%+v", err, result)
		}
		if !reflect.DeepEqual(result.Recovery.RestoreArguments, exactPushArguments(fixture.policy.CommitB, fixture.policy.CommitA, fixture.policy.RemoteURL)) {
			t.Fatalf("recovery=%+v", result.Recovery)
		}
	})

	t.Run("interrupted outcome unknown", func(t *testing.T) {
		fixture := newTagMoveFixture(t)
		ctx, cancel := context.WithCancel(context.Background())
		pushed := false
		runner := interceptGitBoundary{
			base: fixture.runner,
			intercept: func(_ context.Context, worktree string, arguments []string) ([]byte, error, bool) {
				if len(arguments) > 0 && arguments[0] == "push" {
					pushed = true
					cancel()
					return nil, context.Canceled, true
				}
				if pushed && len(arguments) > 0 && arguments[0] == "ls-remote" {
					return []byte("Authorization: Bearer SYNTHETIC_TEST_TOKEN_DO_NOT_USE"), errors.New("token=SYNTHETIC_TEST_TOKEN_DO_NOT_USE"), true
				}
				return nil, nil, false
			},
		}
		result, err := MoveV1(ctx, runner, fixture.policy, fixture.request(fixture.policy.CommitA, fixture.policy.CommitB))
		if !errors.Is(err, context.Canceled) || !errors.Is(err, ErrTagMoveUnknown) || result.Recovery == nil {
			t.Fatalf("error=%v result=%+v", err, result)
		}
		if strings.Contains(err.Error(), "SYNTHETIC_TEST_TOKEN_DO_NOT_USE") {
			t.Fatalf("unsanitized error=%q", err)
		}
	})

	t.Run("interrupted install readback at A remains outcome unknown", func(t *testing.T) {
		fixture := newTagMoveFixture(t)
		ctx, cancel := context.WithCancel(context.Background())
		runner := interceptGitBoundary{
			base: fixture.runner,
			intercept: func(_ context.Context, _ string, arguments []string) ([]byte, error, bool) {
				if len(arguments) > 0 && arguments[0] == "push" {
					cancel()
					return nil, context.Canceled, true
				}
				return nil, nil, false
			},
		}
		result, err := MoveV1(ctx, runner, fixture.policy, fixture.request(fixture.policy.CommitA, fixture.policy.CommitB))
		if !errors.Is(err, context.Canceled) || !errors.Is(err, ErrTagMoveUnknown) || result.After != fixture.policy.CommitA || result.Verified || result.Recovery == nil || !result.Recovery.Required {
			t.Fatalf("single immediate A readback was treated as conclusive: error=%v result=%+v", err, result)
		}
		if len(result.Recovery.ReadbackArguments) == 0 || len(result.Recovery.RestoreArguments) != 0 {
			t.Fatalf("A readback recovery must require reconciliation without inventing a B lease: %+v", result.Recovery)
		}
		record, recordErr := EncodeTagMoveRecord(fixture.policy, result, err, time.Now().Add(time.Second))
		if recordErr != nil {
			t.Fatalf("outcome-unknown A readback could not be preserved: %v", recordErr)
		}
		decoded, recordErr := decodeTagMoveRecord(record)
		if recordErr != nil || decoded.Outcome != "OUTCOME_UNKNOWN" || decoded.After == nil || decoded.After.Target.ObjectID != fixture.policy.CommitA || !decoded.Recovery.Required {
			t.Fatalf("outcome-unknown record lost reconciliation semantics: record=%#v err=%v", decoded, recordErr)
		}
		// Model a receive transaction that becomes visible only after the first
		// reconciliation read. The earlier result must remain outcome-unknown.
		runGit(t, fixture.git, "--git-dir", fixture.remote, "update-ref", MutableV1Ref, fixture.policy.CommitB, fixture.policy.CommitA)
		if got := fixture.remoteV1(t); got != fixture.policy.CommitB {
			t.Fatalf("delayed synthetic receive did not expose B: %s", got)
		}
	})
}

func TestMoveV1RestoreFailureReturnsExactRecoveryWithoutSensitiveDiagnostics(t *testing.T) {
	fixture := newTagMoveFixture(t)
	if _, err := MoveV1(context.Background(), fixture.runner, fixture.policy, fixture.request(fixture.policy.CommitA, fixture.policy.CommitB)); err != nil {
		t.Fatal(err)
	}
	runner := interceptGitBoundary{
		base: fixture.runner,
		intercept: func(_ context.Context, _ string, arguments []string) ([]byte, error, bool) {
			if len(arguments) > 0 && arguments[0] == "push" {
				return []byte("Authorization: Bearer SYNTHETIC_TEST_TOKEN_DO_NOT_USE\x1b[31m"), errors.New("https://synthetic-test-token@host.invalid/private"), true
			}
			return nil, nil, false
		},
	}
	result, err := MoveV1(context.Background(), runner, fixture.policy, fixture.request(fixture.policy.CommitB, fixture.policy.CommitA))
	if !errors.Is(err, ErrRestoreFailed) || strings.Contains(err.Error(), "SYNTHETIC_TEST_TOKEN_DO_NOT_USE") || strings.Contains(err.Error(), "synthetic-test-token") {
		t.Fatalf("error=%q", err)
	}
	if result.Verified || result.After != fixture.policy.CommitB || result.Recovery == nil {
		t.Fatalf("result=%+v", result)
	}
	if !reflect.DeepEqual(result.Recovery.RestoreArguments, exactPushArguments(fixture.policy.CommitB, fixture.policy.CommitA, fixture.policy.RemoteURL)) || result.Recovery.RestoreAcknowledgement != RequiredTagMoveAcknowledgement(fixture.policy.Repository, fixture.policy.CommitB, fixture.policy.CommitA) {
		t.Fatalf("recovery=%+v", result.Recovery)
	}
	if got := fixture.remoteV1(t); got != fixture.policy.CommitB {
		t.Fatalf("failed restore unexpectedly changed v1 to %s", got)
	}
}

func TestTagMovePolicyRejectsCredentialBearingOrAmbiguousRemotes(t *testing.T) {
	fixture := newTagMoveFixture(t)
	for _, remote := range []string{
		"https://synthetic-test-token@github.com/example/cirewind-lab.git",
		"https://github.com/example/cirewind-lab.git?token=SYNTHETIC_TEST_TOKEN_DO_NOT_USE",
		"https://github.com/other/cirewind-lab.git",
		"https://example.com/example/cirewind-lab.git",
		"https://github.com:8443/example/cirewind-lab.git",
		"ssh://user@github.com/example/cirewind-lab.git",
		"ssh://git@github.com:2222/example/cirewind-lab.git",
		"file:///tmp/cirewind-lab.git",
		"git://github.com/example/cirewind-lab.git",
		"ext::sh -c exploit",
		"refs/tags/*",
		"../relative.git",
		"-option",
		"git@github.com:example/*",
	} {
		t.Run(strings.ReplaceAll(remote, "/", "_"), func(t *testing.T) {
			policy := fixture.policy
			policy.RemoteURL = remote
			request := fixture.request(policy.CommitA, policy.CommitB)
			request.RemoteURL = remote
			request.Acknowledgement = RequiredTagMoveAcknowledgement(policy.Repository, policy.CommitA, policy.CommitB)
			_, err := PlanV1Move(policy, request)
			if !errors.Is(err, ErrTagMovePolicy) {
				t.Fatalf("remote accepted: %q error=%v", remote, err)
			}
			if strings.Contains(err.Error(), "SYNTHETIC_TEST_TOKEN_DO_NOT_USE") || strings.Contains(err.Error(), "synthetic-test-token@") {
				t.Fatalf("remote leaked through diagnostic: %q", err)
			}
		})
	}
}

func TestTagMovePolicyAcceptsBoundGitHubAndTestOnlyAbsoluteLocalRemotes(t *testing.T) {
	fixture := newTagMoveFixture(t)
	for _, remote := range []string{
		fixture.remote,
		"https://github.com/example/cirewind-lab.git",
		"https://github.com/example/cirewind-lab",
		"ssh://git@github.com/example/cirewind-lab.git",
		"git@github.com:example/cirewind-lab.git",
	} {
		policy := fixture.policy
		policy.RemoteURL = remote
		request := fixture.request(policy.CommitA, policy.CommitB)
		request.RemoteURL = remote
		request.Acknowledgement = RequiredTagMoveAcknowledgement(policy.Repository, policy.CommitA, policy.CommitB)
		if _, err := PlanV1Move(policy, request); err != nil {
			t.Fatalf("bound remote %q rejected: %v", remote, err)
		}
	}

	policy := fixture.policy
	policy.TestOnlyAllowLocalRemote = false
	request := fixture.request(policy.CommitA, policy.CommitB)
	if _, err := PlanV1Move(policy, request); !errors.Is(err, ErrTagMovePolicy) {
		t.Fatalf("production policy accepted absolute local remote: %v", err)
	}
}

func TestParseRemoteRefsRejectsHostileOrAmbiguousOutput(t *testing.T) {
	sha := strings.Repeat("a", 40)
	for _, output := range [][]byte{
		nil,
		[]byte("Authorization: Bearer SYNTHETIC_TEST_TOKEN_DO_NOT_USE"),
		[]byte(sha + " refs/tags/v1\n"),
		[]byte(sha + "\trefs/tags/*\n"),
		[]byte(sha + "\trefs/tags/v1\n" + sha + "\trefs/tags/v1\n"),
		[]byte(sha + "\trefs/tags/v1\x00forged\n"),
		[]byte(strings.Repeat("x", maxGitCommandOutput+1)),
	} {
		if refs, err := parseRemoteRefs(output); err == nil {
			t.Fatalf("hostile output accepted: %#v", refs)
		}
	}
}

func TestExactPushPorcelainRequiresOneForcedUpdateForTheExactRefspec(t *testing.T) {
	newTarget := strings.Repeat("b", 40)
	valid := []byte("To /synthetic/local/remote.git\r\n+\t" + newTarget + ":refs/tags/v1\t1111111...bbbbbbb (forced update)\r\nDone\r\n")
	if !exactPushWasApplied(valid, newTarget) {
		t.Fatal("exact forced-update porcelain was not accepted")
	}
	for _, output := range [][]byte{
		[]byte("To /synthetic/local/remote.git\n=\t" + newTarget + ":refs/tags/v1\t[up to date]\nDone\n"),
		[]byte("To /synthetic/local/remote.git\n+\t" + newTarget + ":refs/tags/fixture-a\told...new (forced update)\nDone\n"),
		append(append([]byte(nil), valid...), []byte("+\t"+newTarget+":refs/tags/v1\told...new (forced update)\n")...),
		[]byte("remote: +\t" + newTarget + ":refs/tags/v1\told...new (forced update)\n"),
		[]byte("+\t" + newTarget + ":refs/tags/v1\told...new (forced update)\x00forged\n"),
	} {
		if exactPushWasApplied(output, newTarget) {
			t.Fatalf("ambiguous or hostile porcelain accepted: %q", output)
		}
	}
}
