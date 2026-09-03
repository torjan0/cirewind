package publiclab

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestTagMoveRecordsCloseExactPackInputSequence(t *testing.T) {
	fixture := newTagMoveFixture(t)
	fixture.policy.Repository = RepositoryName
	installTimes := sequenceClock(t,
		time.Date(2026, 8, 31, 1, 0, 0, 100, time.UTC),
		time.Date(2026, 8, 31, 1, 0, 1, 200, time.UTC),
	)
	installResult, err := moveV1(context.Background(), fixture.runner, fixture.policy, fixture.request(fixture.policy.CommitA, fixture.policy.CommitB), installTimes)
	if err != nil {
		t.Fatal(err)
	}
	install, err := EncodeTagMoveRecord(fixture.policy, installResult, nil, time.Date(2026, 8, 31, 1, 0, 2, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}

	restoreTimes := sequenceClock(t,
		time.Date(2026, 8, 31, 1, 1, 0, 300, time.UTC),
		time.Date(2026, 8, 31, 1, 1, 1, 400, time.UTC),
	)
	restoreResult, err := moveV1(context.Background(), fixture.runner, fixture.policy, fixture.request(fixture.policy.CommitB, fixture.policy.CommitA), restoreTimes)
	if err != nil {
		t.Fatal(err)
	}
	restore, err := EncodeTagMoveRecord(fixture.policy, restoreResult, nil, time.Date(2026, 8, 31, 1, 1, 2, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}

	for name, data := range map[string][]byte{"install": install, "restore": restore} {
		if bytes.Contains(data, []byte(fixture.remote)) || bytes.Contains(data, []byte(fixture.worktree)) || bytes.Contains(data, []byte("--force-with-lease")) {
			t.Fatalf("%s record disclosed operational path or command: %s", name, data)
		}
		if _, err := decodeTagMoveRecord(data); err != nil {
			t.Fatalf("%s record rejected: %v", name, err)
		}
	}

	artifact, err := Build(context.Background(), sourceRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	createdAt := time.Date(2026, 8, 31, 1, 1, 3, 0, time.UTC)
	first, err := GeneratePackInputRecord(context.Background(), sourceRoot(t), recordSchemaDir(t), artifact, install, restore, createdAt)
	if err != nil {
		t.Fatal(err)
	}
	second, err := GeneratePackInputRecord(context.Background(), sourceRoot(t), recordSchemaDir(t), artifact, install, restore, createdAt)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("fixed tag observations produced nondeterministic pack-input bytes")
	}
	var document map[string]any
	if err := json.Unmarshal(first, &document); err != nil {
		t.Fatal(err)
	}
	mutable := document["mutable_tag"].(map[string]any)
	if observedObjectID(mutable["before"]) != fixture.policy.CommitA || observedObjectID(mutable["during"]) != fixture.policy.CommitB || observedObjectID(mutable["after"]) != fixture.policy.CommitA {
		t.Fatalf("pack input does not preserve exact A-to-B-to-A sequence: %#v", mutable)
	}
	if _, exists := document["workflow_runs"]; exists {
		t.Fatal("pre-case pack input unexpectedly contains workflow conclusions")
	}
}

func TestTagMoveRecordRejectsTamperMismatchAndUnconfirmedPackInput(t *testing.T) {
	fixture := newTagMoveFixture(t)
	fixture.policy.Repository = RepositoryName
	result, err := moveV1(context.Background(), fixture.runner, fixture.policy, fixture.request(fixture.policy.CommitA, fixture.policy.CommitB), sequenceClock(t,
		time.Date(2026, 8, 31, 2, 0, 0, 0, time.UTC),
		time.Date(2026, 8, 31, 2, 0, 1, 0, time.UTC),
	))
	if err != nil {
		t.Fatal(err)
	}
	record, err := EncodeTagMoveRecord(fixture.policy, result, nil, time.Date(2026, 8, 31, 2, 0, 2, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	tampered := bytes.Replace(record, []byte(fixture.policy.CommitB), []byte(strings.Repeat("f", 40)), 1)
	if _, err := decodeTagMoveRecord(tampered); err == nil {
		t.Fatal("content-tampered tag record was accepted")
	}

	artifact, err := Build(context.Background(), sourceRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := GeneratePackInputRecord(context.Background(), sourceRoot(t), recordSchemaDir(t), artifact, record, record, time.Date(2026, 8, 31, 2, 1, 0, 0, time.UTC)); err == nil {
		t.Fatal("two install records were accepted as a closed A-to-B-to-A sequence")
	}
}

func TestTagMoveFailureRecordIsSafeAndNonQualifying(t *testing.T) {
	fixture := newTagMoveFixture(t)
	runner := interceptGitBoundary{
		base: fixture.runner,
		intercept: func(_ context.Context, _ string, arguments []string) ([]byte, error, bool) {
			if len(arguments) > 0 && arguments[0] == "push" {
				return []byte("Authorization: Bearer SYNTHETIC_TEST_TOKEN_DO_NOT_USE"), errors.New("synthetic transport failure"), true
			}
			return nil, nil, false
		},
	}
	result, moveErr := moveV1(context.Background(), runner, fixture.policy, fixture.request(fixture.policy.CommitA, fixture.policy.CommitB), sequenceClock(t,
		time.Date(2026, 8, 31, 3, 0, 0, 0, time.UTC),
		time.Date(2026, 8, 31, 3, 0, 1, 0, time.UTC),
	))
	if moveErr == nil {
		t.Fatal("synthetic failed push unexpectedly succeeded")
	}
	record, err := EncodeTagMoveRecord(fixture.policy, result, moveErr, time.Date(2026, 8, 31, 3, 0, 2, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(record, []byte("SYNTHETIC_TEST_TOKEN_DO_NOT_USE")) || bytes.Contains(record, []byte(fixture.remote)) || bytes.Contains(record, []byte(fixture.worktree)) {
		t.Fatalf("failure record disclosed hostile output or paths: %s", record)
	}
	decoded, err := decodeTagMoveRecord(record)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Outcome == "CONFIRMED_APPLIED" || decoded.Verified {
		t.Fatalf("failed move was made qualifying: %#v", decoded)
	}
}

func TestPostPushReadbackFailurePreservesUnknownOutcomeRecord(t *testing.T) {
	fixture := newTagMoveFixture(t)
	remoteReads := 0
	runner := interceptGitBoundary{
		base: fixture.runner,
		intercept: func(_ context.Context, _ string, arguments []string) ([]byte, error, bool) {
			if len(arguments) > 0 && arguments[0] == "ls-remote" {
				remoteReads++
				if remoteReads == 2 {
					return nil, errors.New("synthetic post-push readback failure"), true
				}
			}
			return nil, nil, false
		},
	}
	result, moveErr := moveV1(context.Background(), runner, fixture.policy, fixture.request(fixture.policy.CommitA, fixture.policy.CommitB), sequenceClock(t,
		time.Date(2026, 8, 31, 3, 30, 0, 0, time.UTC),
	))
	if !errors.Is(moveErr, ErrTagMoveUnknown) || result.Before != fixture.policy.CommitA || result.After != "" || result.Recovery == nil || result.Recovery.ObservedTarget != "" {
		t.Fatalf("post-push readback failure result=%+v err=%v", result, moveErr)
	}
	record, err := EncodeTagMoveRecord(fixture.policy, result, moveErr, time.Date(2026, 8, 31, 3, 30, 1, 0, time.UTC))
	if err != nil {
		t.Fatalf("encode outcome-unknown record: %v", err)
	}
	decoded, err := decodeTagMoveRecord(record)
	if err != nil {
		t.Fatalf("decode outcome-unknown record: %v", err)
	}
	if decoded.Outcome != "OUTCOME_UNKNOWN" || decoded.Before == nil || decoded.After != nil || !decoded.Recovery.Required || decoded.Recovery.ObservedTarget != nil {
		t.Fatalf("unknown outcome lost its bounded observations: %#v", decoded)
	}
	if got := fixture.remoteV1(t); got != fixture.policy.CommitB {
		t.Fatalf("synthetic push did not reach B: %s", got)
	}
}

func TestPreconditionFailureAtAffectedBPreservesReadbackAndRecovery(t *testing.T) {
	fixture := newTagMoveFixture(t)
	runGit(t, fixture.git, "--git-dir", fixture.remote, "update-ref", MutableV1Ref, fixture.policy.CommitB, fixture.policy.CommitA)
	result, moveErr := moveV1(context.Background(), fixture.runner, fixture.policy, fixture.request(fixture.policy.CommitA, fixture.policy.CommitB), sequenceClock(t,
		time.Date(2026, 8, 31, 4, 0, 0, 0, time.UTC),
	))
	if !errors.Is(moveErr, ErrTagMovePrecondition) || result.Before != fixture.policy.CommitB || result.After != "" || result.Recovery == nil || !result.Recovery.Required {
		t.Fatalf("precondition result=%+v err=%v", result, moveErr)
	}
	record, err := EncodeTagMoveRecord(fixture.policy, result, moveErr, time.Date(2026, 8, 31, 4, 0, 1, 0, time.UTC))
	if err != nil {
		t.Fatalf("encode exact-B precondition record: %v", err)
	}
	decoded, err := decodeTagMoveRecord(record)
	if err != nil {
		t.Fatalf("decode exact-B precondition record: %v", err)
	}
	if decoded.Outcome != "PRECONDITION_FAILED" || decoded.Before == nil || decoded.Before.Target.ObjectID != fixture.policy.CommitB || !decoded.Recovery.Required || decoded.Recovery.RestoreAcknowledgement == nil {
		t.Fatalf("precondition record omitted exact readback or recovery: %#v", decoded)
	}
	assertNoPush(t, fixture.runner.callSnapshot())
}

func sequenceClock(t *testing.T, values ...time.Time) func() time.Time {
	t.Helper()
	index := 0
	return func() time.Time {
		t.Helper()
		if index >= len(values) {
			t.Fatalf("observation clock called %d times, only %d values supplied", index+1, len(values))
		}
		value := values[index]
		index++
		return value
	}
}

func observedObjectID(value any) string {
	return value.(map[string]any)["target_commit"].(map[string]any)["objectId"].(string)
}
