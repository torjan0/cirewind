package publiclab

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestVerifyPackInputSourceCommitKeepsMainAtImportAndBindsExactBytes(t *testing.T) {
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
	worktree := filepath.Join(root, "worktree")
	if err := os.WriteFile(bundle, artifact.Bundle, 0o600); err != nil {
		t.Fatal(err)
	}
	runGit(t, git, "clone", "--quiet", bundle, worktree)
	runGit(t, git, "-C", worktree, "config", "user.name", "Synthetic Provenance Test")
	runGit(t, git, "-C", worktree, "config", "user.email", "synthetic-provenance@example.invalid")
	runGit(t, git, "-C", worktree, "switch", "--quiet", "-c", "observations")

	install, restore, record := confirmedProvenanceRecords(t, artifact)
	var recordValue map[string]any
	if err := json.Unmarshal(record, &recordValue); err != nil {
		t.Fatal(err)
	}
	recordID := recordValue["record_id"].(string)
	observationDir := filepath.Join(worktree, "observations")
	if err := os.Mkdir(observationDir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct {
		id   string
		data []byte
	}{
		{id: decodedTagMoveID(t, install), data: install},
		{id: decodedTagMoveID(t, restore), data: restore},
		{id: recordID, data: record},
	} {
		if err := os.WriteFile(filepath.Join(observationDir, item.id+".json"), item.data, 0o600); err != nil {
			t.Fatal(err)
		}
		runGit(t, git, "-C", worktree, "add", "observations/"+item.id+".json")
	}
	runGit(t, git, "-C", worktree, "commit", "--quiet", "-m", "docs: record synthetic tag observations")
	revision := strings.TrimSpace(runGit(t, git, "-C", worktree, "rev-parse", "HEAD"))
	url := "https://github.com/" + RepositoryName + "/blob/" + revision + "/observations/" + recordID + ".json"
	boundary, err := NewLocalGitBoundary(git)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyPackInputSourceCommit(context.Background(), boundary, worktree, artifact, record, install, restore, url); err != nil {
		t.Fatalf("exact observations commit rejected: %v", err)
	}

	tampered := append([]byte(nil), record...)
	tampered[len(tampered)-2] ^= 1
	if err := VerifyPackInputSourceCommit(context.Background(), boundary, worktree, artifact, tampered, install, restore, url); err == nil {
		t.Fatal("pack-input bytes differing from the immutable commit were accepted")
	}
	importURL := "https://github.com/" + RepositoryName + "/blob/" + artifact.Model.Commits[5].ObjectID + "/observations/" + recordID + ".json"
	if err := VerifyPackInputSourceCommit(context.Background(), boundary, worktree, artifact, record, install, restore, importURL); err == nil {
		t.Fatal("impossible pack-input URL at import I was accepted")
	}

	tamperedInstall := append([]byte(nil), install...)
	tamperedInstall[len(tamperedInstall)-2] ^= 1
	if err := VerifyPackInputSourceCommit(context.Background(), boundary, worktree, artifact, record, tamperedInstall, restore, url); err == nil {
		t.Fatal("pack input accepted a different install derivation record")
	}
}

func confirmedProvenanceRecords(t *testing.T, artifact Artifact) ([]byte, []byte, []byte) {
	t.Helper()
	policy := TagMovePolicy{
		Repository:               artifact.Model.Repository,
		RepositoryDatabaseID:     101,
		RemoteURL:                "/synthetic/absolute/remote.git",
		ReviewedMain:             artifact.Model.Commits[5].ObjectID,
		CommitA:                  artifact.Model.Commits[1].ObjectID,
		CommitB:                  artifact.Model.Commits[2].ObjectID,
		FixtureATagObject:        artifact.Model.Tags[0].ObjectID,
		FixtureBTagObject:        artifact.Model.Tags[1].ObjectID,
		TestOnlyAllowLocalRemote: true,
	}
	moveRecord := func(direction TagMoveDirection, oldTarget, newTarget string, before, after, recorded time.Time) []byte {
		result := TagMoveResult{
			Plan: TagMovePlan{
				Repository:           policy.Repository,
				RepositoryDatabaseID: policy.RepositoryDatabaseID,
				Ref:                  MutableV1Ref,
				ExpectedOld:          oldTarget,
				NewTarget:            newTarget,
				Direction:            direction,
			},
			Before:           oldTarget,
			BeforeObservedAt: canonicalObservationTime(before),
			After:            newTarget,
			AfterObservedAt:  canonicalObservationTime(after),
			Verified:         true,
		}
		data, err := EncodeTagMoveRecord(policy, result, nil, recorded)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	install := moveRecord(InstallAffectedMarker, policy.CommitA, policy.CommitB,
		time.Date(2026, 8, 31, 1, 0, 0, 0, time.UTC), time.Date(2026, 8, 31, 1, 0, 1, 0, time.UTC), time.Date(2026, 8, 31, 1, 0, 2, 0, time.UTC))
	restore := moveRecord(RestoreKnownGood, policy.CommitB, policy.CommitA,
		time.Date(2026, 8, 31, 1, 1, 0, 0, time.UTC), time.Date(2026, 8, 31, 1, 1, 1, 0, time.UTC), time.Date(2026, 8, 31, 1, 1, 2, 0, time.UTC))
	packInput, err := GeneratePackInputRecord(context.Background(), sourceRoot(t), recordSchemaDir(t), artifact, install, restore, time.Date(2026, 8, 31, 1, 1, 3, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	return install, restore, packInput
}

func decodedTagMoveID(t *testing.T, data []byte) string {
	t.Helper()
	record, err := decodeTagMoveRecord(data)
	if err != nil {
		t.Fatal(err)
	}
	return record.RecordID
}
