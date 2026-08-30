package archive

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/torjan0/cirewind/internal/evidence"
	"github.com/torjan0/cirewind/internal/model"
)

func TestArchiveAppendIdempotentDeterministicAndReadOnlyReplay(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "archive.db")
	archive, err := Create(ctx, path, Options{CreatedAt: testInstant(0)})
	if err != nil {
		t.Fatal(err)
	}
	batch := testBatch(t)
	if err := archive.Append(ctx, batch); err != nil {
		t.Fatal(err)
	}
	if err := archive.Append(ctx, batch); err != nil {
		t.Fatalf("idempotent append failed: %v", err)
	}
	for table, want := range map[string]int{
		"archive_batches": 1, "archive_facts": 8, "archive_batch_facts": 8,
		"archive_evidence_envelopes": 1, "archive_checkpoints": 1,
	} {
		var got int
		if err := archive.store.DB().QueryRowContext(ctx, "SELECT count(*) FROM "+table).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Fatalf("%s count = %d, want %d", table, got, want)
		}
	}
	var first, second bytes.Buffer
	if err := archive.Export(ctx, &first); err != nil {
		t.Fatal(err)
	}
	if err := archive.Export(ctx, &second); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.Bytes(), second.Bytes()) {
		t.Fatal("unchanged archive produced nondeterministic snapshots")
	}
	decoded, err := DecodeSnapshot(bytes.NewReader(first.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded.Facts) != 8 || len(decoded.Evidence) != 1 {
		t.Fatalf("decoded snapshot lost compact facts: %d facts, %d evidence", len(decoded.Facts), len(decoded.Evidence))
	}
	if err := archive.store.Finalize(ctx); err != nil {
		t.Fatal(err)
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}

	replay, err := OpenReplay(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer replay.Close()
	if err := replay.Append(ctx, batch); err == nil || !strings.Contains(err.Error(), "read-only") {
		t.Fatalf("read-only replay append error = %v", err)
	}
	var replayed bytes.Buffer
	if err := replay.Export(ctx, &replayed); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.Bytes(), replayed.Bytes()) {
		t.Fatal("read-only replay changed deterministic snapshot")
	}

	importPath := filepath.Join(t.TempDir(), "imported.db")
	imported, err := Import(ctx, importPath, decoded)
	if err != nil {
		t.Fatal(err)
	}
	defer imported.Close()
	var importedBytes bytes.Buffer
	if err := imported.Export(ctx, &importedBytes); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.Bytes(), importedBytes.Bytes()) {
		t.Fatal("snapshot import did not reproduce exact canonical export")
	}
}

func TestOpenReplaySeesCommittedWALFromInterruptedWriter(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "archive.db")
	writer, err := Create(ctx, path, Options{CreatedAt: testInstant(0)})
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	if _, err := writer.store.DB().ExecContext(ctx, `PRAGMA wal_autocheckpoint=0`); err != nil {
		t.Fatal(err)
	}
	if err := writer.Append(ctx, testBatch(t)); err != nil {
		t.Fatal(err)
	}

	// Model replay opening after a collector was interrupted after commit but
	// before its writable connection checkpointed the WAL.
	replay, err := OpenReplay(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer replay.Close()
	snapshot, err := replay.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Facts) != 8 || len(snapshot.Evidence) != 1 {
		t.Fatalf("replay ignored committed WAL: facts=%d evidence=%d", len(snapshot.Facts), len(snapshot.Evidence))
	}
}

func TestArchiveCloseCheckpointsCommittedWAL(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "archive.db")
	writer, err := Create(ctx, path, Options{CreatedAt: testInstant(0)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.store.DB().ExecContext(ctx, `PRAGMA wal_autocheckpoint=0`); err != nil {
		t.Fatal(err)
	}
	if err := writer.Append(ctx, testBatch(t)); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		if _, err := os.Lstat(path + suffix); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("normal archive close left sidecar %s: %v", suffix, err)
		}
	}

	replay, err := OpenReplay(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer replay.Close()
	snapshot, err := replay.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Facts) != 8 || len(snapshot.Evidence) != 1 {
		t.Fatalf("checkpointed replay: facts=%d evidence=%d", len(snapshot.Facts), len(snapshot.Evidence))
	}
}

func TestRawSidecarIsExactOwnerOnlyDeduplicatedAndNonBlockingForCompactReplay(t *testing.T) {
	ctx := context.Background()
	base := t.TempDir()
	archivePath := filepath.Join(base, "archive.db")
	archiveStore, err := Create(ctx, archivePath, Options{CreatedAt: testInstant(0)})
	if err != nil {
		t.Fatal(err)
	}
	defer archiveStore.Close()
	rawBytes := []byte("exact raw workflow log bytes\n")
	source := filepath.Join(base, "transient-source.zip")
	if err := os.WriteFile(source, rawBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(rawBytes)
	digest := hex.EncodeToString(sum[:])
	input := RawInput{SHA256: digest, MediaType: "application/zip", ByteLength: uint64(len(rawBytes)), SourcePath: source}
	if err := archiveStore.RetainRaw(ctx, input); err != nil {
		t.Fatal(err)
	}
	if err := archiveStore.RetainRaw(ctx, input); err != nil {
		t.Fatalf("deduplicated raw retention failed: %v", err)
	}
	batch := testBatch(t)
	rawEnvelope := testRawEnvelope(t, digest, uint64(len(rawBytes)), input.MediaType)
	batch.Evidence = append(batch.Evidence, rawEnvelope)
	batch.Collections[0].RawRetention = true
	batch.Capabilities = append(batch.Capabilities, Capability{Name: "raw_logs", Status: CapabilityRetained, ExtractorVersion: "1.0.0", Details: map[string]string{"policy": "exact-opt-in", "retained_count": "1"}})
	if err := archiveStore.Append(ctx, batch); err != nil {
		t.Fatal(err)
	}
	if err := archiveStore.VerifyRaw(ctx); err != nil {
		t.Fatal(err)
	}
	var copied bytes.Buffer
	if err := archiveStore.CopyRaw(ctx, digest, &copied); err != nil || !bytes.Equal(copied.Bytes(), rawBytes) {
		t.Fatalf("copy raw: bytes=%q err=%v", copied.Bytes(), err)
	}

	rootInfo, err := os.Lstat(archivePath + ".raw")
	if err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(archivePath + ".raw")
	if err != nil || len(entries) != 1 || entries[0].Name() != digest+".bin" {
		t.Fatalf("raw sidecar entries=%v err=%v", entries, err)
	}
	fileInfo, err := entries[0].Info()
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && (rootInfo.Mode().Perm() != 0o700 || fileInfo.Mode().Perm() != 0o600) {
		t.Fatalf("raw permissions directory=%o file=%o", rootInfo.Mode().Perm(), fileInfo.Mode().Perm())
	}

	snapshot, err := archiveStore.Snapshot(ctx)
	if err != nil || len(snapshot.Facts) == 0 {
		t.Fatalf("raw-bearing compact snapshot: facts=%d err=%v", len(snapshot.Facts), err)
	}
	if err := archiveStore.Export(ctx, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), ".raw sidecar") {
		t.Fatalf("single-file raw export error=%v", err)
	}
	if _, err := Import(ctx, filepath.Join(base, "import.db"), snapshot); err == nil || !strings.Contains(err.Error(), "archive bundle") {
		t.Fatalf("single-file raw import error=%v", err)
	}

	// Corrupting the optional sidecar makes raw-specific operations fail, while
	// compact replay remains available and its capability becomes an explicit gap.
	if err := os.WriteFile(filepath.Join(archivePath+".raw", digest+".bin"), bytes.Repeat([]byte("x"), len(rawBytes)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := archiveStore.VerifyRaw(ctx); err == nil {
		t.Fatal("corrupt raw sidecar verified")
	}
	snapshot, err = archiveStore.Snapshot(ctx)
	if err != nil || len(snapshot.Facts) == 0 {
		t.Fatalf("corrupt optional raw sidecar blocked compact replay: facts=%d err=%v", len(snapshot.Facts), err)
	}
	for _, capability := range snapshot.Capabilities {
		if capability.Name == "raw_logs" && (capability.Status != CapabilityGap || capability.Details["availability"] != "sidecar-incomplete") {
			t.Fatalf("corrupt raw availability was not surfaced: %#v", capability)
		}
	}
}

func TestRawRetentionRejectsSymlinkSidecarAndCancelledCopy(t *testing.T) {
	ctx := context.Background()
	base := t.TempDir()
	archivePath := filepath.Join(base, "archive.db")
	archiveStore, err := Create(ctx, archivePath, Options{CreatedAt: testInstant(0)})
	if err != nil {
		t.Fatal(err)
	}
	defer archiveStore.Close()
	rawBytes := []byte("bounded bytes")
	source := filepath.Join(base, "source")
	if err := os.WriteFile(source, rawBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(rawBytes)
	digest := hex.EncodeToString(sum[:])
	if _, err := RawRelativePath("../../escape"); err == nil {
		t.Fatal("unsafe raw digest produced a path")
	}
	redirect := t.TempDir()
	if err := os.Symlink(redirect, archivePath+".raw"); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	input := RawInput{SHA256: digest, MediaType: "text/plain", ByteLength: uint64(len(rawBytes)), SourcePath: source}
	if err := archiveStore.RetainRaw(ctx, input); err == nil {
		t.Fatal("symlink raw sidecar accepted")
	}
	if entries, err := os.ReadDir(redirect); err != nil || len(entries) != 0 {
		t.Fatalf("symlink target was mutated: entries=%v err=%v", entries, err)
	}
	if err := os.Remove(archivePath + ".raw"); err != nil {
		t.Fatal(err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if err := archiveStore.RetainRaw(cancelled, input); err == nil {
		t.Fatal("cancelled raw retention succeeded")
	}
	entries, err := os.ReadDir(archivePath + ".raw")
	if err != nil || len(entries) != 0 {
		t.Fatalf("cancelled raw retention left a partial object: entries=%v err=%v", entries, err)
	}
	var descriptors int
	if err := archiveStore.store.DB().QueryRowContext(ctx, `SELECT count(*) FROM evidence_payloads WHERE retained_path IS NOT NULL`).Scan(&descriptors); err != nil || descriptors != 0 {
		t.Fatalf("cancelled raw retention persisted descriptor count=%d err=%v", descriptors, err)
	}
}

func TestPreparedBatchResumesWithoutPrematureCheckpoint(t *testing.T) {
	ctx := context.Background()
	archive, err := Create(ctx, filepath.Join(t.TempDir(), "archive.db"), Options{CreatedAt: testInstant(0)})
	if err != nil {
		t.Fatal(err)
	}
	defer archive.Close()
	batch, err := NormalizeBatch(testBatch(t))
	if err != nil {
		t.Fatal(err)
	}
	state, err := archive.prepareBatch(ctx, batch)
	if err != nil || state != "PREPARED" {
		t.Fatalf("prepare state = %q, err = %v", state, err)
	}
	var checkpoints, facts int
	if err := archive.store.DB().QueryRowContext(ctx, `SELECT count(*) FROM archive_checkpoints`).Scan(&checkpoints); err != nil {
		t.Fatal(err)
	}
	if err := archive.store.DB().QueryRowContext(ctx, `SELECT count(*) FROM archive_facts`).Scan(&facts); err != nil {
		t.Fatal(err)
	}
	if checkpoints != 0 || facts != 0 {
		t.Fatal("PREPARED phase exposed facts or advanced a checkpoint")
	}
	snapshot, err := archive.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Collections) != 0 {
		t.Fatal("PREPARED collection leaked into replay snapshot")
	}
	if err := archive.Append(ctx, batch); err != nil {
		t.Fatal(err)
	}
	var persistedState string
	if err := archive.store.DB().QueryRowContext(ctx, `SELECT state FROM archive_batches WHERE batch_id=?`, batch.ID).Scan(&persistedState); err != nil {
		t.Fatal(err)
	}
	if persistedState != "COMMITTED" {
		t.Fatalf("resumed batch state = %q", persistedState)
	}
	if err := archive.store.DB().QueryRowContext(ctx, `SELECT count(*) FROM archive_checkpoints`).Scan(&checkpoints); err != nil {
		t.Fatal(err)
	}
	if checkpoints != 1 {
		t.Fatalf("checkpoint count after resume = %d", checkpoints)
	}
}

func TestArchiveRejectsCredentialLikePayloadAndUnknownSnapshotFields(t *testing.T) {
	material := []byte("Authorization: Bearer ghp_not-a-real-token")
	sum := sha256.Sum256(material)
	payload := Payload{SHA256: hex.EncodeToString(sum[:]), MediaType: "text/plain", Bytes: material}
	if err := payload.Validate(); err == nil {
		t.Fatal("credential-like payload was accepted")
	}
	if _, err := DecodeSnapshot(strings.NewReader(`{"metadata":{},"unexpected":true}`)); err == nil {
		t.Fatal("snapshot decoder accepted unknown fields")
	}
}

func TestRunnerGroupIDIsOptionalAndNonnegative(t *testing.T) {
	t.Parallel()
	evidenceID := model.EvidenceID("ev1:" + strings.Repeat("a", 64))
	execution := model.JobExecutionIdentity{RepositoryID: 1, RunID: 1, RunAttempt: 1, JobID: 1}
	zero := int64(0)
	fact := Fact{
		Kind: FactExposure, EvidenceIDs: []model.EvidenceID{evidenceID},
		Exposure: &ExposureFact{
			Execution: execution, EventTime: unknownEventTime(),
			Runner: &RunnerContextFact{
				Classification: "github-hosted", RunnerGroupID: &zero,
				RunnerGroup: "GitHub Actions", Labels: []string{},
			},
		},
	}
	normalized, err := NormalizeFact(fact)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(normalized.Exposure.Runner)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(encoded, []byte(`"runner_group_id":0`)) {
		t.Fatalf("meaningful zero runner group ID was omitted: %s", encoded)
	}

	absent := fact
	absent.Exposure = &ExposureFact{Execution: execution, EventTime: unknownEventTime(), Runner: &RunnerContextFact{
		Classification: "unknown", Labels: []string{},
	}}
	normalized, err = NormalizeFact(absent)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err = json.Marshal(normalized.Exposure.Runner)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte("runner_group_id")) {
		t.Fatalf("absent runner group ID changed retained JSON shape: %s", encoded)
	}

	negative := int64(-1)
	fact.Exposure.Runner.RunnerGroupID = &negative
	if _, err := NormalizeFact(fact); err == nil || !strings.Contains(err.Error(), "runner group ID must be nonnegative") {
		t.Fatalf("negative runner group ID error=%v", err)
	}
}

func TestEnvironmentGateStatesRequireCoherentJobStartAndPreserveTransitions(t *testing.T) {
	t.Parallel()
	evidenceID := model.EvidenceID("ev1:" + strings.Repeat("b", 64))
	execution := model.JobExecutionIdentity{RepositoryID: 1, RunID: 1, RunAttempt: 1, JobID: 1}
	secretName, err := model.NewSecretName("DEPLOY_KEY")
	if err != nil {
		t.Fatal(err)
	}
	makeFact := func(state string, started bool, names []model.SecretName, second int) Fact {
		at := testInstant(second)
		return Fact{
			Kind: FactExposure, EvidenceIDs: []model.EvidenceID{evidenceID},
			Exposure: &ExposureFact{
				Execution:   execution,
				Environment: &EnvironmentEligibilityFact{EnvironmentName: "production", GateState: state, JobStarted: started, SecretNames: names},
				EventTime:   model.EventInterval{Start: &at, Precision: model.PrecisionSecond, Approximation: model.ApproximationExact, Basis: model.TimeBasisLogTimestamp},
			},
		}
	}
	for _, test := range []struct {
		state   string
		started bool
		names   []model.SecretName
		valid   bool
	}{
		{state: "approved", started: true, names: []model.SecretName{secretName}, valid: true},
		{state: "bypassed", started: true, names: []model.SecretName{secretName}, valid: true},
		{state: "crossed", started: true, names: []model.SecretName{secretName}, valid: true},
		{state: "not-required", started: true, names: []model.SecretName{secretName}, valid: true},
		{state: "pending", started: false, names: []model.SecretName{}, valid: true},
		{state: "rejected", started: false, names: []model.SecretName{}, valid: true},
		{state: "pending", started: true, names: []model.SecretName{}},
		{state: "rejected", started: true, names: []model.SecretName{}},
		{state: "unknown", started: true, names: []model.SecretName{secretName}},
	} {
		t.Run(test.state+"/started="+strconv.FormatBool(test.started)+"/names="+strconv.Itoa(len(test.names)), func(t *testing.T) {
			_, err := NormalizeFact(makeFact(test.state, test.started, test.names, 1))
			if (err == nil) != test.valid {
				t.Fatalf("NormalizeFact() error=%v, valid=%t", err, test.valid)
			}
		})
	}
	unknownNotRequired := makeFact("not-required", true, []model.SecretName{secretName}, 1)
	unknownNotRequired.Exposure.EventTime = model.EventInterval{
		Precision: model.PrecisionUnknown, Approximation: model.ApproximationUnknown, Basis: model.TimeBasisUnknown,
	}
	if _, err := NormalizeFact(unknownNotRequired); err == nil || !strings.Contains(err.Error(), "environment secrets cannot be eligible") {
		t.Fatalf("unknown-time not-required eligibility error=%v", err)
	}

	pending, err := NormalizeFact(makeFact("pending", false, []model.SecretName{}, 1))
	if err != nil {
		t.Fatal(err)
	}
	crossed, err := NormalizeFact(makeFact("crossed", true, []model.SecretName{secretName}, 2))
	if err != nil {
		t.Fatal(err)
	}
	if pending.ID == crossed.ID || pending.Exposure.Environment.GateState != "pending" || crossed.Exposure.Environment.GateState != "crossed" {
		t.Fatalf("event-timed pending and crossed observations were merged: pending=%#v crossed=%#v", pending, crossed)
	}
}

func TestRetainedV1CredentialBasisCompatibilityIsReadOnlyAndNarrow(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		basis model.CredentialExposureBasis
	}{
		{name: "empty", basis: ""},
		{name: "unrecognized", basis: "removed-basis-v0"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			batch := testBatch(t)
			var input Fact
			for _, fact := range batch.Facts {
				if fact.Exposure != nil && fact.Exposure.Credential != nil {
					input = fact
					break
				}
			}
			if input.Exposure == nil {
				t.Fatal("fixture lacks credential exposure")
			}
			input.Exposure.Credential.Basis = test.basis
			input.ID = ""
			if _, err := NormalizeFact(input); err == nil || !strings.Contains(err.Error(), "credential-exposure basis") {
				t.Fatalf("fresh NormalizeFact accepted basis %q: %v", test.basis, err)
			}
			retained, err := NormalizeRetainedV1Fact(input)
			if err != nil {
				t.Fatalf("retained v1 fact basis %q: %v", test.basis, err)
			}
			if retained.Exposure.Credential.Basis != test.basis || retained.ID == "" {
				t.Fatalf("retained fact did not preserve canonical payload: %#v", retained.Exposure.Credential)
			}

			for index := range batch.Facts {
				if batch.Facts[index].Exposure != nil && batch.Facts[index].Exposure.Credential != nil {
					batch.Facts[index] = retained
				}
			}
			store, err := Create(context.Background(), filepath.Join(t.TempDir(), "fresh.db"), Options{CreatedAt: testInstant(0)})
			if err != nil {
				t.Fatal(err)
			}
			appendErr := store.Append(context.Background(), batch)
			closeErr := store.Close()
			if appendErr == nil || !strings.Contains(appendErr.Error(), "credential-exposure basis") {
				t.Fatalf("fresh Append accepted retained-only basis %q: %v", test.basis, appendErr)
			}
			if closeErr != nil {
				t.Fatal(closeErr)
			}
		})
	}

	input := testBatch(t).Facts[0]
	for _, fact := range testBatch(t).Facts {
		if fact.Exposure != nil && fact.Exposure.Credential != nil {
			input = fact
			break
		}
	}
	input.Exposure.Credential.Basis = "<unsafe>"
	input.ID = ""
	if _, err := NormalizeRetainedV1Fact(input); err == nil || !strings.Contains(err.Error(), "unsupported character") {
		t.Fatalf("unsafe retained basis was accepted: %v", err)
	}
}

func TestReplaySnapshotRejectsUnknownPersistedFactFields(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	archiveStore, err := Create(ctx, filepath.Join(t.TempDir(), "archive.db"), Options{CreatedAt: testInstant(0)})
	if err != nil {
		t.Fatal(err)
	}
	defer archiveStore.Close()
	if err := archiveStore.Append(ctx, testBatch(t)); err != nil {
		t.Fatal(err)
	}
	var factID, encoded string
	if err := archiveStore.store.DB().QueryRowContext(ctx, `SELECT fact_id,payload_json FROM archive_facts ORDER BY fact_id LIMIT 1`).Scan(&factID, &encoded); err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(encoded, "}") {
		t.Fatalf("unexpected persisted fact JSON %q", encoded)
	}
	hostile := strings.TrimSuffix(encoded, "}") + `,"unexpected":true}`
	if _, err := archiveStore.store.DB().ExecContext(ctx, `UPDATE archive_facts SET payload_json=? WHERE fact_id=?`, hostile, factID); err != nil {
		t.Fatal(err)
	}
	if _, err := archiveStore.Snapshot(ctx); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("unknown persisted fact field error = %v", err)
	}
}

func TestCoverageGapFactIsAnExplicitEvidenceGap(t *testing.T) {
	repositoryID := model.RepositoryID(1)
	unit := model.CoverageUnit{
		ID: model.CoverageUnitID("cov1:" + strings.Repeat("0", 64)), Kind: model.CoverageAttemptLog,
		Scope: model.CoverageScope{RepositoryID: &repositoryID}, LogicalKey: "attempt-log:10:1", RequiredForNegative: true,
	}
	var err error
	unit.ID, err = evidence.NewCoverageUnitID(unit)
	if err != nil {
		t.Fatal(err)
	}
	assessment := model.CoverageAssessment{
		ID: model.CoverageAssessmentID("cova1:" + strings.Repeat("0", 64)), UnitID: unit.ID,
		Status: model.CoverageGap, Gap: &model.CoverageGapDetail{Reason: model.GapRetentionOrDeletion, Material: true},
		EvidenceIDs: []model.EvidenceID{},
	}
	assessment.ID, err = evidence.NewCoverageAssessmentID(assessment)
	if err != nil {
		t.Fatal(err)
	}
	fact, err := NormalizeFact(Fact{Kind: FactCoverageGap, EvidenceIDs: []model.EvidenceID{}, CoverageGap: &CoverageGapFact{Unit: unit, Assessment: assessment}})
	if err != nil {
		t.Fatal(err)
	}
	if fact.Subject.RepositoryID != repositoryID || len(fact.EvidenceIDs) != 0 {
		t.Fatal("coverage gap lost explicit repository scope or invented supporting evidence")
	}
}

func TestRepositoryVisibilityGapMayHaveGlobalScope(t *testing.T) {
	unit := model.CoverageUnit{
		Kind: model.CoverageRepositoryVisibility, Scope: model.CoverageScope{},
		LogicalKey: "organization:acme:repository-visibility", RequiredForNegative: true,
	}
	var err error
	unit.ID, err = evidence.NewCoverageUnitID(unit)
	if err != nil {
		t.Fatal(err)
	}
	assessment := model.CoverageAssessment{
		UnitID: unit.ID, Status: model.CoverageGap,
		Gap:         &model.CoverageGapDetail{Reason: model.GapForbidden, Material: true},
		EvidenceIDs: []model.EvidenceID{},
	}
	assessment.ID, err = evidence.NewCoverageAssessmentID(assessment)
	if err != nil {
		t.Fatal(err)
	}
	fact, err := NormalizeFact(Fact{Kind: FactCoverageGap, EvidenceIDs: []model.EvidenceID{}, CoverageGap: &CoverageGapFact{Unit: unit, Assessment: assessment}})
	if err != nil {
		t.Fatal(err)
	}
	if fact.Subject.RepositoryID != 0 || fact.Subject.RunID != nil {
		t.Fatalf("global gap acquired invented subject identity: %#v", fact.Subject)
	}
	batch := Batch{
		Collections: []CollectionSession{{
			ID: "collection:global-gap", Mode: "archive", AuthKind: "environment",
			StartedAt: testInstant(0), EndedAt: testInstant(1),
			Scope:  CollectionScope{Organization: "acme", Repositories: []model.RepositoryID{}},
			Limits: map[string]uint64{},
		}},
		Payloads: []Payload{}, Evidence: []evidence.Envelope{}, Facts: []Fact{fact},
		Capabilities: []Capability{}, Checkpoints: []Checkpoint{},
	}
	ctx := context.Background()
	store, err := Create(ctx, filepath.Join(t.TempDir(), "global.db"), Options{CreatedAt: testInstant(0)})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Append(ctx, batch); err != nil {
		_ = store.Close()
		t.Fatal(err)
	}
	snapshot, snapshotErr := store.Snapshot(ctx)
	closeErr := store.Close()
	if snapshotErr != nil || closeErr != nil {
		t.Fatalf("global-gap round trip: snapshot=%v close=%v", snapshotErr, closeErr)
	}
	if len(snapshot.Facts) != 1 || snapshot.Facts[0].Subject.RepositoryID != 0 || snapshot.Collections[0].Scope.Repositories == nil {
		t.Fatalf("global-gap round trip changed explicit global scope: %#v", snapshot)
	}

	batch.Collections[0].Scope.Repositories = nil
	if _, err := NormalizeBatch(batch); err == nil {
		t.Fatal("nil repository scope was accepted as an explicit empty target set")
	}

	unit.Kind = model.CoverageAttemptLog
	unit.ID, err = evidence.NewCoverageUnitID(unit)
	if err != nil {
		t.Fatal(err)
	}
	assessment.UnitID = unit.ID
	assessment.ID, err = evidence.NewCoverageAssessmentID(assessment)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NormalizeFact(Fact{Kind: FactCoverageGap, EvidenceIDs: []model.EvidenceID{}, CoverageGap: &CoverageGapFact{Unit: unit, Assessment: assessment}}); err == nil {
		t.Fatal("non-repository coverage gap accepted without repository scope")
	}
}

func TestCoverageFactRequiresEvidenceBackedTerminalClosure(t *testing.T) {
	envelope, _ := testEnvelope(t)
	repositoryID := model.RepositoryID(1)
	unit := model.CoverageUnit{
		ID: model.CoverageUnitID("cov1:" + strings.Repeat("0", 64)), Kind: model.CoverageJobLog,
		Scope: model.CoverageScope{RepositoryID: &repositoryID}, LogicalKey: "repository:1:all-job-logs", RequiredForNegative: true,
	}
	unitID, err := evidence.NewCoverageUnitID(unit)
	if err != nil {
		t.Fatal(err)
	}
	unit.ID = unitID
	one := uint64(1)
	assessment := model.CoverageAssessment{
		ID: model.CoverageAssessmentID("cova1:" + strings.Repeat("0", 64)), UnitID: unit.ID,
		Status: model.CoverageCollected, ExpectedCount: &one, ObservedCount: 1,
		EvidenceIDs: []model.EvidenceID{envelope.Evidence.ID},
	}
	assessmentID, err := evidence.NewCoverageAssessmentID(assessment)
	if err != nil {
		t.Fatal(err)
	}
	assessment.ID = assessmentID
	fact, err := NormalizeFact(Fact{Kind: FactCoverage, EvidenceIDs: []model.EvidenceID{envelope.Evidence.ID}, Coverage: &CoverageFact{Unit: unit, Assessment: assessment}})
	if err != nil {
		t.Fatal(err)
	}
	if fact.Subject.RepositoryID != repositoryID || len(fact.EvidenceIDs) != 1 {
		t.Fatal("coverage closure lost scope or supporting evidence")
	}
	bad := fact
	bad.ID = ""
	bad.Coverage = &CoverageFact{Unit: unit, Assessment: assessment}
	bad.Coverage.Assessment.Status = model.CoverageExpected
	if _, err := NormalizeFact(bad); err == nil {
		t.Fatal("coverage closure accepted a non-terminal assessment")
	}
}

func TestDependencyFactKeepsTypedHistoricalIdentities(t *testing.T) {
	envelope, _ := testEnvelope(t)
	current := Fact{
		Kind:        FactDependency,
		EvidenceIDs: []model.EvidenceID{envelope.Evidence.ID},
		Dependency: &DependencyFact{
			Relation: DependencyWorkflowDeclaredAction, TargetKind: DependencyTargetAction,
			Basis: DefinitionCurrentSnapshot, CallerRepositoryID: 1, CallerRepository: "acme/service",
			CallerPath: ".github/workflows/ci.yml", TargetRepository: "example/action", DeclaredRef: "v1",
			ContradictsFactIDs: []string{}, EventTime: unknownEventTime(),
		},
	}
	current, err := NormalizeFact(current)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		mutate func(*DependencyFact)
	}{
		{name: "historical execution identity", mutate: func(value *DependencyFact) {
			execution := model.JobExecutionIdentity{RepositoryID: 1, RunID: 10, RunAttempt: 1, JobID: 20}
			value.Execution = &execution
		}},
		{name: "historical event time", mutate: func(value *DependencyFact) { value.EventTime = testEvent(1) }},
	} {
		t.Run("current snapshot rejects "+test.name, func(t *testing.T) {
			bad := current
			bad.ID = ""
			dependency := *current.Dependency
			test.mutate(&dependency)
			bad.Dependency = &dependency
			if _, err := NormalizeFact(bad); err == nil || !strings.Contains(err.Error(), "current snapshot") {
				t.Fatalf("current snapshot accepted %s: %v", test.name, err)
			}
		})
	}
	caller := model.CallerWorkflowObjectID(model.GitObjectID{Algorithm: model.HashSHA1, Value: strings.Repeat("b", 40)})
	target := model.ActionSourceObjectID(model.GitObjectID{Algorithm: model.HashSHA1, Value: strings.Repeat("a", 40)})
	historical := current
	historical.ID = ""
	historical.Dependency = &DependencyFact{
		Relation: DependencyRefResolvedTo, TargetKind: DependencyTargetAction, Basis: DefinitionHistoricalAtRun,
		CallerRepositoryID: 1, CallerRepository: "acme/service", CallerPath: ".github/workflows/ci.yml",
		CallerWorkflowObjectID: &caller, TargetRepository: "example/action", DeclaredRef: "v1",
		TargetActionObjectID: &target, ContradictsFactIDs: []string{current.ID}, EventTime: testEvent(1),
	}
	historical, err = NormalizeFact(historical)
	if err != nil {
		t.Fatal(err)
	}
	if historical.ID == current.ID || historical.Dependency.TargetActionObjectID == nil {
		t.Fatal("historical exact identity collapsed into current declaration")
	}
	bad := historical
	bad.ID = ""
	bad.Dependency = cloneDependency(historical.Dependency)
	called := model.CalledWorkflowObjectID(model.GitObjectID{Algorithm: model.HashSHA1, Value: strings.Repeat("c", 40)})
	bad.Dependency.TargetCalledWorkflowObjectID = &called
	if _, err := NormalizeFact(bad); err == nil {
		t.Fatal("dependency accepted competing Action and called-workflow identities")
	}
	reusable := historical
	reusable.ID = ""
	reusable.Dependency = &DependencyFact{
		Relation: DependencyWorkflowCalledWorkflow, TargetKind: DependencyTargetReusableWorkflow,
		Basis: DefinitionHistoricalAtRun, CallerRepositoryID: 1, CallerRepository: "acme/service",
		CallerPath: ".github/workflows/ci.yml", CallerWorkflowObjectID: &caller,
		TargetRepository: "acme/shared", TargetPath: ".github/workflows/build.yml", DeclaredRef: "main",
		TargetCalledWorkflowObjectID: &called, ContradictsFactIDs: []string{}, EventTime: testEvent(1),
	}
	if _, err := NormalizeFact(reusable); err != nil {
		t.Fatalf("exact called-workflow dependency rejected: %v", err)
	}
	runtimeMetadata := reusable
	runtimeMetadata.ID = ""
	runtimeMetadata.Dependency = cloneDependency(reusable.Dependency)
	runtimeMetadata.Dependency.Basis = DefinitionRuntimeAttemptMetadata
	runtimeMetadata.Dependency.CallerWorkflowObjectID = nil
	attemptIdentity := model.RunAttemptIdentity{RepositoryID: 1, RunID: 10, RunAttempt: 2}
	runtimeMetadata.Dependency.AttemptExecution = &attemptIdentity
	if _, err := NormalizeFact(runtimeMetadata); err != nil {
		t.Fatalf("attempt-scoped called-workflow metadata rejected: %v", err)
	}
	runtimeMetadata.Dependency.TargetCalledWorkflowObjectID = nil
	if _, err := NormalizeFact(runtimeMetadata); err == nil {
		t.Fatal("attempt metadata accepted without an exact called-workflow object ID")
	}
	local := historical
	local.ID = ""
	local.Dependency = &DependencyFact{
		Relation: DependencyLocalActionResolvedTo, TargetKind: DependencyTargetLocalAction,
		Basis: DefinitionHistoricalAtRun, CallerRepositoryID: 1, CallerRepository: "acme/service",
		CallerPath: ".github/workflows/ci.yml", CallerWorkflowObjectID: &caller,
		TargetRepository: "other/repository", TargetPath: ".github/actions/local", TargetActionObjectID: &target,
		ContradictsFactIDs: []string{}, EventTime: testEvent(1),
	}
	if _, err := NormalizeFact(local); err == nil {
		t.Fatal("local Action dependency crossed repository boundary")
	}
}

func cloneDependency(value *DependencyFact) *DependencyFact {
	copy := *value
	copy.ContradictsFactIDs = append([]string(nil), value.ContradictsFactIDs...)
	return &copy
}

func testBatch(t *testing.T) Batch {
	t.Helper()
	envelope, payload := testEnvelope(t)
	evidenceID := envelope.Evidence.ID
	workflowPath, err := model.NewWorkflowPath(".github/workflows/ci.yml")
	if err != nil {
		t.Fatal(err)
	}
	runID, attempt, jobID := model.WorkflowRunID(10), model.RunAttempt(1), model.JobID(20)
	execution := model.JobExecutionIdentity{RepositoryID: 1, RunID: runID, RunAttempt: attempt, JobID: jobID}
	apiStep := model.APIStepNumber(1)
	step := model.StepIdentity{Job: execution, APIStepNumber: &apiStep, LifecyclePhase: model.LifecycleMain, Occurrence: 1}
	actionOID := model.ActionSourceObjectID(model.GitObjectID{Algorithm: model.HashSHA1, Value: strings.Repeat("a", 40)})
	observation := model.RuntimeActionObservation{
		ID: model.RuntimeObservationID("rtobs1:" + strings.Repeat("0", 64)), Kind: model.ObservationLifecycleStarted,
		Execution: execution, Step: &step, ActionRepository: "example/action", DeclaredRef: "v1",
		SourceObjectID: &actionOID, EventTime: testEvent(4), SourceEvidenceIDs: []model.EvidenceID{evidenceID},
		SourceSpan: model.SourceSpan{ByteStart: 10, ByteEnd: 40}, ExtractorName: "runner-log",
		ExtractorVersion: "1.0.0", RulesetSHA256: strings.Repeat("d", 64),
	}
	observation.ID, err = evidence.NewRuntimeObservationID(observation)
	if err != nil {
		t.Fatal(err)
	}
	currentDependency := Fact{
		Kind: FactDependency, EvidenceIDs: []model.EvidenceID{evidenceID},
		Dependency: &DependencyFact{
			Relation: DependencyWorkflowDeclaredAction, TargetKind: DependencyTargetAction, Basis: DefinitionCurrentSnapshot,
			CallerRepositoryID: 1, CallerRepository: "acme/service", CallerPath: string(workflowPath),
			TargetRepository: "example/action", DeclaredRef: "v1", ContradictsFactIDs: []string{}, EventTime: unknownEventTime(),
		},
	}
	currentDependency, err = NormalizeFact(currentDependency)
	if err != nil {
		t.Fatal(err)
	}
	callerOID := model.CallerWorkflowObjectID(model.GitObjectID{Algorithm: model.HashSHA1, Value: strings.Repeat("b", 40)})
	historicalDependency := Fact{
		Kind: FactDependency, EvidenceIDs: []model.EvidenceID{evidenceID},
		Dependency: &DependencyFact{
			Relation: DependencyRefResolvedTo, TargetKind: DependencyTargetAction, Basis: DefinitionHistoricalAtRun,
			CallerRepositoryID: 1, CallerRepository: "acme/service", CallerPath: string(workflowPath),
			CallerWorkflowObjectID: &callerOID, TargetRepository: "example/action", DeclaredRef: "v1",
			TargetActionObjectID: &actionOID, Execution: &execution, StepKey: step.Key(),
			ContradictsFactIDs: []string{currentDependency.ID}, EventTime: testEvent(4),
		},
	}
	secretName, err := model.NewSecretName("DEPLOY_KEY")
	if err != nil {
		t.Fatal(err)
	}
	private, no := true, false
	facts := []Fact{
		{Kind: FactExposure, EvidenceIDs: []model.EvidenceID{evidenceID}, Exposure: &ExposureFact{
			Execution: execution, StepKey: step.Key(), EventTime: testEvent(4),
			Credential: &model.CredentialExposure{Kind: model.ExposureSecretPassedToStep, Basis: model.ExposureBasisHistoricalDefinitionFlow, SecretName: &secretName,
				Conclusion: "The named secret was passed to this started step.", EvidenceIDs: []model.EvidenceID{evidenceID}},
		}},
		{Kind: FactJob, EvidenceIDs: []model.EvidenceID{evidenceID}, Job: &JobFact{Execution: execution, DisplayName: "build", Status: "completed", Conclusion: "success", EventTime: testEvent(3)}},
		{Kind: FactActionOccurrence, EvidenceIDs: []model.EvidenceID{evidenceID}, ActionOccurrence: &ActionOccurrenceFact{Observation: observation}},
		historicalDependency,
		currentDependency,
		{Kind: FactAttempt, EvidenceIDs: []model.EvidenceID{evidenceID}, Attempt: &AttemptFact{RepositoryID: 1, RunID: runID, RunAttempt: attempt, Status: "completed", Conclusion: "success", Actor: ActorFact{Login: "octocat"}, TriggeringActor: ActorFact{Login: "octocat"}, EventTime: testEvent(2)}},
		{Kind: FactRun, EvidenceIDs: []model.EvidenceID{evidenceID}, Run: &RunFact{RepositoryID: 1, RunID: runID, WorkflowPath: &workflowPath, EventType: "push", Status: "completed", Conclusion: "success", Actor: ActorFact{Login: "octocat"}, EventTime: testEvent(1)}},
		{Kind: FactRepository, EvidenceIDs: []model.EvidenceID{evidenceID}, Repository: &RepositoryFact{Repository: model.RepositorySubject{ID: 1, Name: "acme/service"}, Visibility: "private", Private: &private, Fork: &no, Archived: &no, Disabled: &no, DefaultBranch: "main"}},
	}
	return Batch{
		Collections: []CollectionSession{{
			ID: "collection:test", Mode: "fixture", APIVersion: "2026-03-10", AuthKind: "none",
			StartedAt: testInstant(0), EndedAt: testInstant(10),
			Scope:  CollectionScope{Organization: "acme", Repositories: []model.RepositoryID{1}},
			Limits: map[string]uint64{"max_log_bytes": 16 << 20},
		}},
		Payloads: []Payload{payload}, Evidence: []evidence.Envelope{envelope}, Facts: facts,
		Capabilities: []Capability{{Name: "attempt-logs", Status: CapabilityStructuredOnly, ExtractorVersion: "1.0.0", Details: map[string]string{"format": "normalized"}}},
		Checkpoints: []Checkpoint{{RepositoryID: 1, DiscoveryWatermark: instantPointer(testInstant(10)), OverlapSeconds: 3600, WatchHorizonDays: 35,
			LastSuccessfulCollection: "collection:test", WatchedParents: []WatchedParent{{RunID: runID, CreatedAt: testInstant(1), LastRefreshedAt: instantPointer(testInstant(10)), FinalRefreshComplete: true}}}},
	}
}

func testEnvelope(t *testing.T) (evidence.Envelope, Payload) {
	t.Helper()
	payloadBytes := []byte(`{"repository":"acme/service","run_id":10}`)
	payloadSum := sha256.Sum256(payloadBytes)
	payloadHash := hex.EncodeToString(payloadSum[:])
	payload := Payload{SHA256: payloadHash, MediaType: "application/json", Bytes: payloadBytes}
	repositoryID, runID, attempt, jobID := model.RepositoryID(1), model.WorkflowRunID(10), model.RunAttempt(1), model.JobID(20)
	scope := model.CoverageScope{RepositoryID: &repositoryID, RunID: &runID, RunAttempt: &attempt, JobID: &jobID}
	identity := evidence.LogicalSourceIdentity{Kind: evidence.SourceAPIJSON, CanonicalID: "repos/acme/service/actions/runs/10", Scope: scope, RequestParameters: evidence.RequestParameters{"page": "1"}}
	sourceID, err := evidence.NewLogicalSourceID(identity)
	if err != nil {
		t.Fatal(err)
	}
	sourceBytes := []byte("sanitized-source-object")
	sourceSum := sha256.Sum256(sourceBytes)
	sourceHash := hex.EncodeToString(sourceSum[:])
	retention := evidence.RetentionDescriptor{MediaType: payload.MediaType, ByteLength: uint64(len(payloadBytes)), RetainedPayloadSHA256: &payloadHash, RedactionStatus: evidence.RedactionStructuredAllowlist, RedactionPolicyVersion: "1.0.0"}
	evidenceID, err := evidence.NewEvidenceID(sourceID, sourceHash, retention)
	if err != nil {
		t.Fatal(err)
	}
	observationID, err := evidence.NewCollectionObservationID(evidenceID, "collection:test", "request:test", testInstant(10), 1)
	if err != nil {
		t.Fatal(err)
	}
	envelope := evidence.Envelope{
		Evidence: evidence.EvidenceObject{
			SchemaVersion: evidence.EvidenceSchemaVersion, ID: evidenceID,
			LogicalSource: evidence.LogicalSource{ID: sourceID, Kind: identity.Kind, CanonicalID: identity.CanonicalID, RequestParameters: identity.RequestParameters},
			Source:        evidence.SourceDescriptor{Provider: evidence.ProviderGitHub, APIVersion: "2026-03-10", EndpointTemplate: "/repos/{owner}/{repo}/actions/runs/{run_id}", RequestParameters: evidence.RequestParameters{"page": "1"}, RequestAttempt: 1},
			Scope:         scope, EventTime: testEvent(1),
			Content:    evidence.ContentDescriptor{MediaType: payload.MediaType, ByteLength: uint64(len(payloadBytes)), Complete: true, SourceSHA256: sourceHash, RetainedPayloadSHA256: &payloadHash},
			Extractor:  evidence.ExtractorDescriptor{Name: "github-rest", Version: "1.0.0", RulesetSHA256: strings.Repeat("c", 64)},
			Redaction:  evidence.RedactionDescriptor{Status: evidence.RedactionStructuredAllowlist, PolicyVersion: "1.0.0"},
			Derivation: evidence.DerivationDescriptor{ParentEvidenceIDs: []model.EvidenceID{}}, Errors: []evidence.EvidenceError{},
		},
		Observation: evidence.CollectionObservation{ID: observationID, EvidenceID: evidenceID, CollectionSessionID: "collection:test", RequestID: "request:test", RequestAttempt: 1,
			CollectionTime: model.CollectionWindow{StartedAt: testInstant(0), EndedAt: testInstant(10)}},
	}
	if err := envelope.Validate(); err != nil {
		t.Fatal(err)
	}
	return envelope, payload
}

func testRawEnvelope(t *testing.T, digest string, length uint64, mediaType string) evidence.Envelope {
	t.Helper()
	repositoryID, runID, attempt, jobID := model.RepositoryID(1), model.WorkflowRunID(10), model.RunAttempt(1), model.JobID(20)
	scope := model.CoverageScope{RepositoryID: &repositoryID, RunID: &runID, RunAttempt: &attempt, JobID: &jobID}
	identity := evidence.LogicalSourceIdentity{Kind: evidence.SourceJobLog, CanonicalID: "github:job-log:1:10:1:20", Scope: scope, RequestParameters: evidence.RequestParameters{"job_id": "20", "run_id": "10"}}
	logicalID, err := evidence.NewLogicalSourceID(identity)
	if err != nil {
		t.Fatal(err)
	}
	retainedPath, err := RawRelativePath(digest)
	if err != nil {
		t.Fatal(err)
	}
	retention := evidence.RetentionDescriptor{MediaType: mediaType, ByteLength: length, RawRetained: true, RetainedPayloadSHA256: &digest, RedactionStatus: evidence.RedactionNotInspected, RedactionPolicyVersion: "raw-exact-opt-in-v1"}
	evidenceID, err := evidence.NewEvidenceID(logicalID, digest, retention)
	if err != nil {
		t.Fatal(err)
	}
	requestID := model.RequestID("request:" + strings.Repeat("9", 64))
	observationID, err := evidence.NewCollectionObservationID(evidenceID, "collection:test", requestID, testInstant(10), 1)
	if err != nil {
		t.Fatal(err)
	}
	envelope := evidence.Envelope{
		Evidence: evidence.EvidenceObject{
			SchemaVersion: evidence.EvidenceSchemaVersion, ID: evidenceID,
			LogicalSource: evidence.LogicalSource{ID: logicalID, Kind: identity.Kind, CanonicalID: identity.CanonicalID, RequestParameters: identity.RequestParameters},
			Source:        evidence.SourceDescriptor{Provider: evidence.ProviderGitHub, APIVersion: "2026-03-10", EndpointTemplate: "/repos/{owner}/{repo}/actions/jobs/{job_id}/logs", RequestParameters: identity.RequestParameters, RequestAttempt: 1},
			Scope:         scope, EventTime: testEvent(3),
			Content:    evidence.ContentDescriptor{MediaType: mediaType, ByteLength: length, Complete: true, SourceSHA256: digest, RetainedPayloadSHA256: &digest, RawRetained: true, RetainedPath: retainedPath},
			Extractor:  evidence.ExtractorDescriptor{Name: "livecollect", Version: "1.0.0", RulesetSHA256: strings.Repeat("e", 64)},
			Redaction:  evidence.RedactionDescriptor{Status: evidence.RedactionNotInspected, PolicyVersion: "raw-exact-opt-in-v1"},
			Derivation: evidence.DerivationDescriptor{ParentEvidenceIDs: []model.EvidenceID{}}, Errors: []evidence.EvidenceError{},
		},
		Observation: evidence.CollectionObservation{ID: observationID, EvidenceID: evidenceID, CollectionSessionID: "collection:test", RequestID: requestID, RequestAttempt: 1, CollectionTime: model.CollectionWindow{StartedAt: testInstant(0), EndedAt: testInstant(10)}},
	}
	if err := envelope.Validate(); err != nil {
		t.Fatal(err)
	}
	return envelope
}

func testInstant(seconds int) model.Instant {
	return model.MustInstant(time.Date(2026, 8, 20, 12, 0, seconds, 0, time.UTC))
}

func testEvent(seconds int) model.EventInterval {
	instant := testInstant(seconds)
	return model.EventInterval{Start: &instant, Precision: model.PrecisionSecond, Approximation: model.ApproximationExact, Basis: model.TimeBasisAPIField}
}

func instantPointer(value model.Instant) *model.Instant { return &value }

func TestNormalizeBatchDoesNotDependOnInputOrder(t *testing.T) {
	first, err := NormalizeBatch(testBatch(t))
	if err != nil {
		t.Fatal(err)
	}
	secondInput := testBatch(t)
	for left, right := 0, len(secondInput.Facts)-1; left < right; left, right = left+1, right-1 {
		secondInput.Facts[left], secondInput.Facts[right] = secondInput.Facts[right], secondInput.Facts[left]
	}
	second, err := NormalizeBatch(secondInput)
	if err != nil {
		t.Fatal(err)
	}
	if first.ID != second.ID || !reflect.DeepEqual(first, second) {
		t.Fatal("archive batch normalization depends on fact input order")
	}
}

func TestNormalizeBatchPreservesExplicitEmptyWatchedParents(t *testing.T) {
	input := testBatch(t)
	input.Checkpoints[0].WatchedParents = []WatchedParent{}

	normalized, err := NormalizeBatch(input)
	if err != nil {
		t.Fatal(err)
	}
	if normalized.Checkpoints[0].WatchedParents == nil {
		t.Fatal("normalization changed an explicit empty watched-parent array to nil")
	}

	input.Checkpoints[0].WatchedParents = nil
	if _, err := NormalizeBatch(input); err == nil {
		t.Fatal("normalization accepted a nil watched-parent array")
	}
}
