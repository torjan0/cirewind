package casegen_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/torjan0/cirewind/internal/analyze"
	"github.com/torjan0/cirewind/internal/archive"
	"github.com/torjan0/cirewind/internal/casefile"
	"github.com/torjan0/cirewind/internal/casegen"
	"github.com/torjan0/cirewind/internal/demodata"
	"github.com/torjan0/cirewind/internal/evidence"
	"github.com/torjan0/cirewind/internal/incident"
	"github.com/torjan0/cirewind/internal/model"
	"github.com/torjan0/cirewind/internal/store"
)

var requiredCaseFiles = []string{
	"affected-runs.csv",
	"case.db",
	"collection-metadata.json",
	"evidence.jsonl",
	"findings.json",
	"graph.json",
	"graph.svg",
	"manifest.sha256",
	"report.html",
	"summary.md",
}

func TestGenerateEndToEndPersistsVerifiableIdentityContract(t *testing.T) {
	ctx := context.Background()
	snapshot, pack, derived := fixture(t, ctx)
	reordered := reverseSnapshotInput(t, snapshot)
	reorderedDerived, err := analyze.Derive(reordered, pack, time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC), analyze.ModeReplay)
	if err != nil {
		t.Fatal(err)
	}
	first := filepath.Join(t.TempDir(), "case-one")
	second := filepath.Join(t.TempDir(), "case-two")
	inputs := []struct {
		output   string
		snapshot archive.Snapshot
		derived  analyze.Result
	}{
		{output: first, snapshot: snapshot, derived: derived},
		{output: second, snapshot: reordered, derived: reorderedDerived},
	}
	for _, input := range inputs {
		if err := casegen.Generate(ctx, casegen.Options{Output: input.output, Snapshot: input.snapshot, Pack: pack, Case: input.derived.Case}); err != nil {
			t.Fatalf("Generate(%s): %v", input.output, err)
		}
		if err := casefile.VerifyManifest(ctx, input.output); err != nil {
			t.Fatalf("VerifyManifest(%s): %v", input.output, err)
		}
		for _, name := range requiredCaseFiles {
			info, err := os.Stat(filepath.Join(input.output, name))
			if err != nil {
				t.Fatalf("required case file %s: %v", name, err)
			}
			if !info.Mode().IsRegular() {
				t.Fatalf("case output %s is not regular", name)
			}
			if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
				t.Fatalf("case output %s has permissive mode %o", name, info.Mode().Perm())
			}
		}
		verifyOrdinaryReadOnlyInspectionDoesNotInvalidate(t, ctx, input.output)
	}

	for _, name := range requiredCaseFiles {
		firstBytes, err := os.ReadFile(filepath.Join(first, name))
		if err != nil {
			t.Fatal(err)
		}
		secondBytes, err := os.ReadFile(filepath.Join(second, name))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(firstBytes, secondBytes) {
			t.Fatalf("fixed-input case output %s is nondeterministic", name)
		}
	}

	database, err := store.OpenReadOnly(ctx, filepath.Join(first, "case.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if kind, err := database.Kind(ctx); err != nil || kind != store.KindCase {
		t.Fatalf("case database kind = %q, %v", kind, err)
	}
	if err := database.IntegrityCheck(ctx); err != nil {
		t.Fatalf("case database integrity: %v", err)
	}
	verifyPersistedFindingIdentities(t, ctx, database, pack)

	if err := os.WriteFile(filepath.Join(first, "findings.json"), []byte("tampered\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := casefile.VerifyManifest(ctx, first); err == nil {
		t.Fatal("tampered generated case passed manifest verification")
	}
}

func reverseSnapshotInput(t *testing.T, source archive.Snapshot) archive.Snapshot {
	t.Helper()
	encoded, err := json.Marshal(source)
	if err != nil {
		t.Fatal(err)
	}
	var cloned archive.Snapshot
	if err := json.Unmarshal(encoded, &cloned); err != nil {
		t.Fatal(err)
	}
	reverseSlice(cloned.Collections)
	reverseSlice(cloned.Evidence)
	reverseSlice(cloned.Facts)
	return cloned
}

func reverseSlice[T any](values []T) {
	for left, right := 0, len(values)-1; left < right; left, right = left+1, right-1 {
		values[left], values[right] = values[right], values[left]
	}
}

func verifyOrdinaryReadOnlyInspectionDoesNotInvalidate(t *testing.T, ctx context.Context, output string) {
	t.Helper()
	path := filepath.Join(output, "case.db")
	inspector, err := sql.Open("sqlite", ordinaryReadOnlyDSN(path))
	if err != nil {
		t.Fatal(err)
	}
	var journalMode string
	if err := inspector.QueryRowContext(ctx, `PRAGMA journal_mode`).Scan(&journalMode); err != nil {
		_ = inspector.Close()
		t.Fatal(err)
	}
	if journalMode != "delete" {
		_ = inspector.Close()
		t.Fatalf("generated case journal mode = %q, want delete", journalMode)
	}
	var findings int
	if err := inspector.QueryRowContext(ctx, `SELECT count(*) FROM finding_revisions`).Scan(&findings); err != nil {
		_ = inspector.Close()
		t.Fatal(err)
	}
	if err := inspector.Close(); err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		if _, err := os.Lstat(path + suffix); !os.IsNotExist(err) {
			t.Fatalf("ordinary read-only inspection created sidecar %s: %v", path+suffix, err)
		}
	}
	if err := casefile.VerifyManifest(ctx, output); err != nil {
		t.Fatalf("ordinary read-only inspection invalidated case manifest: %v", err)
	}
}

func ordinaryReadOnlyDSN(path string) string {
	slashPath := filepath.ToSlash(path)
	if filepath.VolumeName(path) != "" && !strings.HasPrefix(slashPath, "/") {
		slashPath = "/" + slashPath
	}
	target := &url.URL{Scheme: "file", Path: slashPath}
	query := url.Values{}
	query.Set("mode", "ro")
	target.RawQuery = query.Encode()
	return target.String()
}

type fixtureRawSource map[string][]byte

func (s fixtureRawSource) CopyRaw(_ context.Context, digest string, destination io.Writer) error {
	_, err := destination.Write(s[digest])
	return err
}

type fixtureRawSourceFunc func(context.Context, string, io.Writer) error

func (f fixtureRawSourceFunc) CopyRaw(ctx context.Context, digest string, destination io.Writer) error {
	return f(ctx, digest, destination)
}

func TestGenerateCopiesOptedInRawEvidenceOnceAndManifestsIt(t *testing.T) {
	ctx := context.Background()
	snapshot, pack, _ := fixture(t, ctx)
	rawBytes := []byte("exact retained log bytes\n")
	sum := sha256.Sum256(rawBytes)
	digest := hex.EncodeToString(sum[:])
	snapshot.Evidence = append(snapshot.Evidence, rawEnvelope(t, snapshot, digest, uint64(len(rawBytes))))
	snapshot.Collections[0].RawRetention = true
	foundRawCapability := false
	for index := range snapshot.Capabilities {
		if snapshot.Capabilities[index].Name == "raw_logs" {
			foundRawCapability = true
			snapshot.Capabilities[index].Status = archive.CapabilityRetained
			snapshot.Capabilities[index].Details = map[string]string{"policy": "exact-opt-in", "retained_count": "1"}
		}
	}
	if !foundRawCapability {
		snapshot.Capabilities = append(snapshot.Capabilities, archive.Capability{Name: "raw_logs", Status: archive.CapabilityRetained, Details: map[string]string{"policy": "exact-opt-in", "retained_count": "1"}})
	}
	normalized, err := archive.NormalizeSnapshot(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	derived, err := analyze.Derive(normalized, pack, time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC), analyze.ModeReplay)
	if err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "case")
	if err := casegen.Generate(ctx, casegen.Options{Output: output, Raw: true, RawSource: fixtureRawSource{digest: rawBytes}, Snapshot: normalized, Pack: pack, Case: derived.Case}); err != nil {
		t.Fatal(err)
	}
	retained, err := os.ReadFile(filepath.Join(output, "raw", digest+".bin"))
	if err != nil || !bytes.Equal(retained, rawBytes) {
		t.Fatalf("retained case raw bytes=%q err=%v", retained, err)
	}
	if err := casefile.VerifyManifest(ctx, output); err != nil {
		t.Fatal(err)
	}
	manifest, _ := os.ReadFile(filepath.Join(output, "manifest.sha256"))
	if strings.Count(string(manifest), "raw/"+digest+".bin") != 1 {
		t.Fatalf("raw object was not manifested exactly once: %q", manifest)
	}
	database, err := store.OpenReadOnly(ctx, filepath.Join(output, "case.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	var rawMaterialized, retainedPath string
	if err := database.DB().QueryRowContext(ctx, `SELECT value FROM metadata WHERE key='case_raw_materialized'`).Scan(&rawMaterialized); err != nil {
		t.Fatal(err)
	}
	if err := database.DB().QueryRowContext(ctx, `SELECT retained_path FROM evidence_payloads WHERE payload_sha256=?`, digest).Scan(&retainedPath); err != nil {
		t.Fatal(err)
	}
	if rawMaterialized != "true" || retainedPath != "raw/"+digest+".bin" {
		t.Fatalf("raw case metadata materialized=%q path=%q", rawMaterialized, retainedPath)
	}

	compactOutput := filepath.Join(t.TempDir(), "compact-case")
	if err := casegen.Generate(ctx, casegen.Options{Output: compactOutput, Raw: false, Snapshot: normalized, Pack: pack, Case: derived.Case}); err != nil {
		t.Fatalf("compact replay of raw-bearing evidence was blocked: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(compactOutput, "raw")); !os.IsNotExist(err) {
		t.Fatalf("raw directory exists without opt-in: %v", err)
	}
	compactDatabase, err := store.OpenReadOnly(ctx, filepath.Join(compactOutput, "case.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer compactDatabase.Close()
	if err := compactDatabase.DB().QueryRowContext(ctx, `SELECT value FROM metadata WHERE key='case_raw_materialized'`).Scan(&rawMaterialized); err != nil {
		t.Fatal(err)
	}
	if rawMaterialized != "false" {
		t.Fatalf("compact case raw materialization marker=%q", rawMaterialized)
	}
}

func TestGenerateRawCopyFailsClosedAndCleansStaging(t *testing.T) {
	for _, test := range []struct {
		name string
		copy fixtureRawSourceFunc
	}{
		{
			name: "one overlong write",
			copy: func(_ context.Context, _ string, destination io.Writer) error {
				_, _ = destination.Write([]byte("abc!"))
				return nil
			},
		},
		{
			name: "extra write error ignored by source",
			copy: func(_ context.Context, _ string, destination io.Writer) error {
				if _, err := destination.Write([]byte("abc")); err != nil {
					return err
				}
				_, _ = destination.Write([]byte("!"))
				return nil
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			snapshot, pack, derived, _ := rawFixture(t, ctx, []byte("abc"), 3)
			parent := t.TempDir()
			output := filepath.Join(parent, "case")
			err := casegen.Generate(ctx, casegen.Options{Output: output, Raw: true, RawSource: test.copy, Snapshot: snapshot, Pack: pack, Case: derived.Case})
			if err == nil || !strings.Contains(err.Error(), "declared byte length") {
				t.Fatalf("Generate error = %v, want declared-length rejection", err)
			}
			assertNoPublishedOrStagedCase(t, parent, output)
		})
	}
}

func TestGenerateRawCopyHonorsMidStreamCancellationAndCleansStaging(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	snapshot, pack, derived, _ := rawFixture(t, ctx, []byte("ab"), 2)
	source := fixtureRawSourceFunc(func(_ context.Context, _ string, destination io.Writer) error {
		if _, err := destination.Write([]byte("a")); err != nil {
			return err
		}
		cancel()
		_, _ = destination.Write([]byte("b"))
		return nil
	})
	parent := t.TempDir()
	output := filepath.Join(parent, "case")
	err := casegen.Generate(ctx, casegen.Options{Output: output, Raw: true, RawSource: source, Snapshot: snapshot, Pack: pack, Case: derived.Case})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Generate error = %v, want context cancellation", err)
	}
	assertNoPublishedOrStagedCase(t, parent, output)
}

func TestGenerateRawMaterializationPreflightRunsBeforeSource(t *testing.T) {
	ctx := context.Background()
	const oversized = uint64(2<<30) + 1
	snapshot, pack, derived, _ := rawFixture(t, ctx, nil, oversized)
	called := false
	source := fixtureRawSourceFunc(func(context.Context, string, io.Writer) error {
		called = true
		return nil
	})
	parent := t.TempDir()
	output := filepath.Join(parent, "case")
	err := casegen.Generate(ctx, casegen.Options{Output: output, Raw: true, RawSource: source, Snapshot: snapshot, Pack: pack, Case: derived.Case})
	if err == nil || !strings.Contains(err.Error(), "exceeds the 2147483648-byte limit") {
		t.Fatalf("Generate error = %v, want per-object preflight rejection", err)
	}
	if called {
		t.Fatal("raw source was called before the materialization plan passed preflight")
	}
	assertNoPublishedOrStagedCase(t, parent, output)
}

func TestGenerateRawDisabledDoesNotApplyMaterializationLimits(t *testing.T) {
	ctx := context.Background()
	const oversized = uint64(2<<30) + 1
	snapshot, pack, derived, _ := rawFixture(t, ctx, nil, oversized)
	output := filepath.Join(t.TempDir(), "compact-case")
	if err := casegen.Generate(ctx, casegen.Options{Output: output, Raw: false, Snapshot: snapshot, Pack: pack, Case: derived.Case}); err != nil {
		t.Fatalf("compact generation applied a raw materialization limit: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(output, "raw")); !os.IsNotExist(err) {
		t.Fatalf("raw directory exists in compact case: %v", err)
	}
	if err := casefile.VerifyManifest(ctx, output); err != nil {
		t.Fatalf("verify compact raw-bearing case: %v", err)
	}
}

func rawFixture(t *testing.T, ctx context.Context, sourceBytes []byte, length uint64) (archive.Snapshot, *incident.ValidatedPack, analyze.Result, string) {
	t.Helper()
	snapshot, pack, _ := fixture(t, ctx)
	sum := sha256.Sum256(sourceBytes)
	digest := hex.EncodeToString(sum[:])
	snapshot.Evidence = append(snapshot.Evidence, rawEnvelope(t, snapshot, digest, length))
	snapshot.Collections[0].RawRetention = true
	foundRawCapability := false
	for index := range snapshot.Capabilities {
		if snapshot.Capabilities[index].Name != "raw_logs" {
			continue
		}
		foundRawCapability = true
		snapshot.Capabilities[index].Status = archive.CapabilityRetained
		snapshot.Capabilities[index].Details = map[string]string{"policy": "exact-opt-in", "retained_count": "1"}
	}
	if !foundRawCapability {
		snapshot.Capabilities = append(snapshot.Capabilities, archive.Capability{Name: "raw_logs", Status: archive.CapabilityRetained, Details: map[string]string{"policy": "exact-opt-in", "retained_count": "1"}})
	}
	normalized, err := archive.NormalizeSnapshot(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	derived, err := analyze.Derive(normalized, pack, time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC), analyze.ModeReplay)
	if err != nil {
		t.Fatal(err)
	}
	return normalized, pack, derived, digest
}

func assertNoPublishedOrStagedCase(t *testing.T, parent, output string) {
	t.Helper()
	if _, err := os.Lstat(output); !os.IsNotExist(err) {
		t.Fatalf("failed generation published output: %v", err)
	}
	entries, err := os.ReadDir(parent)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".cirewind-case-") {
			t.Fatalf("failed generation left staging directory %q", entry.Name())
		}
	}
}

func rawEnvelope(t *testing.T, snapshot archive.Snapshot, digest string, length uint64) evidence.Envelope {
	t.Helper()
	base := snapshot.Evidence[0].Evidence
	scope := base.Scope
	identity := evidence.LogicalSourceIdentity{Kind: evidence.SourceJobLog, CanonicalID: "github:job-log:synthetic-raw", Scope: scope, RequestParameters: evidence.RequestParameters{"fixture": "raw"}}
	logicalID, err := evidence.NewLogicalSourceID(identity)
	if err != nil {
		t.Fatal(err)
	}
	path, err := archive.RawRelativePath(digest)
	if err != nil {
		t.Fatal(err)
	}
	retention := evidence.RetentionDescriptor{MediaType: "text/plain", ByteLength: length, RawRetained: true, RetainedPayloadSHA256: &digest, RedactionStatus: evidence.RedactionNotInspected, RedactionPolicyVersion: "raw-exact-opt-in-v1"}
	evidenceID, err := evidence.NewEvidenceID(logicalID, digest, retention)
	if err != nil {
		t.Fatal(err)
	}
	requestID := model.RequestID("request:" + strings.Repeat("8", 64))
	ended := snapshot.Collections[0].EndedAt
	observationID, err := evidence.NewCollectionObservationID(evidenceID, snapshot.Collections[0].ID, requestID, ended, 1)
	if err != nil {
		t.Fatal(err)
	}
	result := evidence.Envelope{
		Evidence: evidence.EvidenceObject{
			SchemaVersion: evidence.EvidenceSchemaVersion, ID: evidenceID,
			LogicalSource: evidence.LogicalSource{ID: logicalID, Kind: identity.Kind, CanonicalID: identity.CanonicalID, RequestParameters: identity.RequestParameters},
			Source:        evidence.SourceDescriptor{Provider: evidence.ProviderGitHub, APIVersion: "2026-03-10", EndpointTemplate: "/repos/{owner}/{repo}/actions/jobs/{job_id}/logs", RequestParameters: identity.RequestParameters, RequestAttempt: 1},
			Scope:         scope, EventTime: base.EventTime,
			Content:    evidence.ContentDescriptor{MediaType: "text/plain", ByteLength: length, Complete: true, SourceSHA256: digest, RetainedPayloadSHA256: &digest, RawRetained: true, RetainedPath: path},
			Extractor:  evidence.ExtractorDescriptor{Name: "fixture", Version: "1.0.0", RulesetSHA256: strings.Repeat("7", 64)},
			Redaction:  evidence.RedactionDescriptor{Status: evidence.RedactionNotInspected, PolicyVersion: "raw-exact-opt-in-v1"},
			Derivation: evidence.DerivationDescriptor{ParentEvidenceIDs: []model.EvidenceID{}}, Errors: []evidence.EvidenceError{},
		},
		Observation: evidence.CollectionObservation{ID: observationID, EvidenceID: evidenceID, CollectionSessionID: snapshot.Collections[0].ID, RequestID: requestID, RequestAttempt: 1, CollectionTime: model.CollectionWindow{StartedAt: snapshot.Collections[0].StartedAt, EndedAt: ended}},
	}
	if err := result.Validate(); err != nil {
		t.Fatal(err)
	}
	return result
}

type persistedFinding struct {
	FindingID       model.FindingID
	RevisionID      model.FindingRevisionID
	IndicatorID     string
	PropositionKind string
	State           model.FindingState
	Provenance      model.ProvenanceLevel
	PropositionJSON string
	RuleVersion     string
}

func verifyPersistedFindingIdentities(t *testing.T, ctx context.Context, database *store.Store, pack *incident.ValidatedPack) {
	t.Helper()
	rows, err := database.DB().QueryContext(ctx, `
		SELECT f.finding_id,fr.finding_revision_id,f.indicator_id,f.proposition_kind,
		       fr.state,fr.provenance,fr.proposition_json,fr.rule_version
		FROM findings f JOIN finding_revisions fr ON fr.finding_id=f.finding_id
		ORDER BY fr.finding_revision_id`)
	if err != nil {
		t.Fatal(err)
	}
	var persisted []persistedFinding
	for rows.Next() {
		var finding persistedFinding
		if err := rows.Scan(&finding.FindingID, &finding.RevisionID, &finding.IndicatorID, &finding.PropositionKind,
			&finding.State, &finding.Provenance, &finding.PropositionJSON, &finding.RuleVersion); err != nil {
			_ = rows.Close()
			t.Fatal(err)
		}
		persisted = append(persisted, finding)
	}
	if err := rows.Close(); err != nil {
		t.Fatal(err)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(persisted) == 0 {
		t.Fatal("generated case database has no finding revisions")
	}
	indicatorKinds := make(map[string]string, len(pack.Pack.Spec.Indicators))
	for _, indicator := range pack.Pack.Spec.Indicators {
		indicatorKinds[indicator.ID] = indicator.Kind
	}
	for _, row := range persisted {
		indicatorKind, ok := indicatorKinds[row.IndicatorID]
		if !ok {
			t.Fatalf("persisted finding references unknown indicator %q", row.IndicatorID)
		}
		expectedProposition, err := analyze.PropositionForIndicatorKind(indicatorKind)
		if err != nil {
			t.Fatal(err)
		}
		var proposition model.Proposition
		if err := json.Unmarshal([]byte(row.PropositionJSON), &proposition); err != nil {
			t.Fatalf("decode persisted proposition: %v", err)
		}
		if row.PropositionKind != expectedProposition.Kind || proposition.Kind != expectedProposition.Kind ||
			len(proposition.Attributes) != 1 || proposition.Attributes[0] != expectedProposition.Attributes[0] {
			t.Fatalf("persisted proposition drift for %s: kind=%q proposition=%#v expected=%#v", row.RevisionID, row.PropositionKind, proposition, expectedProposition)
		}
		evidenceIDs := queryEvidenceIDs(t, ctx, database, row.RevisionID)
		coverageIDs := queryCoverageIDs(t, ctx, database, row.RevisionID)
		expectedRevision, err := evidence.NewFindingRevisionID(evidence.FindingRevisionInput{
			FindingID: row.FindingID, CanonicalPackSHA256: pack.CanonicalSHA256,
			State: row.State, Provenance: row.Provenance, EvidenceIDs: evidenceIDs,
			CoverageIDs: coverageIDs, RuleVersion: row.RuleVersion, Proposition: proposition,
		})
		if err != nil {
			t.Fatalf("reconstruct persisted revision %s: %v", row.RevisionID, err)
		}
		if expectedRevision != row.RevisionID {
			t.Fatalf("persisted revision %s does not match its proposition/evidence identity; reconstructed %s", row.RevisionID, expectedRevision)
		}
	}
}

func queryEvidenceIDs(t *testing.T, ctx context.Context, database *store.Store, revisionID model.FindingRevisionID) []model.EvidenceID {
	t.Helper()
	rows, err := database.DB().QueryContext(ctx, `SELECT evidence_id FROM finding_revision_evidence WHERE finding_revision_id=? AND role='SUPPORTS' ORDER BY evidence_id`, revisionID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	result := []model.EvidenceID{}
	for rows.Next() {
		var value model.EvidenceID
		if err := rows.Scan(&value); err != nil {
			t.Fatal(err)
		}
		result = append(result, value)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	return result
}

func queryCoverageIDs(t *testing.T, ctx context.Context, database *store.Store, revisionID model.FindingRevisionID) []model.CoverageAssessmentID {
	t.Helper()
	rows, err := database.DB().QueryContext(ctx, `SELECT coverage_id FROM finding_revision_coverage WHERE finding_revision_id=? ORDER BY coverage_id`, revisionID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	result := []model.CoverageAssessmentID{}
	for rows.Next() {
		var value model.CoverageAssessmentID
		if err := rows.Scan(&value); err != nil {
			t.Fatal(err)
		}
		result = append(result, value)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	return result
}

func fixture(t *testing.T, ctx context.Context) (archive.Snapshot, *incident.ValidatedPack, analyze.Result) {
	t.Helper()
	snapshot, err := demodata.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	packBytes, err := os.ReadFile(filepath.Join("..", "..", "incidents", "synthetic", "mutable-tag.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	pack, err := incident.Validate(ctx, packBytes)
	if err != nil {
		t.Fatal(err)
	}
	derived, err := analyze.Derive(snapshot, pack, time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC), "replay")
	if err != nil {
		t.Fatal(err)
	}
	return snapshot, pack, derived
}
