package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/torjan0/cirewind/internal/archive"
	"github.com/torjan0/cirewind/internal/casefile"
	"github.com/torjan0/cirewind/internal/evidence"
	"github.com/torjan0/cirewind/internal/model"
	"github.com/torjan0/cirewind/internal/report"
	"github.com/torjan0/cirewind/internal/store"
)

const replayLiteralMarker = "synthetic retained literal marker"

func TestReplaySearchesRetainedLiteralBeforeOptionalRawMaterialization(t *testing.T) {
	ctx := context.Background()
	archivePath, digest := createLiteralReplayArchive(t, []byte("prefix "+replayLiteralMarker+" suffix"), true)
	packPath := writeLiteralReplayPack(t, replayLiteralMarker)
	fixed := "2026-08-20T12:00:00Z"

	compactOutput := filepath.Join(t.TempDir(), "compact-case")
	var compactStdout, compactStderr bytes.Buffer
	if err := runReplay(ctx, []string{
		"--archive", archivePath, "--incident", packPath, "--out", compactOutput,
		"--fixed-collection-time", fixed,
	}, &compactStdout, &compactStderr); err != nil {
		t.Fatal(err)
	}
	if err := casefile.VerifyManifest(ctx, compactOutput); err != nil {
		t.Fatalf("verify compact replay: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(compactOutput, "raw")); !os.IsNotExist(err) {
		t.Fatalf("default replay materialized raw bytes: %v", err)
	}
	positive := readLiteralReplayFinding(t, compactOutput)
	if positive.State != string(model.UnknownEvidenceGap) || len(positive.EvidenceIDs) == 0 || len(positive.CollectionCoverage) == 0 {
		t.Fatalf("unresolved retained-literal finding = %#v", positive)
	}
	if !strings.Contains(positive.Conclusion, "contained the incident literal") || !strings.Contains(positive.Conclusion, "does not prove") {
		t.Fatalf("unresolved literal conclusion = %q", positive.Conclusion)
	}
	findingsBytes, err := os.ReadFile(filepath.Join(compactOutput, "findings.json"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(findingsBytes, []byte(replayLiteralMarker)) {
		t.Fatal("literal bytes leaked into compact findings")
	}
	database, err := store.OpenReadOnly(ctx, filepath.Join(compactOutput, "case.db"))
	if err != nil {
		t.Fatal(err)
	}
	var coverageStatus string
	var linked int
	queryErr := database.DB().QueryRowContext(ctx, `
		SELECT cu.status,COUNT(*)
		FROM coverage_units cu
		JOIN finding_revision_coverage frc ON frc.coverage_id=cu.coverage_id
		WHERE cu.kind=? AND frc.finding_revision_id=?
		GROUP BY cu.status`, model.CoverageSearchableLiteral, positive.FindingRevisionID).Scan(&coverageStatus, &linked)
	closeErr := database.Close()
	if queryErr != nil || closeErr != nil {
		t.Fatalf("query persisted literal coverage: query=%v close=%v", queryErr, closeErr)
	}
	if coverageStatus != "collected" || linked != 1 {
		t.Fatalf("persisted literal coverage status=%q linked=%d", coverageStatus, linked)
	}

	rawOutput := filepath.Join(t.TempDir(), "raw-case")
	var rawStdout, rawStderr bytes.Buffer
	if err := runReplay(ctx, []string{
		"--archive", archivePath, "--incident", packPath, "--out", rawOutput,
		"--fixed-collection-time", fixed, "--raw-logs",
	}, &rawStdout, &rawStderr); err != nil {
		t.Fatal(err)
	}
	if err := casefile.VerifyManifest(ctx, rawOutput); err != nil {
		t.Fatalf("verify raw replay: %v", err)
	}
	retained, err := os.ReadFile(filepath.Join(rawOutput, "raw", digest+".bin"))
	if err != nil || !bytes.Equal(retained, []byte("prefix "+replayLiteralMarker+" suffix")) {
		t.Fatalf("raw materialization bytes=%q err=%v", retained, err)
	}
	manifest, err := os.ReadFile(filepath.Join(rawOutput, "manifest.sha256"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(manifest), "raw/"+digest+".bin") != 1 {
		t.Fatalf("raw object is not manifested exactly once: %q", manifest)
	}
	if !strings.Contains(rawStderr.String(), "sensitive application output") {
		t.Fatalf("raw replay warning = %q", rawStderr.String())
	}
	if readLiteralReplayFinding(t, rawOutput).State != positive.State {
		t.Fatal("case materialization choice changed literal evidence semantics")
	}
}

func TestReplayMissingRawSidecarIsFindingGapNotGlobalFailure(t *testing.T) {
	ctx := context.Background()
	archivePath, digest := createLiteralReplayArchive(t, []byte("complete log without the requested value"), true)
	if err := os.Remove(filepath.Join(archivePath+".raw", digest+".bin")); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "missing-sidecar-case")
	if err := runReplay(ctx, []string{
		"--archive", archivePath,
		"--incident", writeLiteralReplayPack(t, "newly published absent literal"),
		"--out", output,
		"--fixed-collection-time", "2026-08-20T12:00:00Z",
	}, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatalf("missing optional sidecar aborted compact replay: %v", err)
	}
	if err := casefile.VerifyManifest(ctx, output); err != nil {
		t.Fatal(err)
	}
	finding := readLiteralReplayFinding(t, output)
	if finding.State != string(model.UnknownEvidenceGap) || len(finding.EvidenceIDs) == 0 || len(finding.EvidenceGaps) == 0 {
		t.Fatalf("missing-sidecar finding = %#v", finding)
	}
	if finding.State == string(model.NoMatchConfirmed) {
		t.Fatal("missing raw bytes produced a clean negative")
	}
}

func TestReplayLiteralNoMatchRequiresClosedLogCoverage(t *testing.T) {
	ctx := context.Background()
	packPath := writeLiteralReplayPack(t, "definitely absent literal")
	for _, test := range []struct {
		name   string
		closed bool
		want   model.FindingState
	}{
		{name: "closed", closed: true, want: model.NoMatchConfirmed},
		{name: "coverage-gap", closed: false, want: model.UnknownEvidenceGap},
	} {
		t.Run(test.name, func(t *testing.T) {
			archivePath, _ := createLiteralReplayArchive(t, []byte("complete harmless log"), test.closed)
			output := filepath.Join(t.TempDir(), "case")
			if err := runReplay(ctx, []string{
				"--archive", archivePath, "--incident", packPath, "--out", output,
				"--fixed-collection-time", "2026-08-20T12:00:00Z",
			}, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
				t.Fatal(err)
			}
			finding := readLiteralReplayFinding(t, output)
			if model.FindingState(finding.State) != test.want {
				t.Fatalf("state=%s want=%s finding=%#v", finding.State, test.want, finding)
			}
			if test.want == model.NoMatchConfirmed && (len(finding.EvidenceIDs) == 0 || len(finding.CollectionCoverage) < 2) {
				t.Fatalf("negative lacks source and literal-search closure: %#v", finding)
			}
		})
	}
}

func createLiteralReplayArchive(t *testing.T, raw []byte, closed bool) (string, string) {
	t.Helper()
	ctx := context.Background()
	root := t.TempDir()
	archivePath := filepath.Join(root, "archive.db")
	sum := sha256.Sum256(raw)
	digest := hex.EncodeToString(sum[:])
	sourcePath := filepath.Join(root, "source.log")
	if err := os.WriteFile(sourcePath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	when := model.MustInstant(time.Date(2026, 8, 19, 10, 30, 0, 0, time.UTC))
	repositoryID := model.RepositoryID(101)
	scope := model.CoverageScope{RepositoryID: &repositoryID}
	session := archive.CollectionSession{
		ID: "collection:cli-literal-replay", Mode: "archive", AuthKind: "none", RawRetention: true,
		StartedAt: when, EndedAt: when,
		Scope:  archive.CollectionScope{Repositories: []model.RepositoryID{repositoryID}},
		Limits: map[string]uint64{"raw_log_bytes": uint64(len(raw))},
	}
	envelope := literalReplayEnvelope(t, session, scope, raw, digest)
	repository, _ := model.NewRepositorySlug("cirewind-demo/consumer")
	repositoryFact, err := archive.NormalizeFact(archive.Fact{
		Kind: archive.FactRepository, EvidenceIDs: []model.EvidenceID{envelope.Evidence.ID},
		Repository: &archive.RepositoryFact{Repository: model.RepositorySubject{ID: repositoryID, Name: repository}, Visibility: "public", DefaultBranch: "main"},
	})
	if err != nil {
		t.Fatal(err)
	}
	coverageFact := literalReplayCoverage(t, scope, envelope.Evidence.ID, closed)
	batch := archive.Batch{
		Collections: []archive.CollectionSession{session}, Payloads: []archive.Payload{}, Evidence: []evidence.Envelope{envelope},
		Facts: []archive.Fact{repositoryFact, coverageFact},
		Capabilities: []archive.Capability{
			{Name: "job_logs", Status: archive.CapabilityRetained, ExtractorVersion: "fixture-v1", Details: map[string]string{"collected_count": "1", "gap_count": map[bool]string{true: "0", false: "1"}[closed]}},
			{Name: "raw_logs", Status: archive.CapabilityRetained, ExtractorVersion: "fixture-v1", Details: map[string]string{"retained_count": "1"}},
		},
		Checkpoints: []archive.Checkpoint{},
	}
	store, err := archive.Create(ctx, archivePath, archive.Options{CreatedAt: when})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.RetainRaw(ctx, archive.RawInput{SHA256: digest, MediaType: "text/plain", ByteLength: uint64(len(raw)), SourcePath: sourcePath}); err != nil {
		_ = store.Close()
		t.Fatal(err)
	}
	if err := store.Append(ctx, batch); err != nil {
		_ = store.Close()
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	return archivePath, digest
}

func literalReplayEnvelope(t *testing.T, session archive.CollectionSession, scope model.CoverageScope, raw []byte, digest string) evidence.Envelope {
	t.Helper()
	identity := evidence.LogicalSourceIdentity{
		Kind: evidence.SourceJobLog, CanonicalID: "github:job-log:synthetic-literal-replay",
		Scope: scope, RequestParameters: evidence.RequestParameters{"fixture": "literal-replay"},
	}
	logicalID, err := evidence.NewLogicalSourceID(identity)
	if err != nil {
		t.Fatal(err)
	}
	retainedPath, err := archive.RawRelativePath(digest)
	if err != nil {
		t.Fatal(err)
	}
	retention := evidence.RetentionDescriptor{
		MediaType: "text/plain", ByteLength: uint64(len(raw)), RawRetained: true, RetainedPayloadSHA256: &digest,
		RedactionStatus: evidence.RedactionNotInspected, RedactionPolicyVersion: "raw-exact-opt-in-v1",
	}
	evidenceID, err := evidence.NewEvidenceID(logicalID, digest, retention)
	if err != nil {
		t.Fatal(err)
	}
	requestID := model.RequestID("request:" + strings.Repeat("c", 64))
	observationID, err := evidence.NewCollectionObservationID(evidenceID, session.ID, requestID, session.EndedAt, 1)
	if err != nil {
		t.Fatal(err)
	}
	event := literalReplayEvent(session.StartedAt)
	result := evidence.Envelope{
		Evidence: evidence.EvidenceObject{
			SchemaVersion: evidence.EvidenceSchemaVersion, ID: evidenceID,
			LogicalSource: evidence.LogicalSource{ID: logicalID, Kind: identity.Kind, CanonicalID: identity.CanonicalID, RequestParameters: identity.RequestParameters},
			Source:        evidence.SourceDescriptor{Provider: evidence.ProviderGitHub, APIVersion: "2026-03-10", EndpointTemplate: "/repos/{owner}/{repo}/actions/jobs/{job_id}/logs", RequestParameters: identity.RequestParameters, RequestAttempt: 1},
			Scope:         scope, EventTime: event,
			Content:    evidence.ContentDescriptor{MediaType: "text/plain", ByteLength: uint64(len(raw)), Complete: true, SourceSHA256: digest, RetainedPayloadSHA256: &digest, RawRetained: true, RetainedPath: retainedPath},
			Extractor:  evidence.ExtractorDescriptor{Name: "fixture", Version: "1.0.0", RulesetSHA256: strings.Repeat("d", 64)},
			Redaction:  evidence.RedactionDescriptor{Status: evidence.RedactionNotInspected, PolicyVersion: "raw-exact-opt-in-v1"},
			Derivation: evidence.DerivationDescriptor{ParentEvidenceIDs: []model.EvidenceID{}}, Errors: []evidence.EvidenceError{},
		},
		Observation: evidence.CollectionObservation{
			ID: observationID, EvidenceID: evidenceID, CollectionSessionID: session.ID, RequestID: requestID, RequestAttempt: 1,
			CollectionTime: model.CollectionWindow{StartedAt: session.StartedAt, EndedAt: session.EndedAt},
		},
	}
	if err := result.Validate(); err != nil {
		t.Fatal(err)
	}
	return result
}

func literalReplayCoverage(t *testing.T, scope model.CoverageScope, evidenceID model.EvidenceID, closed bool) archive.Fact {
	t.Helper()
	unit := model.CoverageUnit{Kind: model.CoverageJobLog, Scope: scope, LogicalKey: "job-log:synthetic-literal-replay", RequiredForNegative: true}
	var err error
	unit.ID, err = evidence.NewCoverageUnitID(unit)
	if err != nil {
		t.Fatal(err)
	}
	one := uint64(1)
	assessment := model.CoverageAssessment{
		UnitID: unit.ID, Status: model.CoverageCollected, ExpectedCount: &one, ObservedCount: 1,
		EvidenceIDs: []model.EvidenceID{evidenceID},
	}
	if !closed {
		assessment.Status, assessment.ObservedCount = model.CoverageGap, 0
		assessment.Gap = &model.CoverageGapDetail{Reason: model.GapEvidenceTruncated, Material: true, SanitizedMessage: "synthetic log coverage is incomplete"}
	}
	assessment.ID, err = evidence.NewCoverageAssessmentID(assessment)
	if err != nil {
		t.Fatal(err)
	}
	input := archive.Fact{Kind: archive.FactCoverage, EvidenceIDs: []model.EvidenceID{evidenceID}, Coverage: &archive.CoverageFact{Unit: unit, Assessment: assessment}}
	if !closed {
		input.Kind, input.Coverage, input.CoverageGap = archive.FactCoverageGap, nil, &archive.CoverageGapFact{Unit: unit, Assessment: assessment}
	}
	fact, err := archive.NormalizeFact(input)
	if err != nil {
		t.Fatal(err)
	}
	return fact
}

func writeLiteralReplayPack(t *testing.T, literal string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "literal-incident.yaml")
	value := fmt.Sprintf(`apiVersion: cirewind.dev/v1alpha1
kind: GitHubActionsIncident
metadata:
  id: CIR-SYNTHETIC-LITERAL
  packVersion: 1.0.0
  title: Synthetic retained literal fixture
  publishedAt: "2026-08-20T00:00:00Z"
  updatedAt: "2026-08-20T00:00:00Z"
  sources:
    - id: synthetic-source
      type: synthetic-fixture
      title: Synthetic retained log bytes
      publisher: CIRewind test maintainers
      url: https://example.invalid/cirewind/literal
      retrievedAt: "2026-08-20T00:00:00Z"
spec:
  description: Synthetic literal replay fixture with no real incident claims.
  components:
    - id: harmless-action
      type: github-action
      repository:
        owner: cirewind-fixtures
        name: harmless-action
  indicators:
    - id: synthetic-log-literal
      componentId: harmless-action
      kind: log-literal
      value:
        literal: %q
        caseSensitive: true
        scope: any-retained-log
      confidence: L4_CERTAIN
      sourceRefs:
        - synthetic-source
`, literal)
	if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func readLiteralReplayFinding(t *testing.T, output string) report.Finding {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(output, "findings.json"))
	if err != nil {
		t.Fatal(err)
	}
	var envelope struct {
		Findings []report.Finding `json:"findings"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		t.Fatal(err)
	}
	var matches []report.Finding
	for _, finding := range envelope.Findings {
		if finding.IndicatorID == "synthetic-log-literal" {
			matches = append(matches, finding)
		}
	}
	if len(matches) != 1 {
		t.Fatalf("literal findings = %#v", matches)
	}
	return matches[0]
}

func literalReplayEvent(when model.Instant) model.EventInterval {
	bounds := model.BoundsClosed
	return model.EventInterval{Start: &when, End: &when, Bounds: &bounds, Precision: model.PrecisionSecond, Approximation: model.ApproximationExact, Basis: model.TimeBasisLogTimestamp}
}
