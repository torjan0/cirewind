package literalmatch

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/torjan0/cirewind/internal/archive"
	"github.com/torjan0/cirewind/internal/evidence"
	"github.com/torjan0/cirewind/internal/model"
)

type mapRawSource struct {
	values map[string][]byte
	errors map[string]error
	chunk  int
	cancel context.CancelFunc
}

func (s mapRawSource) CopyRaw(ctx context.Context, digest string, destination io.Writer) error {
	if err := s.errors[digest]; err != nil {
		return err
	}
	value, ok := s.values[digest]
	if !ok {
		return errors.New("raw object missing")
	}
	chunk := s.chunk
	if chunk <= 0 {
		chunk = len(value)
	}
	for offset := 0; offset < len(value); {
		end := offset + chunk
		if end > len(value) {
			end = len(value)
		}
		if _, err := destination.Write(value[offset:end]); err != nil {
			return err
		}
		offset = end
		if s.cancel != nil {
			s.cancel()
			s.cancel = nil
		}
		if err := ctx.Err(); err != nil {
			return err
		}
	}
	return nil
}

func TestScanPlainExactAcrossChunksMultipleAndAbsent(t *testing.T) {
	raw := append([]byte{0xff, 0x00, 0x1b}, []byte("prefix alpha-marker <script>alert(1)</script> suffix")...)
	snapshot, envelope := testSnapshot(t, evidence.SourceJobLog, raw, true, true, nil)
	queries := []Query{
		{IndicatorID: "absent", Literal: []byte("not-present"), Scope: ScopeAnyRetained},
		{IndicatorID: "marker", Literal: []byte("alpha-marker"), Scope: ScopeAnyRetained},
		{IndicatorID: "script", Literal: []byte("<script>"), Scope: ScopeAnyRetained},
	}
	got, err := Scan(context.Background(), snapshot, queries, mapRawSource{values: map[string][]byte{envelope.Evidence.Content.SourceSHA256: raw}, chunk: 10}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Observations) != 2 {
		t.Fatalf("observations = %d, want 2: %#v", len(got.Observations), got.Observations)
	}
	if got.Observations[0].IndicatorID != "marker" || got.Observations[0].FirstOffset != 10 {
		t.Fatalf("cross-chunk marker = %#v", got.Observations[0])
	}
	if got.Observations[1].IndicatorID != "script" {
		t.Fatalf("second observation = %#v", got.Observations[1])
	}
	assessment := assessmentFor(t, got, "absent")
	if assessment.Status != StatusAbsent || assessment.GapCode != "" || len(assessment.CoverageIDs) < 2 {
		t.Fatalf("complete absence = %#v", assessment)
	}
	for _, observation := range got.Observations {
		if strings.Contains(strings.Join(idsToStrings(observation.EvidenceIDs), " "), "alpha-marker") {
			t.Fatal("literal leaked into evidence identifiers")
		}
	}
}

func TestScanRawRetentionGaps(t *testing.T) {
	raw := []byte("harmless marker")
	queries := []Query{{IndicatorID: "marker", Literal: []byte("marker"), Scope: ScopeAnyRetained}}
	tests := []struct {
		name       string
		retained   bool
		sourceData []byte
		sourceErr  error
		want       GapCode
	}{
		{name: "discarded", retained: false, want: GapRawNotRetained},
		{name: "missing", retained: true, sourceErr: errors.New("raw object missing"), want: GapRawUnavailable},
		{name: "corrupt", retained: true, sourceData: []byte("different bytes"), want: GapIntegrityFailure},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			snapshot, envelope := testSnapshot(t, evidence.SourceJobLog, raw, test.retained, true, nil)
			source := mapRawSource{values: map[string][]byte{}, errors: map[string]error{}}
			if test.sourceData != nil {
				source.values[envelope.Evidence.Content.SourceSHA256] = test.sourceData
			}
			if test.sourceErr != nil {
				source.errors[envelope.Evidence.Content.SourceSHA256] = test.sourceErr
			}
			got, err := Scan(context.Background(), snapshot, queries, source, Options{})
			if err != nil {
				t.Fatal(err)
			}
			assessment := assessmentFor(t, got, "marker")
			if assessment.Status != StatusGap || assessment.GapCode != test.want {
				t.Fatalf("gap = %#v, want %s", assessment, test.want)
			}
			if len(got.Observations) != 0 {
				t.Fatalf("unavailable raw produced observations: %#v", got.Observations)
			}
		})
	}
}

func TestScanSizeCancellationAndDeterminism(t *testing.T) {
	raw := []byte("0123456789 marker")
	snapshot, envelope := testSnapshot(t, evidence.SourceJobLog, raw, true, true, nil)
	queries := []Query{{IndicatorID: "marker", Literal: []byte("marker"), Scope: ScopeAnyRetained}}
	limits := DefaultLimits()
	limits.MaxRawSourceBytes = 8
	limits.MaxTotalRawBytes = 8
	limited, err := Scan(context.Background(), snapshot, queries, mapRawSource{values: map[string][]byte{envelope.Evidence.Content.SourceSHA256: raw}}, Options{Limits: limits})
	if err != nil {
		t.Fatal(err)
	}
	if assessment := assessmentFor(t, limited, "marker"); assessment.Status != StatusGap || assessment.GapCode != GapSizeLimit {
		t.Fatalf("size assessment = %#v", assessment)
	}

	ctx, cancel := context.WithCancel(context.Background())
	_, err = Scan(ctx, snapshot, queries, mapRawSource{values: map[string][]byte{envelope.Evidence.Content.SourceSHA256: raw}, chunk: 4, cancel: cancel}, Options{})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel error = %v", err)
	}

	source := mapRawSource{values: map[string][]byte{envelope.Evidence.Content.SourceSHA256: raw}, chunk: 3}
	first, err := Scan(context.Background(), snapshot, queries, source, Options{})
	if err != nil {
		t.Fatal(err)
	}
	second, err := Scan(context.Background(), snapshot, queries, source, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("identical scan inputs were nondeterministic\nfirst=%#v\nsecond=%#v", first, second)
	}
}

func TestScanZIPRequiresExactDerivedEntryJoin(t *testing.T) {
	entry := []byte("prefix scoped-marker suffix")
	raw := testZIP(t, map[string][]byte{"job/2_Run owner/action@v1.txt": entry})
	childRule := "attempt-log-action-step-entry"
	snapshot, envelope := testSnapshot(t, evidence.SourceWorkflowRunAttemptLog, raw, true, true, &derivedFixture{rule: childRule, bytes: entry})
	query := []Query{{IndicatorID: "marker", Literal: []byte("scoped-marker"), Scope: ScopeStep}}
	got, err := Scan(context.Background(), snapshot, query, mapRawSource{values: map[string][]byte{envelope.Evidence.Content.SourceSHA256: raw}, chunk: 7}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Observations) != 1 {
		t.Fatalf("joined step observations = %#v", got.Observations)
	}
	if got.Observations[0].Subject.JobID == nil || len(got.Observations[0].EvidenceIDs) != 2 {
		t.Fatalf("joined step scope/evidence = %#v", got.Observations[0])
	}
	// The positive is real, but current compact metadata does not inventory all
	// possible shell-step entries, so it cannot support a negative closure.
	if assessment := assessmentFor(t, got, "marker"); assessment.Status != StatusGap || assessment.GapCode != GapUncorrelatedEntry {
		t.Fatalf("step coverage = %#v", assessment)
	}

	unjoined, envelope2 := testSnapshot(t, evidence.SourceWorkflowRunAttemptLog, raw, true, true, nil)
	got, err = Scan(context.Background(), unjoined, query, mapRawSource{values: map[string][]byte{envelope2.Evidence.Content.SourceSHA256: raw}}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Observations) != 0 {
		t.Fatalf("unjoined archive-controlled entry produced observation: %#v", got.Observations)
	}
	if assessment := assessmentFor(t, got, "marker"); assessment.Status != StatusGap || assessment.GapCode != GapUncorrelatedEntry {
		t.Fatalf("unjoined assessment = %#v", assessment)
	}
}

func TestScanMalformedArchivePreservesPositiveButNeverNegative(t *testing.T) {
	raw := testZIP(t, map[string][]byte{"safe.txt": []byte("marker"), "../unsafe.txt": []byte("ignored")})
	snapshot, envelope := testSnapshot(t, evidence.SourceWorkflowRunAttemptLog, raw, true, true, nil)
	query := []Query{{IndicatorID: "marker", Literal: []byte("marker"), Scope: ScopeAnyRetained}}
	got, err := Scan(context.Background(), snapshot, query, mapRawSource{values: map[string][]byte{envelope.Evidence.Content.SourceSHA256: raw}}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Observations) != 1 {
		t.Fatalf("safe entry positive = %#v", got.Observations)
	}
	if assessment := assessmentFor(t, got, "marker"); assessment.Status != StatusGap || assessment.GapCode != GapUnsafeArchive {
		t.Fatalf("malformed archive assessment = %#v", assessment)
	}
}

type derivedFixture struct {
	rule  string
	bytes []byte
}

func testSnapshot(t *testing.T, kind evidence.SourceKind, raw []byte, retained, closed bool, derived *derivedFixture) (archive.Snapshot, evidence.Envelope) {
	t.Helper()
	now := model.MustInstant(time.Date(2026, 8, 20, 1, 2, 3, 0, time.UTC))
	repositoryID, runID, attempt, jobID := model.RepositoryID(1), model.WorkflowRunID(10), model.RunAttempt(1), model.JobID(20)
	scope := model.CoverageScope{RepositoryID: &repositoryID, RunID: &runID, RunAttempt: &attempt}
	if kind == evidence.SourceJobLog {
		scope.JobID = &jobID
	}
	sessionID := model.CollectionSessionID("session:" + strings.Repeat("1", 64))
	envelope := testEnvelope(t, sessionID, kind, scope, raw, retained, now)
	evidenceValues := []evidence.Envelope{envelope}
	if derived != nil {
		childScope := scope
		childScope.JobID = &jobID
		evidenceValues = append(evidenceValues, testDerivedEnvelope(t, sessionID, envelope.Evidence.ID, childScope, derived.rule, derived.bytes, now))
	}
	coverageKind := model.CoverageAttemptLog
	if kind == evidence.SourceJobLog {
		coverageKind = model.CoverageJobLog
	}
	coverageFact := testCoverageFact(t, coverageKind, scope, envelope.Evidence.ID, closed)
	repositoryFact, err := archive.NormalizeFact(archive.Fact{Kind: archive.FactRepository, EvidenceIDs: []model.EvidenceID{envelope.Evidence.ID}, Repository: &archive.RepositoryFact{Repository: model.RepositorySubject{ID: repositoryID, Name: "acme/repo"}}})
	if err != nil {
		t.Fatal(err)
	}
	snapshot := archive.Snapshot{
		Metadata:    archive.SnapshotMetadata{SchemaVersion: archive.SnapshotSchemaVersion, StoreSchemaVersion: 1, ArchiveID: "arc1:" + strings.Repeat("2", 64), CreatedAt: now},
		Collections: []archive.CollectionSession{{ID: sessionID, Mode: "fixture", AuthKind: "none", RawRetention: retained, StartedAt: now, EndedAt: now, Scope: archive.CollectionScope{Repositories: []model.RepositoryID{repositoryID}}, Limits: map[string]uint64{}}},
		Payloads:    []archive.Payload{}, Evidence: evidenceValues, Facts: []archive.Fact{repositoryFact, coverageFact}, Capabilities: []archive.Capability{}, Checkpoints: []archive.Checkpoint{},
	}
	snapshot, err = archive.NormalizeSnapshot(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	return snapshot, envelope
}

func testEnvelope(t *testing.T, sessionID model.CollectionSessionID, kind evidence.SourceKind, scope model.CoverageScope, raw []byte, retained bool, now model.Instant) evidence.Envelope {
	t.Helper()
	digest := sha256Hex(raw)
	identity := evidence.LogicalSourceIdentity{Kind: kind, CanonicalID: "fixture:" + string(kind), Scope: scope, RequestParameters: evidence.RequestParameters{}}
	logicalID, err := evidence.NewLogicalSourceID(identity)
	if err != nil {
		t.Fatal(err)
	}
	var retainedSHA *string
	retainedPath := ""
	if retained {
		retainedSHA = &digest
		retainedPath, err = archive.RawRelativePath(digest)
		if err != nil {
			t.Fatal(err)
		}
	}
	retention := evidence.RetentionDescriptor{MediaType: mediaType(kind), ByteLength: uint64(len(raw)), RawRetained: retained, RetainedPayloadSHA256: retainedSHA, RedactionStatus: evidence.RedactionNotInspected, RedactionPolicyVersion: "fixture-raw-v1"}
	evidenceID, err := evidence.NewEvidenceID(logicalID, digest, retention)
	if err != nil {
		t.Fatal(err)
	}
	requestID := model.RequestID("request:" + strings.Repeat("3", 64))
	observationID, err := evidence.NewCollectionObservationID(evidenceID, sessionID, requestID, now, 1)
	if err != nil {
		t.Fatal(err)
	}
	envelope := evidence.Envelope{Evidence: evidence.EvidenceObject{
		SchemaVersion: evidence.EvidenceSchemaVersion, ID: evidenceID,
		LogicalSource: evidence.LogicalSource{ID: logicalID, Kind: kind, CanonicalID: identity.CanonicalID, RequestParameters: evidence.RequestParameters{}},
		Source:        evidence.SourceDescriptor{Provider: evidence.ProviderGitHub, RequestParameters: evidence.RequestParameters{}, RequestAttempt: 1}, Scope: scope,
		EventTime: instantEvent(now), Content: evidence.ContentDescriptor{MediaType: mediaType(kind), ByteLength: uint64(len(raw)), Complete: true, SourceSHA256: digest, RetainedPayloadSHA256: retainedSHA, RawRetained: retained, RetainedPath: retainedPath},
		Extractor: evidence.ExtractorDescriptor{Name: "fixture", Version: "1.0.0", RulesetSHA256: strings.Repeat("4", 64)},
		Redaction: evidence.RedactionDescriptor{Status: evidence.RedactionNotInspected, PolicyVersion: "fixture-raw-v1"}, Derivation: evidence.DerivationDescriptor{ParentEvidenceIDs: []model.EvidenceID{}}, Errors: []evidence.EvidenceError{},
	}, Observation: evidence.CollectionObservation{ID: observationID, EvidenceID: evidenceID, CollectionSessionID: sessionID, RequestID: requestID, RequestAttempt: 1, CollectionTime: model.CollectionWindow{StartedAt: now, EndedAt: now}}}
	if err := envelope.Validate(); err != nil {
		t.Fatal(err)
	}
	return envelope
}

func testDerivedEnvelope(t *testing.T, sessionID model.CollectionSessionID, parent model.EvidenceID, scope model.CoverageScope, rule string, value []byte, now model.Instant) evidence.Envelope {
	t.Helper()
	digest := sha256Hex(value)
	derivation := evidence.DerivationDescriptor{Kind: "archive_entry_extraction", ParentEvidenceIDs: []model.EvidenceID{parent}, RuleID: rule, RuleVersion: "fixture-v1"}
	logical, err := evidence.NewDerivedLogicalSource(scope, derivation, digest)
	if err != nil {
		t.Fatal(err)
	}
	retention := evidence.RetentionDescriptor{MediaType: "text/plain", ByteLength: uint64(len(value)), RawRetained: false, RedactionStatus: evidence.RedactionNotInspected, RedactionPolicyVersion: "fixture-structured-v1"}
	id, err := evidence.NewEvidenceID(logical.ID, digest, retention)
	if err != nil {
		t.Fatal(err)
	}
	requestID := model.RequestID("request:" + strings.Repeat("5", 64))
	observationID, err := evidence.NewCollectionObservationID(id, sessionID, requestID, now, 1)
	if err != nil {
		t.Fatal(err)
	}
	envelope := evidence.Envelope{Evidence: evidence.EvidenceObject{SchemaVersion: evidence.EvidenceSchemaVersion, ID: id, LogicalSource: logical,
		Source: evidence.SourceDescriptor{Provider: evidence.ProviderCIRewind, RequestParameters: evidence.RequestParameters{}, RequestAttempt: 1}, Scope: scope, EventTime: instantEvent(now),
		Content:   evidence.ContentDescriptor{MediaType: "text/plain", ByteLength: uint64(len(value)), Complete: true, SourceSHA256: digest},
		Extractor: evidence.ExtractorDescriptor{Name: "fixture", Version: "1.0.0", RulesetSHA256: strings.Repeat("6", 64)}, Redaction: evidence.RedactionDescriptor{Status: evidence.RedactionNotInspected, PolicyVersion: "fixture-structured-v1"}, Derivation: derivation, Errors: []evidence.EvidenceError{},
	}, Observation: evidence.CollectionObservation{ID: observationID, EvidenceID: id, CollectionSessionID: sessionID, RequestID: requestID, RequestAttempt: 1, CollectionTime: model.CollectionWindow{StartedAt: now, EndedAt: now}}}
	if err := envelope.Validate(); err != nil {
		t.Fatal(err)
	}
	return envelope
}

func testCoverageFact(t *testing.T, kind model.CoverageKind, scope model.CoverageScope, evidenceID model.EvidenceID, closed bool) archive.Fact {
	t.Helper()
	unit := model.CoverageUnit{ID: model.CoverageUnitID("cov1:" + strings.Repeat("0", 64)), Kind: kind, Scope: scope, LogicalKey: "fixture-log", RequiredForNegative: true}
	var err error
	unit.ID, err = evidence.NewCoverageUnitID(unit)
	if err != nil {
		t.Fatal(err)
	}
	assessment := model.CoverageAssessment{ID: model.CoverageAssessmentID("cova1:" + strings.Repeat("0", 64)), UnitID: unit.ID, Status: model.CoverageCollected, ObservedCount: 1, EvidenceIDs: []model.EvidenceID{evidenceID}}
	if !closed {
		assessment.Status, assessment.ObservedCount = model.CoverageGap, 0
		assessment.Gap = &model.CoverageGapDetail{Reason: model.GapRetentionOrDeletion, Material: true, SanitizedMessage: "fixture gap"}
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

func testZIP(t *testing.T, entries map[string][]byte) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	names := make([]string, 0, len(entries))
	for name := range entries {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		entry, err := writer.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := entry.Write(entries[name]); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func assessmentFor(t *testing.T, result Result, indicator string) Assessment {
	t.Helper()
	var matches []Assessment
	for _, assessment := range result.Assessments {
		if assessment.IndicatorID == indicator {
			matches = append(matches, assessment)
		}
	}
	if len(matches) != 1 {
		t.Fatalf("assessments for %s = %#v", indicator, matches)
	}
	return matches[0]
}

func mediaType(kind evidence.SourceKind) string {
	if kind == evidence.SourceWorkflowRunAttemptLog {
		return "application/zip"
	}
	return "text/plain"
}

func instantEvent(value model.Instant) model.EventInterval {
	bounds := model.BoundsClosed
	return model.EventInterval{Start: &value, End: &value, Bounds: &bounds, Precision: model.PrecisionSecond, Approximation: model.ApproximationExact, Basis: model.TimeBasisLogTimestamp}
}

func sha256Hex(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}
