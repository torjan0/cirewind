package analyze

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/torjan0/cirewind/internal/archive"
	"github.com/torjan0/cirewind/internal/evidence"
	"github.com/torjan0/cirewind/internal/incident"
	"github.com/torjan0/cirewind/internal/literalmatch"
	"github.com/torjan0/cirewind/internal/match"
	"github.com/torjan0/cirewind/internal/model"
	"github.com/torjan0/cirewind/internal/report"
)

type literalRawSource map[string][]byte

func (s literalRawSource) CopyRaw(ctx context.Context, digest string, destination io.Writer) error {
	value, ok := s[digest]
	if !ok {
		return errors.New("raw source unavailable")
	}
	for offset := 0; offset < len(value); {
		if err := ctx.Err(); err != nil {
			return err
		}
		end := offset + 3
		if end > len(value) {
			end = len(value)
		}
		if _, err := destination.Write(value[offset:end]); err != nil {
			return err
		}
		offset = end
	}
	return nil
}

func TestDeriveWithRawLiteralPositiveIsAttributedConservativelyAndNotRendered(t *testing.T) {
	raw := []byte("prefix secret-looking-marker suffix")
	snapshot, envelope := literalSnapshot(t, raw, true, true, false)
	pack := literalPack(t, "secret-looking-marker")
	result, err := DeriveWithRaw(context.Background(), snapshot, pack, time.Date(2026, 8, 20, 3, 0, 0, 0, time.UTC), ModeReplay,
		literalRawSource{envelope.Evidence.Content.SourceSHA256: raw}, literalmatch.Options{})
	if err != nil {
		t.Fatal(err)
	}
	finding := literalFinding(t, result.Analysis, "synthetic-log-literal")
	if finding.State != string(model.UnknownEvidenceGap) || !strings.Contains(finding.Conclusion, "literal") || !strings.Contains(finding.Conclusion, "does not prove") {
		t.Fatalf("unattributed positive = %#v", finding)
	}
	if len(finding.EvidenceIDs) == 0 || len(finding.CollectionCoverage) == 0 {
		t.Fatalf("positive lost evidence scope: %#v", finding)
	}
	assertFindingRevisionRule(t, finding, pack, "log-literal", match.RuleVersion+"+"+literalmatch.RuleVersion)
	encoded, err := json.Marshal(result.Analysis.Case)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "secret-looking-marker") {
		t.Fatal("raw literal bytes leaked into report case")
	}
}

func TestDeriveWithRawLiteralAbsentRequiresCompleteRetainedCoverage(t *testing.T) {
	pack := literalPack(t, "not-present")
	raw := []byte("complete harmless log")
	tests := []struct {
		name     string
		retained bool
		closed   bool
		provide  bool
		want     model.FindingState
	}{
		{name: "complete", retained: true, closed: true, provide: true, want: model.NoMatchConfirmed},
		{name: "discarded", retained: false, closed: true, provide: false, want: model.UnknownEvidenceGap},
		{name: "coverage gap", retained: true, closed: false, provide: true, want: model.UnknownEvidenceGap},
		{name: "missing sidecar", retained: true, closed: true, provide: false, want: model.UnknownEvidenceGap},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			snapshot, envelope := literalSnapshot(t, raw, test.retained, test.closed, false)
			source := literalRawSource{}
			if test.provide {
				source[envelope.Evidence.Content.SourceSHA256] = raw
			}
			result, err := DeriveWithRaw(context.Background(), snapshot, pack, time.Date(2026, 8, 20, 3, 0, 0, 0, time.UTC), ModeReplay, source, literalmatch.Options{})
			if err != nil {
				t.Fatal(err)
			}
			finding := literalFinding(t, result.Analysis, "synthetic-log-literal")
			if model.FindingState(finding.State) != test.want {
				t.Fatalf("state = %s, want %s: %#v", finding.State, test.want, finding)
			}
			if test.want == model.NoMatchConfirmed && len(result.Literal.CoverageFacts) == 0 {
				t.Fatal("negative lacks typed searchable-literal coverage")
			}
		})
	}
}

func TestDeriveWithRawCorroboratesExactFindingWithoutInflatingCounts(t *testing.T) {
	raw := []byte("secret-looking-marker")
	snapshot, envelope := literalSnapshot(t, raw, true, true, true)
	pack := literalPack(t, "secret-looking-marker")
	result, err := DeriveWithRaw(context.Background(), snapshot, pack, time.Date(2026, 8, 20, 3, 0, 0, 0, time.UTC), ModeReplay,
		literalRawSource{envelope.Evidence.Content.SourceSHA256: raw}, literalmatch.Options{})
	if err != nil {
		t.Fatal(err)
	}
	var downloaded, literalFindings int
	for _, finding := range result.Analysis.Case.Findings {
		if finding.State == string(model.ConfirmedDownloaded) {
			downloaded++
			if !strings.Contains(strings.Join(finding.Assumptions, " "), "synthetic-log-literal") {
				t.Fatalf("exact finding lacks scoped corroboration: %#v", finding)
			}
			assertFindingRevisionRule(t, finding, pack, "action-commit", match.RuleVersion+"+"+literalmatch.RuleVersion)
		}
		if finding.IndicatorID == "synthetic-log-literal" {
			literalFindings++
		}
	}
	if downloaded != 1 || literalFindings != 0 {
		t.Fatalf("downloaded=%d literalFindings=%d findings=%#v", downloaded, literalFindings, result.Analysis.Case.Findings)
	}
}

func assertFindingRevisionRule(t *testing.T, finding report.Finding, pack *incident.ValidatedPack, indicatorKind, wantRule string) {
	t.Helper()
	if finding.DerivationRuleVersion != wantRule {
		t.Fatalf("derivation rule version = %q, want %q", finding.DerivationRuleVersion, wantRule)
	}
	proposition, err := PropositionForIndicatorKind(indicatorKind)
	if err != nil {
		t.Fatal(err)
	}
	evidenceIDs := make([]model.EvidenceID, len(finding.EvidenceIDs))
	for index, id := range finding.EvidenceIDs {
		evidenceIDs[index] = model.EvidenceID(id)
	}
	coverageIDs := make([]model.CoverageAssessmentID, len(finding.CollectionCoverage))
	for index, id := range finding.CollectionCoverage {
		coverageIDs[index] = model.CoverageAssessmentID(id)
	}
	want, err := evidence.NewFindingRevisionID(evidence.FindingRevisionInput{
		FindingID: model.FindingID(finding.FindingID), CanonicalPackSHA256: pack.CanonicalSHA256,
		State: model.FindingState(finding.State), Provenance: model.ProvenanceLevel(finding.Provenance),
		EvidenceIDs: evidenceIDs, CoverageIDs: coverageIDs, RuleVersion: wantRule, Proposition: proposition,
	})
	if err != nil {
		t.Fatal(err)
	}
	if string(want) != finding.FindingRevisionID {
		t.Fatalf("revision ID = %s, reconstructed %s", finding.FindingRevisionID, want)
	}
}

func literalPack(t *testing.T, literal string) *incident.ValidatedPack {
	t.Helper()
	base := loadPack(t)
	copyPack := *base
	copyPack.Pack.Spec.Indicators = append([]incident.Indicator(nil), base.Pack.Spec.Indicators...)
	truth := true
	copyPack.Pack.Spec.Indicators = append(copyPack.Pack.Spec.Indicators, incident.Indicator{
		ID: "synthetic-log-literal", ComponentID: "harmless-action", Kind: "log-literal",
		Value:      incident.IndicatorValue{Literal: literal, CaseSensitive: &truth, Scope: "any-retained-log"},
		Confidence: model.L4Certain, SourceRefs: []string{"synthetic-lab-protocol"},
	})
	return &copyPack
}

func literalSnapshot(t *testing.T, raw []byte, retained, closed, exact bool) (archive.Snapshot, evidence.Envelope) {
	t.Helper()
	now := model.MustInstant(time.Date(2026, 8, 19, 10, 30, 0, 0, time.UTC))
	repositoryID, runID, attempt, jobID := model.RepositoryID(1), model.WorkflowRunID(10), model.RunAttempt(1), model.JobID(20)
	scope := model.CoverageScope{RepositoryID: &repositoryID, RunID: &runID, RunAttempt: &attempt, JobID: &jobID}
	sessionID := model.CollectionSessionID("session:" + strings.Repeat("7", 64))
	envelope := literalEnvelope(t, sessionID, scope, raw, retained, now)
	repository, _ := model.NewRepositorySlug("acme/service")
	repositoryFact, err := archive.NormalizeFact(archive.Fact{Kind: archive.FactRepository, EvidenceIDs: []model.EvidenceID{envelope.Evidence.ID}, Repository: &archive.RepositoryFact{Repository: model.RepositorySubject{ID: repositoryID, Name: repository}}})
	if err != nil {
		t.Fatal(err)
	}
	runFact, err := archive.NormalizeFact(archive.Fact{Kind: archive.FactRun, EvidenceIDs: []model.EvidenceID{envelope.Evidence.ID}, Run: &archive.RunFact{RepositoryID: repositoryID, RunID: runID, EventType: "push", EventTime: instantEventAt(now.Time)}})
	if err != nil {
		t.Fatal(err)
	}
	coverageFact := literalCoverage(t, scope, envelope.Evidence.ID, closed)
	facts := []archive.Fact{repositoryFact, runFact, coverageFact}
	if exact {
		actionRepository, _ := model.NewRepositorySlug("cirewind-fixtures/harmless-action")
		object, _ := model.NewGitObjectID(model.HashSHA1, strings.Repeat("1", 40))
		actionObject, _ := model.NewActionSourceObjectID(object)
		execution := model.JobExecutionIdentity{RepositoryID: repositoryID, RunID: runID, RunAttempt: attempt, JobID: jobID}
		observation := model.RuntimeActionObservation{Kind: model.ObservationPreparationComplete, Execution: execution, ActionRepository: actionRepository, DeclaredRef: "v1", SourceObjectID: &actionObject, SourceEvidenceIDs: []model.EvidenceID{envelope.Evidence.ID}, EventTime: instantEventAt(now.Time), ExtractorName: "fixture", ExtractorVersion: "1.0.0", RulesetSHA256: strings.Repeat("b", 64)}
		observation.ID, err = evidence.NewRuntimeObservationID(observation)
		if err != nil {
			t.Fatal(err)
		}
		fact, normalizeErr := archive.NormalizeFact(archive.Fact{Kind: archive.FactActionOccurrence, EvidenceIDs: []model.EvidenceID{envelope.Evidence.ID}, ActionOccurrence: &archive.ActionOccurrenceFact{Observation: observation}})
		if normalizeErr != nil {
			t.Fatal(normalizeErr)
		}
		facts = append(facts, fact)
	}
	snapshot := archive.Snapshot{
		Metadata:    archive.SnapshotMetadata{SchemaVersion: archive.SnapshotSchemaVersion, StoreSchemaVersion: 1, ArchiveID: "arc1:" + strings.Repeat("8", 64), CreatedAt: now},
		Collections: []archive.CollectionSession{{ID: sessionID, Mode: "fixture", AuthKind: "none", RawRetention: retained, StartedAt: now, EndedAt: now, Scope: archive.CollectionScope{Repositories: []model.RepositoryID{repositoryID}}, Limits: map[string]uint64{}}},
		Payloads:    []archive.Payload{}, Evidence: []evidence.Envelope{envelope}, Facts: facts, Capabilities: []archive.Capability{}, Checkpoints: []archive.Checkpoint{},
	}
	snapshot, err = archive.NormalizeSnapshot(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	return snapshot, envelope
}

func literalEnvelope(t *testing.T, sessionID model.CollectionSessionID, scope model.CoverageScope, raw []byte, retained bool, now model.Instant) evidence.Envelope {
	t.Helper()
	sum := sha256.Sum256(raw)
	digest := hex.EncodeToString(sum[:])
	identity := evidence.LogicalSourceIdentity{Kind: evidence.SourceJobLog, CanonicalID: "fixture:job-log", Scope: scope, RequestParameters: evidence.RequestParameters{}}
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
	retention := evidence.RetentionDescriptor{MediaType: "text/plain", ByteLength: uint64(len(raw)), RawRetained: retained, RetainedPayloadSHA256: retainedSHA, RedactionStatus: evidence.RedactionNotInspected, RedactionPolicyVersion: "fixture-raw-v1"}
	id, err := evidence.NewEvidenceID(logicalID, digest, retention)
	if err != nil {
		t.Fatal(err)
	}
	requestID := model.RequestID("request:" + strings.Repeat("9", 64))
	observationID, err := evidence.NewCollectionObservationID(id, sessionID, requestID, now, 1)
	if err != nil {
		t.Fatal(err)
	}
	envelope := evidence.Envelope{Evidence: evidence.EvidenceObject{SchemaVersion: evidence.EvidenceSchemaVersion, ID: id,
		LogicalSource: evidence.LogicalSource{ID: logicalID, Kind: evidence.SourceJobLog, CanonicalID: identity.CanonicalID, RequestParameters: evidence.RequestParameters{}},
		Source:        evidence.SourceDescriptor{Provider: evidence.ProviderGitHub, RequestParameters: evidence.RequestParameters{}, RequestAttempt: 1}, Scope: scope, EventTime: instantEventAt(now.Time),
		Content:   evidence.ContentDescriptor{MediaType: "text/plain", ByteLength: uint64(len(raw)), Complete: true, SourceSHA256: digest, RetainedPayloadSHA256: retainedSHA, RawRetained: retained, RetainedPath: retainedPath},
		Extractor: evidence.ExtractorDescriptor{Name: "fixture", Version: "1.0.0", RulesetSHA256: strings.Repeat("a", 64)}, Redaction: evidence.RedactionDescriptor{Status: evidence.RedactionNotInspected, PolicyVersion: "fixture-raw-v1"}, Derivation: evidence.DerivationDescriptor{ParentEvidenceIDs: []model.EvidenceID{}}, Errors: []evidence.EvidenceError{},
	}, Observation: evidence.CollectionObservation{ID: observationID, EvidenceID: id, CollectionSessionID: sessionID, RequestID: requestID, RequestAttempt: 1, CollectionTime: model.CollectionWindow{StartedAt: now, EndedAt: now}}}
	if err := envelope.Validate(); err != nil {
		t.Fatal(err)
	}
	return envelope
}

func literalCoverage(t *testing.T, scope model.CoverageScope, evidenceID model.EvidenceID, closed bool) archive.Fact {
	t.Helper()
	unit := model.CoverageUnit{ID: model.CoverageUnitID("cov1:" + strings.Repeat("0", 64)), Kind: model.CoverageJobLog, Scope: scope, LogicalKey: "fixture-job-log", RequiredForNegative: true}
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

func literalFinding(t *testing.T, result Result, indicatorID string) report.Finding {
	t.Helper()
	var values []report.Finding
	for _, finding := range result.Case.Findings {
		if finding.IndicatorID == indicatorID {
			values = append(values, finding)
		}
	}
	if len(values) != 1 {
		t.Fatalf("findings for %s = %#v", indicatorID, values)
	}
	return values[0]
}
