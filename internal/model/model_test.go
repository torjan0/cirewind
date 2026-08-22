package model

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestCanonicalFindingStatesAndProvenance(t *testing.T) {
	wantStates := []FindingState{
		"CONFIRMED_EXECUTED",
		"CONFIRMED_DOWNLOADED",
		"CONFIRMED_CALLED_WORKFLOW",
		"DECLARED_AT_RUN_SHA",
		"RUN_IN_WINDOW_MUTABLE_REF",
		"POTENTIAL_TRANSITIVE",
		"CURRENT_REFERENCE_ONLY",
		"NO_MATCH_CONFIRMED",
		"UNKNOWN_EVIDENCE_GAP",
		"CONTRADICTORY_EVIDENCE",
	}
	if got := FindingStates(); !reflect.DeepEqual(got, wantStates) {
		t.Fatalf("finding states drifted\n got: %#v\nwant: %#v", got, wantStates)
	}
	wantProvenance := []ProvenanceLevel{"L4_CERTAIN", "L3_STRONG", "L2_PROBABLE", "L1_POSSIBLE", "L0_UNKNOWN"}
	if got := ProvenanceLevels(); !reflect.DeepEqual(got, wantProvenance) {
		t.Fatalf("provenance drifted\n got: %#v\nwant: %#v", got, wantProvenance)
	}

	for _, input := range []string{`"L4"`, `"CERTAIN"`, `"confirmed_executed"`, `"EXECUTED"`} {
		var provenance ProvenanceLevel
		if strings.Contains(input, "executed") || strings.Contains(input, "EXECUTED") {
			var state FindingState
			if err := json.Unmarshal([]byte(input), &state); err == nil {
				t.Fatalf("accepted finding-state alias %s", input)
			}
			continue
		}
		if err := json.Unmarshal([]byte(input), &provenance); err == nil {
			t.Fatalf("accepted provenance alias %s", input)
		}
	}
}

func TestTypedGitObjectIDsAndDigests(t *testing.T) {
	sha1 := strings.Repeat("a", 40)
	objectID, err := NewGitObjectID(HashSHA1, sha1)
	if err != nil {
		t.Fatal(err)
	}
	workflowID, err := NewWorkflowDefinitionObjectID(objectID)
	if err != nil || workflowID.Validate() != nil {
		t.Fatalf("workflow object ID rejected: %v", err)
	}
	if _, err := NewGitObjectID(HashSHA1, strings.Repeat("a", 39)); err == nil {
		t.Fatal("accepted short SHA-1")
	}
	if _, err := NewGitObjectID(HashSHA256, strings.Repeat("A", 64)); err == nil {
		t.Fatal("accepted uppercase object ID")
	}
	if _, err := NewPackageDigest(DigestGitHubActionPackage, HashSHA256, strings.Repeat("b", 64)); err != nil {
		t.Fatalf("valid package digest rejected: %v", err)
	}
	if _, err := NewPackageDigest("", HashSHA256, strings.Repeat("b", 64)); err == nil {
		t.Fatal("accepted untyped package digest")
	}
	if _, err := NewPackageDigest(DigestGitHubActionPackage, HashSHA1, strings.Repeat("b", 40)); err == nil {
		t.Fatal("accepted non-SHA-256 v0.1 package digest")
	}
	wantSubjects := []DigestSubject{
		"github-action-package",
		"oci-manifest",
		"executable-file",
		"release-asset",
		"workflow-artifact",
	}
	for _, subject := range wantSubjects {
		if !subject.Valid() {
			t.Errorf("required digest subject %q is invalid", subject)
		}
	}
	for _, alias := range []DigestSubject{"oci-image", "executable"} {
		if alias.Valid() {
			t.Errorf("accepted obsolete digest subject alias %q", alias)
		}
	}
}

func TestJobAndStepIdentity(t *testing.T) {
	attempt := RunAttemptIdentity{RepositoryID: 1, RunID: 2, RunAttempt: 3}
	if err := attempt.Validate(); err != nil || attempt.String() != "repo:1/run:2/attempt:3" {
		t.Fatalf("attempt identity: %v, %q", err, attempt.String())
	}
	job := JobExecutionIdentity{RepositoryID: 1, RunID: 2, RunAttempt: 3, JobID: 4}
	number := APIStepNumber(5)
	step := StepIdentity{
		Job:            job,
		APIStepNumber:  &number,
		LifecyclePhase: LifecycleMain,
		Occurrence:     1,
	}
	if err := step.Validate(); err != nil {
		t.Fatal(err)
	}
	if got, want := step.Key(), "1/2/3/4/step:5/MAIN/1"; got != want {
		t.Fatalf("step key = %q, want %q", got, want)
	}
	step.APIStepNumber = nil
	if err := step.Validate(); err == nil {
		t.Fatal("step without timeline or API identity validated")
	}
}

func TestEventAndCollectionTimeAreSeparateAndValidated(t *testing.T) {
	start := MustInstant(time.Date(2026, 3, 19, 17, 0, 0, 0, time.UTC))
	end := MustInstant(time.Date(2026, 3, 19, 18, 0, 0, 0, time.UTC))
	bounds := BoundsClosedOpen
	interval := EventInterval{
		Start:         &start,
		End:           &end,
		Bounds:        &bounds,
		Precision:     PrecisionSecond,
		Approximation: ApproximationExact,
		Basis:         TimeBasisLogTimestamp,
	}
	if err := interval.Validate(); err != nil {
		t.Fatal(err)
	}
	bad := interval
	bad.Start, bad.End = bad.End, bad.Start
	if err := bad.Validate(); err == nil {
		t.Fatal("accepted backwards event interval")
	}
	if err := (CollectionWindow{StartedAt: end, EndedAt: start}).Validate(); err == nil {
		t.Fatal("accepted backwards collection window")
	}
}

func TestRuntimeObservationBoundaries(t *testing.T) {
	if ObservationDownloadAnnounced.SupportsDownloaded() {
		t.Fatal("download announcement incorrectly supports completed download")
	}
	if ObservationPreparationFailed.SupportsDownloaded() {
		t.Fatal("preparation failure incorrectly supports completed download")
	}
	if !ObservationPreparationComplete.SupportsDownloaded() {
		t.Fatal("preparation completion should support downloaded")
	}
	if ObservationPreparationComplete.SupportsExecuted() {
		t.Fatal("preparation completion incorrectly supports execution")
	}
	if !ObservationLifecycleStarted.SupportsExecuted() {
		t.Fatal("lifecycle start should support execution when exactly joined")
	}
	if got := ObservationConditionSkipped.Stage(); got != StageDeclared {
		t.Fatalf("condition skip alone mapped to %s, want DECLARED", got)
	}
}

func TestCoverageReconciliationAndNoMatchClosure(t *testing.T) {
	unitA := CoverageUnit{
		ID:                  fakeCoverageUnitID('a'),
		Kind:                CoverageAttemptLog,
		Scope:               CoverageScope{RepositoryID: ptr(RepositoryID(1)), RunID: ptr(WorkflowRunID(2)), RunAttempt: ptr(RunAttempt(1))},
		LogicalKey:          "repo:1/run:2/attempt:1/log",
		RequiredForNegative: true,
	}
	unitB := CoverageUnit{
		ID:                  fakeCoverageUnitID('b'),
		Kind:                CoverageWorkflowDefinition,
		Scope:               CoverageScope{RepositoryID: ptr(RepositoryID(1))},
		LogicalKey:          "repo:1/workflow-definition",
		RequiredForNegative: true,
	}
	collected := CoverageAssessment{
		ID:          fakeCoverageAssessmentID('c'),
		UnitID:      unitA.ID,
		Status:      CoverageCollected,
		EvidenceIDs: []EvidenceID{fakeEvidenceID('d')},
	}
	gap := CoverageAssessment{
		ID:          fakeCoverageAssessmentID('e'),
		UnitID:      unitB.ID,
		Status:      CoverageGap,
		Gap:         &CoverageGapDetail{Reason: GapNotFound, Material: true},
		EvidenceIDs: []EvidenceID{fakeEvidenceID('f')},
	}
	summary, err := ReconcileCoverage([]CoverageUnit{unitA, unitB}, []CoverageAssessment{collected, gap}, true)
	if err != nil {
		t.Fatal(err)
	}
	if summary.AllowsNoMatchConfirmed() {
		t.Fatal("material evidence gap allowed NO_MATCH_CONFIRMED")
	}
	gap.Status = CoverageCollected
	gap.Gap = nil
	summary, err = ReconcileCoverage([]CoverageUnit{unitA, unitB}, []CoverageAssessment{collected, gap}, true)
	if err != nil || !summary.AllowsNoMatchConfirmed() {
		t.Fatalf("closed coverage rejected: summary=%+v err=%v", summary, err)
	}
	if _, err := ReconcileCoverage([]CoverageUnit{unitA}, nil, true); err == nil {
		t.Fatal("final coverage accepted an open expected unit")
	}
}

func ptr[T any](value T) *T { return &value }

func fakeEvidenceID(char byte) EvidenceID {
	return EvidenceID("ev1:" + strings.Repeat(string(char), 64))
}

func fakeCoverageUnitID(char byte) CoverageUnitID {
	return CoverageUnitID("cov1:" + strings.Repeat(string(char), 64))
}

func fakeCoverageAssessmentID(char byte) CoverageAssessmentID {
	return CoverageAssessmentID("cova1:" + strings.Repeat(string(char), 64))
}
