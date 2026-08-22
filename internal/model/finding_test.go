package model

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestFindingSupersetValidation(t *testing.T) {
	finding := validGapFinding(t)
	if err := finding.Validate(); err != nil {
		t.Fatalf("valid gap finding rejected: %v", err)
	}
	encoded, err := json.Marshal(finding)
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		`"workflow"`,
		`"conclusion"`,
		`"assumptions":[]`,
		`"evidence_gaps"`,
		`"contradictory_evidence":[]`,
		`"potential_credential_exposure":[]`,
		`"potential_resource_exposure":[]`,
		`"remediation_guidance":[`,
		`"collection_coverage"`,
	} {
		if !strings.Contains(string(encoded), required) {
			t.Errorf("serialized finding is missing %s: %s", required, encoded)
		}
	}

	withoutGap := finding
	withoutGap.EvidenceGaps = []EvidenceGapReference{}
	if err := withoutGap.Validate(); err == nil {
		t.Fatal("UNKNOWN_EVIDENCE_GAP without a gap validated")
	}

	withoutSupport := finding
	withoutSupport.State = ConfirmedExecuted
	withoutSupport.EvidenceGaps = []EvidenceGapReference{}
	if err := withoutSupport.Validate(); err == nil {
		t.Fatal("positive finding without evidence or gap validated")
	}
}

func TestNoMatchRequiresEvidenceAndCoverage(t *testing.T) {
	finding := validGapFinding(t)
	finding.State = NoMatchConfirmed
	finding.ProvenanceLevel = L3Strong
	finding.EvidenceObjectIDs = []EvidenceID{fakeEvidenceID('a')}
	finding.EvidenceGaps = []EvidenceGapReference{}
	if err := finding.Validate(); err != nil {
		t.Fatalf("closed no-match shape rejected: %v", err)
	}
	finding.CollectionCoverage = []CoverageAssessmentID{}
	if err := finding.Validate(); err == nil {
		t.Fatal("NO_MATCH_CONFIRMED without coverage validated")
	}
}

func TestFindingCoverageRejectsNegativeClosureOverMaterialGap(t *testing.T) {
	finding := validGapFinding(t)
	finding.State = NoMatchConfirmed
	finding.ProvenanceLevel = L3Strong
	finding.EvidenceObjectIDs = []EvidenceID{fakeEvidenceID('a')}
	finding.EvidenceGaps = []EvidenceGapReference{}
	unitID := fakeCoverageUnitID('b')
	assessmentID := finding.CollectionCoverage[0]
	unit := CoverageUnit{
		ID:                  unitID,
		Kind:                CoverageAttemptLog,
		Scope:               CoverageScope{},
		LogicalKey:          "bounded-attempt-log",
		RequiredForNegative: true,
	}
	assessment := CoverageAssessment{
		ID:          assessmentID,
		UnitID:      unitID,
		Status:      CoverageGap,
		Gap:         &CoverageGapDetail{Reason: GapNotFound, Material: true},
		EvidenceIDs: []EvidenceID{fakeEvidenceID('a')},
	}
	if err := ValidateFindingCoverage(finding, []CoverageUnit{unit}, []CoverageAssessment{assessment}); err == nil {
		t.Fatal("NO_MATCH_CONFIRMED passed over a material coverage gap")
	}
	assessment.Status = CoverageCollected
	assessment.Gap = nil
	if err := ValidateFindingCoverage(finding, []CoverageUnit{unit}, []CoverageAssessment{assessment}); err != nil {
		t.Fatalf("closed negative coverage rejected: %v", err)
	}
}

func TestSecretNamesCannotCarryValues(t *testing.T) {
	if _, err := NewSecretName("deploy_key"); err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"value with spaces", "A=B", "${{ secrets.X }}"} {
		if _, err := NewSecretName(value); err == nil {
			t.Errorf("accepted non-name secret material %q", value)
		}
	}
}

func validGapFinding(t *testing.T) Finding {
	t.Helper()
	workflowPath, err := NewWorkflowPath(".github/workflows/build.yml")
	if err != nil {
		t.Fatal(err)
	}
	now := MustInstant(time.Date(2026, 3, 20, 6, 0, 0, 0, time.UTC))
	return Finding{
		SchemaVersion:     FindingsSchemaVersion,
		FindingID:         FindingID("find1:" + strings.Repeat("1", 64)),
		FindingRevisionID: FindingRevisionID("frev1:" + strings.Repeat("2", 64)),
		Incident: IncidentReference{
			ID:                  "synthetic-incident",
			APIVersion:          "cirewind.dev/v1alpha1",
			PackVersion:         "1.0.0",
			SourcePackSHA256:    strings.Repeat("3", 64),
			CanonicalPackSHA256: strings.Repeat("4", 64),
		},
		IndicatorID: "indicator-1",
		Subject: FindingSubject{
			Repository: RepositorySubject{ID: 1, Name: "acme/service"},
			Workflow:   WorkflowSubject{Path: &workflowPath},
		},
		State:             UnknownEvidenceGap,
		ProvenanceLevel:   L0Unknown,
		Conclusion:        "Runtime status is unknown because the attempt log is unavailable.",
		Proposition:       Proposition{Kind: "action_execution", Attributes: []PropositionAttribute{}},
		EventTime:         EventInterval{Precision: PrecisionUnknown, Approximation: ApproximationUnknown, Basis: TimeBasisUnknown},
		EvidenceObjectIDs: []EvidenceID{},
		Assumptions:       []Assumption{},
		EvidenceGaps: []EvidenceGapReference{{
			CoverageAssessmentID: fakeCoverageAssessmentID('5'),
			Code:                 GapNotFound,
			Description:          "The attempt log returned not found; expiry is not assumed.",
		}},
		ContradictoryEvidence:       []ContradictionReference{},
		PotentialCredentialExposure: []CredentialExposure{},
		PotentialResourceExposure:   []ResourceExposure{},
		RemediationGuidance:         []string{"Review adjacent retained evidence."},
		CollectionCoverage:          []CoverageAssessmentID{fakeCoverageAssessmentID('5')},
		Derivation: DerivationReference{
			RuleID:                     "finding.evidence-gap",
			RuleVersion:                "1.0.0",
			FirstProducedAnalysisID:    "analysis:test",
			FirstProducedEngineVersion: "test",
			CanonicalInputsSHA256:      strings.Repeat("6", 64),
		},
		CollectionTime: now,
	}
}
