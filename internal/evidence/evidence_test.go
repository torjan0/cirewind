package evidence

import (
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/torjan0/cirewind/internal/model"
)

func TestCanonicalJSONRestrictedRFC8785(t *testing.T) {
	got, err := CanonicalJSON(map[string]any{"b": 2, "a": "<\n"})
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"a":"<\n","b":2}`; string(got) != want {
		t.Fatalf("canonical JSON = %s, want %s", got, want)
	}

	got, err = CanonicalJSON(map[string]string{"\ue000": "bmp", "\U00010000": "pair"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(got), `{"𐀀":"pair"`) {
		t.Fatalf("keys were not ordered by UTF-16 code units: %s", got)
	}
	if _, err := CanonicalJSON(map[string]any{"float": 1.25}); err == nil {
		t.Fatal("canonical identity accepted a floating-point value")
	}
	if _, err := CanonicalJSON(string([]byte{0xff})); err == nil {
		t.Fatal("canonical identity accepted invalid UTF-8")
	}
}

func TestEvidenceIdentityDeduplicationAndRetention(t *testing.T) {
	repositoryID := model.RepositoryID(1)
	runID := model.WorkflowRunID(2)
	attempt := model.RunAttempt(1)
	jobID := model.JobID(3)
	identity := LogicalSourceIdentity{
		Kind:        SourceWorkflowRunAttemptLog,
		CanonicalID: "repos/acme/service/actions/runs/2/attempts/1/logs",
		Scope: model.CoverageScope{
			RepositoryID: &repositoryID,
			RunID:        &runID,
			RunAttempt:   &attempt,
			JobID:        &jobID,
		},
		RequestParameters: RequestParameters{"per_page": "100", "page": "1"},
	}
	sourceID, err := NewLogicalSourceID(identity)
	if err != nil {
		t.Fatal(err)
	}
	identity.RequestParameters = RequestParameters{"page": "1", "per_page": "100"}
	sourceIDAgain, err := NewLogicalSourceID(identity)
	if err != nil || sourceID != sourceIDAgain {
		t.Fatalf("map order changed source ID: %s %s %v", sourceID, sourceIDAgain, err)
	}
	if want := model.LogicalSourceID("src1:22d98fe449c1ae83597728eb555b39c5f27e2ad52bac46f8ee364fdab3ce4a11"); sourceID != want {
		t.Fatalf("logical-source golden changed: got %s want %s", sourceID, want)
	}

	retainedHash := strings.Repeat("b", 64)
	retention := RetentionDescriptor{
		MediaType:              "application/zip",
		ByteLength:             123,
		RetainedPayloadSHA256:  &retainedHash,
		RedactionStatus:        RedactionStructuredAllowlist,
		RedactionPolicyVersion: "1.0.0",
	}
	evidenceID, err := NewEvidenceID(sourceID, strings.Repeat("a", 64), retention)
	if err != nil {
		t.Fatal(err)
	}
	evidenceIDAgain, err := NewEvidenceID(sourceID, strings.Repeat("a", 64), retention)
	if err != nil || evidenceID != evidenceIDAgain {
		t.Fatalf("identical evidence did not deduplicate: %s %s %v", evidenceID, evidenceIDAgain, err)
	}
	if want := model.EvidenceID("ev1:dc79181c6fcee973993a2084dced53afb8d42f706a8b0c6e2b2835583ac5884b"); evidenceID != want {
		t.Fatalf("evidence golden changed: got %s want %s", evidenceID, want)
	}
	retention.RawRetained = true
	rawID, err := NewEvidenceID(sourceID, strings.Repeat("a", 64), retention)
	if err != nil {
		t.Fatal(err)
	}
	if evidenceID == rawID {
		t.Fatal("material retention change reused evidence ID")
	}

	ended := model.MustInstant(time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC))
	first, err := NewCollectionObservationID(evidenceID, "collection:one", "request:one", ended, 1)
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewCollectionObservationID(evidenceID, "collection:two", "request:one", ended, 1)
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("different recollection session reused observation ID")
	}
	if want := model.CollectionObservationID("obs1:035a967f7e7a875ecc706927059953fbf2fba4192fe850c6db9a3466373d125f"); first != want {
		t.Fatalf("collection-observation golden changed: got %s want %s", first, want)
	}
}

func TestFindingAndRevisionIdentitySemantics(t *testing.T) {
	path, err := model.NewWorkflowPath(".github/workflows/build.yml")
	if err != nil {
		t.Fatal(err)
	}
	runID := model.WorkflowRunID(10)
	attempt := model.RunAttempt(2)
	jobID := model.JobID(30)
	subject := model.FindingSubject{
		Repository: model.RepositorySubject{ID: 1, Name: "acme/service"},
		Workflow:   model.WorkflowSubject{Path: &path},
		RunID:      &runID,
		RunAttempt: &attempt,
		JobID:      &jobID,
	}
	logical := FindingLogicalInput{
		IncidentID:      "synthetic-incident",
		IncidentAPI:     "cirewind.dev/v1alpha1",
		IndicatorID:     "action-b",
		Subject:         subject,
		PropositionKind: "action_execution",
	}
	findingID, err := NewFindingID(logical)
	if err != nil {
		t.Fatal(err)
	}
	logical.Subject.Repository.Name = "renamed/service"
	logical.IncidentAPI = "cirewind.dev/v1beta2"
	sameID, err := NewFindingID(logical)
	if err != nil || sameID != findingID {
		t.Fatalf("descriptive rename or same API major changed finding ID: %s %s %v", findingID, sameID, err)
	}
	logical.IncidentAPI = "cirewind.dev/v2alpha1"
	majorChanged, err := NewFindingID(logical)
	if err != nil {
		t.Fatal(err)
	}
	if majorChanged == findingID {
		t.Fatal("incident API major change reused finding ID")
	}
	if want := model.FindingID("find1:0a374e726729098c6b1f8a73584d3f7574f4b047b2acc3c68aaea01ec2f32563"); findingID != want {
		t.Fatalf("finding golden changed: got %s want %s", findingID, want)
	}

	evidenceA := model.EvidenceID("ev1:" + strings.Repeat("a", 64))
	evidenceB := model.EvidenceID("ev1:" + strings.Repeat("b", 64))
	coverageA := model.CoverageAssessmentID("cova1:" + strings.Repeat("c", 64))
	input := FindingRevisionInput{
		FindingID:           findingID,
		CanonicalPackSHA256: strings.Repeat("d", 64),
		State:               model.ConfirmedExecuted,
		Provenance:          model.L4Certain,
		EvidenceIDs:         []model.EvidenceID{evidenceB, evidenceA},
		CoverageIDs:         []model.CoverageAssessmentID{coverageA},
		RuleVersion:         "1.0.0",
		Proposition: model.Proposition{
			Kind: "action_execution",
			Attributes: []model.PropositionAttribute{
				{Name: "sha", Value: strings.Repeat("e", 40)},
				{Name: "phase", Value: "MAIN"},
			},
		},
	}
	revisionID, err := NewFindingRevisionID(input)
	if err != nil {
		t.Fatal(err)
	}
	input.EvidenceIDs = []model.EvidenceID{evidenceA, evidenceB, evidenceA}
	input.Proposition.Attributes[0], input.Proposition.Attributes[1] = input.Proposition.Attributes[1], input.Proposition.Attributes[0]
	reorderedID, err := NewFindingRevisionID(input)
	if err != nil || revisionID != reorderedID {
		t.Fatalf("set/source order changed revision: %s %s %v", revisionID, reorderedID, err)
	}
	input.RuleVersion = "2.0.0"
	changedID, err := NewFindingRevisionID(input)
	if err != nil {
		t.Fatal(err)
	}
	if changedID == revisionID {
		t.Fatal("semantic rule version change reused revision")
	}
	if want := model.FindingRevisionID("frev1:af0539d2e61737aa1eba5772aa374bb987809ffc7137547b2c6a453b3defda3d"); revisionID != want {
		t.Fatalf("finding-revision golden changed: got %s want %s", revisionID, want)
	}
	finding := model.Finding{
		SchemaVersion:     model.FindingsSchemaVersion,
		FindingID:         findingID,
		FindingRevisionID: revisionID,
		Incident: model.IncidentReference{
			ID:                  "synthetic-incident",
			APIVersion:          "cirewind.dev/v1alpha1",
			PackVersion:         "1.0.0",
			SourcePackSHA256:    strings.Repeat("f", 64),
			CanonicalPackSHA256: strings.Repeat("d", 64),
		},
		IndicatorID:                 "action-b",
		Subject:                     subject,
		State:                       model.ConfirmedExecuted,
		ProvenanceLevel:             model.L4Certain,
		Conclusion:                  "The exact affected Action lifecycle began.",
		Proposition:                 model.NormalizeProposition(input.Proposition),
		EventTime:                   model.EventInterval{Precision: model.PrecisionUnknown, Approximation: model.ApproximationUnknown, Basis: model.TimeBasisUnknown},
		EvidenceObjectIDs:           []model.EvidenceID{evidenceA, evidenceB},
		Assumptions:                 []model.Assumption{},
		EvidenceGaps:                []model.EvidenceGapReference{},
		ContradictoryEvidence:       []model.ContradictionReference{},
		PotentialCredentialExposure: []model.CredentialExposure{},
		PotentialResourceExposure:   []model.ResourceExposure{},
		RemediationGuidance:         []string{},
		CollectionCoverage:          []model.CoverageAssessmentID{coverageA},
		Derivation: model.DerivationReference{
			RuleID:                     "finding.action-execution",
			RuleVersion:                "1.0.0",
			FirstProducedAnalysisID:    "analysis:first",
			FirstProducedEngineVersion: "build-one",
			CanonicalInputsSHA256:      strings.Repeat("9", 64),
		},
		CollectionTime: model.MustInstant(time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)),
	}
	if err := ValidateFindingIdentity(finding); err != nil {
		t.Fatalf("valid finding identity rejected: %v", err)
	}
	finding.Conclusion = "Display prose changed without changing the proposition."
	finding.Derivation.FirstProducedEngineVersion = "build-two"
	if err := ValidateFindingIdentity(finding); err != nil {
		t.Fatalf("display/build-only change altered revision identity: %v", err)
	}
	finding.State = model.ConfirmedDownloaded
	if err := ValidateFindingIdentity(finding); err == nil {
		t.Fatal("identity validation accepted a changed finding state with the old revision ID")
	}
}

func TestCoverageAssessmentIdentityExcludesCollectionSession(t *testing.T) {
	unit := model.CoverageUnit{
		ID:                  model.CoverageUnitID("cov1:" + strings.Repeat("1", 64)),
		Kind:                model.CoverageAttemptLog,
		Scope:               model.CoverageScope{},
		LogicalKey:          "attempt-log:bounded-scope",
		RequiredForNegative: true,
	}
	unitID, err := NewCoverageUnitID(unit)
	if err != nil {
		t.Fatal(err)
	}
	assessment := model.CoverageAssessment{
		ID:          model.CoverageAssessmentID("cova1:" + strings.Repeat("2", 64)),
		UnitID:      unitID,
		Status:      model.CoverageGap,
		Gap:         &model.CoverageGapDetail{Reason: model.GapNotFound, Material: true},
		EvidenceIDs: []model.EvidenceID{},
	}
	assessmentID, err := NewCoverageAssessmentID(assessment)
	if err != nil {
		t.Fatal(err)
	}
	when := model.MustInstant(time.Date(2026, 8, 20, 13, 0, 0, 0, time.UTC))
	first, err := NewCoverageObservationID(assessmentID, "collection:first", when)
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewCoverageObservationID(assessmentID, "collection:second", when)
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("coverage recollections did not receive distinct observation IDs")
	}
}

func TestSensitiveRequestAndErrorMaterialRejected(t *testing.T) {
	if err := (RequestParameters(nil)).Validate(); err == nil {
		t.Fatal("nil request-parameter object was serializable as null")
	}
	if err := (RequestParameters{"authorization": "redacted"}).Validate(); err == nil {
		t.Fatal("authorization parameter was serializable")
	}
	if err := (RequestParameters{"page": "token=example"}).Validate(); err == nil {
		t.Fatal("token-looking request value was serializable")
	}
	if err := (EvidenceError{Phase: ErrorCollect, Code: "FORBIDDEN", SanitizedMessage: "Authorization: Bearer example"}).Validate(); err == nil {
		t.Fatal("authorization-looking error message was serializable")
	}
}

func TestEvidenceEnvelopeValidatesCanonicalIdentity(t *testing.T) {
	identity := LogicalSourceIdentity{
		Kind:              SourceAPIJSON,
		CanonicalID:       "repos/acme/service/actions/runs/10",
		Scope:             model.CoverageScope{},
		RequestParameters: RequestParameters{},
	}
	sourceID, err := NewLogicalSourceID(identity)
	if err != nil {
		t.Fatal(err)
	}
	retained := strings.Repeat("2", 64)
	retention := RetentionDescriptor{
		MediaType:              "application/json",
		ByteLength:             42,
		RetainedPayloadSHA256:  &retained,
		RedactionStatus:        RedactionStructuredAllowlist,
		RedactionPolicyVersion: "1.0.0",
	}
	evidenceID, err := NewEvidenceID(sourceID, strings.Repeat("1", 64), retention)
	if err != nil {
		t.Fatal(err)
	}
	started := model.MustInstant(time.Date(2026, 8, 20, 14, 0, 0, 0, time.UTC))
	ended := model.MustInstant(time.Date(2026, 8, 20, 14, 0, 1, 0, time.UTC))
	observationID, err := NewCollectionObservationID(evidenceID, "collection:test", "request:test", ended, 1)
	if err != nil {
		t.Fatal(err)
	}
	envelope := Envelope{
		Evidence: EvidenceObject{
			SchemaVersion: EvidenceSchemaVersion,
			ID:            evidenceID,
			LogicalSource: LogicalSource{
				ID:                sourceID,
				Kind:              identity.Kind,
				CanonicalID:       identity.CanonicalID,
				RequestParameters: RequestParameters{},
			},
			Source: SourceDescriptor{
				Provider:          ProviderGitHub,
				APIVersion:        "2026-03-10",
				EndpointTemplate:  "/repos/{owner}/{repo}/actions/runs/{run_id}",
				RequestParameters: RequestParameters{},
				RequestAttempt:    1,
			},
			Scope:     model.CoverageScope{},
			EventTime: model.EventInterval{Precision: model.PrecisionUnknown, Approximation: model.ApproximationUnknown, Basis: model.TimeBasisUnknown},
			Content: ContentDescriptor{
				MediaType:             retention.MediaType,
				ByteLength:            retention.ByteLength,
				Complete:              true,
				SourceSHA256:          strings.Repeat("1", 64),
				RetainedPayloadSHA256: &retained,
			},
			Extractor:  ExtractorDescriptor{Name: "github-rest", Version: "1.0.0", RulesetSHA256: strings.Repeat("3", 64)},
			Redaction:  RedactionDescriptor{Status: RedactionStructuredAllowlist, PolicyVersion: "1.0.0"},
			Derivation: DerivationDescriptor{ParentEvidenceIDs: []model.EvidenceID{}},
			Errors:     []EvidenceError{},
		},
		Observation: CollectionObservation{
			ID:                  observationID,
			EvidenceID:          evidenceID,
			CollectionSessionID: "collection:test",
			RequestID:           "request:test",
			RequestAttempt:      1,
			CollectionTime:      model.CollectionWindow{StartedAt: started, EndedAt: ended},
		},
	}
	if err := envelope.Validate(); err != nil {
		t.Fatalf("valid evidence envelope rejected: %v", err)
	}
	envelope.Evidence.Content.ByteLength++
	if err := envelope.Validate(); err == nil {
		t.Fatal("evidence object accepted an ID after identity-bearing content changed")
	}
}

func TestDerivedLogicalSourceBindsParentsAndRule(t *testing.T) {
	parentA := model.EvidenceID("ev1:" + strings.Repeat("a", 64))
	parentB := model.EvidenceID("ev1:" + strings.Repeat("b", 64))
	parameters := strings.Repeat("c", 64)
	derivation := DerivationDescriptor{
		Kind:              "runtime-observation",
		ParentEvidenceIDs: []model.EvidenceID{parentB, parentA},
		RuleID:            "extract.runtime",
		RuleVersion:       "1.0.0",
		ParametersSHA256:  &parameters,
	}
	first, err := NewDerivedLogicalSource(model.CoverageScope{}, derivation, strings.Repeat("d", 64))
	if err != nil {
		t.Fatal(err)
	}
	derivation.ParentEvidenceIDs = []model.EvidenceID{parentA, parentB, parentA}
	second, err := NewDerivedLogicalSource(model.CoverageScope{}, derivation, strings.Repeat("d", 64))
	if err != nil {
		t.Fatal(err)
	}
	if first.ID != second.ID {
		t.Fatal("parent set ordering changed derived logical source")
	}
	derivation.RuleVersion = "2.0.0"
	changed, err := NewDerivedLogicalSource(model.CoverageScope{}, derivation, strings.Repeat("d", 64))
	if err != nil {
		t.Fatal(err)
	}
	if changed.ID == first.ID {
		t.Fatal("semantic derivation rule change reused logical source")
	}
}

func TestSchemasAreJSONAndCanonicalEnumsMatch(t *testing.T) {
	for _, name := range []string{"../../schema/evidence-v1alpha1.json", "../../schema/evidence-ledger-v1alpha1.json", "../../schema/findings-v1alpha1.json"} {
		data, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		var document map[string]any
		if err := json.Unmarshal(data, &document); err != nil {
			t.Fatalf("%s is not JSON: %v", name, err)
		}
	}

	data, err := os.ReadFile("../../schema/findings-v1alpha1.json")
	if err != nil {
		t.Fatal(err)
	}
	var schema struct {
		Definitions map[string]struct {
			Properties map[string]struct {
				Enum []string `json:"enum"`
			} `json:"properties"`
		} `json:"$defs"`
	}
	if err := json.Unmarshal(data, &schema); err != nil {
		t.Fatal(err)
	}
	wantStates := make([]string, 0, len(model.FindingStates()))
	for _, state := range model.FindingStates() {
		wantStates = append(wantStates, string(state))
	}
	wantProvenance := make([]string, 0, len(model.ProvenanceLevels()))
	for _, level := range model.ProvenanceLevels() {
		wantProvenance = append(wantProvenance, string(level))
	}
	reportFinding := schema.Definitions["reportFinding"]
	if got := reportFinding.Properties["state"].Enum; !reflect.DeepEqual(got, wantStates) {
		t.Fatalf("schema finding states drifted: got %v want %v", got, wantStates)
	}
	if got := reportFinding.Properties["provenance"].Enum; !reflect.DeepEqual(got, wantProvenance) {
		t.Fatalf("schema provenance drifted: got %v want %v", got, wantProvenance)
	}
}
