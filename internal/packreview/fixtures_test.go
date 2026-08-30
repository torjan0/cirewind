package packreview

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/torjan0/cirewind/internal/incident"
	"github.com/torjan0/cirewind/internal/model"
)

func TestCompleteSyntheticReviewPacketFixtureMatrix(t *testing.T) {
	repo := newSyntheticReviewRepo(t, StandardPolicyProfile)
	pack := validatedUnitPack(t, repo)

	var got problems
	if err := validateFixtureResults(context.Background(), repo.candidate, pack, repo.unitValue.ExpectedFindings, &got); err != nil {
		t.Fatalf("validate fixture matrix: %v", err)
	}
	if err := got.err(); err != nil {
		t.Fatalf("complete fixture matrix failed: %v", err)
	}

	states := make(map[model.FindingState]bool)
	inclusiveStart, exclusiveEndTemporal, downloaded, downloadedExecuted := 0, 0, 0, 0
	for _, finding := range repo.unitValue.ExpectedFindings.Findings {
		if finding.ScenarioID == syntheticCompleteScenario {
			states[finding.State] = true
			if finding.IndicatorID == "synthetic-boundary-inclusive-start" && finding.State == model.RunInWindowMutableRef {
				inclusiveStart++
			}
			if finding.IndicatorID == "synthetic-boundary-exclusive-end" && (finding.State == model.RunInWindowMutableRef || finding.State == model.PotentialTransitive) {
				exclusiveEndTemporal++
			}
		}
		if finding.ScenarioID == syntheticDownloadScenario {
			switch finding.State {
			case model.ConfirmedDownloaded:
				downloaded++
			case model.ConfirmedExecuted:
				downloadedExecuted++
			}
		}
	}
	for _, state := range model.FindingStates() {
		if !states[state] {
			t.Fatalf("complete scenario oracle omits canonical state %s", state)
		}
	}
	if inclusiveStart == 0 || exclusiveEndTemporal != 0 {
		t.Fatalf("window-boundary oracle drift: inclusive-start=%d exclusive-end-temporal=%d", inclusiveStart, exclusiveEndTemporal)
	}
	if downloaded == 0 || downloadedExecuted != 0 {
		t.Fatalf("download-only oracle drift: downloaded=%d executed=%d", downloaded, downloadedExecuted)
	}
	if len(repo.unitValue.ExpectedFindings.Forbidden) != 1 ||
		repo.unitValue.ExpectedFindings.Forbidden[0].ScenarioID != syntheticDownloadScenario ||
		repo.unitValue.ExpectedFindings.Forbidden[0].State != model.ConfirmedExecuted {
		t.Fatalf("download-only execution prohibition drifted: %#v", repo.unitValue.ExpectedFindings.Forbidden)
	}
}

func TestFixtureReplayRejectsOracleMismatch(t *testing.T) {
	repo := newSyntheticReviewRepo(t, StandardPolicyProfile)
	pack := validatedUnitPack(t, repo)
	oracle := repo.unitValue.ExpectedFindings
	oracle.Findings = append([]ExpectedFinding(nil), oracle.Findings...)
	oracle.Findings[0].Provenance = nextProvenance(oracle.Findings[0].Provenance)
	oracle = NormalizeExpectedFindings(oracle)

	var got problems
	if err := validateFixtureResults(context.Background(), repo.candidate, pack, oracle, &got); err != nil {
		t.Fatalf("validate fixture results: %v", err)
	}
	if !hasProblemCode(got, "FIXTURE_ORACLE_MISMATCH") {
		t.Fatalf("expected fixture oracle mismatch, got %#v", got.items)
	}
}

func TestFixtureReplayRejectsCoverageAssessmentIDMismatch(t *testing.T) {
	repo := newSyntheticReviewRepo(t, StandardPolicyProfile)
	pack := validatedUnitPack(t, repo)
	oracle := repo.unitValue.ExpectedFindings
	oracle.Findings = append([]ExpectedFinding(nil), oracle.Findings...)
	mutated := false
	for index := range oracle.Findings {
		if len(oracle.Findings[index].CoverageAssessmentIDs) == 0 {
			continue
		}
		oracle.Findings[index].CoverageAssessmentIDs = append([]model.CoverageAssessmentID(nil), oracle.Findings[index].CoverageAssessmentIDs...)
		oracle.Findings[index].CoverageAssessmentIDs[0] = model.CoverageAssessmentID("cova1:" + stringOf('f', 64))
		mutated = true
		break
	}
	if !mutated {
		t.Fatal("synthetic review oracle lacks an exact coverage assessment ID")
	}
	oracle = NormalizeExpectedFindings(oracle)

	var got problems
	if err := validateFixtureResults(context.Background(), repo.candidate, pack, oracle, &got); err != nil {
		t.Fatalf("validate fixture results: %v", err)
	}
	if !hasProblemCode(got, "FIXTURE_ORACLE_MISMATCH") {
		t.Fatalf("expected exact coverage assessment mismatch, got %#v", got.items)
	}
}

func TestFixtureReplayRejectsGapReasonMismatch(t *testing.T) {
	repo := newSyntheticReviewRepo(t, StandardPolicyProfile)
	pack := validatedUnitPack(t, repo)
	oracle := repo.unitValue.ExpectedFindings
	oracle.Findings = append([]ExpectedFinding(nil), oracle.Findings...)
	mutated := false
	for index := range oracle.Findings {
		if oracle.Findings[index].State != model.UnknownEvidenceGap {
			continue
		}
		oracle.Findings[index].EvidenceGapCodes = []string{"permission_denied"}
		mutated = true
		break
	}
	if !mutated {
		t.Fatal("synthetic review oracle lacks UNKNOWN_EVIDENCE_GAP")
	}
	oracle = NormalizeExpectedFindings(oracle)

	var got problems
	if err := validateFixtureResults(context.Background(), repo.candidate, pack, oracle, &got); err != nil {
		t.Fatalf("validate fixture results: %v", err)
	}
	if !hasProblemCode(got, "FIXTURE_ORACLE_MISMATCH") {
		t.Fatalf("expected exact gap-reason mismatch, got %#v", got.items)
	}
}

func TestFixtureReplayEnforcesForbiddenState(t *testing.T) {
	repo := newSyntheticReviewRepo(t, StandardPolicyProfile)
	pack := validatedUnitPack(t, repo)
	oracle := repo.unitValue.ExpectedFindings
	oracle.Forbidden = []ForbiddenExpectedFinding{{
		ScenarioID: oracle.Findings[0].ScenarioID,
		State:      oracle.Findings[0].State,
		Rationale:  "Synthetic negative test deliberately forbids an observed state.",
	}}
	oracle = NormalizeExpectedFindings(oracle)

	var got problems
	if err := validateFixtureResults(context.Background(), repo.candidate, pack, oracle, &got); err != nil {
		t.Fatalf("validate fixture results: %v", err)
	}
	if !hasProblemCode(got, "FORBIDDEN_FIXTURE_STATE") {
		t.Fatalf("expected forbidden fixture state, got %#v", got.items)
	}
}

func TestFixtureReplayHonorsCancellation(t *testing.T) {
	repo := newSyntheticReviewRepo(t, StandardPolicyProfile)
	pack := validatedUnitPack(t, repo)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	var got problems
	if err := validateFixtureResults(ctx, repo.candidate, pack, repo.unitValue.ExpectedFindings, &got); err == nil {
		t.Fatal("expected cancellation")
	}
}

func TestFixtureReplayNeverReadsInvalidSnapshotPath(t *testing.T) {
	repo := newSyntheticReviewRepo(t, StandardPolicyProfile)
	pack := validatedUnitPack(t, repo)
	outside := filepath.Clean(filepath.Join(repo.candidate, "fixtures", "..", "..", "outside.json"))
	mustWrite(t, outside, []byte("not a snapshot\n"))
	index := FixtureIndex{SchemaVersion: FixtureIndexSchema, Scenarios: []FixtureScenario{{
		ScenarioID: syntheticCompleteScenario, SnapshotPath: "../../outside.json", AnalysisTime: "2026-08-20T00:00:00Z",
	}}}
	mustWrite(t, filepath.Join(repo.candidate, "fixtures", "index.json"), mustCanonical(t, index))

	var got problems
	if err := validateFixtureResults(context.Background(), repo.candidate, pack, repo.unitValue.ExpectedFindings, &got); err != nil {
		t.Fatalf("validate fixture results: %v", err)
	}
	if !hasProblemCode(got, "FIXTURE_SNAPSHOT_PATH") {
		t.Fatalf("expected invalid snapshot path, got %#v", got.items)
	}
	for _, code := range []string{"FIXTURE_SNAPSHOT_READ", "FIXTURE_SNAPSHOT_JSON", "FIXTURE_SNAPSHOT", "FIXTURE_SNAPSHOT_CANONICAL", "FIXTURE_ANALYSIS"} {
		if hasProblemCode(got, code) {
			t.Fatalf("invalid path was processed (%s): %#v", code, got.items)
		}
	}
}

func TestFixtureReplayRejectsUnindexedSnapshot(t *testing.T) {
	repo := newSyntheticReviewRepo(t, StandardPolicyProfile)
	pack := validatedUnitPack(t, repo)
	source := filepath.Join(repo.candidate, "fixtures", "scenarios", syntheticCompleteScenario, "archive-snapshot.json")
	raw, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	extra := filepath.Join(repo.candidate, "fixtures", "scenarios", "unindexed", "archive-snapshot.json")
	mustMkdir(t, filepath.Dir(extra))
	mustWrite(t, extra, raw)

	var got problems
	if err := validateFixtureResults(context.Background(), repo.candidate, pack, repo.unitValue.ExpectedFindings, &got); err != nil {
		t.Fatalf("validate fixture results: %v", err)
	}
	if !hasProblemCode(got, "UNINDEXED_FIXTURE_SNAPSHOT") {
		t.Fatalf("expected unindexed snapshot rejection, got %#v", got.items)
	}
}

func validatedUnitPack(t *testing.T, repo syntheticReviewRepo) *incident.ValidatedPack {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(repo.candidate, "pack.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	pack, err := incident.Validate(context.Background(), raw)
	if err != nil {
		t.Fatal(err)
	}
	return pack
}

func nextProvenance(current model.ProvenanceLevel) model.ProvenanceLevel {
	if current == model.L4Certain {
		return model.L3Strong
	}
	return model.L4Certain
}

func hasProblemCode(value problems, code string) bool {
	for _, problem := range value.items {
		if problem.Code == code {
			return true
		}
	}
	return false
}
