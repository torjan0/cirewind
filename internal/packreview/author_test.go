package packreview

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/torjan0/cirewind/internal/demodata"
	"github.com/torjan0/cirewind/internal/model"
)

// syntheticAuthoredScenarios mirrors the synthetic review fixture: the complete
// demo snapshot and a downloaded-only projection, with the promotion that must
// never happen recorded as a forbidden row.
func syntheticAuthoredScenarios(t *testing.T) []AuthoredScenario {
	t.Helper()
	bundle, err := demodata.Bundle(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return []AuthoredScenario{
		{ScenarioID: syntheticCompleteScenario, Snapshot: bundle.Snapshot, AnalysisTime: bundle.AnalysisTime},
		{ScenarioID: syntheticDownloadScenario, Snapshot: syntheticSnapshotForRun(t, bundle.Snapshot, 1002), AnalysisTime: bundle.AnalysisTime,
			Forbidden: []ForbiddenExpectedFinding{ForbiddenStateFor(syntheticDownloadScenario, model.ConfirmedExecuted, "Preparation without a lifecycle start must never produce a confirmed-executed conclusion.")}},
	}
}

func TestAssembleCandidateRegeneratesSyntheticUnitDeterministically(t *testing.T) {
	ctx := context.Background()
	repo := newSyntheticReviewRepo(t, "standard-v0.2")
	// Remove every derived file so the assembler must regenerate it.
	for _, name := range []string{"packet.json", "validation.json", "expected-findings.json", CandidateManifestName} {
		if err := os.Remove(filepath.Join(repo.candidate, name)); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.RemoveAll(filepath.Join(repo.candidate, "fixtures", "scenarios")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(repo.candidate, "fixtures", "index.json")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(repo.candidate, "fixtures", FixtureManifestName)); err != nil {
		t.Fatal(err)
	}
	input := AuthoringInput{
		CandidateContent: repo.candidate, RepositoryPolicy: filepath.Join(repo.root, "pack-review-policy.json"),
		Scenarios: syntheticAuthoredScenarios(t), ReviewPolicyProfile: "standard-v0.2",
		Preparation: repo.unitValue.Pack.Preparation,
	}
	first, err := AssembleCandidate(ctx, input)
	if err != nil {
		t.Fatalf("assemble: %v", err)
	}
	manifest, err := os.ReadFile(filepath.Join(repo.candidate, CandidateManifestName))
	if err != nil {
		t.Fatal(err)
	}
	second, err := AssembleCandidate(ctx, input)
	if err != nil {
		t.Fatal(err)
	}
	again, err := os.ReadFile(filepath.Join(repo.candidate, CandidateManifestName))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first, second) || string(manifest) != string(again) {
		t.Fatal("assembly is not deterministic")
	}
	if first.CanonicalPackSHA256 != repo.unitValue.Pack.CanonicalPackSHA256 || first.ClaimsSHA256 != repo.unitValue.Pack.ClaimsSHA256 {
		t.Fatal("assembled packet does not bind the hand-authored inputs")
	}
	if first.CandidateManifestSHA256Unbound() {
		t.Fatal("packet must not carry its own manifest hash")
	}
	unit, err := ValidateUnit(ctx, repo.unit, syntheticCommit)
	if err != nil {
		t.Fatalf("assembled unit must validate: %v", err)
	}
	if unit.CandidateManifestSHA256 == "" {
		t.Fatal("validated unit lacks a manifest hash")
	}
	expectedRaw, err := os.ReadFile(filepath.Join(repo.candidate, "expected-findings.json"))
	if err != nil {
		t.Fatal(err)
	}
	var oracle ExpectedFindings
	if err := json.Unmarshal(expectedRaw, &oracle); err != nil {
		t.Fatal(err)
	}
	downloaded, executedInDownloadScenario := false, false
	for _, row := range oracle.Findings {
		if row.State == model.ConfirmedDownloaded {
			downloaded = true
		}
		if row.ScenarioID == syntheticDownloadScenario && row.State == model.ConfirmedExecuted {
			executedInDownloadScenario = true
		}
	}
	if !downloaded || executedInDownloadScenario || len(oracle.Forbidden) != 1 || oracle.Forbidden[0].ScenarioID != syntheticDownloadScenario {
		t.Fatalf("expected findings are not the replayed oracle: %s", expectedRaw)
	}

	poisoned := syntheticAuthoredScenarios(t)
	poisoned[0].Forbidden = []ForbiddenExpectedFinding{ForbiddenStateFor(syntheticCompleteScenario, model.ConfirmedExecuted, "synthetic contradiction")}
	input.Scenarios = poisoned
	if _, err := AssembleCandidate(ctx, input); err == nil || !strings.Contains(err.Error(), "forbidden state") {
		t.Fatalf("forbidden derived state was not rejected: %v", err)
	}
	input.Scenarios = syntheticAuthoredScenarios(t)
	if _, err := AssembleCandidate(ctx, input); err != nil {
		t.Fatal(err)
	}
	claims := filepath.Join(repo.candidate, "claims.json")
	data, err := os.ReadFile(claims)
	if err != nil {
		t.Fatal(err)
	}
	mustWrite(t, claims, append(data, '\n'))
	if _, err := ValidateUnit(ctx, repo.unit, syntheticCommit); err == nil {
		t.Fatal("post-assembly ledger edit validated")
	}
	if _, err := AssembleCandidate(ctx, AuthoringInput{CandidateContent: filepath.Join(repo.root, "missing"), RepositoryPolicy: input.RepositoryPolicy, Scenarios: input.Scenarios, ReviewPolicyProfile: "standard-v0.2", Preparation: input.Preparation}); err == nil {
		t.Fatal("missing candidate directory accepted")
	}
	if _, err := AssembleCandidate(ctx, AuthoringInput{CandidateContent: repo.candidate, RepositoryPolicy: input.RepositoryPolicy, ReviewPolicyProfile: "standard-v0.2", Preparation: input.Preparation}); err == nil {
		t.Fatal("assembly without fixture scenarios accepted")
	}
}

// CandidateManifestSHA256Unbound reports whether a packet wrongly carries a
// manifest hash; the packet is a hash input of that manifest.
func (p Packet) CandidateManifestSHA256Unbound() bool {
	return strings.Contains(strings.ToLower(p.ReviewUnitPackPath), "manifest")
}
