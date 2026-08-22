package match

import (
	"strings"
	"testing"

	"github.com/torjan0/cirewind/internal/model"
)

func TestDeriveEveryCanonicalState(t *testing.T) {
	evidence := []model.EvidenceID{model.EvidenceID("ev1:" + strings.Repeat("1", 64))}
	coverage := []model.CoverageAssessmentID{model.CoverageAssessmentID("cova1:" + strings.Repeat("2", 64))}
	tests := []struct {
		name string
		in   Candidate
		want model.FindingState
	}{
		{"executed", Candidate{SameAttemptExactRuntime: true, PreparationCompleted: true, LifecycleStarted: true, EvidenceIDs: evidence}, model.ConfirmedExecuted},
		{"downloaded", Candidate{SameAttemptExactRuntime: true, PreparationCompleted: true, EvidenceIDs: evidence}, model.ConfirmedDownloaded},
		{"called workflow", Candidate{ExactCalledWorkflow: true, EvidenceIDs: evidence}, model.ConfirmedCalledWorkflow},
		{"declared", Candidate{HistoricalExactDeclared: true, EvidenceIDs: evidence}, model.DeclaredAtRunSHA},
		{"mutable", Candidate{HistoricalMutableRef: true, RunEventInWindow: true, EvidenceIDs: evidence}, model.RunInWindowMutableRef},
		{"transitive", Candidate{PotentialTransitive: true, EvidenceIDs: evidence}, model.PotentialTransitive},
		{"current", Candidate{CurrentReferenceOnly: true, EvidenceIDs: evidence}, model.CurrentReferenceOnly},
		{"no match", Candidate{RequiredCoverageClosed: true, EvidenceIDs: evidence, CoverageIDs: coverage}, model.NoMatchConfirmed},
		{"gap", Candidate{MaterialEvidenceGap: true}, model.UnknownEvidenceGap},
		{"contradiction", Candidate{MaterialContradiction: true, SameAttemptExactRuntime: true, LifecycleStarted: true, EvidenceIDs: evidence}, model.ContradictoryEvidence},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Derive(tt.in)
			if err != nil {
				t.Fatal(err)
			}
			if got.State != tt.want {
				t.Fatalf("state = %s, want %s", got.State, tt.want)
			}
			if err := ValidateEvidenceSupport(tt.in, got); err != nil && tt.want != model.UnknownEvidenceGap {
				t.Fatalf("support: %v", err)
			}
		})
	}
}

func TestDownloadAnnouncementIsNotDownloaded(t *testing.T) {
	got, err := Derive(Candidate{SameAttemptExactRuntime: true, DownloadAnnouncedOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	if got.State != model.UnknownEvidenceGap {
		t.Fatalf("announcement-only state = %s", got.State)
	}
}

func TestLifecycleWithoutSameAttemptIdentityIsNotExecuted(t *testing.T) {
	got, err := Derive(Candidate{LifecycleStarted: true, MaterialEvidenceGap: true})
	if err != nil {
		t.Fatal(err)
	}
	if got.State != model.UnknownEvidenceGap {
		t.Fatalf("uncorrelated lifecycle state = %s", got.State)
	}
}

func TestKnownGoodExactIdentityDefeatsMutableInference(t *testing.T) {
	evidence := []model.EvidenceID{model.EvidenceID("ev1:" + strings.Repeat("1", 64))}
	coverage := []model.CoverageAssessmentID{model.CoverageAssessmentID("cova1:" + strings.Repeat("2", 64))}
	got, err := Derive(Candidate{
		SameAttemptExactRuntime: true, KnownGoodExactRuntime: true,
		HistoricalMutableRef: true, RunEventInWindow: true,
		RequiredCoverageClosed: true, EvidenceIDs: evidence, CoverageIDs: coverage,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.State != model.NoMatchConfirmed {
		t.Fatalf("state = %s", got.State)
	}
}

func TestNoMatchRequiresClosureEvidence(t *testing.T) {
	_, err := Derive(Candidate{RequiredCoverageClosed: true})
	if err == nil {
		t.Fatal("expected closure-evidence error")
	}
}
