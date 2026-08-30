package packreview

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestRegistryValidationRejectsBrokenChains(t *testing.T) {
	base := RegistryRecord{RecordID: "synthetic-research", IncidentID: "CIR-SYNTHETIC", PackVersion: "1.0.0", Status: "research", ApprovalIDs: []string{}, RecordedAt: "2026-08-20T00:00:00Z"}
	tests := []struct {
		name    string
		records []RegistryRecord
		code    string
	}{
		{"invalid start", []RegistryRecord{{RecordID: "bad", IncidentID: "CIR-SYNTHETIC", PackVersion: "1.0.0", Status: "candidate", ApprovalIDs: []string{}, RecordedAt: "2026-08-20T00:00:00Z"}}, "REGISTRY_CHAIN_START"},
		{"forbidden transition", []RegistryRecord{base, {RecordID: "bad", PreviousRecordID: base.RecordID, IncidentID: base.IncidentID, PackVersion: base.PackVersion, Status: "reviewed", ApprovalIDs: []string{}, RecordedAt: "2026-08-21T00:00:00Z"}}, "REGISTRY_TRANSITION"},
		{"wrong predecessor", []RegistryRecord{base, {RecordID: "bad", PreviousRecordID: "other", IncidentID: base.IncidentID, PackVersion: base.PackVersion, Status: "candidate", ApprovalIDs: []string{}, RecordedAt: "2026-08-21T00:00:00Z"}}, "REGISTRY_PREDECESSOR"},
		{"time reversal", []RegistryRecord{base, {RecordID: "next", PreviousRecordID: base.RecordID, IncidentID: base.IncidentID, PackVersion: base.PackVersion, Status: "candidate", ApprovalIDs: []string{}, RecordedAt: "2026-08-19T00:00:00Z"}}, "REGISTRY_TIME_ORDER"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var got problems
			validateRegistry(Registry{SchemaVersion: RegistrySchema, Records: test.records}, &got)
			assertProblemCode(t, got.err(), test.code)
		})
	}
}

func TestRegistryValidationRejectsMutableOrPrematureSupersession(t *testing.T) {
	repo := newSyntheticReviewRepo(t, StandardPolicyProfile)
	registry := syntheticCandidateRegistry(repo)
	registry.Records[0].SupersedesPackVersion = "0.9.0"
	var got problems
	validateRegistry(registry, &got)
	assertProblemCode(t, got.err(), "RESEARCH_FIELDS")

	registry = syntheticCandidateRegistry(repo)
	registry.Records[1].SupersedesPackVersion = "0.9.0"
	got = problems{}
	validateRegistry(registry, &got)
	assertProblemCode(t, got.err(), "PREPROMOTION_FIELDS")
}

func TestVerifyRegistrySyntheticPromotionAndTamper(t *testing.T) {
	repo := newSyntheticReviewRepo(t, StandardPolicyProfile)
	addSyntheticApprovals(t, &repo, 1)
	promotionCommit := stringOf('f', 40)
	promotion, err := Promote(context.Background(), PromotionOptions{ReviewUnitRoot: repo.unit, RepositoryRoot: repo.root, CandidateCommit: syntheticCommit,
		CandidateManifest: repo.unitValue.CandidateManifestSHA256, PlatformSnapshot: repo.snapshot, PromotedAt: "2026-08-21T00:05:00Z"})
	if err != nil {
		t.Fatal(err)
	}
	reviewManifest, err := os.ReadFile(filepath.Join(repo.unit, ReviewManifestName))
	if err != nil {
		t.Fatal(err)
	}
	identity := RegistryRecord{IncidentID: promotion.IncidentID, PackVersion: promotion.PackVersion, CandidateCommit: syntheticCommit,
		OriginalPackSHA256: promotion.OriginalPackSHA256, CanonicalPackSHA256: promotion.CanonicalPackSHA256,
		CandidateManifestSHA256: promotion.CandidateManifestSHA256, ReviewPolicyProfile: promotion.ReviewPolicyProfile,
		ReviewPolicySHA256: promotion.ReviewPolicySHA256, ApprovalIDs: []string{}}
	research := RegistryRecord{RecordID: "synthetic-registry-1", IncidentID: promotion.IncidentID, PackVersion: promotion.PackVersion, Status: "research", ApprovalIDs: []string{}, RecordedAt: "2026-08-19T00:00:00Z"}
	candidate := identity
	candidate.RecordID = "synthetic-registry-2"
	candidate.PreviousRecordID = research.RecordID
	candidate.Status = "candidate"
	candidate.RecordedAt = "2026-08-20T00:00:00Z"
	inProgress := identity
	inProgress.RecordID = "synthetic-registry-3"
	inProgress.PreviousRecordID = candidate.RecordID
	inProgress.Status = "review_in_progress"
	inProgress.RecordedAt = "2026-08-21T00:00:00Z"
	reviewed := identity
	reviewed.RecordID = "synthetic-registry-4"
	reviewed.PreviousRecordID = inProgress.RecordID
	reviewed.Status = "reviewed"
	reviewed.RecordedAt = "2026-08-22T00:00:00Z"
	reviewed.PromotionContentCommit = promotionCommit
	reviewed.ReviewedPath = promotion.ReviewedPath
	reviewed.ReviewRecordManifestSHA256 = digestHex(reviewManifest)
	reviewed.ApprovalIDs = promotion.ApprovalIDs
	registry := Registry{SchemaVersion: RegistrySchema, Records: []RegistryRecord{research, candidate, inProgress, reviewed}}
	mustWrite(t, filepath.Join(repo.root, "review-registry.json"), mustCanonical(t, registry))
	if err := VerifyRegistry(context.Background(), repo.root, promotionCommit); err != nil {
		t.Fatalf("valid synthetic registry: %v", err)
	}

	mustWrite(t, reviewedPackPath(repo.root, promotion.IncidentID, promotion.PackVersion), []byte("tampered\n"))
	err = VerifyRegistry(context.Background(), repo.root, promotionCommit)
	assertProblemCode(t, err, "REGISTRY_REVIEWED_PACK_DRIFT")
}

func TestValidateCandidateTreeDiscoversUnregisteredReviewUnits(t *testing.T) {
	repo := newSyntheticReviewRepo(t, StandardPolicyProfile)
	if err := ValidateCandidateTree(context.Background(), repo.root, syntheticCommit); err != nil {
		t.Fatalf("valid synthetic candidate governance: %v", err)
	}

	mustWrite(t, filepath.Join(repo.candidate, "expected-findings.json"), []byte("tampered\n"))
	err := ValidateCandidateTree(context.Background(), repo.root, syntheticCommit)
	assertProblemCode(t, err, "INVALID_CANDIDATE_REVIEW_UNIT")
}

func TestValidateGovernanceDoesNotCreateCandidateCommitCycle(t *testing.T) {
	repo := newSyntheticReviewRepo(t, StandardPolicyProfile)
	if err := ValidateGovernance(context.Background(), repo.root); err != nil {
		t.Fatalf("baseline governance must permit an unregistered candidate whose C is supplied only to candidate CI: %v", err)
	}
}

func TestValidateGovernanceRequiresRetainedCandidateReviewUnit(t *testing.T) {
	repo := newSyntheticReviewRepo(t, StandardPolicyProfile)
	root := t.TempDir()
	policy, err := os.ReadFile(filepath.Join(repo.root, "pack-review-policy.json"))
	if err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(root, "pack-review-policy.json"), policy)
	mustWrite(t, filepath.Join(root, "review-registry.json"), mustCanonical(t, syntheticCandidateRegistry(repo)))
	err = ValidateGovernance(context.Background(), root)
	assertProblemCode(t, err, "MISSING_REVIEW_PACKET")
}

func TestValidateCandidateTreeRejectsOrphanAndMissingCandidateCopies(t *testing.T) {
	t.Run("missing", func(t *testing.T) {
		repo := newSyntheticReviewRepo(t, StandardPolicyProfile)
		if err := os.Remove(candidatePackPath(repo.root, repo.unitValue.Pack.IncidentID, repo.unitValue.Pack.PackVersion)); err != nil {
			t.Fatal(err)
		}
		err := ValidateCandidateTree(context.Background(), repo.root, syntheticCommit)
		assertProblemCode(t, err, "MISSING_CANDIDATE_COPY")
	})
	t.Run("orphan", func(t *testing.T) {
		repo := newSyntheticReviewRepo(t, StandardPolicyProfile)
		orphanRoot := filepath.Join(repo.root, "incidents", "candidates", "synthetic-orphan")
		mustMkdir(t, orphanRoot)
		mustWrite(t, filepath.Join(orphanRoot, "1.0.0.yaml"), []byte("synthetic: inert\n"))
		err := ValidateCandidateTree(context.Background(), repo.root, syntheticCommit)
		assertProblemCode(t, err, "ORPHAN_CANDIDATE_COPY")
	})
	t.Run("hard link alias", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("hard-link permission and semantics vary on Windows")
		}
		repo := newSyntheticReviewRepo(t, StandardPolicyProfile)
		copyPath := candidatePackPath(repo.root, repo.unitValue.Pack.IncidentID, repo.unitValue.Pack.PackVersion)
		if err := os.Remove(copyPath); err != nil {
			t.Fatal(err)
		}
		if err := os.Link(filepath.Join(repo.candidate, "pack.yaml"), copyPath); err != nil {
			t.Fatal(err)
		}
		_, err := ValidateUnit(context.Background(), repo.unit, syntheticCommit)
		assertProblemCode(t, err, "CANDIDATE_COPY_HARDLINK")
	})
}

func syntheticCandidateRegistry(repo syntheticReviewRepo) Registry {
	research := RegistryRecord{RecordID: "synthetic-candidate-1", IncidentID: repo.unitValue.Pack.IncidentID,
		PackVersion: repo.unitValue.Pack.PackVersion, Status: "research", ApprovalIDs: []string{}, RecordedAt: "2026-08-19T00:00:00Z"}
	candidate := RegistryRecord{RecordID: "synthetic-candidate-2", PreviousRecordID: research.RecordID,
		IncidentID: repo.unitValue.Pack.IncidentID, PackVersion: repo.unitValue.Pack.PackVersion, Status: "candidate",
		CandidateCommit: syntheticCommit, OriginalPackSHA256: repo.unitValue.Pack.OriginalPackSHA256,
		CanonicalPackSHA256: repo.unitValue.Pack.CanonicalPackSHA256, CandidateManifestSHA256: repo.unitValue.CandidateManifestSHA256,
		ApprovalIDs: []string{}, ReviewPolicyProfile: repo.unitValue.Pack.ReviewPolicyProfile,
		ReviewPolicySHA256: repo.unitValue.Pack.ReviewPolicySHA256, RecordedAt: "2026-08-20T00:00:00Z"}
	return Registry{SchemaVersion: RegistrySchema, Records: []RegistryRecord{research, candidate}}
}
