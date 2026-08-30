package packreview

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestCandidateReviewPolicyRotationUsesCurrentForActiveCandidates(t *testing.T) {
	t.Run("unregistered candidate rejects stale retained policy", func(t *testing.T) {
		repo := newSyntheticReviewRepo(t, StandardPolicyProfile)
		mustWrite(t, filepath.Join(repo.root, "pack-review-policy.json"), rotatedSyntheticPolicy(t))

		err := ValidateCandidateTree(context.Background(), repo.root, syntheticCommit)
		assertProblemCode(t, err, "CANDIDATE_POLICY_STALE")
	})

	for _, status := range []string{"candidate", "review_in_progress"} {
		t.Run("registered "+status+" rejects stale retained policy", func(t *testing.T) {
			repo := newSyntheticReviewRepo(t, StandardPolicyProfile)
			registry := syntheticCandidateRegistry(repo)
			if status == "review_in_progress" {
				inProgress := registry.Records[len(registry.Records)-1]
				inProgress.RecordID = "synthetic-candidate-3"
				inProgress.PreviousRecordID = registry.Records[len(registry.Records)-1].RecordID
				inProgress.Status = status
				inProgress.RecordedAt = "2026-08-21T00:00:00Z"
				registry.Records = append(registry.Records, inProgress)
			}
			mustWrite(t, filepath.Join(repo.root, "review-registry.json"), mustCanonical(t, registry))
			mustWrite(t, filepath.Join(repo.root, "pack-review-policy.json"), rotatedSyntheticPolicy(t))

			err := ValidateCandidateTree(context.Background(), repo.root, syntheticCommit)
			assertProblemCode(t, err, "CANDIDATE_POLICY_STALE")
		})
	}
}

func TestPrePromotionWithdrawnRecordSurvivesCurrentReviewPolicyRotation(t *testing.T) {
	repo := newSyntheticReviewRepo(t, StandardPolicyProfile)
	registry := syntheticCandidateRegistry(repo)
	withdrawn := registry.Records[len(registry.Records)-1]
	withdrawn.RecordID = "synthetic-candidate-withdrawn"
	withdrawn.PreviousRecordID = registry.Records[len(registry.Records)-1].RecordID
	withdrawn.Status = "withdrawn"
	withdrawn.RecordedAt = "2026-08-21T00:00:00Z"
	withdrawn.WithdrawalReason = "Synthetic pre-promotion withdrawal after policy rotation."
	registry.Records = append(registry.Records, withdrawn)
	mustWrite(t, filepath.Join(repo.root, "review-registry.json"), mustCanonical(t, registry))
	mustWrite(t, filepath.Join(repo.root, "pack-review-policy.json"), rotatedSyntheticPolicy(t))

	if err := ValidateCandidateTree(context.Background(), repo.root, syntheticCommit); err != nil {
		t.Fatalf("current review-policy rotation invalidated pre-promotion withdrawn tombstone: %v", err)
	}
}

func TestRegistryReviewPolicyHashBindsRetainedPolicy(t *testing.T) {
	repo := newSyntheticReviewRepo(t, StandardPolicyProfile)
	mustWrite(t, filepath.Join(repo.root, "review-registry.json"), mustCanonical(t, syntheticCandidateRegistry(repo)))

	rotated := rotatedSyntheticPolicy(t)
	mustWrite(t, filepath.Join(repo.candidate, "review-policy.json"), rotated)
	packet := repo.unitValue.Pack
	packet.ReviewPolicySHA256 = digestHex(rotated)
	mustWrite(t, filepath.Join(repo.candidate, "packet.json"), mustCanonical(t, packet))
	if _, err := BuildCandidateManifest(context.Background(), repo.candidate, filepath.Join(repo.candidate, CandidateManifestName)); err != nil {
		t.Fatal(err)
	}

	err := ValidateCandidateTree(context.Background(), repo.root, syntheticCommit)
	assertProblemCode(t, err, "REGISTRY_CANDIDATE_POLICY_DRIFT")
}

func TestReviewedRecordSurvivesCurrentReviewPolicyRotation(t *testing.T) {
	repo := newSyntheticReviewRepo(t, StandardPolicyProfile)
	addSyntheticApprovals(t, &repo, 1)
	promotionCommit := stringOf('f', 40)
	promotion, err := Promote(context.Background(), PromotionOptions{
		ReviewUnitRoot: repo.unit, RepositoryRoot: repo.root, CandidateCommit: syntheticCommit,
		CandidateManifest: repo.unitValue.CandidateManifestSHA256, PlatformSnapshot: repo.snapshot,
		PromotedAt: "2026-08-21T00:05:00Z",
	})
	if err != nil {
		t.Fatal(err)
	}
	reviewManifest, err := os.ReadFile(filepath.Join(repo.unit, ReviewManifestName))
	if err != nil {
		t.Fatal(err)
	}
	identity := RegistryRecord{
		IncidentID: promotion.IncidentID, PackVersion: promotion.PackVersion, CandidateCommit: syntheticCommit,
		OriginalPackSHA256: promotion.OriginalPackSHA256, CanonicalPackSHA256: promotion.CanonicalPackSHA256,
		CandidateManifestSHA256: promotion.CandidateManifestSHA256, ReviewPolicyProfile: promotion.ReviewPolicyProfile,
		ReviewPolicySHA256: promotion.ReviewPolicySHA256, ApprovalIDs: []string{},
	}
	research := RegistryRecord{RecordID: "synthetic-policy-rotation-1", IncidentID: promotion.IncidentID,
		PackVersion: promotion.PackVersion, Status: "research", ApprovalIDs: []string{}, RecordedAt: "2026-08-19T00:00:00Z"}
	candidate := identity
	candidate.RecordID, candidate.PreviousRecordID, candidate.Status, candidate.RecordedAt = "synthetic-policy-rotation-2", research.RecordID, "candidate", "2026-08-20T00:00:00Z"
	inProgress := identity
	inProgress.RecordID, inProgress.PreviousRecordID, inProgress.Status, inProgress.RecordedAt = "synthetic-policy-rotation-3", candidate.RecordID, "review_in_progress", "2026-08-21T00:00:00Z"
	reviewed := identity
	reviewed.RecordID, reviewed.PreviousRecordID, reviewed.Status, reviewed.RecordedAt = "synthetic-policy-rotation-4", inProgress.RecordID, "reviewed", "2026-08-22T00:00:00Z"
	reviewed.PromotionContentCommit = promotionCommit
	reviewed.ReviewedPath = promotion.ReviewedPath
	reviewed.ReviewRecordManifestSHA256 = digestHex(reviewManifest)
	reviewed.ApprovalIDs = promotion.ApprovalIDs
	mustWrite(t, filepath.Join(repo.root, "review-registry.json"), mustCanonical(t, Registry{
		SchemaVersion: RegistrySchema, Records: []RegistryRecord{research, candidate, inProgress, reviewed},
	}))

	mustWrite(t, filepath.Join(repo.root, "pack-review-policy.json"), rotatedSyntheticPolicy(t))
	if err := VerifyRegistry(context.Background(), repo.root, promotionCommit); err != nil {
		t.Fatalf("current review-policy rotation invalidated reviewed historical record: %v", err)
	}
}

func TestPromoteRejectsStaleRetainedReviewPolicyBeforeOutput(t *testing.T) {
	repo := newSyntheticReviewRepo(t, StandardPolicyProfile)
	addSyntheticApprovals(t, &repo, 1)
	mustWrite(t, filepath.Join(repo.root, "pack-review-policy.json"), rotatedSyntheticPolicy(t))

	_, err := Promote(context.Background(), PromotionOptions{
		ReviewUnitRoot: repo.unit, RepositoryRoot: repo.root, CandidateCommit: syntheticCommit,
		CandidateManifest: repo.unitValue.CandidateManifestSHA256, PlatformSnapshot: repo.snapshot,
		PromotedAt: "2026-08-21T00:05:00Z",
	})
	assertProblemCode(t, err, "PROMOTION_POLICY_STALE")
	for _, path := range []string{
		filepath.Join(repo.unit, "promotion-record.json"),
		reviewedPackPath(repo.root, repo.unitValue.Pack.IncidentID, repo.unitValue.Pack.PackVersion),
	} {
		if _, statErr := os.Lstat(path); !os.IsNotExist(statErr) {
			t.Fatalf("stale-policy promotion created output %s: %v", path, statErr)
		}
	}
}

func TestPromoteRequiresCanonicalValidRepositoryReviewPolicy(t *testing.T) {
	tests := []struct {
		name string
		code string
		edit func(t *testing.T, repo syntheticReviewRepo)
	}{
		{
			name: "noncanonical", code: "NON_CANONICAL_JSON",
			edit: func(t *testing.T, repo syntheticReviewRepo) {
				t.Helper()
				path := filepath.Join(repo.root, "pack-review-policy.json")
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				mustWrite(t, path, append(data, '\n'))
			},
		},
		{
			name: "semantically invalid", code: "SAFE_ID",
			edit: func(t *testing.T, repo syntheticReviewRepo) {
				t.Helper()
				policy := syntheticPolicy()
				policy.PolicyVersion = ""
				mustWrite(t, filepath.Join(repo.root, "pack-review-policy.json"), mustCanonical(t, policy))
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			repo := newSyntheticReviewRepo(t, StandardPolicyProfile)
			test.edit(t, repo)

			_, err := Promote(context.Background(), PromotionOptions{
				ReviewUnitRoot: repo.unit, RepositoryRoot: repo.root, CandidateCommit: syntheticCommit,
				CandidateManifest: repo.unitValue.CandidateManifestSHA256, PlatformSnapshot: repo.snapshot,
				PromotedAt: "2026-08-21T00:05:00Z",
			})
			assertProblemCode(t, err, test.code)
			if _, statErr := os.Lstat(filepath.Join(repo.unit, "promotion-record.json")); !os.IsNotExist(statErr) {
				t.Fatalf("invalid current policy created a promotion record: %v", statErr)
			}
		})
	}
}

func rotatedSyntheticPolicy(t *testing.T) []byte {
	t.Helper()
	policy := syntheticPolicy()
	policy.PolicyVersion = "synthetic-policy-v2"
	return mustCanonical(t, policy)
}
