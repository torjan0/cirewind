package packreview

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestCheckApprovalsSyntheticStandardPolicy(t *testing.T) {
	repo := newSyntheticReviewRepo(t, StandardPolicyProfile)
	addSyntheticApprovals(t, &repo, 1)
	result, err := CheckApprovals(context.Background(), repo.unit, syntheticCommit, repo.unitValue.CandidateManifestSHA256, repo.snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if result.Statement != policyResultStatement || len(result.QualifyingApprovalIDs) != 3 {
		t.Fatalf("unexpected policy result: %+v", result)
	}
	if !equalStrings(result.QualifyingApprovalIDs, []string{"synthetic-review-1", "synthetic-review-2", "synthetic-review-3"}) {
		t.Fatalf("approval IDs not stable: %v", result.QualifyingApprovalIDs)
	}
}

func TestCheckApprovalsFailureMatrix(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*testing.T, *syntheticReviewRepo)
		code   string
	}{
		{"stale candidate manifest", func(t *testing.T, repo *syntheticReviewRepo) {}, "STALE_CANDIDATE_MANIFEST"},
		{"self review", func(t *testing.T, repo *syntheticReviewRepo) {
			mutateSyntheticReview(t, repo, "synthetic-review-3", func(review *Review) { review.Reviewer = HumanIdentity{Login: "synthetic-author", DatabaseID: 100} })
			mutateSyntheticSnapshot(t, repo, func(snapshot *PlatformApprovalSnapshot) {
				snapshot.Approvals[2].Reviewer = PlatformActor{Login: "synthetic-author", DatabaseID: 100}
			})
		}, "SELF_REVIEW"},
		{"bot account", func(t *testing.T, repo *syntheticReviewRepo) {
			mutateSyntheticSnapshot(t, repo, func(snapshot *PlatformApprovalSnapshot) { snapshot.Approvals[2].AccountType = "Bot" })
		}, "AUTOMATED_REVIEWER"},
		{"revoked latest approval", func(t *testing.T, repo *syntheticReviewRepo) {
			mutateSyntheticSnapshot(t, repo, func(snapshot *PlatformApprovalSnapshot) {
				base := snapshot.Approvals[2]
				base.ReviewDatabaseID = 2001
				base.ReviewURL = "https://github.com/example/cirewind/pull/7#pullrequestreview-2001"
				base.State = "CHANGES_REQUESTED"
				base.SubmittedAt = "2026-08-21T00:00:30Z"
				snapshot.Approvals = append(snapshot.Approvals, base)
			})
		}, "STALE_OR_REVOKED_REVIEW"},
		{"stale platform head", func(t *testing.T, repo *syntheticReviewRepo) {
			mutateSyntheticSnapshot(t, repo, func(snapshot *PlatformApprovalSnapshot) { snapshot.CandidateCommit = stringOf('d', 40) })
		}, "STALE_PLATFORM_HEAD"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			repo := newSyntheticReviewRepo(t, StandardPolicyProfile)
			addSyntheticApprovals(t, &repo, 1)
			test.mutate(t, &repo)
			manifest := repo.unitValue.CandidateManifestSHA256
			if test.name == "stale candidate manifest" {
				manifest = stringOf('e', 64)
			}
			_, err := CheckApprovals(context.Background(), repo.unit, syntheticCommit, manifest, repo.snapshot)
			assertProblemCode(t, err, test.code)
		})
	}
}

func TestCheckApprovalsRejectsMissingOutsideAndStaleBinding(t *testing.T) {
	t.Run("missing outside reviewer", func(t *testing.T) {
		repo := newSyntheticReviewRepo(t, StandardPolicyProfile)
		addSyntheticApprovals(t, &repo, 0)
		_, err := CheckApprovals(context.Background(), repo.unit, syntheticCommit, repo.unitValue.CandidateManifestSHA256, repo.snapshot)
		assertProblemCode(t, err, "OUTSIDE_APPROVAL_COUNT")
	})
	t.Run("stale hash binding", func(t *testing.T) {
		repo := newSyntheticReviewRepo(t, StandardPolicyProfile)
		addSyntheticApprovals(t, &repo, 1)
		mutateSyntheticReview(t, &repo, "synthetic-review-3", func(review *Review) { review.Bindings.ClaimsSHA256 = stringOf('9', 64) })
		_, err := CheckApprovals(context.Background(), repo.unit, syntheticCommit, repo.unitValue.CandidateManifestSHA256, repo.snapshot)
		assertProblemCode(t, err, "STALE_REVIEW_BINDING")
	})
}

func TestTrivyPolicyRequiresTwoFullyScopedSyntheticOutsiders(t *testing.T) {
	repo := newSyntheticReviewRepo(t, TrivyPolicyProfile)
	addSyntheticApprovals(t, &repo, 2)
	if _, err := CheckApprovals(context.Background(), repo.unit, syntheticCommit, repo.unitValue.CandidateManifestSHA256, repo.snapshot); err != nil {
		t.Fatalf("valid synthetic Trivy review: %v", err)
	}
	mutateSyntheticReview(t, &repo, "synthetic-review-4", func(review *Review) { review.Scopes = []string{"time"} })
	_, err := CheckApprovals(context.Background(), repo.unit, syntheticCommit, repo.unitValue.CandidateManifestSHA256, repo.snapshot)
	assertProblemCode(t, err, "TRIVY_OUTSIDE_SCOPE")
}

func TestPromotionIsIdempotentAndRefusesOverwrite(t *testing.T) {
	repo := newSyntheticReviewRepo(t, StandardPolicyProfile)
	addSyntheticApprovals(t, &repo, 1)
	options := PromotionOptions{ReviewUnitRoot: repo.unit, RepositoryRoot: repo.root, CandidateCommit: syntheticCommit,
		CandidateManifest: repo.unitValue.CandidateManifestSHA256, PlatformSnapshot: repo.snapshot, PromotedAt: "2026-08-21T00:05:00Z"}
	first, err := Promote(context.Background(), options)
	if err != nil {
		t.Fatal(err)
	}
	firstManifest, err := os.ReadFile(filepath.Join(repo.unit, ReviewManifestName))
	if err != nil {
		t.Fatal(err)
	}
	second, err := Promote(context.Background(), options)
	if err != nil {
		t.Fatalf("idempotent promotion: %v", err)
	}
	secondManifest, _ := os.ReadFile(filepath.Join(repo.unit, ReviewManifestName))
	if !reflect.DeepEqual(first, second) || !bytes.Equal(firstManifest, secondManifest) {
		t.Fatal("identical promotion was not byte-idempotent")
	}

	reviewed := reviewedPackPath(repo.root, first.IncidentID, first.PackVersion)
	mustWrite(t, reviewed, []byte("different immutable content\n"))
	_, err = Promote(context.Background(), options)
	assertProblemCode(t, err, "IMMUTABLE_OUTPUT_EXISTS")
}

func TestPromotionRejectsReviewedPackHardLinkAliases(t *testing.T) {
	for _, test := range []struct {
		name   string
		source func(syntheticReviewRepo) string
	}{
		{
			name: "candidate content",
			source: func(repo syntheticReviewRepo) string {
				return filepath.Join(repo.candidate, "pack.yaml")
			},
		},
		{
			name: "candidate copy",
			source: func(repo syntheticReviewRepo) string {
				return candidatePackPath(repo.root, repo.unitValue.Pack.IncidentID, repo.unitValue.Pack.PackVersion)
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			repo := newSyntheticReviewRepo(t, StandardPolicyProfile)
			addSyntheticApprovals(t, &repo, 1)
			reviewed := reviewedPackPath(repo.root, repo.unitValue.Pack.IncidentID, repo.unitValue.Pack.PackVersion)
			mustMkdir(t, filepath.Dir(reviewed))
			if err := os.Link(test.source(repo), reviewed); err != nil {
				t.Skipf("hard links unavailable: %v", err)
			}

			_, err := Promote(context.Background(), PromotionOptions{
				ReviewUnitRoot: repo.unit, RepositoryRoot: repo.root, CandidateCommit: syntheticCommit,
				CandidateManifest: repo.unitValue.CandidateManifestSHA256, PlatformSnapshot: repo.snapshot,
				PromotedAt: "2026-08-21T00:05:00Z",
			})
			assertProblemCode(t, err, "PROMOTION_OUTPUT_ALIAS")
			for _, name := range []string{"promotion-record.json", ReviewManifestName} {
				if _, statErr := os.Stat(filepath.Join(repo.unit, name)); !os.IsNotExist(statErr) {
					t.Fatalf("promotion output %s unexpectedly exists: %v", name, statErr)
				}
			}
		})
	}
}

func TestPromotionRejectsInvalidRecordedSnapshotChronology(t *testing.T) {
	for _, test := range []struct {
		name, promotedAt, code string
	}{
		{"outside recorded interval", "2026-08-21T00:16:01Z", "PROMOTION_INTERVAL"},
		{"predates observation", "2026-08-21T00:00:59Z", "PROMOTION_TIME_ORDER"},
	} {
		t.Run(test.name, func(t *testing.T) {
			repo := newSyntheticReviewRepo(t, StandardPolicyProfile)
			addSyntheticApprovals(t, &repo, 1)
			_, err := Promote(context.Background(), PromotionOptions{ReviewUnitRoot: repo.unit, RepositoryRoot: repo.root, CandidateCommit: syntheticCommit,
				CandidateManifest: repo.unitValue.CandidateManifestSHA256, PlatformSnapshot: repo.snapshot, PromotedAt: test.promotedAt})
			assertProblemCode(t, err, test.code)
		})
	}
}

func TestPromotionCancellationHasNoOutputs(t *testing.T) {
	repo := newSyntheticReviewRepo(t, StandardPolicyProfile)
	addSyntheticApprovals(t, &repo, 1)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := Promote(ctx, PromotionOptions{ReviewUnitRoot: repo.unit, RepositoryRoot: repo.root, CandidateCommit: syntheticCommit,
		CandidateManifest: repo.unitValue.CandidateManifestSHA256, PlatformSnapshot: repo.snapshot, PromotedAt: "2026-08-21T00:05:00Z"})
	if err != context.Canceled {
		t.Fatalf("got %v, want canceled", err)
	}
	if _, err := os.Stat(filepath.Join(repo.unit, "promotion-record.json")); !os.IsNotExist(err) {
		t.Fatalf("promotion output unexpectedly exists: %v", err)
	}
}

func mutateSyntheticReview(t *testing.T, repo *syntheticReviewRepo, reviewID string, mutate func(*Review)) {
	t.Helper()
	directory := filepath.Join(repo.unit, "approvals", reviewID)
	review, _, err := readStrictJSON[Review](context.Background(), filepath.Join(directory, "review.json"))
	if err != nil {
		t.Fatal(err)
	}
	mutate(&review)
	binding, err := ComputeReviewBodyBinding(review)
	if err != nil {
		t.Fatal(err)
	}
	review.PlatformReview.AssertionSHA256 = binding.AssertionSHA256
	review.PlatformReview.BodySHA256 = binding.BodySHA256
	mustWrite(t, filepath.Join(directory, "review.json"), mustCanonical(t, review))
	markdown, err := RenderReview(review)
	if err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(directory, "REVIEW.md"), markdown)
}

func mutateSyntheticSnapshot(t *testing.T, repo *syntheticReviewRepo, mutate func(*PlatformApprovalSnapshot)) {
	t.Helper()
	snapshot, _, err := readStrictJSON[PlatformApprovalSnapshot](context.Background(), repo.snapshot)
	if err != nil {
		t.Fatal(err)
	}
	mutate(&snapshot)
	mustWrite(t, repo.snapshot, mustCanonical(t, snapshot))
}
