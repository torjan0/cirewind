package packreview

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestValidateGovernanceRejectsSymlinkedTreeRootsAndAncestors(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("creating symlinks is not reliably available to unprivileged Windows tests")
	}
	for _, test := range []struct {
		name     string
		mutate   func(*testing.T, syntheticReviewRepo) string
		wantCode string
	}{
		{
			name: "repository root",
			mutate: func(t *testing.T, repo syntheticReviewRepo) string {
				link := filepath.Join(t.TempDir(), "repository-link")
				mustSymlink(t, repo.root, link)
				return link
			},
			wantCode: "REVIEW_ROOT",
		},
		{
			name: "review packets root",
			mutate: func(t *testing.T, repo syntheticReviewRepo) string {
				replaceDirectoryWithSymlink(t, filepath.Join(repo.root, "review-packets"))
				return repo.root
			},
			wantCode: "GOVERNANCE_TREE_ROOT",
		},
		{
			name: "review packet incident ancestor",
			mutate: func(t *testing.T, repo syntheticReviewRepo) string {
				replaceDirectoryWithSymlink(t, filepath.Dir(repo.unit))
				return repo.root
			},
			wantCode: "GOVERNANCE_TREE_ENTRY",
		},
		{
			name: "incidents root",
			mutate: func(t *testing.T, repo syntheticReviewRepo) string {
				replaceDirectoryWithSymlink(t, filepath.Join(repo.root, "incidents"))
				return repo.root
			},
			wantCode: "GOVERNANCE_TREE_ROOT",
		},
		{
			name: "candidate root",
			mutate: func(t *testing.T, repo syntheticReviewRepo) string {
				replaceDirectoryWithSymlink(t, filepath.Join(repo.root, "incidents", "candidates"))
				return repo.root
			},
			wantCode: "GOVERNANCE_TREE_ROOT",
		},
		{
			name: "reviewed root",
			mutate: func(t *testing.T, repo syntheticReviewRepo) string {
				reviewed := filepath.Join(repo.root, "incidents", "reviewed")
				target := filepath.Join(repo.root, "reviewed-real")
				mustMkdir(t, target)
				mustWrite(t, filepath.Join(target, "sentinel"), []byte("synthetic\n"))
				mustSymlink(t, target, reviewed)
				return repo.root
			},
			wantCode: "GOVERNANCE_TREE_ROOT",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			repo := newSyntheticReviewRepo(t, StandardPolicyProfile)
			root := test.mutate(t, repo)
			err := ValidateGovernance(context.Background(), root)
			assertProblemCode(t, err, test.wantCode)
		})
	}
}

func TestValidateGovernanceRejectsEmptyAndArbitraryTreeShapes(t *testing.T) {
	t.Run("empty review packets root", func(t *testing.T) {
		repo := newSyntheticReviewRepo(t, StandardPolicyProfile)
		if err := os.RemoveAll(filepath.Join(repo.root, "review-packets")); err != nil {
			t.Fatal(err)
		}
		mustMkdir(t, filepath.Join(repo.root, "review-packets"))
		assertProblemCode(t, ValidateGovernance(context.Background(), repo.root), "REVIEW_PACKET_COUNT")
	})

	t.Run("empty candidate incident directory", func(t *testing.T) {
		repo := newSyntheticReviewRepo(t, StandardPolicyProfile)
		mustMkdir(t, filepath.Join(repo.root, "incidents", "candidates", "synthetic-empty"))
		assertProblemCode(t, ValidateGovernance(context.Background(), repo.root), "GOVERNANCE_EMPTY_DIRECTORY")
	})

	t.Run("empty reviewed root", func(t *testing.T) {
		repo := newSyntheticReviewRepo(t, StandardPolicyProfile)
		mustMkdir(t, filepath.Join(repo.root, "incidents", "reviewed"))
		assertProblemCode(t, ValidateGovernance(context.Background(), repo.root), "REVIEWED_TREE_COUNT")
	})

	t.Run("arbitrary review unit entry", func(t *testing.T) {
		repo := newSyntheticReviewRepo(t, StandardPolicyProfile)
		unexpected := filepath.Join(repo.unit, "unexpected")
		mustMkdir(t, unexpected)
		mustWrite(t, filepath.Join(unexpected, "payload.txt"), []byte("synthetic inert data\n"))
		assertProblemCode(t, ValidateGovernance(context.Background(), repo.root), "INVALID_CANDIDATE_REVIEW_UNIT")
	})
}

func TestBoundedGovernanceTreeLimitsAndCancellation(t *testing.T) {
	t.Run("entry count", func(t *testing.T) {
		root := t.TempDir()
		mustWrite(t, filepath.Join(root, "a"), []byte("a"))
		mustWrite(t, filepath.Join(root, "b"), []byte("b"))
		err := validateBoundedGovernanceTree(context.Background(), root, governanceTreeLimits{entries: 1, files: 2, depth: 1}, nil)
		assertProblemCode(t, err, "GOVERNANCE_ENTRY_COUNT")
	})

	t.Run("file count", func(t *testing.T) {
		root := t.TempDir()
		mustWrite(t, filepath.Join(root, "a"), []byte("a"))
		err := validateBoundedGovernanceTree(context.Background(), root, governanceTreeLimits{entries: 1, files: 0, depth: 1}, nil)
		assertProblemCode(t, err, "GOVERNANCE_FILE_COUNT")
	})

	t.Run("path depth", func(t *testing.T) {
		root := t.TempDir()
		mustMkdir(t, filepath.Join(root, "a", "b"))
		mustWrite(t, filepath.Join(root, "a", "b", "file"), []byte("synthetic"))
		err := validateBoundedGovernanceTree(context.Background(), root, governanceTreeLimits{entries: 3, files: 1, depth: 1}, nil)
		assertProblemCode(t, err, "GOVERNANCE_PATH_DEPTH")
	})

	t.Run("canceled", func(t *testing.T) {
		root := t.TempDir()
		mustWrite(t, filepath.Join(root, "file"), []byte("synthetic"))
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := validateBoundedGovernanceTree(ctx, root, governanceTreeLimits{entries: 1, files: 1, depth: 1}, nil); err != context.Canceled {
			t.Fatalf("got %v, want context.Canceled", err)
		}
	})
}

func TestCandidateCopyGlobalCountBound(t *testing.T) {
	if err := validateCandidateCopyCount(maxCandidateCopies, "/synthetic/candidates"); err != nil {
		t.Fatalf("maximum candidate-copy count rejected: %v", err)
	}
	assertProblemCode(t, validateCandidateCopyCount(maxCandidateCopies+1, "/synthetic/candidates"), "CANDIDATE_COPY_COUNT")
}

func TestValidateGovernanceHonorsCanceledContext(t *testing.T) {
	repo := newSyntheticReviewRepo(t, StandardPolicyProfile)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := ValidateGovernance(ctx, repo.root); err != context.Canceled {
		t.Fatalf("got %v, want context.Canceled", err)
	}
}

func TestFreshCheckoutCandidateMayOmitApprovalsDirectory(t *testing.T) {
	for _, test := range []struct {
		name       string
		registered bool
	}{
		{name: "unregistered candidate"},
		{name: "registered candidate", registered: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			repo := newSyntheticReviewRepo(t, StandardPolicyProfile)
			// Git does not retain an empty directory. Removing the helper's empty
			// approvals root models the exact tree produced by a clean checkout.
			if err := os.Remove(filepath.Join(repo.unit, "approvals")); err != nil {
				t.Fatal(err)
			}
			if test.registered {
				mustWrite(t, filepath.Join(repo.root, "review-registry.json"), mustCanonical(t, syntheticCandidateRegistry(repo)))
			}

			if err := ValidateCandidateTree(context.Background(), repo.root, syntheticCommit); err != nil {
				t.Fatalf("fresh-checkout candidate governance: %v", err)
			}
		})
	}
}

func TestMissingApprovalsDirectoryIsFailClosedAfterReviewBegins(t *testing.T) {
	t.Run("review in progress", func(t *testing.T) {
		repo := newSyntheticReviewRepo(t, StandardPolicyProfile)
		if err := os.Remove(filepath.Join(repo.unit, "approvals")); err != nil {
			t.Fatal(err)
		}
		registry := syntheticCandidateRegistry(repo)
		inProgress := registry.Records[len(registry.Records)-1]
		inProgress.RecordID = "synthetic-review-in-progress"
		inProgress.PreviousRecordID = registry.Records[len(registry.Records)-1].RecordID
		inProgress.Status = "review_in_progress"
		inProgress.RecordedAt = "2026-08-21T00:00:00Z"
		registry.Records = append(registry.Records, inProgress)
		mustWrite(t, filepath.Join(repo.root, "review-registry.json"), mustCanonical(t, registry))

		assertProblemCode(t, ValidateCandidateTree(context.Background(), repo.root, syntheticCommit), "INVALID_CANDIDATE_REVIEW_UNIT")
	})

	for _, name := range []string{"platform-approvals.json", "promotion-record.json", ReviewManifestName} {
		t.Run("orphaned "+name, func(t *testing.T) {
			repo := newSyntheticReviewRepo(t, StandardPolicyProfile)
			if err := os.Remove(filepath.Join(repo.unit, "approvals")); err != nil {
				t.Fatal(err)
			}
			mustWrite(t, filepath.Join(repo.unit, name), []byte("synthetic inert review material\n"))

			assertProblemCode(t, validateReviewUnitTreeShape(context.Background(), repo.unit, true), "REVIEW_UNIT_SHAPE")
		})
	}
}

func TestPresentApprovalsDirectoryRetainsClosedShape(t *testing.T) {
	t.Run("must be a real directory", func(t *testing.T) {
		repo := newSyntheticReviewRepo(t, StandardPolicyProfile)
		if err := os.Remove(filepath.Join(repo.unit, "approvals")); err != nil {
			t.Fatal(err)
		}
		mustWrite(t, filepath.Join(repo.unit, "approvals"), []byte("synthetic inert data\n"))
		assertProblemCode(t, validateReviewUnitTreeShape(context.Background(), repo.unit, true), "REVIEW_UNIT_SHAPE")
	})

	t.Run("review records must be complete", func(t *testing.T) {
		repo := newSyntheticReviewRepo(t, StandardPolicyProfile)
		reviewRoot := filepath.Join(repo.unit, "approvals", "synthetic-incomplete-review")
		mustMkdir(t, reviewRoot)
		mustWrite(t, filepath.Join(reviewRoot, "review.json"), []byte("{}\n"))
		assertProblemCode(t, validateReviewUnitTreeShape(context.Background(), repo.unit, false), "APPROVAL_FILE_SET")
	})
}

func TestPromotionValidationStillRequiresActualApprovals(t *testing.T) {
	repo := newSyntheticReviewRepo(t, StandardPolicyProfile)
	addSyntheticApprovals(t, &repo, 1)
	if err := os.RemoveAll(filepath.Join(repo.unit, "approvals")); err != nil {
		t.Fatal(err)
	}
	if _, err := CheckApprovals(context.Background(), repo.unit, syntheticCommit, repo.unitValue.CandidateManifestSHA256, repo.snapshot); err == nil {
		t.Fatal("approval validation accepted a missing approvals directory")
	}
	if _, err := Promote(context.Background(), PromotionOptions{
		ReviewUnitRoot: repo.unit, RepositoryRoot: repo.root, CandidateCommit: syntheticCommit,
		CandidateManifest: repo.unitValue.CandidateManifestSHA256, PlatformSnapshot: repo.snapshot,
		PromotedAt: "2026-08-21T00:05:00Z",
	}); err == nil {
		t.Fatal("promotion accepted a missing approvals directory")
	}
	for _, name := range []string{"promotion-record.json", ReviewManifestName} {
		if _, err := os.Lstat(filepath.Join(repo.unit, name)); !os.IsNotExist(err) {
			t.Fatalf("failed promotion created %s: %v", name, err)
		}
	}
}

func replaceDirectoryWithSymlink(t *testing.T, path string) {
	t.Helper()
	target := path + "-real"
	if err := os.Rename(path, target); err != nil {
		t.Fatal(err)
	}
	mustSymlink(t, target, path)
}

func mustSymlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
}
