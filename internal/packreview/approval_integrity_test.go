package packreview

import (
	"context"
	"strings"
	"testing"
)

func TestReviewAssertionBindsEveryMaterialField(t *testing.T) {
	repo := newSyntheticReviewRepo(t, StandardPolicyProfile)
	addSyntheticApprovals(t, &repo, 1)
	load := func() Review {
		review := readSyntheticReview(t, &repo, "synthetic-review-1")
		review.Commands = []ReproductionCommand{{Tool: "cirewind", Version: "synthetic-v1", Arguments: []string{"pack", "validate"}}}
		return review
	}
	base := load()
	want, err := ComputeReviewBodyBinding(base)
	if err != nil {
		t.Fatal(err)
	}
	if want.Body != reviewBodyPrefix+want.AssertionSHA256 || want.BodySHA256 != digestHex([]byte(want.Body)) || len(want.AssertionSHA256) != 64 {
		t.Fatalf("unexpected deterministic body binding: %+v", want)
	}
	for _, forbidden := range []string{base.Reviewer.Login, base.IncidentID, base.Rationale, base.SourceObjectsChecked[0].SourceID} {
		if strings.Contains(want.Body, forbidden) {
			t.Fatalf("fixed review body retained material assertion text %q", forbidden)
		}
	}

	mutations := []struct {
		name   string
		mutate func(*Review)
	}{
		{"review ID", func(r *Review) { r.ReviewID = "different-review" }},
		{"reviewer login", func(r *Review) { r.Reviewer.Login = "different-reviewer" }},
		{"reviewer database ID", func(r *Review) { r.Reviewer.DatabaseID++ }},
		{"declared role", func(r *Review) { r.DeclaredRole = "outside-technical" }},
		{"independence", func(r *Review) { r.Independent = false }},
		{"conflict disclosure", func(r *Review) { r.ConflictDisclosure = "Different synthetic disclosure." }},
		{"incident ID", func(r *Review) { r.IncidentID = "different-incident" }},
		{"pack version", func(r *Review) { r.PackVersion = "9.9.9" }},
		{"candidate commit", func(r *Review) { r.CandidateCommit = stringOf('c', 40) }},
		{"candidate manifest binding", func(r *Review) { r.Bindings.CandidateManifestSHA256 = stringOf('1', 64) }},
		{"original pack binding", func(r *Review) { r.Bindings.OriginalPackSHA256 = stringOf('1', 64) }},
		{"canonical pack binding", func(r *Review) { r.Bindings.CanonicalPackSHA256 = stringOf('1', 64) }},
		{"claims binding", func(r *Review) { r.Bindings.ClaimsSHA256 = stringOf('1', 64) }},
		{"sources binding", func(r *Review) { r.Bindings.SourcesSHA256 = stringOf('1', 64) }},
		{"conflicts binding", func(r *Review) { r.Bindings.ConflictsSHA256 = stringOf('1', 64) }},
		{"fixture binding", func(r *Review) { r.Bindings.FixtureManifestSHA256 = stringOf('1', 64) }},
		{"validator binding", func(r *Review) { r.Bindings.ValidatorPolicySHA256 = stringOf('1', 64) }},
		{"review policy binding", func(r *Review) { r.Bindings.ReviewPolicySHA256 = stringOf('1', 64) }},
		{"repository", func(r *Review) { r.PlatformReview.Repository = "different/project" }},
		{"pull request", func(r *Review) { r.PlatformReview.PullRequestNumber++ }},
		{"scope", func(r *Review) { r.Scopes = []string{"identity", "time"} }},
		{"command tool", func(r *Review) { r.Commands[0].Tool = "different-tool" }},
		{"command version", func(r *Review) { r.Commands[0].Version = "synthetic-v2" }},
		{"command arguments", func(r *Review) { r.Commands[0].Arguments = []string{"different", "arguments"} }},
		{"checked source ID", func(r *Review) { r.SourceObjectsChecked[0].SourceID = "different-source" }},
		{"checked source", func(r *Review) { r.SourceObjectsChecked[0].SHA256 = stringOf('1', 64) }},
		{"decision", func(r *Review) { r.Decision = "request_changes" }},
		{"rationale", func(r *Review) { r.Rationale = "Different synthetic rationale." }},
		{"known limitations", func(r *Review) { r.KnownLimitations = []string{"Different synthetic limitation."} }},
	}
	for _, test := range mutations {
		t.Run(test.name, func(t *testing.T) {
			changed := load()
			test.mutate(&changed)
			got, err := ComputeReviewBodyBinding(changed)
			if err != nil {
				t.Fatal(err)
			}
			if got.AssertionSHA256 == want.AssertionSHA256 || got.BodySHA256 == want.BodySHA256 {
				t.Fatalf("material mutation did not change both bindings: before=%+v after=%+v", want, got)
			}
		})
	}
}

func TestReviewAssertionExcludesOnlyFinalWrapperAndPostSubmissionMetadata(t *testing.T) {
	repo := newSyntheticReviewRepo(t, StandardPolicyProfile)
	addSyntheticApprovals(t, &repo, 1)
	base := readSyntheticReview(t, &repo, "synthetic-review-1")
	want, err := ComputeReviewBodyBinding(base)
	if err != nil {
		t.Fatal(err)
	}
	mutations := []struct {
		name   string
		mutate func(*Review)
	}{
		// The outer review schema is validated independently and projects to the
		// fixed assertion schema, so it is not a reviewer-controlled assertion.
		{"fixed final wrapper schema", func(r *Review) { r.SchemaVersion = "cirewind.review-approval/v9" }},
		{"platform review URL", func(r *Review) {
			r.PlatformReview.ReviewURL = "https://github.com/example/cirewind/pull/7#pullrequestreview-9999"
		}},
		{"platform review database ID", func(r *Review) { r.PlatformReview.ReviewDatabaseID = 9999 }},
		{"recorded assertion hash", func(r *Review) { r.PlatformReview.AssertionSHA256 = stringOf('1', 64) }},
		{"recorded body hash", func(r *Review) { r.PlatformReview.BodySHA256 = stringOf('1', 64) }},
		{"recorded review time", func(r *Review) { r.ReviewedAt = "2026-08-22T00:00:00Z" }},
	}
	for _, test := range mutations {
		t.Run(test.name, func(t *testing.T) {
			changed := base
			test.mutate(&changed)
			got, err := ComputeReviewBodyBinding(changed)
			if err != nil {
				t.Fatal(err)
			}
			if got != want {
				t.Fatalf("post-submission metadata unexpectedly changed assertion: before=%+v after=%+v", want, got)
			}
		})
	}
}

func TestCheckApprovalsRejectsMaterialAssertionAndPlatformBodyTampering(t *testing.T) {
	t.Run("material assertion changed after approval", func(t *testing.T) {
		repo := newSyntheticReviewRepo(t, StandardPolicyProfile)
		addSyntheticApprovals(t, &repo, 1)
		directory := repo.unit + "/approvals/synthetic-review-1"
		review := readSyntheticReview(t, &repo, "synthetic-review-1")
		review.Scopes = []string{"identity", "time"}
		mustWrite(t, directory+"/review.json", mustCanonical(t, review))
		_, err := CheckApprovals(context.Background(), repo.unit, syntheticCommit, repo.unitValue.CandidateManifestSHA256, repo.snapshot)
		assertProblemCode(t, err, "REVIEW_ASSERTION_MISMATCH")
	})

	t.Run("review record rebound without matching platform body", func(t *testing.T) {
		repo := newSyntheticReviewRepo(t, StandardPolicyProfile)
		addSyntheticApprovals(t, &repo, 1)
		mutateSyntheticReview(t, &repo, "synthetic-review-1", func(review *Review) {
			review.Scopes = []string{"identity", "time"}
			binding, err := ComputeReviewBodyBinding(*review)
			if err != nil {
				t.Fatal(err)
			}
			review.PlatformReview.AssertionSHA256 = binding.AssertionSHA256
			review.PlatformReview.BodySHA256 = binding.BodySHA256
		})
		_, err := CheckApprovals(context.Background(), repo.unit, syntheticCommit, repo.unitValue.CandidateManifestSHA256, repo.snapshot)
		assertProblemCode(t, err, "PLATFORM_REVIEW_BODY_MISMATCH")
	})
}

func TestCheckedSourceObjectsCloseAgainstExactSourceLedger(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*Review)
		code   string
	}{
		{"identity source omitted", func(review *Review) { review.SourceObjectsChecked = []CheckedSourceObject{} }, "MISSING_IDENTITY_SOURCE_CHECK"},
		{"unknown source", func(review *Review) {
			review.SourceObjectsChecked = []CheckedSourceObject{{SourceID: "unknown-source", SHA256: stringOf('1', 64)}}
		}, "UNKNOWN_CHECKED_SOURCE"},
		{"reviewed hash mismatch", func(review *Review) { review.SourceObjectsChecked[0].SHA256 = stringOf('1', 64) }, "CHECKED_SOURCE_HASH_MISMATCH"},
	} {
		t.Run(test.name, func(t *testing.T) {
			repo := newSyntheticReviewRepo(t, StandardPolicyProfile)
			addSyntheticApprovals(t, &repo, 1)
			mutateReviewAndPlatformBinding(t, &repo, "synthetic-review-1", test.mutate)
			_, err := CheckApprovals(context.Background(), repo.unit, syntheticCommit, repo.unitValue.CandidateManifestSHA256, repo.snapshot)
			assertProblemCode(t, err, test.code)
		})
	}

	t.Run("every identity claim source is required", func(t *testing.T) {
		repo := newSyntheticReviewRepo(t, StandardPolicyProfile)
		review := Review{Scopes: []string{"identity"}, SourceObjectsChecked: []CheckedSourceObject{{SourceID: syntheticSourceID, SHA256: repo.unitValue.Sources.Sources[0].ReviewedSHA256}}}
		unit := *repo.unitValue
		unit.Sources = repo.unitValue.Sources
		unit.Sources.Sources = append([]SourceRecord(nil), repo.unitValue.Sources.Sources...)
		unit.Sources.Sources = append(unit.Sources.Sources, SourceRecord{SourceID: "second-identity-source", ReviewedSHA256: stringOf('2', 64)})
		unit.Claims = repo.unitValue.Claims
		unit.Claims.Claims = append([]Claim(nil), repo.unitValue.Claims.Claims...)
		unit.Claims.Claims[0].SemanticRole = "compromised-sha"
		unit.Claims.Claims[0].SourceIDs = []string{syntheticSourceID, "second-identity-source"}
		var got problems
		validateCheckedSourceBindings(review, &unit, "/reviews/0", &got)
		assertProblemCode(t, got.err(), "MISSING_IDENTITY_SOURCE_CHECK")
	})

	t.Run("duplicate checked source ID", func(t *testing.T) {
		review := validReviewForParity()
		review.SourceObjectsChecked = []CheckedSourceObject{
			{SourceID: "duplicate-source", SHA256: stringOf('1', 64)},
			{SourceID: "duplicate-source", SHA256: stringOf('2', 64)},
		}
		refreshReviewBodyBindingForParity(&review)
		var got problems
		validateReview(review, &got)
		assertProblemCode(t, got.err(), "DUPLICATE_SOURCE_OBJECT")
	})
}

func TestCheckApprovalsRejectsReviewOutsidePolicyRepository(t *testing.T) {
	repo := newSyntheticReviewRepo(t, StandardPolicyProfile)
	addSyntheticApprovals(t, &repo, 1)
	mutateSyntheticSnapshot(t, &repo, func(snapshot *PlatformApprovalSnapshot) {
		snapshot.Repository = "fork/cirewind"
		snapshot.WorkflowRunURL = "https://github.com/fork/cirewind/actions/runs/77"
		for index := range snapshot.Approvals {
			snapshot.Approvals[index].ReviewURL = strings.Replace(snapshot.Approvals[index].ReviewURL, "example/cirewind", "fork/cirewind", 1)
		}
	})
	_, err := CheckApprovals(context.Background(), repo.unit, syntheticCommit, repo.unitValue.CandidateManifestSHA256, repo.snapshot)
	assertProblemCode(t, err, "UNTRUSTED_REVIEW_REPOSITORY")
}

func TestReviewPolicyRequiresCanonicalOfficialRepository(t *testing.T) {
	for _, repository := range []string{"", "Example/CIRewind"} {
		policy := syntheticPolicy()
		policy.OfficialRepository = repository
		var got problems
		validateReviewPolicy(policy, &got)
		if repository == "" {
			assertProblemCode(t, got.err(), "REPOSITORY")
		} else {
			assertProblemCode(t, got.err(), "OFFICIAL_REPOSITORY_CANONICAL")
		}
	}
}

func readSyntheticReview(t *testing.T, repo *syntheticReviewRepo, reviewID string) Review {
	t.Helper()
	review, _, err := readStrictJSON[Review](context.Background(), repo.unit+"/approvals/"+reviewID+"/review.json")
	if err != nil {
		t.Fatal(err)
	}
	return review
}

func mutateReviewAndPlatformBinding(t *testing.T, repo *syntheticReviewRepo, reviewID string, mutate func(*Review)) {
	t.Helper()
	var bodySHA string
	var platformID int64
	mutateSyntheticReview(t, repo, reviewID, func(review *Review) {
		mutate(review)
		binding, err := ComputeReviewBodyBinding(*review)
		if err != nil {
			t.Fatal(err)
		}
		review.PlatformReview.AssertionSHA256 = binding.AssertionSHA256
		review.PlatformReview.BodySHA256 = binding.BodySHA256
		bodySHA = binding.BodySHA256
		platformID = review.PlatformReview.ReviewDatabaseID
	})
	mutateSyntheticSnapshot(t, repo, func(snapshot *PlatformApprovalSnapshot) {
		for index := range snapshot.Approvals {
			if snapshot.Approvals[index].ReviewDatabaseID == platformID {
				snapshot.Approvals[index].BodySHA256 = bodySHA
				return
			}
		}
		t.Fatalf("platform review %d not found", platformID)
	})
}
