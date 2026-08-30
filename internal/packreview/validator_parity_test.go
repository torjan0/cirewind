package packreview

import (
	"fmt"
	"strings"
	"testing"
)

func TestSafeTextSemanticBoundaries(t *testing.T) {
	tests := []struct {
		name      string
		value     string
		multiline bool
		wantCode  string
	}{
		{name: "single line", value: "Synthetic & inert."},
		{name: "multiline LF", value: "Synthetic\nmultiline", multiline: true},
		{name: "single line LF", value: "Synthetic\nnewline", wantCode: "UNSAFE_TEXT"},
		{name: "tab", value: "Synthetic\ttab", multiline: true, wantCode: "UNSAFE_TEXT"},
		{name: "single line Unicode separator", value: "Synthetic\u2028separator", wantCode: "UNSAFE_TEXT"},
		{name: "left angle", value: "Synthetic <tag", wantCode: "UNSAFE_TEXT"},
		{name: "right angle", value: "Synthetic > tag", wantCode: "UNSAFE_TEXT"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var got problems
			validateText(test.value, 1, 100, test.multiline, "/text", &got)
			if test.wantCode == "" {
				if err := got.err(); err != nil {
					t.Fatalf("valid safe text: %v", err)
				}
				return
			}
			assertProblemCode(t, got.err(), test.wantCode)
		})
	}
}

func TestSemVerSemanticLengthBoundary(t *testing.T) {
	valid := "1.0.0+" + strings.Repeat("a", 122)
	invalid := valid + "a"
	if len(valid) != maxSemVerLength || len(invalid) != maxSemVerLength+1 {
		t.Fatal("test SemVer boundary construction is incorrect")
	}
	if !validSemVer(valid) {
		t.Fatal("128-character canonical SemVer rejected")
	}
	if validSemVer(invalid) {
		t.Fatal("129-character SemVer accepted")
	}
	var got problems
	validateSemVer(invalid, "/packVersion", &got)
	assertProblemCode(t, got.err(), "PACK_VERSION")
}

func TestNumericIdentitySemanticBoundaries(t *testing.T) {
	for _, test := range []struct {
		name     string
		validate func(int64, *problems)
		max      int64
		code     string
	}{
		{
			name: "human database ID", max: maxJSONSafeInteger, code: "HUMAN_DATABASE_ID",
			validate: func(value int64, p *problems) {
				validateHuman(HumanIdentity{Login: "synthetic-human", DatabaseID: value}, "/human", p)
			},
		},
		{
			name: "platform database ID", max: maxJSONSafeInteger, code: "PLATFORM_DATABASE_ID",
			validate: func(value int64, p *problems) {
				validatePlatformActor(PlatformActor{Login: "synthetic-human", DatabaseID: value}, "/actor", p)
			},
		},
		{
			name: "review database ID", max: maxJSONSafeInteger, code: "REVIEW_DATABASE_ID",
			validate: func(value int64, p *problems) {
				validateJSONSafeID(value, "/reviewDatabaseId", "REVIEW_DATABASE_ID", p)
			},
		},
		{
			name: "workflow run ID", max: maxJSONSafeInteger, code: "WORKFLOW_RUN_ID",
			validate: func(value int64, p *problems) { validateJSONSafeID(value, "/workflowRunId", "WORKFLOW_RUN_ID", p) },
		},
		{
			name: "pull request number", max: maxPullRequestNumber, code: "PULL_REQUEST",
			validate: func(value int64, p *problems) { validatePullRequestNumber(value, "/pullRequestNumber", p) },
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			for _, accepted := range []int64{1, test.max} {
				var got problems
				test.validate(accepted, &got)
				if err := got.err(); err != nil {
					t.Fatalf("accepted boundary %d rejected: %v", accepted, err)
				}
			}
			for _, rejected := range []int64{0, test.max + 1} {
				var got problems
				test.validate(rejected, &got)
				assertProblemCode(t, got.err(), test.code)
			}
		})
	}

	base := validPlatformSnapshotForParity()
	for _, attempt := range []int64{1, maxWorkflowRunAttempt} {
		value := base
		value.WorkflowRunAttempt = attempt
		assertValidPlatformSnapshot(t, value)
	}
	for _, attempt := range []int64{0, maxWorkflowRunAttempt + 1} {
		value := base
		value.WorkflowRunAttempt = attempt
		var got problems
		validatePlatformSnapshot(value, &got)
		assertProblemCode(t, got.err(), "WORKFLOW_RUN_ATTEMPT")
	}
}

func TestExpectedWorkflowSemanticBoundaries(t *testing.T) {
	for _, value := range []string{
		".github/workflows/a.yml",
		".github/workflows/dir/build+test_1-2.yaml",
	} {
		var got problems
		validateWorkflowPath(value, "/workflow", &got)
		if err := got.err(); err != nil {
			t.Errorf("valid workflow %q: %v", value, err)
		}
	}
	for _, value := range []string{
		".github/workflows/.hidden.yml",
		".github/workflows/café.yml",
		".github/workflows/a b.yml",
		".github/workflows/../outside.yml",
		".github/workflows/a\\b.yml",
		".github/workflows/" + strings.Repeat("a", 4096) + ".yml",
	} {
		var got problems
		validateWorkflowPath(value, "/workflow", &got)
		assertProblemCode(t, got.err(), "WORKFLOW_PATH")
	}
}

func TestConflictClaimIDSemanticBoundaries(t *testing.T) {
	valid := validConflictForParity()
	var got problems
	validateConflicts(ConflictLedger{SchemaVersion: ConflictsSchema, Conflicts: []Conflict{valid}}, &got)
	if err := got.err(); err != nil {
		t.Fatalf("one-claim conflict rejected: %v", err)
	}

	valid.ClaimIDs = []string{}
	got = problems{}
	validateConflicts(ConflictLedger{SchemaVersion: ConflictsSchema, Conflicts: []Conflict{valid}}, &got)
	assertProblemCode(t, got.err(), "CONFLICT_CLAIMS")
}

func TestReviewSourceObjectSemanticBoundary(t *testing.T) {
	review := validReviewForParity()
	review.SourceObjectsChecked = checkedSourcesForParity(maxReviewSourceObjects)
	refreshReviewBodyBindingForParity(&review)
	var got problems
	validateReview(review, &got)
	if err := got.err(); err != nil {
		t.Fatalf("2000 source objects rejected: %v", err)
	}

	review.SourceObjectsChecked = checkedSourcesForParity(maxReviewSourceObjects + 1)
	refreshReviewBodyBindingForParity(&review)
	got = problems{}
	validateReview(review, &got)
	assertProblemCode(t, got.err(), "SOURCE_OBJECT_COUNT")
}

func TestPromotionAndRegistryApprovalSemanticBoundaries(t *testing.T) {
	for _, test := range []struct {
		name      string
		profile   string
		count     int
		wantValid bool
	}{
		{name: "standard two", profile: StandardPolicyProfile, count: 2},
		{name: "standard three", profile: StandardPolicyProfile, count: 3, wantValid: true},
		{name: "Trivy three", profile: TrivyPolicyProfile, count: 3},
		{name: "Trivy four", profile: TrivyPolicyProfile, count: 4, wantValid: true},
		{name: "standard one hundred", profile: StandardPolicyProfile, count: 100, wantValid: true},
		{name: "standard one hundred one", profile: StandardPolicyProfile, count: 101},
	} {
		t.Run(test.name, func(t *testing.T) {
			promotion := validPromotionForParity(test.profile, test.count)
			var promotionProblems problems
			validatePromotion(promotion, &promotionProblems)
			registry := validReviewedRegistryRecordForParity(test.profile, test.count)
			var registryProblems problems
			validateRegistryStateFields(registry, "/record", &registryProblems)
			if test.wantValid {
				if err := promotionProblems.err(); err != nil {
					t.Fatalf("valid promotion: %v", err)
				}
				if err := registryProblems.err(); err != nil {
					t.Fatalf("valid registry record: %v", err)
				}
				return
			}
			assertProblemCode(t, promotionProblems.err(), "APPROVAL_COUNT")
			if test.count == 101 {
				assertProblemCode(t, registryProblems.err(), "APPROVAL_COUNT")
			} else {
				assertProblemCode(t, registryProblems.err(), "REVIEWED_FIELDS")
			}
		})
	}

	withdrawn := validReviewedRegistryRecordForParity(StandardPolicyProfile, 0)
	withdrawn.Status = "withdrawn"
	withdrawn.PromotionContentCommit = ""
	withdrawn.ReviewedPath = ""
	withdrawn.ReviewRecordManifestSHA256 = ""
	withdrawn.WithdrawalReason = "Synthetic pre-promotion withdrawal."
	withdrawn.ApprovalIDs = []string{}
	var got problems
	validateRegistryStateFields(withdrawn, "/record", &got)
	if err := got.err(); err != nil {
		t.Fatalf("valid pre-promotion withdrawal: %v", err)
	}
	withdrawn.ApprovalIDs = []string{"approval-001"}
	got = problems{}
	validateRegistryStateFields(withdrawn, "/record", &got)
	assertProblemCode(t, got.err(), "PREPROMOTION_FIELDS")
}

func TestPrePromotionWithdrawalRejectsEveryPromotionOnlyField(t *testing.T) {
	base := validReviewedRegistryRecordForParity(StandardPolicyProfile, 0)
	base.Status = "withdrawn"
	base.PromotionContentCommit = ""
	base.ReviewedPath = ""
	base.ReviewRecordManifestSHA256 = ""
	base.ApprovalIDs = []string{}
	base.WithdrawalReason = "Synthetic pre-promotion withdrawal."

	for _, test := range []struct {
		name   string
		mutate func(*RegistryRecord)
	}{
		{name: "reviewed path", mutate: func(record *RegistryRecord) { record.ReviewedPath = "incidents/reviewed/synthetic-incident/1.0.0.yaml" }},
		{name: "review record manifest", mutate: func(record *RegistryRecord) { record.ReviewRecordManifestSHA256 = strings.Repeat("e", 64) }},
		{name: "approval identity", mutate: func(record *RegistryRecord) { record.ApprovalIDs = []string{"approval-001"} }},
		{name: "supersedes version", mutate: func(record *RegistryRecord) { record.SupersedesPackVersion = "0.9.0" }},
		{name: "superseded by version", mutate: func(record *RegistryRecord) { record.SupersededByPackVersion = "1.1.0" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			record := base
			test.mutate(&record)
			var got problems
			validateRegistryStateFields(record, "/record", &got)
			assertProblemCode(t, got.err(), "PREPROMOTION_FIELDS")
		})
	}

	incomplete := base
	incomplete.ReviewPolicySHA256 = ""
	var got problems
	validateRegistryStateFields(incomplete, "/record", &got)
	assertProblemCode(t, got.err(), "WITHDRAWN_CANDIDATE_IDENTITY")
}

func TestPlatformApprovalAccountAndDismissalSemanticMatrix(t *testing.T) {
	base := validPlatformSnapshotForParity()
	for _, test := range []struct {
		name      string
		login     string
		account   string
		state     string
		dismissed bool
		wantCode  string
	}{
		{name: "human approved", login: "synthetic-reviewer", account: "User", state: "APPROVED"},
		{name: "human changes requested", login: "synthetic-reviewer", account: "User", state: "CHANGES_REQUESTED"},
		{name: "bot metadata", login: "synthetic-app[bot]", account: "Bot", state: "COMMENTED"},
		{name: "dismissed", login: "synthetic-reviewer", account: "User", state: "DISMISSED", dismissed: true},
		{name: "bot without suffix", login: "synthetic-app", account: "Bot", state: "COMMENTED", wantCode: "ACCOUNT_LOGIN_MISMATCH"},
		{name: "user with bot suffix", login: "synthetic-app[bot]", account: "User", state: "COMMENTED", wantCode: "ACCOUNT_LOGIN_MISMATCH"},
		{name: "dismissed state false", login: "synthetic-reviewer", account: "User", state: "DISMISSED", wantCode: "DISMISSAL_STATE"},
		{name: "approved dismissed true", login: "synthetic-reviewer", account: "User", state: "APPROVED", dismissed: true, wantCode: "DISMISSAL_STATE"},
	} {
		t.Run(test.name, func(t *testing.T) {
			value := base
			value.Approvals = append([]PlatformApproval(nil), base.Approvals...)
			value.Approvals[0].Reviewer.Login = test.login
			value.Approvals[0].AccountType = test.account
			value.Approvals[0].State = test.state
			value.Approvals[0].Dismissed = test.dismissed
			var got problems
			validatePlatformSnapshot(value, &got)
			if test.wantCode == "" {
				if err := got.err(); err != nil {
					t.Fatalf("valid platform metadata: %v", err)
				}
				return
			}
			assertProblemCode(t, got.err(), test.wantCode)
		})
	}
}

func validReviewForParity() Review {
	hash := strings.Repeat("a", 64)
	review := Review{
		SchemaVersion: ReviewSchema, ReviewID: "review-synthetic", Reviewer: HumanIdentity{Login: "synthetic-reviewer", DatabaseID: 1},
		DeclaredRole: "outside-technical", ConflictDisclosure: "Synthetic disclosure.", IncidentID: "synthetic-incident", PackVersion: "1.0.0",
		CandidateCommit: strings.Repeat("b", 40), Bindings: ReviewBindings{
			CandidateManifestSHA256: hash, OriginalPackSHA256: hash, CanonicalPackSHA256: hash, ClaimsSHA256: hash, SourcesSHA256: hash,
			ConflictsSHA256: hash, FixtureManifestSHA256: hash, ValidatorPolicySHA256: hash, ReviewPolicySHA256: hash,
		},
		PlatformReview: PlatformReviewReference{Repository: "example/project", PullRequestNumber: 7, ReviewURL: "https://github.com/example/project/pull/7#pullrequestreview-41", ReviewDatabaseID: 41},
		Scopes:         []string{"identity"}, Commands: []ReproductionCommand{}, SourceObjectsChecked: []CheckedSourceObject{}, Decision: "abstain",
		ReviewedAt: "2026-08-30T12:00:00Z", Rationale: "Synthetic validation record.", KnownLimitations: []string{},
	}
	refreshReviewBodyBindingForParity(&review)
	return review
}

func refreshReviewBodyBindingForParity(review *Review) {
	binding, err := ComputeReviewBodyBinding(*review)
	if err != nil {
		panic(err)
	}
	review.PlatformReview.AssertionSHA256 = binding.AssertionSHA256
	review.PlatformReview.BodySHA256 = binding.BodySHA256
}

func checkedSourcesForParity(count int) []CheckedSourceObject {
	result := make([]CheckedSourceObject, count)
	for index := range result {
		result[index] = CheckedSourceObject{SourceID: fmt.Sprintf("source-%04d", index), SHA256: strings.Repeat("a", 64)}
	}
	return result
}

func validConflictForParity() Conflict {
	return Conflict{
		ConflictID: "conflict-synthetic", ClaimIDs: []string{"claim-synthetic"}, CompetingSourceIDs: []string{"source-a", "source-b"},
		Description: "Synthetic conflict.", Materiality: "context-only", Disposition: "blocking", Rationale: "Synthetic rationale.",
	}
}

func approvalIDsForParity(count int) []string {
	result := make([]string, count)
	for index := range result {
		result[index] = fmt.Sprintf("approval-%03d", index)
	}
	return result
}

func validPromotionForParity(profile string, approvalCount int) PromotionRecord {
	hash := strings.Repeat("a", 64)
	return PromotionRecord{
		SchemaVersion: PromotionSchema, IncidentID: "synthetic-incident", PackVersion: "1.0.0", Status: "reviewed",
		CandidateCommit: strings.Repeat("b", 40), CandidateManifestSHA256: hash, OriginalPackSHA256: hash, CanonicalPackSHA256: hash,
		ReviewedPath: "incidents/reviewed/synthetic-incident/1.0.0.yaml", ApprovalIDs: approvalIDsForParity(approvalCount),
		PlatformSnapshotSHA256: hash, ReviewPolicyProfile: profile, ReviewPolicySHA256: hash, PromotedAt: "2026-08-30T12:00:00Z",
	}
}

func validReviewedRegistryRecordForParity(profile string, approvalCount int) RegistryRecord {
	promotion := validPromotionForParity(profile, approvalCount)
	return RegistryRecord{
		RecordID: "record-synthetic", IncidentID: promotion.IncidentID, PackVersion: promotion.PackVersion, Status: "reviewed",
		PreviousRecordID: "record-prior", CandidateCommit: promotion.CandidateCommit, PromotionContentCommit: strings.Repeat("c", 40),
		ReviewedPath: promotion.ReviewedPath, OriginalPackSHA256: promotion.OriginalPackSHA256, CanonicalPackSHA256: promotion.CanonicalPackSHA256,
		CandidateManifestSHA256: promotion.CandidateManifestSHA256, ReviewRecordManifestSHA256: strings.Repeat("d", 64),
		ApprovalIDs: promotion.ApprovalIDs, ReviewPolicyProfile: profile, ReviewPolicySHA256: promotion.ReviewPolicySHA256,
		RecordedAt: "2026-08-30T12:00:00Z",
	}
}

func validPlatformSnapshotForParity() PlatformApprovalSnapshot {
	commit := strings.Repeat("b", 40)
	return PlatformApprovalSnapshot{
		SchemaVersion: PlatformSnapshotSchema, Repository: "example/project", PullRequestNumber: 7, CandidateCommit: commit,
		ObservedAt: "2026-08-30T12:00:00Z", ObservationSource: "github-rest-api",
		WorkflowSourceCommit: commit, WorkflowRunURL: "https://github.com/example/project/actions/runs/9", WorkflowRunID: 9, WorkflowRunAttempt: 1,
		ResponseSHA256: strings.Repeat("a", 64), Approvals: []PlatformApproval{{
			ReviewDatabaseID: 41, ReviewURL: "https://github.com/example/project/pull/7#pullrequestreview-41",
			Reviewer: PlatformActor{Login: "synthetic-reviewer", DatabaseID: 1}, AccountType: "User", State: "COMMENTED",
			CommitID: commit, SubmittedAt: "2026-08-30T11:59:00Z", BodySHA256: strings.Repeat("a", 64), Dismissed: false,
		}},
	}
}

func assertValidPlatformSnapshot(t *testing.T, snapshot PlatformApprovalSnapshot) {
	t.Helper()
	var got problems
	validatePlatformSnapshot(snapshot, &got)
	if err := got.err(); err != nil {
		t.Fatalf("valid platform snapshot: %v", err)
	}
}
