package packreview

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

const policyResultStatement = "policy records and matching platform approvals present; this does not establish that incident facts are true"

// CheckApprovals validates human-supplied review records against an externally
// acquired, normalized GitHub review snapshot. The function performs no network
// or process operation and never creates an approval.
func CheckApprovals(ctx context.Context, reviewUnitRoot, candidateCommit, candidateManifestSHA256, platformSnapshotPath string) (PolicyResult, error) {
	unit, err := ValidateUnit(ctx, reviewUnitRoot, candidateCommit)
	if err != nil {
		return PolicyResult{}, err
	}
	var validation problems
	validateSHA256(candidateManifestSHA256, "/candidateManifestSha256", &validation)
	if candidateManifestSHA256 != unit.CandidateManifestSHA256 {
		validation.add("STALE_CANDIDATE_MANIFEST", "/candidateManifestSha256", "does not match exact candidate-content manifest bytes")
	}

	snapshot, snapshotRaw, err := readStrictJSON[PlatformApprovalSnapshot](ctx, platformSnapshotPath)
	if err != nil {
		return PolicyResult{}, err
	}
	if err := requireCanonicalJSONFile(filepath.Base(platformSnapshotPath), snapshotRaw, snapshot); err != nil {
		return PolicyResult{}, err
	}
	validatePlatformSnapshot(snapshot, &validation)
	if snapshot.CandidateCommit != candidateCommit {
		validation.add("STALE_PLATFORM_HEAD", "/platformSnapshot/candidateCommit", "snapshot pull-request head does not equal candidate commit")
	}
	if snapshot.Repository != unit.Policy.OfficialRepository {
		validation.add("UNTRUSTED_REVIEW_REPOSITORY", "/platformSnapshot/repository", "snapshot repository does not equal the official repository bound by review policy")
	}

	reviews, err := loadReviews(ctx, unit.Root)
	if err != nil {
		return PolicyResult{}, err
	}
	latestPlatform := latestPlatformApprovals(snapshot.Approvals)
	platformByID := make(map[int64]PlatformApproval, len(snapshot.Approvals))
	for _, approval := range snapshot.Approvals {
		platformByID[approval.ReviewDatabaseID] = approval
	}
	eligibleMaintainers := make(map[int64]HumanIdentity, len(unit.Policy.EligibleMaintainers))
	for _, identity := range unit.Policy.EligibleMaintainers {
		eligibleMaintainers[identity.DatabaseID] = identity
	}
	disqualified := map[int64]struct{}{}
	disqualified[unit.Pack.Preparation.Preparer.DatabaseID] = struct{}{}
	for _, identity := range unit.Pack.Preparation.Authors {
		disqualified[identity.DatabaseID] = struct{}{}
	}
	for _, identity := range unit.Pack.Preparation.SourceTranscribers {
		disqualified[identity.DatabaseID] = struct{}{}
	}

	qualifying := make([]Review, 0, len(reviews))
	seenHumans := map[int64]string{}
	for index, review := range reviews {
		base := fmt.Sprintf("/reviews/%d", index)
		validateReview(review, &validation)
		validateReviewBinding(review, unit, candidateCommit, base, &validation)
		if review.PlatformReview.Repository != snapshot.Repository || review.PlatformReview.PullRequestNumber != snapshot.PullRequestNumber {
			validation.add("PLATFORM_SCOPE_MISMATCH", base+"/platformReview", "review reference and platform snapshot identify different pull requests")
		}
		if _, blocked := disqualified[review.Reviewer.DatabaseID]; blocked {
			validation.add("SELF_REVIEW", base+"/reviewer", "candidate preparer, author, or source transcriber cannot approve")
		}
		if first, duplicate := seenHumans[review.Reviewer.DatabaseID]; duplicate {
			validation.add("DUPLICATE_HUMAN_REVIEW", base+"/reviewer", "human already supplied review %s", first)
		} else {
			seenHumans[review.Reviewer.DatabaseID] = review.ReviewID
		}
		if review.Decision != "approve" || !review.Independent {
			validation.add("NONQUALIFYING_DECISION", base+"/decision", "policy requires an independent approve decision")
		}
		if review.DeclaredRole == "maintainer" {
			maintainer, ok := eligibleMaintainers[review.Reviewer.DatabaseID]
			if !ok || maintainer.Login != review.Reviewer.Login {
				validation.add("INELIGIBLE_MAINTAINER", base+"/reviewer", "reviewer is not in the hash-bound maintainer policy")
			}
		} else if _, maintainer := eligibleMaintainers[review.Reviewer.DatabaseID]; maintainer {
			validation.add("OUTSIDE_ROLE_CONFLICT", base+"/declaredRole", "eligible project maintainer cannot fill an outside-reviewer slot")
		}
		platform, ok := platformByID[review.PlatformReview.ReviewDatabaseID]
		if !ok {
			validation.add("MISSING_PLATFORM_REVIEW", base+"/platformReview/reviewDatabaseId", "review database ID is absent from platform snapshot")
		} else {
			validatePlatformMatch(review, platform, candidateCommit, snapshot.ObservedAt, base, &validation)
			latest := latestPlatform[review.Reviewer.DatabaseID]
			if latest.ReviewDatabaseID != platform.ReviewDatabaseID || latest.State != "APPROVED" || latest.Dismissed || latest.CommitID != candidateCommit {
				validation.add("STALE_OR_REVOKED_REVIEW", base+"/platformReview", "referenced approval is not the reviewer's latest effective approval for candidate commit")
			}
		}
		qualifying = append(qualifying, review)
	}

	validateReviewPolicyCounts(qualifying, unit.Policy, unit.Pack.ReviewPolicyProfile, &validation)
	for _, conflict := range unit.Conflicts.Conflicts {
		if conflict.Disposition == "blocking" {
			validation.add("BLOCKING_CONFLICT", "/conflicts/"+conflict.ConflictID, "blocking conflict prevents approval policy success")
		}
	}
	if err := validation.err(); err != nil {
		return PolicyResult{}, err
	}

	approvalIDs := make([]string, 0, len(qualifying))
	for _, review := range qualifying {
		approvalIDs = append(approvalIDs, review.ReviewID)
	}
	sort.Strings(approvalIDs)
	return PolicyResult{
		SchemaVersion:           PolicyResultSchema,
		IncidentID:              unit.Pack.IncidentID,
		PackVersion:             unit.Pack.PackVersion,
		CandidateCommit:         candidateCommit,
		CandidateManifestSHA256: unit.CandidateManifestSHA256,
		ReviewPolicyProfile:     unit.Pack.ReviewPolicyProfile,
		QualifyingApprovalIDs:   approvalIDs,
		Statement:               policyResultStatement,
	}, nil
}

func loadReviews(ctx context.Context, root string) ([]Review, error) {
	approvalsRoot := filepath.Join(root, "approvals")
	if err := ensureReviewDirectory(approvalsRoot); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(approvalsRoot)
	if err != nil {
		return nil, err
	}
	if len(entries) == 0 || len(entries) > 100 {
		return nil, &ValidationError{Problems: []Problem{{Code: "APPROVAL_COUNT", Path: approvalsRoot, Message: "approval directory must contain 1-100 review directories"}}}
	}
	var reviews []Review
	for _, entry := range entries {
		if !stableIDRE.MatchString(entry.Name()) || entry.Type()&os.ModeSymlink != 0 || !entry.IsDir() {
			return nil, &ValidationError{Problems: []Problem{{Code: "APPROVAL_PATH", Path: filepath.Join(approvalsRoot, entry.Name()), Message: "approval entry must be a safe real directory"}}}
		}
		directory := filepath.Join(approvalsRoot, entry.Name())
		children, err := os.ReadDir(directory)
		if err != nil {
			return nil, err
		}
		if len(children) != 2 || children[0].Name() != "REVIEW.md" || children[1].Name() != "review.json" {
			return nil, &ValidationError{Problems: []Problem{{Code: "APPROVAL_FILE_SET", Path: directory, Message: "approval directory must contain exactly REVIEW.md and review.json"}}}
		}
		review, _, err := readReviewDirectory(ctx, directory)
		if err != nil {
			return nil, err
		}
		reviews = append(reviews, review)
	}
	sort.Slice(reviews, func(i, j int) bool { return reviews[i].ReviewID < reviews[j].ReviewID })
	return reviews, nil
}

func validateReviewBinding(review Review, unit *Unit, candidateCommit, base string, p *problems) {
	if review.IncidentID != unit.Pack.IncidentID || review.PackVersion != unit.Pack.PackVersion {
		p.add("REVIEW_UNIT_IDENTITY", base, "review incident or pack version does not match candidate")
	}
	if review.CandidateCommit != candidateCommit {
		p.add("STALE_REVIEW_COMMIT", base+"/candidateCommit", "review does not bind exact candidate commit")
	}
	want := ReviewBindings{
		CandidateManifestSHA256: unit.CandidateManifestSHA256,
		OriginalPackSHA256:      unit.Pack.OriginalPackSHA256,
		CanonicalPackSHA256:     unit.Pack.CanonicalPackSHA256,
		ClaimsSHA256:            unit.Pack.ClaimsSHA256,
		SourcesSHA256:           unit.Pack.SourcesSHA256,
		ConflictsSHA256:         unit.Pack.ConflictsSHA256,
		FixtureManifestSHA256:   unit.Pack.FixtureManifestSHA256,
		ValidatorPolicySHA256:   unit.Pack.ValidatorPolicySHA256,
		ReviewPolicySHA256:      unit.Pack.ReviewPolicySHA256,
	}
	if review.Bindings != want {
		p.add("STALE_REVIEW_BINDING", base+"/bindings", "review hashes do not match exact immutable candidate content and policies")
	}
	if review.PlatformReview.Repository != unit.Policy.OfficialRepository {
		p.add("UNTRUSTED_REVIEW_REPOSITORY", base+"/platformReview/repository", "review repository does not equal the official repository bound by review policy")
	}
	validateCheckedSourceBindings(review, unit, base, p)
}

func validateCheckedSourceBindings(review Review, unit *Unit, base string, p *problems) {
	sources := make(map[string]string, len(unit.Sources.Sources))
	for _, source := range unit.Sources.Sources {
		sources[source.SourceID] = source.ReviewedSHA256
	}
	checked := make(map[string]struct{}, len(review.SourceObjectsChecked))
	for index, object := range review.SourceObjectsChecked {
		path := fmt.Sprintf("%s/sourceObjectsChecked/%d", base, index)
		want, ok := sources[object.SourceID]
		if !ok {
			p.add("UNKNOWN_CHECKED_SOURCE", path+"/sourceId", "checked source ID is absent from the exact source ledger")
			continue
		}
		if object.SHA256 != want {
			p.add("CHECKED_SOURCE_HASH_MISMATCH", path+"/sha256", "checked source hash does not equal sources.json reviewedSha256")
			continue
		}
		checked[object.SourceID] = struct{}{}
	}
	if !containsString(review.Scopes, "identity") && !containsString(review.Scopes, "complete") {
		return
	}
	required := make(map[string]struct{})
	for _, claim := range unit.Claims.Claims {
		if !identityReviewRole(claim.SemanticRole) {
			continue
		}
		for _, sourceID := range claim.SourceIDs {
			required[sourceID] = struct{}{}
		}
	}
	for _, sourceID := range sortedStringSet(required) {
		if _, ok := checked[sourceID]; !ok {
			p.add("MISSING_IDENTITY_SOURCE_CHECK", base+"/sourceObjectsChecked", "identity review must reproduce source object %s at its exact reviewed hash", sourceID)
		}
	}
}

func identityReviewRole(role string) bool {
	switch role {
	case "component", "subpath", "ref", "compromised-sha", "package-digest", "known-good-sha":
		return true
	default:
		return false
	}
}

func sortedStringSet(values map[string]struct{}) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func validatePlatformMatch(review Review, platform PlatformApproval, candidateCommit, snapshotTime, base string, p *problems) {
	if platform.Reviewer.DatabaseID != review.Reviewer.DatabaseID || platform.Reviewer.Login != review.Reviewer.Login || platform.ReviewURL != review.PlatformReview.ReviewURL || platform.ReviewDatabaseID != review.PlatformReview.ReviewDatabaseID {
		p.add("PLATFORM_REVIEW_MISMATCH", base+"/platformReview", "platform observation does not match reviewer identity and review reference")
	}
	if platform.AccountType != "User" {
		p.add("AUTOMATED_REVIEWER", base+"/reviewer", "GitHub account type is not User")
	}
	if platform.State != "APPROVED" || platform.Dismissed {
		p.add("PLATFORM_NOT_APPROVED", base+"/platformReview", "platform review is not a current non-dismissed approval")
	}
	if platform.CommitID != candidateCommit {
		p.add("PLATFORM_COMMIT_MISMATCH", base+"/platformReview", "platform review does not bind exact candidate commit")
	}
	if platform.BodySHA256 != review.PlatformReview.BodySHA256 {
		p.add("PLATFORM_REVIEW_BODY_MISMATCH", base+"/platformReview/bodySha256", "platform review body hash does not match the retained review-body binding")
	}
	submitted, submitErr := time.Parse(time.RFC3339Nano, platform.SubmittedAt)
	recorded, recordErr := time.Parse(time.RFC3339Nano, review.ReviewedAt)
	observed, observeErr := time.Parse(time.RFC3339Nano, snapshotTime)
	if submitErr == nil && recordErr == nil && recorded.Before(submitted) {
		p.add("REVIEW_TIME_ORDER", base+"/reviewedAt", "review record predates platform review")
	}
	if submitErr == nil && observeErr == nil && observed.Before(submitted) {
		p.add("SNAPSHOT_TIME_ORDER", base+"/platformReview", "snapshot predates platform review")
	}
}

func latestPlatformApprovals(approvals []PlatformApproval) map[int64]PlatformApproval {
	latest := map[int64]PlatformApproval{}
	for _, approval := range approvals {
		current, exists := latest[approval.Reviewer.DatabaseID]
		if !exists || platformApprovalAfter(approval, current) {
			latest[approval.Reviewer.DatabaseID] = approval
		}
	}
	return latest
}

func platformApprovalAfter(left, right PlatformApproval) bool {
	leftTime, leftErr := time.Parse(time.RFC3339Nano, left.SubmittedAt)
	rightTime, rightErr := time.Parse(time.RFC3339Nano, right.SubmittedAt)
	if leftErr == nil && rightErr == nil && !leftTime.Equal(rightTime) {
		return leftTime.After(rightTime)
	}
	return left.ReviewDatabaseID > right.ReviewDatabaseID
}

func validateReviewPolicyCounts(reviews []Review, policy ReviewPolicy, profileID string, p *problems) {
	var profile *ReviewPolicyProfile
	for i := range policy.Profiles {
		if policy.Profiles[i].ProfileID == profileID {
			profile = &policy.Profiles[i]
			break
		}
	}
	if profile == nil {
		p.add("POLICY_PROFILE", "/packet/reviewPolicyProfile", "profile is absent from hash-bound review policy")
		return
	}
	maintainers, outside := 0, 0
	allScopes := map[string]struct{}{}
	for _, review := range reviews {
		if review.Decision != "approve" || !review.Independent {
			continue
		}
		if review.DeclaredRole == "maintainer" {
			maintainers++
		} else if review.DeclaredRole == "outside-technical" {
			outside++
			if profileID == TrivyPolicyProfile && !hasAllScopes(review.Scopes, profile.RequiredOutsideScopes) {
				p.add("TRIVY_OUTSIDE_SCOPE", "/reviews/"+review.ReviewID+"/scopes", "each Trivy outside reviewer must cover component namespace, IOC extraction, and time")
			}
		}
		for _, scope := range review.Scopes {
			allScopes[scope] = struct{}{}
		}
	}
	if maintainers < profile.MinimumMaintainers {
		p.add("MAINTAINER_APPROVAL_COUNT", "/reviews", "policy requires at least %d distinct eligible maintainer approvals", profile.MinimumMaintainers)
	}
	if outside < profile.MinimumOutsideReviewers {
		p.add("OUTSIDE_APPROVAL_COUNT", "/reviews", "policy requires at least %d distinct outside technical approvals", profile.MinimumOutsideReviewers)
	}
	for _, required := range profile.RequiredAnyApprovalScopes {
		_, complete := allScopes["complete"]
		if _, ok := allScopes[required]; !ok && !complete {
			p.add("REQUIRED_REVIEW_SCOPE", "/reviews", "no qualifying approval covers required scope %s", required)
		}
	}
	if _, identity := allScopes["identity"]; identity {
		checked := false
		for _, review := range reviews {
			if (containsString(review.Scopes, "identity") || containsString(review.Scopes, "complete")) && len(review.SourceObjectsChecked) > 0 {
				checked = true
			}
		}
		if !checked {
			p.add("IDENTITY_REPRODUCTION", "/reviews", "identity review scope requires at least one checked source-object hash")
		}
	}
}

func hasAllScopes(scopes, required []string) bool {
	if containsString(scopes, "complete") {
		return true
	}
	for _, value := range required {
		if !containsString(scopes, value) {
			return false
		}
	}
	return true
}
