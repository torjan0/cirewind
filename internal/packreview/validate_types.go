package packreview

import (
	"fmt"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

var (
	stableIDRE         = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$`)
	semverRE           = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$`)
	sha256RE           = regexp.MustCompile(`^[0-9a-f]{64}$`)
	commitRE           = regexp.MustCompile(`^(?:[0-9a-f]{40}|[0-9a-f]{64})$`)
	repositoryRE       = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$`)
	loginRE            = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$`)
	semanticSelectorRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,299}$`)
	mediaTypeRE        = regexp.MustCompile(`^[a-z0-9][a-z0-9!#$&^_.+-]{0,63}/[a-z0-9][a-z0-9!#$&^_.+-]{0,63}$`)
	reviewWorkflowRE   = regexp.MustCompile(`^\.github/workflows/[A-Za-z0-9][A-Za-z0-9._+/-]*\.ya?ml$`)
)

const (
	maxJSONSafeInteger     int64 = 1<<53 - 1
	maxPullRequestNumber   int64 = 1<<31 - 1
	maxWorkflowRunAttempt  int64 = 10_000
	maxReviewApprovalCount       = 100
	maxReviewSourceObjects       = 2_000
	maxSemVerLength              = 128
)

func validatePacket(packet Packet, p *problems) {
	if packet.SchemaVersion != PacketSchema {
		p.add("SCHEMA_VERSION", "/schemaVersion", "must equal %q", PacketSchema)
	}
	validateID(packet.IncidentID, "/incidentId", p)
	validateSemVer(packet.PackVersion, "/packVersion", p)
	if packet.ReviewUnitPackPath != "pack.yaml" {
		p.add("PACK_PATH", "/reviewUnitPackPath", "must equal pack.yaml")
	}
	for _, field := range []struct{ pointer, value string }{
		{"/originalPackSha256", packet.OriginalPackSHA256},
		{"/canonicalPackSha256", packet.CanonicalPackSHA256},
		{"/validatorPolicySha256", packet.ValidatorPolicySHA256},
		{"/reviewPolicySha256", packet.ReviewPolicySHA256},
		{"/claimsSha256", packet.ClaimsSHA256},
		{"/sourcesSha256", packet.SourcesSHA256},
		{"/conflictsSha256", packet.ConflictsSHA256},
		{"/expectedFindingsSha256", packet.ExpectedFindingsSHA256},
		{"/fixtureManifestSha256", packet.FixtureManifestSHA256},
	} {
		validateSHA256(field.value, field.pointer, p)
	}
	if packet.PackSchemaVersion != "cirewind.dev/v1alpha1" {
		p.add("PACK_SCHEMA", "/packSchemaVersion", "must equal cirewind.dev/v1alpha1")
	}
	validateText(packet.ValidatorVersion, 1, 200, false, "/validatorVersion", p)
	if packet.ReviewPolicyProfile != StandardPolicyProfile && packet.ReviewPolicyProfile != TrivyPolicyProfile {
		p.add("POLICY_PROFILE", "/reviewPolicyProfile", "unsupported review policy profile")
	}
	validateSortedUniqueIDs(packet.ConflictIDs, "/conflictIds", p)
	validateHuman(packet.Preparation.Preparer, "/preparation/preparer", p)
	validateHumans(packet.Preparation.Authors, "/preparation/authors", true, p)
	validateHumans(packet.Preparation.SourceTranscribers, "/preparation/sourceTranscribers", true, p)
	if !containsHuman(packet.Preparation.Authors, packet.Preparation.Preparer.DatabaseID) {
		p.add("PREPARER_NOT_AUTHOR", "/preparation/preparer", "preparer must also appear in authors")
	}
}

func validateReviewPolicy(policy ReviewPolicy, p *problems) {
	if policy.SchemaVersion != ReviewPolicySchema {
		p.add("SCHEMA_VERSION", "/policy/schemaVersion", "must equal %q", ReviewPolicySchema)
	}
	validateID(policy.PolicyVersion, "/policy/policyVersion", p)
	validateRepository(policy.OfficialRepository, "/policy/officialRepository", p)
	if policy.OfficialRepository != strings.ToLower(policy.OfficialRepository) {
		p.add("OFFICIAL_REPOSITORY_CANONICAL", "/policy/officialRepository", "must use the lowercase canonical owner/repository identity")
	}
	validateHumans(policy.EligibleMaintainers, "/policy/eligibleMaintainers", false, p)
	if len(policy.Profiles) != 2 {
		p.add("POLICY_PROFILES", "/policy/profiles", "must contain exactly standard-v0.2 and trivy-v0.2")
	}
	seen := map[string]struct{}{}
	for i, profile := range policy.Profiles {
		base := fmt.Sprintf("/policy/profiles/%d", i)
		if _, duplicate := seen[profile.ProfileID]; duplicate {
			p.add("DUPLICATE_POLICY_PROFILE", base+"/profileId", "policy profile repeated")
		}
		seen[profile.ProfileID] = struct{}{}
		validateSortedUniqueStrings(profile.RequiredAnyApprovalScopes, base+"/requiredAnyApprovalScopes", p)
		validateSortedUniqueStrings(profile.RequiredOutsideScopes, base+"/requiredOutsideScopes", p)
		for j, scope := range append(append([]string(nil), profile.RequiredAnyApprovalScopes...), profile.RequiredOutsideScopes...) {
			switch scope {
			case "identity", "hostile-input-privacy", "component-namespace", "time", "ioc-extraction":
			default:
				p.add("POLICY_SCOPE", fmt.Sprintf("%s/scopes/%d", base, j), "unsupported required policy scope")
			}
		}
		switch profile.ProfileID {
		case StandardPolicyProfile:
			if profile.MinimumMaintainers != 2 || profile.MinimumOutsideReviewers != 1 ||
				!equalStrings(profile.RequiredAnyApprovalScopes, []string{"hostile-input-privacy", "identity"}) || len(profile.RequiredOutsideScopes) != 0 {
				p.add("POLICY_FLOOR", base, "standard-v0.2 must require 2 maintainers, 1 outside reviewer, identity and hostile-input-privacy scopes")
			}
		case TrivyPolicyProfile:
			if profile.MinimumMaintainers != 2 || profile.MinimumOutsideReviewers != 2 ||
				!equalStrings(profile.RequiredAnyApprovalScopes, []string{"hostile-input-privacy", "identity"}) ||
				!equalStrings(profile.RequiredOutsideScopes, []string{"component-namespace", "ioc-extraction", "time"}) {
				p.add("POLICY_FLOOR", base, "trivy-v0.2 must require 2 maintainers, 2 outside reviewers and all component/time/IOC scopes")
			}
		default:
			p.add("POLICY_PROFILE", base+"/profileId", "unsupported policy profile")
		}
	}
	if _, ok := seen[StandardPolicyProfile]; !ok {
		p.add("MISSING_POLICY_PROFILE", "/policy/profiles", "standard-v0.2 is absent")
	}
	if _, ok := seen[TrivyPolicyProfile]; !ok {
		p.add("MISSING_POLICY_PROFILE", "/policy/profiles", "trivy-v0.2 is absent")
	}
}

func validateSources(ledger SourceLedger, p *problems) {
	if ledger.SchemaVersion != SourcesSchema {
		p.add("SCHEMA_VERSION", "/schemaVersion", "must equal %q", SourcesSchema)
	}
	if len(ledger.Sources) == 0 || len(ledger.Sources) > 2000 {
		p.add("SOURCE_COUNT", "/sources", "must contain 1-2000 sources")
	}
	seen := map[string]struct{}{}
	for i, source := range ledger.Sources {
		base := fmt.Sprintf("/sources/%d", i)
		validateID(source.SourceID, base+"/sourceId", p)
		if _, ok := seen[source.SourceID]; ok {
			p.add("DUPLICATE_SOURCE", base+"/sourceId", "duplicate source ID")
		}
		seen[source.SourceID] = struct{}{}
		switch source.SourceClass {
		case "maintainer-advisory", "immutable-repository-object", "github-advisory-database", "government-advisory", "original-research", "secondary-lead", "synthetic-fixture":
		default:
			p.add("SOURCE_CLASS", base+"/sourceClass", "unsupported source class")
		}
		validateText(source.Publisher, 1, 200, false, base+"/publisher", p)
		validateText(source.Title, 1, 500, false, base+"/title", p)
		validateHTTPS(source.Locator, false, base+"/locator", p)
		validateOptionalTime(source.PublishedAt, base+"/publishedAt", p)
		validateOptionalTime(source.UpdatedAt, base+"/updatedAt", p)
		if source.StatedPrecision != "" && !validPrecision(source.StatedPrecision) {
			p.add("TIME_PRECISION", base+"/statedPrecision", "unsupported source precision")
		}
		validateTime(source.RetrievedAt, base+"/retrievedAt", p)
		if source.ImmutableRevision != "" {
			validateText(source.ImmutableRevision, 1, 500, false, base+"/immutableRevision", p)
		}
		if !mediaTypeRE.MatchString(source.MediaType) {
			p.add("MEDIA_TYPE", base+"/mediaType", "must be a conservative lowercase media type")
		}
		if source.ReviewedByteLength < 0 || source.ReviewedByteLength > 1<<30 {
			p.add("SOURCE_SIZE", base+"/reviewedByteLength", "must be between 0 and 1 GiB")
		}
		validateSHA256(source.ReviewedSHA256, base+"/reviewedSha256", p)
		if (source.ArchivePath == "") == (source.NotRedistributedReason == "") {
			p.add("SOURCE_RETENTION", base, "exactly one of archivePath or notRedistributedReason is required")
		}
		if source.ArchivePath != "" {
			validateSafeRelativePath(source.ArchivePath, base+"/archivePath", p)
		}
		if source.NotRedistributedReason != "" {
			validateText(source.NotRedistributedReason, 1, 1000, true, base+"/notRedistributedReason", p)
		}
		switch source.RedistributionAssessment {
		case "redistributable", "metadata-only", "restricted", "unknown":
		default:
			p.add("REDISTRIBUTION", base+"/redistributionAssessment", "unsupported redistribution assessment")
		}
		if source.SupersedesSourceID != "" {
			validateID(source.SupersedesSourceID, base+"/supersedesSourceId", p)
		}
		if source.Notes != "" {
			validateText(source.Notes, 1, 4096, true, base+"/notes", p)
		}
		validateSortedUniqueIDs(source.ConflictIDs, base+"/conflictIds", p)
	}
	for i, source := range ledger.Sources {
		if source.SupersedesSourceID != "" {
			if _, ok := seen[source.SupersedesSourceID]; !ok {
				p.add("UNKNOWN_SUPERSEDED_SOURCE", fmt.Sprintf("/sources/%d/supersedesSourceId", i), "unknown source ID")
			}
		}
	}
}

func validateConflicts(ledger ConflictLedger, p *problems) {
	if ledger.SchemaVersion != ConflictsSchema {
		p.add("SCHEMA_VERSION", "/schemaVersion", "must equal %q", ConflictsSchema)
	}
	if len(ledger.Conflicts) > 2000 {
		p.add("CONFLICT_COUNT", "/conflicts", "must contain at most 2000 conflicts")
	}
	seen := map[string]struct{}{}
	for i, conflict := range ledger.Conflicts {
		base := fmt.Sprintf("/conflicts/%d", i)
		validateID(conflict.ConflictID, base+"/conflictId", p)
		if _, ok := seen[conflict.ConflictID]; ok {
			p.add("DUPLICATE_CONFLICT", base+"/conflictId", "duplicate conflict ID")
		}
		seen[conflict.ConflictID] = struct{}{}
		if len(conflict.ClaimIDs) == 0 {
			p.add("CONFLICT_CLAIMS", base+"/claimIds", "at least one affected claim is required")
		}
		validateSortedUniqueIDs(conflict.ClaimIDs, base+"/claimIds", p)
		if len(conflict.CompetingSourceIDs) < 2 {
			p.add("CONFLICT_SOURCES", base+"/competingSourceIds", "at least two competing sources are required")
		}
		validateSortedUniqueIDs(conflict.CompetingSourceIDs, base+"/competingSourceIds", p)
		validateText(conflict.Description, 1, 4096, true, base+"/description", p)
		switch conflict.Materiality {
		case "matching-scope", "identity", "time", "remediation", "context-only":
		default:
			p.add("MATERIALITY", base+"/materiality", "unsupported materiality")
		}
		switch conflict.Disposition {
		case "excluded", "encoded-uncertain", "resolved", "blocking":
		default:
			p.add("DISPOSITION", base+"/disposition", "unsupported disposition")
		}
		validateText(conflict.Rationale, 1, 4096, true, base+"/rationale", p)
		if conflict.Disposition == "resolved" {
			validateID(conflict.SelectedClaimID, base+"/selectedClaimId", p)
			if len(conflict.SelectedSourceIDs) == 0 {
				p.add("RESOLUTION_SOURCES", base+"/selectedSourceIds", "resolved conflict requires selected sources")
			}
			validateSortedUniqueIDs(conflict.SelectedSourceIDs, base+"/selectedSourceIds", p)
		} else if conflict.SelectedClaimID != "" || len(conflict.SelectedSourceIDs) != 0 {
			p.add("UNEXPECTED_RESOLUTION", base, "only a resolved conflict may select a claim and sources")
		}
	}
}

func validateReview(review Review, p *problems) {
	if review.SchemaVersion != ReviewSchema {
		p.add("SCHEMA_VERSION", "/schemaVersion", "must equal %q", ReviewSchema)
	}
	validateReviewAssertion(ReviewAssertionFromReview(review), p)
	validatePlatformReviewReference(review.PlatformReview, "/platformReview", p)
	binding, err := ComputeReviewBodyBinding(review)
	if err != nil {
		p.add("REVIEW_ASSERTION_ENCODING", "/platformReview", "material review assertion cannot be encoded")
	} else {
		if review.PlatformReview.AssertionSHA256 != binding.AssertionSHA256 {
			p.add("REVIEW_ASSERTION_MISMATCH", "/platformReview/assertionSha256", "does not bind the canonical material review assertion")
		}
		if review.PlatformReview.BodySHA256 != binding.BodySHA256 {
			p.add("REVIEW_BODY_BINDING_MISMATCH", "/platformReview/bodySha256", "does not bind the exact fixed GitHub review body")
		}
	}
	validateTime(review.ReviewedAt, "/reviewedAt", p)
}

func validateReviewAssertion(assertion ReviewAssertion, p *problems) {
	if assertion.SchemaVersion != ReviewAssertionSchema {
		p.add("SCHEMA_VERSION", "/schemaVersion", "must equal %q", ReviewAssertionSchema)
	}
	validateID(assertion.ReviewID, "/reviewId", p)
	validateHuman(assertion.Reviewer, "/reviewer", p)
	if assertion.DeclaredRole != "maintainer" && assertion.DeclaredRole != "outside-technical" {
		p.add("REVIEWER_ROLE", "/declaredRole", "must be maintainer or outside-technical")
	}
	validateText(assertion.ConflictDisclosure, 1, 2000, true, "/conflictDisclosure", p)
	validateID(assertion.IncidentID, "/incidentId", p)
	validateSemVer(assertion.PackVersion, "/packVersion", p)
	validateCommit(assertion.CandidateCommit, "/candidateCommit", p)
	validateBindings(assertion.Bindings, "/bindings", p)
	validateRepository(assertion.Repository, "/repository", p)
	if assertion.Repository != strings.ToLower(assertion.Repository) {
		p.add("ASSERTION_REPOSITORY_CANONICAL", "/repository", "must use lowercase canonical owner/repository identity")
	}
	validatePullRequestNumber(assertion.PullRequestNumber, "/pullRequestNumber", p)
	if len(assertion.Scopes) == 0 || len(assertion.Scopes) > 20 {
		p.add("SCOPE_COUNT", "/scopes", "must contain 1-20 scopes")
	}
	for i, scope := range assertion.Scopes {
		switch scope {
		case "identity", "time", "transitive-mapping", "ioc-extraction", "remediation", "hostile-input-privacy", "component-namespace", "complete":
		default:
			p.add("REVIEW_SCOPE", fmt.Sprintf("/scopes/%d", i), "unsupported review scope")
		}
	}
	validateSortedUniqueStrings(assertion.Scopes, "/scopes", p)
	if assertion.Commands == nil {
		p.add("NULL_ARRAY", "/commands", "must be an array, not null")
	} else if len(assertion.Commands) > 50 {
		p.add("COMMAND_COUNT", "/commands", "must contain at most 50 command records")
	}
	for i, command := range assertion.Commands {
		base := fmt.Sprintf("/commands/%d", i)
		validateText(command.Tool, 1, 200, false, base+"/tool", p)
		validateText(command.Version, 1, 200, false, base+"/version", p)
		if command.Arguments == nil {
			p.add("NULL_ARRAY", base+"/arguments", "must be an array, not null")
		} else if len(command.Arguments) > 100 {
			p.add("ARGUMENT_COUNT", base+"/arguments", "must contain at most 100 inert argument strings")
		}
		for j, argument := range command.Arguments {
			validateText(argument, 1, 1000, false, fmt.Sprintf("%s/arguments/%d", base, j), p)
		}
	}
	seenSources := map[string]struct{}{}
	if assertion.SourceObjectsChecked == nil {
		p.add("NULL_ARRAY", "/sourceObjectsChecked", "must be an array, not null")
	} else if len(assertion.SourceObjectsChecked) > maxReviewSourceObjects {
		p.add("SOURCE_OBJECT_COUNT", "/sourceObjectsChecked", "must contain at most %d source objects", maxReviewSourceObjects)
	}
	for i, object := range assertion.SourceObjectsChecked {
		base := fmt.Sprintf("/sourceObjectsChecked/%d", i)
		validateID(object.SourceID, base+"/sourceId", p)
		validateSHA256(object.SHA256, base+"/sha256", p)
		if _, ok := seenSources[object.SourceID]; ok {
			p.add("DUPLICATE_SOURCE_OBJECT", base+"/sourceId", "source object repeated")
		}
		seenSources[object.SourceID] = struct{}{}
	}
	switch assertion.Decision {
	case "approve", "request_changes", "abstain":
	default:
		p.add("REVIEW_DECISION", "/decision", "unsupported decision")
	}
	validateText(assertion.Rationale, 1, 4096, true, "/rationale", p)
	if assertion.KnownLimitations == nil {
		p.add("NULL_ARRAY", "/knownLimitations", "must be an array, not null")
	} else if len(assertion.KnownLimitations) > 100 {
		p.add("LIMITATION_COUNT", "/knownLimitations", "must contain at most 100 limitations")
	}
	for i, item := range assertion.KnownLimitations {
		validateText(item, 1, 2000, true, fmt.Sprintf("/knownLimitations/%d", i), p)
	}
}

func validatePlatformSnapshot(snapshot PlatformApprovalSnapshot, p *problems) {
	if snapshot.SchemaVersion != PlatformSnapshotSchema {
		p.add("SCHEMA_VERSION", "/schemaVersion", "must equal %q", PlatformSnapshotSchema)
	}
	validateRepository(snapshot.Repository, "/repository", p)
	validatePullRequestNumber(snapshot.PullRequestNumber, "/pullRequestNumber", p)
	validateCommit(snapshot.CandidateCommit, "/candidateCommit", p)
	validateTime(snapshot.ObservedAt, "/observedAt", p)
	if snapshot.ObservationSource != "github-rest-api" && snapshot.ObservationSource != "github-actions-event" {
		p.add("OBSERVATION_SOURCE", "/observationSource", "unsupported normalized observation source")
	}
	validateCommit(snapshot.WorkflowSourceCommit, "/workflowSourceCommit", p)
	validateGitHubWorkflowURL(snapshot.WorkflowRunURL, snapshot.Repository, snapshot.WorkflowRunID, "/workflowRunUrl", p)
	validateJSONSafeID(snapshot.WorkflowRunID, "/workflowRunId", "WORKFLOW_RUN_ID", p)
	if snapshot.WorkflowRunAttempt <= 0 || snapshot.WorkflowRunAttempt > maxWorkflowRunAttempt {
		p.add("WORKFLOW_RUN_ATTEMPT", "/workflowRunAttempt", "must be between 1 and %d", maxWorkflowRunAttempt)
	}
	validateSHA256(snapshot.ResponseSHA256, "/responseSha256", p)
	if len(snapshot.Approvals) == 0 || len(snapshot.Approvals) > 100 {
		p.add("PLATFORM_APPROVAL_COUNT", "/approvals", "must contain 1-100 platform review observations")
	}
	seen := map[int64]struct{}{}
	for i, approval := range snapshot.Approvals {
		base := fmt.Sprintf("/approvals/%d", i)
		validateJSONSafeID(approval.ReviewDatabaseID, base+"/reviewDatabaseId", "REVIEW_DATABASE_ID", p)
		if _, ok := seen[approval.ReviewDatabaseID]; ok {
			p.add("DUPLICATE_PLATFORM_REVIEW", base+"/reviewDatabaseId", "review database ID repeated")
		}
		seen[approval.ReviewDatabaseID] = struct{}{}
		validatePlatformActor(approval.Reviewer, base+"/reviewer", p)
		switch approval.AccountType {
		case "User", "Bot", "Organization", "Mannequin":
		default:
			p.add("ACCOUNT_TYPE", base+"/accountType", "unsupported GitHub account type")
		}
		botLogin := strings.HasSuffix(approval.Reviewer.Login, "[bot]")
		if approval.AccountType == "Bot" && !botLogin || approval.AccountType != "Bot" && botLogin {
			p.add("ACCOUNT_LOGIN_MISMATCH", base+"/reviewer/login", "[bot] login suffix must appear if and only if accountType is Bot")
		}
		validateGitHubReviewURL(approval.ReviewURL, snapshot.Repository, snapshot.PullRequestNumber, approval.ReviewDatabaseID, base+"/reviewUrl", p)
		switch approval.State {
		case "APPROVED", "CHANGES_REQUESTED", "COMMENTED", "DISMISSED":
		default:
			p.add("PLATFORM_REVIEW_STATE", base+"/state", "unsupported review state")
		}
		if approval.Dismissed != (approval.State == "DISMISSED") {
			p.add("DISMISSAL_STATE", base+"/dismissed", "dismissed must be true if and only if state is DISMISSED")
		}
		validateCommit(approval.CommitID, base+"/commitId", p)
		validateTime(approval.SubmittedAt, base+"/submittedAt", p)
		validateSHA256(approval.BodySHA256, base+"/bodySha256", p)
	}
}

func validatePromotion(record PromotionRecord, p *problems) {
	if record.SchemaVersion != PromotionSchema {
		p.add("SCHEMA_VERSION", "/promotion/schemaVersion", "must equal %q", PromotionSchema)
	}
	validateID(record.IncidentID, "/promotion/incidentId", p)
	validateSemVer(record.PackVersion, "/promotion/packVersion", p)
	if record.Status != "reviewed" {
		p.add("PROMOTION_STATUS", "/promotion/status", "must equal reviewed")
	}
	validateCommit(record.CandidateCommit, "/promotion/candidateCommit", p)
	for _, field := range []struct{ pointer, value string }{
		{"/promotion/candidateManifestSha256", record.CandidateManifestSHA256},
		{"/promotion/originalPackSha256", record.OriginalPackSHA256},
		{"/promotion/canonicalPackSha256", record.CanonicalPackSHA256},
		{"/promotion/platformSnapshotSha256", record.PlatformSnapshotSHA256},
		{"/promotion/reviewPolicySha256", record.ReviewPolicySHA256},
	} {
		validateSHA256(field.value, field.pointer, p)
	}
	if record.ReviewedPath != slashReviewedPackPath(record.IncidentID, record.PackVersion) {
		p.add("REVIEWED_PATH", "/promotion/reviewedPath", "must be the identifier-derived reviewed pack path")
	}
	minimumApprovals := 3
	if record.ReviewPolicyProfile == TrivyPolicyProfile {
		minimumApprovals = 4
	}
	if len(record.ApprovalIDs) < minimumApprovals || len(record.ApprovalIDs) > maxReviewApprovalCount {
		p.add("APPROVAL_COUNT", "/promotion/approvalIds", "must contain %d-%d qualifying approval IDs", minimumApprovals, maxReviewApprovalCount)
	}
	validateSortedUniqueIDs(record.ApprovalIDs, "/promotion/approvalIds", p)
	if record.ReviewPolicyProfile != StandardPolicyProfile && record.ReviewPolicyProfile != TrivyPolicyProfile {
		p.add("POLICY_PROFILE", "/promotion/reviewPolicyProfile", "unsupported review policy profile")
	}
	validateTime(record.PromotedAt, "/promotion/promotedAt", p)
}

func validateRegistry(registry Registry, p *problems) {
	if registry.SchemaVersion != RegistrySchema {
		p.add("SCHEMA_VERSION", "/registry/schemaVersion", "must equal %q", RegistrySchema)
	}
	if len(registry.Records) > 10_000 {
		p.add("REGISTRY_COUNT", "/registry/records", "must contain at most 10000 append-only records")
	}
	records := map[string]RegistryRecord{}
	latest := map[string]RegistryRecord{}
	var previousTime time.Time
	for index, record := range registry.Records {
		base := fmt.Sprintf("/registry/records/%d", index)
		validateID(record.RecordID, base+"/recordId", p)
		if _, duplicate := records[record.RecordID]; duplicate {
			p.add("DUPLICATE_REGISTRY_RECORD", base+"/recordId", "record ID repeated")
		}
		validateID(record.IncidentID, base+"/incidentId", p)
		validateSemVer(record.PackVersion, base+"/packVersion", p)
		if !validReviewStatus(record.Status) {
			p.add("REGISTRY_STATUS", base+"/status", "unsupported review status")
		}
		validateTime(record.RecordedAt, base+"/recordedAt", p)
		if parsed, err := time.Parse(time.RFC3339Nano, record.RecordedAt); err == nil {
			if !previousTime.IsZero() && parsed.Before(previousTime) {
				p.add("REGISTRY_TIME_ORDER", base+"/recordedAt", "append-only records must be time ordered")
			}
			previousTime = parsed
		}
		key := record.IncidentID + "\x00" + record.PackVersion
		prior, hasPrior := latest[key]
		if !hasPrior {
			if record.PreviousRecordID != "" || record.Status != "research" {
				p.add("REGISTRY_CHAIN_START", base, "first version record must be research without previousRecordId")
			}
		} else {
			if record.PreviousRecordID != prior.RecordID {
				p.add("REGISTRY_PREDECESSOR", base+"/previousRecordId", "must reference the immediately previous record for this version")
			}
			if !AllowedTransition(prior.Status, record.Status) {
				p.add("REGISTRY_TRANSITION", base+"/status", "transition %s -> %s is forbidden", prior.Status, record.Status)
			}
			validateHistoricalIdentity(prior, record, base, p)
		}
		validateRegistryStateFields(record, base, p)
		records[record.RecordID] = record
		latest[key] = record
	}
	validateSupersessionClosure(registry.Records, latest, p)
}

func validReviewStatus(status string) bool {
	switch status {
	case "research", "candidate", "review_in_progress", "reviewed", "superseded", "withdrawn":
		return true
	default:
		return false
	}
}

// AllowedTransition is the single status-transition authority used by registry
// validation and exhaustive property tests.
func AllowedTransition(from, to string) bool {
	switch from {
	case "research":
		return to == "candidate"
	case "candidate":
		return to == "review_in_progress" || to == "withdrawn"
	case "review_in_progress":
		return to == "candidate" || to == "reviewed"
	case "reviewed":
		return to == "superseded" || to == "withdrawn"
	case "superseded":
		return to == "withdrawn"
	default:
		return false
	}
}

func validateRegistryStateFields(record RegistryRecord, base string, p *problems) {
	if record.CandidateCommit != "" {
		validateCommit(record.CandidateCommit, base+"/candidateCommit", p)
	}
	if record.PromotionContentCommit != "" {
		validateCommit(record.PromotionContentCommit, base+"/promotionContentCommit", p)
	}
	for _, field := range []struct{ pointer, value string }{
		{"/originalPackSha256", record.OriginalPackSHA256},
		{"/canonicalPackSha256", record.CanonicalPackSHA256},
		{"/candidateManifestSha256", record.CandidateManifestSHA256},
		{"/reviewRecordManifestSha256", record.ReviewRecordManifestSHA256},
		{"/reviewPolicySha256", record.ReviewPolicySHA256},
	} {
		if field.value != "" {
			validateSHA256(field.value, base+field.pointer, p)
		}
	}
	if record.ReviewPolicyProfile != "" && record.ReviewPolicyProfile != StandardPolicyProfile && record.ReviewPolicyProfile != TrivyPolicyProfile {
		p.add("POLICY_PROFILE", base+"/reviewPolicyProfile", "unsupported review policy profile")
	}
	validateSortedUniqueIDs(record.ApprovalIDs, base+"/approvalIds", p)
	if len(record.ApprovalIDs) > maxReviewApprovalCount {
		p.add("APPROVAL_COUNT", base+"/approvalIds", "must contain at most %d approval IDs", maxReviewApprovalCount)
	}
	switch record.Status {
	case "research":
		if registryIdentityFieldsPresent(record) {
			p.add("RESEARCH_FIELDS", base, "research record must not assert candidate, review, or promotion identity")
		}
	case "candidate", "review_in_progress":
		if record.CandidateCommit == "" || record.OriginalPackSHA256 == "" || record.CanonicalPackSHA256 == "" || record.CandidateManifestSHA256 == "" || record.ReviewPolicyProfile == "" || record.ReviewPolicySHA256 == "" {
			p.add("CANDIDATE_FIELDS", base, "candidate states require exact candidate and policy identities")
		}
		if record.PromotionContentCommit != "" || record.ReviewedPath != "" || record.ReviewRecordManifestSHA256 != "" || len(record.ApprovalIDs) != 0 || record.SupersedesPackVersion != "" || record.SupersededByPackVersion != "" || record.WithdrawalReason != "" {
			p.add("PREPROMOTION_FIELDS", base, "candidate states must not assert promotion or approval identities")
		}
	case "reviewed", "superseded":
		if !completeReviewedIdentity(record) {
			p.add("REVIEWED_FIELDS", base, "reviewed history requires complete candidate, promotion, manifest, approval, and policy identities")
		}
		if record.ReviewedPath != slashReviewedPackPath(record.IncidentID, record.PackVersion) {
			p.add("REVIEWED_PATH", base+"/reviewedPath", "reviewed path is not identifier-derived")
		}
		if record.Status == "superseded" && !validSemVer(record.SupersededByPackVersion) {
			p.add("SUPERSEDED_BY", base+"/supersededByPackVersion", "superseded record requires a canonical SemVer of at most %d characters", maxSemVerLength)
		}
		if record.Status == "reviewed" && record.SupersededByPackVersion != "" {
			p.add("PREMATURE_SUPERSESSION", base+"/supersededByPackVersion", "reviewed record cannot claim a replacement before the superseded transition")
		}
		if record.WithdrawalReason != "" {
			p.add("WITHDRAWAL_FIELDS", base+"/withdrawalReason", "only a withdrawn event may contain a withdrawal reason")
		}
	case "withdrawn":
		validateText(record.WithdrawalReason, 1, 4096, true, base+"/withdrawalReason", p)
		if record.PromotionContentCommit == "" {
			if !completeCandidateIdentity(record) {
				p.add("WITHDRAWN_CANDIDATE_IDENTITY", base, "withdrawal before promotion must preserve complete candidate and policy identity")
			}
			for _, field := range []struct {
				pointer string
				present bool
			}{
				{pointer: "/reviewedPath", present: record.ReviewedPath != ""},
				{pointer: "/reviewRecordManifestSha256", present: record.ReviewRecordManifestSHA256 != ""},
				{pointer: "/approvalIds", present: len(record.ApprovalIDs) != 0},
				{pointer: "/supersedesPackVersion", present: record.SupersedesPackVersion != ""},
				{pointer: "/supersededByPackVersion", present: record.SupersededByPackVersion != ""},
			} {
				if field.present {
					p.add("PREPROMOTION_FIELDS", base+field.pointer, "withdrawal before promotion must not assert promotion, approval, or supersession identity")
				}
			}
		} else if !completeReviewedIdentity(record) {
			p.add("WITHDRAWN_HISTORY", base, "withdrawal of promoted content must preserve complete reviewed identity")
		}
	}
	if record.SupersedesPackVersion != "" && !validSemVer(record.SupersedesPackVersion) {
		p.add("SUPERSEDES", base+"/supersedesPackVersion", "must be canonical SemVer of at most %d characters", maxSemVerLength)
	}
}

func completeCandidateIdentity(record RegistryRecord) bool {
	return record.CandidateCommit != "" && record.OriginalPackSHA256 != "" && record.CanonicalPackSHA256 != "" &&
		record.CandidateManifestSHA256 != "" && record.ReviewPolicyProfile != "" && record.ReviewPolicySHA256 != ""
}

func registryIdentityFieldsPresent(record RegistryRecord) bool {
	return record.CandidateCommit != "" || record.PromotionContentCommit != "" || record.ReviewedPath != "" || record.OriginalPackSHA256 != "" || record.CanonicalPackSHA256 != "" || record.CandidateManifestSHA256 != "" || record.ReviewRecordManifestSHA256 != "" || len(record.ApprovalIDs) != 0 || record.ReviewPolicyProfile != "" || record.ReviewPolicySHA256 != "" || record.SupersedesPackVersion != "" || record.SupersededByPackVersion != "" || record.WithdrawalReason != ""
}

func completeReviewedIdentity(record RegistryRecord) bool {
	minimumApprovals := 3
	if record.ReviewPolicyProfile == TrivyPolicyProfile {
		minimumApprovals = 4
	}
	return record.CandidateCommit != "" && record.PromotionContentCommit != "" && record.ReviewedPath != "" && record.OriginalPackSHA256 != "" && record.CanonicalPackSHA256 != "" && record.CandidateManifestSHA256 != "" && record.ReviewRecordManifestSHA256 != "" && len(record.ApprovalIDs) >= minimumApprovals && record.ReviewPolicyProfile != "" && record.ReviewPolicySHA256 != ""
}

func validateHistoricalIdentity(previous, current RegistryRecord, base string, p *problems) {
	if previous.CandidateCommit == "" {
		return
	}
	for _, field := range []struct{ label, previous, current string }{
		{"candidateCommit", previous.CandidateCommit, current.CandidateCommit},
		{"originalPackSha256", previous.OriginalPackSHA256, current.OriginalPackSHA256},
		{"canonicalPackSha256", previous.CanonicalPackSHA256, current.CanonicalPackSHA256},
		{"candidateManifestSha256", previous.CandidateManifestSHA256, current.CandidateManifestSHA256},
		{"reviewPolicyProfile", previous.ReviewPolicyProfile, current.ReviewPolicyProfile},
		{"reviewPolicySha256", previous.ReviewPolicySHA256, current.ReviewPolicySHA256},
	} {
		if field.previous != field.current {
			p.add("HISTORICAL_IDENTITY_MUTATION", base+"/"+field.label, "append-only status event changed candidate identity")
		}
	}
	if previous.PromotionContentCommit != "" {
		for _, field := range []struct{ label, previous, current string }{
			{"promotionContentCommit", previous.PromotionContentCommit, current.PromotionContentCommit},
			{"reviewedPath", previous.ReviewedPath, current.ReviewedPath},
			{"reviewRecordManifestSha256", previous.ReviewRecordManifestSHA256, current.ReviewRecordManifestSHA256},
		} {
			if field.previous != field.current {
				p.add("PROMOTION_IDENTITY_MUTATION", base+"/"+field.label, "historical event changed promoted content identity")
			}
		}
		if !equalStrings(previous.ApprovalIDs, current.ApprovalIDs) {
			p.add("APPROVAL_HISTORY_MUTATION", base+"/approvalIds", "historical event changed approval IDs")
		}
		if previous.SupersedesPackVersion != current.SupersedesPackVersion {
			p.add("SUPERSESSION_HISTORY_MUTATION", base+"/supersedesPackVersion", "historical event changed the version this pack supersedes")
		}
		if !(previous.Status == "reviewed" && current.Status == "superseded") && previous.SupersededByPackVersion != current.SupersededByPackVersion {
			p.add("SUPERSESSION_HISTORY_MUTATION", base+"/supersededByPackVersion", "withdrawal must retain the supersession link")
		}
	}
}

func validateSupersessionClosure(records []RegistryRecord, latest map[string]RegistryRecord, p *problems) {
	for index, record := range records {
		if record.Status == "reviewed" && record.SupersedesPackVersion != "" {
			old, ok := latest[record.IncidentID+"\x00"+record.SupersedesPackVersion]
			if !ok || old.SupersededByPackVersion != record.PackVersion || old.Status != "superseded" && old.Status != "withdrawn" {
				p.add("SUPERSESSION_CLOSURE", fmt.Sprintf("/registry/records/%d/supersedesPackVersion", index), "replacement and superseded histories are not mutually linked")
			}
		}
	}
	for _, old := range latest {
		if old.SupersededByPackVersion == "" {
			continue
		}
		replacement, ok := latest[old.IncidentID+"\x00"+old.SupersededByPackVersion]
		if !ok || replacement.SupersedesPackVersion != old.PackVersion || replacement.PromotionContentCommit == "" {
			p.add("SUPERSESSION_CLOSURE", "/registry/"+old.RecordID+"/supersededByPackVersion", "superseded history does not have a mutually linked promoted replacement")
		}
	}
}

func validateBindings(bindings ReviewBindings, base string, p *problems) {
	for _, field := range []struct{ pointer, value string }{
		{"/candidateManifestSha256", bindings.CandidateManifestSHA256},
		{"/originalPackSha256", bindings.OriginalPackSHA256},
		{"/canonicalPackSha256", bindings.CanonicalPackSHA256},
		{"/claimsSha256", bindings.ClaimsSHA256},
		{"/sourcesSha256", bindings.SourcesSHA256},
		{"/conflictsSha256", bindings.ConflictsSHA256},
		{"/fixtureManifestSha256", bindings.FixtureManifestSHA256},
		{"/validatorPolicySha256", bindings.ValidatorPolicySHA256},
		{"/reviewPolicySha256", bindings.ReviewPolicySHA256},
	} {
		validateSHA256(field.value, base+field.pointer, p)
	}
}

func validatePlatformReviewReference(reference PlatformReviewReference, base string, p *problems) {
	validateRepository(reference.Repository, base+"/repository", p)
	validatePullRequestNumber(reference.PullRequestNumber, base+"/pullRequestNumber", p)
	validateJSONSafeID(reference.ReviewDatabaseID, base+"/reviewDatabaseId", "REVIEW_DATABASE_ID", p)
	validateGitHubReviewURL(reference.ReviewURL, reference.Repository, reference.PullRequestNumber, reference.ReviewDatabaseID, base+"/reviewUrl", p)
	validateSHA256(reference.AssertionSHA256, base+"/assertionSha256", p)
	validateSHA256(reference.BodySHA256, base+"/bodySha256", p)
}

func validateHuman(identity HumanIdentity, base string, p *problems) {
	if !loginRE.MatchString(identity.Login) || identity.Login != strings.ToLower(identity.Login) || strings.HasSuffix(identity.Login, "[bot]") {
		p.add("HUMAN_LOGIN", base+"/login", "must be a conservative non-bot GitHub login")
	}
	validateJSONSafeID(identity.DatabaseID, base+"/databaseId", "HUMAN_DATABASE_ID", p)
}

func validatePlatformActor(identity PlatformActor, base string, p *problems) {
	login := identity.Login
	humanForm := login
	if strings.HasSuffix(login, "[bot]") {
		humanForm = strings.TrimSuffix(login, "[bot]")
	}
	if !loginRE.MatchString(humanForm) || login != strings.ToLower(login) {
		p.add("PLATFORM_LOGIN", base+"/login", "must be a canonical GitHub user or bot login")
	}
	validateJSONSafeID(identity.DatabaseID, base+"/databaseId", "PLATFORM_DATABASE_ID", p)
}

func validateHumans(identities []HumanIdentity, base string, nonempty bool, p *problems) {
	if nonempty && len(identities) == 0 {
		p.add("HUMAN_COUNT", base, "must not be empty")
	}
	if len(identities) > 100 {
		p.add("HUMAN_COUNT", base, "must contain at most 100 identities")
	}
	seen := map[int64]struct{}{}
	for i, identity := range identities {
		validateHuman(identity, fmt.Sprintf("%s/%d", base, i), p)
		if _, ok := seen[identity.DatabaseID]; ok {
			p.add("DUPLICATE_HUMAN", fmt.Sprintf("%s/%d", base, i), "human database ID repeated")
		}
		seen[identity.DatabaseID] = struct{}{}
		if i > 0 && identities[i-1].DatabaseID >= identity.DatabaseID {
			p.add("HUMAN_ORDER", base, "identities must be sorted by databaseId")
		}
	}
}

func containsHuman(identities []HumanIdentity, databaseID int64) bool {
	for _, identity := range identities {
		if identity.DatabaseID == databaseID {
			return true
		}
	}
	return false
}

func validateID(value, pointer string, p *problems) {
	if !stableIDRE.MatchString(value) || !safeFilenameComponent(value) {
		p.add("SAFE_ID", pointer, "must be 1-100 conservative ASCII identifier characters")
	}
}

func validateSHA256(value, pointer string, p *problems) {
	if !sha256RE.MatchString(value) {
		p.add("SHA256", pointer, "must be 64 lowercase hexadecimal characters")
	}
}

func validateCommit(value, pointer string, p *problems) {
	if !commitRE.MatchString(value) {
		p.add("GIT_COMMIT", pointer, "must be a full lowercase SHA-1 or SHA-256 Git object ID")
	}
}

func validSemVer(value string) bool {
	return len(value) <= maxSemVerLength && semverRE.MatchString(value)
}

func validateSemVer(value, pointer string, p *problems) {
	if !validSemVer(value) {
		p.add("PACK_VERSION", pointer, "must be canonical SemVer of at most %d characters", maxSemVerLength)
	}
}

func validateJSONSafeID(value int64, pointer, code string, p *problems) {
	if value <= 0 || value > maxJSONSafeInteger {
		p.add(code, pointer, "must be between 1 and %d", maxJSONSafeInteger)
	}
}

func validatePullRequestNumber(value int64, pointer string, p *problems) {
	if value <= 0 || value > maxPullRequestNumber {
		p.add("PULL_REQUEST", pointer, "must be between 1 and %d", maxPullRequestNumber)
	}
}

func validateRepository(value, pointer string, p *problems) {
	if !repositoryRE.MatchString(value) || strings.Contains(value, "..") {
		p.add("REPOSITORY", pointer, "must be owner/name with conservative GitHub characters")
	}
}

func validateTime(value, pointer string, p *problems) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || !strings.HasSuffix(value, "Z") || parsed.Format(time.RFC3339Nano) != value {
		p.add("UTC_TIME", pointer, "must be a canonical RFC3339 UTC timestamp")
	}
}

func validateOptionalTime(value, pointer string, p *problems) {
	if value != "" {
		validateTime(value, pointer, p)
	}
}

func validPrecision(value string) bool {
	switch value {
	case "second", "minute", "hour", "day", "unknown":
		return true
	default:
		return false
	}
}

func validateText(value string, minBytes, maxBytes int, multiline bool, pointer string, p *problems) {
	if !utf8.ValidString(value) || len(value) < minBytes || len(value) > maxBytes || strings.TrimSpace(value) != value {
		p.add("SAFE_TEXT", pointer, "must be trimmed valid UTF-8 between %d and %d bytes", minBytes, maxBytes)
		return
	}
	for _, r := range value {
		if r == '<' || r == '>' {
			p.add("UNSAFE_TEXT", pointer, "contains a prohibited HTML angle bracket")
			return
		}
		if r == 0 || unicode.Is(unicode.Bidi_Control, r) || r >= 0x7f && r <= 0x9f || unicode.Is(unicode.Cf, r) {
			p.add("UNSAFE_TEXT", pointer, "contains a prohibited control or directional character")
			return
		}
		if r < 0x20 && (!multiline || r != '\n') {
			p.add("UNSAFE_TEXT", pointer, "contains a prohibited control character")
			return
		}
		if !multiline && (unicode.Is(unicode.Zl, r) || unicode.Is(unicode.Zp, r)) {
			p.add("UNSAFE_TEXT", pointer, "contains a prohibited line-separator character")
			return
		}
	}
}

func validateHTTPS(value string, githubOnly bool, pointer string, p *problems) {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" {
		p.add("HTTPS_URL", pointer, "must be an HTTPS URL without credentials or query parameters")
		return
	}
	if githubOnly && !strings.EqualFold(parsed.Hostname(), "github.com") {
		p.add("GITHUB_URL", pointer, "must use github.com")
	}
}

func validateGitHubReviewURL(value, repository string, number, reviewID int64, pointer string, p *problems) {
	validateHTTPS(value, true, pointer, p)
	parsed, err := url.Parse(value)
	if err != nil {
		return
	}
	wantPath := "/" + repository + "/pull/" + strconv.FormatInt(number, 10)
	wantFragment := "pullrequestreview-" + strconv.FormatInt(reviewID, 10)
	if parsed.Path != wantPath || parsed.Fragment != wantFragment {
		p.add("GITHUB_REVIEW_URL", pointer, "must identify the exact repository, pull request, and review database ID")
	}
}

func validateGitHubWorkflowURL(value, repository string, runID int64, pointer string, p *problems) {
	validateHTTPS(value, true, pointer, p)
	parsed, err := url.Parse(value)
	if err == nil && parsed.Path != "/"+repository+"/actions/runs/"+strconv.FormatInt(runID, 10) {
		p.add("GITHUB_WORKFLOW_URL", pointer, "must identify the exact repository and workflow run")
	}
}

func validateSafeRelativePath(value, pointer string, p *problems) {
	if value == "" || strings.Contains(value, "\\") || strings.HasPrefix(value, "/") || path.Clean(value) != value {
		p.add("SAFE_PATH", pointer, "must be a canonical slash-separated relative path")
		return
	}
	for _, component := range strings.Split(value, "/") {
		if !stableIDRE.MatchString(component) || !safeFilenameComponent(component) {
			p.add("SAFE_PATH", pointer, "contains an unsafe path component")
			return
		}
	}
}

func validateSortedUniqueIDs(values []string, pointer string, p *problems) {
	if len(values) > 2000 {
		p.add("LIST_COUNT", pointer, "contains more than 2000 values")
	}
	for i, value := range values {
		validateID(value, fmt.Sprintf("%s/%d", pointer, i), p)
		if i > 0 && values[i-1] >= value {
			p.add("CANONICAL_ORDER", pointer, "must be strictly sorted and unique")
			break
		}
	}
}

func validateSortedUniqueStrings(values []string, pointer string, p *problems) {
	if len(values) > 2000 {
		p.add("LIST_COUNT", pointer, "contains more than 2000 values")
	}
	for i := range values {
		if i > 0 && values[i-1] >= values[i] {
			p.add("CANONICAL_ORDER", pointer, "must be strictly sorted and unique")
			break
		}
	}
}

func sortedCopy(values []string) []string {
	result := append([]string(nil), values...)
	sort.Strings(result)
	return result
}
