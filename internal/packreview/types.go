// Package packreview implements the network-disabled governance checks for
// real incident-pack review units. It validates records; it never creates a
// human approval or claims that incident facts are true.
package packreview

import "github.com/torjan0/cirewind/internal/model"

const (
	PacketSchema           = "cirewind.review-packet/v1alpha1"
	SourcesSchema          = "cirewind.review-sources/v1alpha1"
	ClaimsSchema           = "cirewind.review-claims/v1alpha1"
	ConflictsSchema        = "cirewind.review-conflicts/v1alpha1"
	ReviewSchema           = "cirewind.review-approval/v1alpha1"
	ReviewAssertionSchema  = "cirewind.review-assertion/v1alpha1"
	PlatformSnapshotSchema = "cirewind.platform-approval-snapshot/v1alpha1"
	PromotionSchema        = "cirewind.review-promotion/v1alpha1"
	RegistrySchema         = "cirewind.review-registry/v1alpha1"
	ReviewPolicySchema     = "cirewind.review-policy/v1alpha1"
	ValidationSchema       = "cirewind.review-validation/v1alpha1"
	ExpectedFindingsSchema = "cirewind.review-expected-findings/v1alpha1"
	FixtureIndexSchema     = "cirewind.review-fixture-index/v1alpha1"
	PolicyResultSchema     = "cirewind.review-policy-result/v1alpha1"

	StandardPolicyProfile = "standard-v0.2"
	TrivyPolicyProfile    = "trivy-v0.2"
)

// HumanIdentity uses GitHub's stable numeric database identity for uniqueness;
// a mutable login is retained only for transparent display and cross-checking.
type HumanIdentity struct {
	Login      string `json:"login"`
	DatabaseID int64  `json:"databaseId"`
}

// PlatformActor can represent a GitHub bot observation so policy checks can
// reject it explicitly rather than making hostile snapshots unparsable.
type PlatformActor struct {
	Login      string `json:"login"`
	DatabaseID int64  `json:"databaseId"`
}

type Preparation struct {
	Preparer           HumanIdentity   `json:"preparer"`
	Authors            []HumanIdentity `json:"authors"`
	SourceTranscribers []HumanIdentity `json:"sourceTranscribers"`
}

// Packet binds the immutable candidate-content files without containing an
// approval, review status, candidate commit, promotion path, or self-hash.
type Packet struct {
	SchemaVersion          string      `json:"schemaVersion"`
	IncidentID             string      `json:"incidentId"`
	PackVersion            string      `json:"packVersion"`
	ReviewUnitPackPath     string      `json:"reviewUnitPackPath"`
	OriginalPackSHA256     string      `json:"originalPackSha256"`
	CanonicalPackSHA256    string      `json:"canonicalPackSha256"`
	PackSchemaVersion      string      `json:"packSchemaVersion"`
	ValidatorVersion       string      `json:"validatorVersion"`
	ValidatorPolicySHA256  string      `json:"validatorPolicySha256"`
	ClaimsSHA256           string      `json:"claimsSha256"`
	SourcesSHA256          string      `json:"sourcesSha256"`
	ConflictsSHA256        string      `json:"conflictsSha256"`
	ExpectedFindingsSHA256 string      `json:"expectedFindingsSha256"`
	FixtureManifestSHA256  string      `json:"fixtureManifestSha256"`
	ConflictIDs            []string    `json:"conflictIds"`
	ReviewPolicyProfile    string      `json:"reviewPolicyProfile"`
	ReviewPolicySHA256     string      `json:"reviewPolicySha256"`
	Preparation            Preparation `json:"preparation"`
}

type ReviewPolicy struct {
	SchemaVersion       string                `json:"schemaVersion"`
	PolicyVersion       string                `json:"policyVersion"`
	OfficialRepository  string                `json:"officialRepository"`
	EligibleMaintainers []HumanIdentity       `json:"eligibleMaintainers"`
	Profiles            []ReviewPolicyProfile `json:"profiles"`
}

type ReviewPolicyProfile struct {
	ProfileID                 string   `json:"profileId"`
	MinimumMaintainers        int      `json:"minimumMaintainers"`
	MinimumOutsideReviewers   int      `json:"minimumOutsideReviewers"`
	RequiredAnyApprovalScopes []string `json:"requiredAnyApprovalScopes"`
	RequiredOutsideScopes     []string `json:"requiredOutsideScopes"`
}

type SourceLedger struct {
	SchemaVersion string         `json:"schemaVersion"`
	Sources       []SourceRecord `json:"sources"`
}

type SourceRecord struct {
	SourceID                 string   `json:"sourceId"`
	SourceClass              string   `json:"sourceClass"`
	Publisher                string   `json:"publisher"`
	Title                    string   `json:"title"`
	Locator                  string   `json:"locator"`
	PublishedAt              string   `json:"publishedAt,omitempty"`
	UpdatedAt                string   `json:"updatedAt,omitempty"`
	StatedPrecision          string   `json:"statedPrecision,omitempty"`
	RetrievedAt              string   `json:"retrievedAt"`
	ImmutableRevision        string   `json:"immutableRevision,omitempty"`
	MediaType                string   `json:"mediaType"`
	ReviewedByteLength       int64    `json:"reviewedByteLength"`
	ReviewedSHA256           string   `json:"reviewedSha256"`
	ArchivePath              string   `json:"archivePath,omitempty"`
	NotRedistributedReason   string   `json:"notRedistributedReason,omitempty"`
	RedistributionAssessment string   `json:"redistributionAssessment"`
	SupersedesSourceID       string   `json:"supersedesSourceId,omitempty"`
	Notes                    string   `json:"notes,omitempty"`
	ConflictIDs              []string `json:"conflictIds"`
}

type ClaimLedger struct {
	SchemaVersion string  `json:"schemaVersion"`
	Claims        []Claim `json:"claims"`
}

type Claim struct {
	ClaimID          string           `json:"claimId"`
	CanonicalPointer *string          `json:"canonicalPointer" jsonnull:"allow"`
	SemanticSelector string           `json:"semanticSelector"`
	OmittedSlot      string           `json:"omittedSlot,omitempty"`
	NormalizedValue  *string          `json:"normalizedValue,omitempty"`
	ValueSHA256      string           `json:"valueSha256,omitempty"`
	SemanticRole     string           `json:"semanticRole"`
	SourceIDs        []string         `json:"sourceIds"`
	SourceLocations  []SourceLocation `json:"sourceLocations"`
	Transformation   string           `json:"transformation"`
	SourcePrecision  string           `json:"sourcePrecision,omitempty"`
	Approximation    string           `json:"approximation,omitempty"`
	Derivation       string           `json:"derivation,omitempty"`
	ConflictIDs      []string         `json:"conflictIds"`
	AuthorAssessment AuthorAssessment `json:"authorAssessment"`
}

type SourceLocation struct {
	SourceID string `json:"sourceId"`
	Location string `json:"location"`
}

type AuthorAssessment struct {
	Decision  string `json:"decision"`
	Rationale string `json:"rationale"`
}

type ConflictLedger struct {
	SchemaVersion string     `json:"schemaVersion"`
	Conflicts     []Conflict `json:"conflicts"`
}

type Conflict struct {
	ConflictID         string   `json:"conflictId"`
	ClaimIDs           []string `json:"claimIds"`
	CompetingSourceIDs []string `json:"competingSourceIds"`
	Description        string   `json:"description"`
	Materiality        string   `json:"materiality"`
	Disposition        string   `json:"disposition"`
	Rationale          string   `json:"rationale"`
	SelectedClaimID    string   `json:"selectedClaimId,omitempty"`
	SelectedSourceIDs  []string `json:"selectedSourceIds,omitempty"`
}

type ReviewBindings struct {
	CandidateManifestSHA256 string `json:"candidateManifestSha256"`
	OriginalPackSHA256      string `json:"originalPackSha256"`
	CanonicalPackSHA256     string `json:"canonicalPackSha256"`
	ClaimsSHA256            string `json:"claimsSha256"`
	SourcesSHA256           string `json:"sourcesSha256"`
	ConflictsSHA256         string `json:"conflictsSha256"`
	FixtureManifestSHA256   string `json:"fixtureManifestSha256"`
	ValidatorPolicySHA256   string `json:"validatorPolicySha256"`
	ReviewPolicySHA256      string `json:"reviewPolicySha256"`
}

type PlatformReviewReference struct {
	Repository        string `json:"repository"`
	PullRequestNumber int64  `json:"pullRequestNumber"`
	ReviewURL         string `json:"reviewUrl"`
	ReviewDatabaseID  int64  `json:"reviewDatabaseId"`
	AssertionSHA256   string `json:"assertionSha256"`
	BodySHA256        string `json:"bodySha256"`
}

type ReproductionCommand struct {
	Tool      string   `json:"tool"`
	Version   string   `json:"version"`
	Arguments []string `json:"arguments"`
}

type CheckedSourceObject struct {
	SourceID string `json:"sourceId"`
	SHA256   string `json:"sha256"`
}

// Review is supplied by a human reviewer. Package code only validates and
// renders it. No code path synthesizes an approving Review.
type Review struct {
	SchemaVersion        string                  `json:"schemaVersion"`
	ReviewID             string                  `json:"reviewId"`
	Reviewer             HumanIdentity           `json:"reviewer"`
	DeclaredRole         string                  `json:"declaredRole"`
	Independent          bool                    `json:"independent"`
	ConflictDisclosure   string                  `json:"conflictDisclosure"`
	IncidentID           string                  `json:"incidentId"`
	PackVersion          string                  `json:"packVersion"`
	CandidateCommit      string                  `json:"candidateCommit"`
	Bindings             ReviewBindings          `json:"bindings"`
	PlatformReview       PlatformReviewReference `json:"platformReview"`
	Scopes               []string                `json:"scopes"`
	Commands             []ReproductionCommand   `json:"commands"`
	SourceObjectsChecked []CheckedSourceObject   `json:"sourceObjectsChecked"`
	Decision             string                  `json:"decision"`
	ReviewedAt           string                  `json:"reviewedAt"`
	Rationale            string                  `json:"rationale"`
	KnownLimitations     []string                `json:"knownLimitations"`
}

type PlatformApprovalSnapshot struct {
	SchemaVersion        string             `json:"schemaVersion"`
	Repository           string             `json:"repository"`
	PullRequestNumber    int64              `json:"pullRequestNumber"`
	CandidateCommit      string             `json:"candidateCommit"`
	ObservedAt           string             `json:"observedAt"`
	ObservationSource    string             `json:"observationSource"`
	WorkflowSourceCommit string             `json:"workflowSourceCommit"`
	WorkflowRunURL       string             `json:"workflowRunUrl"`
	WorkflowRunID        int64              `json:"workflowRunId"`
	WorkflowRunAttempt   int64              `json:"workflowRunAttempt"`
	ResponseSHA256       string             `json:"responseSha256"`
	Approvals            []PlatformApproval `json:"approvals"`
}

type PlatformApproval struct {
	ReviewDatabaseID int64         `json:"reviewDatabaseId"`
	ReviewURL        string        `json:"reviewUrl"`
	Reviewer         PlatformActor `json:"reviewer"`
	AccountType      string        `json:"accountType"`
	State            string        `json:"state"`
	CommitID         string        `json:"commitId"`
	SubmittedAt      string        `json:"submittedAt"`
	BodySHA256       string        `json:"bodySha256"`
	Dismissed        bool          `json:"dismissed"`
}

type PromotionRecord struct {
	SchemaVersion           string   `json:"schemaVersion"`
	IncidentID              string   `json:"incidentId"`
	PackVersion             string   `json:"packVersion"`
	Status                  string   `json:"status"`
	CandidateCommit         string   `json:"candidateCommit"`
	CandidateManifestSHA256 string   `json:"candidateManifestSha256"`
	OriginalPackSHA256      string   `json:"originalPackSha256"`
	CanonicalPackSHA256     string   `json:"canonicalPackSha256"`
	ReviewedPath            string   `json:"reviewedPath"`
	ApprovalIDs             []string `json:"approvalIds"`
	PlatformSnapshotSHA256  string   `json:"platformSnapshotSha256"`
	ReviewPolicyProfile     string   `json:"reviewPolicyProfile"`
	ReviewPolicySHA256      string   `json:"reviewPolicySha256"`
	PromotedAt              string   `json:"promotedAt"`
}

type Registry struct {
	SchemaVersion string           `json:"schemaVersion"`
	Records       []RegistryRecord `json:"records"`
}

type RegistryRecord struct {
	RecordID                   string   `json:"recordId"`
	IncidentID                 string   `json:"incidentId"`
	PackVersion                string   `json:"packVersion"`
	Status                     string   `json:"status"`
	PreviousRecordID           string   `json:"previousRecordId,omitempty"`
	CandidateCommit            string   `json:"candidateCommit,omitempty"`
	PromotionContentCommit     string   `json:"promotionContentCommit,omitempty"`
	ReviewedPath               string   `json:"reviewedPath,omitempty"`
	OriginalPackSHA256         string   `json:"originalPackSha256,omitempty"`
	CanonicalPackSHA256        string   `json:"canonicalPackSha256,omitempty"`
	CandidateManifestSHA256    string   `json:"candidateManifestSha256,omitempty"`
	ReviewRecordManifestSHA256 string   `json:"reviewRecordManifestSha256,omitempty"`
	ApprovalIDs                []string `json:"approvalIds"`
	ReviewPolicyProfile        string   `json:"reviewPolicyProfile,omitempty"`
	ReviewPolicySHA256         string   `json:"reviewPolicySha256,omitempty"`
	RecordedAt                 string   `json:"recordedAt"`
	SupersedesPackVersion      string   `json:"supersedesPackVersion,omitempty"`
	SupersededByPackVersion    string   `json:"supersededByPackVersion,omitempty"`
	WithdrawalReason           string   `json:"withdrawalReason,omitempty"`
}

// CandidateValidation is produced by the existing pack/fixture validation
// step and hash-bound into the immutable review unit.
type CandidateValidation struct {
	SchemaVersion          string `json:"schemaVersion"`
	IncidentID             string `json:"incidentId"`
	PackVersion            string `json:"packVersion"`
	OriginalPackSHA256     string `json:"originalPackSha256"`
	CanonicalPackSHA256    string `json:"canonicalPackSha256"`
	ValidatorVersion       string `json:"validatorVersion"`
	ValidatorPolicySHA256  string `json:"validatorPolicySha256"`
	ExpectedFindingsSHA256 string `json:"expectedFindingsSha256"`
	FixtureManifestSHA256  string `json:"fixtureManifestSha256"`
	Result                 string `json:"result"`
}

// ExpectedFindings is a bounded deterministic oracle for synthetic review
// fixtures. Its presence and validity do not prove that the fixture was run or
// that any real incident fact is true.
type ExpectedFindings struct {
	SchemaVersion string                     `json:"schemaVersion"`
	Findings      []ExpectedFinding          `json:"findings"`
	Forbidden     []ForbiddenExpectedFinding `json:"forbidden"`
}

type ExpectedFinding struct {
	ScenarioID   string                `json:"scenarioId"`
	IndicatorID  string                `json:"indicatorId"`
	Repository   string                `json:"repository"`
	Workflow     string                `json:"workflow,omitempty"`
	RunID        int64                 `json:"runId,omitempty"`
	RunAttempt   int64                 `json:"runAttempt,omitempty"`
	JobID        int64                 `json:"jobId,omitempty"`
	StepIdentity string                `json:"stepIdentity,omitempty"`
	State        model.FindingState    `json:"state"`
	Provenance   model.ProvenanceLevel `json:"provenance"`
	EvidenceIDs  []model.EvidenceID    `json:"evidenceIds"`
	// CoverageAssessmentIDs freezes both gap and closed-coverage bases. It is
	// required even when empty so an oracle cannot silently discard coverage.
	CoverageAssessmentIDs []model.CoverageAssessmentID `json:"coverageAssessmentIds"`
	EvidenceGapCodes      []string                     `json:"evidenceGapCodes"`
}

type ForbiddenExpectedFinding struct {
	ScenarioID string             `json:"scenarioId"`
	State      model.FindingState `json:"state"`
	Rationale  string             `json:"rationale"`
}

type FixtureIndex struct {
	SchemaVersion string            `json:"schemaVersion"`
	Scenarios     []FixtureScenario `json:"scenarios"`
}

type FixtureScenario struct {
	ScenarioID   string `json:"scenarioId"`
	SnapshotPath string `json:"snapshotPath"`
	AnalysisTime string `json:"analysisTime"`
}

type Unit struct {
	Root                     string
	CandidateContent         string
	Pack                     Packet
	Sources                  SourceLedger
	Claims                   ClaimLedger
	Conflicts                ConflictLedger
	Validation               CandidateValidation
	ExpectedFindings         ExpectedFindings
	Policy                   ReviewPolicy
	OriginalPackSHA256       string
	CanonicalPackSHA256      string
	CandidateManifestSHA256  string
	CandidateManifestContent []byte
}

type PolicyResult struct {
	SchemaVersion           string   `json:"schemaVersion"`
	IncidentID              string   `json:"incidentId"`
	PackVersion             string   `json:"packVersion"`
	CandidateCommit         string   `json:"candidateCommit"`
	CandidateManifestSHA256 string   `json:"candidateManifestSha256"`
	ReviewPolicyProfile     string   `json:"reviewPolicyProfile"`
	QualifyingApprovalIDs   []string `json:"qualifyingApprovalIds"`
	Statement               string   `json:"statement"`
}

type PromotionOptions struct {
	ReviewUnitRoot    string
	RepositoryRoot    string
	CandidateCommit   string
	CandidateManifest string
	PlatformSnapshot  string
	PromotedAt        string
}
