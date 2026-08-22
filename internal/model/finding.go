package model

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"
)

const FindingsSchemaVersion = "cirewind.findings/v1alpha1"

type IncidentReference struct {
	ID                  string `json:"id"`
	APIVersion          string `json:"api_version"`
	PackVersion         string `json:"pack_version"`
	SourcePackSHA256    string `json:"source_pack_sha256"`
	CanonicalPackSHA256 string `json:"canonical_pack_sha256"`
}

func (r IncidentReference) Validate() error {
	if !validBoundedIdentityText(r.ID, 256) {
		return errors.New("incident ID is invalid")
	}
	if !validBoundedIdentityText(r.APIVersion, 128) {
		return errors.New("incident API version is invalid")
	}
	if !validBoundedIdentityText(r.PackVersion, 128) {
		return errors.New("incident pack version is invalid")
	}
	if err := validateSHA256(r.SourcePackSHA256, "source pack SHA-256"); err != nil {
		return err
	}
	return validateSHA256(r.CanonicalPackSHA256, "canonical pack SHA-256")
}

type RepositorySubject struct {
	ID   RepositoryID   `json:"id"`
	Name RepositorySlug `json:"name"`
}

func (s RepositorySubject) Validate() error {
	if err := s.ID.Validate(); err != nil {
		return err
	}
	return s.Name.Validate()
}

type WorkflowSubject struct {
	Path               *WorkflowPath               `json:"path"`
	DefinitionObjectID *WorkflowDefinitionObjectID `json:"definition_object_id"`
	UnknownReason      string                      `json:"unknown_reason,omitempty"`
}

func (s WorkflowSubject) Validate() error {
	if s.Path != nil {
		if err := s.Path.Validate(); err != nil {
			return err
		}
	}
	if s.DefinitionObjectID != nil {
		if err := s.DefinitionObjectID.Validate(); err != nil {
			return err
		}
	}
	if s.Path == nil && s.UnknownReason == "" {
		return errors.New("workflow subject requires a path or explicit unknown reason")
	}
	if s.Path != nil && s.UnknownReason != "" {
		return errors.New("known workflow path cannot also have an unknown reason")
	}
	return validateBoundedText(s.UnknownReason, 1024, "workflow unknown reason")
}

type FindingSubject struct {
	Repository RepositorySubject `json:"repository"`
	Workflow   WorkflowSubject   `json:"workflow"`
	RunID      *WorkflowRunID    `json:"run_id"`
	RunAttempt *RunAttempt       `json:"run_attempt"`
	JobID      *JobID            `json:"job_id"`
	Step       *StepIdentity     `json:"step"`
}

func (s FindingSubject) Validate() error {
	if err := s.Repository.Validate(); err != nil {
		return err
	}
	if err := s.Workflow.Validate(); err != nil {
		return err
	}
	if s.RunID != nil {
		if err := s.RunID.Validate(); err != nil {
			return err
		}
	}
	if s.RunAttempt != nil {
		if s.RunID == nil {
			return errors.New("finding run attempt requires run ID")
		}
		if err := s.RunAttempt.Validate(); err != nil {
			return err
		}
	}
	if s.JobID != nil {
		if s.RunAttempt == nil {
			return errors.New("finding job requires run attempt")
		}
		if err := s.JobID.Validate(); err != nil {
			return err
		}
	}
	if s.Step != nil {
		if s.JobID == nil {
			return errors.New("finding step requires job ID")
		}
		if err := s.Step.Validate(); err != nil {
			return err
		}
		if s.Step.Job.RepositoryID != s.Repository.ID || s.Step.Job.RunID != *s.RunID || s.Step.Job.RunAttempt != *s.RunAttempt || s.Step.Job.JobID != *s.JobID {
			return errors.New("finding step execution identity disagrees with its subject")
		}
	}
	return nil
}

type PropositionAttribute struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type Proposition struct {
	Kind                   string                  `json:"kind"`
	ActionSourceObjectID   *ActionSourceObjectID   `json:"action_source_object_id,omitempty"`
	PackageDigest          *PackageDigest          `json:"package_digest,omitempty"`
	CalledWorkflowObjectID *CalledWorkflowObjectID `json:"called_workflow_object_id,omitempty"`
	Attributes             []PropositionAttribute  `json:"attributes"`
}

func (p Proposition) Validate() error {
	if !validMachineName(p.Kind, 128) {
		return errors.New("proposition kind is invalid")
	}
	if p.Attributes == nil {
		return errors.New("proposition attributes must be an explicit array")
	}
	if p.ActionSourceObjectID != nil {
		if err := p.ActionSourceObjectID.Validate(); err != nil {
			return err
		}
	}
	if p.PackageDigest != nil {
		if err := p.PackageDigest.Validate(); err != nil {
			return err
		}
	}
	if p.CalledWorkflowObjectID != nil {
		if err := p.CalledWorkflowObjectID.Validate(); err != nil {
			return err
		}
	}
	for index, attribute := range p.Attributes {
		if !validMachineName(attribute.Name, 128) {
			return fmt.Errorf("proposition attribute %d has invalid name", index)
		}
		if err := validateBoundedText(attribute.Value, 4096, "proposition attribute value"); err != nil {
			return err
		}
		if index > 0 && p.Attributes[index-1].Name >= attribute.Name {
			return errors.New("proposition attributes must be sorted by unique name")
		}
	}
	return nil
}

func NormalizeProposition(p Proposition) Proposition {
	result := p
	result.Attributes = append([]PropositionAttribute(nil), p.Attributes...)
	sort.Slice(result.Attributes, func(i, j int) bool {
		if result.Attributes[i].Name == result.Attributes[j].Name {
			return result.Attributes[i].Value < result.Attributes[j].Value
		}
		return result.Attributes[i].Name < result.Attributes[j].Name
	})
	return result
}

type DerivationReference struct {
	RuleID                     string            `json:"rule_id"`
	RuleVersion                string            `json:"rule_version"`
	FirstProducedAnalysisID    AnalysisSessionID `json:"first_produced_analysis_id"`
	FirstProducedEngineVersion string            `json:"first_produced_engine_version"`
	CanonicalInputsSHA256      string            `json:"canonical_inputs_sha256"`
}

func (d DerivationReference) Validate() error {
	if !validMachineName(d.RuleID, 256) || !validBoundedIdentityText(d.RuleVersion, 128) {
		return errors.New("derivation rule ID or version is invalid")
	}
	if err := d.FirstProducedAnalysisID.Validate(); err != nil {
		return err
	}
	if !validBoundedIdentityText(d.FirstProducedEngineVersion, 256) {
		return errors.New("first-producing engine version is invalid")
	}
	return validateSHA256(d.CanonicalInputsSHA256, "canonical derivation input SHA-256")
}

type Assumption struct {
	Code        string `json:"code"`
	Description string `json:"description"`
}

func (a Assumption) Validate() error {
	if !validMachineName(a.Code, 128) {
		return errors.New("assumption code is invalid")
	}
	return validateBoundedText(a.Description, 4096, "assumption description")
}

type EvidenceGapReference struct {
	CoverageAssessmentID CoverageAssessmentID `json:"coverage_assessment_id"`
	Code                 GapReason            `json:"code"`
	Description          string               `json:"description"`
}

func (g EvidenceGapReference) Validate() error {
	if err := g.CoverageAssessmentID.Validate(); err != nil {
		return err
	}
	if !g.Code.Valid() {
		return fmt.Errorf("invalid evidence-gap code %q", g.Code)
	}
	return validateBoundedText(g.Description, 4096, "evidence-gap description")
}

type ContradictionReference struct {
	GroupID     string       `json:"group_id"`
	EvidenceIDs []EvidenceID `json:"evidence_ids"`
	Description string       `json:"description"`
}

func (c ContradictionReference) Validate() error {
	if !validBoundedIdentityText(c.GroupID, 256) {
		return errors.New("contradiction group ID is invalid")
	}
	if len(c.EvidenceIDs) < 2 {
		return errors.New("contradiction requires at least two evidence objects")
	}
	if err := validateSortedUniqueEvidenceIDs(c.EvidenceIDs); err != nil {
		return err
	}
	return validateBoundedText(c.Description, 4096, "contradiction description")
}

type CredentialExposureKind string

const (
	ExposureGitHubTokenPermission     CredentialExposureKind = "GITHUB_TOKEN_PERMISSION"
	ExposureSecretReferencedByJob     CredentialExposureKind = "SECRET_REFERENCED_BY_JOB"
	ExposureSecretPassedToStep        CredentialExposureKind = "SECRET_PASSED_TO_STEP"
	ExposureReusableSecretMapped      CredentialExposureKind = "REUSABLE_SECRET_MAPPED"
	ExposureReusableSecretInherited   CredentialExposureKind = "REUSABLE_SECRET_INHERITED"
	ExposureEnvironmentSecretEligible CredentialExposureKind = "ENVIRONMENT_SECRET_ELIGIBLE"
	ExposureOIDCMintingCapability     CredentialExposureKind = "OIDC_MINTING_CAPABILITY"
)

func (k CredentialExposureKind) Valid() bool {
	switch k {
	case ExposureGitHubTokenPermission, ExposureSecretReferencedByJob, ExposureSecretPassedToStep, ExposureReusableSecretMapped, ExposureReusableSecretInherited, ExposureEnvironmentSecretEligible, ExposureOIDCMintingCapability:
		return true
	default:
		return false
	}
}

// CredentialExposureBasis distinguishes runner-observed capabilities from
// conservative propositions reconstructed from exact historical definitions.
// It never upgrades a definition reference into proof that a value existed,
// was read, or was used.
type CredentialExposureBasis string

const (
	ExposureBasisRuntimeObserved               CredentialExposureBasis = "runtime-observed"
	ExposureBasisStaticInferred                CredentialExposureBasis = "static-inferred"
	ExposureBasisHistoricalDefinitionReference CredentialExposureBasis = "historical-definition-reference"
	ExposureBasisHistoricalDefinitionFlow      CredentialExposureBasis = "historical-definition-flow"
	ExposureBasisReusableWorkflowCall          CredentialExposureBasis = "reusable-workflow-call"
)

func (b CredentialExposureBasis) Valid() bool {
	switch b {
	case ExposureBasisRuntimeObserved, ExposureBasisStaticInferred, ExposureBasisHistoricalDefinitionReference, ExposureBasisHistoricalDefinitionFlow, ExposureBasisReusableWorkflowCall:
		return true
	default:
		return false
	}
}

var secretNamePattern = regexp.MustCompile(`^[A-Z_][A-Z0-9_]{0,255}$`)

type SecretName string

func NewSecretName(value string) (SecretName, error) {
	canonical := strings.ToUpper(value)
	if !secretNamePattern.MatchString(canonical) {
		return "", errors.New("secret name is invalid")
	}
	return SecretName(canonical), nil
}

func (n SecretName) Validate() error {
	if !secretNamePattern.MatchString(string(n)) {
		return errors.New("secret name is invalid")
	}
	return nil
}

type CredentialExposure struct {
	Kind        CredentialExposureKind  `json:"kind"`
	Basis       CredentialExposureBasis `json:"basis,omitempty"`
	SecretName  *SecretName             `json:"secret_name,omitempty"`
	Permission  string                  `json:"permission,omitempty"`
	Access      string                  `json:"access,omitempty"`
	Conclusion  string                  `json:"conclusion"`
	EvidenceIDs []EvidenceID            `json:"evidence_ids"`
}

func (e CredentialExposure) Validate() error {
	if !e.Kind.Valid() {
		return fmt.Errorf("invalid credential-exposure kind %q", e.Kind)
	}
	if e.Basis != "" && !e.Basis.Valid() {
		return fmt.Errorf("invalid credential-exposure basis %q", e.Basis)
	}
	if e.SecretName != nil {
		if err := e.SecretName.Validate(); err != nil {
			return err
		}
	}
	secretNameRequired := e.Kind == ExposureSecretReferencedByJob || e.Kind == ExposureSecretPassedToStep || e.Kind == ExposureReusableSecretMapped || e.Kind == ExposureEnvironmentSecretEligible
	if secretNameRequired && e.SecretName == nil {
		return errors.New("named-secret exposure requires a secret name")
	}
	if (e.Kind == ExposureGitHubTokenPermission || e.Kind == ExposureOIDCMintingCapability) && e.SecretName != nil {
		return errors.New("token and OIDC capabilities cannot carry a secret name")
	}
	if e.Kind == ExposureGitHubTokenPermission {
		if !validMachineName(e.Permission, 128) || (e.Access != "read" && e.Access != "write" && e.Access != "none") {
			return errors.New("token exposure requires a permission and read/write/none access")
		}
	} else if e.Permission != "" || e.Access != "" {
		return errors.New("non-token exposure cannot carry token permission fields")
	}
	if err := validateBoundedText(e.Conclusion, 4096, "credential-exposure conclusion"); err != nil {
		return err
	}
	if len(e.EvidenceIDs) == 0 {
		return errors.New("credential exposure requires evidence")
	}
	return validateSortedUniqueEvidenceIDs(e.EvidenceIDs)
}

type ResourceExposureKind string

const (
	ResourceArtifact          ResourceExposureKind = "ARTIFACT"
	ResourcePackage           ResourceExposureKind = "PACKAGE"
	ResourceRelease           ResourceExposureKind = "RELEASE"
	ResourceDeployment        ResourceExposureKind = "DEPLOYMENT"
	ResourceRepositoryWrite   ResourceExposureKind = "REPOSITORY_WRITE"
	ResourcePullRequestChange ResourceExposureKind = "PULL_REQUEST_CHANGE"
)

func (k ResourceExposureKind) Valid() bool {
	switch k {
	case ResourceArtifact, ResourcePackage, ResourceRelease, ResourceDeployment, ResourceRepositoryWrite, ResourcePullRequestChange:
		return true
	default:
		return false
	}
}

type CorrelationKind string

const (
	CorrelationDirect        CorrelationKind = "DIRECT_ATTRIBUTION"
	CorrelationObservedAfter CorrelationKind = "OBSERVED_AFTER"
)

func (k CorrelationKind) Valid() bool { return k == CorrelationDirect || k == CorrelationObservedAfter }

type ResourceExposure struct {
	Kind        ResourceExposureKind `json:"kind"`
	ResourceID  string               `json:"resource_id"`
	Correlation CorrelationKind      `json:"correlation"`
	Conclusion  string               `json:"conclusion"`
	EvidenceIDs []EvidenceID         `json:"evidence_ids"`
}

func (e ResourceExposure) Validate() error {
	if !e.Kind.Valid() || !e.Correlation.Valid() {
		return errors.New("resource exposure has invalid kind or correlation")
	}
	if !validBoundedIdentityText(e.ResourceID, 512) {
		return errors.New("resource ID is invalid")
	}
	if err := validateBoundedText(e.Conclusion, 4096, "resource-exposure conclusion"); err != nil {
		return err
	}
	if len(e.EvidenceIDs) == 0 {
		return errors.New("resource exposure requires evidence")
	}
	return validateSortedUniqueEvidenceIDs(e.EvidenceIDs)
}

type Finding struct {
	SchemaVersion               string                   `json:"schema_version"`
	FindingID                   FindingID                `json:"finding_id"`
	FindingRevisionID           FindingRevisionID        `json:"finding_revision_id"`
	Incident                    IncidentReference        `json:"incident"`
	IndicatorID                 string                   `json:"indicator_id"`
	Subject                     FindingSubject           `json:"subject"`
	State                       FindingState             `json:"state"`
	ProvenanceLevel             ProvenanceLevel          `json:"provenance_level"`
	Conclusion                  string                   `json:"conclusion"`
	Proposition                 Proposition              `json:"proposition"`
	EventTime                   EventInterval            `json:"event_time"`
	EvidenceObjectIDs           []EvidenceID             `json:"evidence_object_ids"`
	Assumptions                 []Assumption             `json:"assumptions"`
	EvidenceGaps                []EvidenceGapReference   `json:"evidence_gaps"`
	ContradictoryEvidence       []ContradictionReference `json:"contradictory_evidence"`
	PotentialCredentialExposure []CredentialExposure     `json:"potential_credential_exposure"`
	PotentialResourceExposure   []ResourceExposure       `json:"potential_resource_exposure"`
	RemediationGuidance         []string                 `json:"remediation_guidance"`
	CollectionCoverage          []CoverageAssessmentID   `json:"collection_coverage"`
	Derivation                  DerivationReference      `json:"derivation"`
	CollectionTime              Instant                  `json:"collection_time"`
	SupersedesRevisionID        *FindingRevisionID       `json:"supersedes_revision_id"`
}

func (f Finding) Validate() error {
	if f.SchemaVersion != FindingsSchemaVersion {
		return fmt.Errorf("unsupported findings schema %q", f.SchemaVersion)
	}
	if err := f.FindingID.Validate(); err != nil {
		return err
	}
	if err := f.FindingRevisionID.Validate(); err != nil {
		return err
	}
	if err := f.Incident.Validate(); err != nil {
		return err
	}
	if !validBoundedIdentityText(f.IndicatorID, 256) {
		return errors.New("indicator ID is invalid")
	}
	if err := f.Subject.Validate(); err != nil {
		return fmt.Errorf("finding subject: %w", err)
	}
	if !f.State.Valid() {
		return fmt.Errorf("invalid finding state %q", f.State)
	}
	if !f.ProvenanceLevel.Valid() {
		return fmt.Errorf("invalid provenance level %q", f.ProvenanceLevel)
	}
	if err := validateBoundedText(f.Conclusion, 8192, "finding conclusion"); err != nil {
		return err
	}
	if err := f.Proposition.Validate(); err != nil {
		return err
	}
	if err := f.EventTime.Validate(); err != nil {
		return err
	}
	if f.EvidenceObjectIDs == nil || f.Assumptions == nil || f.EvidenceGaps == nil || f.ContradictoryEvidence == nil ||
		f.PotentialCredentialExposure == nil || f.PotentialResourceExposure == nil || f.RemediationGuidance == nil || f.CollectionCoverage == nil {
		return errors.New("finding collection fields must be explicit arrays, not null")
	}
	if err := validateSortedUniqueEvidenceIDs(f.EvidenceObjectIDs); err != nil {
		return err
	}
	for _, assumption := range f.Assumptions {
		if err := assumption.Validate(); err != nil {
			return err
		}
	}
	for _, gap := range f.EvidenceGaps {
		if err := gap.Validate(); err != nil {
			return err
		}
	}
	for _, contradiction := range f.ContradictoryEvidence {
		if err := contradiction.Validate(); err != nil {
			return err
		}
	}
	for _, exposure := range f.PotentialCredentialExposure {
		if err := exposure.Validate(); err != nil {
			return err
		}
	}
	for _, exposure := range f.PotentialResourceExposure {
		if err := exposure.Validate(); err != nil {
			return err
		}
	}
	for _, guidance := range f.RemediationGuidance {
		if err := validateBoundedText(guidance, 8192, "remediation guidance"); err != nil {
			return err
		}
	}
	if err := validateSortedUniqueCoverageAssessmentIDs(f.CollectionCoverage); err != nil {
		return err
	}
	if err := f.Derivation.Validate(); err != nil {
		return err
	}
	if err := f.CollectionTime.Validate(); err != nil {
		return err
	}
	if f.SupersedesRevisionID != nil {
		if err := f.SupersedesRevisionID.Validate(); err != nil {
			return err
		}
		if *f.SupersedesRevisionID == f.FindingRevisionID {
			return errors.New("finding revision cannot supersede itself")
		}
	}
	if len(f.EvidenceObjectIDs) == 0 && len(f.EvidenceGaps) == 0 {
		return errors.New("finding requires evidence objects or an explicit evidence gap")
	}
	if f.State == UnknownEvidenceGap && len(f.EvidenceGaps) == 0 {
		return errors.New("UNKNOWN_EVIDENCE_GAP requires an explicit gap")
	}
	if f.State == ContradictoryEvidence && len(f.ContradictoryEvidence) == 0 {
		return errors.New("CONTRADICTORY_EVIDENCE requires contradictory evidence")
	}
	if f.State == NoMatchConfirmed && (len(f.EvidenceObjectIDs) == 0 || len(f.CollectionCoverage) == 0 || len(f.EvidenceGaps) != 0) {
		return errors.New("NO_MATCH_CONFIRMED requires evidence, closed coverage, and no evidence gaps")
	}
	if f.State != ConfirmedExecuted && (len(f.PotentialCredentialExposure) != 0 || len(f.PotentialResourceExposure) != 0) {
		return errors.New("credential or resource reachability requires a separate CONFIRMED_EXECUTED proposition")
	}
	return nil
}

func validateSortedUniqueCoverageAssessmentIDs(ids []CoverageAssessmentID) error {
	for index, id := range ids {
		if err := id.Validate(); err != nil {
			return err
		}
		if index > 0 && ids[index-1] >= id {
			return errors.New("coverage assessment IDs must be strictly bytewise sorted and unique")
		}
	}
	return nil
}

func SortCoverageAssessmentIDs(ids []CoverageAssessmentID) []CoverageAssessmentID {
	result := append([]CoverageAssessmentID(nil), ids...)
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	if len(result) == 0 {
		return result
	}
	write := 1
	for read := 1; read < len(result); read++ {
		if result[read] == result[write-1] {
			continue
		}
		result[write] = result[read]
		write++
	}
	return result[:write]
}

func validMachineName(value string, max int) bool {
	if value == "" || len(value) > max {
		return false
	}
	for _, char := range value {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || char == '_' || char == '-' || char == '.' || char == ':' || char == '/' {
			continue
		}
		return false
	}
	return true
}

func validateBoundedText(value string, max int, label string) error {
	if len(value) > max || !utf8.ValidString(value) || strings.IndexByte(value, 0) >= 0 {
		return fmt.Errorf("%s must be bounded UTF-8 without NUL", label)
	}
	return nil
}
