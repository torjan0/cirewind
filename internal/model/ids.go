package model

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

var (
	hashAlgorithmPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)
	versionedIDPattern   = regexp.MustCompile(`^[a-z][a-z0-9]*1:[0-9a-f]{64}$`)
)

type OrganizationID int64
type RepositoryID int64
type WorkflowRunID int64
type RunAttempt uint32
type JobID int64
type ActorID int64
type APIStepNumber int32
type ASTOrdinal uint32
type Occurrence uint32

func (id OrganizationID) Validate() error { return validatePositive(int64(id), "organization ID") }
func (id RepositoryID) Validate() error   { return validatePositive(int64(id), "repository ID") }
func (id WorkflowRunID) Validate() error  { return validatePositive(int64(id), "workflow run ID") }
func (id RunAttempt) Validate() error     { return validatePositive(int64(id), "run attempt") }
func (id JobID) Validate() error          { return validatePositive(int64(id), "job ID") }
func (id ActorID) Validate() error        { return validatePositive(int64(id), "actor ID") }
func (id APIStepNumber) Validate() error  { return validatePositive(int64(id), "API step number") }
func (id ASTOrdinal) Validate() error     { return validatePositive(int64(id), "AST ordinal") }
func (id Occurrence) Validate() error     { return validatePositive(int64(id), "occurrence") }

func validatePositive(value int64, name string) error {
	if value <= 0 {
		return fmt.Errorf("%s must be positive", name)
	}
	return nil
}

type WorkflowPath string

func NewWorkflowPath(value string) (WorkflowPath, error) {
	if value == "" {
		return "", errors.New("workflow path is empty")
	}
	if !utf8.ValidString(value) || len(value) > 4096 || hasASCIIControl(value) {
		return "", errors.New("workflow path is not a bounded UTF-8 path")
	}
	if strings.Contains(value, `\`) || strings.HasPrefix(value, "/") || path.Clean(value) != value || value == "." || strings.HasPrefix(value, "../") {
		return "", fmt.Errorf("workflow path %q is not canonical repository-relative syntax", value)
	}
	return WorkflowPath(value), nil
}

func (p WorkflowPath) Validate() error {
	_, err := NewWorkflowPath(string(p))
	return err
}

func (p *WorkflowPath) UnmarshalJSON(data []byte) error {
	var value string
	if err := json.Unmarshal(data, &value); err != nil {
		return fmt.Errorf("decode workflow path: %w", err)
	}
	parsed, err := NewWorkflowPath(value)
	if err != nil {
		return err
	}
	*p = parsed
	return nil
}

type RepositorySlug string

func NewRepositorySlug(value string) (RepositorySlug, error) {
	if !utf8.ValidString(value) || len(value) == 0 || len(value) > 512 || hasASCIIControl(value) {
		return "", errors.New("repository name must be bounded UTF-8")
	}
	parts := strings.Split(value, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" || parts[0] == "." || parts[1] == "." || parts[0] == ".." || parts[1] == ".." {
		return "", fmt.Errorf("repository %q must have owner/name form", value)
	}
	return RepositorySlug(value), nil
}

func (r RepositorySlug) Validate() error {
	_, err := NewRepositorySlug(string(r))
	return err
}

type HashAlgorithm string

const (
	HashSHA1   HashAlgorithm = "sha1"
	HashSHA256 HashAlgorithm = "sha256"
)

func (a HashAlgorithm) Valid() bool { return a == HashSHA1 || a == HashSHA256 }

func (a HashAlgorithm) expectedHexLength() int {
	switch a {
	case HashSHA1:
		return 40
	case HashSHA256:
		return 64
	default:
		return 0
	}
}

func (a *HashAlgorithm) UnmarshalJSON(data []byte) error {
	return unmarshalStringEnum(data, (*string)(a), func(value string) bool {
		return HashAlgorithm(value).Valid()
	}, "hash algorithm")
}

// GitObjectID is an algorithm-qualified complete Git object identity.
type GitObjectID struct {
	Algorithm HashAlgorithm `json:"algorithm"`
	Value     string        `json:"value"`
}

func NewGitObjectID(algorithm HashAlgorithm, value string) (GitObjectID, error) {
	id := GitObjectID{Algorithm: algorithm, Value: value}
	if err := id.Validate(); err != nil {
		return GitObjectID{}, err
	}
	return id, nil
}

func (id GitObjectID) Validate() error {
	if !hashAlgorithmPattern.MatchString(string(id.Algorithm)) || !id.Algorithm.Valid() {
		return fmt.Errorf("unsupported Git object algorithm %q", id.Algorithm)
	}
	if len(id.Value) != id.Algorithm.expectedHexLength() {
		return fmt.Errorf("Git %s object ID must contain %d lowercase hexadecimal characters", id.Algorithm, id.Algorithm.expectedHexLength())
	}
	if id.Value != strings.ToLower(id.Value) {
		return errors.New("Git object ID must be lowercase hexadecimal")
	}
	if _, err := hex.DecodeString(id.Value); err != nil {
		return fmt.Errorf("Git object ID is not hexadecimal: %w", err)
	}
	return nil
}

// The semantic wrappers prevent one Git identity from being silently assigned
// to a different historical role.
type WorkflowDefinitionObjectID GitObjectID
type TriggerObjectID GitObjectID
type CallerWorkflowObjectID GitObjectID
type CalledWorkflowObjectID GitObjectID
type ActionSourceObjectID GitObjectID

func NewWorkflowDefinitionObjectID(id GitObjectID) (WorkflowDefinitionObjectID, error) {
	if err := id.Validate(); err != nil {
		return WorkflowDefinitionObjectID{}, err
	}
	return WorkflowDefinitionObjectID(id), nil
}

func NewTriggerObjectID(id GitObjectID) (TriggerObjectID, error) {
	if err := id.Validate(); err != nil {
		return TriggerObjectID{}, err
	}
	return TriggerObjectID(id), nil
}

func NewCallerWorkflowObjectID(id GitObjectID) (CallerWorkflowObjectID, error) {
	if err := id.Validate(); err != nil {
		return CallerWorkflowObjectID{}, err
	}
	return CallerWorkflowObjectID(id), nil
}

func NewCalledWorkflowObjectID(id GitObjectID) (CalledWorkflowObjectID, error) {
	if err := id.Validate(); err != nil {
		return CalledWorkflowObjectID{}, err
	}
	return CalledWorkflowObjectID(id), nil
}

func NewActionSourceObjectID(id GitObjectID) (ActionSourceObjectID, error) {
	if err := id.Validate(); err != nil {
		return ActionSourceObjectID{}, err
	}
	return ActionSourceObjectID(id), nil
}

func (id WorkflowDefinitionObjectID) Validate() error { return GitObjectID(id).Validate() }
func (id TriggerObjectID) Validate() error            { return GitObjectID(id).Validate() }
func (id CallerWorkflowObjectID) Validate() error     { return GitObjectID(id).Validate() }
func (id CalledWorkflowObjectID) Validate() error     { return GitObjectID(id).Validate() }
func (id ActionSourceObjectID) Validate() error       { return GitObjectID(id).Validate() }

type DigestSubject string

const (
	DigestGitHubActionPackage DigestSubject = "github-action-package"
	DigestOCIManifest         DigestSubject = "oci-manifest"
	DigestExecutableFile      DigestSubject = "executable-file"
	DigestReleaseAsset        DigestSubject = "release-asset"
	DigestWorkflowArtifact    DigestSubject = "workflow-artifact"
)

func (s DigestSubject) Valid() bool {
	switch s {
	case DigestGitHubActionPackage, DigestOCIManifest, DigestExecutableFile, DigestReleaseAsset, DigestWorkflowArtifact:
		return true
	default:
		return false
	}
}

type PackageDigest struct {
	Subject   DigestSubject `json:"subject"`
	Algorithm HashAlgorithm `json:"algorithm"`
	Value     string        `json:"value"`
}

func NewPackageDigest(subject DigestSubject, algorithm HashAlgorithm, value string) (PackageDigest, error) {
	digest := PackageDigest{Subject: subject, Algorithm: algorithm, Value: value}
	if err := digest.Validate(); err != nil {
		return PackageDigest{}, err
	}
	return digest, nil
}

func (d PackageDigest) Validate() error {
	if !d.Subject.Valid() {
		return fmt.Errorf("unsupported digest subject %q", d.Subject)
	}
	if d.Algorithm != HashSHA256 {
		return fmt.Errorf("unsupported v0.1 digest algorithm %q", d.Algorithm)
	}
	if len(d.Value) != d.Algorithm.expectedHexLength() || d.Value != strings.ToLower(d.Value) {
		return fmt.Errorf("%s digest must be complete lowercase hexadecimal", d.Algorithm)
	}
	if _, err := hex.DecodeString(d.Value); err != nil {
		return fmt.Errorf("digest is not hexadecimal: %w", err)
	}
	return nil
}

// RunAttemptIdentity preserves attempt-scoped API facts that GitHub does not
// safely join to a specific job, including referenced reusable workflows.
type RunAttemptIdentity struct {
	RepositoryID RepositoryID  `json:"repository_id"`
	RunID        WorkflowRunID `json:"run_id"`
	RunAttempt   RunAttempt    `json:"run_attempt"`
}

func (id RunAttemptIdentity) Validate() error {
	if err := id.RepositoryID.Validate(); err != nil {
		return err
	}
	if err := id.RunID.Validate(); err != nil {
		return err
	}
	return id.RunAttempt.Validate()
}

func (id RunAttemptIdentity) String() string {
	return fmt.Sprintf("repo:%d/run:%d/attempt:%d", id.RepositoryID, id.RunID, id.RunAttempt)
}

// JobExecutionIdentity is the minimum material job-execution identity.
type JobExecutionIdentity struct {
	RepositoryID RepositoryID  `json:"repository_id"`
	RunID        WorkflowRunID `json:"run_id"`
	RunAttempt   RunAttempt    `json:"run_attempt"`
	JobID        JobID         `json:"job_id"`
}

func (id JobExecutionIdentity) Validate() error {
	if err := (RunAttemptIdentity{RepositoryID: id.RepositoryID, RunID: id.RunID, RunAttempt: id.RunAttempt}).Validate(); err != nil {
		return err
	}
	return id.JobID.Validate()
}

func (id JobExecutionIdentity) String() string {
	return strconv.FormatInt(int64(id.RepositoryID), 10) + "/" +
		strconv.FormatInt(int64(id.RunID), 10) + "/" +
		strconv.FormatUint(uint64(id.RunAttempt), 10) + "/" +
		strconv.FormatInt(int64(id.JobID), 10)
}

// StepIdentity uses a timeline identifier when available. Otherwise it uses a
// job-scoped API number, lifecycle phase, and deterministic occurrence.
type StepIdentity struct {
	Job              JobExecutionIdentity `json:"job"`
	TimelineRecordID string               `json:"timeline_record_id,omitempty"`
	APIStepNumber    *APIStepNumber       `json:"api_step_number,omitempty"`
	ASTOrdinal       *ASTOrdinal          `json:"ast_ordinal,omitempty"`
	LifecyclePhase   LifecyclePhase       `json:"lifecycle_phase"`
	Occurrence       Occurrence           `json:"occurrence"`
}

func (id StepIdentity) Validate() error {
	if err := id.Job.Validate(); err != nil {
		return err
	}
	if !id.LifecyclePhase.Valid() {
		return fmt.Errorf("invalid lifecycle phase %q", id.LifecyclePhase)
	}
	if err := id.Occurrence.Validate(); err != nil {
		return err
	}
	if id.TimelineRecordID != "" {
		if !validBoundedIdentityText(id.TimelineRecordID, 256) {
			return errors.New("timeline record ID is invalid")
		}
		return nil
	}
	if id.APIStepNumber == nil {
		return errors.New("step requires a timeline record ID or API step number")
	}
	if err := id.APIStepNumber.Validate(); err != nil {
		return err
	}
	if id.ASTOrdinal != nil {
		if err := id.ASTOrdinal.Validate(); err != nil {
			return err
		}
	}
	return nil
}

func (id StepIdentity) Key() string {
	base := id.Job.String()
	if id.TimelineRecordID != "" {
		return base + "/timeline:" + id.TimelineRecordID + "/" + string(id.LifecyclePhase) + "/" + strconv.FormatUint(uint64(id.Occurrence), 10)
	}
	return base + "/step:" + strconv.FormatInt(int64(*id.APIStepNumber), 10) + "/" + string(id.LifecyclePhase) + "/" + strconv.FormatUint(uint64(id.Occurrence), 10)
}

func validBoundedIdentityText(value string, max int) bool {
	return value != "" && len(value) <= max && utf8.ValidString(value) && !hasASCIIControl(value)
}

func hasASCIIControl(value string) bool {
	for _, char := range value {
		if char < 0x20 || char == 0x7f {
			return true
		}
	}
	return false
}

type LogicalSourceID string
type EvidenceID string
type CollectionObservationID string
type CollectionSessionID string
type RequestID string
type RuntimeObservationID string
type CoverageUnitID string
type CoverageAssessmentID string
type CoverageObservationID string
type FindingID string
type FindingRevisionID string
type AnalysisSessionID string

func (id LogicalSourceID) Validate() error         { return validateVersionedID(string(id), "src1:") }
func (id EvidenceID) Validate() error              { return validateVersionedID(string(id), "ev1:") }
func (id CollectionObservationID) Validate() error { return validateVersionedID(string(id), "obs1:") }
func (id RuntimeObservationID) Validate() error    { return validateVersionedID(string(id), "rtobs1:") }
func (id CoverageUnitID) Validate() error          { return validateVersionedID(string(id), "cov1:") }
func (id CoverageAssessmentID) Validate() error    { return validateVersionedID(string(id), "cova1:") }
func (id CoverageObservationID) Validate() error   { return validateVersionedID(string(id), "covobs1:") }
func (id FindingID) Validate() error               { return validateVersionedID(string(id), "find1:") }
func (id FindingRevisionID) Validate() error       { return validateVersionedID(string(id), "frev1:") }

func (id CollectionSessionID) Validate() error {
	return validateOpaqueID(string(id), "collection session ID")
}
func (id RequestID) Validate() error { return validateOpaqueID(string(id), "request ID") }
func (id AnalysisSessionID) Validate() error {
	return validateOpaqueID(string(id), "analysis session ID")
}

func validateVersionedID(value, prefix string) error {
	if !strings.HasPrefix(value, prefix) || !versionedIDPattern.MatchString(value) {
		return fmt.Errorf("identifier must have %s followed by 64 lowercase hexadecimal characters", prefix)
	}
	return nil
}

func validateOpaqueID(value, name string) error {
	if !validBoundedIdentityText(value, 256) {
		return fmt.Errorf("%s is invalid", name)
	}
	return nil
}

func validateSHA256(value, name string) error {
	if len(value) != 64 || value != strings.ToLower(value) {
		return fmt.Errorf("%s must be 64 lowercase hexadecimal characters", name)
	}
	if _, err := hex.DecodeString(value); err != nil {
		return fmt.Errorf("%s is not hexadecimal: %w", name, err)
	}
	return nil
}
