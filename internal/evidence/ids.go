package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/torjan0/cirewind/internal/model"
)

var apiVersionMajorPattern = regexp.MustCompile(`^[a-z0-9.-]+/(v[1-9][0-9]*)(?:alpha[1-9][0-9]*|beta[1-9][0-9]*)?$`)

func canonicalID(prefix string, input any) (string, error) {
	preimage, err := CanonicalJSON(input)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(preimage)
	return prefix + hex.EncodeToString(sum[:]), nil
}

func CanonicalSHA256(input any) (string, error) {
	preimage, err := CanonicalJSON(input)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(preimage)
	return hex.EncodeToString(sum[:]), nil
}

func NewLogicalSourceID(identity LogicalSourceIdentity) (model.LogicalSourceID, error) {
	if err := identity.Validate(); err != nil {
		return "", err
	}
	preimage := struct {
		Version           string              `json:"version"`
		Kind              SourceKind          `json:"kind"`
		CanonicalID       string              `json:"canonical_id"`
		Scope             model.CoverageScope `json:"scope"`
		RequestParameters RequestParameters   `json:"request_parameters"`
	}{
		Version:           "src1",
		Kind:              identity.Kind,
		CanonicalID:       identity.CanonicalID,
		Scope:             identity.Scope,
		RequestParameters: identity.RequestParameters,
	}
	value, err := canonicalID("src1:", preimage)
	return model.LogicalSourceID(value), err
}

func NewEvidenceID(logicalSourceID model.LogicalSourceID, sourceContentSHA256 string, retention RetentionDescriptor) (model.EvidenceID, error) {
	if err := logicalSourceID.Validate(); err != nil {
		return "", err
	}
	if err := validateSHA256(sourceContentSHA256, "source-content SHA-256"); err != nil {
		return "", err
	}
	if err := retention.Validate(); err != nil {
		return "", err
	}
	preimage := struct {
		Version             string                `json:"version"`
		LogicalSourceID     model.LogicalSourceID `json:"logical_source_id"`
		SourceContentSHA256 string                `json:"source_content_sha256"`
		Retention           RetentionDescriptor   `json:"retention"`
	}{"ev1", logicalSourceID, sourceContentSHA256, retention}
	value, err := canonicalID("ev1:", preimage)
	return model.EvidenceID(value), err
}

// NewDerivedLogicalSource binds a derived logical source to its complete
// parent/rule/payload provenance. It never treats a display description as the
// derivation identity.
func NewDerivedLogicalSource(scope model.CoverageScope, derivation DerivationDescriptor, derivedPayloadSHA256 string) (LogicalSource, error) {
	if derivation.Kind == "" {
		return LogicalSource{}, errors.New("derived logical source requires derivation metadata")
	}
	derivation.ParentEvidenceIDs = sortEvidenceIDs(derivation.ParentEvidenceIDs)
	if err := derivation.Validate(); err != nil {
		return LogicalSource{}, err
	}
	if err := validateSHA256(derivedPayloadSHA256, "derived payload SHA-256"); err != nil {
		return LogicalSource{}, err
	}
	identityInput := struct {
		Version              string             `json:"version"`
		Kind                 string             `json:"kind"`
		ParentEvidenceIDs    []model.EvidenceID `json:"parent_evidence_ids"`
		RuleID               string             `json:"rule_id"`
		RuleVersion          string             `json:"rule_version"`
		ParametersSHA256     *string            `json:"parameters_sha256,omitempty"`
		DerivedPayloadSHA256 string             `json:"derived_payload_sha256"`
	}{"derived1", derivation.Kind, derivation.ParentEvidenceIDs, derivation.RuleID, derivation.RuleVersion, derivation.ParametersSHA256, derivedPayloadSHA256}
	canonicalID, err := canonicalID("derived1:", identityInput)
	if err != nil {
		return LogicalSource{}, err
	}
	source := LogicalSource{
		Kind:              SourceDerivedRecord,
		CanonicalID:       canonicalID,
		RequestParameters: RequestParameters{},
	}
	source.ID, err = NewLogicalSourceID(source.Identity(scope))
	if err != nil {
		return LogicalSource{}, err
	}
	return source, nil
}

func NewCollectionObservationID(evidenceID model.EvidenceID, sessionID model.CollectionSessionID, requestID model.RequestID, collectionEndedAt model.Instant, requestAttempt uint32) (model.CollectionObservationID, error) {
	if err := evidenceID.Validate(); err != nil {
		return "", err
	}
	if err := sessionID.Validate(); err != nil {
		return "", err
	}
	if err := requestID.Validate(); err != nil {
		return "", err
	}
	if err := collectionEndedAt.Validate(); err != nil {
		return "", err
	}
	if requestAttempt == 0 {
		return "", errors.New("request attempt must be positive")
	}
	preimage := struct {
		Version             string                    `json:"version"`
		EvidenceID          model.EvidenceID          `json:"evidence_id"`
		CollectionSessionID model.CollectionSessionID `json:"collection_session_id"`
		RequestID           model.RequestID           `json:"request_id"`
		CollectionEndedAt   model.Instant             `json:"collection_ended_at"`
		RequestAttempt      uint32                    `json:"request_attempt"`
	}{"obs1", evidenceID, sessionID, requestID, collectionEndedAt, requestAttempt}
	value, err := canonicalID("obs1:", preimage)
	return model.CollectionObservationID(value), err
}

func NewRuntimeObservationID(observation model.RuntimeActionObservation) (model.RuntimeObservationID, error) {
	observation.ID = model.RuntimeObservationID("rtobs1:" + strings.Repeat("0", 64))
	observation.SourceEvidenceIDs = model.SortEvidenceIDs(observation.SourceEvidenceIDs)
	if err := observation.Validate(); err != nil {
		return "", err
	}
	preimage := struct {
		Version           string                       `json:"version"`
		Kind              model.RuntimeObservationKind `json:"kind"`
		Execution         model.JobExecutionIdentity   `json:"execution"`
		Step              *model.StepIdentity          `json:"step,omitempty"`
		ActionRepository  model.RepositorySlug         `json:"action_repository"`
		ActionSubpath     string                       `json:"action_subpath,omitempty"`
		DeclaredRef       string                       `json:"declared_ref,omitempty"`
		SourceObjectID    *model.ActionSourceObjectID  `json:"source_object_id,omitempty"`
		PackageDigest     *model.PackageDigest         `json:"package_digest,omitempty"`
		ImmutableVersion  string                       `json:"immutable_version,omitempty"`
		EventTime         model.EventInterval          `json:"event_time"`
		SourceEvidenceIDs []model.EvidenceID           `json:"source_evidence_ids"`
		SourceSpan        model.SourceSpan             `json:"source_span"`
		ExtractorName     string                       `json:"extractor_name"`
		ExtractorVersion  string                       `json:"extractor_version"`
		RulesetSHA256     string                       `json:"ruleset_sha256"`
	}{
		Version:           "rtobs1",
		Kind:              observation.Kind,
		Execution:         observation.Execution,
		Step:              observation.Step,
		ActionRepository:  observation.ActionRepository,
		ActionSubpath:     observation.ActionSubpath,
		DeclaredRef:       observation.DeclaredRef,
		SourceObjectID:    observation.SourceObjectID,
		PackageDigest:     observation.PackageDigest,
		ImmutableVersion:  observation.ImmutableVersion,
		EventTime:         observation.EventTime,
		SourceEvidenceIDs: observation.SourceEvidenceIDs,
		SourceSpan:        observation.SourceSpan,
		ExtractorName:     observation.ExtractorName,
		ExtractorVersion:  observation.ExtractorVersion,
		RulesetSHA256:     observation.RulesetSHA256,
	}
	value, err := canonicalID("rtobs1:", preimage)
	return model.RuntimeObservationID(value), err
}

func ValidateRuntimeObservationIdentity(observation model.RuntimeActionObservation) error {
	if err := observation.Validate(); err != nil {
		return err
	}
	expected, err := NewRuntimeObservationID(observation)
	if err != nil {
		return err
	}
	if expected != observation.ID {
		return errors.New("runtime observation ID does not match its canonical identity")
	}
	return nil
}

func NewCoverageUnitID(unit model.CoverageUnit) (model.CoverageUnitID, error) {
	unit.ID = model.CoverageUnitID("cov1:" + strings.Repeat("0", 64))
	if err := unit.Validate(); err != nil {
		return "", err
	}
	preimage := struct {
		Version             string              `json:"version"`
		Kind                model.CoverageKind  `json:"kind"`
		Scope               model.CoverageScope `json:"scope"`
		LogicalKey          string              `json:"logical_key"`
		RequiredForNegative bool                `json:"required_for_negative"`
	}{"cov1", unit.Kind, unit.Scope, unit.LogicalKey, unit.RequiredForNegative}
	value, err := canonicalID("cov1:", preimage)
	return model.CoverageUnitID(value), err
}

func ValidateCoverageUnitIdentity(unit model.CoverageUnit) error {
	if err := unit.Validate(); err != nil {
		return err
	}
	expected, err := NewCoverageUnitID(unit)
	if err != nil {
		return err
	}
	if expected != unit.ID {
		return errors.New("coverage unit ID does not match its canonical identity")
	}
	return nil
}

func NewCoverageAssessmentID(assessment model.CoverageAssessment) (model.CoverageAssessmentID, error) {
	assessment.ID = model.CoverageAssessmentID("cova1:" + strings.Repeat("0", 64))
	assessment.EvidenceIDs = model.SortEvidenceIDs(assessment.EvidenceIDs)
	if err := assessment.Validate(); err != nil {
		return "", err
	}
	preimage := struct {
		Version       string                   `json:"version"`
		UnitID        model.CoverageUnitID     `json:"coverage_unit_id"`
		Status        model.CoverageStatus     `json:"status"`
		ExpectedCount *uint64                  `json:"expected_count,omitempty"`
		ObservedCount uint64                   `json:"observed_count"`
		Gap           *model.CoverageGapDetail `json:"gap,omitempty"`
		EvidenceIDs   []model.EvidenceID       `json:"evidence_ids"`
	}{"cova1", assessment.UnitID, assessment.Status, assessment.ExpectedCount, assessment.ObservedCount, assessment.Gap, assessment.EvidenceIDs}
	value, err := canonicalID("cova1:", preimage)
	return model.CoverageAssessmentID(value), err
}

func ValidateCoverageAssessmentIdentity(assessment model.CoverageAssessment) error {
	if err := assessment.Validate(); err != nil {
		return err
	}
	expected, err := NewCoverageAssessmentID(assessment)
	if err != nil {
		return err
	}
	if expected != assessment.ID {
		return errors.New("coverage assessment ID does not match its canonical identity")
	}
	return nil
}

func NewCoverageObservationID(assessmentID model.CoverageAssessmentID, sessionID model.CollectionSessionID, observedAt model.Instant) (model.CoverageObservationID, error) {
	if err := assessmentID.Validate(); err != nil {
		return "", err
	}
	if err := sessionID.Validate(); err != nil {
		return "", err
	}
	if err := observedAt.Validate(); err != nil {
		return "", err
	}
	preimage := struct {
		Version             string                     `json:"version"`
		AssessmentID        model.CoverageAssessmentID `json:"coverage_assessment_id"`
		CollectionSessionID model.CollectionSessionID  `json:"collection_session_id"`
		ObservedAt          model.Instant              `json:"observed_at"`
	}{"covobs1", assessmentID, sessionID, observedAt}
	value, err := canonicalID("covobs1:", preimage)
	return model.CoverageObservationID(value), err
}

func ValidateCoverageObservationIdentity(observation model.CoverageObservation) error {
	if err := observation.Validate(); err != nil {
		return err
	}
	expected, err := NewCoverageObservationID(observation.AssessmentID, observation.CollectionSessionID, observation.ObservedAt)
	if err != nil {
		return err
	}
	if expected != observation.ID {
		return errors.New("coverage observation ID does not match its canonical identity")
	}
	return nil
}

type FindingLogicalInput struct {
	IncidentID      string               `json:"incident_id"`
	IncidentAPI     string               `json:"incident_api_version"`
	IndicatorID     string               `json:"indicator_id"`
	Subject         model.FindingSubject `json:"subject"`
	PropositionKind string               `json:"proposition_kind"`
}

func NewFindingID(input FindingLogicalInput) (model.FindingID, error) {
	if input.IncidentID == "" || input.IndicatorID == "" || input.PropositionKind == "" {
		return "", errors.New("finding identity requires incident, indicator, and proposition kind")
	}
	if err := input.Subject.Validate(); err != nil {
		return "", err
	}
	major, err := IncidentAPIMajor(input.IncidentAPI)
	if err != nil {
		return "", err
	}
	preimage := struct {
		Version         string                 `json:"version"`
		IncidentID      string                 `json:"incident_id"`
		IncidentMajor   string                 `json:"incident_api_major"`
		IndicatorID     string                 `json:"indicator_id"`
		Subject         findingSubjectIdentity `json:"subject"`
		PropositionKind string                 `json:"proposition_kind"`
	}{"find1", input.IncidentID, major, input.IndicatorID, subjectIdentity(input.Subject), input.PropositionKind}
	value, err := canonicalID("find1:", preimage)
	return model.FindingID(value), err
}

type FindingRevisionInput struct {
	FindingID           model.FindingID              `json:"finding_id"`
	CanonicalPackSHA256 string                       `json:"canonical_pack_sha256"`
	State               model.FindingState           `json:"state"`
	Provenance          model.ProvenanceLevel        `json:"provenance"`
	EvidenceIDs         []model.EvidenceID           `json:"evidence_ids"`
	CoverageIDs         []model.CoverageAssessmentID `json:"coverage_ids"`
	RuleVersion         string                       `json:"rule_version"`
	Proposition         model.Proposition            `json:"proposition"`
}

func NewFindingRevisionID(input FindingRevisionInput) (model.FindingRevisionID, error) {
	if err := input.FindingID.Validate(); err != nil {
		return "", err
	}
	if err := validateSHA256(input.CanonicalPackSHA256, "canonical pack SHA-256"); err != nil {
		return "", err
	}
	if !input.State.Valid() || !input.Provenance.Valid() || input.RuleVersion == "" {
		return "", errors.New("finding revision has invalid state, provenance, or rule version")
	}
	input.EvidenceIDs = model.SortEvidenceIDs(input.EvidenceIDs)
	input.CoverageIDs = model.SortCoverageAssessmentIDs(input.CoverageIDs)
	input.Proposition = model.NormalizeProposition(input.Proposition)
	if err := input.Proposition.Validate(); err != nil {
		return "", err
	}
	for _, id := range input.EvidenceIDs {
		if err := id.Validate(); err != nil {
			return "", err
		}
	}
	for _, id := range input.CoverageIDs {
		if err := id.Validate(); err != nil {
			return "", err
		}
	}
	preimage := struct {
		Version             string                       `json:"version"`
		FindingID           model.FindingID              `json:"finding_id"`
		CanonicalPackSHA256 string                       `json:"canonical_pack_sha256"`
		State               model.FindingState           `json:"state"`
		Provenance          model.ProvenanceLevel        `json:"provenance"`
		EvidenceIDs         []model.EvidenceID           `json:"evidence_ids"`
		CoverageIDs         []model.CoverageAssessmentID `json:"coverage_ids"`
		RuleVersion         string                       `json:"rule_version"`
		Proposition         model.Proposition            `json:"proposition"`
	}{"frev1", input.FindingID, input.CanonicalPackSHA256, input.State, input.Provenance, input.EvidenceIDs, input.CoverageIDs, input.RuleVersion, input.Proposition}
	value, err := canonicalID("frev1:", preimage)
	return model.FindingRevisionID(value), err
}

// ValidateFindingIdentity checks both the logical and revision identities. It
// intentionally excludes display prose, analysis time, and engine build.
func ValidateFindingIdentity(finding model.Finding) error {
	if err := finding.Validate(); err != nil {
		return err
	}
	logicalID, err := NewFindingID(FindingLogicalInput{
		IncidentID:      finding.Incident.ID,
		IncidentAPI:     finding.Incident.APIVersion,
		IndicatorID:     finding.IndicatorID,
		Subject:         finding.Subject,
		PropositionKind: finding.Proposition.Kind,
	})
	if err != nil {
		return err
	}
	if logicalID != finding.FindingID {
		return errors.New("finding ID does not match its canonical identity")
	}
	revisionID, err := NewFindingRevisionID(FindingRevisionInput{
		FindingID:           finding.FindingID,
		CanonicalPackSHA256: finding.Incident.CanonicalPackSHA256,
		State:               finding.State,
		Provenance:          finding.ProvenanceLevel,
		EvidenceIDs:         finding.EvidenceObjectIDs,
		CoverageIDs:         finding.CollectionCoverage,
		RuleVersion:         finding.Derivation.RuleVersion,
		Proposition:         finding.Proposition,
	})
	if err != nil {
		return err
	}
	if revisionID != finding.FindingRevisionID {
		return errors.New("finding revision ID does not match its canonical identity")
	}
	return nil
}

func IncidentAPIMajor(apiVersion string) (string, error) {
	matches := apiVersionMajorPattern.FindStringSubmatch(apiVersion)
	if len(matches) != 2 {
		return "", fmt.Errorf("incident API version %q does not encode a supported major", apiVersion)
	}
	return matches[1], nil
}

type findingSubjectIdentity struct {
	RepositoryID     model.RepositoryID                `json:"repository_id"`
	WorkflowPath     *model.WorkflowPath               `json:"workflow_path"`
	WorkflowObjectID *model.WorkflowDefinitionObjectID `json:"workflow_object_id"`
	WorkflowUnknown  bool                              `json:"workflow_unknown"`
	RunID            *model.WorkflowRunID              `json:"run_id"`
	RunAttempt       *model.RunAttempt                 `json:"run_attempt"`
	JobID            *model.JobID                      `json:"job_id"`
	StepKey          string                            `json:"step_key,omitempty"`
}

func subjectIdentity(subject model.FindingSubject) findingSubjectIdentity {
	identity := findingSubjectIdentity{
		RepositoryID:     subject.Repository.ID,
		WorkflowPath:     subject.Workflow.Path,
		WorkflowObjectID: subject.Workflow.DefinitionObjectID,
		WorkflowUnknown:  subject.Workflow.Path == nil,
		RunID:            subject.RunID,
		RunAttempt:       subject.RunAttempt,
		JobID:            subject.JobID,
	}
	if subject.Step != nil {
		identity.StepKey = subject.Step.Key()
	}
	return identity
}

func SortedStrings(values []string) []string {
	result := append([]string(nil), values...)
	sort.Strings(result)
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
