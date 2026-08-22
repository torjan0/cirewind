package model

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"
)

type CoverageScope struct {
	RepositoryID *RepositoryID  `json:"repository_id,omitempty"`
	WorkflowPath *WorkflowPath  `json:"workflow_path,omitempty"`
	RunID        *WorkflowRunID `json:"run_id,omitempty"`
	RunAttempt   *RunAttempt    `json:"run_attempt,omitempty"`
	JobID        *JobID         `json:"job_id,omitempty"`
	StepKey      string         `json:"step_key,omitempty"`
}

func (s CoverageScope) Validate() error {
	if s.RepositoryID != nil {
		if err := s.RepositoryID.Validate(); err != nil {
			return err
		}
	}
	if s.WorkflowPath != nil {
		if err := s.WorkflowPath.Validate(); err != nil {
			return err
		}
	}
	if s.RunID != nil {
		if s.RepositoryID == nil {
			return errors.New("coverage run scope requires repository ID")
		}
		if err := s.RunID.Validate(); err != nil {
			return err
		}
	}
	if s.RunAttempt != nil {
		if s.RunID == nil {
			return errors.New("coverage attempt scope requires run ID")
		}
		if err := s.RunAttempt.Validate(); err != nil {
			return err
		}
	}
	if s.JobID != nil {
		if s.RunAttempt == nil {
			return errors.New("coverage job scope requires run attempt")
		}
		if err := s.JobID.Validate(); err != nil {
			return err
		}
	}
	if s.StepKey != "" {
		if s.JobID == nil || !validBoundedIdentityText(s.StepKey, 1024) {
			return errors.New("coverage step key requires a job and bounded identity")
		}
	}
	return nil
}

type CoverageUnit struct {
	ID                  CoverageUnitID `json:"coverage_unit_id"`
	Kind                CoverageKind   `json:"kind"`
	Scope               CoverageScope  `json:"scope"`
	LogicalKey          string         `json:"logical_key"`
	RequiredForNegative bool           `json:"required_for_negative"`
}

func (u CoverageUnit) Validate() error {
	if err := u.ID.Validate(); err != nil {
		return err
	}
	if !u.Kind.Valid() {
		return fmt.Errorf("invalid coverage kind %q", u.Kind)
	}
	if err := u.Scope.Validate(); err != nil {
		return fmt.Errorf("coverage scope: %w", err)
	}
	if !validBoundedIdentityText(u.LogicalKey, 2048) {
		return errors.New("coverage logical key is invalid")
	}
	return nil
}

type CoverageGapDetail struct {
	Reason            GapReason `json:"reason"`
	Retryable         bool      `json:"retryable"`
	Material          bool      `json:"material"`
	PermissionRelated *bool     `json:"permission_related,omitempty"`
	SanitizedMessage  string    `json:"sanitized_message,omitempty"`
}

func (g CoverageGapDetail) Validate() error {
	if !g.Reason.Valid() {
		return fmt.Errorf("invalid gap reason %q", g.Reason)
	}
	if len(g.SanitizedMessage) > 2048 || !utf8.ValidString(g.SanitizedMessage) || strings.IndexByte(g.SanitizedMessage, 0) >= 0 {
		return errors.New("gap message is not bounded UTF-8")
	}
	return nil
}

// CoverageAssessment is content-addressed independently of a collection
// session. Repeated observations of the same assessment therefore do not force
// a new finding revision.
type CoverageAssessment struct {
	ID            CoverageAssessmentID `json:"coverage_assessment_id"`
	UnitID        CoverageUnitID       `json:"coverage_unit_id"`
	Status        CoverageStatus       `json:"status"`
	ExpectedCount *uint64              `json:"expected_count,omitempty"`
	ObservedCount uint64               `json:"observed_count"`
	Gap           *CoverageGapDetail   `json:"gap,omitempty"`
	EvidenceIDs   []EvidenceID         `json:"evidence_ids"`
}

func (a CoverageAssessment) Validate() error {
	if err := a.ID.Validate(); err != nil {
		return err
	}
	if err := a.UnitID.Validate(); err != nil {
		return err
	}
	if !a.Status.Valid() {
		return fmt.Errorf("invalid coverage status %q", a.Status)
	}
	if a.ExpectedCount != nil && a.ObservedCount > *a.ExpectedCount && a.Status != CoverageGap {
		return errors.New("coverage observed count exceeds expected count")
	}
	if a.Status == CoverageGap {
		if a.Gap == nil {
			return errors.New("gap coverage requires gap detail")
		}
		if err := a.Gap.Validate(); err != nil {
			return err
		}
	} else if a.Gap != nil {
		return errors.New("non-gap coverage cannot carry gap detail")
	}
	return validateSortedUniqueEvidenceIDs(a.EvidenceIDs)
}

type CoverageObservation struct {
	ID                  CoverageObservationID `json:"coverage_observation_id"`
	AssessmentID        CoverageAssessmentID  `json:"coverage_assessment_id"`
	CollectionSessionID CollectionSessionID   `json:"collection_session_id"`
	ObservedAt          Instant               `json:"observed_at"`
}

func (o CoverageObservation) Validate() error {
	if err := o.ID.Validate(); err != nil {
		return err
	}
	if err := o.AssessmentID.Validate(); err != nil {
		return err
	}
	if err := o.CollectionSessionID.Validate(); err != nil {
		return err
	}
	return o.ObservedAt.Validate()
}

type CoverageSummary struct {
	Expected      uint64 `json:"expected"`
	Collected     uint64 `json:"collected"`
	NotApplicable uint64 `json:"not_applicable"`
	Gaps          uint64 `json:"gaps"`
	Open          uint64 `json:"open"`
	MaterialGaps  uint64 `json:"material_gaps"`
}

func (s CoverageSummary) Closed() bool {
	return s.Open == 0 && s.Expected == s.Collected+s.NotApplicable+s.Gaps
}

func (s CoverageSummary) AllowsNoMatchConfirmed() bool {
	return s.Closed() && s.MaterialGaps == 0
}

// ReconcileCoverage rejects duplicate units and assessments so one expected
// unit cannot be counted twice. Set requireTerminal when finalizing a scope.
func ReconcileCoverage(units []CoverageUnit, assessments []CoverageAssessment, requireTerminal bool) (CoverageSummary, error) {
	var summary CoverageSummary
	unitByID := make(map[CoverageUnitID]CoverageUnit, len(units))
	for _, unit := range units {
		if err := unit.Validate(); err != nil {
			return summary, fmt.Errorf("coverage unit: %w", err)
		}
		if _, exists := unitByID[unit.ID]; exists {
			return summary, fmt.Errorf("coverage unit %s counted twice", unit.ID)
		}
		unitByID[unit.ID] = unit
	}
	summary.Expected = uint64(len(unitByID))

	assessmentByUnit := make(map[CoverageUnitID]CoverageAssessment, len(assessments))
	assessmentIDs := make(map[CoverageAssessmentID]struct{}, len(assessments))
	for _, assessment := range assessments {
		if err := assessment.Validate(); err != nil {
			return summary, fmt.Errorf("coverage assessment: %w", err)
		}
		unit, exists := unitByID[assessment.UnitID]
		if !exists {
			return summary, fmt.Errorf("assessment %s references unknown coverage unit %s", assessment.ID, assessment.UnitID)
		}
		if _, exists := assessmentByUnit[assessment.UnitID]; exists {
			return summary, fmt.Errorf("coverage unit %s has multiple assessments", assessment.UnitID)
		}
		if _, exists := assessmentIDs[assessment.ID]; exists {
			return summary, fmt.Errorf("coverage assessment %s counted twice", assessment.ID)
		}
		assessmentByUnit[assessment.UnitID] = assessment
		assessmentIDs[assessment.ID] = struct{}{}
		switch assessment.Status {
		case CoverageExpected:
			summary.Open++
		case CoverageCollected:
			summary.Collected++
		case CoverageNotApplicable:
			summary.NotApplicable++
		case CoverageGap:
			summary.Gaps++
			if unit.RequiredForNegative && assessment.Gap != nil && assessment.Gap.Material {
				summary.MaterialGaps++
			}
		}
	}

	for id := range unitByID {
		if _, assessed := assessmentByUnit[id]; !assessed {
			summary.Open++
		}
	}
	if requireTerminal && summary.Open != 0 {
		return summary, fmt.Errorf("coverage has %d open expected units", summary.Open)
	}
	if summary.Expected != summary.Collected+summary.NotApplicable+summary.Gaps+summary.Open {
		return summary, errors.New("coverage reconciliation invariant failed")
	}
	return summary, nil
}

// ValidateFindingCoverage resolves a finding's assessment references and
// enforces the stronger negative-closure and evidence-gap invariants that
// cannot be checked from the Finding value alone.
func ValidateFindingCoverage(finding Finding, units []CoverageUnit, assessments []CoverageAssessment) error {
	if err := finding.Validate(); err != nil {
		return err
	}
	unitByID := make(map[CoverageUnitID]CoverageUnit, len(units))
	for _, unit := range units {
		if err := unit.Validate(); err != nil {
			return err
		}
		if _, duplicate := unitByID[unit.ID]; duplicate {
			return fmt.Errorf("duplicate coverage unit %s", unit.ID)
		}
		unitByID[unit.ID] = unit
	}
	assessmentByID := make(map[CoverageAssessmentID]CoverageAssessment, len(assessments))
	for _, assessment := range assessments {
		if err := assessment.Validate(); err != nil {
			return err
		}
		if _, duplicate := assessmentByID[assessment.ID]; duplicate {
			return fmt.Errorf("duplicate coverage assessment %s", assessment.ID)
		}
		assessmentByID[assessment.ID] = assessment
	}
	for _, gap := range finding.EvidenceGaps {
		assessment, exists := assessmentByID[gap.CoverageAssessmentID]
		if !exists {
			return fmt.Errorf("finding gap references unknown coverage assessment %s", gap.CoverageAssessmentID)
		}
		if assessment.Status != CoverageGap {
			return fmt.Errorf("finding gap references non-gap assessment %s", gap.CoverageAssessmentID)
		}
	}

	selectedUnits := make([]CoverageUnit, 0, len(finding.CollectionCoverage))
	selectedAssessments := make([]CoverageAssessment, 0, len(finding.CollectionCoverage))
	for _, assessmentID := range finding.CollectionCoverage {
		assessment, exists := assessmentByID[assessmentID]
		if !exists {
			return fmt.Errorf("finding references unknown coverage assessment %s", assessmentID)
		}
		unit, exists := unitByID[assessment.UnitID]
		if !exists {
			return fmt.Errorf("coverage assessment %s references unknown unit %s", assessmentID, assessment.UnitID)
		}
		selectedUnits = append(selectedUnits, unit)
		selectedAssessments = append(selectedAssessments, assessment)
	}
	if finding.State == NoMatchConfirmed {
		summary, err := ReconcileCoverage(selectedUnits, selectedAssessments, true)
		if err != nil {
			return fmt.Errorf("NO_MATCH_CONFIRMED coverage is not closed: %w", err)
		}
		if !summary.AllowsNoMatchConfirmed() {
			return errors.New("NO_MATCH_CONFIRMED coverage contains a material gap")
		}
	}
	return nil
}

func validateSortedUniqueEvidenceIDs(ids []EvidenceID) error {
	for index, id := range ids {
		if err := id.Validate(); err != nil {
			return err
		}
		if index > 0 && ids[index-1] >= id {
			return errors.New("evidence IDs must be strictly bytewise sorted and unique")
		}
	}
	return nil
}

func SortEvidenceIDs(ids []EvidenceID) []EvidenceID {
	result := append([]EvidenceID(nil), ids...)
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	return deduplicateEvidenceIDs(result)
}

func deduplicateEvidenceIDs(ids []EvidenceID) []EvidenceID {
	if len(ids) == 0 {
		return ids
	}
	write := 1
	for read := 1; read < len(ids); read++ {
		if ids[read] == ids[write-1] {
			continue
		}
		ids[write] = ids[read]
		write++
	}
	return ids[:write]
}
