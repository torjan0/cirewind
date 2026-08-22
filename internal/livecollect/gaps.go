package livecollect

import (
	"fmt"
	"strings"

	"github.com/torjan0/cirewind/internal/archive"
	"github.com/torjan0/cirewind/internal/collect"
	"github.com/torjan0/cirewind/internal/evidence"
	"github.com/torjan0/cirewind/internal/model"
)

func appendGap(result *repositoryResult, gap collect.Gap) error {
	gap.Diagnostic = safeField(gap.Diagnostic, 2048)
	result.gaps = append(result.gaps, gap)
	if gap.RepositoryID <= 0 {
		return nil
	}
	fact, err := gapFact(gap)
	if err != nil {
		return err
	}
	result.facts = append(result.facts, fact)
	return nil
}

func appendCollectedCoverage(result *repositoryResult, kind model.CoverageKind, scope model.CoverageScope, logicalKey string, observed uint64, evidenceIDs []model.EvidenceID, required bool) error {
	unit := model.CoverageUnit{
		ID: model.CoverageUnitID("cov1:" + strings.Repeat("0", 64)), Kind: kind, Scope: scope,
		LogicalKey: logicalKey, RequiredForNegative: required,
	}
	unitID, err := evidence.NewCoverageUnitID(unit)
	if err != nil {
		return err
	}
	unit.ID = unitID
	assessment := model.CoverageAssessment{
		ID: model.CoverageAssessmentID("cova1:" + strings.Repeat("0", 64)), UnitID: unit.ID,
		Status: model.CoverageCollected, ObservedCount: observed, EvidenceIDs: model.SortEvidenceIDs(evidenceIDs),
	}
	assessmentID, err := evidence.NewCoverageAssessmentID(assessment)
	if err != nil {
		return err
	}
	assessment.ID = assessmentID
	result.facts = append(result.facts, archive.Fact{Kind: archive.FactCoverage, EvidenceIDs: model.SortEvidenceIDs(evidenceIDs), Coverage: &archive.CoverageFact{Unit: unit, Assessment: assessment}})
	return nil
}

func gapFact(gap collect.Gap) (archive.Fact, error) {
	return gapFactWithLogicalKey(gap, coverageLogicalKey(gap.Scope, gap.RepositoryID, gap.RunID, gap.Attempt, gap.JobID))
}

func gapFactWithLogicalKey(gap collect.Gap, logicalKey string) (archive.Fact, error) {
	scope := model.CoverageScope{}
	if gap.RepositoryID > 0 {
		repositoryID := model.RepositoryID(gap.RepositoryID)
		scope.RepositoryID = &repositoryID
	}
	if gap.RunID > 0 {
		runID := model.WorkflowRunID(gap.RunID)
		scope.RunID = &runID
	}
	if gap.Attempt > 0 {
		attempt := model.RunAttempt(gap.Attempt)
		scope.RunAttempt = &attempt
	}
	if gap.JobID > 0 {
		jobID := model.JobID(gap.JobID)
		scope.JobID = &jobID
	}
	unit := model.CoverageUnit{
		ID: model.CoverageUnitID("cov1:" + strings.Repeat("0", 64)), Kind: coverageKind(gap.Scope), Scope: scope,
		LogicalKey:          logicalKey,
		RequiredForNegative: gap.Material,
	}
	unitID, err := evidence.NewCoverageUnitID(unit)
	if err != nil {
		return archive.Fact{}, err
	}
	unit.ID = unitID
	permission := gap.Reason == collect.GapUnauthorized || gap.Reason == collect.GapForbidden
	message := gap.Diagnostic
	if message == "" {
		message = "collection evidence was unavailable"
	}
	assessment := model.CoverageAssessment{
		ID: model.CoverageAssessmentID("cova1:" + strings.Repeat("0", 64)), UnitID: unit.ID,
		Status: model.CoverageGap, ObservedCount: 0,
		Gap:         &model.CoverageGapDetail{Reason: modelGapReason(gap), Retryable: gap.Retryable, Material: gap.Material, PermissionRelated: &permission, SanitizedMessage: message},
		EvidenceIDs: []model.EvidenceID{},
	}
	assessmentID, err := evidence.NewCoverageAssessmentID(assessment)
	if err != nil {
		return archive.Fact{}, err
	}
	assessment.ID = assessmentID
	return archive.Fact{Kind: archive.FactCoverageGap, EvidenceIDs: []model.EvidenceID{}, CoverageGap: &archive.CoverageGapFact{Unit: unit, Assessment: assessment}}, nil
}

func coverageLogicalKey(scope string, repositoryID, runID int64, attempt int, jobID int64) string {
	return fmt.Sprintf("%s:%d:%d:%d:%d", safeMachine(scope, 128), repositoryID, runID, attempt, jobID)
}

func coverageKind(scope string) model.CoverageKind {
	switch scope {
	case "repository", "organization_repositories":
		return model.CoverageRepositoryVisibility
	case "run_partition", "run_partition_probe", "run_partition_pages":
		return model.CoverageRunPartition
	case "workflow_run", "workflow_run_stabilization":
		return model.CoverageWorkflowRun
	case "workflow_run_attempt":
		return model.CoverageRunAttempt
	case "attempt_job", "attempt_jobs":
		return model.CoverageJob
	case "attempt_log":
		return model.CoverageAttemptLog
	case "job_log":
		return model.CoverageJobLog
	case "setup_parser", "setup_correlation", "action_step_parser", "action_step_correlation", "action_step_resolution", "attempt_log_job_identity", "repository_hash_algorithm":
		return model.CoverageParserGrammar
	case "historical_workflow", "called_workflow_metadata", "called_workflow_definition":
		return model.CoverageWorkflowDefinition
	case "action_definition", "local_action_definition":
		return model.CoverageActionDefinition
	default:
		return model.CoverageEnrichment
	}
}

func modelGapReason(gap collect.Gap) model.GapReason {
	if gap.Scope == "historical_workflow" || gap.Scope == "called_workflow_definition" || gap.Scope == "action_definition" || gap.Scope == "local_action_definition" {
		return model.GapHistoricalContentGone
	}
	if (gap.Scope == "job_log" || gap.Scope == "attempt_log") && gap.Reason == collect.GapNotFound {
		return model.GapRetentionOrDeletion
	}
	switch gap.Reason {
	case collect.GapUnauthorized:
		return model.GapUnauthorized
	case collect.GapForbidden:
		return model.GapForbidden
	case collect.GapNotFound:
		return model.GapNotFound
	case collect.GapRetentionOrDeletion:
		return model.GapRetentionOrDeletion
	case collect.GapRateLimited:
		return model.GapRateLimited
	case collect.GapTransient:
		return model.GapTransientNetwork
	case collect.GapRedirectExpired:
		return model.GapRedirectExpired
	case collect.GapSizeLimit:
		return model.GapSizeLimit
	case collect.GapDensityCeiling:
		return model.GapDensityCeiling
	case collect.GapLiveStateRace:
		return model.GapLiveStateRace
	case collect.GapCancelled:
		return model.GapCancelled
	case collect.GapAmbiguousCorrelation:
		return model.GapAmbiguousCorrelation
	case collect.GapMalformedResponse, collect.GapAPIVersion, collect.GapValidation:
		return model.GapUnsupportedGrammar
	case collect.GapPagination, collect.GapPartitionLimit:
		return model.GapEvidenceTruncated
	case collect.GapUnsafeRedirect:
		return model.GapIntegrityFailure
	case collect.GapLocalIO, collect.GapUnknown:
		return model.GapHistoricalContentGone
	default:
		return model.GapHistoricalContentGone
	}
}
