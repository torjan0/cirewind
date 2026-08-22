package model

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// FindingState is the complete v0.1 forensic conclusion vocabulary. It is not
// an ordering and must never be treated as a risk score.
type FindingState string

const (
	ConfirmedExecuted       FindingState = "CONFIRMED_EXECUTED"
	ConfirmedDownloaded     FindingState = "CONFIRMED_DOWNLOADED"
	ConfirmedCalledWorkflow FindingState = "CONFIRMED_CALLED_WORKFLOW"
	DeclaredAtRunSHA        FindingState = "DECLARED_AT_RUN_SHA"
	RunInWindowMutableRef   FindingState = "RUN_IN_WINDOW_MUTABLE_REF"
	PotentialTransitive     FindingState = "POTENTIAL_TRANSITIVE"
	CurrentReferenceOnly    FindingState = "CURRENT_REFERENCE_ONLY"
	NoMatchConfirmed        FindingState = "NO_MATCH_CONFIRMED"
	UnknownEvidenceGap      FindingState = "UNKNOWN_EVIDENCE_GAP"
	ContradictoryEvidence   FindingState = "CONTRADICTORY_EVIDENCE"
)

var findingStates = [...]FindingState{
	ConfirmedExecuted,
	ConfirmedDownloaded,
	ConfirmedCalledWorkflow,
	DeclaredAtRunSHA,
	RunInWindowMutableRef,
	PotentialTransitive,
	CurrentReferenceOnly,
	NoMatchConfirmed,
	UnknownEvidenceGap,
	ContradictoryEvidence,
}

func FindingStates() []FindingState {
	return append([]FindingState(nil), findingStates[:]...)
}

func (s FindingState) Valid() bool {
	for _, candidate := range findingStates {
		if s == candidate {
			return true
		}
	}
	return false
}

func (s *FindingState) UnmarshalJSON(data []byte) error {
	return unmarshalStringEnum(data, (*string)(s), func(value string) bool {
		return FindingState(value).Valid()
	}, "finding state")
}

// ProvenanceLevel describes support for a proposition, not its severity.
type ProvenanceLevel string

const (
	L4Certain  ProvenanceLevel = "L4_CERTAIN"
	L3Strong   ProvenanceLevel = "L3_STRONG"
	L2Probable ProvenanceLevel = "L2_PROBABLE"
	L1Possible ProvenanceLevel = "L1_POSSIBLE"
	L0Unknown  ProvenanceLevel = "L0_UNKNOWN"
)

var provenanceLevels = [...]ProvenanceLevel{
	L4Certain,
	L3Strong,
	L2Probable,
	L1Possible,
	L0Unknown,
}

func ProvenanceLevels() []ProvenanceLevel {
	return append([]ProvenanceLevel(nil), provenanceLevels[:]...)
}

func (p ProvenanceLevel) Valid() bool {
	for _, candidate := range provenanceLevels {
		if p == candidate {
			return true
		}
	}
	return false
}

func (p *ProvenanceLevel) UnmarshalJSON(data []byte) error {
	return unmarshalStringEnum(data, (*string)(p), func(value string) bool {
		return ProvenanceLevel(value).Valid()
	}, "provenance level")
}

// RuntimeStage is the public lifecycle summary. DOWNLOADED means preparation
// completed; a download announcement alone never reaches this stage.
type RuntimeStage string

const (
	StageDeclared           RuntimeStage = "DECLARED"
	StageResolved           RuntimeStage = "RESOLVED"
	StageDownloaded         RuntimeStage = "DOWNLOADED"
	StageStepStarted        RuntimeStage = "STEP_STARTED"
	StageStepCompleted      RuntimeStage = "STEP_COMPLETED"
	StageRuntimeIOCObserved RuntimeStage = "RUNTIME_IOC_OBSERVED"
)

var runtimeStages = [...]RuntimeStage{
	StageDeclared,
	StageResolved,
	StageDownloaded,
	StageStepStarted,
	StageStepCompleted,
	StageRuntimeIOCObserved,
}

func RuntimeStages() []RuntimeStage { return append([]RuntimeStage(nil), runtimeStages[:]...) }

func (s RuntimeStage) Valid() bool {
	for _, candidate := range runtimeStages {
		if s == candidate {
			return true
		}
	}
	return false
}

func (s *RuntimeStage) UnmarshalJSON(data []byte) error {
	return unmarshalStringEnum(data, (*string)(s), func(value string) bool {
		return RuntimeStage(value).Valid()
	}, "runtime stage")
}

// RuntimeObservationKind preserves the evidence boundaries that a RuntimeStage
// intentionally summarizes.
type RuntimeObservationKind string

const (
	ObservationDeclared            RuntimeObservationKind = "DECLARED"
	ObservationResolutionObserved  RuntimeObservationKind = "RESOLUTION_OBSERVED"
	ObservationDownloadAnnounced   RuntimeObservationKind = "DOWNLOAD_ANNOUNCED"
	ObservationPreparationComplete RuntimeObservationKind = "PREPARATION_COMPLETED"
	ObservationPreparationFailed   RuntimeObservationKind = "PREPARATION_FAILED"
	ObservationConditionSkipped    RuntimeObservationKind = "CONDITION_SKIPPED"
	ObservationLifecycleStarted    RuntimeObservationKind = "LIFECYCLE_STARTED"
	ObservationLifecycleCompleted  RuntimeObservationKind = "LIFECYCLE_COMPLETED"
	ObservationRuntimeIOCObserved  RuntimeObservationKind = "RUNTIME_IOC_OBSERVED"
)

var runtimeObservationKinds = [...]RuntimeObservationKind{
	ObservationDeclared,
	ObservationResolutionObserved,
	ObservationDownloadAnnounced,
	ObservationPreparationComplete,
	ObservationPreparationFailed,
	ObservationConditionSkipped,
	ObservationLifecycleStarted,
	ObservationLifecycleCompleted,
	ObservationRuntimeIOCObserved,
}

func RuntimeObservationKinds() []RuntimeObservationKind {
	return append([]RuntimeObservationKind(nil), runtimeObservationKinds[:]...)
}

func (k RuntimeObservationKind) Valid() bool {
	for _, candidate := range runtimeObservationKinds {
		if k == candidate {
			return true
		}
	}
	return false
}

func (k RuntimeObservationKind) Stage() RuntimeStage {
	switch k {
	case ObservationDeclared:
		return StageDeclared
	case ObservationResolutionObserved, ObservationDownloadAnnounced, ObservationPreparationFailed:
		return StageResolved
	case ObservationPreparationComplete:
		return StageDownloaded
	case ObservationConditionSkipped:
		return StageDeclared
	case ObservationLifecycleStarted:
		return StageStepStarted
	case ObservationLifecycleCompleted:
		return StageStepCompleted
	case ObservationRuntimeIOCObserved:
		return StageRuntimeIOCObserved
	default:
		return ""
	}
}

func (k RuntimeObservationKind) SupportsDownloaded() bool {
	return k == ObservationPreparationComplete || k == ObservationLifecycleStarted || k == ObservationLifecycleCompleted
}

func (k RuntimeObservationKind) SupportsExecuted() bool {
	return k == ObservationLifecycleStarted || k == ObservationLifecycleCompleted
}

func (k *RuntimeObservationKind) UnmarshalJSON(data []byte) error {
	return unmarshalStringEnum(data, (*string)(k), func(value string) bool {
		return RuntimeObservationKind(value).Valid()
	}, "runtime observation kind")
}

type LifecyclePhase string

const (
	LifecyclePre  LifecyclePhase = "PRE"
	LifecycleMain LifecyclePhase = "MAIN"
	LifecyclePost LifecyclePhase = "POST"
)

func (p LifecyclePhase) Valid() bool {
	return p == LifecyclePre || p == LifecycleMain || p == LifecyclePost
}

func (p *LifecyclePhase) UnmarshalJSON(data []byte) error {
	return unmarshalStringEnum(data, (*string)(p), func(value string) bool {
		return LifecyclePhase(value).Valid()
	}, "lifecycle phase")
}

type CoverageStatus string

const (
	CoverageExpected      CoverageStatus = "EXPECTED"
	CoverageCollected     CoverageStatus = "COLLECTED"
	CoverageNotApplicable CoverageStatus = "NOT_APPLICABLE"
	CoverageGap           CoverageStatus = "GAP"
)

func (s CoverageStatus) Valid() bool {
	return s == CoverageExpected || s == CoverageCollected || s == CoverageNotApplicable || s == CoverageGap
}

func (s CoverageStatus) Terminal() bool { return s != CoverageExpected && s.Valid() }

func (s *CoverageStatus) UnmarshalJSON(data []byte) error {
	return unmarshalStringEnum(data, (*string)(s), func(value string) bool {
		return CoverageStatus(value).Valid()
	}, "coverage status")
}

type CoverageKind string

const (
	CoverageRepositoryVisibility CoverageKind = "REPOSITORY_VISIBILITY"
	CoverageRunPartition         CoverageKind = "RUN_PARTITION"
	CoverageWorkflowRun          CoverageKind = "WORKFLOW_RUN"
	CoverageRunAttempt           CoverageKind = "RUN_ATTEMPT"
	CoverageJob                  CoverageKind = "JOB"
	CoverageAttemptLog           CoverageKind = "ATTEMPT_LOG"
	CoverageJobLog               CoverageKind = "JOB_LOG"
	CoverageWorkflowDefinition   CoverageKind = "WORKFLOW_DEFINITION"
	CoverageActionDefinition     CoverageKind = "ACTION_DEFINITION"
	CoverageEnrichment           CoverageKind = "ENRICHMENT"
	CoverageParserGrammar        CoverageKind = "PARSER_GRAMMAR"
	CoverageSearchableLiteral    CoverageKind = "SEARCHABLE_LITERAL"
)

var coverageKinds = [...]CoverageKind{
	CoverageRepositoryVisibility,
	CoverageRunPartition,
	CoverageWorkflowRun,
	CoverageRunAttempt,
	CoverageJob,
	CoverageAttemptLog,
	CoverageJobLog,
	CoverageWorkflowDefinition,
	CoverageActionDefinition,
	CoverageEnrichment,
	CoverageParserGrammar,
	CoverageSearchableLiteral,
}

func (k CoverageKind) Valid() bool {
	for _, candidate := range coverageKinds {
		if k == candidate {
			return true
		}
	}
	return false
}

func (k *CoverageKind) UnmarshalJSON(data []byte) error {
	return unmarshalStringEnum(data, (*string)(k), func(value string) bool {
		return CoverageKind(value).Valid()
	}, "coverage kind")
}

type GapReason string

const (
	GapUnauthorized          GapReason = "UNAUTHORIZED"
	GapForbidden             GapReason = "FORBIDDEN"
	GapNotFound              GapReason = "NOT_FOUND"
	GapRetentionOrDeletion   GapReason = "RETENTION_OR_DELETION"
	GapRateLimited           GapReason = "RATE_LIMITED"
	GapSecondaryLimit        GapReason = "SECONDARY_LIMIT"
	GapTransientNetwork      GapReason = "TRANSIENT_NETWORK"
	GapRedirectExpired       GapReason = "REDIRECT_EXPIRED"
	GapSizeLimit             GapReason = "SIZE_LIMIT"
	GapFileCountLimit        GapReason = "FILE_COUNT_LIMIT"
	GapMalformedArchive      GapReason = "MALFORMED_ARCHIVE"
	GapMalformedYAML         GapReason = "MALFORMED_YAML"
	GapUnsupportedGrammar    GapReason = "UNSUPPORTED_GRAMMAR"
	GapAmbiguousCorrelation  GapReason = "AMBIGUOUS_CORRELATION"
	GapDynamicReference      GapReason = "DYNAMIC_REFERENCE"
	GapDensityCeiling        GapReason = "DENSITY_CEILING"
	GapLiveStateRace         GapReason = "LIVE_STATE_RACE"
	GapCancelled             GapReason = "CANCELLED"
	GapIntegrityFailure      GapReason = "INTEGRITY_FAILURE"
	GapEvidenceTruncated     GapReason = "EVIDENCE_TRUNCATED"
	GapHistoricalContentGone GapReason = "HISTORICAL_CONTENT_MISSING"
)

var gapReasons = [...]GapReason{
	GapUnauthorized,
	GapForbidden,
	GapNotFound,
	GapRetentionOrDeletion,
	GapRateLimited,
	GapSecondaryLimit,
	GapTransientNetwork,
	GapRedirectExpired,
	GapSizeLimit,
	GapFileCountLimit,
	GapMalformedArchive,
	GapMalformedYAML,
	GapUnsupportedGrammar,
	GapAmbiguousCorrelation,
	GapDynamicReference,
	GapDensityCeiling,
	GapLiveStateRace,
	GapCancelled,
	GapIntegrityFailure,
	GapEvidenceTruncated,
	GapHistoricalContentGone,
}

func (r GapReason) Valid() bool {
	for _, candidate := range gapReasons {
		if r == candidate {
			return true
		}
	}
	return false
}

func (r *GapReason) UnmarshalJSON(data []byte) error {
	return unmarshalStringEnum(data, (*string)(r), func(value string) bool {
		return GapReason(value).Valid()
	}, "coverage gap reason")
}

func unmarshalStringEnum(data []byte, target *string, valid func(string) bool, name string) error {
	if bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		return fmt.Errorf("%s cannot be null", name)
	}
	var value string
	if err := json.Unmarshal(data, &value); err != nil {
		return fmt.Errorf("decode %s: %w", name, err)
	}
	if !valid(value) {
		return fmt.Errorf("unknown %s %q", name, value)
	}
	*target = value
	return nil
}
