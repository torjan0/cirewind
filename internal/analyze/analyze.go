// Package analyze applies validated incident packs to compact archived facts.
// It performs no network or process execution.
package analyze

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/torjan0/cirewind/internal/archive"
	"github.com/torjan0/cirewind/internal/evidence"
	"github.com/torjan0/cirewind/internal/graph"
	"github.com/torjan0/cirewind/internal/incident"
	"github.com/torjan0/cirewind/internal/match"
	"github.com/torjan0/cirewind/internal/model"
	"github.com/torjan0/cirewind/internal/report"
)

const EngineVersion = "cirewind-analyzer/v1alpha1"

const (
	ModeInvestigate = "investigate"
	ModeReplay      = "replay"
)

type Result struct {
	Case report.Case
}

type index struct {
	repositories    map[model.RepositoryID]model.RepositorySubject
	runs            map[string]archive.RunFact
	attempts        map[string]archive.AttemptFact
	jobs            map[string]archive.JobFact
	repositoryFacts map[model.RepositoryID]archive.Fact
	runFacts        map[string]archive.Fact
	attemptFacts    map[string]archive.Fact
	jobFacts        map[string]archive.Fact
	factsByID       map[string]archive.Fact
	actions         []archive.Fact
	dependencies    []archive.Fact
	exposures       []archive.Fact
	coverage        []archive.Fact
	gaps            []archive.Fact
}

// Derive deterministically applies one validated pack to one compact snapshot.
func Derive(snapshot archive.Snapshot, pack *incident.ValidatedPack, analysisTime time.Time, mode string) (Result, error) {
	if pack == nil {
		return Result{}, errors.New("validated incident pack is nil")
	}
	if analysisTime.IsZero() {
		return Result{}, errors.New("analysis time is required")
	}
	analysisTime = analysisTime.UTC().Round(0)
	if mode != ModeReplay && mode != ModeInvestigate {
		return Result{}, fmt.Errorf("invalid analysis mode %q", mode)
	}
	idx, err := buildIndex(snapshot)
	if err != nil {
		return Result{}, err
	}
	if mode == ModeInvestigate {
		windows, windowErr := investigateWindows(snapshot)
		if windowErr != nil {
			return Result{}, windowErr
		}
		idx = restrictIndexToWindows(idx, windows)
	}
	metadata := buildMetadata(snapshot, pack, analysisTime, mode, idx)
	caseValue := report.Case{Metadata: metadata, Graph: graph.Graph{SchemaVersion: graph.SchemaVersion}}
	caseValue.Metadata.CaseID = deterministicID("case1", snapshot.Metadata.ArchiveID, pack.CanonicalSHA256, analysisTime.Format(time.RFC3339Nano), mode)

	components := make(map[string]incident.Component, len(pack.Pack.Spec.Components))
	for _, component := range pack.Pack.Spec.Components {
		components[component.ID] = component
	}
	for _, indicator := range pack.Pack.Spec.Indicators {
		component := components[indicator.ComponentID]
		findings, err := deriveIndicator(idx, pack, component, indicator, analysisTime)
		if err != nil {
			return Result{}, fmt.Errorf("indicator %s: %w", indicator.ID, err)
		}
		caseValue.Findings = append(caseValue.Findings, findings...)
	}
	caseValue.Graph = buildGraph(idx, caseValue.Findings)
	if err := caseValue.NormalizeAndValidate(); err != nil {
		return Result{}, err
	}
	return Result{Case: caseValue}, nil
}

func buildIndex(snapshot archive.Snapshot) (index, error) {
	idx := index{
		repositories: map[model.RepositoryID]model.RepositorySubject{}, runs: map[string]archive.RunFact{},
		attempts: map[string]archive.AttemptFact{}, jobs: map[string]archive.JobFact{},
		repositoryFacts: map[model.RepositoryID]archive.Fact{}, runFacts: map[string]archive.Fact{},
		attemptFacts: map[string]archive.Fact{}, jobFacts: map[string]archive.Fact{}, factsByID: map[string]archive.Fact{},
	}
	for _, fact := range snapshot.Facts {
		if fact.ID != "" {
			idx.factsByID[fact.ID] = fact
		}
		switch fact.Kind {
		case archive.FactRepository:
			if fact.Repository != nil {
				idx.repositories[fact.Repository.Repository.ID] = fact.Repository.Repository
				idx.repositoryFacts[fact.Repository.Repository.ID] = fact
			}
		case archive.FactRun:
			if fact.Run != nil {
				key := runKey(fact.Run.RepositoryID, fact.Run.RunID)
				idx.runs[key] = *fact.Run
				idx.runFacts[key] = fact
			}
		case archive.FactAttempt:
			if fact.Attempt != nil {
				key := attemptKey(fact.Attempt.RepositoryID, fact.Attempt.RunID, fact.Attempt.RunAttempt)
				idx.attempts[key] = *fact.Attempt
				idx.attemptFacts[key] = fact
			}
		case archive.FactJob:
			if fact.Job != nil {
				idx.jobs[fact.Job.Execution.String()] = *fact.Job
				idx.jobFacts[fact.Job.Execution.String()] = fact
			}
		case archive.FactActionOccurrence:
			idx.actions = append(idx.actions, fact)
		case archive.FactDependency:
			idx.dependencies = append(idx.dependencies, fact)
		case archive.FactExposure:
			idx.exposures = append(idx.exposures, fact)
		case archive.FactCoverage:
			idx.coverage = append(idx.coverage, fact)
		case archive.FactCoverageGap:
			idx.gaps = append(idx.gaps, fact)
		}
	}
	return idx, nil
}

// investigateWindows returns every explicitly requested investigation window.
// Discovery windows are deliberately ignored: they exist to find parent runs
// and reruns, not to widen the incident-analysis scope.
func investigateWindows(snapshot archive.Snapshot) ([]model.EventInterval, error) {
	windows := make([]model.EventInterval, 0, len(snapshot.Collections))
	for _, collection := range snapshot.Collections {
		if collection.Mode != ModeInvestigate {
			continue
		}
		window := collection.Scope.RequestedEventWindow
		if window == nil {
			continue
		}
		if err := window.Validate(); err != nil || window.Start == nil || window.End == nil || window.Bounds == nil {
			if err == nil {
				err = errors.New("window is not bounded")
			}
			return nil, fmt.Errorf("investigate collection %s requested event window: %w", collection.ID, err)
		}
		windows = append(windows, *window)
	}
	if len(windows) == 0 {
		return nil, errors.New("investigate analysis requires an explicit requested event window")
	}
	sort.Slice(windows, func(i, j int) bool {
		if !windows[i].Start.Equal(windows[j].Start.Time) {
			return windows[i].Start.Before(windows[j].Start.Time)
		}
		if !windows[i].End.Equal(windows[j].End.Time) {
			return windows[i].End.Before(windows[j].End.Time)
		}
		return *windows[i].Bounds < *windows[j].Bounds
	})
	return windows, nil
}

func restrictIndexToWindows(idx index, windows []model.EventInterval) index {
	idx.actions = filterFacts(idx, idx.actions, windows)
	idx.dependencies = filterFacts(idx, idx.dependencies, windows)
	idx.gaps = filterFacts(idx, idx.gaps, windows)
	return idx
}

func filterFacts(idx index, facts []archive.Fact, windows []model.EventInterval) []archive.Fact {
	filtered := make([]archive.Fact, 0, len(facts))
	for _, fact := range facts {
		event, known := effectiveFactEvent(idx, fact)
		if known && overlapsAnyWindow(event, windows) {
			filtered = append(filtered, fact)
			continue
		}
		// A coverage gap with no recoverable event time is itself the reason
		// window membership cannot be established. Preserve the unknown rather
		// than silently turning missing evidence into a negative conclusion.
		if !known && fact.Kind == archive.FactCoverageGap {
			filtered = append(filtered, fact)
		}
	}
	return filtered
}

func effectiveFactEvent(idx index, fact archive.Fact) (model.EventInterval, bool) {
	if fact.EventTime.Start != nil {
		return fact.EventTime, true
	}
	subject := fact.Subject
	if subject.RunID == nil {
		return fact.EventTime, false
	}
	if subject.JobID != nil && subject.RunAttempt != nil {
		execution := model.JobExecutionIdentity{
			RepositoryID: subject.RepositoryID,
			RunID:        *subject.RunID,
			RunAttempt:   *subject.RunAttempt,
			JobID:        *subject.JobID,
		}
		if job, ok := idx.jobs[execution.String()]; ok && job.EventTime.Start != nil {
			return job.EventTime, true
		}
	}
	if subject.RunAttempt != nil {
		if attempt, ok := idx.attempts[attemptKey(subject.RepositoryID, *subject.RunID, *subject.RunAttempt)]; ok && attempt.EventTime.Start != nil {
			return attempt.EventTime, true
		}
	}
	if run, ok := idx.runs[runKey(subject.RepositoryID, *subject.RunID)]; ok && run.EventTime.Start != nil {
		return run.EventTime, true
	}
	return fact.EventTime, false
}

func overlapsAnyWindow(event model.EventInterval, windows []model.EventInterval) bool {
	for _, window := range windows {
		if intervalsOverlap(event, window) {
			return true
		}
	}
	return false
}

func intervalsOverlap(left, right model.EventInterval) bool {
	if left.Start == nil || right.Start == nil {
		return false
	}
	leftEnd, leftEndClosed := intervalEnd(left)
	rightEnd, rightEndClosed := intervalEnd(right)
	leftStartClosed := intervalStartClosed(left)
	rightStartClosed := intervalStartClosed(right)
	if leftEnd.Before(right.Start.Time) || rightEnd.Before(left.Start.Time) {
		return false
	}
	if leftEnd.Equal(right.Start.Time) && !(leftEndClosed && rightStartClosed) {
		return false
	}
	if rightEnd.Equal(left.Start.Time) && !(rightEndClosed && leftStartClosed) {
		return false
	}
	return true
}

func intervalStartClosed(interval model.EventInterval) bool {
	return interval.End == nil || interval.Bounds == nil || strings.HasPrefix(string(*interval.Bounds), "[")
}

func intervalEnd(interval model.EventInterval) (time.Time, bool) {
	if interval.End == nil {
		return interval.Start.Time, true
	}
	return interval.End.Time, interval.Bounds != nil && strings.HasSuffix(string(*interval.Bounds), "]")
}

func deriveIndicator(idx index, pack *incident.ValidatedPack, component incident.Component, indicator incident.Indicator, analysisTime time.Time) ([]report.Finding, error) {
	var findings []report.Finding
	seen := make(map[string]bool)

	for _, fact := range idx.actions {
		obs := fact.ActionOccurrence.Observation
		if !componentMatches(component, string(obs.ActionRepository), obs.ActionSubpath) {
			continue
		}
		identityMatch := runtimeIdentityMatches(indicator, obs)
		knownGood := runtimeKnownGood(pack.Pack.Spec.KnownGood, indicator.ComponentID, obs)
		if !identityMatch && !knownGood {
			continue
		}
		if strongerRuntimeObservationExists(idx, fact, component, indicator) {
			continue
		}
		candidate := match.Candidate{
			SameAttemptExactRuntime: identityMatch || knownGood,
			KnownGoodExactRuntime:   knownGood,
			EvidenceIDs:             append([]model.EvidenceID(nil), fact.EvidenceIDs...),
			PreparationCompleted:    obs.Kind.SupportsDownloaded(),
			LifecycleStarted:        obs.Kind.SupportsExecuted(),
			DownloadAnnouncedOnly:   obs.Kind == model.ObservationDownloadAnnounced || obs.Kind == model.ObservationResolutionObserved,
			MaterialEvidenceGap:     hasMaterialGap(idx, fact.Subject),
			RequiredCoverageClosed:  !hasMaterialGap(idx, fact.Subject),
			CoverageIDs:             coverageFor(idx, fact.Subject),
		}
		// Exact known-good evidence supports a negative only with independently
		// closed coverage; absence of a coverage record is not closure.
		if knownGood && len(candidate.CoverageIDs) == 0 {
			candidate.RequiredCoverageClosed = false
		}
		decision, err := match.Derive(candidate)
		if err != nil {
			continue
		}
		finding, err := makeFinding(idx, pack, indicator, fact.Subject, obs.Step, obs.EventTime, candidate, decision, analysisTime)
		if err != nil {
			return nil, err
		}
		appendUnique(&findings, seen, finding)
	}

	for _, fact := range idx.dependencies {
		dep := fact.Dependency
		if dep == nil || !componentMatches(component, string(dep.TargetRepository), dep.TargetPath) {
			continue
		}
		candidate := match.Candidate{EvidenceIDs: append([]model.EvidenceID(nil), fact.EvidenceIDs...), CoverageIDs: coverageFor(idx, fact.Subject)}
		candidate.MaterialContradiction = len(dep.ContradictsFactIDs) != 0
		switch indicator.Kind {
		case "action-commit", "digest":
			if !dependencyExactMatches(indicator, *dep) {
				continue
			}
			if dep.Basis == archive.DefinitionCurrentSnapshot {
				candidate.CurrentReferenceOnly = true
			} else if dep.TransitiveDepth > 0 || dep.Relation == archive.DependencyActionContainsAction {
				candidate.PotentialTransitive = true
			} else {
				candidate.HistoricalExactDeclared = true
			}
		case "reusable-workflow-commit":
			if !dependencyExactMatches(indicator, *dep) {
				continue
			}
			if (dep.Execution != nil || dep.AttemptExecution != nil) && dep.TargetCalledWorkflowObjectID != nil {
				candidate.ExactCalledWorkflow = true
			} else if dep.Basis == archive.DefinitionCurrentSnapshot {
				candidate.CurrentReferenceOnly = true
			} else {
				candidate.HistoricalExactDeclared = true
			}
		case "mutable-action-ref", "mutable-workflow-ref":
			if dep.DeclaredRef != indicator.Value.Ref {
				continue
			}
			if dep.Basis == archive.DefinitionCurrentSnapshot {
				candidate.CurrentReferenceOnly = true
			} else if dep.TransitiveDepth > 0 {
				candidate.PotentialTransitive = true
			} else {
				// A mutable declaration is only the fallback when exact runtime
				// resolution is unavailable for this execution. Exact affected or
				// known-good identities receive their own exact conclusion.
				if hasExactRuntime(idx, fact.Subject, component) {
					continue
				}
				candidate.HistoricalMutableRef = true
				candidate.RunEventInWindow = inAnyWindow(pack.Pack.Spec.Windows, indicator.WindowRefs, dep.EventTime)
				candidate.MaterialEvidenceGap = true
			}
		default:
			continue
		}
		candidate.RequiredCoverageClosed = !candidate.MaterialEvidenceGap && len(candidate.CoverageIDs) > 0
		decision, err := match.Derive(candidate)
		if err != nil {
			continue
		}
		finding, err := makeFinding(idx, pack, indicator, fact.Subject, nil, dep.EventTime, candidate, decision, analysisTime)
		if err != nil {
			return nil, err
		}
		if candidate.MaterialContradiction {
			finding.ContradictoryEvidence = append([]string(nil), dep.ContradictsFactIDs...)
		}
		appendUnique(&findings, seen, finding)
	}

	// Literal and external IOC packs cannot be replayed from a discarded raw
	// log unless a future typed retained capability says otherwise.
	if len(findings) == 0 && indicatorNeedsUnarchivedSource(indicator.Kind) {
		for _, repository := range relevantRepositories(idx, component) {
			subject := archive.FactSubject{RepositoryID: repository.ID}
			candidate := match.Candidate{MaterialEvidenceGap: true}
			decision, _ := match.Derive(candidate)
			finding, err := makeFinding(idx, pack, indicator, subject, nil, unknownTime(), candidate, decision, analysisTime)
			if err != nil {
				return nil, err
			}
			finding.EvidenceGaps = []string{"the compact archive did not retain data required to evaluate this indicator; a discarded-log hash cannot prove a later literal match"}
			appendUnique(&findings, seen, finding)
		}
	}
	// A quarantined identity join is a separate execution-scope unknown even
	// when another attempt or job produced an exact finding. Preserve that
	// partial coverage instead of allowing a valid sibling to hide it. Other
	// generic gaps retain the existing fallback behavior to avoid multiplying
	// unrelated capability gaps across every matched indicator.
	includeAllMaterialGaps := len(findings) == 0
	{
		type materialGapAggregate struct {
			subject     archive.FactSubject
			event       model.EventInterval
			evidenceIDs []model.EvidenceID
			coverageIDs []model.CoverageAssessmentID
			reasons     []string
		}
		aggregates := make(map[string]*materialGapAggregate)
		for _, gapFact := range idx.gaps {
			if gapFact.CoverageGap == nil || gapFact.CoverageGap.Assessment.Gap == nil || !gapFact.CoverageGap.Assessment.Gap.Material {
				continue
			}
			if !includeAllMaterialGaps && gapFact.CoverageGap.Assessment.Gap.Reason != model.GapAmbiguousCorrelation &&
				!gapRelatedToFindings(findings, gapFact.Subject, idx) {
				continue
			}
			// Organization enumeration can fail before GitHub discloses any
			// repository identity. Preserve that global visibility gap in case
			// coverage, but do not invent a repository-scoped finding.
			if gapFact.Subject.RepositoryID == 0 {
				continue
			}
			key := subjectKeyForLiteral(gapFact.Subject)
			aggregate := aggregates[key]
			if aggregate == nil {
				aggregate = &materialGapAggregate{subject: gapFact.Subject, event: gapFact.EventTime}
				aggregates[key] = aggregate
			}
			aggregate.evidenceIDs = append(aggregate.evidenceIDs, gapFact.EvidenceIDs...)
			aggregate.coverageIDs = append(aggregate.coverageIDs, gapFact.CoverageGap.Assessment.ID)
			aggregate.reasons = append(aggregate.reasons, string(gapFact.CoverageGap.Assessment.Gap.Reason))
		}
		keys := make([]string, 0, len(aggregates))
		for key := range aggregates {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			aggregate := aggregates[key]
			candidate := match.Candidate{
				MaterialEvidenceGap: true,
				EvidenceIDs:         model.SortEvidenceIDs(aggregate.evidenceIDs),
				CoverageIDs:         model.SortCoverageAssessmentIDs(aggregate.coverageIDs),
			}
			decision, _ := match.Derive(candidate)
			finding, err := makeFinding(idx, pack, indicator, aggregate.subject, nil, aggregate.event, candidate, decision, analysisTime)
			if err != nil {
				return nil, err
			}
			for _, reason := range sortedUniqueStrings(aggregate.reasons) {
				finding.EvidenceGaps = append(finding.EvidenceGaps, "material coverage gap: "+reason)
			}
			appendUnique(&findings, seen, finding)
		}
	}
	return coalesceIndicatorFindings(findings, pack, indicator)
}

func gapRelatedToFindings(findings []report.Finding, subject archive.FactSubject, idx index) bool {
	repository, ok := idx.repositories[subject.RepositoryID]
	if !ok || subject.RunID == nil {
		return false
	}
	for _, finding := range findings {
		if finding.Repository != string(repository.Name) || finding.RunID != int64(*subject.RunID) {
			continue
		}
		if subject.RunAttempt != nil && finding.RunAttempt != int(*subject.RunAttempt) {
			continue
		}
		if subject.JobID != nil && finding.JobID != 0 && finding.JobID != int64(*subject.JobID) {
			continue
		}
		return true
	}
	return false
}

// coalesceIndicatorFindings selects one immutable revision for each logical
// finding in an analysis session. Multiple evidence paths can support the same
// incident/indicator/subject proposition (for example, an exact runner
// download and a reconstructed transitive edge). They are evidence for one
// logical conclusion, not parallel current revisions of the same finding.
func coalesceIndicatorFindings(findings []report.Finding, pack *incident.ValidatedPack, indicator incident.Indicator) ([]report.Finding, error) {
	result := make([]report.Finding, 0, len(findings))
	positions := make(map[string]int, len(findings))
	for _, finding := range findings {
		position, exists := positions[finding.FindingID]
		if !exists {
			positions[finding.FindingID] = len(result)
			result = append(result, finding)
			continue
		}
		merged, err := mergeFindingRevisions(result[position], finding, pack, indicator)
		if err != nil {
			return nil, err
		}
		result[position] = merged
	}
	return result, nil
}

func mergeFindingRevisions(left, right report.Finding, pack *incident.ValidatedPack, indicator incident.Indicator) (report.Finding, error) {
	if left.FindingID != right.FindingID || left.IndicatorID != right.IndicatorID ||
		left.Repository != right.Repository || left.Workflow != right.Workflow || left.RunID != right.RunID ||
		left.RunAttempt != right.RunAttempt || left.JobID != right.JobID || left.StepIdentity != right.StepIdentity {
		return report.Finding{}, errors.New("logical finding identity collision disagrees with its display subject")
	}

	leftState, rightState := model.FindingState(left.State), model.FindingState(right.State)
	selected := left
	contradiction := leftState == model.ContradictoryEvidence || rightState == model.ContradictoryEvidence
	if (leftState == model.NoMatchConfirmed && isPositiveFindingState(rightState)) ||
		(rightState == model.NoMatchConfirmed && isPositiveFindingState(leftState)) {
		contradiction = true
	}
	if contradiction {
		decision, err := match.Derive(match.Candidate{MaterialContradiction: true})
		if err != nil {
			return report.Finding{}, err
		}
		selected.State = string(decision.State)
		selected.Provenance = string(capProvenance(decision.Provenance, indicator.Confidence))
		selected.Conclusion = decision.Conclusion
		selected.ContradictoryEvidence = unionStrings(selected.ContradictoryEvidence, right.ContradictoryEvidence)
		selected.ContradictoryEvidence = unionStrings(selected.ContradictoryEvidence, append(append([]string(nil), left.EvidenceIDs...), right.EvidenceIDs...))
		selected.RemediationGuidance = unionStrings(selected.RemediationGuidance, remediationFor(pack.Pack.Spec.Remediation, decision.State))
	} else if preferFinding(rightState, model.ProvenanceLevel(right.Provenance), leftState, model.ProvenanceLevel(left.Provenance)) {
		selected = right
	}

	selected.EvidenceIDs = unionStrings(left.EvidenceIDs, right.EvidenceIDs)
	selected.CollectionCoverage = unionStrings(left.CollectionCoverage, right.CollectionCoverage)
	selected.Assumptions = unionStrings(left.Assumptions, right.Assumptions)
	selected.EvidenceGaps = unionStrings(left.EvidenceGaps, right.EvidenceGaps)
	selected.ContradictoryEvidence = unionStrings(selected.ContradictoryEvidence, unionStrings(left.ContradictoryEvidence, right.ContradictoryEvidence))
	selected.CredentialExposure = append(append([]report.Exposure(nil), left.CredentialExposure...), right.CredentialExposure...)
	selected.ResourceExposure = append(append([]report.Exposure(nil), left.ResourceExposure...), right.ResourceExposure...)
	selected.RemediationGuidance = unionStrings(selected.RemediationGuidance, unionStrings(left.RemediationGuidance, right.RemediationGuidance))

	proposition, err := PropositionForIndicatorKind(indicator.Kind)
	if err != nil {
		return report.Finding{}, err
	}
	evidenceIDs := make([]model.EvidenceID, len(selected.EvidenceIDs))
	for index, id := range selected.EvidenceIDs {
		evidenceIDs[index] = model.EvidenceID(id)
	}
	coverageIDs := make([]model.CoverageAssessmentID, len(selected.CollectionCoverage))
	for index, id := range selected.CollectionCoverage {
		coverageIDs[index] = model.CoverageAssessmentID(id)
	}
	revision, err := evidence.NewFindingRevisionID(evidence.FindingRevisionInput{
		FindingID: model.FindingID(selected.FindingID), CanonicalPackSHA256: pack.CanonicalSHA256,
		State: model.FindingState(selected.State), Provenance: model.ProvenanceLevel(selected.Provenance),
		EvidenceIDs: evidenceIDs, CoverageIDs: coverageIDs, RuleVersion: FindingRuleVersion(indicator.Kind), Proposition: proposition,
	})
	if err != nil {
		return report.Finding{}, err
	}
	selected.FindingRevisionID = string(revision)
	selected.DerivationRuleVersion = FindingRuleVersion(indicator.Kind)
	return selected, nil
}

func isPositiveFindingState(state model.FindingState) bool {
	switch state {
	case model.ConfirmedExecuted, model.ConfirmedDownloaded, model.ConfirmedCalledWorkflow,
		model.DeclaredAtRunSHA, model.RunInWindowMutableRef, model.PotentialTransitive,
		model.CurrentReferenceOnly:
		return true
	default:
		return false
	}
}

func preferFinding(candidateState model.FindingState, candidateProvenance model.ProvenanceLevel, currentState model.FindingState, currentProvenance model.ProvenanceLevel) bool {
	candidateRank, currentRank := findingStateRank(candidateState), findingStateRank(currentState)
	if candidateRank != currentRank {
		return candidateRank > currentRank
	}
	return provenanceRank(candidateProvenance) > provenanceRank(currentProvenance)
}

func findingStateRank(state model.FindingState) int {
	switch state {
	case model.ContradictoryEvidence:
		return 100
	case model.ConfirmedExecuted:
		return 90
	case model.ConfirmedDownloaded, model.ConfirmedCalledWorkflow:
		return 80
	case model.DeclaredAtRunSHA:
		return 70
	case model.RunInWindowMutableRef:
		return 60
	case model.PotentialTransitive:
		return 50
	case model.CurrentReferenceOnly:
		return 40
	case model.UnknownEvidenceGap:
		return 30
	case model.NoMatchConfirmed:
		return 20
	default:
		return 0
	}
}

func provenanceRank(level model.ProvenanceLevel) int {
	switch level {
	case model.L4Certain:
		return 4
	case model.L3Strong:
		return 3
	case model.L2Probable:
		return 2
	case model.L1Possible:
		return 1
	default:
		return 0
	}
}

func makeFinding(idx index, pack *incident.ValidatedPack, indicator incident.Indicator, subject archive.FactSubject, step *model.StepIdentity, event model.EventInterval, candidate match.Candidate, decision match.Decision, analysisTime time.Time) (report.Finding, error) {
	repository, ok := idx.repositories[subject.RepositoryID]
	if !ok {
		return report.Finding{}, fmt.Errorf("subject repository %d is absent", subject.RepositoryID)
	}
	workflow := model.WorkflowSubject{UnknownReason: "workflow path unavailable in retained facts"}
	workflowText := ""
	if subject.RunID != nil {
		if run, exists := idx.runs[runKey(subject.RepositoryID, *subject.RunID)]; exists && run.WorkflowPath != nil {
			pathCopy := *run.WorkflowPath
			workflow = model.WorkflowSubject{Path: &pathCopy}
			workflowText = string(pathCopy)
		}
	}
	modelSubject := model.FindingSubject{Repository: repository, Workflow: workflow, RunID: subject.RunID, RunAttempt: subject.RunAttempt, JobID: subject.JobID, Step: step}
	proposition, err := PropositionForIndicatorKind(indicator.Kind)
	if err != nil {
		return report.Finding{}, err
	}
	findingID, err := evidence.NewFindingID(evidence.FindingLogicalInput{
		IncidentID: pack.Pack.Metadata.ID, IncidentAPI: pack.Pack.APIVersion, IndicatorID: indicator.ID,
		Subject: modelSubject, PropositionKind: proposition.Kind,
	})
	if err != nil {
		return report.Finding{}, err
	}
	provenance := capProvenance(decision.Provenance, indicator.Confidence)
	evidenceIDs := model.SortEvidenceIDs(candidate.EvidenceIDs)
	coverageIDs := model.SortCoverageAssessmentIDs(candidate.CoverageIDs)
	revisionID, err := evidence.NewFindingRevisionID(evidence.FindingRevisionInput{
		FindingID: findingID, CanonicalPackSHA256: pack.CanonicalSHA256, State: decision.State,
		Provenance: provenance, EvidenceIDs: evidenceIDs, CoverageIDs: coverageIDs,
		RuleVersion: FindingRuleVersion(indicator.Kind), Proposition: proposition,
	})
	if err != nil {
		return report.Finding{}, err
	}
	result := report.Finding{
		FindingID: string(findingID), FindingRevisionID: string(revisionID), IncidentID: pack.Pack.Metadata.ID,
		IndicatorID: indicator.ID, Repository: string(repository.Name), Workflow: workflowText,
		State: string(decision.State), Provenance: string(provenance), Conclusion: decision.Conclusion,
		EventTime: eventText(event), EvidenceIDs: idsToStrings(evidenceIDs), CollectionCoverage: coverageToStrings(coverageIDs),
		RemediationGuidance:   append([]string(nil), remediationFor(pack.Pack.Spec.Remediation, decision.State)...),
		DerivationRuleVersion: FindingRuleVersion(indicator.Kind),
	}
	if subject.RunID != nil {
		result.RunID = int64(*subject.RunID)
	}
	if subject.RunAttempt != nil {
		result.RunAttempt = int(*subject.RunAttempt)
	}
	if subject.JobID != nil {
		result.JobID = int64(*subject.JobID)
	}
	if step != nil {
		result.StepIdentity = step.Key()
	} else {
		result.StepIdentity = subject.StepKey
	}
	if decision.State == model.UnknownEvidenceGap {
		result.EvidenceGaps = []string{"required retained evidence is missing, incomplete, inaccessible, or cannot be safely correlated"}
	}
	result.CredentialExposure, result.ResourceExposure = exposuresFor(idx, subject, decision.State)
	return result, nil
}

func componentMatches(component incident.Component, repository, subpath string) bool {
	want := strings.ToLower(component.Repository.Owner + "/" + component.Repository.Name)
	if strings.ToLower(repository) != want {
		return false
	}
	if len(component.Subpaths) == 0 && len(component.WorkflowPaths) == 0 {
		return true
	}
	for _, path := range append(append([]string(nil), component.Subpaths...), component.WorkflowPaths...) {
		if path == subpath || (path == "" && subpath == "") {
			return true
		}
	}
	return false
}

func runtimeIdentityMatches(indicator incident.Indicator, obs model.RuntimeActionObservation) bool {
	switch indicator.Kind {
	case "action-commit":
		return obs.SourceObjectID != nil && gitObjectEqual(indicator.Value.GitObject, model.GitObjectID(*obs.SourceObjectID))
	case "digest":
		return obs.PackageDigest != nil && digestEqual(indicator.Value, *obs.PackageDigest)
	default:
		return false
	}
}

func runtimeKnownGood(known []incident.KnownGood, componentID string, obs model.RuntimeActionObservation) bool {
	for _, good := range known {
		if good.ComponentID != componentID {
			continue
		}
		switch good.Kind {
		case "action-commit", "reusable-workflow-commit":
			if obs.SourceObjectID != nil && gitObjectEqual(good.Value.GitObject, model.GitObjectID(*obs.SourceObjectID)) {
				return true
			}
		case "digest":
			if obs.PackageDigest != nil && digestEqual(good.Value, *obs.PackageDigest) {
				return true
			}
		}
	}
	return false
}

func dependencyExactMatches(indicator incident.Indicator, dep archive.DependencyFact) bool {
	switch indicator.Kind {
	case "action-commit":
		return dep.TargetActionObjectID != nil && gitObjectEqual(indicator.Value.GitObject, model.GitObjectID(*dep.TargetActionObjectID))
	case "reusable-workflow-commit":
		return dep.TargetCalledWorkflowObjectID != nil && gitObjectEqual(indicator.Value.GitObject, model.GitObjectID(*dep.TargetCalledWorkflowObjectID)) && (indicator.Value.Path == "" || indicator.Value.Path == dep.TargetPath)
	case "digest":
		return dep.PackageDigest != nil && digestEqual(indicator.Value, *dep.PackageDigest)
	}
	return false
}

func gitObjectEqual(indicatorObject *incident.GitObject, object model.GitObjectID) bool {
	return indicatorObject != nil && indicatorObject.Algorithm == string(object.Algorithm) && indicatorObject.Value == object.Value
}

func digestEqual(value incident.IndicatorValue, digest model.PackageDigest) bool {
	return value.Subject == string(digest.Subject) && value.Algorithm == string(digest.Algorithm) && value.Digest == digest.Value
}

func hasExactRuntime(idx index, subject archive.FactSubject, component incident.Component) bool {
	for _, fact := range idx.actions {
		if !sameExecutionSubject(fact.Subject, subject) || fact.ActionOccurrence == nil {
			continue
		}
		obs := fact.ActionOccurrence.Observation
		if componentMatches(component, string(obs.ActionRepository), obs.ActionSubpath) && (obs.SourceObjectID != nil || obs.PackageDigest != nil) {
			return true
		}
	}
	return false
}

func strongerRuntimeObservationExists(idx index, current archive.Fact, component incident.Component, indicator incident.Indicator) bool {
	if current.ActionOccurrence == nil {
		return false
	}
	currentObservation := current.ActionOccurrence.Observation
	currentRank := runtimeRank(currentObservation.Kind)
	for _, candidateFact := range idx.actions {
		if candidateFact.ID == current.ID || candidateFact.ActionOccurrence == nil || !sameExecutionSubject(candidateFact.Subject, current.Subject) {
			continue
		}
		observation := candidateFact.ActionOccurrence.Observation
		if !componentMatches(component, string(observation.ActionRepository), observation.ActionSubpath) || runtimeRank(observation.Kind) <= currentRank {
			continue
		}
		if sameRuntimeIdentity(currentObservation, observation) || runtimeIdentityMatches(indicator, observation) {
			return true
		}
	}
	return false
}

func sameRuntimeIdentity(a, b model.RuntimeActionObservation) bool {
	if a.SourceObjectID != nil && b.SourceObjectID != nil {
		return model.GitObjectID(*a.SourceObjectID) == model.GitObjectID(*b.SourceObjectID)
	}
	if a.PackageDigest != nil && b.PackageDigest != nil {
		return *a.PackageDigest == *b.PackageDigest
	}
	return false
}

func runtimeRank(kind model.RuntimeObservationKind) int {
	switch {
	case kind.SupportsExecuted():
		return 3
	case kind.SupportsDownloaded():
		return 2
	case kind == model.ObservationResolutionObserved || kind == model.ObservationDownloadAnnounced:
		return 1
	default:
		return 0
	}
}

func hasMaterialGap(idx index, subject archive.FactSubject) bool {
	for _, fact := range idx.gaps {
		if sameExecutionSubject(fact.Subject, subject) && fact.CoverageGap != nil && fact.CoverageGap.Assessment.Gap != nil && fact.CoverageGap.Assessment.Gap.Material {
			return true
		}
	}
	return false
}

func coverageFor(idx index, subject archive.FactSubject) []model.CoverageAssessmentID {
	var ids []model.CoverageAssessmentID
	for _, fact := range idx.coverage {
		if sameExecutionSubject(fact.Subject, subject) && fact.Coverage != nil {
			ids = append(ids, fact.Coverage.Assessment.ID)
		}
	}
	for _, fact := range idx.gaps {
		if sameExecutionSubject(fact.Subject, subject) && fact.CoverageGap != nil {
			ids = append(ids, fact.CoverageGap.Assessment.ID)
		}
	}
	return model.SortCoverageAssessmentIDs(ids)
}

func sameExecutionSubject(a, b archive.FactSubject) bool {
	if a.RepositoryID != b.RepositoryID {
		return false
	}
	if b.RunID != nil && (a.RunID == nil || *a.RunID != *b.RunID) {
		return false
	}
	if b.RunAttempt != nil && (a.RunAttempt == nil || *a.RunAttempt != *b.RunAttempt) {
		return false
	}
	if b.JobID != nil && (a.JobID == nil || *a.JobID != *b.JobID) {
		return false
	}
	return true
}

func inAnyWindow(windows []incident.Window, refs []string, event model.EventInterval) bool {
	if event.Start == nil {
		return false
	}
	wanted := make(map[string]bool, len(refs))
	for _, ref := range refs {
		wanted[ref] = true
	}
	for _, window := range windows {
		if !wanted[window.ID] {
			continue
		}
		start, startErr := time.Parse(time.RFC3339Nano, window.Start)
		end, endErr := time.Parse(time.RFC3339Nano, window.End)
		if startErr != nil || endErr != nil {
			continue
		}
		when := event.Start.Time
		left := when.After(start) || (when.Equal(start) && strings.HasPrefix(window.Bounds, "["))
		right := when.Before(end) || (when.Equal(end) && strings.HasSuffix(window.Bounds, "]"))
		if left && right {
			return true
		}
	}
	return false
}

func exposuresFor(idx index, subject archive.FactSubject, state model.FindingState) ([]report.Exposure, []report.Exposure) {
	if state != model.ConfirmedExecuted {
		return nil, nil
	}
	var credentials, resources []report.Exposure
	for _, fact := range idx.exposures {
		if !sameExecutionSubject(fact.Subject, subject) || fact.Exposure == nil {
			continue
		}
		exposure := fact.Exposure
		if exposure.StepKey != "" && subject.StepKey != "" && exposure.StepKey != subject.StepKey {
			continue
		}
		if exposure.Credential != nil {
			name := ""
			if exposure.Credential.SecretName != nil {
				name = string(*exposure.Credential.SecretName)
			}
			capability := exposure.Credential.Permission
			if exposure.Credential.Access != "" {
				capability += ":" + exposure.Credential.Access
			}
			basis := string(exposure.Credential.Basis)
			if basis == "" {
				basis = "evidence-backed"
			}
			credentials = append(credentials, report.Exposure{Kind: string(exposure.Credential.Kind), Name: name, Capability: capability, Basis: basis, Conclusion: exposure.Credential.Conclusion, EvidenceIDs: idsToStrings(exposure.Credential.EvidenceIDs)})
		}
		if exposure.Resource != nil {
			resources = append(resources, report.Exposure{Kind: string(exposure.Resource.Kind), Name: exposure.Resource.ResourceID, Basis: string(exposure.Resource.Correlation), Conclusion: exposure.Resource.Conclusion, EvidenceIDs: idsToStrings(exposure.Resource.EvidenceIDs)})
		}
		if exposure.Runner != nil {
			resources = append(resources, report.Exposure{Kind: strings.ToUpper(strings.ReplaceAll(exposure.Runner.Classification, "-", "_")) + "_RUNNER", Name: exposure.Runner.RunnerName, Basis: "observed", Conclusion: "Affected job runner classification was observed; persistence is not inferred.", EvidenceIDs: idsToStrings(fact.EvidenceIDs)})
		}
		if exposure.Environment != nil {
			environment := exposure.Environment
			conclusion := "The affected job's exact historical definition targeted this environment; retained job state did not establish that its protection gates were crossed. No environment secret names, values, reads, or use were inferred."
			if environment.JobStarted && environment.GateState == "crossed" {
				conclusion = "The affected job targeted this environment and demonstrably started, which establishes only that applicable environment gates were crossed. Human approval, bypass, environment secret names or values, reads, and use were not established."
			} else if environment.GateState == "pending" {
				conclusion = "The affected job targeted this environment but remained pending and did not demonstrably start. Environment-secret eligibility, values, reads, and use were not established."
			}
			resources = append(resources, report.Exposure{Kind: "ENVIRONMENT_GATE_CONTEXT", Name: environment.EnvironmentName, Capability: environment.GateState, Basis: "historical-definition-and-job-state", Conclusion: conclusion, EvidenceIDs: idsToStrings(fact.EvidenceIDs)})
		}
	}
	return credentials, resources
}

func buildMetadata(snapshot archive.Snapshot, pack *incident.ValidatedPack, analysisTime time.Time, mode string, idx index) report.Metadata {
	coverage := report.Coverage{
		RepositoriesRequested:  requestedRepositoryCount(snapshot, len(idx.repositories)),
		RepositoriesAccessible: len(idx.repositories),
		RunsEnumerated:         len(idx.runs),
		JobsEnumerated:         len(idx.jobs),
	}
	attempts := make(map[string]bool)
	for _, fact := range snapshot.Facts {
		if fact.Kind == archive.FactAttempt && fact.Attempt != nil {
			attempts[fmt.Sprintf("%d/%d/%d", fact.Attempt.RepositoryID, fact.Attempt.RunID, fact.Attempt.RunAttempt)] = true
		}
	}
	coverage.AttemptsEnumerated = len(attempts)

	incomplete := make(map[string]struct{})
	optionalDenied := make(map[string]struct{})
	seenCapabilities := make(map[string]struct{}, len(snapshot.Capabilities))
	capabilities := append([]archive.Capability(nil), snapshot.Capabilities...)
	sort.Slice(capabilities, func(i, j int) bool { return capabilities[i].Name < capabilities[j].Name })
	rawLogsRetained := false
	for _, capability := range capabilities {
		seenCapabilities[capability.Name] = struct{}{}
		switch capability.Name {
		case "attempt_logs", "job_logs":
			applyLogCapability(&coverage, incomplete, capability, idx)
		case "workflow_definitions":
			applyDefinitionCapability(&coverage.WorkflowDefinitionsRetrieved, incomplete, capability, definitionCoverageCount(idx, model.CoverageWorkflowDefinition))
		case "action_definitions":
			applyDefinitionCapability(&coverage.ActionDefinitionsRetrieved, incomplete, capability, definitionCoverageCount(idx, model.CoverageActionDefinition))
		case "repository_visibility":
			applyRepositoryVisibility(&coverage, incomplete, capability)
		case "raw_logs":
			rawLogsRetained = capability.Status == archive.CapabilityRetained
		}
		if coreCapabilityUnavailable(capability) {
			incomplete[fmt.Sprintf("Core capability %s is %s.", capability.Name, capability.Status)] = struct{}{}
		}
		if !coreCapability(capability.Name) && permissionDeniedCapability(capability) {
			optionalDenied[capability.Name] = struct{}{}
		}
	}
	for _, name := range coreCapabilities() {
		if _, ok := seenCapabilities[name]; !ok {
			incomplete[fmt.Sprintf("Core capability %s has no collection record.", name)] = struct{}{}
		}
	}
	if coverage.RepositoriesDenied > 0 {
		incomplete[fmt.Sprintf("%d requested repositories were denied.", coverage.RepositoriesDenied)] = struct{}{}
	}
	if coverage.RepositoriesRequested < coverage.RepositoriesAccessible+coverage.RepositoriesDenied {
		incomplete["Repository visibility counts are internally inconsistent."] = struct{}{}
	}
	if len(idx.gaps) != 0 {
		incomplete["Material or scoped evidence gaps are present; conclusions are limited to retained evidence."] = struct{}{}
	}
	coverage.OptionalCapabilitiesDenied = sortedSet(optionalDenied)
	coverage.IncompleteEvidence = sortedSet(incomplete)
	coverage.Partial = len(coverage.IncompleteEvidence) != 0 || len(coverage.OptionalCapabilitiesDenied) != 0 || coverage.LogsMissing != 0 || coverage.RepositoriesDenied != 0
	if coverage.Partial && len(coverage.IncompleteEvidence) == 0 {
		coverage.IncompleteEvidence = []string{"Coverage is partial; conclusions are limited to retained evidence."}
	}
	warnings := []string{"Analysis is complete only for structured facts retained by the archive; discarded raw-log literals remain evidence gaps."}
	return report.Metadata{
		SchemaVersion: report.MetadataSchema, Mode: mode, IncidentID: pack.Pack.Metadata.ID,
		IncidentPackVersion: pack.Pack.Metadata.PackVersion, CanonicalPackSHA256: pack.CanonicalSHA256,
		SourcePackSHA256: pack.OriginalSHA256, EngineVersion: EngineVersion, AnalysisTime: analysisTime.Format(time.RFC3339Nano),
		RawLogsRetained: rawLogsRetained, WatchHorizonDays: 65, Coverage: coverage,
		LimitPolicy: "hard-bounded parsers; compact structured archive; provisional 65-day parent lookback",
		Warnings:    warnings,
	}
}

func requestedRepositoryCount(snapshot archive.Snapshot, fallback int) int {
	requested := make(map[model.RepositoryID]struct{})
	for _, collection := range snapshot.Collections {
		for _, repositoryID := range collection.Scope.Repositories {
			requested[repositoryID] = struct{}{}
		}
	}
	if len(requested) > fallback {
		return len(requested)
	}
	return fallback
}

func applyLogCapability(coverage *report.Coverage, incomplete map[string]struct{}, capability archive.Capability, idx index) {
	collectedAggregate, missingAggregate := logCoverageCounts(idx, capability.Name)
	collected, present, valid := numericCapabilityDetail(capability, "collected_count")
	if present && !valid {
		incomplete[fmt.Sprintf("Capability %s has an invalid collected_count.", capability.Name)] = struct{}{}
	}
	// Capability rows are latest-status summaries. Typed coverage facts are
	// append-only across collection batches, so a nonzero aggregate is the
	// authoritative case total and the capability count is only a legacy
	// fallback.
	if collectedAggregate > 0 {
		collected = collectedAggregate
	} else if !present || !valid {
		collected = 0
	}
	available := capability.Status == archive.CapabilityRetained || capability.Status == archive.CapabilityStructuredOnly || capability.Status == archive.CapabilityHashOnly
	if !present && collectedAggregate == 0 && collected == 0 && available {
		// Legacy capability rows did not carry counts. Retain the pre-v0.1
		// lower-bound behavior: the successful capability proves at least one
		// log acquisition, including hash-only discard-sink acquisitions.
		collected = 1
	}
	if available || collected > 0 {
		addCoverageCount(&coverage.LogsRetrieved, collected, capability.Name+" collected_count", incomplete)
	}

	missing, missingPresent, missingValid := numericCapabilityDetail(capability, "gap_count")
	if missingPresent && !missingValid {
		incomplete[fmt.Sprintf("Capability %s has an invalid gap_count.", capability.Name)] = struct{}{}
	}
	if missingAggregate > 0 {
		missing = missingAggregate
	} else if !missingPresent || !missingValid {
		missing = 0
	}
	if (capability.Status == archive.CapabilityGap || capability.Status == archive.CapabilityNotCollected) && missing == 0 {
		missing = 1
	}
	addCoverageCount(&coverage.LogsMissing, missing, capability.Name+" gap_count", incomplete)
}

func applyDefinitionCapability(destination *int, incomplete map[string]struct{}, capability archive.Capability, aggregate int) {
	collected, present, valid := numericCapabilityDetail(capability, "collected_count")
	if !present {
		alias := "definition_count"
		if capability.Name == "action_definitions" {
			alias = "parsed_count"
		}
		collected, present, valid = numericCapabilityDetail(capability, alias)
	}
	if present && !valid {
		incomplete[fmt.Sprintf("Capability %s has an invalid definition count.", capability.Name)] = struct{}{}
		return
	}
	if aggregate > 0 {
		collected = aggregate
	} else if !present && (capability.Status == archive.CapabilityRetained || capability.Status == archive.CapabilityStructuredOnly) {
		// Legacy compact archives recorded successful capability presence but
		// not an object count. Preserve that lower bound without pretending it
		// is an exact inventory total.
		collected = 1
	}
	addCoverageCount(destination, collected, capability.Name+" collected_count", incomplete)
}

func definitionCoverageCount(idx index, kind model.CoverageKind) int {
	collected := make(map[model.CoverageUnitID]struct{})
	for _, fact := range idx.coverage {
		if fact.Coverage != nil && fact.Coverage.Unit.Kind == kind {
			collected[fact.Coverage.Unit.ID] = struct{}{}
		}
	}
	return len(collected)
}

func applyRepositoryVisibility(coverage *report.Coverage, incomplete map[string]struct{}, capability archive.Capability) {
	for _, field := range []struct {
		key         string
		destination *int
	}{
		{key: "requested_count", destination: &coverage.RepositoriesRequested},
		{key: "accessible_count", destination: &coverage.RepositoriesAccessible},
		{key: "denied_count", destination: &coverage.RepositoriesDenied},
	} {
		if capability.Details[field.key] == "unknown" && capability.Details["requested_total_known"] == "false" {
			// Organization enumeration cannot quantify repositories hidden from
			// the credential. The explicit unknown is a partial-visibility fact,
			// not a malformed numeric counter.
			continue
		}
		value, present, valid := numericCapabilityDetail(capability, field.key)
		if present && valid {
			if value > *field.destination {
				*field.destination = value
			}
		} else if present {
			incomplete[fmt.Sprintf("Capability %s has an invalid %s.", capability.Name, field.key)] = struct{}{}
		}
	}
	if _, present := capability.Details["accessible_count"]; !present {
		if value, enumerated, valid := numericCapabilityDetail(capability, "enumerated_count"); enumerated && valid {
			if value > coverage.RepositoriesAccessible {
				coverage.RepositoriesAccessible = value
			}
		} else if enumerated {
			incomplete["Capability repository_visibility has an invalid enumerated_count."] = struct{}{}
		}
	}
	if value, present := capability.Details["requested_total_known"]; present {
		switch value {
		case "true":
		case "false":
			incomplete["The total requested repository population is unknown because organization visibility may be partial."] = struct{}{}
		default:
			incomplete["Capability repository_visibility has an invalid requested_total_known value."] = struct{}{}
		}
	}
	if capability.Details["unresolved_count"] == "unknown" && capability.Details["requested_total_known"] == "false" {
		return
	}
	if unresolved, present, valid := numericCapabilityDetail(capability, "unresolved_count"); present {
		if !valid {
			incomplete["Capability repository_visibility has an invalid unresolved_count."] = struct{}{}
		} else if unresolved > 0 {
			incomplete[fmt.Sprintf("%d requested repositories could not be resolved.", unresolved)] = struct{}{}
		}
	}
}

func numericCapabilityDetail(capability archive.Capability, key string) (int, bool, bool) {
	raw, present := capability.Details[key]
	if !present {
		return 0, false, false
	}
	value, err := strconv.ParseUint(raw, 10, strconv.IntSize)
	if err != nil || uint64(int(value)) != value {
		return 0, true, false
	}
	return int(value), true, true
}

func addCoverageCount(destination *int, value int, label string, incomplete map[string]struct{}) {
	if value <= 0 {
		return
	}
	maximum := int(^uint(0) >> 1)
	if *destination > maximum-value {
		incomplete[fmt.Sprintf("Capability count %s overflowed the report counter.", label)] = struct{}{}
		return
	}
	*destination += value
}

func logCoverageCounts(idx index, capabilityName string) (int, int) {
	want := model.CoverageAttemptLog
	if capabilityName == "job_logs" {
		want = model.CoverageJobLog
	}
	collected := make(map[model.CoverageUnitID]struct{})
	missing := make(map[model.CoverageUnitID]struct{})
	for _, fact := range idx.coverage {
		if fact.Coverage != nil && fact.Coverage.Unit.Kind == want {
			collected[fact.Coverage.Unit.ID] = struct{}{}
		}
	}
	for _, fact := range idx.gaps {
		if fact.CoverageGap != nil && fact.CoverageGap.Unit.Kind == want {
			missing[fact.CoverageGap.Unit.ID] = struct{}{}
		}
	}
	return len(collected), len(missing)
}

func coreCapabilities() []string {
	return []string{
		"action_definitions", "action_execution", "action_resolution", "attempt_logs", "job_logs",
		"referenced_workflow_identity", "repository_visibility", "runner_context", "runtime_permissions", "workflow_definitions",
	}
}

func coreCapability(name string) bool {
	for _, candidate := range coreCapabilities() {
		if name == candidate {
			return true
		}
	}
	return false
}

func coreCapabilityUnavailable(capability archive.Capability) bool {
	if !coreCapability(capability.Name) {
		return false
	}
	switch capability.Status {
	case archive.CapabilityGap, archive.CapabilityNotCollected:
		return true
	case archive.CapabilityHashOnly:
		return capability.Name != "attempt_logs" && capability.Name != "job_logs"
	default:
		return false
	}
}

func permissionDeniedCapability(capability archive.Capability) bool {
	if capability.Status != archive.CapabilityGap && capability.Status != archive.CapabilityNotCollected {
		return false
	}
	reason := strings.ToLower(capability.Details["reason"])
	return strings.Contains(reason, "permission") || strings.Contains(reason, "forbidden") || strings.Contains(reason, "unauthorized") || strings.Contains(reason, "denied")
}

func sortedSet(values map[string]struct{}) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func capProvenance(derived, incidentLevel model.ProvenanceLevel) model.ProvenanceLevel {
	rank := map[model.ProvenanceLevel]int{model.L0Unknown: 0, model.L1Possible: 1, model.L2Probable: 2, model.L3Strong: 3, model.L4Certain: 4}
	if rank[incidentLevel] < rank[derived] {
		return incidentLevel
	}
	return derived
}

func remediationFor(remediation *incident.Remediation, state model.FindingState) []string {
	if remediation == nil {
		return nil
	}
	result := append([]string(nil), remediation.Guidance...)
	for _, trigger := range remediation.CredentialRotationTriggers {
		for _, candidate := range trigger.WhenStates {
			if candidate == state {
				result = append(result, trigger.Guidance)
			}
		}
	}
	return result
}

func indicatorNeedsUnarchivedSource(kind string) bool {
	switch kind {
	case "log-literal", "domain", "ip-address", "repository-name", "release-version":
		return true
	default:
		return false
	}
}

func relevantRepositories(idx index, component incident.Component) []model.RepositorySubject {
	var result []model.RepositorySubject
	want := strings.ToLower(component.Repository.Owner + "/" + component.Repository.Name)
	for _, repository := range idx.repositories {
		if want == "/" || strings.EqualFold(string(repository.Name), want) {
			result = append(result, repository)
		}
	}
	if len(result) == 0 {
		for _, repository := range idx.repositories {
			result = append(result, repository)
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result
}

// PropositionForIndicatorKind is the stable finding-identity contract shared
// with case persistence. Presentation records may omit this internal value,
// but a persisted revision must use this exact proposition to remain
// verifiable against its content-addressed finding revision ID.
func PropositionForIndicatorKind(indicatorKind string) (model.Proposition, error) {
	proposition := model.Proposition{
		Kind:       "incident_" + strings.ReplaceAll(indicatorKind, "-", "_"),
		Attributes: []model.PropositionAttribute{{Name: "indicator_kind", Value: indicatorKind}},
	}
	if err := proposition.Validate(); err != nil {
		return model.Proposition{}, fmt.Errorf("finding proposition for indicator kind %q: %w", indicatorKind, err)
	}
	return proposition, nil
}

func deterministicID(prefix string, parts ...string) string {
	h := sha256.New()
	for _, part := range parts {
		h.Write([]byte(strconv.Itoa(len(part))))
		h.Write([]byte{':'})
		h.Write([]byte(part))
	}
	return prefix + ":" + hex.EncodeToString(h.Sum(nil))
}

func appendUnique(findings *[]report.Finding, seen map[string]bool, finding report.Finding) {
	if !seen[finding.FindingRevisionID] {
		seen[finding.FindingRevisionID] = true
		*findings = append(*findings, finding)
	}
}

func runKey(repositoryID model.RepositoryID, runID model.WorkflowRunID) string {
	return fmt.Sprintf("%d/%d", repositoryID, runID)
}

func attemptKey(repositoryID model.RepositoryID, runID model.WorkflowRunID, attempt model.RunAttempt) string {
	return fmt.Sprintf("%d/%d/%d", repositoryID, runID, attempt)
}

func unknownTime() model.EventInterval {
	return model.EventInterval{Precision: model.PrecisionUnknown, Approximation: model.ApproximationUnknown, Basis: model.TimeBasisUnknown}
}

func eventText(event model.EventInterval) string {
	if event.Start == nil {
		return "unknown"
	}
	if event.End == nil {
		return event.Start.Format(time.RFC3339Nano)
	}
	return fmt.Sprintf("%s%s,%s%s", string((*event.Bounds)[0]), event.Start.Format(time.RFC3339Nano), event.End.Format(time.RFC3339Nano), string((*event.Bounds)[1]))
}

func idsToStrings(ids []model.EvidenceID) []string {
	result := make([]string, len(ids))
	for i, id := range ids {
		result[i] = string(id)
	}
	return result
}

func coverageToStrings(ids []model.CoverageAssessmentID) []string {
	result := make([]string, len(ids))
	for i, id := range ids {
		result[i] = string(id)
	}
	return result
}
