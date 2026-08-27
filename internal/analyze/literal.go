package analyze

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/torjan0/cirewind/internal/archive"
	"github.com/torjan0/cirewind/internal/evidence"
	"github.com/torjan0/cirewind/internal/incident"
	"github.com/torjan0/cirewind/internal/literalmatch"
	"github.com/torjan0/cirewind/internal/match"
	"github.com/torjan0/cirewind/internal/model"
	"github.com/torjan0/cirewind/internal/report"
)

// RawResult returns the augmented case snapshot because searchable-literal
// coverage is material to a NO_MATCH_CONFIRMED conclusion and must accompany
// any persisted findings. Literal contains no raw bytes or literal values.
type RawResult struct {
	Analysis Result
	Snapshot archive.Snapshot
	Literal  literalmatch.Result
}

type literalPending struct {
	indicator incident.Indicator
	subject   archive.FactSubject
	event     model.EventInterval
	evidence  []model.EvidenceID
	coverage  []model.CoverageAssessmentID
	observed  bool
	gapCodes  []string
}

// FindingRuleVersion returns the complete deterministic ruleset identity used
// to derive a finding for an indicator kind. Literal findings depend on both
// the canonical finding-state rules and the retained-log scanner rules; the
// latter must therefore participate in the immutable finding revision ID and
// the persisted case record.
func FindingRuleVersion(indicatorKind string) string {
	if indicatorKind == "log-literal" {
		return match.RuleVersion + "+" + literalmatch.RuleVersion
	}
	return match.RuleVersion
}

// DeriveWithRaw applies exact literal indicators to explicitly retained raw
// bytes, then runs the ordinary structured analyzer. It performs no network or
// process execution. Existing Derive remains the compact/hash-only path.
func DeriveWithRaw(ctx context.Context, snapshot archive.Snapshot, pack *incident.ValidatedPack, analysisTime time.Time, mode string, source literalmatch.RawSource, options literalmatch.Options) (RawResult, error) {
	if pack == nil {
		return RawResult{}, errors.New("validated incident pack is nil")
	}
	queries := make([]literalmatch.Query, 0)
	literalIndicators := make(map[string]incident.Indicator)
	for _, indicator := range pack.Pack.Spec.Indicators {
		if indicator.Kind != "log-literal" {
			continue
		}
		queries = append(queries, literalmatch.Query{IndicatorID: indicator.ID, Literal: []byte(indicator.Value.Literal), Scope: literalmatch.Scope(indicator.Value.Scope)})
		literalIndicators[indicator.ID] = indicator
	}
	if len(queries) == 0 {
		analysis, err := Derive(snapshot, pack, analysisTime, mode)
		return RawResult{Analysis: analysis, Snapshot: snapshot, Literal: literalmatch.Result{Observations: []literalmatch.Observation{}, Assessments: []literalmatch.Assessment{}, CoverageFacts: []archive.Fact{}}}, err
	}
	literalResult, err := literalmatch.Scan(ctx, snapshot, queries, source, options)
	if err != nil {
		return RawResult{}, err
	}
	enriched, err := appendLiteralCoverage(snapshot, literalResult.CoverageFacts)
	if err != nil {
		return RawResult{}, fmt.Errorf("normalize literal-search coverage: %w", err)
	}
	analysis, err := Derive(enriched, pack, analysisTime, mode)
	if err != nil {
		return RawResult{}, err
	}
	idx, err := buildIndex(enriched)
	if err != nil {
		return RawResult{}, err
	}
	var investigate []model.EventInterval
	if mode == ModeInvestigate {
		investigate, err = investigateWindows(enriched)
		if err != nil {
			return RawResult{}, err
		}
		idx = restrictIndexToWindows(idx, investigate)
	}

	// The compact analyzer intentionally emits a hash-only gap for every
	// literal. Replace only those findings; all structured indicator findings
	// remain authoritative and may receive scoped literal corroboration.
	findings := make([]report.Finding, 0, len(analysis.Case.Findings))
	for _, finding := range analysis.Case.Findings {
		if _, literal := literalIndicators[finding.IndicatorID]; !literal {
			findings = append(findings, finding)
		}
	}

	indicators := make(map[string]incident.Indicator, len(pack.Pack.Spec.Indicators))
	components := make(map[string]string, len(pack.Pack.Spec.Indicators))
	componentValues := make(map[string]incident.Component, len(pack.Pack.Spec.Components))
	for _, component := range pack.Pack.Spec.Components {
		componentValues[component.ID] = component
	}
	for _, indicator := range pack.Pack.Spec.Indicators {
		indicators[indicator.ID] = indicator
		components[indicator.ID] = indicator.ComponentID
	}

	pending := make(map[string]*literalPending)
	repositoryAssessment := make(map[string][]literalmatch.Assessment)
	repositoryObserved := make(map[string]bool)

	for _, observation := range literalResult.Observations {
		indicator, ok := literalIndicators[observation.IndicatorID]
		if !ok || !literalSubjectRelevant(idx, componentValues[indicator.ComponentID], observation.Subject) ||
			!literalEventRelevant(observation.EventTime, investigate, mode, false) {
			continue
		}
		corroborated := false
		for findingIndex := range findings {
			finding := &findings[findingIndex]
			if components[finding.IndicatorID] != indicator.ComponentID || !corroboratableState(model.FindingState(finding.State)) ||
				!findingExactSubject(*finding, observation.Subject, idx) {
				continue
			}
			finding.EvidenceIDs = unionStrings(finding.EvidenceIDs, idsToStrings(observation.EvidenceIDs))
			finding.CollectionCoverage = unionStrings(finding.CollectionCoverage, coverageToStrings(observation.CoverageIDs))
			finding.Assumptions = unionStrings(finding.Assumptions, []string{"Scoped retained log evidence also matched literal indicator " + indicator.ID + "; no literal bytes or surrounding output are included in this report."})
			if err := refreshFindingRevision(finding, pack, indicators[finding.IndicatorID]); err != nil {
				return RawResult{}, err
			}
			corroborated = true
		}
		repositoryObserved[literalRepositoryKey(observation.IndicatorID, observation.Subject.RepositoryID)] = true
		if !corroborated {
			value := unresolvedFor(pending, indicator, observation.Subject, observation.EventTime)
			value.observed = true
			value.evidence = append(value.evidence, observation.EvidenceIDs...)
			value.coverage = append(value.coverage, observation.CoverageIDs...)
		}
	}

	for _, assessment := range literalResult.Assessments {
		indicator, ok := literalIndicators[assessment.IndicatorID]
		if !ok || !literalSubjectRelevant(idx, componentValues[indicator.ComponentID], assessment.Subject) ||
			!literalEventRelevant(assessment.EventTime, investigate, mode, assessment.Status == literalmatch.StatusGap) {
			continue
		}
		repositoryKey := literalRepositoryKey(assessment.IndicatorID, assessment.Subject.RepositoryID)
		repositoryAssessment[repositoryKey] = append(repositoryAssessment[repositoryKey], assessment)
		if assessment.Status != literalmatch.StatusGap {
			continue
		}
		value := unresolvedFor(pending, indicator, assessment.Subject, assessment.EventTime)
		value.evidence = append(value.evidence, assessment.EvidenceIDs...)
		value.coverage = append(value.coverage, assessment.CoverageIDs...)
		value.gapCodes = append(value.gapCodes, string(assessment.GapCode))
	}

	// Materialize unresolved positive attribution and raw/coverage gaps first.
	pendingKeys := make([]string, 0, len(pending))
	for key := range pending {
		pendingKeys = append(pendingKeys, key)
	}
	sort.Strings(pendingKeys)
	seen := make(map[string]bool)
	for _, finding := range findings {
		seen[finding.FindingRevisionID] = true
	}
	for _, key := range pendingKeys {
		value := pending[key]
		candidate := match.Candidate{MaterialEvidenceGap: true, EvidenceIDs: model.SortEvidenceIDs(value.evidence), CoverageIDs: model.SortCoverageAssessmentIDs(value.coverage)}
		decision, _ := match.Derive(candidate)
		finding, err := makeFinding(idx, pack, value.indicator, value.subject, "", nil, value.event, candidate, decision, analysisTime)
		if err != nil {
			return RawResult{}, err
		}
		if value.observed {
			finding.Conclusion = "The retained log source contained the incident literal in this exact retained evidence scope, but attribution to execution of the affected component is unresolved; the literal alone does not prove that component executed."
			finding.EvidenceGaps = []string{"literal observed, but no same-scoped exact affected identity or historical reachability finding supports execution attribution"}
		}
		if len(value.gapCodes) > 0 {
			codes := sortedUniqueStrings(value.gapCodes)
			finding.EvidenceGaps = unionStrings(finding.EvidenceGaps, []string{"literal search coverage is incomplete (" + strings.Join(codes, ", ") + ")"})
		}
		appendUnique(&findings, seen, finding)
	}

	// An absent literal receives one repository-scoped negative only when all
	// relevant raw sources produced complete ABSENT assessments. Any positive or
	// gap suppresses the negative; no assessments at all is itself a gap.
	for _, indicator := range pack.Pack.Spec.Indicators {
		if indicator.Kind != "log-literal" {
			continue
		}
		for _, repository := range relevantRepositories(idx, componentValues[indicator.ComponentID]) {
			key := literalRepositoryKey(indicator.ID, repository.ID)
			assessments := repositoryAssessment[key]
			if repositoryObserved[key] || hasAssessmentStatus(assessments, literalmatch.StatusMatched) || hasAssessmentStatus(assessments, literalmatch.StatusGap) {
				continue
			}
			subject := archive.FactSubject{RepositoryID: repository.ID}
			if len(assessments) == 0 {
				candidate := match.Candidate{MaterialEvidenceGap: true}
				decision, _ := match.Derive(candidate)
				finding, err := makeFinding(idx, pack, indicator, subject, "", nil, unknownTime(), candidate, decision, analysisTime)
				if err != nil {
					return RawResult{}, err
				}
				finding.EvidenceGaps = []string{"no eligible retained and coverage-closed log source was available; a raw hash alone is not searchable"}
				appendUnique(&findings, seen, finding)
				continue
			}
			var evidenceIDs []model.EvidenceID
			var coverageIDs []model.CoverageAssessmentID
			for _, assessment := range assessments {
				evidenceIDs = append(evidenceIDs, assessment.EvidenceIDs...)
				coverageIDs = append(coverageIDs, assessment.CoverageIDs...)
			}
			candidate := match.Candidate{RequiredCoverageClosed: true, EvidenceIDs: model.SortEvidenceIDs(evidenceIDs), CoverageIDs: model.SortCoverageAssessmentIDs(coverageIDs)}
			decision, err := match.Derive(candidate)
			if err != nil {
				return RawResult{}, err
			}
			finding, err := makeFinding(idx, pack, indicator, subject, "", nil, unknownTime(), candidate, decision, analysisTime)
			if err != nil {
				return RawResult{}, err
			}
			finding.Conclusion = "Every relevant retained, verified, and coverage-closed log source for this repository was examined with an exact case-sensitive byte search, and the incident literal was absent."
			appendUnique(&findings, seen, finding)
		}
	}

	analysis.Case.Findings = findings
	analysis.Case.Graph = buildGraph(idx, analysis.Case.Findings)
	analysis.Case.GraphV2, err = buildGraphV2(idx, analysis.Case.Graph, analysis.Case.Findings, pack, analysis.Case.Metadata.CaseKind)
	if err != nil {
		return RawResult{}, fmt.Errorf("project retained-literal v0.2 evidence graph: %w", err)
	}
	if err := analysis.Case.NormalizeAndValidate(); err != nil {
		return RawResult{}, err
	}
	return RawResult{Analysis: analysis, Snapshot: enriched, Literal: literalResult}, nil
}

func appendLiteralCoverage(snapshot archive.Snapshot, facts []archive.Fact) (archive.Snapshot, error) {
	result := snapshot
	result.Facts = append([]archive.Fact(nil), snapshot.Facts...)
	seen := make(map[string]bool, len(result.Facts)+len(facts))
	for _, fact := range result.Facts {
		seen[fact.ID] = true
	}
	for _, fact := range facts {
		if !seen[fact.ID] {
			result.Facts = append(result.Facts, fact)
			seen[fact.ID] = true
		}
	}
	return archive.NormalizeSnapshot(result)
}

func unresolvedFor(values map[string]*literalPending, indicator incident.Indicator, subject archive.FactSubject, event model.EventInterval) *literalPending {
	key := indicator.ID + "\x00" + subjectKeyForLiteral(subject)
	if values[key] == nil {
		values[key] = &literalPending{indicator: indicator, subject: subject, event: event}
	}
	return values[key]
}

func literalSubjectRelevant(idx index, component incident.Component, subject archive.FactSubject) bool {
	for _, repository := range relevantRepositories(idx, component) {
		if repository.ID == subject.RepositoryID {
			return true
		}
	}
	return false
}

func literalEventRelevant(event model.EventInterval, windows []model.EventInterval, mode string, preserveUnknown bool) bool {
	if mode != ModeInvestigate {
		return true
	}
	if event.Start == nil {
		return preserveUnknown
	}
	return overlapsAnyWindow(event, windows)
}

func findingExactSubject(finding report.Finding, subject archive.FactSubject, idx index) bool {
	repository, ok := idx.repositories[subject.RepositoryID]
	if !ok || finding.Repository != string(repository.Name) {
		return false
	}
	if subject.RunID == nil || finding.RunID != int64(*subject.RunID) {
		return subject.RunID == nil && finding.RunID == 0 && subject.RunAttempt == nil && finding.RunAttempt == 0 && subject.JobID == nil && finding.JobID == 0 && subject.StepKey == finding.StepIdentity
	}
	if subject.RunAttempt == nil || finding.RunAttempt != int(*subject.RunAttempt) {
		return subject.RunAttempt == nil && finding.RunAttempt == 0 && subject.JobID == nil && finding.JobID == 0 && subject.StepKey == finding.StepIdentity
	}
	if subject.JobID == nil || finding.JobID != int64(*subject.JobID) {
		return subject.JobID == nil && finding.JobID == 0 && subject.StepKey == finding.StepIdentity
	}
	return subject.StepKey == finding.StepIdentity
}

func corroboratableState(state model.FindingState) bool {
	switch state {
	case model.ConfirmedExecuted, model.ConfirmedDownloaded, model.ConfirmedCalledWorkflow,
		model.DeclaredAtRunSHA, model.RunInWindowMutableRef, model.PotentialTransitive,
		model.ContradictoryEvidence:
		return true
	default:
		return false
	}
}

func refreshFindingRevision(finding *report.Finding, pack *incident.ValidatedPack, indicator incident.Indicator) error {
	proposition, err := PropositionForIndicatorKind(indicator.Kind)
	if err != nil {
		return err
	}
	evidenceIDs := make([]model.EvidenceID, len(finding.EvidenceIDs))
	for index, id := range finding.EvidenceIDs {
		evidenceIDs[index] = model.EvidenceID(id)
	}
	coverageIDs := make([]model.CoverageAssessmentID, len(finding.CollectionCoverage))
	for index, id := range finding.CollectionCoverage {
		coverageIDs[index] = model.CoverageAssessmentID(id)
	}
	revision, err := evidence.NewFindingRevisionID(evidence.FindingRevisionInput{
		FindingID: model.FindingID(finding.FindingID), CanonicalPackSHA256: pack.CanonicalSHA256,
		State: model.FindingState(finding.State), Provenance: model.ProvenanceLevel(finding.Provenance),
		EvidenceIDs: evidenceIDs, CoverageIDs: coverageIDs,
		RuleVersion: match.RuleVersion + "+" + literalmatch.RuleVersion, Proposition: proposition,
	})
	if err != nil {
		return err
	}
	finding.FindingRevisionID = string(revision)
	finding.DerivationRuleVersion = match.RuleVersion + "+" + literalmatch.RuleVersion
	return nil
}

func hasAssessmentStatus(values []literalmatch.Assessment, status literalmatch.Status) bool {
	for _, value := range values {
		if value.Status == status {
			return true
		}
	}
	return false
}

func literalRepositoryKey(indicatorID string, repositoryID model.RepositoryID) string {
	return fmt.Sprintf("%s/%d", indicatorID, repositoryID)
}

func subjectKeyForLiteral(subject archive.FactSubject) string {
	value := fmt.Sprintf("%d", subject.RepositoryID)
	if subject.RunID != nil {
		value += fmt.Sprintf("/%d", *subject.RunID)
	} else {
		value += "/-"
	}
	if subject.RunAttempt != nil {
		value += fmt.Sprintf("/%d", *subject.RunAttempt)
	} else {
		value += "/-"
	}
	if subject.JobID != nil {
		value += fmt.Sprintf("/%d", *subject.JobID)
	} else {
		value += "/-"
	}
	return value + "/" + subject.StepKey
}

func unionStrings(left, right []string) []string {
	return sortedUniqueStrings(append(append([]string(nil), left...), right...))
}

func sortedUniqueStrings(values []string) []string {
	sort.Strings(values)
	if len(values) == 0 {
		return values
	}
	write := 1
	for read := 1; read < len(values); read++ {
		if values[read] == values[write-1] {
			continue
		}
		values[write] = values[read]
		write++
	}
	return values[:write]
}
