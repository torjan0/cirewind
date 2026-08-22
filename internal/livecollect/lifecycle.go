package livecollect

import (
	"bytes"
	"context"
	"fmt"
	"math"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/torjan0/cirewind/internal/archive"
	"github.com/torjan0/cirewind/internal/collect"
	"github.com/torjan0/cirewind/internal/evidence"
	"github.com/torjan0/cirewind/internal/githubapi"
	"github.com/torjan0/cirewind/internal/logparse"
	"github.com/torjan0/cirewind/internal/model"
)

type parsedActionStep struct {
	entry                 logparse.Entry
	job                   githubapi.WorkflowJob
	step                  githubapi.JobStep
	identity              model.StepIdentity
	expectedAction        string
	result                logparse.ParseResult
	bytes                 []byte
	rejection             string
	rejectMaterial        bool
	consolidated          bool
	lineOffset            int
	historicalDeclaration string
	historicalEvidence    []model.EvidenceID
	adjacentRun           *logparse.ConsolidatedRunGroup
}

type stepEntryIssue struct {
	jobID      int64
	diagnostic string
}

type setupResolution struct {
	action      logparse.Action
	evidenceIDs []model.EvidenceID
}

// setupObservation binds one parsed runner-control observation to the exact
// evidence used to type its Action source. Action source algorithms remain
// empty until the target repository's object format has been observed.
type setupObservation struct {
	observation logparse.Observation
	evidenceIDs []model.EvidenceID
}

type acceptedStep struct {
	step githubapi.JobStep
}

var (
	actionStepEntryPattern      = regexp.MustCompile(`^([1-9][0-9]*)_(.+)\.txt$`)
	consolidatedJobEntryPattern = regexp.MustCompile(`^0_(.+)\.txt$`)
)

// correlateConsolidatedJobEntry recognizes only the observed root whole-job
// shape. The display label is a correlation attribute, never identity: it must
// match exactly one already validated API job, and the consolidated framer
// independently requires the runner's Complete-job-name record to agree.
func correlateConsolidatedJobEntry(name string, jobs []githubapi.WorkflowJob) (githubapi.WorkflowJob, bool, string) {
	if path.Dir(name) != "." {
		return githubapi.WorkflowJob{}, false, ""
	}
	match := consolidatedJobEntryPattern.FindStringSubmatch(name)
	if match == nil {
		return githubapi.WorkflowJob{}, false, ""
	}
	label := match[1]
	if !safeJobCorrelationLabel(label) {
		return githubapi.WorkflowJob{}, true, "consolidated job-log label contains unsafe structural data"
	}
	var selected githubapi.WorkflowJob
	count := 0
	for _, job := range jobs {
		if archiveJobLabelMatches(label, job.Name) {
			selected = job
			count++
		}
	}
	if count != 1 {
		return githubapi.WorkflowJob{}, true, "consolidated job-log label did not identify exactly one API job"
	}
	return selected, true, ""
}

// archiveJobLabelMatches accepts only the two GitHub attempt-log encodings
// observed for a complete API job display name. A slash cannot occur in a ZIP
// path component, so GitHub renders that rune as "_" (spaces surrounding a
// slash in the API name therefore remain spaces). The decoded label is never
// used as identity: correlation still requires one unique API job and the
// runner-owned Complete-job-name record must match the unencoded API name.
func archiveJobLabelMatches(entryLabel, apiName string) bool {
	return entryLabel == apiName || entryLabel == strings.ReplaceAll(apiName, "/", "_")
}

func safeJobCorrelationLabel(value string) bool {
	if value == "" || !utf8.ValidString(value) {
		return false
	}
	for _, char := range value {
		if char < 0x20 || char == 0x7f {
			return false
		}
	}
	return true
}

// correlateActionStepEntry binds an archive entry through both the unique API
// job display name and the unique API step number. The filename label is only
// a consistency check against two explicitly allowlisted encodings; it is
// never used as the step identity.
func correlateActionStepEntry(name string, jobs []githubapi.WorkflowJob) (githubapi.WorkflowJob, githubapi.JobStep, bool, string) {
	base := path.Base(name)
	match := actionStepEntryPattern.FindStringSubmatch(base)
	if match == nil || path.Dir(name) == "." || base == "1_Set up job.txt" {
		return githubapi.WorkflowJob{}, githubapi.JobStep{}, false, ""
	}
	stepNumber, err := strconv.ParseInt(match[1], 10, 32)
	if err != nil || stepNumber <= 0 || stepNumber > math.MaxInt32 {
		return githubapi.WorkflowJob{}, githubapi.JobStep{}, true, "step-log entry number is outside the supported API range"
	}
	parent := path.Dir(name)
	var job githubapi.WorkflowJob
	jobMatches := 0
	for _, candidate := range jobs {
		if archiveJobLabelMatches(parent, candidate.Name) {
			job = candidate
			jobMatches++
		}
	}
	if jobMatches != 1 {
		if looksLikeActionStepLabel(match[2]) {
			return githubapi.WorkflowJob{}, githubapi.JobStep{}, true, "step-log parent did not identify exactly one API job"
		}
		return githubapi.WorkflowJob{}, githubapi.JobStep{}, false, ""
	}
	var step githubapi.JobStep
	stepMatches := 0
	for _, candidate := range job.Steps {
		if candidate.Number == int(stepNumber) {
			step = candidate
			stepMatches++
		}
	}
	if stepMatches != 1 {
		return job, githubapi.JobStep{}, true, "step-log number did not identify exactly one API step"
	}
	if !archiveStepLabelMatches(match[2], step.Name) {
		return job, step, true, "step-log label did not match the bound API step under the supported archive encodings"
	}
	return job, step, true, ""
}

func archiveStepLabelMatches(entryLabel, apiName string) bool {
	if entryLabel == apiName {
		return true
	}
	withoutSeparators := strings.ReplaceAll(apiName, "/", "")
	withUnderscores := strings.ReplaceAll(apiName, "/", "_")
	return entryLabel == withoutSeparators || entryLabel == withUnderscores
}

func looksLikeActionStepLabel(label string) bool {
	return strings.HasPrefix(label, "Run ") || strings.HasPrefix(label, "Pre Run ") || strings.HasPrefix(label, "Post Run ")
}

func parseActionStepCandidate(ctx context.Context, target repositoryWork, runID int64, attempt int, job githubapi.WorkflowJob, step githubapi.JobStep, entry logparse.Entry, entryBytes []byte, consolidated bool, lineOffset int, binding *historicalStepBinding) (parsedActionStep, error) {
	execution := model.JobExecutionIdentity{
		RepositoryID: model.RepositoryID(target.repository.ID), RunID: model.WorkflowRunID(runID),
		RunAttempt: model.RunAttempt(attempt), JobID: model.JobID(job.ID),
	}
	apiNumber := model.APIStepNumber(step.Number)
	identity := model.StepIdentity{Job: execution, APIStepNumber: &apiNumber, LifecyclePhase: model.LifecycleMain, Occurrence: 1}
	if err := identity.Validate(); err != nil {
		return parsedActionStep{}, err
	}
	candidate := parsedActionStep{entry: entry, job: job, step: step, identity: identity, bytes: entryBytes, consolidated: consolidated, lineOffset: lineOffset}
	switch strings.ToLower(step.Conclusion) {
	case "skipped":
		candidate.rejection = "API step conclusion is skipped; no Action lifecycle start was emitted"
		candidate.rejectMaterial = false
		return candidate, nil
	case "cancelled", "canceled":
		candidate.rejection = "canceled API step is not promoted to Action lifecycle evidence"
		candidate.rejectMaterial = true
		return candidate, nil
	}
	if step.StartedAt == nil || step.StartedAt.IsZero() {
		candidate.rejection = "API step has no started_at and cannot support lifecycle correlation"
		candidate.rejectMaterial = true
		return candidate, nil
	}
	if strings.HasPrefix(step.Name, "Run ") {
		candidate.expectedAction = strings.TrimPrefix(step.Name, "Run ")
	}
	if binding != nil {
		candidate.historicalDeclaration = binding.declaration
		candidate.historicalEvidence = model.SortEvidenceIDs(binding.evidenceIDs)
		if candidate.expectedAction != "" && actionKeyFromDeclaration(candidate.expectedAction) != actionKeyFromDeclaration(binding.declaration) {
			candidate.rejection = "default API Action declaration disagreed with the exact historical workflow step"
			candidate.rejectMaterial = true
			return candidate, nil
		}
		candidate.expectedAction = binding.declaration
	}
	grammar := ""
	if consolidated {
		grammar = logparse.ConsolidatedGrammarVersion
	}
	parsed, err := logparse.Parse(ctx, bytes.NewReader(entryBytes), logparse.SourceContext{
		Scope: logparse.ExecutionScope{
			RepositoryID: target.repository.ID, RunID: runID, RunAttempt: attempt,
			JobID: job.ID, StepKey: identity.Key(),
		},
		Role: logparse.RoleActionStep, LifecyclePhase: logparse.PhaseMain,
		ExpectedAction: candidate.expectedAction, APIStatus: step.Status,
		APIConclusion: step.Conclusion, Grammar: grammar, LineOffset: lineOffset, GrammarValidated: true,
	})
	if err != nil {
		return parsedActionStep{}, err
	}
	candidate.result = parsed
	return candidate, nil
}

func addSetupResolutions(destination map[int64]map[string][]setupResolution, jobID int64, observations []setupObservation) {
	for _, item := range observations {
		observation := item.observation
		if observation.Kind != logparse.ObservationResolution || observation.Action == nil {
			continue
		}
		key := actionDeclarationKey(*observation.Action)
		if key == "" || (observation.Action.Source.Value == "" && observation.Action.Digest.Value == "") {
			continue
		}
		if destination[jobID] == nil {
			destination[jobID] = make(map[string][]setupResolution)
		}
		destination[jobID][key] = append(destination[jobID][key], setupResolution{action: *observation.Action, evidenceIDs: model.SortEvidenceIDs(item.evidenceIDs)})
	}
}

func actionDeclarationKey(action logparse.Action) string {
	if action.Owner == "" || action.Repository == "" || action.Ref == "" {
		return ""
	}
	name := strings.ToLower(action.Owner) + "/" + strings.ToLower(action.Repository)
	if action.Subpath != "" {
		name += "/" + action.Subpath
	}
	return name + "@" + action.Ref
}

func selectSetupResolution(values []setupResolution) (setupResolution, bool) {
	if len(values) == 0 {
		return setupResolution{}, false
	}
	byIdentity := make(map[string]setupResolution, len(values))
	for _, value := range values {
		identity := strings.Join([]string{
			value.action.Source.Algorithm, strings.ToLower(value.action.Source.Value), value.action.Version,
			value.action.Digest.Subject, value.action.Digest.Algorithm, strings.ToLower(value.action.Digest.Value),
		}, "\x00")
		if existing, ok := byIdentity[identity]; ok {
			existing.evidenceIDs = model.SortEvidenceIDs(append(existing.evidenceIDs, value.evidenceIDs...))
			byIdentity[identity] = existing
			continue
		}
		byIdentity[identity] = value
	}
	if len(byIdentity) != 1 {
		return setupResolution{}, false
	}
	for _, value := range byIdentity {
		return value, true
	}
	return setupResolution{}, false
}

// selectActionStepCandidate recognizes only the current GitHub archive's
// duplicate consolidated/split views. The consolidated frame must be the
// exact timestamped-runner-text prefix of the split entry and both parses must
// describe the same lifecycle semantics. Same-layout duplicates and every
// materially different candidate remain ambiguous.
func selectActionStepCandidate(ctx context.Context, candidates []parsedActionStep) (int, error) {
	if len(candidates) == 1 {
		return 0, nil
	}
	if len(candidates) != 2 || candidates[0].consolidated == candidates[1].consolidated {
		return -1, nil
	}
	consolidated, split := 0, 1
	if !candidates[consolidated].consolidated {
		consolidated, split = split, consolidated
	}
	if !sameActionCandidateSemantics(candidates[consolidated], candidates[split]) {
		return -1, nil
	}
	equal, err := logparse.RunnerControlTextIsPrefix(ctx, candidates[consolidated].bytes, candidates[split].bytes)
	if err != nil || !equal {
		return -1, err
	}
	return consolidated, nil
}

func sameActionCandidateSemantics(left, right parsedActionStep) bool {
	if left.identity.Key() != right.identity.Key() || left.expectedAction != right.expectedAction || left.historicalDeclaration != right.historicalDeclaration || left.rejection != right.rejection || left.rejectMaterial != right.rejectMaterial || left.result.Complete != right.result.Complete {
		return false
	}
	if len(left.historicalEvidence) != len(right.historicalEvidence) {
		return false
	}
	for index := range left.historicalEvidence {
		if left.historicalEvidence[index] != right.historicalEvidence[index] {
			return false
		}
	}
	if len(left.result.Diagnostics) != len(right.result.Diagnostics) || len(left.result.Observations) != len(right.result.Observations) {
		return false
	}
	for index := range left.result.Diagnostics {
		if left.result.Diagnostics[index].Code != right.result.Diagnostics[index].Code {
			return false
		}
	}
	for index := range left.result.Observations {
		leftObservation, rightObservation := left.result.Observations[index], right.result.Observations[index]
		if leftObservation.Kind != rightObservation.Kind || leftObservation.Phase != rightObservation.Phase || leftObservation.Derived != rightObservation.Derived {
			return false
		}
		if (leftObservation.Action == nil) != (rightObservation.Action == nil) {
			return false
		}
		if leftObservation.Action != nil && *leftObservation.Action != *rightObservation.Action {
			return false
		}
	}
	return true
}

func processActionStepCandidates(
	ctx context.Context,
	target repositoryWork,
	runID int64,
	bundle collect.AttemptBundle,
	sessionID model.CollectionSessionID,
	started, ended model.Instant,
	attemptEvidenceID model.EvidenceID,
	archiveTrusted bool,
	candidates map[int64]map[int][]parsedActionStep,
	resolutions map[int64]map[string][]setupResolution,
	jobEvidence map[int64]model.EvidenceID,
	historical *historicalAttempt,
	result *repositoryResult,
) error {
	repositoryID, typedRun, typedAttempt := model.RepositoryID(target.repository.ID), model.WorkflowRunID(runID), model.RunAttempt(bundle.Attempt)
	jobIDs := make([]int64, 0, len(candidates))
	for jobID := range candidates {
		jobIDs = append(jobIDs, jobID)
	}
	sort.Slice(jobIDs, func(i, j int) bool { return jobIDs[i] < jobIDs[j] })
	seenCandidates := make(map[int64]map[int]bool, len(candidates))
	accepted := make(map[int64][]acceptedStep)
	for _, jobID := range jobIDs {
		stepNumbers := make([]int, 0, len(candidates[jobID]))
		for number := range candidates[jobID] {
			stepNumbers = append(stepNumbers, number)
		}
		sort.Ints(stepNumbers)
		for _, number := range stepNumbers {
			values := candidates[jobID][number]
			if seenCandidates[jobID] == nil {
				seenCandidates[jobID] = make(map[int]bool)
			}
			seenCandidates[jobID][number] = true
			sort.Slice(values, func(i, j int) bool { return values[i].entry.Index < values[j].entry.Index })
			selected, selectionErr := selectActionStepCandidate(ctx, values)
			if selectionErr != nil {
				return selectionErr
			}
			entryEvidenceIDs := make([]model.EvidenceID, 0, len(values))
			for _, candidate := range values {
				jobIDTyped := model.JobID(jobID)
				scope := model.CoverageScope{RepositoryID: &repositoryID, RunID: &typedRun, RunAttempt: &typedAttempt, JobID: &jobIDTyped}
				var envelope evidence.Envelope
				var err error
				if candidate.consolidated {
					envelope, err = derivedConsolidatedActionFrameEnvelope(
						sessionID,
						requestID("consolidated-action-frame", fmt.Sprint(target.repository.ID), fmt.Sprint(runID), fmt.Sprint(bundle.Attempt), fmt.Sprint(jobID), fmt.Sprint(number), fmt.Sprint(candidate.entry.Index)),
						scope, stepEventTime(candidate.step), uint64(len(candidate.bytes)), sha256Hex(candidate.bytes), attemptEvidenceID, started, ended,
					)
				} else {
					envelope, err = derivedActionStepEntryEnvelope(
						sessionID,
						requestID("action-step-entry", fmt.Sprint(target.repository.ID), fmt.Sprint(runID), fmt.Sprint(bundle.Attempt), fmt.Sprint(jobID), fmt.Sprint(number), fmt.Sprint(candidate.entry.Index)),
						scope, stepEventTime(candidate.step), uint64(len(candidate.bytes)), sha256Hex(candidate.bytes), attemptEvidenceID, started, ended,
					)
				}
				if err != nil {
					return err
				}
				result.evidence = append(result.evidence, envelope)
				entryEvidenceIDs = append(entryEvidenceIDs, envelope.Evidence.ID)
			}
			if selected < 0 {
				if err := appendGap(result, collect.Gap{Reason: collect.GapValidation, Scope: "action_step_correlation", RepositoryID: target.repository.ID, RunID: runID, Attempt: bundle.Attempt, JobID: jobID, Material: true, Diagnostic: "multiple materially different step-log entries mapped to the same API step"}); err != nil {
					return err
				}
				continue
			}
			candidate := values[selected]
			if !archiveTrusted {
				if err := appendGap(result, collect.Gap{Reason: collect.GapMalformedResponse, Scope: "action_step_correlation", RepositoryID: target.repository.ID, RunID: runID, Attempt: bundle.Attempt, JobID: jobID, Material: true, Diagnostic: "attempt archive was incomplete, so step lifecycle correlation was withheld"}); err != nil {
					return err
				}
				continue
			}
			if candidate.rejection != "" {
				if err := appendGap(result, collect.Gap{Reason: collect.GapValidation, Scope: "action_step_correlation", RepositoryID: target.repository.ID, RunID: runID, Attempt: bundle.Attempt, JobID: jobID, Material: candidate.rejectMaterial, Diagnostic: candidate.rejection}); err != nil {
					return err
				}
				continue
			}
			if len(candidate.result.Diagnostics) > 0 || !candidate.result.Complete {
				for _, diagnostic := range candidate.result.Diagnostics {
					material := diagnostic.Code != "SHELL_STEP_LOOKALIKE"
					if err := appendGap(result, collect.Gap{Reason: collect.GapValidation, Scope: "action_step_parser", RepositoryID: target.repository.ID, RunID: runID, Attempt: bundle.Attempt, JobID: jobID, Material: material, Diagnostic: safeField(diagnostic.Code+": "+diagnostic.Error, 2048)}); err != nil {
						return err
					}
				}
				if len(candidate.result.Diagnostics) == 0 {
					if err := appendGap(result, collect.Gap{Reason: collect.GapValidation, Scope: "action_step_parser", RepositoryID: target.repository.ID, RunID: runID, Attempt: bundle.Attempt, JobID: jobID, Material: true, Diagnostic: "action-step parser did not close its structural grammar"}); err != nil {
						return err
					}
				}
				continue
			}

			lifecycle := make([]logparse.Observation, 0, 2)
			for _, observation := range candidate.result.Observations {
				if (observation.Kind == logparse.ObservationLifecycleStarted || observation.Kind == logparse.ObservationLifecycleCompleted) && observation.Action != nil {
					lifecycle = append(lifecycle, observation)
				}
			}
			if len(lifecycle) == 0 {
				if err := appendGap(result, collect.Gap{Reason: collect.GapValidation, Scope: "action_step_parser", RepositoryID: target.repository.ID, RunID: runID, Attempt: bundle.Attempt, JobID: jobID, Material: true, Diagnostic: "validated step entry contained no repository Action lifecycle start"}); err != nil {
					return err
				}
				continue
			}
			key := actionDeclarationKey(*lifecycle[0].Action)
			resolution, exact := selectSetupResolution(resolutions[jobID][key])
			if !exact {
				if err := appendGap(result, collect.Gap{Reason: collect.GapValidation, Scope: "action_step_resolution", RepositoryID: target.repository.ID, RunID: runID, Attempt: bundle.Attempt, JobID: jobID, Material: true, Diagnostic: "step lifecycle did not join to one exact setup SHA or immutable package identity in the same job attempt"}); err != nil {
					return err
				}
				continue
			}
			jobEvidenceID, ok := jobEvidence[jobID]
			if !ok || jobEvidenceID.Validate() != nil {
				return fmt.Errorf("exact Action lifecycle correlation is missing its job API evidence for job %d", jobID)
			}
			evidenceIDs := model.SortEvidenceIDs(append(append(append(append([]model.EvidenceID{}, entryEvidenceIDs...), resolution.evidenceIDs...), candidate.historicalEvidence...), jobEvidenceID))
			for _, observation := range lifecycle {
				enriched := observation
				action := *observation.Action
				action.Source = resolution.action.Source
				action.Version = resolution.action.Version
				action.Digest = resolution.action.Digest
				enriched.Action = &action
				runtime, err := runtimeObservation(candidate.identity.Job, enriched, evidenceIDs, logEventTime(enriched.EventTime), &candidate.identity)
				if err != nil {
					return fmt.Errorf("normalize exact Action lifecycle observation: %w", err)
				}
				result.facts = append(result.facts, archive.Fact{Kind: archive.FactActionOccurrence, EvidenceIDs: evidenceIDs, ActionOccurrence: &archive.ActionOccurrenceFact{Observation: runtime}})
				result.actionFacts++
				result.lifecycleFacts++
			}
			if err := processCompositePrefixLifecycle(
				ctx, target, runID, bundle.Attempt, sessionID, started, ended, attemptEvidenceID,
				candidate, resolution, entryEvidenceIDs, jobEvidenceID, resolutions[jobID], historical, result,
			); err != nil {
				return err
			}
			accepted[jobID] = append(accepted[jobID], acceptedStep{step: candidate.step})
			jobIDTyped := model.JobID(jobID)
			scope := model.CoverageScope{RepositoryID: &repositoryID, RunID: &typedRun, RunAttempt: &typedAttempt, JobID: &jobIDTyped}
			if err := appendCollectedCoverage(result, model.CoverageParserGrammar, scope, fmt.Sprintf("action_step_parser:%d:%d:%d:%d:%d", target.repository.ID, runID, bundle.Attempt, jobID, number), uint64(len(lifecycle)), evidenceIDs, true); err != nil {
				return err
			}
		}
	}

	// A default-named API step whose declaration was resolved in setup is a
	// known lifecycle candidate. Its missing entry is a material evidence gap;
	// absence is never converted into a clean non-execution conclusion.
	jobs := append([]githubapi.WorkflowJob(nil), bundle.Jobs...)
	sort.Slice(jobs, func(i, j int) bool { return jobs[i].ID < jobs[j].ID })
	for _, job := range jobs {
		steps := append([]githubapi.JobStep(nil), job.Steps...)
		sort.Slice(steps, func(i, j int) bool { return steps[i].Number < steps[j].Number })
		for _, step := range steps {
			if seenCandidates[job.ID][step.Number] {
				continue
			}
			if !strings.HasPrefix(step.Name, "Run ") {
				continue
			}
			declared := strings.TrimPrefix(step.Name, "Run ")
			key := actionKeyFromDeclaration(declared)
			if key == "" || len(resolutions[job.ID][key]) == 0 {
				continue
			}
			material := !strings.EqualFold(step.Conclusion, "skipped")
			diagnostic := "resolved default-named Action step had no unambiguously bound step-log entry"
			if !material {
				diagnostic = "skipped resolved Action step had no lifecycle entry; no execution was inferred"
			}
			if err := appendGap(result, collect.Gap{Reason: collect.GapNotFound, Scope: "action_step_correlation", RepositoryID: target.repository.ID, RunID: runID, Attempt: bundle.Attempt, JobID: job.ID, Material: material, Diagnostic: diagnostic}); err != nil {
				return err
			}
		}
	}

	for jobID, steps := range accepted {
		if hasOverlappingStepIntervals(steps) {
			if err := appendGap(result, collect.Gap{Reason: collect.GapValidation, Scope: "step_ordering", RepositoryID: target.repository.ID, RunID: runID, Attempt: bundle.Attempt, JobID: jobID, Material: false, Diagnostic: "API step intervals overlap; individual starts were preserved but no relative execution order was inferred"}); err != nil {
				return err
			}
		}
	}
	return nil
}

func processCompositePrefixLifecycle(
	ctx context.Context,
	target repositoryWork,
	runID int64,
	attempt int,
	sessionID model.CollectionSessionID,
	started, ended model.Instant,
	attemptEvidenceID model.EvidenceID,
	parent parsedActionStep,
	parentResolution setupResolution,
	parentFrameEvidence []model.EvidenceID,
	jobEvidenceID model.EvidenceID,
	jobResolutions map[string][]setupResolution,
	historical *historicalAttempt,
	result *repositoryResult,
) error {
	if historical == nil {
		return nil
	}
	binding, bound := historical.compositeBinding(parent.job.ID, parentResolution)
	if !bound {
		if parent.adjacentRun != nil {
			return appendGap(result, collect.Gap{
				Reason: collect.GapAmbiguousCorrelation, Scope: "composite_step_correlation", RepositoryID: target.repository.ID,
				RunID: runID, Attempt: attempt, JobID: parent.job.ID, Material: true,
				Diagnostic: "an adjacent Run group was present, but exact composite metadata did not establish it as the first unconditional child Action",
			})
		}
		return nil
	}
	if parent.adjacentRun == nil {
		return appendGap(result, collect.Gap{
			Reason: collect.GapNotFound, Scope: "composite_step_correlation", RepositoryID: target.repository.ID,
			RunID: runID, Attempt: attempt, JobID: parent.job.ID, Material: true,
			Diagnostic: "the exact composite first child had no complete immediately adjacent runner-control group; child execution was not inferred",
		})
	}
	if parent.adjacentRun.MarkerLine != 0 && parent.adjacentRun.MarkerDisplay != binding.childDisplayName {
		return appendGap(result, collect.Gap{
			Reason: collect.GapAmbiguousCorrelation, Scope: "composite_step_correlation", RepositoryID: target.repository.ID,
			RunID: runID, Attempt: attempt, JobID: parent.job.ID, Material: true,
			Diagnostic: "the runner composite start marker did not exactly match the first static child display name",
		})
	}
	childKey := actionKeyFromDeclaration(binding.childDeclaration)
	childResolution, exact := selectSetupResolution(jobResolutions[childKey])
	if !exact || !setupResolutionMatchesDefinition(childResolution, binding.childDefinition) {
		return appendGap(result, collect.Gap{
			Reason: collect.GapAmbiguousCorrelation, Scope: "composite_step_correlation", RepositoryID: target.repository.ID,
			RunID: runID, Attempt: attempt, JobID: parent.job.ID, Material: true,
			Diagnostic: "the composite child group did not join to one exact same-job setup identity matching the historical child definition",
		})
	}

	repositoryID, typedRun, typedAttempt, typedJob := model.RepositoryID(target.repository.ID), model.WorkflowRunID(runID), model.RunAttempt(attempt), model.JobID(parent.job.ID)
	scope := model.CoverageScope{RepositoryID: &repositoryID, RunID: &typedRun, RunAttempt: &typedAttempt, JobID: &typedJob}
	frame := parent.adjacentRun
	evidenceBytes := frame.EvidenceBytes
	if len(evidenceBytes) == 0 {
		evidenceBytes = frame.Bytes
	}
	frameEnvelope, err := derivedConsolidatedCompositePrefixFrameEnvelope(
		sessionID,
		requestID("consolidated-composite-prefix-frame", fmt.Sprint(target.repository.ID), fmt.Sprint(runID), fmt.Sprint(attempt), fmt.Sprint(parent.job.ID), fmt.Sprint(parent.step.Number), fmt.Sprint(parent.entry.Index)),
		scope, stepEventTime(parent.step), uint64(len(evidenceBytes)), sha256Hex(evidenceBytes), attemptEvidenceID, started, ended,
	)
	if err != nil {
		return err
	}
	result.evidence = append(result.evidence, frameEnvelope)

	identity := parent.identity
	identity.Occurrence = 2
	ordinal := binding.childASTOrdinal
	identity.ASTOrdinal = &ordinal
	if err := identity.Validate(); err != nil {
		return err
	}
	parsed, err := logparse.Parse(ctx, bytes.NewReader(frame.Bytes), logparse.SourceContext{
		Scope: logparse.ExecutionScope{
			RepositoryID: target.repository.ID, RunID: runID, RunAttempt: attempt,
			JobID: parent.job.ID, StepKey: identity.Key(),
		},
		Role: logparse.RoleActionStep, LifecyclePhase: logparse.PhaseMain,
		ExpectedAction: binding.childDeclaration, APIStatus: parent.step.Status, APIConclusion: parent.step.Conclusion,
		Grammar: logparse.ConsolidatedGrammarVersion, LineOffset: frame.LineStart - 1, GrammarValidated: true,
	})
	if err != nil {
		return err
	}
	if len(parsed.Diagnostics) != 0 || !parsed.Complete {
		return appendGap(result, collect.Gap{
			Reason: collect.GapValidation, Scope: "composite_step_correlation", RepositoryID: target.repository.ID,
			RunID: runID, Attempt: attempt, JobID: parent.job.ID, Material: true,
			Diagnostic: "the immediate composite child group did not satisfy the strict repository-Action lifecycle grammar",
		})
	}
	lifecycle := make([]logparse.Observation, 0, 2)
	for _, observation := range parsed.Observations {
		if (observation.Kind == logparse.ObservationLifecycleStarted || observation.Kind == logparse.ObservationLifecycleCompleted) && observation.Action != nil {
			lifecycle = append(lifecycle, observation)
		}
	}
	if len(lifecycle) != 2 || lifecycle[0].Kind != logparse.ObservationLifecycleStarted || lifecycle[1].Kind != logparse.ObservationLifecycleCompleted || !compositeObservationsWithinAPIStep(lifecycle, parent.step) {
		return appendGap(result, collect.Gap{
			Reason: collect.GapValidation, Scope: "composite_step_correlation", RepositoryID: target.repository.ID,
			RunID: runID, Attempt: attempt, JobID: parent.job.ID, Material: true,
			Diagnostic: "the immediate composite child group did not establish one complete lifecycle inside the exact API step interval",
		})
	}
	evidenceIDs := model.SortEvidenceIDs(append(append(append(append(append(append(append([]model.EvidenceID{}, parentFrameEvidence...), frameEnvelope.Evidence.ID), parent.historicalEvidence...), parentResolution.evidenceIDs...), childResolution.evidenceIDs...), binding.evidenceIDs...), jobEvidenceID))
	for _, observation := range lifecycle {
		enriched := observation
		action := *observation.Action
		action.Source = childResolution.action.Source
		action.Version = childResolution.action.Version
		action.Digest = childResolution.action.Digest
		enriched.Action = &action
		runtime, err := runtimeObservation(identity.Job, enriched, evidenceIDs, logEventTime(enriched.EventTime), &identity)
		if err != nil {
			return err
		}
		result.facts = append(result.facts, archive.Fact{Kind: archive.FactActionOccurrence, EvidenceIDs: evidenceIDs, ActionOccurrence: &archive.ActionOccurrenceFact{Observation: runtime}})
		result.actionFacts++
		result.lifecycleFacts++
	}
	return appendCollectedCoverage(result, model.CoverageParserGrammar, scope, fmt.Sprintf("composite_action_step_parser:%d:%d:%d:%d:%d", target.repository.ID, runID, attempt, parent.job.ID, parent.step.Number), uint64(len(lifecycle)), evidenceIDs, true)
}

func compositeObservationsWithinAPIStep(values []logparse.Observation, step githubapi.JobStep) bool {
	if step.StartedAt == nil || step.StartedAt.IsZero() {
		return false
	}
	start := step.StartedAt.UTC()
	var end *time.Time
	if step.CompletedAt != nil && !step.CompletedAt.IsZero() && !step.CompletedAt.Before(start) {
		value := step.CompletedAt.UTC().Add(time.Second)
		end = &value
	}
	for _, observation := range values {
		if observation.EventTime == nil || observation.EventTime.Before(start) || (end != nil && !observation.EventTime.Before(*end)) {
			return false
		}
	}
	return true
}

func actionKeyFromDeclaration(value string) string {
	at := strings.LastIndexByte(value, '@')
	if at <= 0 || at == len(value)-1 {
		return ""
	}
	segments := strings.Split(value[:at], "/")
	if len(segments) < 2 || segments[0] == "" || segments[1] == "" {
		return ""
	}
	for _, segment := range segments {
		if segment == "" || segment == "." || segment == ".." || strings.Contains(segment, `\`) {
			return ""
		}
	}
	action := logparse.Action{Owner: strings.ToLower(segments[0]), Repository: strings.ToLower(segments[1]), Subpath: strings.Join(segments[2:], "/"), Ref: value[at+1:]}
	return actionDeclarationKey(action)
}

func actionKeyFromDefaultAPIStep(step githubapi.JobStep) string {
	if !strings.HasPrefix(step.Name, "Run ") {
		return ""
	}
	return actionKeyFromDeclaration(strings.TrimPrefix(step.Name, "Run "))
}

func stepEventTime(step githubapi.JobStep) model.EventInterval {
	if step.StartedAt == nil || step.StartedAt.IsZero() {
		return unknownTime()
	}
	start := model.MustInstant(step.StartedAt.UTC())
	if step.CompletedAt == nil || step.CompletedAt.IsZero() || step.CompletedAt.Before(*step.StartedAt) {
		return model.EventInterval{Start: &start, Precision: model.PrecisionSecond, Approximation: model.ApproximationExact, Basis: model.TimeBasisAPIField}
	}
	end := model.MustInstant(step.CompletedAt.UTC())
	bounds := model.BoundsClosedOpen
	if end.Equal(start.Time) {
		bounds = model.BoundsClosed
	}
	return model.EventInterval{Start: &start, End: &end, Bounds: &bounds, Precision: model.PrecisionSecond, Approximation: model.ApproximationExact, Basis: model.TimeBasisAPIField}
}

func hasOverlappingStepIntervals(values []acceptedStep) bool {
	for left := 0; left < len(values); left++ {
		a := values[left].step
		if a.StartedAt == nil || a.CompletedAt == nil || !a.StartedAt.Before(*a.CompletedAt) {
			continue
		}
		for right := left + 1; right < len(values); right++ {
			b := values[right].step
			if b.StartedAt == nil || b.CompletedAt == nil || !b.StartedAt.Before(*b.CompletedAt) {
				continue
			}
			if a.StartedAt.Before(*b.CompletedAt) && b.StartedAt.Before(*a.CompletedAt) {
				return true
			}
		}
	}
	return false
}
