package livecollect

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/torjan0/cirewind/internal/archive"
	"github.com/torjan0/cirewind/internal/collect"
	"github.com/torjan0/cirewind/internal/evidence"
	"github.com/torjan0/cirewind/internal/githubapi"
	"github.com/torjan0/cirewind/internal/logparse"
	"github.com/torjan0/cirewind/internal/model"
)

const maxSetupEntryBytes = int64(16 << 20)

type parsedSetup struct {
	entry        logparse.Entry
	job          githubapi.WorkflowJob
	result       logparse.ParseResult
	bytes        []byte
	consolidated bool
}

// selectSetupCandidate accepts the current GitHub archive's two structural
// views only when one consolidated setup frame and one legacy split setup
// entry contain the exact same ordered runner payload records. Display-view
// timestamps may differ. Two entries of the same layout, any third candidate,
// or any payload difference remains ambiguous.
func selectSetupCandidate(ctx context.Context, candidates []parsedSetup) (selected int, equivalentViews []int, err error) {
	if len(candidates) == 1 {
		return 0, []int{0}, nil
	}
	if len(candidates) != 2 || candidates[0].consolidated == candidates[1].consolidated {
		return -1, nil, nil
	}
	equal, err := logparse.EqualRunnerControlText(ctx, candidates[0].bytes, candidates[1].bytes)
	if err != nil || !equal {
		return -1, nil, err
	}
	if candidates[0].consolidated {
		return 0, []int{0, 1}, nil
	}
	return 1, []int{0, 1}, nil
}

type runnerMetadataProjection struct {
	Attribute string `json:"attribute"`
	Value     string `json:"value"`
	EventTime string `json:"event_time,omitempty"`
	Line      int    `json:"line"`
}

type setupRunnerProjection struct {
	Schema       string                     `json:"schema"`
	Grammar      string                     `json:"grammar"`
	RepositoryID int64                      `json:"repository_id"`
	RunID        int64                      `json:"run_id"`
	RunAttempt   int                        `json:"run_attempt"`
	JobID        int64                      `json:"job_id"`
	Metadata     []runnerMetadataProjection `json:"metadata"`
}

type untypedActionSourceProjection struct {
	Kind             string `json:"kind"`
	Repository       string `json:"repository"`
	Subpath          string `json:"subpath,omitempty"`
	DeclaredRef      string `json:"declared_ref"`
	SourceHexUntyped string `json:"source_hex_untyped,omitempty"`
	PackageDigest    string `json:"package_digest,omitempty"`
	LineStart        int    `json:"line_start"`
	LineEnd          int    `json:"line_end"`
}

type setupActionSourceProjection struct {
	Schema       string                          `json:"schema"`
	RepositoryID int64                           `json:"repository_id"`
	RunID        int64                           `json:"run_id"`
	RunAttempt   int                             `json:"run_attempt"`
	JobID        int64                           `json:"job_id"`
	Sources      []untypedActionSourceProjection `json:"sources"`
}

func (c Collector) downloadAndParseAttempt(ctx context.Context, request Request, target repositoryWork, parent githubapi.WorkflowRun, runID int64, bundle collect.AttemptBundle, _ string, sessionID model.CollectionSessionID, attemptEvidenceID model.EvidenceID, now Clock, limits logparse.ArchiveLimits, jobs map[int64]githubapi.WorkflowJob, jobEvidence map[int64]model.EvidenceID, result *repositoryResult) (returnErr error) {
	setupResolutions := make(map[int64]map[string][]setupResolution)
	historical := c.newHistoricalAttempt(target, parent, runID, bundle, sessionID, now, result)
	// API, retention, and malformed-archive gaps normally return nil after
	// being persisted. Resolve in a defer so exact called-workflow metadata is
	// still preserved when attempt logs are absent; cancellation and internal
	// invariant failures remain non-committable.
	defer func() {
		if returnErr != nil {
			return
		}
		returnErr = historical.resolve(ctx, setupResolutions, attemptEvidenceID)
	}()
	file, err := os.CreateTemp(c.TempDir, "cirewind-attempt-log-*.zip")
	if err != nil {
		return appendGap(result, collect.Gap{Reason: collect.GapLocalIO, Scope: "attempt_log", RepositoryID: target.repository.ID, RunID: runID, Attempt: bundle.Attempt, Material: true, Diagnostic: "could not create an owner-only transient log file"})
	}
	name := file.Name()
	keepForSink := false
	defer func() {
		if !keepForSink {
			_ = os.Remove(name)
		}
	}()
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return appendGap(result, collect.Gap{Reason: collect.GapLocalIO, Scope: "attempt_log", RepositoryID: target.repository.ID, RunID: runID, Attempt: bundle.Attempt, Material: true, Diagnostic: "could not restrict transient log-file permissions"})
	}
	hasher := sha256.New()
	writer := &boundedFileHashWriter{file: file, hash: hasher, limit: request.MaxAttemptLogBytes}
	started := model.MustInstant(now().UTC())
	download, downloadErr := c.API.DownloadAttemptLogs(ctx, target.owner, target.name, runID, bundle.Attempt, writer)
	ended := model.MustInstant(now().UTC())
	closeErr := file.Close()
	if downloadErr != nil || closeErr != nil {
		gap := collect.GapFromError("attempt_log", target.repository.ID, runID, bundle.Attempt, downloadErr)
		if downloadErr == nil {
			gap = collect.Gap{Reason: collect.GapLocalIO, Scope: "attempt_log", RepositoryID: target.repository.ID, RunID: runID, Attempt: bundle.Attempt, Material: true, Diagnostic: "could not close the transient attempt-log file"}
		} else if writer.count >= request.MaxAttemptLogBytes {
			gap.Reason = collect.GapSizeLimit
			gap.Material = true
			gap.Diagnostic = "attempt log exceeded the adapter byte limit and its transient bytes were discarded"
		}
		return appendGap(result, gap)
	}
	localSHA := hex.EncodeToString(hasher.Sum(nil))
	repositoryID, typedRun, typedAttempt := model.RepositoryID(target.repository.ID), model.WorkflowRunID(runID), model.RunAttempt(bundle.Attempt)
	attemptScope := model.CoverageScope{RepositoryID: &repositoryID, RunID: &typedRun, RunAttempt: &typedAttempt}
	attemptEnvelope, envelopeErr := logEnvelope(sessionID, requestID("attempt-log", fmt.Sprint(target.repository.ID), fmt.Sprint(runID), fmt.Sprint(bundle.Attempt)), fmt.Sprintf("github:attempt-log:%d:%d:%d", target.repository.ID, runID, bundle.Attempt), evidence.SourceWorkflowRunAttemptLog, "/repos/{owner}/{repo}/actions/runs/{run_id}/attempts/{attempt_number}/logs", evidence.RequestParameters{"owner": target.owner, "repo": target.name, "run_id": fmt.Sprint(runID), "attempt_number": fmt.Sprint(bundle.Attempt)}, attemptScope, runAttemptEvent(bundle.Run), download, uint64(writer.count), localSHA, request.RawRetention, started, ended)
	if envelopeErr != nil {
		return appendGap(result, collect.Gap{Reason: collect.GapMalformedResponse, Scope: "attempt_log", RepositoryID: target.repository.ID, RunID: runID, Attempt: bundle.Attempt, Material: true, Diagnostic: "attempt-log download metadata did not match locally hashed bytes"})
	}
	result.evidence = append(result.evidence, attemptEnvelope)
	result.attemptLogs++
	if request.RawRetention {
		result.rawInputs = append(result.rawInputs, archive.RawInput{SHA256: localSHA, MediaType: attemptEnvelope.Evidence.Content.MediaType, ByteLength: uint64(writer.count), SourcePath: name})
		result.rawLogs++
		keepForSink = true
	}
	if err := historical.prepareLifecycleBindings(ctx, attemptEnvelope.Evidence.ID); err != nil {
		return err
	}

	opened, err := os.Open(name)
	if err != nil {
		return appendGap(result, collect.Gap{Reason: collect.GapLocalIO, Scope: "attempt_log", RepositoryID: target.repository.ID, RunID: runID, Attempt: bundle.Attempt, Material: true, Diagnostic: "could not reopen the transient attempt-log file"})
	}
	defer opened.Close()
	parsedByJob := make(map[int64][]parsedSetup)
	parsedSteps := make(map[int64]map[int][]parsedActionStep)
	stepIssues := make([]stepEntryIssue, 0)
	framingIssues := make([]stepEntryIssue, 0)
	quarantinedCorrelationBlocked := false
	archiveResult, archiveErr := logparse.ReadZIP(ctx, opened, writer.count, limits, func(parseCtx context.Context, entry logparse.Entry, reader io.Reader) error {
		consolidatedJob, consolidatedRelevant, consolidatedIssue := correlateConsolidatedJobEntry(entry.LogicalName, bundle.Jobs)
		if consolidatedRelevant {
			if consolidatedIssue != "" {
				framingIssues = append(framingIssues, stepEntryIssue{diagnostic: consolidatedIssue})
				return nil
			}
			if !bundle.LogJobNameCorrelationSafe(consolidatedJob.Name) {
				quarantinedCorrelationBlocked = true
				return nil
			}
			entryBytes, readErr := io.ReadAll(io.LimitReader(reader, int64(logparse.MaxConsolidatedJobBytes)+1))
			if readErr != nil {
				return readErr
			}
			if len(entryBytes) > logparse.MaxConsolidatedJobBytes {
				return fmt.Errorf("consolidated job entry exceeds %d bytes", logparse.MaxConsolidatedJobBytes)
			}
			framed, frameErr := logparse.FrameConsolidatedJob(parseCtx, entryBytes, consolidatedJob.Name, consolidatedSteps(consolidatedJob, historical))
			entryBytes = nil
			if frameErr != nil {
				return frameErr
			}
			for _, diagnostic := range framed.Diagnostics {
				framingIssues = append(framingIssues, stepEntryIssue{jobID: consolidatedJob.ID, diagnostic: safeField(diagnostic.Code+": "+diagnostic.Error, 2048)})
			}
			if framed.Setup != nil {
				setupStatus, setupConclusion, recognized := setupStepConclusion(consolidatedJob)
				if !recognized {
					parsedByJob[consolidatedJob.ID] = append(parsedByJob[consolidatedJob.ID], parsedSetup{entry: entry, job: consolidatedJob, bytes: framed.Setup.Bytes, consolidated: true, result: logparse.ParseResult{Complete: false, Diagnostics: []logparse.ParseDiagnostic{{Code: "AMBIGUOUS_CORRELATION", Error: "job API omitted an unambiguous Set up job step"}}}})
				} else {
					parsed, parseErr := logparse.Parse(parseCtx, bytes.NewReader(framed.Setup.Bytes), logparse.SourceContext{
						Scope: logparse.ExecutionScope{RepositoryID: target.repository.ID, RunID: runID, RunAttempt: bundle.Attempt, JobID: consolidatedJob.ID, StepKey: "setup"},
						Role:  logparse.RoleSetup, LifecyclePhase: logparse.PhaseMain,
						APIStatus: setupStatus, APIConclusion: setupConclusion, Grammar: logparse.ConsolidatedGrammarVersion,
						LineOffset: framed.Setup.LineStart - 1, GrammarValidated: true,
					})
					if parseErr != nil {
						return parseErr
					}
					parsedByJob[consolidatedJob.ID] = append(parsedByJob[consolidatedJob.ID], parsedSetup{entry: entry, job: consolidatedJob, result: parsed, bytes: framed.Setup.Bytes, consolidated: true})
				}
			}
			for _, frame := range framed.ActionSteps {
				step, ok := exactAPIStep(consolidatedJob, frame.APIStepNumber)
				if !ok {
					framingIssues = append(framingIssues, stepEntryIssue{jobID: consolidatedJob.ID, diagnostic: "consolidated Action frame did not bind to exactly one API step"})
					continue
				}
				binding, bound := historical.stepBinding(consolidatedJob.ID, step.Number)
				if !bound && actionKeyFromDefaultAPIStep(step) == "" {
					continue
				}
				candidate, parseErr := parseActionStepCandidate(parseCtx, target, runID, bundle.Attempt, consolidatedJob, step, entry, frame.Bytes, true, frame.LineStart-1, binding)
				if parseErr != nil {
					return parseErr
				}
				if frame.AdjacentRun != nil {
					copy := *frame.AdjacentRun
					copy.Bytes = append([]byte(nil), frame.AdjacentRun.Bytes...)
					copy.EvidenceBytes = append([]byte(nil), frame.AdjacentRun.EvidenceBytes...)
					candidate.adjacentRun = &copy
				}
				if parsedSteps[consolidatedJob.ID] == nil {
					parsedSteps[consolidatedJob.ID] = make(map[int][]parsedActionStep)
				}
				parsedSteps[consolidatedJob.ID][step.Number] = append(parsedSteps[consolidatedJob.ID][step.Number], candidate)
			}
			return nil
		}

		entryBase := path.Base(entry.LogicalName)
		entryJobName := path.Base(path.Dir(entry.LogicalName))
		jobScopedEntry := entryBase == "1_Set up job.txt" || actionStepEntryPattern.MatchString(entryBase)
		if jobScopedEntry && !bundle.LogJobNameCorrelationSafe(entryJobName) {
			// The ZIP format identifies jobs by a display-name directory, not by
			// the API job ID. A quarantined API object with the same (or an
			// absent) name makes this entry ambiguous. Do not let its bytes bind
			// to a valid sibling merely because that sibling remains collectable.
			quarantinedCorrelationBlocked = true
			return nil
		}
		job, ok := correlateSetupEntry(entry.LogicalName, bundle.Jobs)
		if ok {
			entryBytes, readErr := io.ReadAll(io.LimitReader(reader, maxSetupEntryBytes+1))
			if readErr != nil {
				return readErr
			}
			if int64(len(entryBytes)) > maxSetupEntryBytes {
				return fmt.Errorf("setup entry exceeds %d bytes", maxSetupEntryBytes)
			}
			setupStatus, setupConclusion, recognized := setupStepConclusion(job)
			if !recognized {
				parsedByJob[job.ID] = append(parsedByJob[job.ID], parsedSetup{entry: entry, job: job, bytes: entryBytes, result: logparse.ParseResult{Complete: false, Diagnostics: []logparse.ParseDiagnostic{{Code: "AMBIGUOUS_CORRELATION", Error: "job API omitted an unambiguous Set up job step"}}}})
				return nil
			}
			parsed, parseErr := logparse.Parse(parseCtx, bytes.NewReader(entryBytes), logparse.SourceContext{
				Scope: logparse.ExecutionScope{RepositoryID: target.repository.ID, RunID: runID, RunAttempt: bundle.Attempt, JobID: job.ID, StepKey: "setup"},
				Role:  logparse.RoleSetup, LifecyclePhase: logparse.PhaseMain,
				APIStatus: setupStatus, APIConclusion: setupConclusion, GrammarValidated: true,
			})
			if parseErr != nil {
				return parseErr
			}
			parsedByJob[job.ID] = append(parsedByJob[job.ID], parsedSetup{entry: entry, job: job, result: parsed, bytes: entryBytes})
			return nil
		}

		stepJob, step, relevant, correlationIssue := correlateActionStepEntry(entry.LogicalName, bundle.Jobs)
		if !relevant {
			return nil
		}
		if correlationIssue != "" {
			stepIssues = append(stepIssues, stepEntryIssue{jobID: stepJob.ID, diagnostic: correlationIssue})
			return nil
		}
		binding, bound := historical.stepBinding(stepJob.ID, step.Number)
		if !bound && actionKeyFromDefaultAPIStep(step) == "" {
			return nil
		}
		entryBytes, readErr := io.ReadAll(io.LimitReader(reader, maxSetupEntryBytes+1))
		if readErr != nil {
			return readErr
		}
		if int64(len(entryBytes)) > maxSetupEntryBytes {
			return fmt.Errorf("action-step entry exceeds %d bytes", maxSetupEntryBytes)
		}
		candidate, parseErr := parseActionStepCandidate(parseCtx, target, runID, bundle.Attempt, stepJob, step, entry, entryBytes, false, 0, binding)
		if parseErr != nil {
			return parseErr
		}
		if parsedSteps[stepJob.ID] == nil {
			parsedSteps[stepJob.ID] = make(map[int][]parsedActionStep)
		}
		parsedSteps[stepJob.ID][step.Number] = append(parsedSteps[stepJob.ID][step.Number], candidate)
		return nil
	})
	if err := ctx.Err(); err != nil {
		return err
	}
	if archiveErr != nil {
		reason := collect.GapMalformedResponse
		if strings.Contains(strings.ToLower(archiveErr.Error()), "limit") {
			reason = collect.GapSizeLimit
		}
		if err := appendGap(result, collect.Gap{Reason: reason, Scope: "attempt_log", RepositoryID: target.repository.ID, RunID: runID, Attempt: bundle.Attempt, Material: true, Diagnostic: "attempt-log ZIP could not be parsed within safety limits"}); err != nil {
			return err
		}
	}
	for _, diagnostic := range archiveResult.Diagnostics {
		reason := collect.GapMalformedResponse
		if strings.Contains(diagnostic.Code, "SIZE") || strings.Contains(diagnostic.Code, "RATIO") {
			reason = collect.GapSizeLimit
		}
		if err := appendGap(result, collect.Gap{Reason: reason, Scope: "attempt_log", RepositoryID: target.repository.ID, RunID: runID, Attempt: bundle.Attempt, Material: true, Diagnostic: "attempt-log ZIP contained an unsafe, ambiguous, or malformed entry"}); err != nil {
			return err
		}
	}
	if quarantinedCorrelationBlocked {
		if err := appendGap(result, collect.Gap{Reason: collect.GapAmbiguousCorrelation, Scope: "attempt_log_job_identity", RepositoryID: target.repository.ID, RunID: runID, Attempt: bundle.Attempt, Material: true, Diagnostic: "attempt-log entry could not be bound because a job API identity was quarantined"}); err != nil {
			return err
		}
	}
	for _, issue := range stepIssues {
		if err := appendGap(result, collect.Gap{Reason: collect.GapValidation, Scope: "action_step_correlation", RepositoryID: target.repository.ID, RunID: runID, Attempt: bundle.Attempt, JobID: issue.jobID, Material: true, Diagnostic: issue.diagnostic}); err != nil {
			return err
		}
	}
	for _, issue := range framingIssues {
		if err := appendGap(result, collect.Gap{Reason: collect.GapValidation, Scope: "consolidated_log_framing", RepositoryID: target.repository.ID, RunID: runID, Attempt: bundle.Attempt, JobID: issue.jobID, Material: true, Diagnostic: issue.diagnostic}); err != nil {
			return err
		}
	}

	jobIDs := make([]int64, 0, len(jobs))
	for jobID := range jobs {
		jobIDs = append(jobIDs, jobID)
	}
	sort.Slice(jobIDs, func(i, j int) bool { return jobIDs[i] < jobIDs[j] })
	for _, jobID := range jobIDs {
		job := jobs[jobID]
		candidates := parsedByJob[jobID]
		sort.Slice(candidates, func(i, j int) bool { return candidates[i].entry.Index < candidates[j].entry.Index })
		selected, equivalentViews, selectionErr := selectSetupCandidate(ctx, candidates)
		if selectionErr != nil {
			return selectionErr
		}
		if selected < 0 {
			if job.StartedAt != nil || len(candidates) > 1 {
				diagnostic := "runner-owned setup entry was not present"
				if len(candidates) > 1 {
					diagnostic = "multiple materially different runner-owned setup entries mapped to the same job"
				}
				if err := appendGap(result, collect.Gap{Reason: collect.GapMalformedResponse, Scope: "setup_correlation", RepositoryID: target.repository.ID, RunID: runID, Attempt: bundle.Attempt, JobID: jobID, Material: true, Diagnostic: diagnostic}); err != nil {
					return err
				}
			}
			continue
		}
		candidate := candidates[selected]
		jobIDTyped := model.JobID(jobID)
		entryScope := model.CoverageScope{RepositoryID: &repositoryID, RunID: &typedRun, RunAttempt: &typedAttempt, JobID: &jobIDTyped}
		entryEvidenceIDs := make([]model.EvidenceID, 0, len(equivalentViews))
		for _, viewIndex := range equivalentViews {
			view := candidates[viewIndex]
			entryHash := sha256Hex(view.bytes)
			var entryEnvelope evidence.Envelope
			var entryErr error
			if view.consolidated {
				entryEnvelope, entryErr = derivedConsolidatedSetupFrameEnvelope(sessionID, requestID("consolidated-setup-frame", fmt.Sprint(target.repository.ID), fmt.Sprint(runID), fmt.Sprint(bundle.Attempt), fmt.Sprint(jobID), fmt.Sprint(view.entry.Index)), entryScope, jobEventTime(job), uint64(len(view.bytes)), entryHash, attemptEnvelope.Evidence.ID, started, ended)
			} else {
				entryEnvelope, entryErr = derivedSetupEntryEnvelope(sessionID, requestID("setup-entry", fmt.Sprint(target.repository.ID), fmt.Sprint(runID), fmt.Sprint(bundle.Attempt), fmt.Sprint(jobID), fmt.Sprint(view.entry.Index)), entryScope, jobEventTime(job), uint64(len(view.bytes)), entryHash, attemptEnvelope.Evidence.ID, started, ended)
			}
			if entryErr != nil {
				return entryErr
			}
			result.evidence = append(result.evidence, entryEnvelope)
			entryEvidenceIDs = append(entryEvidenceIDs, entryEnvelope.Evidence.ID)
		}
		entryEvidenceIDs = model.SortEvidenceIDs(entryEvidenceIDs)
		if sourceProjection, ok := projectUntypedActionSources(candidate.result.Observations, job); ok {
			sourcePayload, sourceEnvelope, sourceErr := compactDerivedEnvelope(
				sessionID,
				requestID("setup-action-source", fmt.Sprint(target.repository.ID), fmt.Sprint(runID), fmt.Sprint(bundle.Attempt), fmt.Sprint(jobID)),
				entryScope, jobEventTime(job), sourceProjection, entryEvidenceIDs,
				"setup_action_source", "github-runner-setup-action-source", started, ended,
			)
			if sourceErr != nil {
				return sourceErr
			}
			result.payloads = append(result.payloads, sourcePayload)
			result.evidence = append(result.evidence, sourceEnvelope)
		}
		verified, verifyErr := historical.verifySetupObservations(ctx, candidate.result.Observations, model.SortEvidenceIDs(append(append([]model.EvidenceID(nil), entryEvidenceIDs...), attemptEnvelope.Evidence.ID)))
		if verifyErr != nil {
			return verifyErr
		}
		addSetupResolutions(setupResolutions, jobID, verified)
		if runnerProjection, ok := projectRunnerMetadata(candidate.result.Observations, job); ok {
			runnerPayload, runnerEnvelope, projectionErr := compactDerivedEnvelope(
				sessionID,
				requestID("setup-runner-metadata", fmt.Sprint(target.repository.ID), fmt.Sprint(runID), fmt.Sprint(bundle.Attempt), fmt.Sprint(jobID)),
				entryScope, jobEventTime(job), runnerProjection, entryEvidenceIDs,
				"setup_runner_metadata", "github-runner-setup-metadata", started, ended,
			)
			if projectionErr != nil {
				return projectionErr
			}
			result.payloads, result.evidence = append(result.payloads, runnerPayload), append(result.evidence, runnerEnvelope)
		}
		for _, diagnostic := range candidate.result.Diagnostics {
			if err := appendGap(result, collect.Gap{Reason: collect.GapValidation, Scope: "setup_parser", RepositoryID: target.repository.ID, RunID: runID, Attempt: bundle.Attempt, JobID: jobID, Material: true, Diagnostic: safeField(diagnostic.Code+": "+diagnostic.Error, 2048)}); err != nil {
				return err
			}
		}
		if err := convertSetupObservations(verified, job, result); err != nil {
			return err
		}
		if candidate.result.Complete {
			coverageEvidence := model.SortEvidenceIDs(append(append([]model.EvidenceID(nil), entryEvidenceIDs...), attemptEnvelope.Evidence.ID))
			if err := appendCollectedCoverage(result, model.CoverageParserGrammar, entryScope, coverageLogicalKey("setup_parser", target.repository.ID, runID, bundle.Attempt, jobID), uint64(len(candidate.result.Observations)), coverageEvidence, true); err != nil {
				return err
			}
		}
	}
	if err := historical.prepareCompositeLifecycleBindings(ctx, setupResolutions); err != nil {
		return err
	}
	if err := processActionStepCandidates(ctx, target, runID, bundle, sessionID, started, ended, attemptEnvelope.Evidence.ID, archiveErr == nil && archiveResult.Complete, parsedSteps, setupResolutions, jobEvidence, historical, result); err != nil {
		return err
	}
	if archiveErr == nil && archiveResult.Complete {
		if err := appendCollectedCoverage(result, model.CoverageAttemptLog, attemptScope, coverageLogicalKey("attempt_log", target.repository.ID, runID, bundle.Attempt, 0), uint64(archiveResult.EntriesRead), []model.EvidenceID{attemptEnvelope.Evidence.ID}, true); err != nil {
			return err
		}
	}
	return nil
}

func projectUntypedActionSources(observations []logparse.Observation, job githubapi.WorkflowJob) (setupActionSourceProjection, bool) {
	projected := make([]untypedActionSourceProjection, 0)
	for _, observation := range observations {
		if observation.Kind != logparse.ObservationResolution || observation.Action == nil {
			continue
		}
		action := observation.Action
		if action.Source.Value == "" && action.Digest.Value == "" {
			continue
		}
		item := untypedActionSourceProjection{
			Kind: string(observation.Kind), Repository: safeField(strings.ToLower(action.Owner)+"/"+strings.ToLower(action.Repository), 512),
			Subpath: safeField(action.Subpath, 4096), DeclaredRef: safeField(action.Ref, 1024),
			SourceHexUntyped: strings.ToLower(action.Source.Value), LineStart: max(0, observation.LineStart), LineEnd: max(0, observation.LineEnd),
		}
		if action.Digest.Value != "" {
			item.PackageDigest = safeField(strings.ToLower(action.Digest.Algorithm)+":"+strings.ToLower(action.Digest.Value), 512)
		}
		projected = append(projected, item)
	}
	if len(projected) == 0 {
		return setupActionSourceProjection{}, false
	}
	first := observations[0].Scope
	return setupActionSourceProjection{
		Schema: "cirewind.github-setup-action-source-projection/v1", RepositoryID: first.RepositoryID,
		RunID: first.RunID, RunAttempt: first.RunAttempt, JobID: job.ID, Sources: projected,
	}, true
}

func projectRunnerMetadata(observations []logparse.Observation, job githubapi.WorkflowJob) (setupRunnerProjection, bool) {
	metadata := make([]runnerMetadataProjection, 0, 3)
	grammar := logparse.GrammarVersion
	for _, observation := range observations {
		if observation.Kind != logparse.ObservationRunnerMetadata {
			continue
		}
		if observation.Grammar != "" {
			grammar = observation.Grammar
		}
		attribute := safeMachine(observation.Attribute, 64)
		if attribute != "runner-version" && attribute != "runner-image" && attribute != "runner-os" {
			continue
		}
		value := safeField(observation.Value, 2048)
		if value == "" {
			continue
		}
		projected := runnerMetadataProjection{Attribute: attribute, Value: value, Line: max(0, observation.LineStart)}
		if observation.EventTime != nil && !observation.EventTime.IsZero() {
			projected.EventTime = observation.EventTime.UTC().Format(time.RFC3339Nano)
		}
		metadata = append(metadata, projected)
	}
	if len(metadata) == 0 {
		return setupRunnerProjection{}, false
	}
	sort.Slice(metadata, func(i, j int) bool {
		if metadata[i].Attribute != metadata[j].Attribute {
			return metadata[i].Attribute < metadata[j].Attribute
		}
		if metadata[i].Value != metadata[j].Value {
			return metadata[i].Value < metadata[j].Value
		}
		return metadata[i].Line < metadata[j].Line
	})
	return setupRunnerProjection{
		Schema: "cirewind.github-setup-runner-metadata/v1", Grammar: grammar,
		RepositoryID: observations[0].Scope.RepositoryID, RunID: observations[0].Scope.RunID,
		RunAttempt: observations[0].Scope.RunAttempt, JobID: job.ID, Metadata: metadata,
	}, true
}

func correlateSetupEntry(name string, jobs []githubapi.WorkflowJob) (githubapi.WorkflowJob, bool) {
	if path.Base(name) != "1_Set up job.txt" {
		return githubapi.WorkflowJob{}, false
	}
	if len(jobs) == 1 {
		return jobs[0], true
	}
	parent := path.Base(path.Dir(name))
	var matched githubapi.WorkflowJob
	count := 0
	for _, job := range jobs {
		if archiveJobLabelMatches(parent, job.Name) {
			matched, count = job, count+1
		}
	}
	return matched, count == 1
}

func setupStepConclusion(job githubapi.WorkflowJob) (string, string, bool) {
	var selected githubapi.JobStep
	count := 0
	for _, step := range job.Steps {
		if step.Name == "Set up job" {
			selected = step
			count++
		}
	}
	return selected.Status, selected.Conclusion, count == 1
}

func consolidatedSteps(job githubapi.WorkflowJob, historical *historicalAttempt) []logparse.ConsolidatedStep {
	steps := make([]logparse.ConsolidatedStep, 0, len(job.Steps))
	for _, step := range job.Steps {
		value := logparse.ConsolidatedStep{
			Number: step.Number, Name: step.Name, Status: step.Status, Conclusion: step.Conclusion,
			StartedAt: step.StartedAt, CompletedAt: step.CompletedAt,
		}
		if historical != nil {
			if binding, ok := historical.stepBinding(job.ID, step.Number); ok {
				value.ExpectedAction = binding.declaration
				value.HistoricalBound = true
			}
		}
		steps = append(steps, value)
	}
	return steps
}

func exactAPIStep(job githubapi.WorkflowJob, number int) (githubapi.JobStep, bool) {
	var selected githubapi.JobStep
	count := 0
	for _, step := range job.Steps {
		if step.Number == number {
			selected = step
			count++
		}
	}
	return selected, count == 1
}

func convertSetupObservations(observations []setupObservation, job githubapi.WorkflowJob, result *repositoryResult) error {
	if len(observations) == 0 {
		return nil
	}
	first := observations[0].observation
	execution := model.JobExecutionIdentity{RepositoryID: model.RepositoryID(first.Scope.RepositoryID), RunID: model.WorkflowRunID(first.Scope.RunID), RunAttempt: model.RunAttempt(first.Scope.RunAttempt), JobID: model.JobID(job.ID)}
	for _, item := range observations {
		observation := item.observation
		evidenceIDs := model.SortEvidenceIDs(item.evidenceIDs)
		event := logEventTime(observation.EventTime)
		switch observation.Kind {
		case logparse.ObservationResolution, logparse.ObservationDownloadAnnounced, logparse.ObservationPreparationComplete, logparse.ObservationPreparationFailed:
			if observation.Action == nil {
				continue
			}
			runtime, err := runtimeObservation(execution, observation, evidenceIDs, event, nil)
			if err != nil {
				if gapErr := appendGap(result, collect.Gap{
					Reason: collect.GapValidation, Scope: "setup_parser", RepositoryID: observation.Scope.RepositoryID,
					RunID: observation.Scope.RunID, Attempt: observation.Scope.RunAttempt, JobID: job.ID,
					Material: true, Diagnostic: "setup record contained an Action identity that could not be normalized",
				}); gapErr != nil {
					return gapErr
				}
				continue
			}
			result.facts = append(result.facts, archive.Fact{Kind: archive.FactActionOccurrence, EvidenceIDs: evidenceIDs, ActionOccurrence: &archive.ActionOccurrenceFact{Observation: runtime}})
			result.actionFacts++
		case logparse.ObservationTokenPermission:
			permission := safeMachine(strings.ToLower(observation.Permission), 128)
			access := strings.ToLower(observation.Access)
			if permission == "" || permission == "unknown" || (access != "read" && access != "write" && access != "none") {
				continue
			}
			if permission == "id-token" {
				if access != "write" {
					continue
				}
				oidc := model.CredentialExposure{Kind: model.ExposureOIDCMintingCapability, Basis: model.ExposureBasisRuntimeObserved, Conclusion: "The job could request a GitHub OIDC token; this does not prove token minting, compatible cloud trust, token exchange, or cloud-role assumption.", EvidenceIDs: evidenceIDs}
				result.facts = append(result.facts, archive.Fact{Kind: archive.FactExposure, EvidenceIDs: evidenceIDs, Exposure: &archive.ExposureFact{Execution: execution, Credential: &oidc, EventTime: event}})
				result.permissionFacts++
				continue
			}
			credential := model.CredentialExposure{Kind: model.ExposureGitHubTokenPermission, Basis: model.ExposureBasisRuntimeObserved, Permission: permission, Access: access, Conclusion: "Effective GITHUB_TOKEN permission was observed in the runner-owned setup record; this capability does not prove the permission was exercised.", EvidenceIDs: evidenceIDs}
			result.facts = append(result.facts, archive.Fact{Kind: archive.FactExposure, EvidenceIDs: evidenceIDs, Exposure: &archive.ExposureFact{Execution: execution, Credential: &credential, EventTime: event}})
			result.permissionFacts++
		case logparse.ObservationRunnerMetadata:
			// Exact metadata remains represented by the entry evidence hash. The
			// archive runner fact is sourced from stable job API fields; parser
			// strings are not overloaded into unrelated runner columns.
		}
	}
	return nil
}

func runtimeObservation(execution model.JobExecutionIdentity, parsed logparse.Observation, sourceEvidence []model.EvidenceID, event model.EventInterval, step *model.StepIdentity) (model.RuntimeActionObservation, error) {
	kind := model.ObservationResolutionObserved
	switch parsed.Kind {
	case logparse.ObservationResolution:
		kind = model.ObservationResolutionObserved
	case logparse.ObservationDownloadAnnounced:
		kind = model.ObservationDownloadAnnounced
	case logparse.ObservationPreparationComplete:
		kind = model.ObservationPreparationComplete
	case logparse.ObservationPreparationFailed:
		kind = model.ObservationPreparationFailed
	case logparse.ObservationLifecycleStarted:
		kind = model.ObservationLifecycleStarted
	case logparse.ObservationLifecycleCompleted:
		kind = model.ObservationLifecycleCompleted
	default:
		return model.RuntimeActionObservation{}, fmt.Errorf("unsupported runtime observation kind %q", parsed.Kind)
	}
	slug, err := model.NewRepositorySlug(parsed.Action.Owner + "/" + parsed.Action.Repository)
	if err != nil {
		return model.RuntimeActionObservation{}, err
	}
	var sourceObject *model.ActionSourceObjectID
	if parsed.Action.Source.Value != "" {
		gitID, err := model.NewGitObjectID(model.HashAlgorithm(parsed.Action.Source.Algorithm), strings.ToLower(parsed.Action.Source.Value))
		if err != nil {
			return model.RuntimeActionObservation{}, err
		}
		value, err := model.NewActionSourceObjectID(gitID)
		if err != nil {
			return model.RuntimeActionObservation{}, err
		}
		sourceObject = &value
	}
	var digest *model.PackageDigest
	if parsed.Action.Digest.Value != "" {
		value, err := model.NewPackageDigest(model.DigestSubject(parsed.Action.Digest.Subject), model.HashAlgorithm(parsed.Action.Digest.Algorithm), strings.ToLower(parsed.Action.Digest.Value))
		if err != nil {
			return model.RuntimeActionObservation{}, err
		}
		digest = &value
	}
	observation := model.RuntimeActionObservation{
		ID: model.RuntimeObservationID("rtobs1:" + strings.Repeat("0", 64)), Kind: kind, Execution: execution,
		Step:             step,
		ActionRepository: slug, ActionSubpath: parsed.Action.Subpath, DeclaredRef: safeField(parsed.Action.Ref, 1024),
		SourceObjectID: sourceObject, PackageDigest: digest, ImmutableVersion: safeField(parsed.Action.Version, 256),
		EventTime: event, SourceEvidenceIDs: model.SortEvidenceIDs(sourceEvidence),
		SourceSpan:    model.SourceSpan{LineStart: uint64(max(0, parsed.LineStart)), LineEnd: uint64(max(0, parsed.LineEnd))},
		ExtractorName: "github-runner-setup", ExtractorVersion: ExtractorVersion, RulesetSHA256: extractorRulesetSHA256,
	}
	if kind == model.ObservationLifecycleStarted || kind == model.ObservationLifecycleCompleted {
		observation.ExtractorName = "github-runner-action-step"
	}
	id, err := evidence.NewRuntimeObservationID(observation)
	if err != nil {
		return model.RuntimeActionObservation{}, err
	}
	observation.ID = id
	return observation, observation.Validate()
}

func logEventTime(value *time.Time) model.EventInterval {
	if value == nil || value.IsZero() {
		return unknownTime()
	}
	instant := model.MustInstant(*value)
	return model.EventInterval{Start: &instant, Precision: model.PrecisionSecond, Approximation: model.ApproximationExact, Basis: model.TimeBasisLogTimestamp}
}

type boundedFileHashWriter struct {
	file  *os.File
	hash  io.Writer
	limit int64
	count int64
}

func (w *boundedFileHashWriter) Write(p []byte) (int, error) {
	remaining := w.limit - w.count
	if remaining <= 0 {
		return 0, fmt.Errorf("attempt log exceeded adapter byte limit")
	}
	exceeded := int64(len(p)) > remaining
	if int64(len(p)) > remaining {
		p = p[:remaining]
	}
	written, fileErr := w.file.Write(p)
	if written > 0 {
		if hashWritten, hashErr := w.hash.Write(p[:written]); hashErr != nil || hashWritten != written {
			if hashErr != nil {
				return written, hashErr
			}
			return written, io.ErrShortWrite
		}
		w.count += int64(written)
	}
	if fileErr != nil {
		return written, fileErr
	}
	if int64(written) < int64(len(p)) {
		return written, io.ErrShortWrite
	}
	if exceeded {
		return written, fmt.Errorf("attempt log exceeded adapter byte limit")
	}
	return written, nil
}
