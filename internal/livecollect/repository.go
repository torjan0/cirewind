package livecollect

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/torjan0/cirewind/internal/archive"
	"github.com/torjan0/cirewind/internal/collect"
	"github.com/torjan0/cirewind/internal/evidence"
	"github.com/torjan0/cirewind/internal/githubapi"
	"github.com/torjan0/cirewind/internal/logparse"
	"github.com/torjan0/cirewind/internal/model"
)

func (c Collector) collectRepository(ctx context.Context, request Request, discovery collect.Interval, target repositoryWork, sessionID model.CollectionSessionID, now Clock, limits logparse.ArchiveLimits) (repositoryResult, error) {
	result := repositoryResult{facts: []archive.Fact{}, payloads: []archive.Payload{}, evidence: []evidence.Envelope{}, gaps: []collect.Gap{}, called: []CalledWorkflowObservation{}}
	repositoryID := model.RepositoryID(target.repository.ID)
	hashAlgorithm := ""
	hashStarted := model.MustInstant(now().UTC())
	hashResult, hashErr := c.API.GetRepositoryHashAlgorithm(ctx, target.owner, target.name)
	hashEnded := model.MustInstant(now().UTC())
	if hashErr != nil {
		gap := collect.GapFromError("repository_hash_algorithm", target.repository.ID, 0, 0, hashErr)
		if err := appendGap(&result, gap); err != nil {
			return result, err
		}
	} else if hashResult.Value != "sha1" && hashResult.Value != "sha256" {
		if err := appendGap(&result, collect.Gap{Reason: collect.GapMalformedResponse, Scope: "repository_hash_algorithm", RepositoryID: target.repository.ID, Material: true, Diagnostic: "GitHub returned an unsupported repository hash algorithm"}); err != nil {
			return result, err
		}
	} else {
		hashAlgorithm = hashResult.Value
		payload, envelope, err := compactEnvelope(sessionID, requestID("hash-algorithm", fmt.Sprint(target.repository.ID)), "normalized:github:repository-hash-algorithm:"+fmt.Sprint(target.repository.ID), evidence.SourceAPIJSON, githubapi.APIVersion, "/repos/{owner}/{repo}/hash-algorithm", evidence.RequestParameters{"owner": target.owner, "repo": target.name}, model.CoverageScope{RepositoryID: &repositoryID}, struct {
			Schema       string               `json:"schema"`
			RepositoryID int64                `json:"repository_id"`
			Algorithm    string               `json:"algorithm"`
			Responses    []responseProjection `json:"responses"`
		}{"cirewind.github-repository-hash-projection/v1", target.repository.ID, hashAlgorithm, projectResponses(hashResult.Responses)}, hashStarted, hashEnded)
		if err != nil {
			return result, err
		}
		result.payloads, result.evidence = append(result.payloads, payload), append(result.evidence, envelope)
	}

	schedule := scheduleRepository(request, discovery, repositoryID)
	parentWindow := schedule.parentWindow
	partitioner := collect.Partitioner{API: c.API, MaxPartitions: request.MaxPartitions, MinBucket: time.Second}
	partitionStarted := model.MustInstant(now().UTC())
	partition, err := partitioner.Enumerate(ctx, collect.RepositoryTarget{ID: target.repository.ID, Owner: target.owner, Name: target.name}, parentWindow)
	partitionEnded := model.MustInstant(now().UTC())
	if err != nil && ctx.Err() != nil {
		return result, ctx.Err()
	}
	partitionComplete := true
	for _, gap := range partition.Gaps {
		if gap.Material {
			partitionComplete = false
		}
		if appendErr := appendGap(&result, gap); appendErr != nil {
			return result, appendErr
		}
	}
	if err != nil {
		return result, err
	}
	parentEvent := *collectionEventWindow(parentWindow, true)
	partitionPayload, partitionEvidence, partitionErr := compactEnvelopeAt(sessionID, requestID("run-partition", fmt.Sprint(target.repository.ID), parentWindow.From.UTC().Format(time.RFC3339Nano), parentWindow.To.UTC().Format(time.RFC3339Nano)), "normalized:github:workflow-run-partition:"+fmt.Sprint(target.repository.ID)+":"+safeKey(parentWindow.From.UTC().Format(time.RFC3339Nano)+"/"+parentWindow.To.UTC().Format(time.RFC3339Nano)), evidence.SourceAPIJSON, githubapi.APIVersion, "/repos/{owner}/{repo}/actions/runs", evidence.RequestParameters{"owner": target.owner, "repo": target.name, "requested_from": parentWindow.From.UTC().Format(time.RFC3339Nano), "requested_to": parentWindow.To.UTC().Format(time.RFC3339Nano), "strategy": string(schedule.basis)}, model.CoverageScope{RepositoryID: &repositoryID}, parentEvent, projectRunPartition(target.repository.ID, partition), partitionStarted, partitionEnded)
	if partitionErr != nil {
		return result, partitionErr
	}
	result.payloads, result.evidence = append(result.payloads, partitionPayload), append(result.evidence, partitionEvidence)
	if partitionComplete {
		if err := appendCollectedCoverage(&result, model.CoverageRunPartition, model.CoverageScope{RepositoryID: &repositoryID}, coverageLogicalKey("run_partition", target.repository.ID, 0, 0, 0), uint64(len(partition.Runs)), []model.EvidenceID{partitionEvidence.Evidence.ID}, true); err != nil {
			return result, err
		}
	}

	parents := make(map[int64]archive.WatchedParent, len(schedule.retainedByRunID)+len(partition.Runs))
	for runID, parent := range schedule.retainedByRunID {
		parents[runID] = parent
	}
	requiredRefresh := make(map[int64]collect.WatchedRun, len(schedule.requiredRefresh))
	for _, watched := range schedule.requiredRefresh {
		requiredRefresh[watched.RunID] = watched
	}
	processed := make(map[int64]struct{}, len(partition.Runs)+len(schedule.requiredRefresh))
	checkpointComplete := partitionComplete
	if schedule.continuityGap != nil {
		checkpointComplete = false
		if err := appendGap(&result, collect.Gap{
			Reason: collect.GapValidation, Scope: "archive_checkpoint_continuity", RepositoryID: target.repository.ID,
			Material: true, Retryable: true,
			Diagnostic: "the requested --since window begins after the prior archive watermark; extend --since to close the uncollected parent-run interval",
		}); err != nil {
			return result, err
		}
	}
	for _, run := range partition.Runs {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		if watched, required := requiredRefresh[run.ID]; required && !watched.CreatedAt.Equal(run.CreatedAt) {
			checkpointComplete = false
			if err := appendGap(&result, collect.Gap{Reason: collect.GapMalformedResponse, Scope: "watched_parent_refresh", RepositoryID: target.repository.ID, RunID: run.ID, Material: true, Diagnostic: "refreshed parent creation time contradicted the archive checkpoint"}); err != nil {
				return result, err
			}
		}
		parent, complete, collectErr := c.collectParentRun(ctx, request, target, hashAlgorithm, run, sessionID, now, limits, &result, parentRunSource{
			requestKind: "run", logicalSuffix: "partition", route: "/repos/{owner}/{repo}/actions/runs",
			parameters:  evidence.RequestParameters{"owner": target.owner, "repo": target.name, "created": partitionFilterForRun(partition.Root, run.CreatedAt), "per_page": "100"},
			evidenceIDs: []model.EvidenceID{partitionEvidence.Evidence.ID}, projection: projectRun(target.repository.ID, run),
		})
		if collectErr != nil {
			return result, collectErr
		}
		processed[run.ID] = struct{}{}
		if parent.RunID > 0 {
			parents[run.ID] = parent
		}
		if !complete {
			checkpointComplete = false
		}
	}
	for _, watched := range schedule.requiredRefresh {
		if _, alreadyProcessed := processed[watched.RunID]; alreadyProcessed {
			continue
		}
		refreshStarted := model.MustInstant(now().UTC())
		fetched, fetchErr := c.API.GetWorkflowRun(ctx, target.owner, target.name, watched.RunID)
		refreshEnded := model.MustInstant(now().UTC())
		if fetchErr != nil {
			checkpointComplete = false
			if err := appendGap(&result, collect.GapFromError("watched_parent_refresh", target.repository.ID, watched.RunID, 0, fetchErr)); err != nil {
				return result, err
			}
			if ctx.Err() != nil {
				return result, ctx.Err()
			}
			continue
		}
		run := fetched.Value
		if run.ID != watched.RunID || !run.CreatedAt.Equal(watched.CreatedAt) {
			checkpointComplete = false
			if err := appendGap(&result, collect.Gap{Reason: collect.GapMalformedResponse, Scope: "watched_parent_refresh", RepositoryID: target.repository.ID, RunID: watched.RunID, Material: true, Diagnostic: "refreshed parent identity contradicted the archive checkpoint"}); err != nil {
				return result, err
			}
			continue
		}
		parent, complete, collectErr := c.collectParentRun(ctx, request, target, hashAlgorithm, run, sessionID, now, limits, &result, parentRunSource{
			requestKind: "watched-run", logicalSuffix: "watch", route: "/repos/{owner}/{repo}/actions/runs/{run_id}",
			parameters: evidence.RequestParameters{"owner": target.owner, "repo": target.name, "run_id": fmt.Sprint(watched.RunID), "strategy": "provisional-65-day-watch-refresh"},
			projection: struct {
				Schema    string                `json:"schema"`
				Run       runProjectionDocument `json:"run"`
				Responses []responseProjection  `json:"responses"`
			}{"cirewind.github-watched-run-refresh/v1", projectRun(target.repository.ID, run), projectResponses(fetched.Responses)},
			startedAt: refreshStarted, endedAt: refreshEnded,
		})
		if collectErr != nil {
			return result, collectErr
		}
		if parent.RunID > 0 {
			parents[watched.RunID] = parent
		}
		if !complete {
			checkpointComplete = false
		}
	}
	if schedule.writeCheckpoint && checkpointComplete {
		watermark := model.MustInstant(request.Interval.To.UTC())
		result.checkpoint = &archive.Checkpoint{
			RepositoryID: repositoryID, DiscoveryWatermark: &watermark,
			OverlapSeconds: uint32(collect.DefaultArchiveOverlap / time.Second), WatchHorizonDays: uint32(collect.ProvisionalParentLookback / (24 * time.Hour)),
			LastSuccessfulCollection: sessionID, WatchedParents: sortedWatchedParents(parents),
		}
	}
	if err := c.collectRepositoryEnrichments(ctx, target, sessionID, now, &result); err != nil {
		return result, err
	}
	return result, nil
}

type parentRunSource struct {
	requestKind   string
	logicalSuffix string
	route         string
	parameters    evidence.RequestParameters
	evidenceIDs   []model.EvidenceID
	projection    any
	startedAt     model.Instant
	endedAt       model.Instant
}

func (c Collector) collectParentRun(ctx context.Context, request Request, target repositoryWork, hashAlgorithm string, run githubapi.WorkflowRun, sessionID model.CollectionSessionID, now Clock, limits logparse.ArchiveLimits, result *repositoryResult, source parentRunSource) (archive.WatchedParent, bool, error) {
	created, event, eventErr := apiInstant(run.CreatedAt)
	if eventErr != nil || run.ID <= 0 {
		return archive.WatchedParent{}, false, appendGap(result, collect.Gap{Reason: collect.GapMalformedResponse, Scope: "workflow_run", RepositoryID: target.repository.ID, RunID: run.ID, Material: true, Diagnostic: "workflow run omitted a valid identity or created_at"})
	}
	workflowPath, pathErr := workflowPath(run.Path)
	if pathErr != nil {
		if err := appendGap(result, collect.Gap{Reason: collect.GapMalformedResponse, Scope: "historical_workflow", RepositoryID: target.repository.ID, RunID: run.ID, Material: true, Diagnostic: "workflow run path could not be normalized"}); err != nil {
			return archive.WatchedParent{}, false, err
		}
	}
	if source.startedAt.Time.IsZero() {
		source.startedAt = model.MustInstant(now().UTC())
	}
	if source.endedAt.Time.IsZero() {
		source.endedAt = model.MustInstant(now().UTC())
	}
	repositoryID := model.RepositoryID(target.repository.ID)
	payload, runEvidence, err := compactEnvelopeAt(sessionID, requestID(source.requestKind, fmt.Sprint(target.repository.ID), fmt.Sprint(run.ID)), "normalized:github:workflow-run:"+fmt.Sprint(target.repository.ID)+":"+fmt.Sprint(run.ID)+":"+source.logicalSuffix, evidence.SourceAPIJSON, githubapi.APIVersion, source.route, source.parameters, model.CoverageScope{RepositoryID: &repositoryID}, event, source.projection, source.startedAt, source.endedAt)
	if err != nil {
		return archive.WatchedParent{}, false, err
	}
	result.payloads, result.evidence = append(result.payloads, payload), append(result.evidence, runEvidence)
	var trigger *model.TriggerObjectID
	if object, ok := typedGitObject(hashAlgorithm, run.HeadSHA); ok {
		value, objectErr := model.NewTriggerObjectID(object)
		if objectErr == nil {
			trigger = &value
		}
	}
	runEvidenceIDs := append(append([]model.EvidenceID(nil), source.evidenceIDs...), runEvidence.Evidence.ID)
	runEvidenceIDs = model.SortEvidenceIDs(runEvidenceIDs)
	result.facts = append(result.facts, archive.Fact{Kind: archive.FactRun, EvidenceIDs: runEvidenceIDs, Run: &archive.RunFact{
		RepositoryID: repositoryID, RunID: model.WorkflowRunID(run.ID), WorkflowPath: workflowPath,
		EventType: nonemptyMachine(run.Event), Status: safeMachine(run.Status, 128), Conclusion: safeMachine(run.Conclusion, 128),
		TriggerObject: trigger, TriggerRef: safeField(run.HeadBranch, 1024), Actor: actorFact(run.Actor), EventTime: event,
	}})

	attempts := collect.AttemptCollector{API: c.API, MaxStabilizationPasses: 3}
	snapshot, snapshotErr := attempts.Snapshot(ctx, collect.RepositoryTarget{ID: target.repository.ID, Owner: target.owner, Name: target.name}, run.ID)
	complete := snapshot.Stable
	for _, gap := range snapshot.Gaps {
		if gap.Material {
			complete = false
		}
		if appendErr := appendGap(result, gap); appendErr != nil {
			return archive.WatchedParent{}, false, appendErr
		}
	}
	if snapshotErr != nil && ctx.Err() != nil {
		return archive.WatchedParent{}, false, ctx.Err()
	}
	if snapshotErr != nil {
		return archive.WatchedParent{}, false, snapshotErr
	}
	for _, attempt := range snapshot.Attempts {
		if err := c.collectAttempt(ctx, request, target, hashAlgorithm, workflowPath, run, attempt, sessionID, now, limits, result); err != nil {
			return archive.WatchedParent{}, false, err
		}
	}
	refreshed := model.MustInstant(now().UTC())
	parent := archive.WatchedParent{
		RunID: model.WorkflowRunID(run.ID), CreatedAt: created, LastRefreshedAt: &refreshed,
		FinalRefreshComplete: complete && !run.CreatedAt.Add(collect.ProvisionalParentLookback).After(refreshed.Time),
	}
	return parent, complete, nil
}

func (c Collector) collectAttempt(ctx context.Context, request Request, target repositoryWork, hashAlgorithm string, callerPath *model.WorkflowPath, parent githubapi.WorkflowRun, bundle collect.AttemptBundle, sessionID model.CollectionSessionID, now Clock, limits logparse.ArchiveLimits, result *repositoryResult) error {
	repositoryID := model.RepositoryID(target.repository.ID)
	runID := model.WorkflowRunID(parent.ID)
	attemptNumber := model.RunAttempt(bundle.Attempt)
	scope := model.CoverageScope{RepositoryID: &repositoryID, RunID: &runID, RunAttempt: &attemptNumber}
	event := runAttemptEvent(bundle.Run)
	started := model.MustInstant(now().UTC())
	payload, attemptEvidence, err := compactEnvelopeAt(sessionID, requestID("attempt", fmt.Sprint(target.repository.ID), fmt.Sprint(parent.ID), fmt.Sprint(bundle.Attempt)), fmt.Sprintf("normalized:github:workflow-run-attempt:%d:%d:%d", target.repository.ID, parent.ID, bundle.Attempt), evidence.SourceAPIJSON, githubapi.APIVersion, "/repos/{owner}/{repo}/actions/runs/{run_id}/attempts/{attempt_number}", evidence.RequestParameters{"owner": target.owner, "repo": target.name, "run_id": fmt.Sprint(parent.ID), "attempt_number": fmt.Sprint(bundle.Attempt)}, scope, event, projectAttempt(target.repository.ID, bundle), started, model.MustInstant(now().UTC()))
	if err != nil {
		return err
	}
	result.payloads, result.evidence = append(result.payloads, payload), append(result.evidence, attemptEvidence)
	if err := appendCollectedCoverage(result, model.CoverageRunAttempt, scope, coverageLogicalKey("workflow_run_attempt", target.repository.ID, parent.ID, bundle.Attempt, 0), 1, []model.EvidenceID{attemptEvidence.Evidence.ID}, true); err != nil {
		return err
	}
	result.facts = append(result.facts, archive.Fact{Kind: archive.FactAttempt, EvidenceIDs: []model.EvidenceID{attemptEvidence.Evidence.ID}, Attempt: &archive.AttemptFact{
		RepositoryID: repositoryID, RunID: runID, RunAttempt: attemptNumber,
		Status: safeMachine(bundle.Run.Status, 128), Conclusion: safeMachine(bundle.Run.Conclusion, 128),
		Actor: actorFact(bundle.Run.Actor), TriggeringActor: actorFact(bundle.Run.TriggeringActor), EventTime: event,
	}})

	jobsByID := make(map[int64]githubapi.WorkflowJob, len(bundle.Jobs))
	jobEvidenceByID := make(map[int64]model.EvidenceID, len(bundle.Jobs))
	for _, job := range bundle.Jobs {
		jobsByID[job.ID] = job
		jobID := model.JobID(job.ID)
		jobScope := model.CoverageScope{RepositoryID: &repositoryID, RunID: &runID, RunAttempt: &attemptNumber, JobID: &jobID}
		jobEvent := jobEventTime(job)
		jobStarted := model.MustInstant(now().UTC())
		jobPayload, jobEnvelope, buildErr := compactEnvelopeAt(sessionID, requestID("job", fmt.Sprint(target.repository.ID), fmt.Sprint(parent.ID), fmt.Sprint(bundle.Attempt), fmt.Sprint(job.ID)), fmt.Sprintf("normalized:github:workflow-job:%d:%d:%d:%d", target.repository.ID, parent.ID, bundle.Attempt, job.ID), evidence.SourceAPIJSON, githubapi.APIVersion, "/repos/{owner}/{repo}/actions/runs/{run_id}/attempts/{attempt_number}/jobs", evidence.RequestParameters{"owner": target.owner, "repo": target.name, "run_id": fmt.Sprint(parent.ID), "attempt_number": fmt.Sprint(bundle.Attempt), "job_id": fmt.Sprint(job.ID)}, jobScope, jobEvent, projectJob(target.repository.ID, parent.ID, bundle.Attempt, job), jobStarted, model.MustInstant(now().UTC()))
		if buildErr != nil {
			return buildErr
		}
		result.payloads, result.evidence = append(result.payloads, jobPayload), append(result.evidence, jobEnvelope)
		jobEvidenceByID[job.ID] = jobEnvelope.Evidence.ID
		if err := appendCollectedCoverage(result, model.CoverageJob, jobScope, coverageLogicalKey("attempt_job", target.repository.ID, parent.ID, bundle.Attempt, job.ID), 1, []model.EvidenceID{jobEnvelope.Evidence.ID}, true); err != nil {
			return err
		}
		execution := model.JobExecutionIdentity{RepositoryID: repositoryID, RunID: runID, RunAttempt: attemptNumber, JobID: jobID}
		name := safeField(job.Name, 4096)
		if name == "" {
			name = "[unnamed job]"
		}
		result.facts = append(result.facts,
			archive.Fact{Kind: archive.FactJob, EvidenceIDs: []model.EvidenceID{jobEnvelope.Evidence.ID}, Job: &archive.JobFact{Execution: execution, DisplayName: name, Status: safeMachine(job.Status, 128), Conclusion: safeMachine(job.Conclusion, 128), EventTime: jobEvent}},
			archive.Fact{Kind: archive.FactExposure, EvidenceIDs: []model.EvidenceID{jobEnvelope.Evidence.ID}, Exposure: &archive.ExposureFact{Execution: execution, Runner: runnerFact(job), EventTime: jobEvent}},
		)
		result.runnerFacts++
		if err := c.downloadJobLog(ctx, request, target, parent.ID, bundle.Attempt, job, sessionID, now, jobEvent, result); err != nil {
			return err
		}
	}

	if err := c.downloadAndParseAttempt(ctx, request, target, parent, parent.ID, bundle, hashAlgorithm, sessionID, attemptEvidence.Evidence.ID, now, limits, jobsByID, jobEvidenceByID, result); err != nil {
		return err
	}
	return nil
}

func (c Collector) downloadJobLog(ctx context.Context, request Request, target repositoryWork, runID int64, attempt int, job githubapi.WorkflowJob, sessionID model.CollectionSessionID, now Clock, event model.EventInterval, result *repositoryResult) error {
	hasher := sha256.New()
	var writer io.Writer
	var byteCount func() int64
	var transient *os.File
	transientPath := ""
	keepForSink := false
	defer func() {
		if transientPath != "" && !keepForSink {
			_ = os.Remove(transientPath)
		}
	}()
	if request.RawRetention {
		var createErr error
		transient, createErr = os.CreateTemp(c.TempDir, "cirewind-job-log-*.txt")
		if createErr != nil {
			return appendGap(result, collect.Gap{Reason: collect.GapLocalIO, Scope: "job_log", RepositoryID: target.repository.ID, RunID: runID, Attempt: attempt, JobID: job.ID, Material: true, Diagnostic: "could not create an owner-only transient job-log file"})
		}
		transientPath = transient.Name()
		if chmodErr := transient.Chmod(0o600); chmodErr != nil {
			_ = transient.Close()
			return appendGap(result, collect.Gap{Reason: collect.GapLocalIO, Scope: "job_log", RepositoryID: target.repository.ID, RunID: runID, Attempt: attempt, JobID: job.ID, Material: true, Diagnostic: "could not restrict transient job-log permissions"})
		}
		bounded := &boundedFileHashWriter{file: transient, hash: hasher, limit: request.MaxJobLogBytes}
		writer = bounded
		byteCount = func() int64 { return bounded.count }
	} else {
		bounded := &boundedHashWriter{hash: hasher, limit: request.MaxJobLogBytes}
		writer = bounded
		byteCount = func() int64 { return bounded.count }
	}
	started := model.MustInstant(now().UTC())
	download, err := c.API.DownloadJobLogs(ctx, target.owner, target.name, job.ID, writer)
	ended := model.MustInstant(now().UTC())
	var closeErr error
	if transient != nil {
		closeErr = transient.Close()
	}
	count := byteCount()
	if err != nil || closeErr != nil {
		gap := collect.GapFromError("job_log", target.repository.ID, runID, attempt, err)
		gap.JobID = job.ID
		if err == nil {
			gap = collect.Gap{Reason: collect.GapLocalIO, Scope: "job_log", RepositoryID: target.repository.ID, RunID: runID, Attempt: attempt, JobID: job.ID, Material: true, Diagnostic: "could not close the transient job-log file"}
		} else if count >= request.MaxJobLogBytes {
			gap.Reason = collect.GapSizeLimit
			gap.Material = true
			gap.Diagnostic = "job log exceeded the adapter byte limit and was discarded"
		}
		return appendGap(result, gap)
	}
	localSHA := hex.EncodeToString(hasher.Sum(nil))
	repositoryID, typedRun, typedAttempt, jobID := model.RepositoryID(target.repository.ID), model.WorkflowRunID(runID), model.RunAttempt(attempt), model.JobID(job.ID)
	envelope, envelopeErr := logEnvelope(sessionID, requestID("job-log", fmt.Sprint(target.repository.ID), fmt.Sprint(runID), fmt.Sprint(attempt), fmt.Sprint(job.ID)), fmt.Sprintf("github:job-log:%d:%d:%d:%d", target.repository.ID, runID, attempt, job.ID), evidence.SourceJobLog, "/repos/{owner}/{repo}/actions/jobs/{job_id}/logs", evidence.RequestParameters{"owner": target.owner, "repo": target.name, "job_id": fmt.Sprint(job.ID), "run_id": fmt.Sprint(runID), "attempt_number": fmt.Sprint(attempt)}, model.CoverageScope{RepositoryID: &repositoryID, RunID: &typedRun, RunAttempt: &typedAttempt, JobID: &jobID}, event, download, uint64(count), localSHA, request.RawRetention, started, ended)
	if envelopeErr != nil {
		return appendGap(result, collect.Gap{Reason: collect.GapMalformedResponse, Scope: "job_log", RepositoryID: target.repository.ID, RunID: runID, Attempt: attempt, JobID: job.ID, Material: true, Diagnostic: "download metadata did not match the bytes streamed to the discard sink"})
	}
	result.evidence = append(result.evidence, envelope)
	if request.RawRetention {
		result.rawInputs = append(result.rawInputs, archive.RawInput{SHA256: localSHA, MediaType: envelope.Evidence.Content.MediaType, ByteLength: uint64(count), SourcePath: transientPath})
		result.rawLogs++
		keepForSink = true
	}
	if err := appendCollectedCoverage(result, model.CoverageJobLog, model.CoverageScope{RepositoryID: &repositoryID, RunID: &typedRun, RunAttempt: &typedAttempt, JobID: &jobID}, coverageLogicalKey("job_log", target.repository.ID, runID, attempt, job.ID), 1, []model.EvidenceID{envelope.Evidence.ID}, true); err != nil {
		return err
	}
	result.jobLogs++
	return nil
}

type boundedHashWriter struct {
	hash  io.Writer
	limit int64
	count int64
}

func (w *boundedHashWriter) Write(p []byte) (int, error) {
	remaining := w.limit - w.count
	if remaining <= 0 {
		return 0, fmt.Errorf("log exceeded adapter byte limit")
	}
	if int64(len(p)) > remaining {
		written, err := w.hash.Write(p[:remaining])
		w.count += int64(written)
		if err != nil {
			return written, err
		}
		return written, fmt.Errorf("log exceeded adapter byte limit")
	}
	written, err := w.hash.Write(p)
	w.count += int64(written)
	return written, err
}

func actorFact(actor githubapi.Actor) archive.ActorFact {
	result := archive.ActorFact{Login: safeField(actor.Login, 256)}
	if actor.ID > 0 {
		id := model.ActorID(actor.ID)
		result.ID = &id
	}
	return result
}

func runnerFact(job githubapi.WorkflowJob) *archive.RunnerContextFact {
	classification := "unknown"
	for _, label := range job.Labels {
		switch strings.ToLower(label) {
		case "self-hosted":
			classification = "self-hosted"
		case "github-hosted":
			if classification == "unknown" {
				classification = "github-hosted"
			}
		}
	}
	// GitHub.com's hosted fleet currently supplies an API-controlled sentinel
	// group (ID 0), group name, and runner name derived from the numeric runner
	// ID even though the job label list need not include "github-hosted". Require
	// the complete tuple so a familiar ubuntu-* label or attacker-chosen name is
	// never sufficient on its own. Explicit self-hosted labels always win.
	if classification == "unknown" && job.RunnerID > 0 && job.RunnerGroupID == 0 &&
		job.RunnerGroupName == "GitHub Actions" && job.RunnerName == fmt.Sprintf("GitHub Actions %d", job.RunnerID) {
		classification = "github-hosted"
	}
	result := &archive.RunnerContextFact{Classification: classification, RunnerName: safeField(job.RunnerName, 1024), RunnerGroup: safeField(job.RunnerGroupName, 1024), Labels: safeStrings(job.Labels, 256, 256)}
	if job.RunnerID > 0 {
		id := job.RunnerID
		result.RunnerID = &id
	}
	return result
}

func apiInstant(value time.Time) (model.Instant, model.EventInterval, error) {
	instant, err := model.NewInstant(value)
	if err != nil {
		return model.Instant{}, unknownTime(), err
	}
	return instant, model.EventInterval{Start: &instant, Precision: model.PrecisionSecond, Approximation: model.ApproximationExact, Basis: model.TimeBasisAPIField}, nil
}

func runAttemptEvent(run githubapi.WorkflowRun) model.EventInterval {
	if run.RunStartedAt != nil && !run.RunStartedAt.IsZero() {
		_, event, err := apiInstant(*run.RunStartedAt)
		if err == nil {
			return event
		}
	}
	_, event, err := apiInstant(run.CreatedAt)
	if err == nil {
		return event
	}
	return unknownTime()
}

func jobEventTime(job githubapi.WorkflowJob) model.EventInterval {
	if job.StartedAt == nil || job.StartedAt.IsZero() {
		return unknownTime()
	}
	start := model.MustInstant(*job.StartedAt)
	if job.CompletedAt == nil || job.CompletedAt.IsZero() || job.CompletedAt.Before(*job.StartedAt) {
		return model.EventInterval{Start: &start, Precision: model.PrecisionSecond, Approximation: model.ApproximationExact, Basis: model.TimeBasisAPIField}
	}
	end := model.MustInstant(*job.CompletedAt)
	if end.Equal(start.Time) {
		bounds := model.BoundsClosed
		return model.EventInterval{Start: &start, End: &end, Bounds: &bounds, Precision: model.PrecisionSecond, Approximation: model.ApproximationExact, Basis: model.TimeBasisAPIField}
	}
	bounds := model.BoundsClosedOpen
	return model.EventInterval{Start: &start, End: &end, Bounds: &bounds, Precision: model.PrecisionSecond, Approximation: model.ApproximationExact, Basis: model.TimeBasisAPIField}
}

func typedGitObject(algorithm, value string) (model.GitObjectID, bool) {
	object, err := model.NewGitObjectID(model.HashAlgorithm(algorithm), strings.ToLower(value))
	return object, err == nil
}

func workflowPath(raw string) (*model.WorkflowPath, error) {
	value := safeField(raw, 4096)
	if marker := strings.Index(value, ".github/workflows/"); marker >= 0 {
		value = value[marker:]
	}
	if marker := strings.Index(value, ".yaml@"); marker >= 0 {
		value = value[:marker+5]
	} else if marker := strings.Index(value, ".yml@"); marker >= 0 {
		value = value[:marker+4]
	}
	path, err := model.NewWorkflowPath(value)
	if err != nil {
		return nil, err
	}
	return &path, nil
}

func nonemptyMachine(value string) string {
	value = safeMachine(value, 128)
	if value == "" {
		return "unknown"
	}
	return value
}
