package livecollect

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/torjan0/cirewind/internal/archive"
	"github.com/torjan0/cirewind/internal/collect"
	"github.com/torjan0/cirewind/internal/evidence"
	"github.com/torjan0/cirewind/internal/githubapi"
	"github.com/torjan0/cirewind/internal/logparse"
	"github.com/torjan0/cirewind/internal/model"
)

type repositoryWork struct {
	repository githubapi.Repository
	slug       model.RepositorySlug
	owner      string
	name       string
	evidenceID model.EvidenceID
}

type repositoryResult struct {
	facts                     []archive.Fact
	payloads                  []archive.Payload
	evidence                  []evidence.Envelope
	gaps                      []collect.Gap
	called                    []CalledWorkflowObservation
	checkpoint                *archive.Checkpoint
	jobLogs                   uint64
	attemptLogs               uint64
	actionFacts               uint64
	actionDefinitions         uint64
	workflowDefinitions       uint64
	callerWorkflowDefinitions uint64
	calledWorkflowDefinitions uint64
	lifecycleFacts            uint64
	permissionFacts           uint64
	staticPermissionFacts     uint64
	secretFlowFacts           uint64
	environmentFacts          uint64
	runnerFacts               uint64
	historicalGaps            uint64
	rawLogs                   uint64
	rawInputs                 []archive.RawInput
}

// Collect constructs a normalized, append-ready compact archive batch. API
// permission, retention, and parser failures are represented as gaps and do
// not abort other repositories. A returned non-nil error denotes invalid local
// configuration, cancellation, or an internal invariant failure.
func (c Collector) Collect(ctx context.Context, input Request) (Result, error) {
	if input.RawRetention {
		return Result{}, errors.New("raw retention requires CollectInto with a raw-capable archive sink")
	}
	return c.collect(ctx, input)
}

func (c Collector) collect(ctx context.Context, input Request) (Result, error) {
	request, err := c.defaults(input)
	if err != nil {
		return Result{}, err
	}
	limits := c.LogLimits
	if limits == (logparse.ArchiveLimits{}) {
		limits = logparse.DefaultArchiveLimits()
	}
	if err := limits.Validate(); err != nil {
		return Result{}, fmt.Errorf("workflow-log ZIP limits: %w", err)
	}
	discovery, err := collect.ExpandIncidentDiscoveryWindow(request.Interval)
	if err != nil {
		return Result{}, err
	}
	now := c.Now
	if now == nil {
		now = time.Now
	}
	started, initialTime, err := initialClockInstant(now)
	if err != nil {
		return Result{}, err
	}
	clock := newCheckedClock(now, initialTime)
	now = clock.Now
	sessionID, err := collectionSessionID(request, started)
	if err != nil {
		return Result{}, err
	}

	result := Result{Requested: request.Interval, Discovery: discovery, Gaps: []collect.Gap{}, CalledWorkflows: []CalledWorkflowObservation{}}
	targets, topPayloads, topEvidence, topFacts, topGaps, err := c.resolveRepositories(ctx, request, sessionID, started, now)
	result.Gaps = append(result.Gaps, topGaps...)
	if err != nil {
		return result, err
	}

	workResults := make([]repositoryResult, len(targets))
	workCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	indices := make(chan int)
	var workers sync.WaitGroup
	var firstErr error
	var errorMu sync.Mutex
	workerCount := min(request.Concurrency, max(1, len(targets)))
	for worker := 0; worker < workerCount; worker++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for index := range indices {
				collected, collectErr := c.collectRepository(workCtx, request, discovery, targets[index], sessionID, now, limits)
				workResults[index] = collected
				if collectErr != nil {
					errorMu.Lock()
					if firstErr == nil {
						firstErr = collectErr
						cancel()
					}
					errorMu.Unlock()
					return
				}
			}
		}()
	}
	feedDone := false
	for index := range targets {
		select {
		case indices <- index:
		case <-workCtx.Done():
			feedDone = true
		}
		if feedDone {
			break
		}
	}
	close(indices)
	workers.Wait()

	ended := model.MustInstant(now().UTC())
	if ended.Before(started.Time) {
		ended = started
	}
	if err := clock.Err(); err != nil {
		return result, err
	}
	repositoryIDs := make([]model.RepositoryID, 0, len(targets))
	for _, target := range targets {
		repositoryIDs = append(repositoryIDs, model.RepositoryID(target.repository.ID))
	}
	sort.Slice(repositoryIDs, func(i, j int) bool { return repositoryIDs[i] < repositoryIDs[j] })
	session := archive.CollectionSession{
		ID: sessionID, Mode: string(request.Purpose), APIVersion: githubapi.APIVersion, AuthKind: request.AuthKind,
		RawRetention: request.RawRetention,
		StartedAt:    started, EndedAt: ended,
		Scope: archive.CollectionScope{
			Organization: safeField(request.Organization, 256), Repositories: repositoryIDs,
			RequestedEventWindow: collectionEventWindow(request.Interval, false), DiscoveryEventWindow: collectionEventWindow(discovery, true),
		},
		Limits: map[string]uint64{
			"concurrency": uint64(request.Concurrency), "job_log_bytes": uint64(request.MaxJobLogBytes),
			"attempt_log_bytes": uint64(request.MaxAttemptLogBytes), "max_partitions": uint64(request.MaxPartitions),
			"watch_horizon_days": uint64(collect.ProvisionalParentLookback / (24 * time.Hour)),
		},
	}
	batch := archive.Batch{
		Collections: []archive.CollectionSession{session}, Payloads: topPayloads, Evidence: topEvidence,
		Facts: topFacts, Capabilities: []archive.Capability{}, Checkpoints: []archive.Checkpoint{},
	}
	var totals repositoryResult
	for _, collected := range workResults {
		batch.Payloads = append(batch.Payloads, collected.payloads...)
		batch.Evidence = append(batch.Evidence, collected.evidence...)
		batch.Facts = append(batch.Facts, collected.facts...)
		if collected.checkpoint != nil {
			batch.Checkpoints = append(batch.Checkpoints, *collected.checkpoint)
		}
		result.Gaps = append(result.Gaps, collected.gaps...)
		result.CalledWorkflows = append(result.CalledWorkflows, collected.called...)
		result.rawInputs = append(result.rawInputs, collected.rawInputs...)
		totals.jobLogs += collected.jobLogs
		totals.attemptLogs += collected.attemptLogs
		totals.actionFacts += collected.actionFacts
		totals.actionDefinitions += collected.actionDefinitions
		totals.workflowDefinitions += collected.workflowDefinitions
		totals.callerWorkflowDefinitions += collected.callerWorkflowDefinitions
		totals.calledWorkflowDefinitions += collected.calledWorkflowDefinitions
		totals.lifecycleFacts += collected.lifecycleFacts
		totals.permissionFacts += collected.permissionFacts
		totals.staticPermissionFacts += collected.staticPermissionFacts
		totals.secretFlowFacts += collected.secretFlowFacts
		totals.environmentFacts += collected.environmentFacts
		totals.runnerFacts += collected.runnerFacts
		totals.historicalGaps += collected.historicalGaps
		totals.rawLogs += collected.rawLogs
	}
	batch.Facts = deduplicateFacts(batch.Facts)
	batch.Payloads = deduplicatePayloads(batch.Payloads)
	batch.Evidence = deduplicateObservations(batch.Evidence)
	batch.Capabilities = append(capabilities(totals, result.Gaps, request, len(targets)), enrichmentCapabilities(c.API, batch.Evidence, result.Gaps)...)
	sortCalled(result.CalledWorkflows)
	result.CalledWorkflows = deduplicateCalled(result.CalledWorkflows)
	sortGaps(result.Gaps)

	normalized, normalizeErr := archive.NormalizeBatch(batch)
	if normalizeErr != nil {
		return result, fmt.Errorf("normalize live collection batch: %w", normalizeErr)
	}
	result.Batch = normalized
	if firstErr != nil {
		return result, firstErr
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	return result, nil
}

func collectionEventWindow(interval collect.Interval, expanded bool) *model.EventInterval {
	start := model.MustInstant(interval.From.UTC())
	end := model.MustInstant(interval.To.UTC())
	bounds := model.BoundsClosedOpen
	approximation := model.ApproximationExact
	if expanded {
		approximation = model.ApproximationConservativeExpanded
	}
	return &model.EventInterval{Start: &start, End: &end, Bounds: &bounds, Precision: model.PrecisionSecond, Approximation: approximation, Basis: model.TimeBasisProxyInterval}
}

// CollectInto appends an entirely normalized batch to a caller-provided
// archive sink. Cancellation and invariant errors are never committed.
func (c Collector) CollectInto(ctx context.Context, request Request, sink Sink) (Result, error) {
	if sink == nil {
		return Result{}, errors.New("archive sink is nil")
	}
	var rawSink RawSink
	if request.RawRetention {
		var ok bool
		rawSink, ok = sink.(RawSink)
		if !ok {
			return Result{}, errors.New("raw retention requires a raw-capable archive sink")
		}
	}
	result, err := c.collect(ctx, request)
	defer cleanupRawInputs(result.rawInputs)
	if err != nil {
		return result, err
	}
	if request.RawRetention {
		rawInputs, normalizeErr := normalizeRawInputs(result.rawInputs)
		if normalizeErr != nil {
			return result, normalizeErr
		}
		for _, input := range rawInputs {
			if err := rawSink.RetainRaw(ctx, input); err != nil {
				return result, fmt.Errorf("retain raw workflow log: %w", err)
			}
		}
	}
	if err := sink.Append(ctx, result.Batch); err != nil {
		return result, fmt.Errorf("append live collection batch: %w", err)
	}
	return result, nil
}

func cleanupRawInputs(inputs []archive.RawInput) {
	for _, input := range inputs {
		if input.SourcePath != "" {
			_ = os.Remove(input.SourcePath)
		}
	}
}

func normalizeRawInputs(inputs []archive.RawInput) ([]archive.RawInput, error) {
	result := append([]archive.RawInput(nil), inputs...)
	sort.Slice(result, func(i, j int) bool {
		if result[i].SHA256 != result[j].SHA256 {
			return result[i].SHA256 < result[j].SHA256
		}
		return result[i].SourcePath < result[j].SourcePath
	})
	write := 0
	for _, input := range result {
		if write > 0 && result[write-1].SHA256 == input.SHA256 {
			previous := result[write-1]
			if previous.ByteLength != input.ByteLength || previous.MediaType != input.MediaType {
				return nil, errors.New("identical raw log hash has contradictory descriptors")
			}
			continue
		}
		result[write] = input
		write++
	}
	return result[:write], nil
}

func collectionSessionID(request Request, started model.Instant) (model.CollectionSessionID, error) {
	value, err := evidence.CanonicalSHA256(struct {
		Version            string
		APIVersion         string
		Organization       string
		Repositories       []string
		From               string
		To                 string
		Purpose            Purpose
		AuthKind           string
		Concurrency        int
		RawRetention       bool
		MaxJobLogBytes     int64
		MaxAttemptLogBytes int64
		MaxPartitions      int
		ArchiveSchedule    ArchiveScheduleMode
		ArchiveCheckpoints []archive.Checkpoint
		Started            model.Instant
	}{
		Version: "live-collection/v3", APIVersion: githubapi.APIVersion,
		Organization: request.Organization, Repositories: append([]string(nil), request.Repositories...),
		From: request.Interval.From.UTC().Format(time.RFC3339Nano), To: request.Interval.To.UTC().Format(time.RFC3339Nano),
		Purpose: request.Purpose, AuthKind: request.AuthKind, Concurrency: request.Concurrency,
		RawRetention: request.RawRetention, MaxJobLogBytes: request.MaxJobLogBytes,
		MaxAttemptLogBytes: request.MaxAttemptLogBytes, MaxPartitions: request.MaxPartitions,
		ArchiveSchedule: request.ArchiveSchedule, ArchiveCheckpoints: append([]archive.Checkpoint(nil), request.ArchiveCheckpoints...), Started: started,
	})
	if err != nil {
		return "", err
	}
	return model.CollectionSessionID("collection:" + value), nil
}

func (c Collector) resolveRepositories(ctx context.Context, request Request, sessionID model.CollectionSessionID, started model.Instant, now Clock) ([]repositoryWork, []archive.Payload, []evidence.Envelope, []archive.Fact, []collect.Gap, error) {
	var repositories []githubapi.Repository
	var payloads []archive.Payload
	var envelopes []evidence.Envelope
	var facts []archive.Fact
	var gaps []collect.Gap
	if request.Organization != "" {
		listed, err := c.API.ListOrganizationRepositories(ctx, request.Organization)
		if err != nil {
			gaps = append(gaps, collect.GapFromError("organization_repositories", 0, 0, 0, err))
			if ctx.Err() != nil {
				return nil, payloads, envelopes, facts, gaps, ctx.Err()
			}
		}
		// A later-page failure can still return verified repositories and response
		// metadata. Continue those targets while retaining the enumeration gap.
		repositories = append(repositories, listed.Repositories...)
		if err == nil || len(listed.Repositories) > 0 || len(listed.Responses) > 0 {
			projection := organizationProjection(request.Organization, listed)
			payload, envelope, buildErr := compactEnvelope(sessionID, requestID("org", request.Organization), "normalized:github:organization-repositories:"+safeKey(request.Organization), evidence.SourceAPIJSON, githubapi.APIVersion, "/orgs/{org}/repos", evidence.RequestParameters{"org": safeField(request.Organization, 256), "type": "all"}, model.CoverageScope{}, projection, started, model.MustInstant(now().UTC()))
			if buildErr != nil {
				return nil, nil, nil, nil, gaps, buildErr
			}
			payloads, envelopes = append(payloads, payload), append(envelopes, envelope)
		}
	} else {
		slugs, err := normalizeRequestedSlugs(request.Repositories)
		if err != nil {
			return nil, nil, nil, nil, gaps, err
		}
		for _, slug := range slugs {
			owner, name := splitSlug(slug)
			resolved, getErr := c.API.GetRepository(ctx, owner, name)
			if getErr != nil {
				gap := collect.GapFromError("repository", 0, 0, 0, getErr)
				gap.Diagnostic = "explicit repository " + safeField(string(slug), 512) + " was inaccessible: " + gap.Diagnostic
				gaps = append(gaps, gap)
				if ctx.Err() != nil {
					return nil, payloads, envelopes, facts, gaps, ctx.Err()
				}
				continue
			}
			repositories = append(repositories, resolved.Value)
		}
	}
	seen := make(map[int64]struct{}, len(repositories))
	targets := make([]repositoryWork, 0, len(repositories))
	for _, repository := range repositories {
		if repository.ID <= 0 {
			gaps = append(gaps, collect.Gap{Reason: collect.GapMalformedResponse, Scope: "repository", Material: true, Diagnostic: "repository response omitted a positive repository ID"})
			continue
		}
		if _, duplicate := seen[repository.ID]; duplicate {
			gaps = append(gaps, collect.Gap{Reason: collect.GapPagination, Scope: "repository", RepositoryID: repository.ID, Material: true, Diagnostic: "repository enumeration repeated a repository ID"})
			continue
		}
		seen[repository.ID] = struct{}{}
		slug, err := model.NewRepositorySlug(repository.FullName)
		if err != nil {
			gaps = append(gaps, collect.Gap{Reason: collect.GapMalformedResponse, Scope: "repository", RepositoryID: repository.ID, Material: true, Diagnostic: "repository response contained an unsafe full name"})
			continue
		}
		owner, name := splitSlug(slug)
		repository.ID = int64(model.RepositoryID(repository.ID))
		projection := repositoryProjection(repository)
		repoID := model.RepositoryID(repository.ID)
		endpoint := "/repos/{owner}/{repo}"
		parameters := evidence.RequestParameters{"owner": owner, "repo": name}
		if request.Organization != "" {
			// Organization targets came from the list response; do not imply a
			// per-repository request that was never made. The repository ID ties
			// this compact projection back to its list entry.
			endpoint = "/orgs/{org}/repos"
			parameters = evidence.RequestParameters{"org": safeField(request.Organization, 256), "repository_id": fmt.Sprint(repository.ID), "type": "all"}
		}
		payload, envelope, err := compactEnvelope(sessionID, requestID("repository", fmt.Sprint(repository.ID)), "normalized:github:repository:"+fmt.Sprint(repository.ID), evidence.SourceAPIJSON, githubapi.APIVersion, endpoint, parameters, model.CoverageScope{RepositoryID: &repoID}, projection, started, model.MustInstant(now().UTC()))
		if err != nil {
			return nil, nil, nil, nil, gaps, err
		}
		payloads, envelopes = append(payloads, payload), append(envelopes, envelope)
		private, fork, archived, disabled := repository.Private, repository.Fork, repository.Archived, repository.Disabled
		facts = append(facts, archive.Fact{Kind: archive.FactRepository, EvidenceIDs: []model.EvidenceID{envelope.Evidence.ID}, Repository: &archive.RepositoryFact{
			Repository: model.RepositorySubject{ID: repoID, Name: slug}, Visibility: safeField(repository.Visibility, 32),
			Private: &private, Fork: &fork, Archived: &archived, Disabled: &disabled, DefaultBranch: safeField(repository.DefaultBranch, 1024),
		}})
		targets = append(targets, repositoryWork{repository: repository, slug: slug, owner: owner, name: name, evidenceID: envelope.Evidence.ID})
	}
	// Repository-target failures occur before a stable repository ID is
	// available. Persist them as global, target-keyed coverage gaps instead of
	// leaving the typed failure only in the in-memory result. The archive permits
	// global scope only for repository-visibility coverage.
	sortGaps(gaps)
	for index, gap := range gaps {
		logicalKey := coverageLogicalKey(gap.Scope, gap.RepositoryID, gap.RunID, gap.Attempt, gap.JobID) + ":" + safeKey(fmt.Sprintf("%d\x00%s", index, gap.Diagnostic))
		fact, factErr := gapFactWithLogicalKey(gap, logicalKey)
		if factErr != nil {
			return nil, nil, nil, nil, gaps, factErr
		}
		facts = append(facts, fact)
	}
	sort.Slice(targets, func(i, j int) bool {
		if targets[i].repository.ID != targets[j].repository.ID {
			return targets[i].repository.ID < targets[j].repository.ID
		}
		return targets[i].slug < targets[j].slug
	})
	return targets, payloads, envelopes, facts, gaps, nil
}

func normalizeRequestedSlugs(values []string) ([]model.RepositorySlug, error) {
	result := make([]model.RepositorySlug, 0, len(values))
	for _, value := range values {
		slug, err := model.NewRepositorySlug(strings.TrimSpace(value))
		if err != nil {
			return nil, err
		}
		result = append(result, slug)
	}
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	for index := 1; index < len(result); index++ {
		if strings.EqualFold(string(result[index-1]), string(result[index])) {
			return nil, errors.New("explicit repositories must be unique")
		}
	}
	return result, nil
}

func splitSlug(slug model.RepositorySlug) (string, string) {
	parts := strings.SplitN(string(slug), "/", 2)
	return parts[0], parts[1]
}

func capabilities(totals repositoryResult, gaps []collect.Gap, request Request, accessible int) []archive.Capability {
	actionStatus := capabilityStatus(gaps, "attempt_log", "setup_parser", "setup_correlation", "repository_hash_algorithm")
	actionDefinitionStatus := archive.CapabilityNotCollected
	if totals.actionDefinitions > 0 {
		actionDefinitionStatus = archive.CapabilityStructuredOnly
	}
	if capabilityStatus(gaps, "action_definition", "local_action_definition") == archive.CapabilityGap {
		actionDefinitionStatus = archive.CapabilityGap
	}
	attemptLogStatus := capabilityStatus(gaps, "attempt_log", "setup_parser", "setup_correlation")
	lifecycleStatus := capabilityStatus(gaps, "attempt_log", "action_step_correlation", "action_step_parser", "action_step_resolution")
	calledStatus := capabilityStatus(gaps, "called_workflow_metadata", "workflow_run_attempt")
	runnerStatus := capabilityStatus(gaps, "attempt_job", "attempt_jobs")
	permissionStatus := capabilityStatus(gaps, "attempt_log", "setup_parser", "setup_correlation")
	jobLogStatus := archive.CapabilityHashOnly
	if capabilityStatus(gaps, "job_log") == archive.CapabilityGap {
		jobLogStatus = archive.CapabilityGap
	} else if request.RawRetention {
		jobLogStatus = archive.CapabilityRetained
	}
	if request.RawRetention && attemptLogStatus != archive.CapabilityGap {
		attemptLogStatus = archive.CapabilityRetained
	}
	workflowDefinitionStatus := archive.CapabilityNotCollected
	if totals.workflowDefinitions > 0 {
		workflowDefinitionStatus = archive.CapabilityStructuredOnly
	}
	if capabilityStatus(gaps, "historical_workflow", "called_workflow_definition", "called_workflow_metadata") == archive.CapabilityGap {
		workflowDefinitionStatus = archive.CapabilityGap
	}
	historicalExposureStatus := archive.CapabilityNotCollected
	if totals.workflowDefinitions > 0 {
		historicalExposureStatus = archive.CapabilityStructuredOnly
	}
	if capabilityStatus(gaps, exposureJoinScope, secretFlowScope) == archive.CapabilityGap {
		historicalExposureStatus = archive.CapabilityGap
	}
	staticPermissionStatus := archive.CapabilityNotCollected
	if totals.workflowDefinitions > 0 {
		staticPermissionStatus = archive.CapabilityStructuredOnly
	}
	if capabilityStatus(gaps, staticPermissionScope) == archive.CapabilityGap {
		staticPermissionStatus = archive.CapabilityGap
	}
	environmentContextStatus := archive.CapabilityNotCollected
	if totals.workflowDefinitions > 0 {
		environmentContextStatus = archive.CapabilityStructuredOnly
	}
	if capabilityStatus(gaps, environmentContextScope, exposureJoinScope) == archive.CapabilityGap {
		environmentContextStatus = archive.CapabilityGap
	}
	rawStatus := archive.CapabilityNotCollected
	rawDetails := map[string]string{"policy": "disabled", "retained_count": "0"}
	if request.RawRetention {
		rawStatus = archive.CapabilityRetained
		rawDetails = map[string]string{"policy": "exact-opt-in", "retained_count": fmt.Sprint(totals.rawLogs), "sensitivity": "may-contain-unmasked-application-output"}
		if capabilityStatus(gaps, "attempt_log", "job_log") == archive.CapabilityGap {
			rawStatus = archive.CapabilityGap
			rawDetails["availability"] = "partial"
		}
	}
	return []archive.Capability{
		{Name: "action_definitions", Status: actionDefinitionStatus, ExtractorVersion: ExtractorVersion, Details: map[string]string{"parsed_count": fmt.Sprint(totals.actionDefinitions), "basis": "exact-runtime-source-object"}},
		{Name: "action_execution", Status: lifecycleStatus, ExtractorVersion: ExtractorVersion, Details: map[string]string{"fact_count": fmt.Sprint(totals.lifecycleFacts), "mode": "strict-default-main-step"}},
		{Name: "action_resolution", Status: actionStatus, ExtractorVersion: ExtractorVersion, Details: map[string]string{"fact_count": fmt.Sprint(totals.actionFacts)}},
		{Name: "attempt_logs", Status: attemptLogStatus, ExtractorVersion: ExtractorVersion, Details: map[string]string{"collected_count": fmt.Sprint(totals.attemptLogs), "mode": "setup-and-strict-action-lifecycle"}},
		{Name: "job_logs", Status: jobLogStatus, ExtractorVersion: ExtractorVersion, Details: map[string]string{"collected_count": fmt.Sprint(totals.jobLogs), "raw": map[bool]string{false: "discarded", true: "retained"}[request.RawRetention]}},
		{Name: "historical_permissions", Status: staticPermissionStatus, ExtractorVersion: ExtractorVersion, Details: map[string]string{"fact_count": fmt.Sprint(totals.staticPermissionFacts), "basis": "exact-definition-static-inference"}},
		{Name: "historical_secret_flows", Status: historicalExposureStatus, ExtractorVersion: ExtractorVersion, Details: map[string]string{"fact_count": fmt.Sprint(totals.secretFlowFacts), "mode": "exact-job-and-lifecycle-joins"}},
		{Name: "environment_job_context", Status: environmentContextStatus, ExtractorVersion: ExtractorVersion, Details: map[string]string{"fact_count": fmt.Sprint(totals.environmentFacts), "content_policy": "names-and-relationships-only"}},
		{Name: "raw_logs", Status: rawStatus, ExtractorVersion: ExtractorVersion, Details: rawDetails},
		repositoryCapability(request, accessible, gaps),
		{Name: "referenced_workflow_identity", Status: calledStatus, ExtractorVersion: ExtractorVersion, Details: map[string]string{"basis": "attempt-metadata"}},
		{Name: "runner_context", Status: runnerStatus, ExtractorVersion: ExtractorVersion, Details: map[string]string{"fact_count": fmt.Sprint(totals.runnerFacts)}},
		{Name: "runtime_permissions", Status: permissionStatus, ExtractorVersion: ExtractorVersion, Details: map[string]string{"fact_count": fmt.Sprint(totals.permissionFacts)}},
		{Name: "workflow_definitions", Status: workflowDefinitionStatus, ExtractorVersion: ExtractorVersion, Details: map[string]string{
			"caller_definition_count": fmt.Sprint(totals.callerWorkflowDefinitions), "called_definition_count": fmt.Sprint(totals.calledWorkflowDefinitions),
			"caller_gap_count": fmt.Sprint(totals.historicalGaps), "definition_count": fmt.Sprint(totals.workflowDefinitions),
		}},
	}
}

func capabilityStatus(gaps []collect.Gap, scopes ...string) archive.CapabilityStatus {
	allowed := make(map[string]struct{}, len(scopes))
	for _, scope := range scopes {
		allowed[scope] = struct{}{}
	}
	for _, gap := range gaps {
		if _, ok := allowed[gap.Scope]; ok && gap.Material {
			return archive.CapabilityGap
		}
	}
	return archive.CapabilityStructuredOnly
}

func repositoryCapability(request Request, accessible int, gaps []collect.Gap) archive.Capability {
	details := map[string]string{"accessible_count": fmt.Sprint(accessible), "enumerated_count": fmt.Sprint(accessible)}
	status := capabilityStatus(gaps, "repository", "organization_repositories")
	denied, unresolved := 0, 0
	for _, gap := range gaps {
		if gap.Scope != "repository" && gap.Scope != "organization_repositories" {
			continue
		}
		if gap.Reason == collect.GapForbidden || gap.Reason == collect.GapUnauthorized {
			denied++
		} else {
			unresolved++
		}
	}
	if request.Organization == "" {
		details["requested_total_known"] = "true"
		details["requested_count"] = fmt.Sprint(len(request.Repositories))
		details["denied_count"] = fmt.Sprint(denied)
		details["unresolved_count"] = fmt.Sprint(unresolved)
	} else {
		details["requested_total_known"] = "false"
		details["denied_count"] = "unknown"
		details["unresolved_count"] = "unknown"
		details["enumeration_gap_count"] = fmt.Sprint(denied + unresolved)
	}
	return archive.Capability{Name: "repository_visibility", Status: status, ExtractorVersion: ExtractorVersion, Details: details}
}

func deduplicateFacts(facts []archive.Fact) []archive.Fact {
	result := make([]archive.Fact, 0, len(facts))
	seen := make(map[string]int, len(facts))
	for _, fact := range facts {
		normalized, err := archive.NormalizeFact(fact)
		if err != nil {
			// Preserve invalid facts for NormalizeBatch to report with context.
			result = append(result, fact)
			continue
		}
		if index, ok := seen[normalized.ID]; ok {
			result[index].EvidenceIDs = model.SortEvidenceIDs(append(result[index].EvidenceIDs, normalized.EvidenceIDs...))
			continue
		}
		seen[normalized.ID] = len(result)
		result = append(result, normalized)
	}
	return result
}

func deduplicatePayloads(payloads []archive.Payload) []archive.Payload {
	seen := make(map[string]struct{}, len(payloads))
	result := make([]archive.Payload, 0, len(payloads))
	for _, payload := range payloads {
		if _, ok := seen[payload.SHA256]; ok {
			continue
		}
		seen[payload.SHA256] = struct{}{}
		result = append(result, payload)
	}
	return result
}

func deduplicateObservations(envelopes []evidence.Envelope) []evidence.Envelope {
	seen := make(map[model.CollectionObservationID]struct{}, len(envelopes))
	result := make([]evidence.Envelope, 0, len(envelopes))
	for _, envelope := range envelopes {
		if _, ok := seen[envelope.Observation.ID]; ok {
			continue
		}
		seen[envelope.Observation.ID] = struct{}{}
		result = append(result, envelope)
	}
	return result
}

func sortCalled(values []CalledWorkflowObservation) {
	sort.Slice(values, func(i, j int) bool {
		a, b := values[i], values[j]
		if a.RepositoryID != b.RepositoryID {
			return a.RepositoryID < b.RepositoryID
		}
		if a.RunID != b.RunID {
			return a.RunID < b.RunID
		}
		if a.RunAttempt != b.RunAttempt {
			return a.RunAttempt < b.RunAttempt
		}
		if a.TargetRepository != b.TargetRepository {
			return a.TargetRepository < b.TargetRepository
		}
		if a.TargetPath != b.TargetPath {
			return a.TargetPath < b.TargetPath
		}
		if a.DeclaredRef != b.DeclaredRef {
			return a.DeclaredRef < b.DeclaredRef
		}
		if a.RecordedRef != b.RecordedRef {
			return a.RecordedRef < b.RecordedRef
		}
		return model.GitObjectID(a.CalledObjectID).Value < model.GitObjectID(b.CalledObjectID).Value
	})
}

func deduplicateCalled(values []CalledWorkflowObservation) []CalledWorkflowObservation {
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

func sortGaps(gaps []collect.Gap) {
	sort.SliceStable(gaps, func(i, j int) bool {
		a, b := gaps[i], gaps[j]
		if a.RepositoryID != b.RepositoryID {
			return a.RepositoryID < b.RepositoryID
		}
		if a.RunID != b.RunID {
			return a.RunID < b.RunID
		}
		if a.Attempt != b.Attempt {
			return a.Attempt < b.Attempt
		}
		if a.JobID != b.JobID {
			return a.JobID < b.JobID
		}
		if a.Scope != b.Scope {
			return a.Scope < b.Scope
		}
		if a.Reason != b.Reason {
			return a.Reason < b.Reason
		}
		return a.Diagnostic < b.Diagnostic
	})
}
