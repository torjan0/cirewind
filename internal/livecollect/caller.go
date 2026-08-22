package livecollect

import (
	"context"
	"errors"
	"sort"
	"strings"

	"github.com/torjan0/cirewind/internal/collect"
	"github.com/torjan0/cirewind/internal/githubapi"
	"github.com/torjan0/cirewind/internal/model"
	"github.com/torjan0/cirewind/internal/resolve"
	"github.com/torjan0/cirewind/internal/workflow"
)

const maxCallerPullRequestCandidates = 1024

type historicalCallerCandidate struct {
	path  model.WorkflowPath
	sha   string
	basis string
	event string
}

type historicalCallerIssue struct {
	reason     collect.GapReason
	diagnostic string
}

type historicalStepBinding struct {
	declaration string
	workflowJob string
	stepOrdinal int
	evidenceIDs []model.EvidenceID
}

type historicalStepBindingIssue struct {
	jobID      int64
	diagnostic string
}

// deriveHistoricalCallerCandidate applies only event semantics documented by
// GitHub for GITHUB_SHA. REST head_sha remains the trigger object everywhere;
// this function gives it the separate caller-definition role only for the
// allowlisted events below. It deliberately consumes no GraphQL URL field.
func deriveHistoricalCallerCandidate(target repositoryWork, parent githubapi.WorkflowRun, attempt githubapi.WorkflowRun) (historicalCallerCandidate, *historicalCallerIssue) {
	path, pathErr := historicalCallerPath(attempt.Path)
	if pathErr != nil {
		return historicalCallerCandidate{}, callerIssue(collect.GapValidation, "attempt metadata did not contain a safe workflow path")
	}
	if parent.Path != "" {
		parentPath, err := historicalCallerPath(parent.Path)
		if err != nil || parentPath != path {
			return historicalCallerCandidate{}, callerIssue(collect.GapAmbiguousCorrelation, "parent and attempt metadata disagreed on the workflow path")
		}
	}
	event := attempt.Event
	if event == "" || event != strings.TrimSpace(event) || event != strings.ToLower(event) {
		return historicalCallerCandidate{}, callerIssue(collect.GapValidation, "attempt metadata did not contain a supported canonical event name")
	}
	if parent.Event != "" && parent.Event != event {
		return historicalCallerCandidate{}, callerIssue(collect.GapAmbiguousCorrelation, "parent and attempt metadata disagreed on the triggering event")
	}

	var sha, basis string
	switch event {
	case "push":
		sha, basis = attempt.HeadSHA, "event-github-sha:push-tip"
	case "workflow_dispatch":
		sha, basis = attempt.HeadSHA, "event-github-sha:dispatched-ref"
	case "pull_request":
		sha, basis = attempt.HeadSHA, "event-github-sha:pull-request-merge"
		// GitHub documents GITHUB_SHA as the merge-branch commit, not the PR
		// head or base object. If REST metadata collapses those identities, do
		// not silently reconstruct the caller from the wrong tree.
		for _, pullRequest := range attempt.PullRequests {
			if strings.EqualFold(sha, pullRequest.Head.SHA) || strings.EqualFold(sha, pullRequest.Base.SHA) {
				return historicalCallerCandidate{}, callerIssue(collect.GapAmbiguousCorrelation, "pull_request head_sha was not distinct from the recorded PR head/base object, so the merge-workflow object was not established")
			}
		}
	case "pull_request_target":
		var issue *historicalCallerIssue
		sha, issue = uniqueSameRepositoryPRBase(target, attempt.PullRequests)
		if issue != nil {
			return historicalCallerCandidate{}, issue
		}
		basis = "event-github-sha:pull-request-target-base"
		if attempt.HeadSHA == "" || !strings.EqualFold(attempt.HeadSHA, sha) {
			return historicalCallerCandidate{}, callerIssue(collect.GapAmbiguousCorrelation, "pull_request_target head_sha disagreed with the unique same-repository PR base SHA")
		}
	case "issue_comment":
		sha, basis = attempt.HeadSHA, "event-github-sha:default-branch-issue-comment"
	case "repository_dispatch":
		sha, basis = attempt.HeadSHA, "event-github-sha:default-branch-repository-dispatch"
	case "schedule":
		sha, basis = attempt.HeadSHA, "event-github-sha:default-branch-schedule"
	case "workflow_run":
		sha, basis = attempt.HeadSHA, "event-github-sha:default-branch-workflow-run"
	case "workflow_call":
		return historicalCallerCandidate{}, callerIssue(collect.GapValidation, "workflow_call inherits its caller event SHA/ref, but REST run metadata alone does not establish the caller workflow definition repository/path/object")
	default:
		return historicalCallerCandidate{}, callerIssue(collect.GapValidation, "trigger event is not allowlisted for historical caller workflow reconstruction")
	}
	if sha == "" {
		return historicalCallerCandidate{}, callerIssue(collect.GapValidation, "event-specific caller candidate omitted a trigger SHA")
	}
	if parent.HeadSHA != "" && !strings.EqualFold(parent.HeadSHA, sha) {
		return historicalCallerCandidate{}, callerIssue(collect.GapAmbiguousCorrelation, "parent and attempt metadata disagreed on the event-specific caller candidate SHA")
	}
	return historicalCallerCandidate{path: path, sha: strings.ToLower(sha), basis: basis, event: event}, nil
}

// historicalCallerPath is deliberately stricter than workflowPath, which also
// decodes GitHub's referenced-workflow metadata. A run's caller path must be a
// repository-relative workflow path as returned by the REST run APIs. URLs,
// owner/repository prefixes, and ref suffixes are never converted into paths.
func historicalCallerPath(raw string) (model.WorkflowPath, error) {
	if raw == "" || raw != strings.TrimSpace(raw) || !strings.HasPrefix(raw, ".github/workflows/") || strings.Contains(raw, "@") {
		return "", errors.New("caller workflow path is not an exact repository-relative path")
	}
	return model.NewWorkflowPath(raw)
}

func uniqueSameRepositoryPRBase(target repositoryWork, values []githubapi.PullRequestRef) (string, *historicalCallerIssue) {
	if len(values) == 0 {
		return "", callerIssue(collect.GapAmbiguousCorrelation, "pull_request_target metadata omitted a PR base candidate")
	}
	if len(values) > maxCallerPullRequestCandidates {
		return "", callerIssue(collect.GapSizeLimit, "pull_request_target metadata exceeded the bounded PR candidate count")
	}
	candidates := make(map[string]struct{})
	for _, pullRequest := range values {
		if pullRequest.Base.Repo == nil || pullRequest.Base.Repo.ID <= 0 || pullRequest.Base.Repo.ID != target.repository.ID {
			return "", callerIssue(collect.GapAmbiguousCorrelation, "pull_request_target metadata contained a base repository that was absent or differed from the run repository")
		}
		sha := strings.ToLower(pullRequest.Base.SHA)
		if sha == "" {
			return "", callerIssue(collect.GapValidation, "pull_request_target metadata contained an empty base SHA")
		}
		candidates[sha] = struct{}{}
	}
	if len(candidates) != 1 {
		return "", callerIssue(collect.GapAmbiguousCorrelation, "pull_request_target metadata did not establish one unique same-repository PR base SHA")
	}
	for sha := range candidates {
		return sha, nil
	}
	return "", callerIssue(collect.GapAmbiguousCorrelation, "pull_request_target metadata did not establish a PR base SHA")
}

func callerIssue(reason collect.GapReason, diagnostic string) *historicalCallerIssue {
	return &historicalCallerIssue{reason: reason, diagnostic: diagnostic}
}

func (h *historicalAttempt) prepareCallerWorkflow(ctx context.Context, attemptEvidenceID model.EvidenceID) error {
	if h.callerPrepared {
		return nil
	}
	h.callerPrepared = true
	candidate, issue := deriveHistoricalCallerCandidate(h.target, h.parent, h.bundle.Run)
	if issue != nil {
		return h.appendCallerGap(issue.reason, issue.diagnostic)
	}
	hash, err := h.repositoryHash(ctx, h.target.slug, "historical_workflow")
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return err
		}
		h.result.historicalGaps++
		return nil
	}
	object, err := model.NewGitObjectID(model.HashAlgorithm(hash.algorithm), candidate.sha)
	if err != nil {
		return h.appendCallerGap(collect.GapValidation, "event-specific caller candidate did not match the run repository hash algorithm")
	}
	evidenceIDs := model.SortEvidenceIDs([]model.EvidenceID{attemptEvidenceID, hash.evidenceID})
	stringIDs := make([]string, len(evidenceIDs))
	for index, evidenceID := range evidenceIDs {
		stringIDs[index] = string(evidenceID)
	}
	h.algorithms[string(h.target.slug)] = hash.algorithm
	h.caller = &historicalWorkflowRoot{
		resolved: resolve.ResolvedWorkflow{Definition: resolve.DefinitionKey{
			Repository: resolve.Repository{ID: h.target.repository.ID, Owner: h.target.owner, Name: h.target.name},
			Path:       string(candidate.path), Commit: resolve.GitObject{Algorithm: string(object.Algorithm), Value: object.Value},
		}, EvidenceIDs: stringIDs},
		event: h.event, scope: "historical_workflow", basis: candidate.basis,
	}
	return nil
}

// prepareLifecycleBindings parses the exact event-specific caller definition
// before log lifecycle derivation. It does not execute or evaluate workflow
// expressions. A custom API step can be bound only when a single static caller
// job and the exact historical step ordinal/name/uses declaration agree.
func (h *historicalAttempt) prepareLifecycleBindings(ctx context.Context, attemptEvidenceID model.EvidenceID) error {
	if h.lifecycleBindingsPrepared {
		return nil
	}
	h.lifecycleBindingsPrepared = true
	if err := h.prepareCallerWorkflow(ctx, attemptEvidenceID); err != nil {
		return err
	}
	if err := h.prepareCalledWorkflows(ctx, attemptEvidenceID); err != nil {
		return err
	}
	if h.caller == nil || h.exact == nil {
		return nil
	}
	h.ensureContentSource()
	content, err := h.source.Fetch(ctx, h.caller.resolved.Definition)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return err
		}
		return nil
	}
	parsed, parseDiagnostics, err := workflow.ParseWorkflow(content.Bytes, workflow.DefaultLimits())
	if err != nil || len(parseDiagnostics) != 0 {
		return nil
	}
	evidenceIDs, err := historicalBindingEvidence(h.caller.resolved.EvidenceIDs, content.EvidenceID)
	if err != nil {
		return err
	}
	directBindings, bindingIssues := deriveHistoricalStepBindings(parsed, h.bundle.Jobs, evidenceIDs)
	h.stepBindings = directBindings
	reusableBindings, reusableIssues, reusableErr := h.deriveReusableLifecycleBindings(ctx, parsed, evidenceIDs)
	if reusableErr != nil {
		return reusableErr
	}
	for jobID, byStep := range reusableBindings {
		if h.stepBindings[jobID] == nil {
			h.stepBindings[jobID] = make(map[int]historicalStepBinding)
		}
		for stepNumber, binding := range byStep {
			if _, exists := h.stepBindings[jobID][stepNumber]; exists {
				delete(h.stepBindings[jobID], stepNumber)
				bindingIssues = append(bindingIssues, historicalStepBindingIssue{jobID: jobID, diagnostic: "direct and reusable historical declarations collided on one API step identity"})
				continue
			}
			h.stepBindings[jobID][stepNumber] = binding
		}
	}
	bindingIssues = append(bindingIssues, reusableIssues...)
	for _, diagnostic := range bindingIssues {
		if err := appendGap(h.result, collect.Gap{
			Reason: collect.GapAmbiguousCorrelation, Scope: "action_step_correlation", RepositoryID: h.target.repository.ID,
			RunID: h.runID, Attempt: h.bundle.Attempt, JobID: diagnostic.jobID, Material: true,
			Diagnostic: diagnostic.diagnostic,
		}); err != nil {
			return err
		}
	}
	return nil
}

type reusableLifecycleDocument struct {
	definition  resolve.DefinitionKey
	workflow    *workflow.Workflow
	evidenceIDs []model.EvidenceID
}

type reusableLifecyclePlan struct {
	job         workflow.Job
	apiName     string
	evidenceIDs []model.EvidenceID
}

// deriveReusableLifecycleBindings joins a top-level reusable-workflow call to
// jobs inside exact, positively peeled called definitions. It never evaluates
// expressions or matrix values. A binding requires one runtime-bound called
// definition, a unique static caller/callee label path, one exact API job name,
// and the same API step ordinal/name rules used for a direct caller job.
func (h *historicalAttempt) deriveReusableLifecycleBindings(ctx context.Context, caller *workflow.Workflow, callerEvidence []model.EvidenceID) (map[int64]map[int]historicalStepBinding, []historicalStepBindingIssue, error) {
	bindings := make(map[int64]map[int]historicalStepBinding)
	issues := make([]historicalStepBindingIssue, 0)
	if caller == nil || len(h.workflows) == 0 {
		return bindings, issues, nil
	}
	documents := make(map[string]reusableLifecycleDocument, len(h.workflows))
	for _, root := range h.workflows {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		content, err := h.source.Fetch(ctx, root.resolved.Definition)
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return nil, nil, err
			}
			continue
		}
		parsed, diagnostics, err := workflow.ParseWorkflow(content.Bytes, workflow.DefaultLimits())
		if err != nil || len(diagnostics) != 0 {
			continue
		}
		evidenceIDs, err := historicalBindingEvidence(root.resolved.EvidenceIDs, content.EvidenceID)
		if err != nil {
			return nil, nil, err
		}
		documents[root.resolved.Definition.String()] = reusableLifecycleDocument{definition: root.resolved.Definition, workflow: parsed, evidenceIDs: evidenceIDs}
	}

	callerRepository := h.caller.resolved.Definition.Repository
	plans := make([]reusableLifecyclePlan, 0)
	for _, job := range caller.Jobs {
		if job.Uses == nil {
			continue
		}
		name, static := staticHistoricalJobName(job)
		if !static {
			issues = append(issues, historicalStepBindingIssue{diagnostic: "reusable caller job had a dynamic display label"})
			continue
		}
		target, ok := uniqueLifecycleWorkflow(h.workflowRefs[resolve.ReferenceBindingKey(callerRepository, *job.Uses)])
		if !ok {
			issues = append(issues, historicalStepBindingIssue{diagnostic: "reusable caller job did not identify one exact GitHub-recorded called definition"})
			continue
		}
		document, ok := documents[target.Definition.String()]
		if !ok {
			issues = append(issues, historicalStepBindingIssue{diagnostic: "exact called workflow was unavailable for lifecycle binding"})
			continue
		}
		pathEvidence := model.SortEvidenceIDs(append(append([]model.EvidenceID(nil), callerEvidence...), document.evidenceIDs...))
		stack := map[string]bool{target.Definition.String(): true}
		h.walkReusableLifecyclePlans(document, name, pathEvidence, documents, stack, 1, &plans, &issues)
	}
	reusableBindings, bindIssues := bindReusableLifecyclePlans(plans, h.bundle.Jobs)
	issues = append(issues, bindIssues...)
	return reusableBindings, issues, nil
}

func (h *historicalAttempt) walkReusableLifecyclePlans(document reusableLifecycleDocument, prefix string, evidenceIDs []model.EvidenceID, documents map[string]reusableLifecycleDocument, stack map[string]bool, depth int, plans *[]reusableLifecyclePlan, issues *[]historicalStepBindingIssue) {
	if document.workflow == nil {
		return
	}
	if depth > historicalResolutionDepth {
		*issues = append(*issues, historicalStepBindingIssue{diagnostic: "reusable lifecycle binding exceeded the historical resolution depth"})
		return
	}
	for _, job := range document.workflow.Jobs {
		name, static := staticHistoricalJobName(job)
		if !static {
			if historicalJobHasRepositoryAction(job) || job.Uses != nil {
				*issues = append(*issues, historicalStepBindingIssue{diagnostic: "called workflow job had a dynamic display label"})
			}
			continue
		}
		apiName := prefix + " / " + name
		if historicalJobHasRepositoryAction(job) {
			*plans = append(*plans, reusableLifecyclePlan{job: job, apiName: apiName, evidenceIDs: append([]model.EvidenceID(nil), evidenceIDs...)})
		}
		if job.Uses == nil {
			continue
		}
		target, ok := uniqueLifecycleWorkflow(h.workflowRefs[resolve.ReferenceBindingKey(document.definition.Repository, *job.Uses)])
		if !ok {
			*issues = append(*issues, historicalStepBindingIssue{diagnostic: "nested reusable job did not identify one exact GitHub-recorded called definition"})
			continue
		}
		key := target.Definition.String()
		if stack[key] {
			*issues = append(*issues, historicalStepBindingIssue{diagnostic: "reusable lifecycle binding encountered a called-workflow cycle"})
			continue
		}
		nested, ok := documents[key]
		if !ok {
			*issues = append(*issues, historicalStepBindingIssue{diagnostic: "nested exact called workflow was unavailable for lifecycle binding"})
			continue
		}
		nextEvidence := model.SortEvidenceIDs(append(append([]model.EvidenceID(nil), evidenceIDs...), nested.evidenceIDs...))
		stack[key] = true
		h.walkReusableLifecyclePlans(nested, apiName, nextEvidence, documents, stack, depth+1, plans, issues)
		delete(stack, key)
	}
}

func uniqueLifecycleWorkflow(values []resolve.ResolvedWorkflow) (resolve.ResolvedWorkflow, bool) {
	byDefinition := make(map[string]resolve.ResolvedWorkflow, len(values))
	for _, value := range values {
		key := value.Definition.String()
		if existing, ok := byDefinition[key]; ok {
			existing.EvidenceIDs = mergeStringEvidence(existing.EvidenceIDs, value.EvidenceIDs)
			byDefinition[key] = existing
			continue
		}
		byDefinition[key] = value
	}
	if len(byDefinition) != 1 {
		return resolve.ResolvedWorkflow{}, false
	}
	for _, value := range byDefinition {
		return value, true
	}
	return resolve.ResolvedWorkflow{}, false
}

func bindReusableLifecyclePlans(plans []reusableLifecyclePlan, apiJobs []githubapi.WorkflowJob) (map[int64]map[int]historicalStepBinding, []historicalStepBindingIssue) {
	bindings := make(map[int64]map[int]historicalStepBinding)
	issues := make([]historicalStepBindingIssue, 0)
	nameCount := make(map[string]int, len(plans))
	for _, plan := range plans {
		nameCount[plan.apiName]++
	}
	for _, plan := range plans {
		if nameCount[plan.apiName] != 1 {
			issues = append(issues, historicalStepBindingIssue{diagnostic: "called-workflow Action job had a non-unique static caller/callee label path"})
			continue
		}
		matches := make([]githubapi.WorkflowJob, 0, 1)
		for _, apiJob := range apiJobs {
			if apiJob.Name == plan.apiName {
				matches = append(matches, apiJob)
			}
		}
		if len(matches) != 1 {
			issues = append(issues, historicalStepBindingIssue{diagnostic: "called-workflow Action job did not bind to exactly one API job by its complete static name"})
			continue
		}
		if !hasExactSetupStep(matches[0]) {
			issues = append(issues, historicalStepBindingIssue{jobID: matches[0].ID, diagnostic: "called-workflow API job did not contain the exact setup step required for historical ordinal binding"})
			continue
		}
		apiJob := matches[0]
		for _, step := range plan.job.Steps {
			if step.Uses == nil || step.Uses.Kind != workflow.ReferenceRepository {
				continue
			}
			apiNumber := step.Ordinal + 1
			apiStep, ok := uniqueAPIStep(apiJob, apiNumber)
			expectedName, static := staticHistoricalStepName(step)
			if !ok {
				issues = append(issues, historicalStepBindingIssue{jobID: apiJob.ID, diagnostic: "called-workflow Action step ordinal did not bind to exactly one API step number"})
				continue
			}
			if !static || apiStep.Name != expectedName {
				issues = append(issues, historicalStepBindingIssue{jobID: apiJob.ID, diagnostic: "called-workflow Action step did not match the API step's exact static display name"})
				continue
			}
			if bindings[apiJob.ID] == nil {
				bindings[apiJob.ID] = make(map[int]historicalStepBinding)
			}
			if _, exists := bindings[apiJob.ID][apiNumber]; exists {
				delete(bindings[apiJob.ID], apiNumber)
				issues = append(issues, historicalStepBindingIssue{jobID: apiJob.ID, diagnostic: "multiple called-workflow declarations collided on one API step identity"})
				continue
			}
			bindings[apiJob.ID][apiNumber] = historicalStepBinding{
				declaration: step.Uses.Raw, workflowJob: plan.apiName, stepOrdinal: step.Ordinal,
				evidenceIDs: append([]model.EvidenceID(nil), plan.evidenceIDs...),
			}
		}
	}
	return bindings, issues
}

func (h *historicalAttempt) ensureContentSource() {
	if h.source == nil && h.exact != nil {
		h.source = newHistoricalContentSource(h.exact, h.sessionID, h.scope, h.event, h.now, h.result)
	}
}

func (h *historicalAttempt) stepBinding(jobID int64, stepNumber int) (*historicalStepBinding, bool) {
	values := h.stepBindings[jobID]
	value, ok := values[stepNumber]
	if !ok {
		return nil, false
	}
	copy := value
	copy.evidenceIDs = append([]model.EvidenceID(nil), value.evidenceIDs...)
	return &copy, true
}

func historicalBindingEvidence(values []string, contentEvidence string) ([]model.EvidenceID, error) {
	result := make([]model.EvidenceID, 0, len(values)+1)
	for _, value := range append(append([]string(nil), values...), contentEvidence) {
		evidenceID := model.EvidenceID(value)
		if evidenceID.Validate() != nil {
			return nil, errors.New("historical workflow binding had an invalid evidence identity")
		}
		result = append(result, evidenceID)
	}
	return model.SortEvidenceIDs(result), nil
}

func deriveHistoricalStepBindings(parsed *workflow.Workflow, apiJobs []githubapi.WorkflowJob, evidenceIDs []model.EvidenceID) (map[int64]map[int]historicalStepBinding, []historicalStepBindingIssue) {
	bindings := make(map[int64]map[int]historicalStepBinding)
	issues := make([]historicalStepBindingIssue, 0)
	if parsed == nil {
		return bindings, issues
	}
	jobs := append([]workflow.Job(nil), parsed.Jobs...)
	sort.Slice(jobs, func(i, j int) bool { return jobs[i].ID < jobs[j].ID })
	staticNames := make(map[string]int)
	for _, job := range jobs {
		if historicalJobHasRepositoryAction(job) {
			if name, ok := staticHistoricalJobName(job); ok {
				staticNames[name]++
			}
		}
	}
	for _, job := range jobs {
		if !historicalJobHasRepositoryAction(job) {
			continue
		}
		jobName, static := staticHistoricalJobName(job)
		if !static || staticNames[jobName] != 1 {
			issues = append(issues, historicalStepBindingIssue{diagnostic: "historical caller Action job had a dynamic or non-unique static name"})
			continue
		}
		matches := make([]githubapi.WorkflowJob, 0, 1)
		for _, apiJob := range apiJobs {
			if apiJob.Name == jobName {
				matches = append(matches, apiJob)
			}
		}
		if len(matches) != 1 {
			issues = append(issues, historicalStepBindingIssue{diagnostic: "historical caller Action job did not bind to exactly one API job by its static name"})
			continue
		}
		apiJob := matches[0]
		if !hasExactSetupStep(apiJob) {
			issues = append(issues, historicalStepBindingIssue{jobID: apiJob.ID, diagnostic: "API job did not contain the exact setup step required for historical ordinal binding"})
			continue
		}
		for _, step := range job.Steps {
			if step.Uses == nil || step.Uses.Kind != workflow.ReferenceRepository {
				continue
			}
			apiNumber := step.Ordinal + 1
			apiStep, ok := uniqueAPIStep(apiJob, apiNumber)
			if !ok {
				issues = append(issues, historicalStepBindingIssue{jobID: apiJob.ID, diagnostic: "historical caller Action step ordinal did not bind to exactly one API step number"})
				continue
			}
			expectedName, static := staticHistoricalStepName(step)
			if !static || apiStep.Name != expectedName {
				issues = append(issues, historicalStepBindingIssue{jobID: apiJob.ID, diagnostic: "historical caller Action step did not match the API step's exact static display name"})
				continue
			}
			if bindings[apiJob.ID] == nil {
				bindings[apiJob.ID] = make(map[int]historicalStepBinding)
			}
			bindings[apiJob.ID][apiNumber] = historicalStepBinding{
				declaration: step.Uses.Raw, workflowJob: job.ID, stepOrdinal: step.Ordinal,
				evidenceIDs: append([]model.EvidenceID(nil), evidenceIDs...),
			}
		}
	}
	return bindings, issues
}

func historicalJobHasRepositoryAction(job workflow.Job) bool {
	for _, step := range job.Steps {
		if step.Uses != nil && step.Uses.Kind == workflow.ReferenceRepository {
			return true
		}
	}
	return false
}

func staticHistoricalJobName(job workflow.Job) (string, bool) {
	name := job.Name
	if name == "" {
		name = job.ID
	}
	return name, name != "" && !strings.Contains(name, "${{")
}

func staticHistoricalStepName(step workflow.Step) (string, bool) {
	if step.Uses == nil || step.Uses.Raw == "" {
		return "", false
	}
	if step.Name == "" {
		return "Run " + step.Uses.Raw, !strings.Contains(step.Uses.Raw, "${{")
	}
	return step.Name, !strings.Contains(step.Name, "${{") && !strings.Contains(step.Uses.Raw, "${{")
}

func hasExactSetupStep(job githubapi.WorkflowJob) bool {
	step, ok := uniqueAPIStep(job, 1)
	return ok && step.Name == "Set up job"
}

func uniqueAPIStep(job githubapi.WorkflowJob, number int) (githubapi.JobStep, bool) {
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

func (h *historicalAttempt) appendCallerGap(reason collect.GapReason, diagnostic string) error {
	h.result.historicalGaps++
	return appendGap(h.result, collect.Gap{
		Reason: reason, Scope: "historical_workflow", RepositoryID: h.target.repository.ID,
		RunID: h.runID, Attempt: h.bundle.Attempt, Material: true, Diagnostic: diagnostic,
	})
}
