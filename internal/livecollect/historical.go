package livecollect

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/torjan0/cirewind/internal/archive"
	"github.com/torjan0/cirewind/internal/collect"
	"github.com/torjan0/cirewind/internal/evidence"
	"github.com/torjan0/cirewind/internal/githubapi"
	"github.com/torjan0/cirewind/internal/logparse"
	"github.com/torjan0/cirewind/internal/model"
	"github.com/torjan0/cirewind/internal/resolve"
	"github.com/torjan0/cirewind/internal/workflow"
)

const historicalResolutionDepth = 10

type historicalHashResult struct {
	algorithm  string
	evidenceID model.EvidenceID
	err        error
}

type historicalActionRoot struct {
	resolved  resolve.ResolvedAction
	execution model.JobExecutionIdentity
	event     model.EventInterval
	bindings  map[string][]resolve.ResolvedAction
}

type historicalWorkflowRoot struct {
	resolved resolve.ResolvedWorkflow
	event    model.EventInterval
	scope    string
	basis    string
}

type historicalAttempt struct {
	collector                 Collector
	exact                     ExactContentAPI
	peeler                    GitObjectPeelAPI
	target                    repositoryWork
	parent                    githubapi.WorkflowRun
	runID                     int64
	bundle                    collect.AttemptBundle
	sessionID                 model.CollectionSessionID
	now                       Clock
	result                    *repositoryResult
	scope                     model.CoverageScope
	event                     model.EventInterval
	source                    *historicalContentSource
	hashes                    map[model.RepositorySlug]historicalHashResult
	algorithms                map[string]string
	actions                   []historicalActionRoot
	actionsPrepared           bool
	caller                    *historicalWorkflowRoot
	callerPrepared            bool
	calledPrepared            bool
	lifecycleBindingsPrepared bool
	stepBindings              map[int64]map[int]historicalStepBinding
	compositeBindings         map[int64]map[string]historicalCompositeBinding
	compositePrepared         bool
	workflows                 []historicalWorkflowRoot
	actionLookup              map[string][]resolve.ResolvedAction
	workflowRefs              map[string][]resolve.ResolvedWorkflow
}

// resolveHistoricalAttempt is intentionally called only after runner-owned
// setup evidence has been parsed. The function receives no head SHA and has no
// fallback that could silently turn the trigger object into a definition ID.
func (c Collector) resolveHistoricalAttempt(
	ctx context.Context,
	target repositoryWork,
	runID int64,
	bundle collect.AttemptBundle,
	sessionID model.CollectionSessionID,
	now Clock,
	setup map[int64]map[string][]setupResolution,
	attemptEvidenceID model.EvidenceID,
	result *repositoryResult,
) error {
	attempt := c.newHistoricalAttempt(target, bundle.Run, runID, bundle, sessionID, now, result)
	return attempt.resolve(ctx, setup, attemptEvidenceID)
}

func (c Collector) resolveHistoricalAttemptWithParent(
	ctx context.Context,
	target repositoryWork,
	parent githubapi.WorkflowRun,
	runID int64,
	bundle collect.AttemptBundle,
	sessionID model.CollectionSessionID,
	now Clock,
	setup map[int64]map[string][]setupResolution,
	attemptEvidenceID model.EvidenceID,
	result *repositoryResult,
) error {
	attempt := c.newHistoricalAttempt(target, parent, runID, bundle, sessionID, now, result)
	return attempt.resolve(ctx, setup, attemptEvidenceID)
}

func (c Collector) newHistoricalAttempt(
	target repositoryWork,
	parent githubapi.WorkflowRun,
	runID int64,
	bundle collect.AttemptBundle,
	sessionID model.CollectionSessionID,
	now Clock,
	result *repositoryResult,
) *historicalAttempt {
	repositoryID, typedRun, typedAttempt := model.RepositoryID(target.repository.ID), model.WorkflowRunID(runID), model.RunAttempt(bundle.Attempt)
	scope := model.CoverageScope{RepositoryID: &repositoryID, RunID: &typedRun, RunAttempt: &typedAttempt}
	exact, _ := c.API.(ExactContentAPI)
	peeler, _ := c.API.(GitObjectPeelAPI)
	return &historicalAttempt{
		collector: c, exact: exact, peeler: peeler, target: target, parent: parent, runID: runID, bundle: bundle, sessionID: sessionID, now: now,
		result: result, scope: scope, event: runAttemptEvent(bundle.Run), hashes: make(map[model.RepositorySlug]historicalHashResult),
		algorithms: make(map[string]string), actionLookup: make(map[string][]resolve.ResolvedAction), workflowRefs: make(map[string][]resolve.ResolvedWorkflow),
		stepBindings: make(map[int64]map[int]historicalStepBinding), compositeBindings: make(map[int64]map[string]historicalCompositeBinding),
	}
}

// verifySetupObservations assigns an Action source algorithm only after the
// target Action repository's object format has been observed through GitHub's
// typed repository endpoint. A full hex value from runner output remains
// evidence, but width alone never creates a GitObjectID.
func (h *historicalAttempt) verifySetupObservations(ctx context.Context, observations []logparse.Observation, baseEvidence []model.EvidenceID) ([]setupObservation, error) {
	values := append([]logparse.Observation(nil), observations...)
	logparse.SortObservations(values)
	result := make([]setupObservation, 0, len(values))
	failedIdentity := make(map[string]struct{})
	for _, observation := range values {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if observation.Action == nil || observation.Action.Source.Value == "" {
			result = append(result, setupObservation{observation: observation, evidenceIDs: model.SortEvidenceIDs(baseEvidence)})
			continue
		}
		action := *observation.Action
		slug, slugErr := model.NewRepositorySlug(strings.ToLower(action.Owner) + "/" + strings.ToLower(action.Repository))
		if slugErr != nil {
			if err := h.appendSetupIdentityGap(observation, failedIdentity, "unsafe-action-repository", "runner setup record named an Action repository that could not be normalized"); err != nil {
				return nil, err
			}
			continue
		}
		hash, hashErr := h.repositoryHash(ctx, slug, "action_definition")
		if hashErr != nil {
			if errors.Is(hashErr, context.Canceled) || errors.Is(hashErr, context.DeadlineExceeded) {
				return nil, hashErr
			}
			if action.Digest.Value == "" {
				continue
			}
			// An immutable package digest has independent semantics. Preserve it
			// without attaching an unverified source object.
			action.Source = logparse.GitObject{}
			observation.Action = &action
			result = append(result, setupObservation{observation: observation, evidenceIDs: model.SortEvidenceIDs(baseEvidence)})
			continue
		}
		object, objectErr := model.NewGitObjectID(model.HashAlgorithm(hash.algorithm), strings.ToLower(action.Source.Value))
		if objectErr != nil {
			if err := h.appendSetupIdentityGap(observation, failedIdentity, string(slug)+"\x00"+strings.ToLower(action.Source.Value), "runner setup source value did not match the target Action repository hash algorithm"); err != nil {
				return nil, err
			}
			if action.Digest.Value == "" {
				continue
			}
			action.Source = logparse.GitObject{}
		} else {
			action.Source = logparse.GitObject{Algorithm: string(object.Algorithm), Value: object.Value}
		}
		observation.Action = &action
		evidenceIDs := model.SortEvidenceIDs(append(append([]model.EvidenceID(nil), baseEvidence...), hash.evidenceID))
		result = append(result, setupObservation{observation: observation, evidenceIDs: evidenceIDs})
	}
	return result, nil
}

func (h *historicalAttempt) appendSetupIdentityGap(observation logparse.Observation, seen map[string]struct{}, key, diagnostic string) error {
	if _, exists := seen[key]; exists {
		return nil
	}
	seen[key] = struct{}{}
	return appendGap(h.result, collect.Gap{
		Reason: collect.GapValidation, Scope: "action_definition", RepositoryID: h.target.repository.ID,
		RunID: h.runID, Attempt: h.bundle.Attempt, JobID: observation.Scope.JobID, Material: true,
		Diagnostic: diagnostic,
	})
}

func (h *historicalAttempt) resolve(ctx context.Context, setup map[int64]map[string][]setupResolution, attemptEvidenceID model.EvidenceID) error {
	if err := h.prepareCallerWorkflow(ctx, attemptEvidenceID); err != nil {
		return err
	}
	if err := h.prepareActions(ctx, setup); err != nil {
		return err
	}
	if err := h.prepareCalledWorkflows(ctx, attemptEvidenceID); err != nil {
		return err
	}
	if h.exact == nil {
		if h.caller != nil {
			if err := h.appendCallerGap(collect.GapValidation, "the configured GitHub adapter does not expose exact-object caller workflow content"); err != nil {
				return err
			}
		}
		if len(h.actions) > 0 {
			if err := appendGap(h.result, collect.Gap{Reason: collect.GapValidation, Scope: "action_definition", RepositoryID: h.target.repository.ID, RunID: h.runID, Attempt: h.bundle.Attempt, Material: true, Diagnostic: "the configured GitHub adapter does not expose exact-object repository content"}); err != nil {
				return err
			}
		}
		if len(h.workflows) > 0 {
			if err := appendGap(h.result, collect.Gap{Reason: collect.GapValidation, Scope: "called_workflow_definition", RepositoryID: h.target.repository.ID, RunID: h.runID, Attempt: h.bundle.Attempt, Material: true, Diagnostic: "the configured GitHub adapter does not expose exact-object repository content"}); err != nil {
				return err
			}
		}
		return nil
	}
	h.ensureContentSource()
	if err := h.resolveActions(ctx); err != nil {
		return err
	}
	return h.resolveWorkflows(ctx)
}

func (h *historicalAttempt) prepareActions(ctx context.Context, setup map[int64]map[string][]setupResolution) error {
	if h.actionsPrepared {
		return nil
	}
	h.actionsPrepared = true
	jobByID := make(map[int64]githubapi.WorkflowJob, len(h.bundle.Jobs))
	for _, job := range h.bundle.Jobs {
		jobByID[job.ID] = job
	}
	jobIDs := make([]int64, 0, len(setup))
	for jobID := range setup {
		jobIDs = append(jobIDs, jobID)
	}
	sort.Slice(jobIDs, func(i, j int) bool { return jobIDs[i] < jobIDs[j] })
	for _, jobID := range jobIDs {
		job, ok := jobByID[jobID]
		if !ok {
			continue
		}
		keys := make([]string, 0, len(setup[jobID]))
		for key := range setup[jobID] {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		bindings := make(map[string][]resolve.ResolvedAction)
		rootByIdentity := make(map[string]resolve.ResolvedAction)
		for _, key := range keys {
			values := append([]setupResolution(nil), setup[jobID][key]...)
			sort.Slice(values, func(i, j int) bool {
				left, right := values[i].action, values[j].action
				return left.Owner+"/"+left.Repository+"/"+left.Subpath+"@"+left.Ref+left.Source.Value < right.Owner+"/"+right.Repository+"/"+right.Subpath+"@"+right.Ref+right.Source.Value
			})
			for _, value := range values {
				if value.action.Source.Value == "" {
					// Immutable package-digest evidence is useful to matching and
					// lifecycle derivation, but it cannot identify Action metadata.
					continue
				}
				resolved, err := h.exactRuntimeAction(ctx, value)
				if err != nil {
					if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
						return err
					}
					continue
				}
				bindings[key] = append(bindings[key], resolved)
				h.actionLookup[key] = append(h.actionLookup[key], resolved)
				identity := strings.ToLower(resolved.Repository.Owner) + "/" + strings.ToLower(resolved.Repository.Name) + "\x00" + resolved.Subpath + "\x00" + resolved.Commit.Algorithm + "\x00" + resolved.Commit.Value
				if existing, exists := rootByIdentity[identity]; exists {
					existing.EvidenceIDs = mergeStringEvidence(existing.EvidenceIDs, resolved.EvidenceIDs)
					rootByIdentity[identity] = existing
				} else {
					rootByIdentity[identity] = resolved
				}
			}
		}
		identities := make([]string, 0, len(rootByIdentity))
		for identity := range rootByIdentity {
			identities = append(identities, identity)
		}
		sort.Strings(identities)
		execution := model.JobExecutionIdentity{RepositoryID: model.RepositoryID(h.target.repository.ID), RunID: model.WorkflowRunID(h.runID), RunAttempt: model.RunAttempt(h.bundle.Attempt), JobID: model.JobID(jobID)}
		for _, identity := range identities {
			h.actions = append(h.actions, historicalActionRoot{resolved: rootByIdentity[identity], execution: execution, event: jobEventTime(job), bindings: bindings})
		}
	}
	return nil
}

func (h *historicalAttempt) exactRuntimeAction(ctx context.Context, value setupResolution) (resolve.ResolvedAction, error) {
	action := value.action
	slug, err := model.NewRepositorySlug(strings.ToLower(action.Owner) + "/" + strings.ToLower(action.Repository))
	if err != nil || action.Source.Value == "" {
		if appendErr := appendGap(h.result, collect.Gap{Reason: collect.GapValidation, Scope: "action_definition", RepositoryID: h.target.repository.ID, RunID: h.runID, Attempt: h.bundle.Attempt, Material: true, Diagnostic: "runtime Action resolution lacked a safe repository or full source object"}); appendErr != nil {
			return resolve.ResolvedAction{}, appendErr
		}
		if err == nil {
			err = errors.New("runtime Action source object is absent")
		}
		return resolve.ResolvedAction{}, err
	}
	hash, err := h.repositoryHash(ctx, slug, "action_definition")
	if err != nil {
		return resolve.ResolvedAction{}, err
	}
	object, err := model.NewGitObjectID(model.HashAlgorithm(hash.algorithm), strings.ToLower(action.Source.Value))
	if err != nil {
		if appendErr := appendGap(h.result, collect.Gap{Reason: collect.GapValidation, Scope: "action_definition", RepositoryID: h.target.repository.ID, RunID: h.runID, Attempt: h.bundle.Attempt, Material: true, Diagnostic: "runtime Action source object did not match the target repository hash algorithm"}); appendErr != nil {
			return resolve.ResolvedAction{}, appendErr
		}
		return resolve.ResolvedAction{}, err
	}
	repositoryID := int64(0)
	if slug == h.target.slug {
		repositoryID = h.target.repository.ID
	}
	evidenceIDs := append([]model.EvidenceID(nil), value.evidenceIDs...)
	evidenceIDs = model.SortEvidenceIDs(append(evidenceIDs, hash.evidenceID))
	stringsEvidence := make([]string, len(evidenceIDs))
	for index, evidenceID := range evidenceIDs {
		stringsEvidence[index] = string(evidenceID)
	}
	h.algorithms[string(slug)] = hash.algorithm
	return resolve.ResolvedAction{
		Repository: resolve.Repository{ID: repositoryID, Owner: action.Owner, Name: action.Repository}, Subpath: action.Subpath,
		Commit: resolve.GitObject{Algorithm: string(object.Algorithm), Value: object.Value}, EvidenceIDs: stringsEvidence,
	}, nil
}

func (h *historicalAttempt) prepareCalledWorkflows(ctx context.Context, attemptEvidenceID model.EvidenceID) error {
	if h.calledPrepared {
		return nil
	}
	h.calledPrepared = true
	values := append([]githubapi.ReferencedWorkflow(nil), h.bundle.Run.ReferencedWorkflows...)
	sort.Slice(values, func(i, j int) bool {
		if values[i].Path != values[j].Path {
			return values[i].Path < values[j].Path
		}
		if values[i].Ref != values[j].Ref {
			return values[i].Ref < values[j].Ref
		}
		return values[i].SHA < values[j].SHA
	})
	for _, referenced := range values {
		slug, targetPath, declaredRef, recordedRef, refCompatible, err := calledWorkflowTarget(h.target.slug, referenced)
		if err != nil {
			if appendErr := appendGap(h.result, collect.Gap{Reason: collect.GapMalformedResponse, Scope: "called_workflow_definition", RepositoryID: h.target.repository.ID, RunID: h.runID, Attempt: h.bundle.Attempt, Material: true, Diagnostic: "GitHub-recorded referenced workflow metadata could not be normalized"}); appendErr != nil {
				return appendErr
			}
			continue
		}
		hash, err := h.repositoryHash(ctx, slug, "called_workflow_definition")
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return err
			}
			continue
		}
		object, err := model.NewGitObjectID(model.HashAlgorithm(hash.algorithm), strings.ToLower(strings.TrimSpace(referenced.SHA)))
		if err != nil {
			if appendErr := appendGap(h.result, collect.Gap{Reason: collect.GapValidation, Scope: "called_workflow_definition", RepositoryID: h.target.repository.ID, RunID: h.runID, Attempt: h.bundle.Attempt, Material: true, Diagnostic: "GitHub-recorded called-workflow SHA did not match the target repository hash algorithm"}); appendErr != nil {
				return appendErr
			}
			continue
		}
		callerPath, pathErr := workflowPath(h.bundle.Run.Path)
		if pathErr != nil || callerPath == nil {
			if appendErr := appendGap(h.result, collect.Gap{Reason: collect.GapMalformedResponse, Scope: "called_workflow_metadata", RepositoryID: h.target.repository.ID, RunID: h.runID, Attempt: h.bundle.Attempt, Material: true, Diagnostic: "called-workflow metadata had no safe caller workflow path"}); appendErr != nil {
				return appendErr
			}
			continue
		}
		calledID, calledErr := model.NewCalledWorkflowObjectID(object)
		if calledErr != nil {
			return calledErr
		}
		h.result.called = append(h.result.called, CalledWorkflowObservation{
			RepositoryID: model.RepositoryID(h.target.repository.ID), RunID: model.WorkflowRunID(h.runID), RunAttempt: model.RunAttempt(h.bundle.Attempt),
			CallerPath: *callerPath, TargetRepository: slug, TargetPath: targetPath, DeclaredRef: declaredRef, RecordedRef: recordedRef,
			CalledObjectID: calledID, EvidenceID: attemptEvidenceID,
		})
		attemptExecution := model.RunAttemptIdentity{RepositoryID: model.RepositoryID(h.target.repository.ID), RunID: model.WorkflowRunID(h.runID), RunAttempt: model.RunAttempt(h.bundle.Attempt)}
		recordedEvidenceIDs := model.SortEvidenceIDs([]model.EvidenceID{attemptEvidenceID, hash.evidenceID})
		h.result.facts = append(h.result.facts, archive.Fact{Kind: archive.FactDependency, EvidenceIDs: recordedEvidenceIDs, Dependency: &archive.DependencyFact{
			Relation: archive.DependencyWorkflowCalledWorkflow, TargetKind: archive.DependencyTargetReusableWorkflow,
			Basis: archive.DefinitionRuntimeAttemptMetadata, CallerRepositoryID: model.RepositoryID(h.target.repository.ID),
			CallerRepository: h.target.slug, CallerPath: string(*callerPath), TargetRepository: slug, TargetPath: string(targetPath),
			DeclaredRef: safeField(declaredRef, 1024), TargetCalledWorkflowObjectID: &calledID, AttemptExecution: &attemptExecution,
			ContradictsFactIDs: []string{}, EventTime: h.event,
		}})
		if !refCompatible {
			if appendErr := appendGap(h.result, collect.Gap{Reason: collect.GapValidation, Scope: "called_workflow_metadata", RepositoryID: h.target.repository.ID, RunID: h.runID, Attempt: h.bundle.Attempt, Material: true, Diagnostic: "the caller literal in referenced-workflow path was absent or incompatible with GitHub's separately recorded ref; runtime caller binding was withheld"}); appendErr != nil {
				return appendErr
			}
		}

		// A value named SHA by the run-attempt API is still a Git object ID. It
		// may identify an annotated tag object, so it must not be used as a
		// repository-content commit until GitHub has positively typed and peeled
		// it. The observation and runtime-attempt fact above intentionally retain
		// the recorded object unchanged regardless of peel success.
		if h.peeler == nil {
			if appendErr := appendGap(h.result, collect.Gap{Reason: collect.GapValidation, Scope: "called_workflow_definition", RepositoryID: h.target.repository.ID, RunID: h.runID, Attempt: h.bundle.Attempt, Material: true, Diagnostic: "the configured GitHub adapter does not expose positive called-workflow Git object typing"}); appendErr != nil {
				return appendErr
			}
			continue
		}
		peeledCommit, peelEvidenceID, ok, peelErr := h.peelCalledWorkflowObject(ctx, slug, object)
		if peelErr != nil {
			return peelErr
		}
		if !ok {
			continue
		}

		repositoryID := int64(0)
		if slug == h.target.slug {
			repositoryID = h.target.repository.ID
		}
		parts := strings.SplitN(string(slug), "/", 2)
		definition := resolve.DefinitionKey{Repository: resolve.Repository{ID: repositoryID, Owner: parts[0], Name: parts[1]}, Path: string(targetPath), Commit: resolve.GitObject{Algorithm: string(peeledCommit.Algorithm), Value: peeledCommit.Value}}
		evidenceIDs := model.SortEvidenceIDs(append(append([]model.EvidenceID(nil), recordedEvidenceIDs...), peelEvidenceID))
		stringsEvidence := make([]string, len(evidenceIDs))
		for index, evidenceID := range evidenceIDs {
			stringsEvidence[index] = string(evidenceID)
		}
		resolved := resolve.ResolvedWorkflow{Definition: definition, EvidenceIDs: stringsEvidence}
		h.workflows = append(h.workflows, historicalWorkflowRoot{resolved: resolved, event: h.event, scope: "called_workflow_definition", basis: "runtime-attempt-object-peel"})
		if refCompatible {
			ref := workflow.Reference{Kind: workflow.ReferenceReusableWorkflow, Owner: definition.Repository.Owner, Repository: definition.Repository.Name, Subpath: definition.Path, Ref: declaredRef}
			if key := resolve.ReferenceBindingKey(resolve.Repository{}, ref); key != "" {
				h.workflowRefs[key] = append(h.workflowRefs[key], resolved)
			}
		}
		h.algorithms[string(slug)] = hash.algorithm
	}
	return nil
}

func (h *historicalAttempt) resolveActions(ctx context.Context) error {
	resolver := resolve.Resolver{Source: h.source, Limits: workflow.DefaultLimits(), MaxDepth: historicalResolutionDepth}
	for _, root := range h.actions {
		if err := ctx.Err(); err != nil {
			return err
		}
		resolved, err := resolver.ResolveAction(ctx, root.resolved, resolve.ResolutionInputs{
			RuntimeActions: root.bindings, RuntimeCalledWorkflows: h.workflowRefs, RepositoryHashAlgorithms: h.algorithms,
			PreserveLocalWorkspaceOnly: true,
		})
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return err
			}
			if appendErr := appendGap(h.result, collect.Gap{Reason: collect.GapValidation, Scope: "action_definition", RepositoryID: h.target.repository.ID, RunID: h.runID, Attempt: h.bundle.Attempt, JobID: int64(root.execution.JobID), Material: true, Diagnostic: "exact Action metadata could not be parsed within hostile-input limits"}); appendErr != nil {
				return appendErr
			}
			continue
		}
		if err := h.persistResolution(resolved, &root.execution, nil, root.event, ""); err != nil {
			return err
		}
	}
	return nil
}

func (h *historicalAttempt) resolveWorkflows(ctx context.Context) error {
	resolver := resolve.Resolver{Source: h.source, Limits: workflow.DefaultLimits(), MaxDepth: historicalResolutionDepth}
	attemptIdentity := model.RunAttemptIdentity{RepositoryID: model.RepositoryID(h.target.repository.ID), RunID: model.WorkflowRunID(h.runID), RunAttempt: model.RunAttempt(h.bundle.Attempt)}
	documents := make([]historicalExposureDocument, 0, len(h.workflows)+1)
	roots := make([]historicalWorkflowRoot, 0, len(h.workflows)+1)
	if h.caller != nil {
		roots = append(roots, *h.caller)
	}
	roots = append(roots, h.workflows...)
	for _, root := range roots {
		if err := ctx.Err(); err != nil {
			return err
		}
		content, fetchErr := h.source.Fetch(ctx, root.resolved.Definition)
		if fetchErr != nil {
			if errors.Is(fetchErr, context.Canceled) || errors.Is(fetchErr, context.DeadlineExceeded) {
				return fetchErr
			}
			if errors.Is(fetchErr, resolve.ErrContentNotFound) {
				diagnostic := "GitHub-recorded exact called-workflow content was deleted or unavailable"
				if root.scope == "historical_workflow" {
					diagnostic = "event-specific exact caller workflow content was deleted or unavailable"
				}
				if appendErr := appendGap(h.result, collect.Gap{Reason: collect.GapNotFound, Scope: root.scope, RepositoryID: h.target.repository.ID, RunID: h.runID, Attempt: h.bundle.Attempt, Material: true, Diagnostic: diagnostic}); appendErr != nil {
					return appendErr
				}
			}
			if root.scope == "historical_workflow" {
				h.result.historicalGaps++
			}
			continue
		}
		resolved, err := resolver.ResolveWorkflow(ctx, root.resolved.Definition, content, resolve.ResolutionInputs{
			RuntimeActions: h.actionLookup, RuntimeCalledWorkflows: h.workflowRefs, RepositoryHashAlgorithms: h.algorithms,
			PreserveLocalWorkspaceOnly: true,
		})
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return err
			}
			diagnostic := "exact called-workflow YAML could not be parsed within hostile-input limits"
			if root.scope == "historical_workflow" {
				diagnostic = "exact caller workflow YAML could not be parsed within hostile-input limits"
				h.result.historicalGaps++
			}
			if appendErr := appendGap(h.result, collect.Gap{Reason: collect.GapValidation, Scope: root.scope, RepositoryID: h.target.repository.ID, RunID: h.runID, Attempt: h.bundle.Attempt, Material: true, Diagnostic: diagnostic}); appendErr != nil {
				return appendErr
			}
			continue
		}
		if err := h.persistResolution(resolved, nil, &attemptIdentity, root.event, root.scope); err != nil {
			return err
		}
		parsed, diagnostics, parseErr := workflow.ParseWorkflow(content.Bytes, workflow.DefaultLimits())
		if parseErr == nil && len(diagnostics) == 0 {
			evidenceID := model.EvidenceID(content.EvidenceID)
			if err := evidenceID.Validate(); err != nil {
				return errors.New("exact historical workflow content had an invalid evidence identity")
			}
			documents = append(documents, historicalExposureDocument{root: root, workflow: parsed, evidenceID: evidenceID})
		}
	}
	return h.projectHistoricalExposures(documents)
}

func (h *historicalAttempt) repositoryHash(ctx context.Context, slug model.RepositorySlug, gapScope string) (historicalHashResult, error) {
	if cached, ok := h.hashes[slug]; ok {
		return cached, cached.err
	}
	owner, name := splitSlug(slug)
	started := model.MustInstant(h.now().UTC())
	response, err := h.collector.API.GetRepositoryHashAlgorithm(ctx, owner, name)
	ended := model.MustInstant(h.now().UTC())
	if err != nil {
		cached := historicalHashResult{err: err}
		h.hashes[slug] = cached
		gap := collect.GapFromError(gapScope, h.target.repository.ID, h.runID, h.bundle.Attempt, err)
		gap.Diagnostic = "target repository hash algorithm was unavailable; no Action or workflow object type was guessed"
		if appendErr := appendGap(h.result, gap); appendErr != nil {
			return cached, appendErr
		}
		return cached, err
	}
	if response.Value != string(model.HashSHA1) && response.Value != string(model.HashSHA256) {
		err = errors.New("GitHub returned an unsupported target repository hash algorithm")
		cached := historicalHashResult{err: err}
		h.hashes[slug] = cached
		if appendErr := appendGap(h.result, collect.Gap{Reason: collect.GapMalformedResponse, Scope: gapScope, RepositoryID: h.target.repository.ID, RunID: h.runID, Attempt: h.bundle.Attempt, Material: true, Diagnostic: err.Error()}); appendErr != nil {
			return cached, appendErr
		}
		return cached, err
	}
	projection := struct {
		Schema     string               `json:"schema"`
		Repository string               `json:"repository"`
		Algorithm  string               `json:"algorithm"`
		Responses  []responseProjection `json:"responses"`
	}{"cirewind.github-target-hash-projection/v1", string(slug), response.Value, projectResponses(response.Responses)}
	payload, envelope, buildErr := compactEnvelopeAt(
		h.sessionID, scopedRequestID("target-hash-algorithm", h.scope, string(slug)), "normalized:github:target-repository-hash-algorithm:"+safeKey(string(slug)),
		evidence.SourceAPIJSON, githubapi.APIVersion, "/repos/{owner}/{repo}/hash-algorithm", evidence.RequestParameters{"owner": owner, "repo": name},
		h.scope, h.event, projection, started, ended,
	)
	if buildErr != nil {
		return historicalHashResult{}, fmt.Errorf("construct target repository hash evidence: %w", buildErr)
	}
	h.result.payloads = append(h.result.payloads, payload)
	h.result.evidence = append(h.result.evidence, envelope)
	cached := historicalHashResult{algorithm: response.Value, evidenceID: envelope.Evidence.ID}
	h.hashes[slug] = cached
	h.algorithms[string(slug)] = response.Value
	return cached, nil
}

func calledWorkflowTarget(caller model.RepositorySlug, referenced githubapi.ReferencedWorkflow) (model.RepositorySlug, model.WorkflowPath, string, string, bool, error) {
	value := referenced.Path
	recordedRef := referenced.Ref
	if value == "" || len(value) > 4096 || safeField(value, 4096) != value {
		return "", "", "", "", false, errors.New("called workflow path is unsafe or exceeds its limit")
	}
	if len(recordedRef) > 1024 || safeField(recordedRef, 1024) != recordedRef {
		return "", "", "", "", false, errors.New("called workflow recorded ref is unsafe or exceeds its limit")
	}
	declaredRef := ""
	if at := strings.LastIndexByte(value, '@'); at > 0 {
		declaredRef = value[at+1:]
		if declaredRef == "" || len(declaredRef) > 1024 || safeField(declaredRef, 1024) != declaredRef {
			return "", "", "", "", false, errors.New("called workflow caller ref is unsafe or exceeds its limit")
		}
		value = value[:at]
	}
	segments := strings.Split(value, "/")
	var slug model.RepositorySlug
	var pathValue string
	var err error
	if strings.HasPrefix(value, ".github/workflows/") {
		slug, pathValue = caller, value
	} else if len(segments) >= 4 {
		slug, err = model.NewRepositorySlug(strings.ToLower(segments[0]) + "/" + strings.ToLower(segments[1]))
		pathValue = strings.Join(segments[2:], "/")
	} else {
		return "", "", "", "", false, errors.New("called workflow path is incomplete")
	}
	if err != nil {
		return "", "", "", "", false, err
	}
	workflowPath, err := model.NewWorkflowPath(pathValue)
	if err != nil || !strings.HasPrefix(string(workflowPath), ".github/workflows/") {
		return "", "", "", "", false, errors.New("called workflow path is unsafe or outside .github/workflows")
	}
	return slug, workflowPath, declaredRef, recordedRef, compatibleCalledWorkflowRefs(declaredRef, recordedRef), nil
}

func compatibleCalledWorkflowRefs(declaredRef, recordedRef string) bool {
	if declaredRef == "" {
		return false
	}
	if recordedRef == "" || recordedRef == declaredRef {
		return true
	}
	return recordedRef == "refs/tags/"+declaredRef || recordedRef == "refs/heads/"+declaredRef
}

func mergeStringEvidence(left, right []string) []string {
	values := append(append([]string(nil), left...), right...)
	sort.Strings(values)
	write := 0
	for _, value := range values {
		if value == "" || (write > 0 && values[write-1] == value) {
			continue
		}
		values[write] = value
		write++
	}
	return values[:write]
}
