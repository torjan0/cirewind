package livecollect

import (
	"errors"
	"fmt"
	"strings"

	"github.com/torjan0/cirewind/internal/archive"
	"github.com/torjan0/cirewind/internal/collect"
	"github.com/torjan0/cirewind/internal/model"
	"github.com/torjan0/cirewind/internal/resolve"
	"github.com/torjan0/cirewind/internal/workflow"
)

func (h *historicalAttempt) persistResolution(resolution resolve.Result, execution *model.JobExecutionIdentity, attempt *model.RunAttemptIdentity, event model.EventInterval, workflowScope string) error {
	nodes := make(map[string]resolve.Node, len(resolution.Nodes))
	for _, node := range resolution.Nodes {
		nodes[node.ID] = node
		evidenceID := model.EvidenceID(node.EvidenceID)
		if evidenceID.Validate() != nil {
			return fmt.Errorf("historical resolver node has invalid evidence identity")
		}
		scope := h.scope
		kind, logicalPrefix := model.CoverageWorkflowDefinition, "called_workflow_definition"
		if node.Kind == resolve.NodeAction {
			kind, logicalPrefix = model.CoverageActionDefinition, "action_definition"
			h.result.actionDefinitions++
		} else {
			h.result.workflowDefinitions++
			if workflowScope != "" {
				logicalPrefix = workflowScope
			}
			if workflowScope == "historical_workflow" {
				h.result.callerWorkflowDefinitions++
			} else {
				h.result.calledWorkflowDefinitions++
			}
		}
		if execution != nil {
			jobID := execution.JobID
			scope.JobID = &jobID
		}
		if err := appendCollectedCoverage(h.result, kind, scope, logicalPrefix+":"+safeKey(node.ID), 1, []model.EvidenceID{evidenceID}, true); err != nil {
			return err
		}
	}

	for _, edge := range resolution.Edges {
		caller, ok := nodes[edge.From]
		if !ok {
			return errors.New("historical resolver edge omitted its caller definition")
		}
		if edge.Declaration.Kind == workflow.ReferenceDynamic || edge.Declaration.Kind == workflow.ReferenceDocker {
			if edge.GapCode != "" {
				if err := h.appendResolutionGap(edge.GapCode, execution, "opaque or dynamic Action declaration was preserved without invented repository identity"); err != nil {
					return err
				}
			}
			continue
		}
		if err := h.persistResolutionEdge(caller, edge, execution, attempt, event); err != nil {
			return err
		}
		if edge.GapCode != "" && edge.GapCode != "HISTORICAL_CONTENT_MISSING" && edge.GapCode != "CONTENT_FETCH_FAILED" {
			if err := h.appendResolutionGap(edge.GapCode, execution, resolutionGapMessage(edge)); err != nil {
				return err
			}
		}
	}
	for _, diagnostic := range resolution.Diagnostics {
		if diagnostic.Code == "CONTENT_FETCH_FAILED" {
			// The exact-content boundary already persisted the typed API/decoder
			// failure with its response class and scope.
			continue
		}
		if diagnostic.Code == "HISTORICAL_CONTENT_MISSING" {
			scope := "action_definition"
			if strings.Contains(diagnostic.Definition, ":.github/workflows/") {
				scope = "called_workflow_definition"
			}
			if err := h.appendResolutionGapInScope(diagnostic.Code, scope, execution, "exact historical Action or workflow metadata was deleted or unavailable"); err != nil {
				return err
			}
			continue
		}
		if err := h.appendResolutionGap(diagnostic.Code, execution, "historical resolver reported "+safeMachine(diagnostic.Code, 128)); err != nil {
			return err
		}
	}
	return nil
}

func (h *historicalAttempt) persistResolutionEdge(caller resolve.Node, edge resolve.Edge, execution *model.JobExecutionIdentity, attempt *model.RunAttemptIdentity, event model.EventInterval) error {
	targetRepository, targetPath, targetKind, err := resolutionTarget(caller.Definition.Repository, edge)
	if err != nil {
		return h.appendResolutionGap("UNSAFE_DEPENDENCY_TARGET", execution, "parsed historical dependency target was unsafe")
	}
	callerRepository, err := model.NewRepositorySlug(strings.ToLower(caller.Definition.Repository.Owner) + "/" + strings.ToLower(caller.Definition.Repository.Name))
	if err != nil {
		return err
	}
	dependency := archive.DependencyFact{
		Relation: relationForEdge(edge.Kind), TargetKind: targetKind, Basis: archive.DefinitionHistoricalAtRun,
		CallerRepositoryID: model.RepositoryID(h.target.repository.ID), CallerRepository: callerRepository,
		CallerPath: caller.Definition.Path, TargetRepository: targetRepository, TargetPath: targetPath,
		DeclaredRef: safeField(edge.Declaration.Ref, 1024), TransitiveDepth: edge.Depth,
		Execution: execution, AttemptExecution: attempt, ContradictsFactIDs: []string{}, EventTime: event,
	}
	if caller.Kind == resolve.NodeWorkflow {
		object, err := model.NewGitObjectID(model.HashAlgorithm(caller.Definition.Commit.Algorithm), caller.Definition.Commit.Value)
		if err != nil {
			return err
		}
		callerID, err := model.NewCallerWorkflowObjectID(object)
		if err != nil {
			return err
		}
		dependency.CallerWorkflowObjectID = &callerID
	} else {
		object, err := model.NewGitObjectID(model.HashAlgorithm(caller.Definition.Commit.Algorithm), caller.Definition.Commit.Value)
		if err != nil {
			return err
		}
		callerID, err := model.NewActionSourceObjectID(object)
		if err != nil {
			return err
		}
		dependency.CallerActionObjectID = &callerID
	}
	staticObject, hasStaticObject := h.staticTargetObject(caller.Definition, edge, targetRepository)
	if hasStaticObject {
		if targetKind == archive.DependencyTargetReusableWorkflow {
			value, err := model.NewCalledWorkflowObjectID(staticObject)
			if err != nil {
				return err
			}
			dependency.TargetCalledWorkflowObjectID = &value
		} else {
			value, err := model.NewActionSourceObjectID(staticObject)
			if err != nil {
				return err
			}
			dependency.TargetActionObjectID = &value
		}
	}
	parentEvidence := model.EvidenceID(caller.EvidenceID)
	static, err := archive.NormalizeFact(archive.Fact{Kind: archive.FactDependency, EvidenceIDs: []model.EvidenceID{parentEvidence}, Dependency: &dependency})
	if err != nil {
		return fmt.Errorf("normalize historical declaration fact: %w", err)
	}
	h.result.facts = append(h.result.facts, static)

	if !edge.RuntimeBound || edge.ResolvedDefinition == nil {
		return nil
	}
	runtimeObject, err := model.NewGitObjectID(model.HashAlgorithm(edge.ResolvedDefinition.Commit.Algorithm), edge.ResolvedDefinition.Commit.Value)
	if err != nil {
		return err
	}
	runtime := dependency
	runtime.Relation = archive.DependencyRefResolvedTo
	runtime.TargetActionObjectID = nil
	runtime.TargetCalledWorkflowObjectID = nil
	if targetKind == archive.DependencyTargetReusableWorkflow {
		value, err := model.NewCalledWorkflowObjectID(runtimeObject)
		if err != nil {
			return err
		}
		runtime.TargetCalledWorkflowObjectID = &value
	} else {
		value, err := model.NewActionSourceObjectID(runtimeObject)
		if err != nil {
			return err
		}
		runtime.TargetActionObjectID = &value
	}
	if hasStaticObject && staticObject != runtimeObject {
		runtime.ContradictsFactIDs = []string{static.ID}
	}
	runtimeEvidence, err := resolutionEvidenceIDs(edge.EvidenceIDs)
	if err != nil {
		return err
	}
	runtimeFact, err := archive.NormalizeFact(archive.Fact{Kind: archive.FactDependency, EvidenceIDs: runtimeEvidence, Dependency: &runtime})
	if err != nil {
		return fmt.Errorf("normalize historical runtime resolution fact: %w", err)
	}
	h.result.facts = append(h.result.facts, runtimeFact)
	return nil
}

func resolutionTarget(caller resolve.Repository, edge resolve.Edge) (model.RepositorySlug, string, archive.DependencyTargetKind, error) {
	ref := edge.Declaration
	owner, repository := ref.Owner, ref.Repository
	if ref.Kind == workflow.ReferenceSelfRepository || ref.Kind == workflow.ReferenceLocalWorkspace {
		owner, repository = caller.Owner, caller.Name
	}
	slug, err := model.NewRepositorySlug(strings.ToLower(owner) + "/" + strings.ToLower(repository))
	if err != nil {
		return "", "", "", err
	}
	targetPath, err := workflow.NormalizeRepositoryPath(ref.Subpath)
	if err != nil {
		return "", "", "", err
	}
	if edge.Kind == resolve.EdgeWorkflowCalledWorkflow {
		if targetPath == "" {
			return "", "", "", errors.New("reusable workflow path is absent")
		}
		return slug, targetPath, archive.DependencyTargetReusableWorkflow, nil
	}
	if ref.Kind == workflow.ReferenceLocalWorkspace {
		return slug, targetPath, archive.DependencyTargetLocalAction, nil
	}
	return slug, targetPath, archive.DependencyTargetAction, nil
}

func relationForEdge(kind resolve.EdgeKind) archive.DependencyRelation {
	switch kind {
	case resolve.EdgeWorkflowDeclaredAction:
		return archive.DependencyWorkflowDeclaredAction
	case resolve.EdgeWorkflowCalledWorkflow:
		return archive.DependencyWorkflowCalledWorkflow
	default:
		return archive.DependencyActionContainsAction
	}
}

func (h *historicalAttempt) staticTargetObject(caller resolve.DefinitionKey, edge resolve.Edge, target model.RepositorySlug) (model.GitObjectID, bool) {
	if edge.Declaration.Kind == workflow.ReferenceSelfRepository || (edge.Kind == resolve.EdgeWorkflowCalledWorkflow && edge.Declaration.Kind == workflow.ReferenceLocalWorkspace) {
		object, err := model.NewGitObjectID(model.HashAlgorithm(caller.Commit.Algorithm), caller.Commit.Value)
		return object, err == nil
	}
	if edge.Declaration.Kind == workflow.ReferenceLocalWorkspace || edge.Declaration.Ref == "" {
		return model.GitObjectID{}, false
	}
	algorithm := h.algorithms[string(target)]
	if algorithm == "" {
		return model.GitObjectID{}, false
	}
	object, err := model.NewGitObjectID(model.HashAlgorithm(algorithm), strings.ToLower(edge.Declaration.Ref))
	return object, err == nil
}

func resolutionEvidenceIDs(values []string) ([]model.EvidenceID, error) {
	result := make([]model.EvidenceID, 0, len(values))
	for _, value := range values {
		id := model.EvidenceID(value)
		if err := id.Validate(); err != nil {
			return nil, errors.New("historical resolver edge has invalid evidence identity")
		}
		result = append(result, id)
	}
	result = model.SortEvidenceIDs(result)
	if len(result) == 0 {
		return nil, errors.New("historical resolver edge has no supporting evidence")
	}
	return result, nil
}

func (h *historicalAttempt) appendResolutionGap(code string, execution *model.JobExecutionIdentity, message string) error {
	scope := "action_definition"
	if strings.Contains(code, "WORKFLOW") {
		scope = "called_workflow_definition"
	}
	return h.appendResolutionGapInScope(code, scope, execution, message)
}

func (h *historicalAttempt) appendResolutionGapInScope(code, scope string, execution *model.JobExecutionIdentity, message string) error {
	jobID := int64(0)
	if execution != nil {
		jobID = int64(execution.JobID)
	}
	reason := collect.GapValidation
	if strings.Contains(code, "MISSING") {
		reason = collect.GapNotFound
	}
	return appendGap(h.result, collect.Gap{Reason: reason, Scope: scope, RepositoryID: h.target.repository.ID, RunID: h.runID, Attempt: h.bundle.Attempt, JobID: jobID, Material: true, Diagnostic: safeField(message, 2048)})
}

func resolutionGapMessage(edge resolve.Edge) string {
	switch edge.GapCode {
	case "LOCAL_WORKSPACE_BYTES_UNPROVEN":
		return "local Action workspace bytes were not established at an exact object; repository content was not substituted"
	case "ACTION_RUNTIME_IDENTITY_MISSING":
		return "mutable Action declaration had no unique exact runtime source object"
	case "ACTION_RUNTIME_IDENTITY_AMBIGUOUS":
		return "mutable Action declaration matched more than one exact runtime source object"
	case "CALLED_WORKFLOW_IDENTITY_MISSING":
		return "reusable workflow declaration had no GitHub-recorded exact called-workflow identity"
	case "CALLED_WORKFLOW_IDENTITY_AMBIGUOUS":
		return "reusable workflow declaration matched more than one GitHub-recorded exact called-workflow identity"
	case "RESOLUTION_DEPTH_LIMIT":
		return "historical dependency resolution stopped at the compiled depth limit"
	default:
		return "historical dependency resolution remained incomplete: " + safeMachine(edge.GapCode, 128)
	}
}
