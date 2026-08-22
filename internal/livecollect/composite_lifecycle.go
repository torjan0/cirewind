package livecollect

import (
	"context"
	"errors"
	"sort"
	"strings"

	"github.com/torjan0/cirewind/internal/model"
	"github.com/torjan0/cirewind/internal/resolve"
	"github.com/torjan0/cirewind/internal/workflow"
)

// historicalCompositeBinding describes the only composite child lifecycle
// that v0.1 can promote safely: the exact parent's first unconditional
// repository-Action operation. A later composite group is application-output
// adjacent and therefore spoofable without stronger runner timeline evidence.
type historicalCompositeBinding struct {
	childDeclaration string
	childDisplayName string
	childDefinition  resolve.DefinitionKey
	childASTOrdinal  model.ASTOrdinal
	evidenceIDs      []model.EvidenceID
}

// prepareCompositeLifecycleBindings parses no logs and executes no Action
// code. It resolves exact Action metadata already anchored by same-attempt
// setup SHAs, then retains only a structurally unique first-child binding.
func (h *historicalAttempt) prepareCompositeLifecycleBindings(ctx context.Context, setup map[int64]map[string][]setupResolution) error {
	if h.compositePrepared {
		return nil
	}
	h.compositePrepared = true
	if h.exact == nil {
		return nil
	}
	if err := h.prepareActions(ctx, setup); err != nil {
		return err
	}
	h.ensureContentSource()
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
			continue
		}
		binding, ok, err := deriveHistoricalCompositeBinding(ctx, h.source, root.resolved, resolved)
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return err
			}
			continue
		}
		if !ok {
			continue
		}
		jobID := int64(root.execution.JobID)
		key := resolvedActionLifecycleIdentity(root.resolved)
		if key == "" {
			continue
		}
		if h.compositeBindings[jobID] == nil {
			h.compositeBindings[jobID] = make(map[string]historicalCompositeBinding)
		}
		if existing, exists := h.compositeBindings[jobID][key]; exists {
			if existing.childDeclaration != binding.childDeclaration || existing.childDisplayName != binding.childDisplayName || existing.childDefinition.String() != binding.childDefinition.String() {
				delete(h.compositeBindings[jobID], key)
				continue
			}
			existing.evidenceIDs = model.SortEvidenceIDs(append(existing.evidenceIDs, binding.evidenceIDs...))
			h.compositeBindings[jobID][key] = existing
			continue
		}
		h.compositeBindings[jobID][key] = binding
	}
	return nil
}

func deriveHistoricalCompositeBinding(ctx context.Context, source resolve.ContentSource, root resolve.ResolvedAction, result resolve.Result) (historicalCompositeBinding, bool, error) {
	rootNodes := make([]resolve.Node, 0, 1)
	for _, node := range result.Nodes {
		if node.Kind == resolve.NodeAction && actionNodeMatchesResolved(node, root) {
			rootNodes = append(rootNodes, node)
		}
	}
	if len(rootNodes) != 1 || rootNodes[0].ActionKind != "composite" {
		return historicalCompositeBinding{}, false, nil
	}
	rootNode := rootNodes[0]
	content, err := source.Fetch(ctx, rootNode.Definition)
	if err != nil {
		return historicalCompositeBinding{}, false, err
	}
	metadata, diagnostics, err := workflow.ParseAction(content.Bytes, workflow.DefaultLimits())
	if err != nil || len(diagnostics) != 0 || metadata.Using != "composite" || len(metadata.Steps) == 0 {
		return historicalCompositeBinding{}, false, err
	}
	first := metadata.Steps[0]
	if first.Ordinal != 1 || first.Condition != "" || first.Uses == nil || first.Uses.Kind != workflow.ReferenceRepository || first.Name == "" || strings.Contains(first.Name, "${{") {
		return historicalCompositeBinding{}, false, nil
	}
	edges := make([]resolve.Edge, 0, 1)
	for _, edge := range result.Edges {
		if edge.Kind == resolve.EdgeActionContainsAction && edge.From == rootNode.ID && edge.Declaration.Span.Path == first.Uses.Span.Path {
			edges = append(edges, edge)
		}
	}
	if len(edges) != 1 {
		return historicalCompositeBinding{}, false, nil
	}
	edge := edges[0]
	if !edge.Exact || !edge.RuntimeBound || edge.GapCode != "" || edge.ResolvedDefinition == nil || edge.To == "" {
		return historicalCompositeBinding{}, false, nil
	}
	children := make([]resolve.Node, 0, 1)
	for _, node := range result.Nodes {
		if node.ID == edge.To && node.Kind == resolve.NodeAction && actionNodeMatchesDefinitionBase(node, *edge.ResolvedDefinition) {
			children = append(children, node)
		}
	}
	if len(children) != 1 || children[0].ActionKind == "" {
		return historicalCompositeBinding{}, false, nil
	}
	evidenceIDs, ok := validatedCompositeEvidence(rootNode, edge, children[0], content.EvidenceID)
	if !ok {
		return historicalCompositeBinding{}, false, nil
	}
	return historicalCompositeBinding{
		childDeclaration: first.Uses.Raw,
		childDisplayName: first.Name,
		childDefinition:  children[0].Definition,
		childASTOrdinal:  model.ASTOrdinal(first.Ordinal),
		evidenceIDs:      evidenceIDs,
	}, true, nil
}

func validatedCompositeEvidence(root resolve.Node, edge resolve.Edge, child resolve.Node, contentEvidence string) ([]model.EvidenceID, bool) {
	values := make([]string, 0, len(root.EvidenceIDs)+len(edge.EvidenceIDs)+len(child.EvidenceIDs)+4)
	values = append(values, root.EvidenceID, contentEvidence, child.EvidenceID)
	values = append(values, root.EvidenceIDs...)
	values = append(values, edge.EvidenceIDs...)
	values = append(values, child.EvidenceIDs...)
	sort.Strings(values)
	result := make([]model.EvidenceID, 0, len(values))
	for _, value := range values {
		if value == "" || (len(result) > 0 && string(result[len(result)-1]) == value) {
			continue
		}
		id := model.EvidenceID(value)
		if id.Validate() != nil {
			return nil, false
		}
		result = append(result, id)
	}
	return result, len(result) > 0
}

func actionNodeMatchesResolved(node resolve.Node, action resolve.ResolvedAction) bool {
	definition := node.Definition
	return strings.EqualFold(definition.Repository.Owner, action.Repository.Owner) &&
		strings.EqualFold(definition.Repository.Name, action.Repository.Name) &&
		definition.Commit.Algorithm == action.Commit.Algorithm && strings.EqualFold(definition.Commit.Value, action.Commit.Value) &&
		actionMetadataPathMatches(definition.Path, action.Subpath)
}

func actionNodeMatchesDefinitionBase(node resolve.Node, base resolve.DefinitionKey) bool {
	return strings.EqualFold(node.Definition.Repository.Owner, base.Repository.Owner) &&
		strings.EqualFold(node.Definition.Repository.Name, base.Repository.Name) &&
		node.Definition.Commit.Algorithm == base.Commit.Algorithm && strings.EqualFold(node.Definition.Commit.Value, base.Commit.Value) &&
		actionMetadataPathMatches(node.Definition.Path, base.Path)
}

func actionMetadataPathMatches(metadataPath, subpath string) bool {
	prefix := strings.TrimSuffix(subpath, "/")
	if prefix != "" {
		prefix += "/"
	}
	return metadataPath == prefix+"action.yml" || metadataPath == prefix+"action.yaml"
}

func resolvedActionLifecycleIdentity(action resolve.ResolvedAction) string {
	if action.Repository.Owner == "" || action.Repository.Name == "" || action.Commit.Algorithm == "" || action.Commit.Value == "" {
		return ""
	}
	return strings.ToLower(action.Repository.Owner) + "/" + strings.ToLower(action.Repository.Name) + "/" + action.Subpath + "@" + action.Commit.Algorithm + ":" + strings.ToLower(action.Commit.Value)
}

func setupActionLifecycleIdentity(action setupResolution) string {
	value := action.action
	if value.Owner == "" || value.Repository == "" || value.Source.Algorithm == "" || value.Source.Value == "" {
		return ""
	}
	return strings.ToLower(value.Owner) + "/" + strings.ToLower(value.Repository) + "/" + value.Subpath + "@" + value.Source.Algorithm + ":" + strings.ToLower(value.Source.Value)
}

func (h *historicalAttempt) compositeBinding(jobID int64, parent setupResolution) (*historicalCompositeBinding, bool) {
	key := setupActionLifecycleIdentity(parent)
	value, ok := h.compositeBindings[jobID][key]
	if !ok {
		return nil, false
	}
	copy := value
	copy.evidenceIDs = append([]model.EvidenceID(nil), value.evidenceIDs...)
	return &copy, true
}

func setupResolutionMatchesDefinition(value setupResolution, definition resolve.DefinitionKey) bool {
	action := value.action
	return strings.EqualFold(action.Owner, definition.Repository.Owner) &&
		strings.EqualFold(action.Repository, definition.Repository.Name) &&
		action.Source.Algorithm == definition.Commit.Algorithm && strings.EqualFold(action.Source.Value, definition.Commit.Value) &&
		actionMetadataPathMatches(definition.Path, action.Subpath)
}
