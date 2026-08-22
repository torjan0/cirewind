// Package resolve reconstructs workflow and Action dependency declarations
// from exact historical bytes. It has no process, checkout, or execution path.
package resolve

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/torjan0/cirewind/internal/model"
	"github.com/torjan0/cirewind/internal/workflow"
)

var ErrContentNotFound = errors.New("historical content not found")

type Repository struct {
	ID    int64  `json:"id,omitempty"`
	Owner string `json:"owner"`
	Name  string `json:"name"`
}

type GitObject struct {
	Algorithm string `json:"algorithm"`
	Value     string `json:"value"`
}

type DefinitionKey struct {
	Repository Repository `json:"repository"`
	Path       string     `json:"path"`
	Commit     GitObject  `json:"commit"`
}

func (k DefinitionKey) String() string {
	return fmt.Sprintf("%d:%s/%s@%s:%s:%s", k.Repository.ID, strings.ToLower(k.Repository.Owner), strings.ToLower(k.Repository.Name), k.Commit.Algorithm, k.Commit.Value, k.Path)
}

type Content struct {
	Bytes      []byte
	EvidenceID string
}

// ContentSource fetches only content at an exact typed Git object. A GitHub
// implementation must reject branch/tag objects before this boundary.
type ContentSource interface {
	Fetch(ctx context.Context, key DefinitionKey) (Content, error)
}

type ResolvedAction struct {
	Repository  Repository `json:"repository"`
	Subpath     string     `json:"subpath,omitempty"`
	Commit      GitObject  `json:"commit"`
	EvidenceIDs []string   `json:"evidenceIds"`
}

type ResolvedWorkflow struct {
	Definition  DefinitionKey `json:"definition"`
	EvidenceIDs []string      `json:"evidenceIds"`
}

// ResolutionInputs hold exact runtime/API bindings indexed by the declaration
// occurrence key returned by OccurrenceKey.
type ResolutionInputs struct {
	Actions         map[string]ResolvedAction
	CalledWorkflows map[string]ResolvedWorkflow
	// RuntimeActions and RuntimeCalledWorkflows are attempt-scoped fallback
	// bindings keyed by ReferenceBindingKey. They are used only when exactly
	// one immutable identity is observed for that declaration. Occurrence-keyed
	// bindings above remain authoritative because a repeated declaration can
	// otherwise be ambiguous.
	RuntimeActions         map[string][]ResolvedAction
	RuntimeCalledWorkflows map[string][]ResolvedWorkflow
	// RepositoryHashAlgorithms contains independently observed repository
	// object formats keyed by lower-case owner/name. It permits a literal full
	// declaration to be typed without guessing its algorithm from string width.
	RepositoryHashAlgorithms map[string]string
	// PreserveLocalWorkspaceOnly forbids treating repository content as the
	// exact bytes of a ./ Action. Callers set it when checkout/mutation evidence
	// has not established one exact workspace object.
	PreserveLocalWorkspaceOnly bool
	// DeclaredGitObjects contains explicitly typed full immutable refs. The
	// resolver never guesses an algorithm from string width.
	DeclaredGitObjects map[string]GitObject
}

func OccurrenceKey(parent DefinitionKey, span workflow.SourceSpan) string {
	return parent.String() + "#" + span.Path
}

// ReferenceBindingKey returns the attempt-scoped lookup key for a repository
// Action or reusable-workflow declaration. It is deliberately derived only
// from parsed structured fields; raw YAML text is never used as a map key.
func ReferenceBindingKey(parent Repository, ref workflow.Reference) string {
	owner, repository := ref.Owner, ref.Repository
	if ref.Kind == workflow.ReferenceSelfRepository || ref.Kind == workflow.ReferenceLocalWorkspace {
		owner, repository = parent.Owner, parent.Name
	}
	if owner == "" || repository == "" || ref.Ref == "" {
		return ""
	}
	subpath, err := workflow.NormalizeRepositoryPath(ref.Subpath)
	if err != nil {
		return ""
	}
	key := strings.ToLower(owner) + "/" + strings.ToLower(repository)
	if subpath != "" {
		key += "/" + subpath
	}
	return key + "@" + ref.Ref
}

type NodeKind string

const (
	NodeWorkflow NodeKind = "WorkflowDefinition"
	NodeAction   NodeKind = "ActionDefinition"
)

type Node struct {
	ID          string        `json:"id"`
	Kind        NodeKind      `json:"kind"`
	Definition  DefinitionKey `json:"definition"`
	EvidenceID  string        `json:"evidenceId"`
	EvidenceIDs []string      `json:"evidenceIds,omitempty"`
	ActionKind  string        `json:"actionKind,omitempty"`
}

type EdgeKind string

const (
	EdgeWorkflowDeclaredAction EdgeKind = "WORKFLOW_DECLARED_ACTION"
	EdgeWorkflowCalledWorkflow EdgeKind = "WORKFLOW_CALLED_WORKFLOW"
	EdgeActionContainsAction   EdgeKind = "ACTION_CONTAINS_ACTION"
)

type Edge struct {
	ID                 string             `json:"id"`
	Kind               EdgeKind           `json:"kind"`
	From               string             `json:"from"`
	To                 string             `json:"to,omitempty"`
	Declaration        workflow.Reference `json:"declaration"`
	Exact              bool               `json:"exact"`
	RuntimeBound       bool               `json:"runtimeBound"`
	Depth              uint32             `json:"depth"`
	ResolvedDefinition *DefinitionKey     `json:"resolvedDefinition,omitempty"`
	WorkspaceUncertain bool               `json:"workspaceUncertain,omitempty"`
	EvidenceIDs        []string           `json:"evidenceIds"`
	GapCode            string             `json:"gapCode,omitempty"`
}

type Diagnostic struct {
	Code        string   `json:"code"`
	Definition  string   `json:"definition"`
	Path        string   `json:"path,omitempty"`
	Message     string   `json:"message"`
	EvidenceIDs []string `json:"evidenceIds,omitempty"`
}

type Result struct {
	Nodes       []Node       `json:"nodes"`
	Edges       []Edge       `json:"edges"`
	Diagnostics []Diagnostic `json:"diagnostics,omitempty"`
}

type Resolver struct {
	Source   ContentSource
	Limits   workflow.Limits
	MaxDepth int
}

// ResolveWorkflow reconstructs one exact workflow and reachable definitions.
func (r Resolver) ResolveWorkflow(ctx context.Context, root DefinitionKey, content Content, inputs ResolutionInputs) (Result, error) {
	if err := r.validate(); err != nil {
		return Result{}, err
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	parsed, diagnostics, err := workflow.ParseWorkflow(content.Bytes, r.Limits)
	if err != nil {
		return Result{}, fmt.Errorf("parse root workflow: %w", err)
	}
	result := Result{Nodes: []Node{{ID: nodeID(NodeWorkflow, root), Kind: NodeWorkflow, Definition: root, EvidenceID: content.EvidenceID, EvidenceIDs: sortedUnique([]string{content.EvidenceID})}}}
	for _, diagnostic := range diagnostics {
		result.Diagnostics = append(result.Diagnostics, Diagnostic{Code: diagnostic.Code, Definition: root.String(), Path: diagnostic.Path, Message: diagnostic.Message})
	}
	stack := map[string]bool{root.String(): true}
	r.resolveWorkflowParsed(ctx, root, parsed, content.EvidenceID, inputs, 1, stack, &result)
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	sortResult(&result)
	return result, nil
}

// ResolveAction reconstructs one repository Action starting at an exact,
// algorithm-qualified source commit. Subpath is the repository-relative Action
// directory, not a local filesystem path. The resolver fetches only bounded
// metadata YAML and never checks out, imports, builds, or executes Action code.
func (r Resolver) ResolveAction(ctx context.Context, root ResolvedAction, inputs ResolutionInputs) (Result, error) {
	if err := r.validate(); err != nil {
		return Result{}, err
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	normalized, err := normalizeResolvedAction(root, "")
	if err != nil {
		return Result{}, fmt.Errorf("validate root Action: %w", err)
	}
	base := DefinitionKey{Repository: normalized.Repository, Path: normalized.Subpath, Commit: normalized.Commit}
	content, metadataPath, metadataEvidence, ambiguous, fetchErr := r.fetchActionMetadata(ctx, base)
	if fetchErr != nil {
		if cancellationError(ctx, fetchErr) != nil {
			return Result{}, cancellationError(ctx, fetchErr)
		}
		result := Result{Diagnostics: []Diagnostic{{Code: classifyFetch(fetchErr), Definition: base.String(), Message: boundedMessage(fetchErr), EvidenceIDs: sortedUnique(append(append([]string(nil), normalized.EvidenceIDs...), metadataEvidence...))}}}
		sortResult(&result)
		return result, nil
	}
	definition := actionMetadataDefinition(base, metadataPath)
	if ambiguous {
		result := Result{Diagnostics: []Diagnostic{{Code: "AMBIGUOUS_ACTION_METADATA", Definition: base.String(), Message: "both action.yml and action.yaml are present; precedence is not live-validated", EvidenceIDs: sortedUnique(append(append([]string(nil), normalized.EvidenceIDs...), metadataEvidence...))}}}
		sortResult(&result)
		return result, nil
	}
	metadata, diagnostics, err := workflow.ParseAction(content.Bytes, r.Limits)
	if err != nil {
		return Result{}, fmt.Errorf("parse root Action metadata: %w", err)
	}
	rootEvidence := sortedUnique(append(append([]string(nil), normalized.EvidenceIDs...), metadataEvidence...))
	result := Result{Nodes: []Node{{
		ID: nodeID(NodeAction, definition), Kind: NodeAction, Definition: definition,
		EvidenceID: content.EvidenceID, EvidenceIDs: rootEvidence, ActionKind: metadata.Using,
	}}}
	for _, diagnostic := range diagnostics {
		result.Diagnostics = append(result.Diagnostics, Diagnostic{Code: diagnostic.Code, Definition: definition.String(), Path: diagnostic.Path, Message: diagnostic.Message})
	}
	if !metadata.IsLeaf {
		stack := map[string]bool{definition.String(): true}
		for _, child := range metadata.Steps {
			if child.Uses != nil {
				r.resolveAction(ctx, definition, *child.Uses, content.EvidenceID, inputs, 1, stack, EdgeActionContainsAction, &result)
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	sortResult(&result)
	return result, nil
}

func (r Resolver) validate() error {
	if r.Source == nil {
		return errors.New("content source is required")
	}
	if r.MaxDepth <= 0 || r.MaxDepth > 10 {
		return errors.New("resolver depth must be between 1 and 10")
	}
	return nil
}

func (r Resolver) resolveWorkflowParsed(ctx context.Context, parent DefinitionKey, parsed *workflow.Workflow, parentEvidence string, inputs ResolutionInputs, depth int, stack map[string]bool, result *Result) {
	for _, job := range parsed.Jobs {
		if ctx.Err() != nil {
			return
		}
		if job.Uses != nil {
			r.resolveReusable(ctx, parent, *job.Uses, parentEvidence, inputs, depth, stack, result)
		}
		for _, step := range job.Steps {
			if step.Uses != nil {
				r.resolveAction(ctx, parent, *step.Uses, parentEvidence, inputs, depth, stack, EdgeWorkflowDeclaredAction, result)
			}
		}
	}
}

func (r Resolver) resolveReusable(ctx context.Context, parent DefinitionKey, ref workflow.Reference, parentEvidence string, inputs ResolutionInputs, depth int, stack map[string]bool, result *Result) {
	edge := Edge{ID: edgeID(parent, ref, EdgeWorkflowCalledWorkflow), Kind: EdgeWorkflowCalledWorkflow, From: nodeID(NodeWorkflow, parent), Declaration: ref, EvidenceIDs: []string{parentEvidence}, Depth: uint32(depth)}
	if ctx.Err() != nil {
		return
	}
	if depth >= r.MaxDepth {
		edge.GapCode = "RESOLUTION_DEPTH_LIMIT"
		result.Edges = append(result.Edges, edge)
		return
	}
	var target DefinitionKey
	var bindingEvidence []string
	if ref.Kind == workflow.ReferenceLocalWorkspace && strings.HasPrefix(ref.Subpath, ".github/workflows/") {
		target = DefinitionKey{Repository: parent.Repository, Path: ref.Subpath, Commit: parent.Commit}
		edge.Exact = true
	} else if resolved, ok := inputs.CalledWorkflows[OccurrenceKey(parent, ref.Span)]; ok {
		target, bindingEvidence = resolved.Definition, resolved.EvidenceIDs
		edge.Exact, edge.RuntimeBound = true, true
	} else if resolved, ok := uniqueRuntimeWorkflow(inputs.RuntimeCalledWorkflows[ReferenceBindingKey(parent.Repository, ref)]); ok {
		target, bindingEvidence = resolved.Definition, resolved.EvidenceIDs
		edge.Exact, edge.RuntimeBound = true, true
	} else if len(inputs.RuntimeCalledWorkflows[ReferenceBindingKey(parent.Repository, ref)]) > 0 {
		edge.GapCode = "CALLED_WORKFLOW_IDENTITY_AMBIGUOUS"
		result.Edges = append(result.Edges, edge)
		return
	} else if object, ok := declaredReferenceObject(inputs, parent.Repository, ref); ok && ref.Kind == workflow.ReferenceReusableWorkflow {
		normalizedPath, err := workflow.NormalizeRepositoryPath(ref.Subpath)
		if err != nil {
			edge.GapCode = "UNSAFE_WORKFLOW_PATH"
			result.Edges = append(result.Edges, edge)
			return
		}
		target = DefinitionKey{Repository: Repository{Owner: ref.Owner, Name: ref.Repository}, Path: normalizedPath, Commit: object}
		edge.Exact = true
	} else {
		edge.GapCode = "CALLED_WORKFLOW_IDENTITY_MISSING"
		result.Edges = append(result.Edges, edge)
		return
	}
	targetID := nodeID(NodeWorkflow, target)
	edge.To = targetID
	edge.ResolvedDefinition = definitionPointer(target)
	edge.EvidenceIDs = sortedUnique(append(edge.EvidenceIDs, bindingEvidence...))
	result.Edges = append(result.Edges, edge)
	if stack[target.String()] {
		result.Diagnostics = append(result.Diagnostics, Diagnostic{Code: "RESOLUTION_CYCLE", Definition: parent.String(), Path: ref.Span.Path, Message: "reusable workflow cycle detected"})
		return
	}
	content, err := r.Source.Fetch(ctx, target)
	if err != nil {
		result.Diagnostics = append(result.Diagnostics, Diagnostic{Code: classifyFetch(err), Definition: target.String(), Message: boundedMessage(err), EvidenceIDs: edge.EvidenceIDs})
		return
	}
	result.Nodes = append(result.Nodes, Node{ID: targetID, Kind: NodeWorkflow, Definition: target, EvidenceID: content.EvidenceID, EvidenceIDs: sortedUnique([]string{content.EvidenceID})})
	parsed, diagnostics, err := workflow.ParseWorkflow(content.Bytes, r.Limits)
	if err != nil {
		result.Diagnostics = append(result.Diagnostics, Diagnostic{Code: "MALFORMED_WORKFLOW", Definition: target.String(), Message: boundedMessage(err), EvidenceIDs: sortedUnique([]string{content.EvidenceID})})
		return
	}
	for _, diagnostic := range diagnostics {
		result.Diagnostics = append(result.Diagnostics, Diagnostic{Code: diagnostic.Code, Definition: target.String(), Path: diagnostic.Path, Message: diagnostic.Message})
	}
	nextStack := copyStack(stack)
	nextStack[target.String()] = true
	r.resolveWorkflowParsed(ctx, target, parsed, content.EvidenceID, inputs, depth+1, nextStack, result)
}

func (r Resolver) resolveAction(ctx context.Context, parent DefinitionKey, ref workflow.Reference, parentEvidence string, inputs ResolutionInputs, depth int, stack map[string]bool, kind EdgeKind, result *Result) {
	edge := Edge{ID: edgeID(parent, ref, kind), Kind: kind, From: nodeID(definitionNodeKind(parent.Path), parent), Declaration: ref, EvidenceIDs: []string{parentEvidence}, Depth: uint32(depth)}
	if ctx.Err() != nil {
		return
	}
	if ref.Kind == workflow.ReferenceDynamic || ref.Kind == workflow.ReferenceDocker {
		edge.GapCode = "DYNAMIC_OR_OPAQUE_ACTION"
		result.Edges = append(result.Edges, edge)
		return
	}
	if depth >= r.MaxDepth {
		edge.GapCode = "RESOLUTION_DEPTH_LIMIT"
		result.Edges = append(result.Edges, edge)
		return
	}
	occurrence := OccurrenceKey(parent, ref.Span)
	var target DefinitionKey
	var bindingEvidence []string
	switch ref.Kind {
	case workflow.ReferenceSelfRepository:
		normalized, err := workflow.NormalizeRepositoryPath(ref.Subpath)
		if err != nil {
			edge.GapCode = "UNSAFE_ACTION_PATH"
			result.Edges = append(result.Edges, edge)
			return
		}
		target = DefinitionKey{Repository: parent.Repository, Path: normalized, Commit: parent.Commit}
		edge.Exact = true
	case workflow.ReferenceLocalWorkspace:
		normalized, err := workflow.NormalizeRepositoryPath(ref.Subpath)
		if err != nil {
			edge.GapCode = "UNSAFE_ACTION_PATH"
			result.Edges = append(result.Edges, edge)
			return
		}
		target = DefinitionKey{Repository: parent.Repository, Path: normalized, Commit: parent.Commit}
		edge.WorkspaceUncertain = true
		edge.GapCode = "LOCAL_WORKSPACE_BYTES_UNPROVEN"
		if inputs.PreserveLocalWorkspaceOnly {
			result.Edges = append(result.Edges, edge)
			return
		}
	case workflow.ReferenceRepository:
		if resolved, ok := inputs.Actions[occurrence]; ok {
			normalized, err := normalizeResolvedAction(resolved, ref.Subpath)
			if err != nil {
				edge.GapCode = "INVALID_ACTION_RESOLUTION"
				result.Edges = append(result.Edges, edge)
				result.Diagnostics = append(result.Diagnostics, Diagnostic{Code: edge.GapCode, Definition: parent.String(), Path: ref.Span.Path, Message: boundedMessage(err)})
				return
			}
			target = DefinitionKey{Repository: normalized.Repository, Path: normalized.Subpath, Commit: normalized.Commit}
			bindingEvidence = normalized.EvidenceIDs
			edge.Exact, edge.RuntimeBound = true, true
		} else if resolved, ok := uniqueRuntimeAction(inputs.RuntimeActions[ReferenceBindingKey(parent.Repository, ref)], ref.Subpath); ok {
			target = DefinitionKey{Repository: resolved.Repository, Path: resolved.Subpath, Commit: resolved.Commit}
			bindingEvidence = resolved.EvidenceIDs
			edge.Exact, edge.RuntimeBound = true, true
		} else if len(inputs.RuntimeActions[ReferenceBindingKey(parent.Repository, ref)]) > 0 {
			edge.GapCode = "ACTION_RUNTIME_IDENTITY_AMBIGUOUS"
			result.Edges = append(result.Edges, edge)
			return
		} else if oid, ok := inputs.DeclaredGitObjects[occurrence]; ok {
			normalized, err := normalizeResolvedAction(ResolvedAction{
				Repository: Repository{Owner: ref.Owner, Name: ref.Repository},
				Subpath:    ref.Subpath,
				Commit:     oid,
			}, ref.Subpath)
			if err != nil {
				edge.GapCode = "INVALID_ACTION_RESOLUTION"
				result.Edges = append(result.Edges, edge)
				result.Diagnostics = append(result.Diagnostics, Diagnostic{Code: edge.GapCode, Definition: parent.String(), Path: ref.Span.Path, Message: boundedMessage(err)})
				return
			}
			target = DefinitionKey{Repository: normalized.Repository, Path: normalized.Subpath, Commit: normalized.Commit}
			edge.Exact = true
		} else if oid, ok := declaredReferenceObject(inputs, parent.Repository, ref); ok {
			normalized, err := normalizeResolvedAction(ResolvedAction{
				Repository: Repository{Owner: ref.Owner, Name: ref.Repository},
				Subpath:    ref.Subpath,
				Commit:     oid,
			}, ref.Subpath)
			if err != nil {
				edge.GapCode = "INVALID_ACTION_RESOLUTION"
				result.Edges = append(result.Edges, edge)
				result.Diagnostics = append(result.Diagnostics, Diagnostic{Code: edge.GapCode, Definition: parent.String(), Path: ref.Span.Path, Message: boundedMessage(err)})
				return
			}
			target = DefinitionKey{Repository: normalized.Repository, Path: normalized.Subpath, Commit: normalized.Commit}
			edge.Exact = true
		} else {
			edge.GapCode = "ACTION_RUNTIME_IDENTITY_MISSING"
			result.Edges = append(result.Edges, edge)
			return
		}
	default:
		edge.GapCode = "UNSUPPORTED_ACTION_REFERENCE"
		result.Edges = append(result.Edges, edge)
		return
	}

	edge.EvidenceIDs = sortedUnique(append(edge.EvidenceIDs, bindingEvidence...))
	edge.ResolvedDefinition = definitionPointer(target)
	metadataContent, metadataPath, metadataEvidence, ambiguous, err := r.fetchActionMetadata(ctx, target)
	if err != nil {
		if cancellationError(ctx, err) != nil {
			return
		}
		edge.GapCode = classifyFetch(err)
		edge.EvidenceIDs = sortedUnique(append(edge.EvidenceIDs, metadataEvidence...))
		result.Edges = append(result.Edges, edge)
		result.Diagnostics = append(result.Diagnostics, Diagnostic{Code: edge.GapCode, Definition: target.String(), Path: ref.Span.Path, Message: boundedMessage(err), EvidenceIDs: edge.EvidenceIDs})
		return
	}
	definition := actionMetadataDefinition(target, metadataPath)
	targetID := nodeID(NodeAction, definition)
	edge.To = targetID
	edge.EvidenceIDs = sortedUnique(append(edge.EvidenceIDs, metadataEvidence...))
	result.Edges = append(result.Edges, edge)
	if ambiguous {
		result.Diagnostics = append(result.Diagnostics, Diagnostic{Code: "AMBIGUOUS_ACTION_METADATA", Definition: target.String(), Path: ref.Span.Path, Message: "both action.yml and action.yaml are present; precedence is not live-validated", EvidenceIDs: edge.EvidenceIDs})
		return
	}
	if stack[definition.String()] {
		result.Diagnostics = append(result.Diagnostics, Diagnostic{Code: "RESOLUTION_CYCLE", Definition: definition.String(), Path: ref.Span.Path, Message: "composite Action cycle detected", EvidenceIDs: edge.EvidenceIDs})
		return
	}
	metadata, diagnostics, err := workflow.ParseAction(metadataContent.Bytes, r.Limits)
	if err != nil {
		result.Diagnostics = append(result.Diagnostics, Diagnostic{Code: "MALFORMED_ACTION_METADATA", Definition: definition.String(), Message: boundedMessage(err), EvidenceIDs: edge.EvidenceIDs})
		return
	}
	result.Nodes = append(result.Nodes, Node{ID: targetID, Kind: NodeAction, Definition: definition, EvidenceID: metadataContent.EvidenceID, EvidenceIDs: sortedUnique(append(append([]string(nil), bindingEvidence...), metadataEvidence...)), ActionKind: metadata.Using})
	for _, diagnostic := range diagnostics {
		result.Diagnostics = append(result.Diagnostics, Diagnostic{Code: diagnostic.Code, Definition: definition.String(), Path: diagnostic.Path, Message: diagnostic.Message})
	}
	if metadata.IsLeaf {
		return
	}
	nextStack := copyStack(stack)
	nextStack[definition.String()] = true
	for _, child := range metadata.Steps {
		if child.Uses != nil {
			r.resolveAction(ctx, definition, *child.Uses, metadataContent.EvidenceID, inputs, depth+1, nextStack, EdgeActionContainsAction, result)
		}
	}
}

func (r Resolver) fetchActionMetadata(ctx context.Context, target DefinitionKey) (Content, string, []string, bool, error) {
	if err := validateDefinitionBase(target); err != nil {
		return Content{}, "", nil, false, err
	}
	if err := ctx.Err(); err != nil {
		return Content{}, "", nil, false, err
	}
	prefix := strings.TrimSuffix(target.Path, "/")
	if prefix != "" {
		prefix += "/"
	}
	ymlKey := target
	ymlKey.Path = prefix + "action.yml"
	yamlKey := target
	yamlKey.Path = prefix + "action.yaml"
	yml, ymlErr := r.Source.Fetch(ctx, ymlKey)
	if err := cancellationError(ctx, ymlErr); err != nil {
		return Content{}, "", nil, false, err
	}
	yamlContent, yamlErr := r.Source.Fetch(ctx, yamlKey)
	if err := cancellationError(ctx, yamlErr); err != nil {
		return Content{}, "", nil, false, err
	}
	if ymlErr == nil && yamlErr == nil {
		return yml, "action.yml", sortedUnique([]string{yml.EvidenceID, yamlContent.EvidenceID}), true, nil
	}
	if ymlErr == nil {
		if errors.Is(yamlErr, ErrContentNotFound) {
			return yml, "action.yml", sortedUnique([]string{yml.EvidenceID}), false, nil
		}
		return Content{}, "", sortedUnique([]string{yml.EvidenceID}), false, yamlErr
	}
	if yamlErr == nil {
		if errors.Is(ymlErr, ErrContentNotFound) {
			return yamlContent, "action.yaml", sortedUnique([]string{yamlContent.EvidenceID}), false, nil
		}
		return Content{}, "", sortedUnique([]string{yamlContent.EvidenceID}), false, ymlErr
	}
	if !errors.Is(ymlErr, ErrContentNotFound) {
		return Content{}, "", nil, false, ymlErr
	}
	if !errors.Is(yamlErr, ErrContentNotFound) {
		return Content{}, "", nil, false, yamlErr
	}
	return Content{}, "", nil, false, ErrContentNotFound
}

func normalizeResolvedAction(action ResolvedAction, fallbackSubpath string) (ResolvedAction, error) {
	if err := validateRepository(action.Repository); err != nil {
		return ResolvedAction{}, err
	}
	object := model.GitObjectID{Algorithm: model.HashAlgorithm(action.Commit.Algorithm), Value: action.Commit.Value}
	if err := object.Validate(); err != nil {
		return ResolvedAction{}, fmt.Errorf("Action source object: %w", err)
	}
	subpath := action.Subpath
	if subpath == "" {
		subpath = fallbackSubpath
	}
	normalized, err := workflow.NormalizeRepositoryPath(subpath)
	if err != nil {
		return ResolvedAction{}, fmt.Errorf("Action subpath: %w", err)
	}
	action.Subpath = normalized
	action.EvidenceIDs = sortedUnique(append([]string(nil), action.EvidenceIDs...))
	return action, nil
}

func validateRepository(repository Repository) error {
	if repository.ID < 0 {
		return errors.New("repository ID must not be negative")
	}
	if _, err := model.NewRepositorySlug(repository.Owner + "/" + repository.Name); err != nil {
		return err
	}
	return nil
}

func validateDefinitionBase(target DefinitionKey) error {
	_, err := normalizeResolvedAction(ResolvedAction{Repository: target.Repository, Subpath: target.Path, Commit: target.Commit}, "")
	return err
}

func actionMetadataDefinition(base DefinitionKey, metadataPath string) DefinitionKey {
	definition := base
	if definition.Path == "" {
		definition.Path = metadataPath
	} else {
		definition.Path = strings.TrimSuffix(definition.Path, "/") + "/" + metadataPath
	}
	return definition
}

func cancellationError(ctx context.Context, fetchErr error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if errors.Is(fetchErr, context.Canceled) || errors.Is(fetchErr, context.DeadlineExceeded) {
		return fetchErr
	}
	return nil
}

func boundedMessage(err error) string {
	if err == nil {
		return ""
	}
	const maxBytes = 1024
	var message strings.Builder
	message.Grow(maxBytes)
	for _, r := range err.Error() {
		if r == '\n' || r == '\r' || r == '\t' || r == '\x1b' || r < 0x20 || r == 0x7f {
			continue
		}
		size := utf8.RuneLen(r)
		if size < 0 {
			size = utf8.RuneLen(utf8.RuneError)
			r = utf8.RuneError
		}
		if message.Len()+size > maxBytes {
			break
		}
		message.WriteRune(r)
	}
	return message.String()
}

func nodeID(kind NodeKind, key DefinitionKey) string { return string(kind) + ":" + key.String() }
func definitionNodeKind(path string) NodeKind {
	if strings.HasSuffix(path, "action.yml") || strings.HasSuffix(path, "action.yaml") {
		return NodeAction
	}
	return NodeWorkflow
}
func edgeID(parent DefinitionKey, ref workflow.Reference, kind EdgeKind) string {
	return string(kind) + ":" + parent.String() + "#" + ref.Span.Path
}
func classifyFetch(err error) string {
	if errors.Is(err, ErrContentNotFound) {
		return "HISTORICAL_CONTENT_MISSING"
	}
	return "CONTENT_FETCH_FAILED"
}
func copyStack(source map[string]bool) map[string]bool {
	result := make(map[string]bool, len(source)+1)
	for key, value := range source {
		result[key] = value
	}
	return result
}

func definitionPointer(value DefinitionKey) *DefinitionKey {
	copy := value
	return &copy
}

func uniqueRuntimeAction(values []ResolvedAction, fallbackSubpath string) (ResolvedAction, bool) {
	byIdentity := make(map[string]ResolvedAction, len(values))
	for _, value := range values {
		normalized, err := normalizeResolvedAction(value, fallbackSubpath)
		if err != nil {
			continue
		}
		key := strings.ToLower(normalized.Repository.Owner) + "/" + strings.ToLower(normalized.Repository.Name) + "\x00" + normalized.Subpath + "\x00" + normalized.Commit.Algorithm + "\x00" + normalized.Commit.Value
		if existing, ok := byIdentity[key]; ok {
			existing.EvidenceIDs = sortedUnique(append(existing.EvidenceIDs, normalized.EvidenceIDs...))
			byIdentity[key] = existing
		} else {
			byIdentity[key] = normalized
		}
	}
	if len(byIdentity) != 1 {
		return ResolvedAction{}, false
	}
	for _, value := range byIdentity {
		return value, true
	}
	return ResolvedAction{}, false
}

func uniqueRuntimeWorkflow(values []ResolvedWorkflow) (ResolvedWorkflow, bool) {
	byIdentity := make(map[string]ResolvedWorkflow, len(values))
	for _, value := range values {
		if err := validateDefinitionBase(value.Definition); err != nil {
			continue
		}
		key := strings.ToLower(value.Definition.Repository.Owner) + "/" + strings.ToLower(value.Definition.Repository.Name) + "\x00" + value.Definition.Path + "\x00" + value.Definition.Commit.Algorithm + "\x00" + value.Definition.Commit.Value
		value.EvidenceIDs = sortedUnique(append([]string(nil), value.EvidenceIDs...))
		if existing, ok := byIdentity[key]; ok {
			existing.EvidenceIDs = sortedUnique(append(existing.EvidenceIDs, value.EvidenceIDs...))
			byIdentity[key] = existing
		} else {
			byIdentity[key] = value
		}
	}
	if len(byIdentity) != 1 {
		return ResolvedWorkflow{}, false
	}
	for _, value := range byIdentity {
		return value, true
	}
	return ResolvedWorkflow{}, false
}

func declaredReferenceObject(inputs ResolutionInputs, parent Repository, ref workflow.Reference) (GitObject, bool) {
	if ref.Ref == "" {
		return GitObject{}, false
	}
	owner, repository := ref.Owner, ref.Repository
	if ref.Kind == workflow.ReferenceSelfRepository || ref.Kind == workflow.ReferenceLocalWorkspace {
		owner, repository = parent.Owner, parent.Name
	}
	algorithm := inputs.RepositoryHashAlgorithms[strings.ToLower(owner)+"/"+strings.ToLower(repository)]
	if algorithm == "" {
		return GitObject{}, false
	}
	object := model.GitObjectID{Algorithm: model.HashAlgorithm(algorithm), Value: strings.ToLower(ref.Ref)}
	if err := object.Validate(); err != nil {
		return GitObject{}, false
	}
	return GitObject{Algorithm: string(object.Algorithm), Value: object.Value}, true
}
func sortedUnique(values []string) []string {
	sort.Strings(values)
	result := values[:0]
	for _, value := range values {
		if value != "" && (len(result) == 0 || value != result[len(result)-1]) {
			result = append(result, value)
		}
	}
	return result
}
func sortResult(result *Result) {
	sort.Slice(result.Nodes, func(i, j int) bool { return result.Nodes[i].ID < result.Nodes[j].ID })
	sort.Slice(result.Edges, func(i, j int) bool { return result.Edges[i].ID < result.Edges[j].ID })
	sort.Slice(result.Diagnostics, func(i, j int) bool {
		a, b := result.Diagnostics[i], result.Diagnostics[j]
		if a.Definition != b.Definition {
			return a.Definition < b.Definition
		}
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		return a.Code < b.Code
	})
}
