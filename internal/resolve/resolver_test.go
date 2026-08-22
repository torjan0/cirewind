package resolve

import (
	"context"
	"strings"
	"testing"

	"github.com/torjan0/cirewind/internal/workflow"
)

type memorySource map[string]Content

func (m memorySource) Fetch(_ context.Context, key DefinitionKey) (Content, error) {
	content, ok := m[key.String()]
	if !ok {
		return Content{}, ErrContentNotFound
	}
	return content, nil
}

func key(repo Repository, path string, commit GitObject) DefinitionKey {
	return DefinitionKey{Repository: repo, Path: path, Commit: commit}
}

func TestResolveCompositeAtExactRuntimeCommit(t *testing.T) {
	t.Parallel()
	repo := Repository{ID: 1, Owner: "fixture", Name: "caller"}
	actionRepo := Repository{ID: 2, Owner: "fixture", Name: "wrapper"}
	childRepo := Repository{ID: 3, Owner: "fixture", Name: "child"}
	callerOID := GitObject{Algorithm: "sha1", Value: strings.Repeat("a", 40)}
	wrapperOID := GitObject{Algorithm: "sha1", Value: strings.Repeat("b", 40)}
	childOID := GitObject{Algorithm: "sha1", Value: strings.Repeat("c", 40)}
	root := key(repo, ".github/workflows/test.yml", callerOID)
	rootBytes := []byte("jobs:\n  test:\n    steps:\n      - uses: fixture/wrapper@v1\n")
	parsed, _, err := workflow.ParseWorkflow(rootBytes, workflow.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	rootOccurrence := OccurrenceKey(root, parsed.Jobs[0].Steps[0].Uses.Span)
	wrapperBase := key(actionRepo, "", wrapperOID)
	wrapperMeta := wrapperBase
	wrapperMeta.Path = "action.yml"
	wrapperBytes := []byte("name: wrapper\nruns:\n  using: composite\n  steps:\n    - uses: fixture/child@" + childOID.Value + "\n")
	wrapperParsed, _, err := workflow.ParseAction(wrapperBytes, workflow.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	wrapperDefinition := wrapperMeta
	childOccurrence := OccurrenceKey(wrapperDefinition, wrapperParsed.Steps[0].Uses.Span)
	childBase := key(childRepo, "", childOID)
	childMeta := childBase
	childMeta.Path = "action.yml"
	source := memorySource{wrapperMeta.String(): {Bytes: wrapperBytes, EvidenceID: "ev-wrapper"}, childMeta.String(): {Bytes: []byte("name: child\nruns:\n  using: node20\n  main: dist/index.js\n"), EvidenceID: "ev-child"}}
	resolver := Resolver{Source: source, Limits: workflow.DefaultLimits(), MaxDepth: 10}
	result, err := resolver.ResolveWorkflow(context.Background(), root, Content{Bytes: rootBytes, EvidenceID: "ev-root"}, ResolutionInputs{Actions: map[string]ResolvedAction{
		rootOccurrence:  {Repository: actionRepo, Commit: wrapperOID, EvidenceIDs: []string{"ev-runtime-wrapper"}},
		childOccurrence: {Repository: childRepo, Commit: childOID, EvidenceIDs: []string{"ev-runtime-child"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Nodes) != 3 || len(result.Edges) != 2 {
		t.Fatalf("unexpected graph nodes=%+v edges=%+v diagnostics=%+v", result.Nodes, result.Edges, result.Diagnostics)
	}
	for _, edge := range result.Edges {
		if !edge.RuntimeBound {
			t.Fatalf("edge not runtime-bound: %+v", edge)
		}
	}
}

func TestLocalWorkspaceRemainsUncertain(t *testing.T) {
	t.Parallel()
	repo := Repository{ID: 1, Owner: "fixture", Name: "caller"}
	oid := GitObject{Algorithm: "sha1", Value: strings.Repeat("a", 40)}
	root := key(repo, ".github/workflows/test.yml", oid)
	rootBytes := []byte("jobs:\n  test:\n    steps:\n      - uses: ./actions/local\n")
	meta := key(repo, "actions/local/action.yml", oid)
	source := memorySource{meta.String(): {Bytes: []byte("runs:\n  using: composite\n  steps: []\n"), EvidenceID: "ev-local"}}
	result, err := (Resolver{Source: source, Limits: workflow.DefaultLimits(), MaxDepth: 10}).ResolveWorkflow(context.Background(), root, Content{Bytes: rootBytes, EvidenceID: "ev-root"}, ResolutionInputs{})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Edges) != 1 || !result.Edges[0].WorkspaceUncertain || result.Edges[0].GapCode != "LOCAL_WORKSPACE_BYTES_UNPROVEN" {
		t.Fatalf("local bytes overclaimed: %+v", result)
	}
}

func TestMissingRuntimeMutableRefStopsAtDeclaration(t *testing.T) {
	t.Parallel()
	repo := Repository{ID: 1, Owner: "fixture", Name: "caller"}
	oid := GitObject{Algorithm: "sha1", Value: strings.Repeat("a", 40)}
	root := key(repo, "wf.yml", oid)
	result, err := (Resolver{Source: memorySource{}, Limits: workflow.DefaultLimits(), MaxDepth: 10}).ResolveWorkflow(context.Background(), root, Content{Bytes: []byte("jobs:\n  test:\n    steps:\n      - uses: fixture/action@v1\n"), EvidenceID: "ev-root"}, ResolutionInputs{})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Edges) != 1 || result.Edges[0].Exact || result.Edges[0].GapCode != "ACTION_RUNTIME_IDENTITY_MISSING" {
		t.Fatalf("mutable ref silently resolved: %+v", result)
	}
}

func TestAliasedDeclarationsProduceDistinctDependencyEdges(t *testing.T) {
	t.Parallel()
	repo := Repository{ID: 1, Owner: "fixture", Name: "caller"}
	oid := GitObject{Algorithm: "sha1", Value: strings.Repeat("a", 40)}
	root := key(repo, "wf.yml", oid)
	workflowBytes := []byte(`jobs:
  actions:
    steps:
      - uses: &scalar_action fixture/scalar@v1
      - uses: *scalar_action
      - &whole_step
        uses: fixture/whole-step@v2
      - *whole_step
  reusable:
    uses: &called_workflow fixture/workflows/.github/workflows/call.yml@v3
  reusable_alias:
    uses: *called_workflow
`)
	result, err := (Resolver{Source: memorySource{}, Limits: workflow.DefaultLimits(), MaxDepth: 10}).ResolveWorkflow(context.Background(), root, Content{Bytes: workflowBytes, EvidenceID: "ev-root"}, ResolutionInputs{})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Edges) != 6 {
		t.Fatalf("aliased dependencies were omitted: %+v", result)
	}
	paths := map[string]bool{}
	ids := map[string]bool{}
	actions, workflows := 0, 0
	for _, edge := range result.Edges {
		if edge.Declaration.Span.Path == "" || paths[edge.Declaration.Span.Path] {
			t.Fatalf("aliased declaration occurrence was not distinct: %+v", result.Edges)
		}
		paths[edge.Declaration.Span.Path] = true
		if edge.ID == "" || ids[edge.ID] {
			t.Fatalf("aliased declaration edge identity was not distinct: %+v", result.Edges)
		}
		ids[edge.ID] = true
		switch edge.Kind {
		case EdgeWorkflowDeclaredAction:
			actions++
		case EdgeWorkflowCalledWorkflow:
			workflows++
		}
	}
	if actions != 4 || workflows != 2 {
		t.Fatalf("edge kinds actions=%d workflows=%d edges=%+v", actions, workflows, result.Edges)
	}
}
