package resolve_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/torjan0/cirewind/internal/resolve"
	"github.com/torjan0/cirewind/internal/workflow"
)

type recordingSource struct {
	content   map[string]resolve.Content
	errors    map[string]error
	calls     []resolve.DefinitionKey
	afterCall func(int)
}

func (s *recordingSource) Fetch(ctx context.Context, key resolve.DefinitionKey) (resolve.Content, error) {
	if err := ctx.Err(); err != nil {
		return resolve.Content{}, err
	}
	s.calls = append(s.calls, key)
	if s.afterCall != nil {
		s.afterCall(len(s.calls))
	}
	if err, ok := s.errors[key.String()]; ok {
		return resolve.Content{}, err
	}
	content, ok := s.content[key.String()]
	if !ok {
		return resolve.Content{}, resolve.ErrContentNotFound
	}
	return content, nil
}

func actionResolver(source resolve.ContentSource, maxDepth int) resolve.Resolver {
	return resolve.Resolver{Source: source, Limits: workflow.DefaultLimits(), MaxDepth: maxDepth}
}

func exactAction(repository resolve.Repository, subpath, value string, evidenceIDs ...string) resolve.ResolvedAction {
	return resolve.ResolvedAction{
		Repository:  repository,
		Subpath:     subpath,
		Commit:      resolve.GitObject{Algorithm: "sha1", Value: value},
		EvidenceIDs: evidenceIDs,
	}
}

func definition(repository resolve.Repository, path, value string) resolve.DefinitionKey {
	return resolve.DefinitionKey{
		Repository: repository,
		Path:       path,
		Commit:     resolve.GitObject{Algorithm: "sha1", Value: value},
	}
}

func metadataKey(repository resolve.Repository, subpath, filename, value string) resolve.DefinitionKey {
	path := filename
	if subpath != "" {
		path = subpath + "/" + filename
	}
	return definition(repository, path, value)
}

func requireDiagnostic(t *testing.T, result resolve.Result, code string) resolve.Diagnostic {
	t.Helper()
	for _, diagnostic := range result.Diagnostics {
		if diagnostic.Code == code {
			return diagnostic
		}
	}
	t.Fatalf("diagnostic %q absent from %+v", code, result.Diagnostics)
	return resolve.Diagnostic{}
}

func requireEdgeByKind(t *testing.T, result resolve.Result, kind workflow.ReferenceKind) resolve.Edge {
	t.Helper()
	for _, edge := range result.Edges {
		if edge.Declaration.Kind == kind {
			return edge
		}
	}
	t.Fatalf("edge with declaration kind %q absent from %+v", kind, result.Edges)
	return resolve.Edge{}
}

func TestResolveActionJavaScriptLeafAtExactCommit(t *testing.T) {
	repository := resolve.Repository{ID: 21, Owner: "fixture", Name: "javascript"}
	commit := strings.Repeat("a", 40)
	key := metadataKey(repository, "", "action.yml", commit)
	source := &recordingSource{content: map[string]resolve.Content{
		key.String(): {Bytes: []byte("name: JavaScript leaf\nruns:\n  using: node20\n  main: dist/index.js\n"), EvidenceID: "ev-metadata"},
	}}

	result, err := actionResolver(source, 10).ResolveAction(context.Background(), exactAction(repository, "", commit, "ev-runtime"), resolve.ResolutionInputs{})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Nodes) != 1 || len(result.Edges) != 0 || len(result.Diagnostics) != 0 {
		t.Fatalf("unexpected leaf result: %+v", result)
	}
	node := result.Nodes[0]
	if node.ActionKind != "node20" || node.Definition.Path != "action.yml" {
		t.Fatalf("wrong JavaScript definition: %+v", node)
	}
	if strings.Join(node.EvidenceIDs, ",") != "ev-metadata,ev-runtime" {
		t.Fatalf("exact binding evidence was not preserved: %+v", node.EvidenceIDs)
	}
	if len(source.calls) != 2 || source.calls[0].Path != "action.yml" || source.calls[1].Path != "action.yaml" {
		t.Fatalf("metadata names not fetched deterministically: %+v", source.calls)
	}
}

func TestResolveActionDockerLeafFromActionYAML(t *testing.T) {
	repository := resolve.Repository{ID: 22, Owner: "fixture", Name: "docker"}
	commit := strings.Repeat("b", 40)
	key := metadataKey(repository, "container", "action.yaml", commit)
	source := &recordingSource{content: map[string]resolve.Content{
		key.String(): {Bytes: []byte("runs:\n  using: docker\n  image: Dockerfile\n"), EvidenceID: "ev-docker"},
	}}

	result, err := actionResolver(source, 10).ResolveAction(context.Background(), exactAction(repository, "container", commit), resolve.ResolutionInputs{})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Nodes) != 1 || result.Nodes[0].ActionKind != "docker" || result.Nodes[0].Definition.Path != "container/action.yaml" {
		t.Fatalf("Docker metadata was not treated as a leaf: %+v", result)
	}
	if len(result.Edges) != 0 {
		t.Fatalf("Docker implementation was traversed: %+v", result.Edges)
	}
}

func TestResolveActionCompositeNestedRepositoryChild(t *testing.T) {
	rootRepository := resolve.Repository{ID: 23, Owner: "fixture", Name: "wrapper"}
	childRepository := resolve.Repository{ID: 24, Owner: "fixture", Name: "child"}
	rootCommit := strings.Repeat("c", 40)
	childCommit := strings.Repeat("d", 40)
	rootBytes := []byte("runs:\n  using: composite\n  steps:\n    - uses: fixture/child/subdir@v1\n")
	rootDefinition := metadataKey(rootRepository, "wrapper", "action.yml", rootCommit)
	parsed, _, err := workflow.ParseAction(rootBytes, workflow.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	occurrence := resolve.OccurrenceKey(rootDefinition, parsed.Steps[0].Uses.Span)
	childDefinition := metadataKey(childRepository, "subdir", "action.yml", childCommit)
	source := &recordingSource{content: map[string]resolve.Content{
		rootDefinition.String():  {Bytes: rootBytes, EvidenceID: "ev-root-metadata"},
		childDefinition.String(): {Bytes: []byte("runs:\n  using: composite\n  steps:\n    - uses: $/leaf\n"), EvidenceID: "ev-child-metadata"},
		metadataKey(childRepository, "leaf", "action.yaml", childCommit).String(): {Bytes: []byte("runs:\n  using: node20\n  main: index.js\n"), EvidenceID: "ev-grandchild-metadata"},
	}}
	inputs := resolve.ResolutionInputs{Actions: map[string]resolve.ResolvedAction{
		occurrence: exactAction(childRepository, "", childCommit, "ev-child-runtime"),
	}}

	result, err := actionResolver(source, 10).ResolveAction(context.Background(), exactAction(rootRepository, "wrapper", rootCommit, "ev-root-runtime"), inputs)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Nodes) != 3 || len(result.Edges) != 2 {
		t.Fatalf("nested composite was not reconstructed: %+v", result)
	}
	var runtimeEdge *resolve.Edge
	for index := range result.Edges {
		if result.Edges[index].RuntimeBound {
			runtimeEdge = &result.Edges[index]
		}
	}
	if runtimeEdge == nil || runtimeEdge.Kind != resolve.EdgeActionContainsAction || !runtimeEdge.Exact || runtimeEdge.GapCode != "" {
		t.Fatalf("child exact-runtime binding was lost: %+v", result.Edges)
	}
	if !strings.Contains(strings.Join(runtimeEdge.EvidenceIDs, ","), "ev-child-runtime") {
		t.Fatalf("child binding evidence absent: %+v", runtimeEdge.EvidenceIDs)
	}
}

func TestResolveActionSelfAndLocalChildrenRemainDistinct(t *testing.T) {
	repository := resolve.Repository{ID: 25, Owner: "fixture", Name: "same-repository"}
	commit := strings.Repeat("e", 40)
	rootDefinition := metadataKey(repository, "actions/root", "action.yml", commit)
	source := &recordingSource{content: map[string]resolve.Content{
		rootDefinition.String(): {Bytes: []byte("runs:\n  using: composite\n  steps:\n    - uses: $/actions/self\n    - uses: ./actions/local\n"), EvidenceID: "ev-root"},
		metadataKey(repository, "actions/self", "action.yml", commit).String():  {Bytes: []byte("runs:\n  using: node20\n  main: index.js\n"), EvidenceID: "ev-self"},
		metadataKey(repository, "actions/local", "action.yml", commit).String(): {Bytes: []byte("runs:\n  using: docker\n  image: Dockerfile\n"), EvidenceID: "ev-local-candidate"},
	}}

	result, err := actionResolver(source, 10).ResolveAction(context.Background(), exactAction(repository, "actions/root", commit), resolve.ResolutionInputs{})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Nodes) != 3 || len(result.Edges) != 2 {
		t.Fatalf("same-repository children were not reconstructed: %+v", result)
	}
	self := requireEdgeByKind(t, result, workflow.ReferenceSelfRepository)
	if !self.Exact || self.WorkspaceUncertain || self.GapCode != "" {
		t.Fatalf("$/ child was not bound to containing exact commit: %+v", self)
	}
	local := requireEdgeByKind(t, result, workflow.ReferenceLocalWorkspace)
	if local.Exact || !local.WorkspaceUncertain || local.GapCode != "LOCAL_WORKSPACE_BYTES_UNPROVEN" {
		t.Fatalf("./ candidate bytes were overclaimed: %+v", local)
	}
}

func TestResolveActionMutableChildRequiresExplicitBinding(t *testing.T) {
	repository := resolve.Repository{ID: 26, Owner: "fixture", Name: "wrapper"}
	commit := strings.Repeat("f", 40)
	rootDefinition := metadataKey(repository, "", "action.yml", commit)
	source := &recordingSource{content: map[string]resolve.Content{
		rootDefinition.String(): {Bytes: []byte("runs:\n  using: composite\n  steps:\n    - uses: third-party/action@v1\n"), EvidenceID: "ev-root"},
	}}

	result, err := actionResolver(source, 10).ResolveAction(context.Background(), exactAction(repository, "", commit), resolve.ResolutionInputs{})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Nodes) != 1 || len(result.Edges) != 1 {
		t.Fatalf("unexpected mutable child result: %+v", result)
	}
	if result.Edges[0].Exact || result.Edges[0].To != "" || result.Edges[0].GapCode != "ACTION_RUNTIME_IDENTITY_MISSING" {
		t.Fatalf("mutable child was falsely resolved: %+v", result.Edges[0])
	}
	if len(source.calls) != 2 {
		t.Fatalf("unbound child triggered a content fetch: %+v", source.calls)
	}
}

func TestResolveActionCompositeCycleIsBounded(t *testing.T) {
	repository := resolve.Repository{ID: 27, Owner: "fixture", Name: "cycle"}
	commit := strings.Repeat("1", 40)
	rootDefinition := metadataKey(repository, "actions/root", "action.yml", commit)
	source := &recordingSource{content: map[string]resolve.Content{
		rootDefinition.String(): {Bytes: []byte("runs:\n  using: composite\n  steps:\n    - uses: $/actions/root\n"), EvidenceID: "ev-root"},
	}}

	result, err := actionResolver(source, 10).ResolveAction(context.Background(), exactAction(repository, "actions/root", commit), resolve.ResolutionInputs{})
	if err != nil {
		t.Fatal(err)
	}
	requireDiagnostic(t, result, "RESOLUTION_CYCLE")
	if len(result.Nodes) != 1 || len(result.Edges) != 1 || result.Edges[0].To != result.Nodes[0].ID {
		t.Fatalf("cycle graph is not finite or does not target its root: %+v", result)
	}
	if len(source.calls) != 4 {
		t.Fatalf("cycle caused unexpected fetch count: %+v", source.calls)
	}
}

func TestResolveActionBothMetadataNamesAreAmbiguous(t *testing.T) {
	repository := resolve.Repository{ID: 28, Owner: "fixture", Name: "ambiguous"}
	commit := strings.Repeat("2", 40)
	yml := metadataKey(repository, "", "action.yml", commit)
	yaml := metadataKey(repository, "", "action.yaml", commit)
	source := &recordingSource{content: map[string]resolve.Content{
		yml.String():  {Bytes: []byte("runs:\n  using: node20\n  main: yml.js\n"), EvidenceID: "ev-yml"},
		yaml.String(): {Bytes: []byte("runs:\n  using: docker\n  image: Dockerfile\n"), EvidenceID: "ev-yaml"},
	}}

	result, err := actionResolver(source, 10).ResolveAction(context.Background(), exactAction(repository, "", commit), resolve.ResolutionInputs{})
	if err != nil {
		t.Fatal(err)
	}
	requireDiagnostic(t, result, "AMBIGUOUS_ACTION_METADATA")
	if got := strings.Join(result.Diagnostics[0].EvidenceIDs, ","); got != "ev-yaml,ev-yml" {
		t.Fatalf("ambiguous metadata evidence IDs = %q", got)
	}
	if len(result.Nodes) != 0 || len(result.Edges) != 0 {
		t.Fatalf("ambiguous metadata was silently selected: %+v", result)
	}
}

func TestResolveActionMissingMetadataIsDiagnostic(t *testing.T) {
	repository := resolve.Repository{ID: 29, Owner: "fixture", Name: "missing"}
	commit := strings.Repeat("3", 40)
	result, err := actionResolver(&recordingSource{content: map[string]resolve.Content{}}, 10).ResolveAction(context.Background(), exactAction(repository, "", commit), resolve.ResolutionInputs{})
	if err != nil {
		t.Fatal(err)
	}
	requireDiagnostic(t, result, "HISTORICAL_CONTENT_MISSING")
	if len(result.Nodes) != 0 {
		t.Fatalf("missing content created a definition: %+v", result.Nodes)
	}
}

func TestResolveActionSanitizesHostileFetchDiagnostic(t *testing.T) {
	repository := resolve.Repository{ID: 36, Owner: "fixture", Name: "hostile-error"}
	commit := strings.Repeat("9", 40)
	yml := metadataKey(repository, "", "action.yml", commit)
	source := &recordingSource{
		content: map[string]resolve.Content{},
		errors: map[string]error{
			yml.String(): errors.New("\x1b[31mforged line\nsecret-looking detail\t" + strings.Repeat("x", 4096)),
		},
	}

	result, err := actionResolver(source, 10).ResolveAction(context.Background(), exactAction(repository, "", commit, "ev-runtime"), resolve.ResolutionInputs{})
	if err != nil {
		t.Fatal(err)
	}
	diagnostic := requireDiagnostic(t, result, "CONTENT_FETCH_FAILED")
	if strings.ContainsAny(diagnostic.Message, "\x1b\n\r\t") {
		t.Fatalf("diagnostic retained terminal or line controls: %q", diagnostic.Message)
	}
	if len(diagnostic.Message) > 1024 {
		t.Fatalf("diagnostic length = %d", len(diagnostic.Message))
	}
	if strings.Join(diagnostic.EvidenceIDs, ",") != "ev-runtime" {
		t.Fatalf("diagnostic lost binding evidence: %+v", diagnostic.EvidenceIDs)
	}
}

func TestResolveActionRejectsUnsafeRootPathBeforeFetch(t *testing.T) {
	repository := resolve.Repository{ID: 30, Owner: "fixture", Name: "unsafe"}
	commit := strings.Repeat("4", 40)
	source := &recordingSource{content: map[string]resolve.Content{}}

	_, err := actionResolver(source, 10).ResolveAction(context.Background(), exactAction(repository, "../escape", commit), resolve.ResolutionInputs{})
	if err == nil || !strings.Contains(err.Error(), "Action subpath") {
		t.Fatalf("unsafe path error = %v", err)
	}
	if len(source.calls) != 0 {
		t.Fatalf("unsafe path reached ContentSource: %+v", source.calls)
	}
}

func TestResolveActionDepthLimitStopsBeforeChildFetch(t *testing.T) {
	repository := resolve.Repository{ID: 31, Owner: "fixture", Name: "depth-root"}
	childRepository := resolve.Repository{ID: 32, Owner: "fixture", Name: "depth-child"}
	rootCommit := strings.Repeat("5", 40)
	childCommit := strings.Repeat("6", 40)
	rootBytes := []byte("runs:\n  using: composite\n  steps:\n    - uses: fixture/depth-child@v1\n")
	rootDefinition := metadataKey(repository, "", "action.yml", rootCommit)
	parsed, _, err := workflow.ParseAction(rootBytes, workflow.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	occurrence := resolve.OccurrenceKey(rootDefinition, parsed.Steps[0].Uses.Span)
	source := &recordingSource{content: map[string]resolve.Content{
		rootDefinition.String(): {Bytes: rootBytes, EvidenceID: "ev-root"},
	}}

	result, err := actionResolver(source, 1).ResolveAction(context.Background(), exactAction(repository, "", rootCommit), resolve.ResolutionInputs{Actions: map[string]resolve.ResolvedAction{
		occurrence: exactAction(childRepository, "", childCommit, "ev-binding"),
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Edges) != 1 || result.Edges[0].GapCode != "RESOLUTION_DEPTH_LIMIT" || result.Edges[0].To != "" {
		t.Fatalf("depth limit was not explicit: %+v", result)
	}
	if len(source.calls) != 2 {
		t.Fatalf("depth-limited child was fetched: %+v", source.calls)
	}
}

func TestResolveActionCancellationStopsBeforeFetch(t *testing.T) {
	repository := resolve.Repository{ID: 33, Owner: "fixture", Name: "cancel"}
	commit := strings.Repeat("7", 40)
	source := &recordingSource{content: map[string]resolve.Content{}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := actionResolver(source, 10).ResolveAction(ctx, exactAction(repository, "", commit), resolve.ResolutionInputs{})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation error = %v", err)
	}
	if len(source.calls) != 0 {
		t.Fatalf("canceled resolution fetched content: %+v", source.calls)
	}
}

func TestResolveActionCancellationBetweenMetadataFetches(t *testing.T) {
	repository := resolve.Repository{ID: 35, Owner: "fixture", Name: "cancel-during-fetch"}
	commit := strings.Repeat("8", 40)
	ctx, cancel := context.WithCancel(context.Background())
	source := &recordingSource{
		content: map[string]resolve.Content{
			metadataKey(repository, "", "action.yml", commit).String(): {Bytes: []byte("runs:\n  using: node20\n  main: index.js\n"), EvidenceID: "ev-metadata"},
		},
		afterCall: func(call int) {
			if call == 1 {
				cancel()
			}
		},
	}

	_, err := actionResolver(source, 10).ResolveAction(ctx, exactAction(repository, "", commit), resolve.ResolutionInputs{})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation error = %v", err)
	}
	if len(source.calls) != 1 {
		t.Fatalf("resolver fetched after cancellation: %+v", source.calls)
	}
}

func TestResolveActionRejectsNonExactCommit(t *testing.T) {
	repository := resolve.Repository{ID: 34, Owner: "fixture", Name: "mutable-root"}
	source := &recordingSource{content: map[string]resolve.Content{}}

	_, err := actionResolver(source, 10).ResolveAction(context.Background(), resolve.ResolvedAction{
		Repository: repository,
		Commit:     resolve.GitObject{Algorithm: "sha1", Value: "v1"},
	}, resolve.ResolutionInputs{})
	if err == nil || !strings.Contains(err.Error(), "must contain 40") {
		t.Fatalf("non-exact root error = %v", err)
	}
	if len(source.calls) != 0 {
		t.Fatalf("mutable root reached ContentSource: %+v", source.calls)
	}
}

func TestResolveActionUsesUniqueAttemptScopedRuntimeBinding(t *testing.T) {
	rootRepository := resolve.Repository{ID: 31, Owner: "fixture", Name: "wrapper"}
	childRepository := resolve.Repository{ID: 32, Owner: "fixture", Name: "child"}
	rootCommit := strings.Repeat("1", 40)
	childCommit := strings.Repeat("2", 40)
	rootKey := metadataKey(rootRepository, "", "action.yml", rootCommit)
	childKey := metadataKey(childRepository, "", "action.yml", childCommit)
	rootBytes := []byte("runs:\n  using: composite\n  steps:\n    - uses: fixture/child@v1\n")
	parsed, _, err := workflow.ParseAction(rootBytes, workflow.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	bindingKey := resolve.ReferenceBindingKey(rootRepository, *parsed.Steps[0].Uses)
	source := &recordingSource{content: map[string]resolve.Content{
		rootKey.String():  {Bytes: rootBytes, EvidenceID: "ev-root"},
		childKey.String(): {Bytes: []byte("runs:\n  using: node20\n  main: dist/index.js\n"), EvidenceID: "ev-child"},
	}}
	result, err := actionResolver(source, 10).ResolveAction(context.Background(), exactAction(rootRepository, "", rootCommit, "ev-root-runtime"), resolve.ResolutionInputs{
		RuntimeActions: map[string][]resolve.ResolvedAction{
			bindingKey: {exactAction(childRepository, "", childCommit, "ev-child-runtime")},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	edge := requireEdgeByKind(t, result, workflow.ReferenceRepository)
	if !edge.RuntimeBound || !edge.Exact || edge.ResolvedDefinition == nil || edge.ResolvedDefinition.Commit.Value != childCommit || edge.Depth != 1 {
		t.Fatalf("unique runtime binding was not retained exactly: %+v", edge)
	}
}

func TestResolveActionRejectsAmbiguousAttemptScopedRuntimeBinding(t *testing.T) {
	rootRepository := resolve.Repository{ID: 33, Owner: "fixture", Name: "wrapper"}
	childRepository := resolve.Repository{ID: 34, Owner: "fixture", Name: "child"}
	rootCommit := strings.Repeat("3", 40)
	rootKey := metadataKey(rootRepository, "", "action.yml", rootCommit)
	rootBytes := []byte("runs:\n  using: composite\n  steps:\n    - uses: fixture/child@v1\n")
	parsed, _, err := workflow.ParseAction(rootBytes, workflow.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	bindingKey := resolve.ReferenceBindingKey(rootRepository, *parsed.Steps[0].Uses)
	source := &recordingSource{content: map[string]resolve.Content{rootKey.String(): {Bytes: rootBytes, EvidenceID: "ev-root"}}}
	result, err := actionResolver(source, 10).ResolveAction(context.Background(), exactAction(rootRepository, "", rootCommit), resolve.ResolutionInputs{
		RuntimeActions: map[string][]resolve.ResolvedAction{
			bindingKey: {
				exactAction(childRepository, "", strings.Repeat("4", 40)),
				exactAction(childRepository, "", strings.Repeat("5", 40)),
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	edge := requireEdgeByKind(t, result, workflow.ReferenceRepository)
	if edge.Exact || edge.RuntimeBound || edge.ResolvedDefinition != nil || edge.GapCode != "ACTION_RUNTIME_IDENTITY_AMBIGUOUS" {
		t.Fatalf("ambiguous runtime identities were collapsed: %+v", edge)
	}
}

func TestResolveActionTypesFullDeclarationOnlyFromRepositoryAlgorithmEvidence(t *testing.T) {
	rootRepository := resolve.Repository{ID: 35, Owner: "fixture", Name: "wrapper"}
	childRepository := resolve.Repository{ID: 36, Owner: "fixture", Name: "child"}
	rootCommit := strings.Repeat("6", 40)
	childCommit := strings.Repeat("7", 40)
	rootKey := metadataKey(rootRepository, "", "action.yml", rootCommit)
	childKey := metadataKey(childRepository, "", "action.yml", childCommit)
	rootBytes := []byte("runs:\n  using: composite\n  steps:\n    - uses: fixture/child@" + childCommit + "\n")
	source := &recordingSource{content: map[string]resolve.Content{
		rootKey.String():  {Bytes: rootBytes, EvidenceID: "ev-root"},
		childKey.String(): {Bytes: []byte("runs:\n  using: node20\n  main: dist/index.js\n"), EvidenceID: "ev-child"},
	}}
	withoutAlgorithm, err := actionResolver(source, 10).ResolveAction(context.Background(), exactAction(rootRepository, "", rootCommit), resolve.ResolutionInputs{})
	if err != nil {
		t.Fatal(err)
	}
	if edge := requireEdgeByKind(t, withoutAlgorithm, workflow.ReferenceRepository); edge.Exact || edge.GapCode != "ACTION_RUNTIME_IDENTITY_MISSING" {
		t.Fatalf("full declaration was typed by width without repository evidence: %+v", edge)
	}
	withAlgorithm, err := actionResolver(source, 10).ResolveAction(context.Background(), exactAction(rootRepository, "", rootCommit), resolve.ResolutionInputs{
		RepositoryHashAlgorithms: map[string]string{"fixture/child": "sha1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	edge := requireEdgeByKind(t, withAlgorithm, workflow.ReferenceRepository)
	if !edge.Exact || edge.RuntimeBound || edge.ResolvedDefinition == nil || edge.ResolvedDefinition.Commit.Value != childCommit {
		t.Fatalf("algorithm-backed exact declaration was not resolved: %+v", edge)
	}
}
