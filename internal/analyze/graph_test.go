package analyze

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/torjan0/cirewind/internal/archive"
	"github.com/torjan0/cirewind/internal/demodata"
	"github.com/torjan0/cirewind/internal/graph"
	"github.com/torjan0/cirewind/internal/model"
)

func TestFocusedGraphProjectsTypedEvidenceBackedFactsDeterministically(t *testing.T) {
	snapshot, err := demodata.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	analysisTime := time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC)
	first, err := Derive(snapshot, loadPack(t), analysisTime, ModeReplay)
	if err != nil {
		t.Fatal(err)
	}

	nodeTypes := make(map[string]graph.NodeType, len(first.Case.Graph.Nodes))
	for _, node := range first.Case.Graph.Nodes {
		nodeTypes[node.ID] = node.Type
	}
	seenEdges := map[graph.EdgeType]bool{}
	for _, edge := range first.Case.Graph.Edges {
		if len(edge.EvidenceIDs) == 0 {
			t.Fatalf("edge %s lacks evidence", edge.ID)
		}
		if edge.Type == graph.EdgeSupportedByEvidence &&
			(nodeTypes[edge.Source] != graph.NodeFinding || nodeTypes[edge.Target] != graph.NodeEvidenceObject) {
			t.Fatalf("semantically invalid support edge: %+v", edge)
		}
		seenEdges[edge.Type] = true
	}
	for _, edgeType := range []graph.EdgeType{
		graph.EdgeAttemptOfRun,
		graph.EdgeJobExecutedInAttempt,
		graph.EdgeStepDownloadedAction,
		graph.EdgeStepExecutedAction,
		graph.EdgeJobPreparedAction,
		graph.EdgeWorkflowCalledWorkflow,
		graph.EdgeHadTokenPermission,
		graph.EdgeCouldMintOIDC,
		graph.EdgeExecutedOnRunner,
		graph.EdgeObservedAfter,
		graph.EdgeContradicts,
		graph.EdgeSupportedByEvidence,
	} {
		if !seenEdges[edgeType] {
			t.Errorf("focused graph lacks %s", edgeType)
		}
	}

	firstJSON, err := json.Marshal(first.Case.Graph)
	if err != nil {
		t.Fatal(err)
	}
	reversed := snapshot
	reversed.Facts = slices.Clone(snapshot.Facts)
	slices.Reverse(reversed.Facts)
	second, err := Derive(reversed, loadPack(t), analysisTime, ModeReplay)
	if err != nil {
		t.Fatal(err)
	}
	secondJSON, err := json.Marshal(second.Case.Graph)
	if err != nil {
		t.Fatal(err)
	}
	if string(firstJSON) != string(secondJSON) {
		t.Fatal("graph projection changed when normalized fact order changed")
	}
}

func TestRefResolutionGraphStartsAtDeclaredRef(t *testing.T) {
	snapshot, err := demodata.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Evidence) == 0 {
		t.Fatal("demo snapshot lacks evidence")
	}
	evidenceID := snapshot.Evidence[0].Evidence.ID
	caller := model.CallerWorkflowObjectID(model.GitObjectID{Algorithm: model.HashSHA1, Value: strings.Repeat("b", 40)})
	target := model.ActionSourceObjectID(model.GitObjectID{Algorithm: model.HashSHA1, Value: strings.Repeat("a", 40)})
	fact := archive.Fact{
		Kind:        archive.FactDependency,
		EvidenceIDs: []model.EvidenceID{evidenceID},
		Dependency: &archive.DependencyFact{
			Relation:               archive.DependencyRefResolvedTo,
			TargetKind:             archive.DependencyTargetAction,
			Basis:                  archive.DefinitionHistoricalAtRun,
			CallerRepositoryID:     1,
			CallerRepository:       "acme/service",
			CallerPath:             ".github/workflows/ci.yml",
			CallerWorkflowObjectID: &caller,
			TargetRepository:       "example/action",
			DeclaredRef:            "v1",
			TargetActionObjectID:   &target,
		},
	}
	builder := graphBuilder{nodes: map[string]graph.Node{}, edges: map[string]graph.Edge{}}
	builder.projectDependency(index{}, fact, "", true)
	result := graph.Graph{SchemaVersion: graph.SchemaVersion}
	for _, node := range builder.nodes {
		result.Nodes = append(result.Nodes, node)
	}
	for _, edge := range builder.edges {
		result.Edges = append(result.Edges, edge)
	}
	if err := result.NormalizeAndValidate(); err != nil {
		t.Fatal(err)
	}
	nodeTypes := make(map[string]graph.NodeType, len(result.Nodes))
	for _, node := range result.Nodes {
		nodeTypes[node.ID] = node.Type
	}
	var resolutions int
	for _, edge := range result.Edges {
		if edge.Type != graph.EdgeRefResolvedTo {
			continue
		}
		resolutions++
		if nodeTypes[edge.Source] != graph.NodeActionRef || nodeTypes[edge.Target] != graph.NodeActionCommit {
			t.Fatalf("resolution has wrong endpoints: %s -> %s", nodeTypes[edge.Source], nodeTypes[edge.Target])
		}
	}
	if resolutions != 1 {
		t.Fatalf("got %d ref-resolution edges, want 1", resolutions)
	}
}
