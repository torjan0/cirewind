package graph_test

import (
	"context"
	"strings"
	"testing"

	"github.com/torjan0/cirewind/internal/analyze"
	"github.com/torjan0/cirewind/internal/demodata"
	"github.com/torjan0/cirewind/internal/graph"
	"github.com/torjan0/cirewind/internal/incident"
	"github.com/torjan0/cirewind/internal/model"
)

type demoLaneIdentity struct {
	state   model.FindingState
	run     int64
	attempt uint32
}

func TestSyntheticDemoTemporalEvidencePathAcceptanceOracle(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	bundle, err := demodata.Bundle(ctx)
	if err != nil {
		t.Fatal(err)
	}
	pack, err := incident.Validate(ctx, bundle.PackYAML)
	if err != nil {
		t.Fatal(err)
	}
	result, err := analyze.Derive(bundle.Snapshot, pack, bundle.AnalysisTime, analyze.ModeReplay)
	if err != nil {
		t.Fatal(err)
	}
	path, svg, err := graph.RenderGraphSVG(ctx, result.Case.GraphV2, graph.PathOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := graph.ValidateTemporalEvidencePath(path); err != nil {
		t.Fatal(err)
	}
	if path.Counts.SelectedFindings != len(bundle.Oracle.Findings) || path.Counts.OmittedFindings != 0 {
		t.Fatalf("demo visual is not complete: %+v", path.Counts)
	}

	lanes := make(map[demoLaneIdentity]graph.TemporalEvidenceLane, len(path.Lanes))
	allEdgeTypes := make(map[graph.EdgeType]bool)
	allClasses := make(map[graph.EvidenceClass]bool)
	for _, lane := range path.Lanes {
		identity := demoLaneIdentity{state: lane.Finding.State}
		if lane.Finding.RunID != nil {
			identity.run = int64(*lane.Finding.RunID)
		}
		if lane.Finding.RunAttempt != nil {
			identity.attempt = uint32(*lane.Finding.RunAttempt)
		}
		lanes[identity] = lane
		for _, edge := range lane.Edges {
			allEdgeTypes[edge.Edge.Type] = true
			allClasses[edge.Edge.EvidenceClass] = true
			if len(edge.Edge.EvidenceIDs) == 0 || len(edge.EvidenceRefs) == 0 {
				t.Fatalf("edge %s lost evidence traceability", edge.Edge.ID)
			}
		}
	}

	for _, class := range []graph.EvidenceClass{
		graph.EvidenceClassExactObservation,
		graph.EvidenceClassInference,
		graph.EvidenceClassTemporalCorrelation,
		graph.EvidenceClassContradiction,
	} {
		if !allClasses[class] {
			t.Errorf("demo lacks evidence class %s", class)
		}
	}
	for _, edgeType := range []graph.EdgeType{
		graph.EdgeStepExecutedAction,
		graph.EdgeJobPreparedAction,
		graph.EdgeActionContainsAction,
		graph.EdgeObservedAfter,
		graph.EdgeContradicts,
		graph.EdgeHadTokenPermission,
		graph.EdgePassedSecretTo,
		graph.EdgeCouldMintOIDC,
		graph.EdgeExecutedOnRunner,
		graph.EdgeTargetedEnvironment,
	} {
		if !allEdgeTypes[edgeType] {
			t.Errorf("demo visual lacks required relationship %s (present=%v)", edgeType, allEdgeTypes)
		}
	}

	executed := requireLane(t, lanes, demoLaneIdentity{state: model.ConfirmedExecuted, run: 1001, attempt: 1})
	knownGood := requireLane(t, lanes, demoLaneIdentity{state: model.NoMatchConfirmed, run: 1001, attempt: 2})
	if executed.Finding.FindingRevisionID == knownGood.Finding.FindingRevisionID {
		t.Fatal("rerun attempts were merged")
	}
	if !laneHasEdge(executed, graph.EdgeStepExecutedAction) {
		t.Fatal("affected B lane lacks exact execution relationship")
	}
	downloaded := requireLane(t, lanes, demoLaneIdentity{state: model.ConfirmedDownloaded, run: 1002, attempt: 1})
	if !laneHasEdge(downloaded, graph.EdgeJobPreparedAction) || laneHasEdge(downloaded, graph.EdgeStepExecutedAction) {
		t.Fatal("downloaded/prepared-only B lane acquired execution semantics")
	}

	pending := requireLane(t, lanes, demoLaneIdentity{state: model.RunInWindowMutableRef, run: 1005, attempt: 1})
	if !laneHasEdge(pending, graph.EdgeTargetedEnvironment) {
		t.Fatal("pending environment lane lacks its directly evidenced target")
	}
	for _, prohibited := range []graph.EdgeType{
		graph.EdgeCrossedEnvironmentGate,
		graph.EdgeEnvironmentSecretEligible,
		graph.EdgeHadTokenPermission,
		graph.EdgeReferencedSecret,
		graph.EdgePassedSecretTo,
		graph.EdgeInheritedSecret,
		graph.EdgeCouldMintOIDC,
		graph.EdgeExecutedOnRunner,
		graph.EdgeObservedAfter,
		graph.EdgeStepExecutedAction,
	} {
		if laneHasEdge(pending, prohibited) {
			t.Errorf("pending environment lane acquired prohibited relationship %s", prohibited)
		}
	}

	gap := requireLane(t, lanes, demoLaneIdentity{state: model.UnknownEvidenceGap, run: 1007, attempt: 1})
	if strings.TrimSpace(gap.Finding.EvidenceGapReason) == "" {
		t.Fatal("evidence-gap lane lacks its explicit reason")
	}
	for _, edge := range gap.Edges {
		if edge.Edge.Type == graph.EdgeStepExecutedAction {
			t.Fatal("missing logs were converted into execution")
		}
	}

	current := requireLane(t, lanes, demoLaneIdentity{state: model.CurrentReferenceOnly, run: 1006, attempt: 1})
	historical := requireLane(t, lanes, demoLaneIdentity{state: model.DeclaredAtRunSHA, run: 1010, attempt: 1})
	currentDefinitions := nodeIDsByType(current, graph.NodeWorkflowDefinition)
	historicalDefinitions := nodeIDsByType(historical, graph.NodeWorkflowDefinition)
	if len(currentDefinitions) == 0 || len(historicalDefinitions) == 0 || intersects(currentDefinitions, historicalDefinitions) {
		t.Fatal("current and historical workflow definition identities were not kept separate")
	}

	text := string(svg)
	for _, required := range []string{
		"contents: write",
		"could mint OIDC token",
		"observed after — causation not established",
		"targeted; gate not shown crossed",
		"UNKNOWN_EVIDENCE_GAP",
	} {
		if !strings.Contains(text, required) {
			t.Errorf("demo SVG lacks required bounded wording %q", required)
		}
	}
	for _, prohibited := range []string{
		"cloud role assumed",
		"secret accessed",
		"deployment caused by",
		"runner compromised",
		"attack path",
	} {
		if strings.Contains(strings.ToLower(text), prohibited) {
			t.Errorf("demo SVG contains prohibited claim %q", prohibited)
		}
	}
}

func requireLane(t *testing.T, lanes map[demoLaneIdentity]graph.TemporalEvidenceLane, key demoLaneIdentity) graph.TemporalEvidenceLane {
	t.Helper()
	lane, ok := lanes[key]
	if !ok {
		t.Fatalf("missing visual lane state=%s run=%d attempt=%d", key.state, key.run, key.attempt)
	}
	return lane
}

func laneHasEdge(lane graph.TemporalEvidenceLane, edgeType graph.EdgeType) bool {
	for _, edge := range lane.Edges {
		if edge.Edge.Type == edgeType {
			return true
		}
	}
	return false
}

func nodeIDsByType(lane graph.TemporalEvidenceLane, nodeType graph.NodeType) map[string]struct{} {
	result := make(map[string]struct{})
	for _, node := range lane.Nodes {
		if node.Node.Type == nodeType {
			result[node.Node.ID] = struct{}{}
		}
	}
	return result
}

func intersects(left, right map[string]struct{}) bool {
	for id := range left {
		if _, ok := right[id]; ok {
			return true
		}
	}
	return false
}
