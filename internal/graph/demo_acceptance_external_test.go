package graph_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/torjan0/cirewind/internal/analyze"
	"github.com/torjan0/cirewind/internal/demodata"
	"github.com/torjan0/cirewind/internal/graph"
	"github.com/torjan0/cirewind/internal/incident"
	"github.com/torjan0/cirewind/internal/model"
)

type demoLaneIdentity struct {
	state     model.FindingState
	run       int64
	attempt   uint32
	indicator string
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
		identity.indicator = lane.Finding.IndicatorID
		lanes[identity] = lane
		labelRects := make([]visualRect, 0, len(lane.Edges))
		for _, edge := range lane.Edges {
			allEdgeTypes[edge.Edge.Type] = true
			allClasses[edge.Edge.EvidenceClass] = true
			if len(edge.Edge.EvidenceIDs) == 0 || len(edge.EvidenceRefs) == 0 {
				t.Fatalf("edge %s lost evidence traceability", edge.Edge.ID)
			}
			if len(edge.LabelLines) != 2 || !strings.Contains(edge.LabelLines[0], string(edge.Edge.Type)) || !strings.Contains(edge.LabelLines[0], string(edge.Edge.EvidenceClass)) || !strings.Contains(edge.LabelLines[1], edge.RelationshipText) {
				t.Fatalf("edge %s lacks an explicit two-line relationship ledger label: %q", edge.Edge.ID, edge.LabelLines)
			}
			for _, reference := range edge.EvidenceRefs {
				if !strings.Contains(edge.LabelLines[1], reference) {
					t.Fatalf("edge %s ledger label omits compact evidence reference %s", edge.Edge.ID, reference)
				}
			}
			labelRect := visualRect{edge.LabelRectX, edge.LabelRectY, edge.LabelRectWidth, edge.LabelRectHeight}
			if labelRect.x < 0 || labelRect.y < lane.Y || labelRect.x+labelRect.width > path.Width || labelRect.y+labelRect.height > lane.Y+lane.Height {
				t.Fatalf("edge %s ledger label is outside its lane: %+v", edge.Edge.ID, labelRect)
			}
			for _, node := range lane.Nodes {
				if visualRectsOverlap(labelRect, visualRect{node.X, node.Y, node.Width, node.Height}) {
					t.Fatalf("edge %s ledger label overlaps node %s", edge.Edge.ID, node.Node.ID)
				}
			}
			for _, prior := range labelRects {
				if visualRectsOverlap(labelRect, prior) {
					t.Fatalf("edge %s ledger label overlaps another label", edge.Edge.ID)
				}
			}
			labelRects = append(labelRects, labelRect)
			for _, node := range lane.Nodes {
				if node.Node.ID == edge.Edge.Source || node.Node.ID == edge.Edge.Target {
					continue
				}
				nodeRect := visualRect{node.X - 8, node.Y - 8, node.Width + 16, node.Height + 16}
				if visualRouteIntersectsRect(edge.Points, nodeRect) {
					t.Fatalf("edge %s route intersects non-endpoint node %s", edge.Edge.ID, node.Node.ID)
				}
			}
		}
		for left := range lane.Edges {
			for right := left + 1; right < len(lane.Edges); right++ {
				if visualRoutesCollinearlyOverlap(lane.Edges[left].Points, lane.Edges[right].Points) {
					t.Fatalf("lane %s routes %s and %s share a positive-length centerline", lane.Finding.FindingRevisionID, lane.Edges[left].Edge.ID, lane.Edges[right].Edge.ID)
				}
				if unrelatedEndpointStubsTouch(lane.Edges[left], lane.Edges[right]) {
					t.Fatalf("lane %s routes %s and %s visually join unrelated endpoint stubs", lane.Finding.FindingRevisionID, lane.Edges[left].Edge.ID, lane.Edges[right].Edge.ID)
				}
			}
		}
	}
	rootDimensions := fmt.Sprintf(`width="%d" height="%d" viewBox="0 0 %d %d"`, path.Width, path.Height, path.Width, path.Height)
	if !strings.Contains(string(svg), rootDimensions) {
		t.Fatalf("standalone SVG lacks intrinsic dimensions matching its viewBox: %s", rootDimensions)
	}
	renderedEdges := 0
	for _, lane := range path.Lanes {
		renderedEdges += len(lane.Edges)
	}
	if got := strings.Count(string(svg), `data-route-underlay="true"`); got != renderedEdges {
		t.Fatalf("standalone route underlays=%d, want one per rendered edge (%d)", got, renderedEdges)
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
	if header := graph.TemporalLaneHeader(knownGood.Finding); !strings.Contains(header, "comparison context") || !strings.Contains(string(svg), header) {
		t.Fatalf("known-good no-match lane lacks visible comparison labeling: %q", header)
	}

	transitiveCommit := requireLane(t, lanes, demoLaneIdentity{state: model.PotentialTransitive, run: 1004, attempt: 1, indicator: "synthetic-compromised-commit"})
	transitiveMutable := requireLane(t, lanes, demoLaneIdentity{state: model.PotentialTransitive, run: 1004, attempt: 1, indicator: "synthetic-mutable-ref"})
	_, commitScope := graph.TemporalLaneScope(transitiveCommit.Finding)
	_, mutableScope := graph.TemporalLaneScope(transitiveMutable.Finding)
	if commitScope == mutableScope || !strings.Contains(commitScope, "synthetic-compromised-commit") || !strings.Contains(mutableScope, "synthetic-mutable-ref") {
		t.Fatalf("distinct transitive propositions are not visibly distinguishable: commit=%q mutable=%q", commitScope, mutableScope)
	}
	downloaded := requireLane(t, lanes, demoLaneIdentity{state: model.ConfirmedDownloaded, run: 1002, attempt: 1})
	if !laneHasEdge(downloaded, graph.EdgeJobPreparedAction) || laneHasEdge(downloaded, graph.EdgeStepExecutedAction) {
		t.Fatal("downloaded/prepared-only B lane acquired execution semantics")
	}

	pending := requireLane(t, lanes, demoLaneIdentity{state: model.RunInWindowMutableRef, run: 1005, attempt: 1})
	if !laneHasEdge(pending, graph.EdgeTargetedEnvironment) {
		t.Fatal("pending environment lane lacks its historical-definition/API-job inferred target")
	}
	for _, prohibited := range []graph.EdgeType{
		graph.EdgeCrossedEnvironmentGate,
		graph.EdgeEnvironmentGateSatisfied,
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

	current := requireLane(t, lanes, demoLaneIdentity{state: model.CurrentReferenceOnly})
	if current.Finding.RunID != nil || current.Finding.RunAttempt != nil || current.Finding.JobID != nil || current.Finding.StepIdentity != "" {
		t.Fatal("present-day-only finding acquired historical execution identity")
	}
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
		"targeted; gate not shown satisfied",
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

func visualRoutesCollinearlyOverlap(left, right []graph.Point) bool {
	for leftIndex := 1; leftIndex < len(left); leftIndex++ {
		for rightIndex := 1; rightIndex < len(right); rightIndex++ {
			if visualSegmentsCollinearlyOverlap(left[leftIndex-1], left[leftIndex], right[rightIndex-1], right[rightIndex]) {
				return true
			}
		}
	}
	return false
}

func visualSegmentsCollinearlyOverlap(a, b, c, d graph.Point) bool {
	if a.X == b.X && c.X == d.X && a.X == c.X {
		return min(max(a.Y, b.Y), max(c.Y, d.Y))-max(min(a.Y, b.Y), min(c.Y, d.Y)) > 0
	}
	if a.Y == b.Y && c.Y == d.Y && a.Y == c.Y {
		return min(max(a.X, b.X), max(c.X, d.X))-max(min(a.X, b.X), min(c.X, d.X)) > 0
	}
	return false
}

func unrelatedEndpointStubsTouch(left, right graph.VisualEdge) bool {
	type endpointStub struct {
		from, to graph.Point
		nodeID   string
	}
	stubs := func(edge graph.VisualEdge) []endpointStub {
		last := len(edge.Points) - 1
		return []endpointStub{
			{from: edge.Points[0], to: edge.Points[1], nodeID: edge.Edge.Source},
			{from: edge.Points[last-1], to: edge.Points[last], nodeID: edge.Edge.Target},
		}
	}
	for _, a := range stubs(left) {
		for _, b := range stubs(right) {
			if a.nodeID == b.nodeID || a.from.Y != a.to.Y || b.from.Y != b.to.Y || a.from.Y != b.from.Y {
				continue
			}
			if min(max(a.from.X, a.to.X), max(b.from.X, b.to.X)) >= max(min(a.from.X, a.to.X), min(b.from.X, b.to.X)) {
				return true
			}
		}
	}
	return false
}

func visualRouteIntersectsRect(points []graph.Point, rect visualRect) bool {
	for index := 1; index < len(points); index++ {
		from, to := points[index-1], points[index]
		if from.Y == to.Y {
			left, right := min(from.X, to.X), max(from.X, to.X)
			if from.Y >= rect.y && from.Y <= rect.y+rect.height && right >= rect.x && left <= rect.x+rect.width {
				return true
			}
		}
		if from.X == to.X {
			top, bottom := min(from.Y, to.Y), max(from.Y, to.Y)
			if from.X >= rect.x && from.X <= rect.x+rect.width && bottom >= rect.y && top <= rect.y+rect.height {
				return true
			}
		}
	}
	return false
}

type visualRect struct{ x, y, width, height int }

func visualRectsOverlap(left, right visualRect) bool {
	return left.x < right.x+right.width && right.x < left.x+left.width &&
		left.y < right.y+right.height && right.y < left.y+left.height
}

func requireLane(t *testing.T, lanes map[demoLaneIdentity]graph.TemporalEvidenceLane, key demoLaneIdentity) graph.TemporalEvidenceLane {
	t.Helper()
	if key.indicator != "" {
		lane, ok := lanes[key]
		if !ok {
			t.Fatalf("missing visual lane state=%s run=%d attempt=%d indicator=%s", key.state, key.run, key.attempt, key.indicator)
		}
		return lane
	}
	var result graph.TemporalEvidenceLane
	matches := 0
	for identity, lane := range lanes {
		if identity.state == key.state && identity.run == key.run && identity.attempt == key.attempt {
			result = lane
			matches++
		}
	}
	if matches != 1 {
		t.Fatalf("visual lane state=%s run=%d attempt=%d matches=%d, want 1", key.state, key.run, key.attempt, matches)
	}
	return result
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
