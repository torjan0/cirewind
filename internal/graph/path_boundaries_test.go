package graph

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/torjan0/cirewind/internal/model"
)

func TestTemporalPathOptionHardBoundaries(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name    string
		options PathOptions
	}{
		{"lane hard", PathOptions{MaxFindingLanes: HardPathFindingLanes}},
		{"node hard", PathOptions{MaxNodes: HardPathNodes}},
		{"edge hard", PathOptions{MaxEdges: HardPathEdges}},
		{"evidence hard", PathOptions{MaxEvidenceIDs: HardPathEvidenceIDs}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := normalizePathOptions(test.options); err != nil {
				t.Fatal(err)
			}
		})
	}
	for _, test := range []struct {
		name    string
		options PathOptions
	}{
		{"lane over hard", PathOptions{MaxFindingLanes: HardPathFindingLanes + 1}},
		{"node over hard", PathOptions{MaxNodes: HardPathNodes + 1}},
		{"edge over hard", PathOptions{MaxEdges: HardPathEdges + 1}},
		{"evidence over hard", PathOptions{MaxEvidenceIDs: HardPathEvidenceIDs + 1}},
		{"negative lane", PathOptions{MaxFindingLanes: -1}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := normalizePathOptions(test.options); err == nil {
				t.Fatal("invalid option boundary accepted")
			}
		})
	}
}

func TestTemporalPathDefaultAndHardSelectionBoundaries(t *testing.T) {
	t.Parallel()
	t.Run("finding lanes", func(t *testing.T) {
		for _, test := range []struct {
			count, limit, want int
		}{
			{DefaultPathFindingLanes, 0, DefaultPathFindingLanes},
			{DefaultPathFindingLanes + 1, 0, DefaultPathFindingLanes},
			{HardPathFindingLanes, HardPathFindingLanes, HardPathFindingLanes},
		} {
			g := manyLaneGraph(t, test.count)
			path, err := BuildTemporalEvidencePath(context.Background(), g, PathOptions{
				MaxFindingLanes: test.limit, MaxNodes: HardPathNodes,
				MaxEdges: HardPathEdges, MaxEvidenceIDs: HardPathEvidenceIDs,
			})
			if err != nil {
				t.Fatal(err)
			}
			if path.Counts.SelectedFindings != test.want || path.Counts.OmittedFindings != test.count-test.want {
				t.Fatalf("count=%d limit=%d counts=%+v", test.count, test.limit, path.Counts)
			}
		}
	})

	t.Run("logical nodes", func(t *testing.T) {
		for _, test := range []struct {
			count, limit, want int
		}{
			{DefaultPathNodes, 0, 1},
			{DefaultPathNodes + 1, 0, 0},
			{HardPathNodes, HardPathNodes, 1},
		} {
			path, err := BuildTemporalEvidencePath(context.Background(), manyNodeGraph(test.count), PathOptions{
				MaxNodes: test.limit, MaxEdges: HardPathEdges, MaxEvidenceIDs: HardPathEvidenceIDs,
			})
			if err != nil {
				t.Fatal(err)
			}
			if path.Counts.SelectedFindings != test.want {
				t.Fatalf("count=%d limit=%d counts=%+v", test.count, test.limit, path.Counts)
			}
		}
	})

	t.Run("material edges", func(t *testing.T) {
		for _, test := range []struct {
			count, limit, want int
		}{
			{pathNodePortCapacity, 0, 1},
			{pathNodePortCapacity, pathNodePortCapacity - 1, 0},
			{pathNodePortCapacity + 1, HardPathEdges, 0},
		} {
			path, err := BuildTemporalEvidencePath(context.Background(), manyEdgeGraph(t, test.count), PathOptions{
				MaxNodes: HardPathNodes, MaxEdges: test.limit, MaxEvidenceIDs: HardPathEvidenceIDs,
			})
			if err != nil {
				t.Fatal(err)
			}
			if path.Counts.SelectedFindings != test.want {
				t.Fatalf("count=%d limit=%d counts=%+v", test.count, test.limit, path.Counts)
			}
		}
	})

	t.Run("unique evidence", func(t *testing.T) {
		for _, test := range []struct {
			count, limit, want int
		}{
			{DefaultPathEvidenceIDs, 0, 1},
			{DefaultPathEvidenceIDs + 1, 0, 0},
			{HardPathEvidenceIDs, HardPathEvidenceIDs, 1},
		} {
			path, err := BuildTemporalEvidencePath(context.Background(), manyEvidenceGraph(t, test.count), PathOptions{
				MaxNodes: HardPathNodes, MaxEdges: HardPathEdges, MaxEvidenceIDs: test.limit,
			})
			if err != nil {
				t.Fatal(err)
			}
			if path.Counts.SelectedFindings != test.want {
				t.Fatalf("count=%d limit=%d counts=%+v", test.count, test.limit, path.Counts)
			}
		}
	})
}

func TestRenderGraphSVGDegradesByCompleteLanesAtEightMiBHardBound(t *testing.T) {
	if testing.Short() {
		t.Skip("large bounded rendering test")
	}
	g := largeSharedLaneGraph(t)
	path, data, err := RenderGraphSVG(context.Background(), g, PathOptions{
		MaxFindingLanes: HardPathFindingLanes, MaxNodes: HardPathNodes,
		MaxEdges: HardPathEdges, MaxEvidenceIDs: HardPathEvidenceIDs,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(data) > MaxSVGBytes {
		t.Fatalf("SVG bytes=%d", len(data))
	}
	if len(path.Lanes) == 0 || len(path.Lanes) >= HardPathFindingLanes {
		t.Fatalf("hard byte ceiling did not omit a complete suffix: lanes=%d bytes=%d", len(path.Lanes), len(data))
	}
	if path.Counts.OmittedFindings != HardPathFindingLanes-len(path.Lanes) {
		t.Fatalf("omission counts=%+v lanes=%d", path.Counts, len(path.Lanes))
	}
	unrestricted, err := BuildTemporalEvidencePath(context.Background(), g, PathOptions{
		MaxFindingLanes: HardPathFindingLanes, MaxNodes: HardPathNodes,
		MaxEdges: HardPathEdges, MaxEvidenceIDs: HardPathEvidenceIDs,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(unrestricted.Lanes) == len(path.Lanes) {
		t.Fatal("test graph did not distinguish unrestricted and renderable paths")
	}
	if err := ValidateRenderableTemporalEvidencePath(context.Background(), g, path, PathOptions{
		MaxFindingLanes: HardPathFindingLanes, MaxNodes: HardPathNodes,
		MaxEdges: HardPathEdges, MaxEvidenceIDs: HardPathEvidenceIDs,
	}); err != nil {
		t.Fatalf("reduced standalone path was not accepted as the canonical renderable projection: %v", err)
	}
	if err := ValidateRenderableTemporalEvidencePath(context.Background(), g, unrestricted, PathOptions{
		MaxFindingLanes: HardPathFindingLanes, MaxNodes: HardPathNodes,
		MaxEdges: HardPathEdges, MaxEvidenceIDs: HardPathEvidenceIDs,
	}); err == nil {
		t.Fatal("unrestricted path was accepted despite exceeding the standalone SVG budget")
	}
	assertNoDanglingVisualEdges(t, path)
}

func TestDefinitionWordingUsesTypedEdgeBasisNotFindingStateOrLabels(t *testing.T) {
	t.Parallel()
	for index, test := range []struct {
		name       string
		edgeType   EdgeType
		sourceType NodeType
		targetType NodeType
		rule       string
		want       string
	}{
		{name: "current declaration despite contradiction finding", edgeType: EdgeWorkflowDeclaredAction, sourceType: NodeWorkflowDefinition, targetType: NodeActionRef, rule: DefinitionBasisCurrentSnapshotRule, want: "present-day workflow snapshot declared Action"},
		{name: "historical declaration despite current-only finding", edgeType: EdgeWorkflowDeclaredAction, sourceType: NodeWorkflowDefinition, targetType: NodeActionRef, rule: DefinitionBasisHistoricalAtRunRule, want: "historical workflow declared Action"},
		{name: "current reusable call", edgeType: EdgeWorkflowCalledWorkflow, sourceType: NodeWorkflowDefinition, targetType: NodeReusableWorkflowDefinition, rule: DefinitionBasisCurrentSnapshotRule, want: "present-day workflow snapshot called reusable workflow"},
		{name: "runtime reusable call", edgeType: EdgeWorkflowCalledWorkflow, sourceType: NodeRunAttempt, targetType: NodeReusableWorkflowDefinition, rule: DefinitionBasisRuntimeAttemptMetadataRule, want: "GitHub run-attempt metadata recorded reusable-workflow call"},
		{name: "historical local action", edgeType: EdgeLocalActionResolvedTo, sourceType: NodeWorkflowDefinition, targetType: NodeActionDefinition, rule: DefinitionBasisHistoricalAtRunRule, want: "local Action resolved at historical commit"},
		{name: "current local action", edgeType: EdgeLocalActionResolvedTo, sourceType: NodeWorkflowDefinition, targetType: NodeActionDefinition, rule: DefinitionBasisCurrentSnapshotRule, want: "local Action resolved in present-day snapshot"},
	} {
		t.Run(test.name, func(t *testing.T) {
			focus := indexedFindingID(200 + index)
			evidence := indexedEvidenceID(200 + index)
			edge, err := NewEdgeV2(test.edgeType, "workflow", "target", []string{evidence}, "", EvidenceClassExactObservation, test.rule, []string{focus})
			if err != nil {
				t.Fatal(err)
			}
			state := model.ContradictoryEvidence
			if index == 1 {
				state = model.CurrentReferenceOnly
			}
			g := GraphV2{
				SchemaVersion: SchemaVersionV2, CaseKind: CaseKindSynthetic,
				FindingIndex: []FindingIndexEntry{testFinding(focus, state)},
				Nodes: []NodeV2{
					{ID: "workflow", Type: test.sourceType, Label: "hostile opposite temporal-looking label", FocusFindingIDs: []string{focus}},
					{ID: "target", Type: test.targetType, Label: "target", FocusFindingIDs: []string{focus}},
				},
				Edges: []EdgeV2{edge},
			}
			path, err := BuildTemporalEvidencePath(context.Background(), g, PathOptions{})
			if err != nil {
				t.Fatal(err)
			}
			if got := path.Lanes[0].Edges[0].RelationshipText; got != test.want {
				t.Fatalf("relationship=%q, want %q", got, test.want)
			}
		})
	}
}

func TestDualClassRelationshipWordingDoesNotCallInferenceObserved(t *testing.T) {
	t.Parallel()
	finding := testFinding(indexedFindingID(300), model.ConfirmedExecuted)
	for _, test := range []struct {
		edgeType EdgeType
		rule     string
		exact    string
		inferred string
	}{
		{EdgeStepInJob, "step-membership/v1", "step recorded in job", "step associated with job by derivation"},
		{EdgeWorkflowDeclaredAction, DefinitionBasisHistoricalAtRunRule, "historical workflow declared Action", "historical workflow declared Action by derivation"},
		{EdgeHadTokenPermission, "credential/static/v1", "token permission capability observed", "token permission capability inferred"},
		{EdgeReferencedSecret, "credential/static/v1", "secret name referenced", "secret name reference inferred"},
		{EdgePassedSecretTo, "credential/static/v1", "secret mapped or passed", "secret mapping or passage inferred"},
		{EdgeInheritedSecret, "credential/static/v1", "secret relationship inherited", "secret inheritance relationship inferred"},
		{EdgeTargetedEnvironment, EnvironmentTargetHistoricalRule, "environment target observed", "environment target inferred"},
		{EdgeCrossedEnvironmentGate, "environment-gate/v1", "environment gate crossing observed", "environment gate crossing inferred"},
	} {
		t.Run(string(test.edgeType), func(t *testing.T) {
			exact := EdgeV2{Type: test.edgeType, Source: "source", Target: "target", EvidenceClass: EvidenceClassExactObservation, DerivationRule: test.rule}
			inferred := exact
			inferred.EvidenceClass = EvidenceClassInference
			laneEdges := []EdgeV2{exact}
			if test.edgeType == EdgeTargetedEnvironment {
				laneEdges = append(laneEdges, EdgeV2{Type: EdgeEnvironmentGateSatisfied, Source: exact.Source, Target: exact.Target})
			}
			if got := relationshipText(exact, laneEdges, finding); got != test.exact {
				t.Fatalf("exact wording=%q, want %q", got, test.exact)
			}
			laneEdges[0] = inferred
			if got := relationshipText(inferred, laneEdges, finding); got != test.inferred {
				t.Fatalf("inferred wording=%q, want %q", got, test.inferred)
			}
			if strings.Contains(test.inferred, "observed") {
				t.Fatalf("inferred wording calls the relationship observed: %q", test.inferred)
			}
		})
	}
}

func TestTemporalPathValidatorRejectsForgedCountsGeometryEdgesAndEvidence(t *testing.T) {
	t.Parallel()
	base, err := BuildTemporalEvidencePath(context.Background(), testGraphV2(t), PathOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*TemporalEvidencePath){
		"selected count": func(path *TemporalEvidencePath) { path.Counts.SelectedNodes++ },
		"omission count": func(path *TemporalEvidencePath) { path.Counts.OmittedEdges++ },
		"node geometry":  func(path *TemporalEvidencePath) { path.Lanes[0].Nodes[0].X++ },
		"node order": func(path *TemporalEvidencePath) {
			slices.Reverse(path.Lanes[0].Nodes)
		},
		"dangling edge": func(path *TemporalEvidencePath) { path.Lanes[0].Edges[0].Edge.Target = "absent" },
		"edge route":    func(path *TemporalEvidencePath) { path.Lanes[0].Edges[0].Points[0].X++ },
		"edge label geometry": func(path *TemporalEvidencePath) {
			path.Lanes[0].Edges[0].LabelRectY = path.Lanes[0].Nodes[0].Y
		},
		"edge label text": func(path *TemporalEvidencePath) {
			path.Lanes[0].Edges[0].LabelLines[0] = "forged relationship"
		},
		"extra evidence key": func(path *TemporalEvidencePath) {
			path.EvidenceKey = append(path.EvidenceKey, EvidenceReference{CompactID: fmt.Sprintf("E%03d", len(path.EvidenceKey)+1), EvidenceID: indexedEvidenceID(9999)})
			path.Counts.SelectedEvidenceIDs++
			path.Counts.TotalEvidenceIDs++
			path.Height += 25
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := cloneTemporalPath(base)
			mutate(&changed)
			if err := ValidateTemporalEvidencePath(changed); err == nil {
				t.Fatal("forged presentation model accepted")
			}
		})
	}
}

func TestTemporalPathValidatorReappliesClosedForensicSemantics(t *testing.T) {
	t.Parallel()
	makeEdge := func(t *testing.T, edgeType EdgeType, source, target string, class EvidenceClass, rule, focus string) EdgeV2 {
		t.Helper()
		edge, err := NewEdgeV2(edgeType, source, target, []string{evidenceID("9")}, "unknown", class, rule, []string{focus})
		if err != nil {
			t.Fatal(err)
		}
		return edge
	}

	t.Run("relationship evidence class", func(t *testing.T) {
		focus := findingID("8")
		g := GraphV2{
			SchemaVersion: SchemaVersionV2, CaseKind: CaseKindSynthetic,
			FindingIndex: []FindingIndexEntry{testFinding(focus, model.ConfirmedExecuted)},
			Nodes: []NodeV2{
				{ID: "step", Type: NodeStep, Label: "step", FocusFindingIDs: []string{focus}},
				{ID: "commit", Type: NodeActionCommit, Label: "commit", FocusFindingIDs: []string{focus}},
			},
			Edges: []EdgeV2{makeEdge(t, EdgeStepExecutedAction, "step", "commit", EvidenceClassExactObservation, "", focus)},
		}
		path, err := BuildTemporalEvidencePath(context.Background(), g, PathOptions{})
		if err != nil {
			t.Fatal(err)
		}
		edge := path.Lanes[0].Edges[0].Edge
		edge.EvidenceClass = EvidenceClassInference
		edge.DerivationRule = "forged-lifecycle-inference/v1"
		edge.ID, err = StableEdgeIDV2(edge.Type, edge.Source, edge.Target, edge.EventTime, edge.EvidenceClass, edge.DerivationRule)
		if err != nil {
			t.Fatal(err)
		}
		nodes := map[string]VisualNode{}
		maxRows := 0
		for _, node := range path.Lanes[0].Nodes {
			nodes[node.Node.ID] = node
			maxRows = max(maxRows, node.Row+1)
		}
		refs := map[string]string{}
		for _, reference := range path.EvidenceKey {
			refs[reference.EvidenceID] = reference.CompactID
		}
		rebuilt := layoutEdges([]EdgeV2{edge}, nodes, refs, path.Lanes[0].Finding, path.Lanes[0].Y, maxRows)
		rebuilt[0].LocalID = path.Lanes[0].Edges[0].LocalID
		path.Lanes[0].Edges = rebuilt
		if err := ValidateTemporalEvidencePath(path); err == nil || !strings.Contains(err.Error(), "cannot use evidence class") {
			t.Fatalf("forged lifecycle inference was not rejected by the standalone path contract: %v", err)
		}
	})

	t.Run("non-executed runner context", func(t *testing.T) {
		focus := findingID("7")
		g := GraphV2{
			SchemaVersion: SchemaVersionV2, CaseKind: CaseKindSynthetic,
			FindingIndex: []FindingIndexEntry{testFinding(focus, model.ConfirmedExecuted)},
			Nodes: []NodeV2{
				{ID: "job", Type: NodeJob, Label: "job", FocusFindingIDs: []string{focus}},
				{ID: "runner", Type: NodeRunner, Label: "runner", FocusFindingIDs: []string{focus}},
			},
			Edges: []EdgeV2{makeEdge(t, EdgeExecutedOnRunner, "job", "runner", EvidenceClassExactObservation, "", focus)},
		}
		path, err := BuildTemporalEvidencePath(context.Background(), g, PathOptions{})
		if err != nil {
			t.Fatal(err)
		}
		path.Lanes[0].Finding.State = model.ConfirmedDownloaded
		if err := ValidateTemporalEvidencePath(path); err == nil || !strings.Contains(err.Error(), "non-executed") {
			t.Fatalf("runner context was accepted on a non-executed standalone lane: %v", err)
		}
	})

	t.Run("narrow pending environment remains valid", func(t *testing.T) {
		focus := findingID("6")
		g := GraphV2{
			SchemaVersion: SchemaVersionV2, CaseKind: CaseKindSynthetic,
			FindingIndex: []FindingIndexEntry{testFinding(focus, model.ConfirmedDownloaded)},
			Nodes: []NodeV2{
				{ID: "job", Type: NodeJob, Label: "pending job", FocusFindingIDs: []string{focus}},
				{ID: "environment", Type: NodeEnvironment, Label: "production", FocusFindingIDs: []string{focus}},
			},
			Edges: []EdgeV2{makeEdge(t, EdgeTargetedEnvironment, "job", "environment", EvidenceClassInference, EnvironmentTargetPendingRule, focus)},
		}
		path, err := BuildTemporalEvidencePath(context.Background(), g, PathOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if err := ValidateTemporalEvidencePath(path); err != nil {
			t.Fatalf("narrow pending environment path was rejected: %v", err)
		}
	})

	t.Run("environment eligibility requires gate satisfaction in standalone path", func(t *testing.T) {
		focus := findingID("5")
		evidence := evidenceID("5")
		g := GraphV2{
			SchemaVersion: SchemaVersionV2, CaseKind: CaseKindSynthetic,
			FindingIndex: []FindingIndexEntry{testFinding(focus, model.ConfirmedExecuted)},
			Nodes: []NodeV2{
				{ID: "job", Type: NodeJob, Label: "job", FocusFindingIDs: []string{focus}},
				{ID: "environment", Type: NodeEnvironment, Label: "production", FocusFindingIDs: []string{focus}},
				{ID: "secret", Type: NodeSecretMetadata, Label: "DEPLOY_KEY", FocusFindingIDs: []string{focus}},
			},
			Edges: []EdgeV2{
				makeEdge(t, EdgeTargetedEnvironment, "job", "environment", EvidenceClassInference, EnvironmentTargetHistoricalRule, focus),
				makeEdge(t, EdgeEnvironmentGateSatisfied, "job", "environment", EvidenceClassInference, EnvironmentGateSatisfiedApprovedRule, focus),
				makeEdge(t, EdgeEnvironmentSecretEligible, "environment", "secret", EvidenceClassInference, EnvironmentSecretEligibilityRule, focus),
			},
		}
		// Use one shared evidence object so changing the relationship cannot fail
		// first on an unrelated evidence-key count.
		for index := range g.Edges {
			g.Edges[index].EvidenceIDs = []string{evidence}
		}
		path, err := BuildTemporalEvidencePath(context.Background(), g, PathOptions{})
		if err != nil {
			t.Fatal(err)
		}
		lane := &path.Lanes[0]
		edges := edgeValues(lane.Edges)
		for index := range edges {
			if edges[index].Type != EdgeEnvironmentGateSatisfied {
				continue
			}
			edges[index].Type = EdgeCrossedEnvironmentGate
			edges[index].DerivationRule = "environment-crossing/v1"
			edges[index].ID, err = StableEdgeIDV2(edges[index].Type, edges[index].Source, edges[index].Target, edges[index].EventTime, edges[index].EvidenceClass, edges[index].DerivationRule)
			if err != nil {
				t.Fatal(err)
			}
		}
		nodes := make(map[string]VisualNode, len(lane.Nodes))
		maxRows := 0
		for _, node := range lane.Nodes {
			nodes[node.Node.ID] = node
			maxRows = max(maxRows, node.Row+1)
		}
		refs := map[string]string{evidence: "E001"}
		lane.Edges = layoutEdges(edges, nodes, refs, lane.Finding, lane.Y, maxRows)
		for index := range lane.Edges {
			lane.Edges[index].LocalID = fmt.Sprintf("e%04d", index+1)
		}
		if err := ValidateTemporalEvidencePath(path); err == nil || !strings.Contains(err.Error(), "ENVIRONMENT_SECRET_ELIGIBLE") {
			t.Fatalf("standalone path accepted eligibility without gate satisfaction: %v", err)
		}
	})
}

func TestGeneratedRoutesAvoidEveryNonEndpointNode(t *testing.T) {
	t.Parallel()
	path, err := BuildTemporalEvidencePath(context.Background(), testGraphV2(t), PathOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for _, lane := range path.Lanes {
		for _, edge := range lane.Edges {
			for _, node := range lane.Nodes {
				if node.Node.ID == edge.Edge.Source || node.Node.ID == edge.Edge.Target {
					continue
				}
				rect := integerRect{X: node.X - pathRouteClearance, Y: node.Y - pathRouteClearance, Width: node.Width + 2*pathRouteClearance, Height: node.Height + 2*pathRouteClearance}
				if routeIntersectsRect(edge.Points, rect) {
					t.Fatalf("edge %s route intersects non-endpoint node %s", edge.Edge.ID, node.Node.ID)
				}
			}
		}
	}
}

func TestRouteEdgeAvoidsFullNodeGridForEveryColumnPair(t *testing.T) {
	t.Parallel()
	const laneY = 200
	nodes := make([]VisualNode, 0, len(pathColumnX)*3)
	for column := range pathColumnX {
		for row := 0; row < 3; row++ {
			nodes = append(nodes, VisualNode{
				Node:   NodeV2{ID: fmt.Sprintf("column-%d-row-%d", column, row)},
				Column: column,
				Row:    row,
				X:      pathColumnX[column],
				Y:      laneY + 78 + row*(pathNodeHeight+pathRowGap),
				Width:  pathNodeWidth,
				Height: pathNodeHeight,
			})
		}
	}
	for sourceColumn := range pathColumnX {
		for targetColumn := range pathColumnX {
			source := nodes[sourceColumn*3]
			target := nodes[targetColumn*3+2]
			points := routeEdge(source, target, laneY+600)
			for index := 1; index < len(points); index++ {
				if points[index] == points[index-1] {
					t.Fatalf("columns %d to %d contain consecutive duplicate route points", sourceColumn, targetColumn)
				}
				if points[index].X != points[index-1].X && points[index].Y != points[index-1].Y {
					t.Fatalf("columns %d to %d contain a diagonal route", sourceColumn, targetColumn)
				}
			}
			if routeRetraces(points) {
				t.Fatalf("columns %d to %d contain a retraced route segment: %v", sourceColumn, targetColumn, points)
			}
			for _, node := range nodes {
				if node.Node.ID == source.Node.ID || node.Node.ID == target.Node.ID {
					continue
				}
				rect := integerRect{X: node.X - pathRouteClearance, Y: node.Y - pathRouteClearance, Width: node.Width + 2*pathRouteClearance, Height: node.Height + 2*pathRouteClearance}
				if routeIntersectsRect(points, rect) {
					t.Fatalf("columns %d to %d route intersects blocker %s", sourceColumn, targetColumn, node.Node.ID)
				}
			}
		}
	}
}

func TestRouteBanksSeparateEveryEndpointAndOmitOverCapacityLane(t *testing.T) {
	t.Parallel()
	path, err := BuildTemporalEvidencePath(context.Background(), manyBankEdgeGraph(t, pathRouteBankCapacity), PathOptions{
		MaxNodes: HardPathNodes, MaxEdges: HardPathEdges, MaxEvidenceIDs: HardPathEvidenceIDs,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(path.Lanes) != 1 || len(path.Lanes[0].Edges) != pathRouteBankCapacity {
		t.Fatalf("at-capacity lane was not selected: %+v", path.Counts)
	}
	sourceRails, targetRails := make(map[int]struct{}), make(map[int]struct{})
	for _, edge := range path.Lanes[0].Edges {
		sourceRails[edge.Points[1].X] = struct{}{}
		targetRails[edge.Points[len(edge.Points)-2].X] = struct{}{}
		if routeRetraces(edge.Points) {
			t.Fatalf("edge %s retraces a routed segment: %v", edge.Edge.ID, edge.Points)
		}
	}
	if len(sourceRails) != pathRouteBankCapacity || len(targetRails) != pathRouteBankCapacity {
		t.Fatalf("route rails are not unique at capacity: source=%d target=%d", len(sourceRails), len(targetRails))
	}
	for name, rails := range map[string]map[int]struct{}{"source": sourceRails, "target": targetRails} {
		ordered := make([]int, 0, len(rails))
		for rail := range rails {
			ordered = append(ordered, rail)
		}
		slices.Sort(ordered)
		for index := 1; index < len(ordered); index++ {
			if distance := ordered[index] - ordered[index-1]; distance < routeUnderlayWidth(EvidenceClassContradiction, 4)+2 {
				t.Fatalf("%s route rails are too close for a non-junction underlay: %v", name, ordered)
			}
		}
	}

	overflow, err := BuildTemporalEvidencePath(context.Background(), manyBankEdgeGraph(t, pathRouteBankCapacity+1), PathOptions{
		MaxNodes: HardPathNodes, MaxEdges: HardPathEdges, MaxEvidenceIDs: HardPathEvidenceIDs,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(overflow.Lanes) != 0 || overflow.Counts.SelectedFindings != 0 || overflow.Counts.OmittedFindings != 1 || overflow.Counts.OmittedEdges != pathRouteBankCapacity+1 {
		t.Fatalf("over-capacity lane was partially rendered: %+v", overflow.Counts)
	}
	portOverflow, err := BuildTemporalEvidencePath(context.Background(), manyEdgeGraph(t, pathNodePortCapacity+1), PathOptions{
		MaxNodes: HardPathNodes, MaxEdges: HardPathEdges, MaxEvidenceIDs: HardPathEvidenceIDs,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(portOverflow.Lanes) != 0 || portOverflow.Counts.OmittedFindings != 1 {
		t.Fatalf("over-capacity node port was partially rendered: %+v", portOverflow.Counts)
	}
}

func TestRoutePortAndTrackPitchClearArrowAndUnderlayEnvelopes(t *testing.T) {
	t.Parallel()
	if pathRailPitch < routeUnderlayWidth(EvidenceClassContradiction, 4)+2 {
		t.Fatalf("rail pitch %d cannot separate a %dpx underlay", pathRailPitch, routeUnderlayWidth(EvidenceClassContradiction, 4))
	}
	if pathEdgeRouteRowHeight < routeUnderlayWidth(EvidenceClassContradiction, 4)+2 {
		t.Fatalf("track pitch %d cannot separate a %dpx underlay", pathEdgeRouteRowHeight, routeUnderlayWidth(EvidenceClassContradiction, 4))
	}
	if pathPortPitch < 16 {
		t.Fatalf("port pitch %d overlaps 14px arrowheads", pathPortPitch)
	}
	if pathNodeHeight != 2*pathPortInset+(pathNodePortCapacity-1)*pathPortPitch {
		t.Fatalf("node height %d does not exactly bound %d separated ports", pathNodeHeight, pathNodePortCapacity)
	}
	if leftRail := pathColumnX[0] - pathRailDistanceMax; leftRail < pathLaneRectX+pathRouteClearance {
		t.Fatalf("left outer rail %d crosses the lane-border clearance", leftRail)
	}
	lastColumn := pathColumnX[len(pathColumnX)-1]
	if rightRail := lastColumn + pathNodeWidth + pathRailDistanceMax; rightRail > pathCanvasWidth-pathLaneRectX-pathRouteClearance {
		t.Fatalf("right outer rail %d crosses the lane-border clearance", rightRail)
	}
	for column := 1; column < len(pathColumnX); column++ {
		gap := pathColumnX[column] - (pathColumnX[column-1] + pathNodeWidth)
		if gap < 2*pathRailDistanceMax+pathInterBankGap {
			t.Fatalf("column gap %d cannot isolate two full route banks", gap)
		}
	}
}

func TestSameColumnAndCrossColumnEndpointStubsCannotFormFalseRelationship(t *testing.T) {
	t.Parallel()
	left := VisualNode{Column: 0, Row: 0, X: pathColumnX[0], Y: 278, Width: pathNodeWidth, Height: pathNodeHeight}
	middleSource := VisualNode{Column: 1, Row: 0, X: pathColumnX[1], Y: 278, Width: pathNodeWidth, Height: pathNodeHeight}
	middleTarget := VisualNode{Column: 1, Row: 1, X: pathColumnX[1], Y: 396, Width: pathNodeWidth, Height: pathNodeHeight}
	right := VisualNode{Column: 2, Row: 1, X: pathColumnX[2], Y: 396, Width: pathNodeWidth, Height: pathNodeHeight}
	sameColumn := routeEdge(middleSource, middleTarget, 700)
	crossColumn := routeEdge(left, right, 714)
	if horizontalSegmentsTouch(sameColumn[len(sameColumn)-2], sameColumn[len(sameColumn)-1], crossColumn[len(crossColumn)-2], crossColumn[len(crossColumn)-1]) {
		t.Fatalf("unrelated target stubs form a false continuous relationship: same=%v cross=%v", sameColumn, crossColumn)
	}
}

func routeRetraces(points []Point) bool {
	for left := 1; left < len(points); left++ {
		for right := left + 1; right < len(points); right++ {
			if collinearSegmentOverlap(points[left-1], points[left], points[right-1], points[right]) {
				return true
			}
		}
	}
	return false
}

func TestRouteRetraceDetectorRejectsAdjacentReversalOnly(t *testing.T) {
	t.Parallel()
	if !routeRetraces([]Point{{X: 0, Y: 0}, {X: 10, Y: 0}, {X: 10, Y: 20}, {X: 10, Y: 5}, {X: 20, Y: 5}}) {
		t.Fatal("adjacent same-gutter reversal was not detected")
	}
	for _, points := range [][]Point{
		{{X: 0, Y: 0}, {X: 10, Y: 0}, {X: 10, Y: 20}},
		{{X: 0, Y: 0}, {X: 10, Y: 0}, {X: 10, Y: 20}, {X: 20, Y: 20}},
	} {
		if routeRetraces(points) {
			t.Fatalf("non-retracing route was rejected: %v", points)
		}
	}
}

func collinearSegmentOverlap(a, b, c, d Point) bool {
	if a.X == b.X && c.X == d.X && a.X == c.X {
		return min(max(a.Y, b.Y), max(c.Y, d.Y))-max(min(a.Y, b.Y), min(c.Y, d.Y)) > 0
	}
	if a.Y == b.Y && c.Y == d.Y && a.Y == c.Y {
		return min(max(a.X, b.X), max(c.X, d.X))-max(min(a.X, b.X), min(c.X, d.X)) > 0
	}
	return false
}

func horizontalSegmentsTouch(a, b, c, d Point) bool {
	if a.Y != b.Y || c.Y != d.Y || a.Y != c.Y {
		return false
	}
	return min(max(a.X, b.X), max(c.X, d.X)) >= max(min(a.X, b.X), min(c.X, d.X))
}

func TestRouteIntersectionUsesStrokeClearance(t *testing.T) {
	t.Parallel()
	rect := integerRect{X: 10, Y: 10, Width: 20, Height: 20}
	for name, points := range map[string][]Point{
		"horizontal": {{X: 0, Y: 10}, {X: 40, Y: 10}},
		"vertical":   {{X: 30, Y: 0}, {X: 30, Y: 40}},
	} {
		if !routeIntersectsRect(points, rect) {
			t.Fatalf("%s boundary contact was not treated as an intersection", name)
		}
	}
	if routeIntersectsRect([]Point{{X: 0, Y: 9}, {X: 40, Y: 9}}, rect) {
		t.Fatal("separated route was treated as an intersection")
	}
}

func TestSVGHostileLabelCorpusAndClosedXMLVocabulary(t *testing.T) {
	t.Parallel()
	corpus := [][]byte{
		[]byte(`</text><script>alert("x")</script>`),
		[]byte(`quotes " ' & ampersand < >`),
		[]byte("control\x00\x07\x1b[31mred\x1b[0m\u202e"),
		[]byte("line\r\nseparator\u2028paragraph\u2029end"),
		{0xff, 0xfe, '<', '&', '"'},
		[]byte("xml-invalid-\u0001-noncharacter-\ufdd0-\U0010ffff"),
		[]byte(strings.Repeat("🙂", 4_000)),
		[]byte("=1+1 +SUM(A:A) -2 @cmd"),
		[]byte("https://example.invalid/data:text/html,javascript:alert(1)"),
	}
	for index, hostile := range corpus {
		t.Run(fmt.Sprintf("case-%02d", index), func(t *testing.T) {
			g := testGraphV2(t)
			g.Nodes[0].Label = string(hostile)
			_, data, err := RenderGraphSVG(context.Background(), g, PathOptions{})
			if err != nil {
				t.Fatal(err)
			}
			auditInertSVG(t, data)
			if !utf8.Valid(data) {
				t.Fatal("renderer emitted invalid UTF-8")
			}
		})
	}
}

func TestSVGSanitizesHostileFindingDescriptionWithoutChangingRetainedGap(t *testing.T) {
	t.Parallel()
	g := testGraphV2(t)
	hostileGap := "expired\x00\x1b[2J\r\nforged\u202e\u2066end"
	found := false
	for index := range g.FindingIndex {
		if g.FindingIndex[index].State != model.UnknownEvidenceGap {
			continue
		}
		g.FindingIndex[index].Repository = "fixture/repository\nforged\u202e"
		g.FindingIndex[index].WorkflowPath = ".github/workflows/demo.yml\u2066"
		g.FindingIndex[index].IndicatorID = "fixture-indicator\u202e"
		g.FindingIndex[index].EvidenceGapReason = hostileGap
		found = true
	}
	if !found {
		t.Fatal("fixture lacks UNKNOWN_EVIDENCE_GAP finding")
	}
	_, data, err := RenderGraphSVG(context.Background(), g, PathOptions{})
	if err != nil {
		t.Fatal(err)
	}
	auditInertSVG(t, data)
	for _, forbidden := range [][]byte{{0}, {0x1b}, {'\r'}, []byte("\u202e"), []byte("\u2066")} {
		if bytes.Contains(data, forbidden) {
			t.Fatalf("standalone SVG retained hostile control bytes %x", forbidden)
		}
	}
	for _, finding := range g.FindingIndex {
		if finding.State == model.UnknownEvidenceGap && finding.EvidenceGapReason != hostileGap {
			t.Fatal("SVG presentation changed retained machine evidence gap")
		}
	}
}

func TestSVGUsesOnlyRendererOwnedDOMIDsForHostileGraphIdentities(t *testing.T) {
	t.Parallel()
	focus := indexedFindingID(0)
	sourceID := `step-&<>'"-https://example.invalid/#fragment`
	targetID := `commit-&<>'"-data:image/svg+xml`
	edge, err := NewEdgeV2(EdgeStepExecutedAction, sourceID, targetID, []string{indexedEvidenceID(0)}, "t", EvidenceClassExactObservation, "", []string{focus})
	if err != nil {
		t.Fatal(err)
	}
	g := GraphV2{
		SchemaVersion: SchemaVersionV2, CaseKind: CaseKindSynthetic,
		FindingIndex: []FindingIndexEntry{testFinding(focus, model.ConfirmedExecuted)},
		Nodes: []NodeV2{
			{ID: sourceID, Type: NodeStep, Label: "step", FocusFindingIDs: []string{focus}},
			{ID: targetID, Type: NodeActionCommit, Label: "commit", FocusFindingIDs: []string{focus}},
		},
		Edges: []EdgeV2{edge},
	}
	_, data, err := RenderGraphSVG(context.Background(), g, PathOptions{})
	if err != nil {
		t.Fatal(err)
	}
	auditInertSVG(t, data)
	decoder := xml.NewDecoder(bytes.NewReader(data))
	seenDataIDs := make(map[string]bool)
	for {
		token, decodeErr := decoder.Token()
		if decodeErr != nil {
			if decodeErr.Error() == "EOF" {
				break
			}
			t.Fatal(decodeErr)
		}
		start, ok := token.(xml.StartElement)
		if !ok {
			continue
		}
		for _, attribute := range start.Attr {
			switch attribute.Name.Local {
			case "id":
				if attribute.Value != "tep-title" && attribute.Value != "tep-desc" && !strings.HasPrefix(attribute.Value, "n") && !strings.HasPrefix(attribute.Value, "e") {
					t.Fatalf("hostile identity controlled DOM id=%q", attribute.Value)
				}
			case "data-node-id":
				seenDataIDs[attribute.Value] = true
			}
		}
	}
	if !seenDataIDs[sourceID] || !seenDataIDs[targetID] {
		t.Fatalf("escaped data-node-id values did not preserve graph identity: %v", seenDataIDs)
	}
}

func TestGraphV2RejectsIdentityThatSVGSinkWouldRewrite(t *testing.T) {
	t.Parallel()
	g := manyNodeGraph(1)
	g.Nodes[0].ID = "step\nrewritten"
	if err := g.NormalizeAndValidate(); err == nil {
		t.Fatal("node identity requiring SVG-sink rewriting was accepted")
	}
}

func TestSVGSanitizerFlattensUnicodeLineBoundaries(t *testing.T) {
	t.Parallel()
	got, truncated := sanitizeSVGText("left\u2028middle\u2029right", 128)
	if truncated || got != "left middle right" {
		t.Fatalf("sanitized=%q truncated=%v", got, truncated)
	}
}

func TestFixedGeometryTextBoundsWideAndSpoofingLabelsDeterministically(t *testing.T) {
	t.Parallel()
	wide := strings.Repeat("界", 300)
	fullScope, visibleScope := PresentTemporalScope(wide + "\u202e-hidden")
	if strings.ContainsRune(fullScope, '\u202e') || strings.Contains(visibleScope, "hidden") {
		t.Fatalf("scope retained bidi-controlled presentation: full=%q visible=%q", fullScope, visibleScope)
	}
	if len([]rune(visibleScope)) > 80 || !strings.HasSuffix(visibleScope, "…") {
		t.Fatalf("wide scope is not bounded to 160 conservative units: runes=%d value=%q", len([]rune(visibleScope)), visibleScope)
	}

	fullGap, visibleGap := PresentTemporalGapReason(wide + "\x1b[2J\u2066-hidden")
	if strings.ContainsRune(fullGap, '\u2066') || strings.ContainsRune(fullGap, '\x1b') || strings.Contains(visibleGap, "hidden") {
		t.Fatalf("gap retained active presentation controls: full=%q visible=%q", fullGap, visibleGap)
	}
	if len([]rune(visibleGap)) > 60 || !strings.HasSuffix(visibleGap, "…") {
		t.Fatalf("wide gap is not bounded to 120 conservative units: runes=%d value=%q", len([]rune(visibleGap)), visibleGap)
	}

	lines := visibleLabelLines(wide)
	if len(lines) != 3 || !strings.HasSuffix(lines[len(lines)-1], "…") {
		t.Fatalf("wide node label lines=%q", lines)
	}
	for _, line := range lines {
		if len([]rune(line)) > 15 {
			t.Fatalf("wide node line exceeds 30 conservative units: %q", line)
		}
	}
	first := strings.Join(lines, "\x00")
	if second := strings.Join(visibleLabelLines(wide), "\x00"); first != second {
		t.Fatal("wide-label presentation is nondeterministic")
	}
}

func TestTemporalPathCancellationIsObservedBetweenBoundedPhases(t *testing.T) {
	t.Parallel()
	buildContext := newStepCancelContext(3)
	if _, err := BuildTemporalEvidencePath(buildContext, testGraphV2(t), PathOptions{}); err != context.Canceled {
		t.Fatalf("build cancellation error=%v", err)
	}
	path, err := BuildTemporalEvidencePath(context.Background(), testGraphV2(t), PathOptions{})
	if err != nil {
		t.Fatal(err)
	}
	renderContext := newStepCancelContext(2)
	if _, err := RenderSVG(renderContext, path); err != context.Canceled {
		t.Fatalf("render cancellation error=%v", err)
	}
}

func TestEdgeEvidenceReferencesAreBoundedAndFullyTraceable(t *testing.T) {
	t.Parallel()
	g := manyEvidenceGraph(t, 12)
	path, data, err := RenderGraphSVG(context.Background(), g, PathOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(path.Lanes) != 1 || len(path.Lanes[0].Edges) != 1 {
		t.Fatalf("unexpected visual shape: %+v", path.Counts)
	}
	edge := path.Lanes[0].Edges[0]
	if len(edge.EvidenceRefs) != 8 || edge.AdditionalRefs != 4 {
		t.Fatalf("compact refs=%v additional=%d", edge.EvidenceRefs, edge.AdditionalRefs)
	}
	for _, evidenceID := range edge.Edge.EvidenceIDs {
		if !bytes.Contains(data, []byte(evidenceID)) {
			t.Fatalf("full evidence ID %s is absent from accessible SVG detail", evidenceID)
		}
	}
	if !strings.Contains(string(data), "+4 more") {
		t.Fatal("visible edge label lacks bounded evidence-reference omission count")
	}
}

func TestKnownGoodComparisonRejectsSameAffectedAndKnownGoodIdentity(t *testing.T) {
	t.Parallel()
	run := model.WorkflowRunID(42)
	first, second := model.RunAttempt(1), model.RunAttempt(2)
	anchor := testFinding(findingID("1"), model.ConfirmedExecuted)
	anchor.RunID, anchor.RunAttempt = &run, &first
	anchor.ExactIdentityKind, anchor.ExactIdentity = ExactIdentityActionCommitSHA, "sha1:"+strings.Repeat("1", 40)
	candidate := testFinding(findingID("2"), model.NoMatchConfirmed)
	candidate.RunID, candidate.RunAttempt = &run, &second
	candidate.ExactIdentityKind, candidate.ExactIdentity = anchor.ExactIdentityKind, anchor.ExactIdentity
	candidate.ExactKnownGood, candidate.CoverageClosed = true, true
	if IsKnownGoodComparison(anchor, candidate) {
		t.Fatal("same exact identity was accepted as both affected anchor and known-good comparison")
	}
}

func manyLaneGraph(t *testing.T, count int) GraphV2 {
	t.Helper()
	g := GraphV2{SchemaVersion: SchemaVersionV2, CaseKind: CaseKindSynthetic}
	for index := 0; index < count; index++ {
		focus := indexedFindingID(index)
		step, commit := fmt.Sprintf("step-%03d", index), fmt.Sprintf("commit-%03d", index)
		g.FindingIndex = append(g.FindingIndex, testFinding(focus, model.ConfirmedExecuted))
		g.Nodes = append(g.Nodes,
			NodeV2{ID: step, Type: NodeStep, Label: step, FocusFindingIDs: []string{focus}},
			NodeV2{ID: commit, Type: NodeActionCommit, Label: commit, FocusFindingIDs: []string{focus}},
		)
		edge, err := NewEdgeV2(EdgeStepExecutedAction, step, commit, []string{indexedEvidenceID(index)}, fmt.Sprintf("t-%03d", index), EvidenceClassExactObservation, "", []string{focus})
		if err != nil {
			t.Fatal(err)
		}
		g.Edges = append(g.Edges, edge)
	}
	return g
}

func manyNodeGraph(count int) GraphV2 {
	focus := indexedFindingID(0)
	g := GraphV2{SchemaVersion: SchemaVersionV2, CaseKind: CaseKindSynthetic, FindingIndex: []FindingIndexEntry{testFinding(focus, model.ConfirmedExecuted)}}
	for index := 0; index < count; index++ {
		id := fmt.Sprintf("step-%03d", index)
		g.Nodes = append(g.Nodes, NodeV2{ID: id, Type: NodeStep, Label: id, FocusFindingIDs: []string{focus}})
	}
	return g
}

func manyEdgeGraph(t *testing.T, count int) GraphV2 {
	t.Helper()
	focus := indexedFindingID(0)
	g := GraphV2{
		SchemaVersion: SchemaVersionV2, CaseKind: CaseKindSynthetic,
		FindingIndex: []FindingIndexEntry{testFinding(focus, model.ConfirmedExecuted)},
		Nodes: []NodeV2{
			{ID: "step", Type: NodeStep, Label: "step", FocusFindingIDs: []string{focus}},
			{ID: "commit", Type: NodeActionCommit, Label: "commit", FocusFindingIDs: []string{focus}},
		},
	}
	for index := 0; index < count; index++ {
		edge, err := NewEdgeV2(EdgeStepExecutedAction, "step", "commit", []string{indexedEvidenceID(0)}, fmt.Sprintf("t-%04d", index), EvidenceClassExactObservation, "", []string{focus})
		if err != nil {
			t.Fatal(err)
		}
		g.Edges = append(g.Edges, edge)
	}
	return g
}

func manyBankEdgeGraph(t *testing.T, count int) GraphV2 {
	t.Helper()
	focus := indexedFindingID(0)
	g := GraphV2{
		SchemaVersion: SchemaVersionV2, CaseKind: CaseKindSynthetic,
		FindingIndex: []FindingIndexEntry{testFinding(focus, model.ConfirmedExecuted)},
		Nodes: []NodeV2{
			{ID: "step-a", Type: NodeStep, Label: "step-a", FocusFindingIDs: []string{focus}},
			{ID: "step-b", Type: NodeStep, Label: "step-b", FocusFindingIDs: []string{focus}},
			{ID: "commit-a", Type: NodeActionCommit, Label: "commit-a", FocusFindingIDs: []string{focus}},
			{ID: "commit-b", Type: NodeActionCommit, Label: "commit-b", FocusFindingIDs: []string{focus}},
		},
	}
	for index := 0; index < count; index++ {
		suffix := "a"
		if index >= (count+1)/2 {
			suffix = "b"
		}
		edge, err := NewEdgeV2(EdgeStepExecutedAction, "step-"+suffix, "commit-"+suffix, []string{indexedEvidenceID(0)}, fmt.Sprintf("t-bank-%04d", index), EvidenceClassExactObservation, "", []string{focus})
		if err != nil {
			t.Fatal(err)
		}
		g.Edges = append(g.Edges, edge)
	}
	return g
}

func manyEvidenceGraph(t *testing.T, count int) GraphV2 {
	t.Helper()
	focus := indexedFindingID(0)
	evidence := make([]string, count)
	for index := range evidence {
		evidence[index] = indexedEvidenceID(index)
	}
	edge, err := NewEdgeV2(EdgeStepExecutedAction, "step", "commit", evidence, "t", EvidenceClassExactObservation, "", []string{focus})
	if err != nil {
		t.Fatal(err)
	}
	return GraphV2{
		SchemaVersion: SchemaVersionV2, CaseKind: CaseKindSynthetic,
		FindingIndex: []FindingIndexEntry{testFinding(focus, model.ConfirmedExecuted)},
		Nodes: []NodeV2{
			{ID: "step", Type: NodeStep, Label: "step", FocusFindingIDs: []string{focus}},
			{ID: "commit", Type: NodeActionCommit, Label: "commit", FocusFindingIDs: []string{focus}},
		},
		Edges: []EdgeV2{edge},
	}
}

func largeSharedLaneGraph(t *testing.T) GraphV2 {
	t.Helper()
	findings := make([]FindingIndexEntry, HardPathFindingLanes)
	focus := make([]string, HardPathFindingLanes)
	for index := range findings {
		focus[index] = indexedFindingID(index)
		findings[index] = testFinding(focus[index], model.ConfirmedExecuted)
	}
	nodes := make([]NodeV2, HardPathNodes)
	label := strings.Repeat("long-hostile-looking-but-inert-&<>'\"-", 128)
	for index := range nodes {
		nodes[index] = NodeV2{ID: fmt.Sprintf("step-%03d", index), Type: NodeStep, Label: label, FocusFindingIDs: append([]string(nil), focus...)}
	}
	return GraphV2{SchemaVersion: SchemaVersionV2, CaseKind: CaseKindSynthetic, FindingIndex: findings, Nodes: nodes}
}

func indexedEvidenceID(index int) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("evidence-%08d", index)))
	return "ev1:" + hex.EncodeToString(sum[:])
}

func indexedFindingID(index int) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("finding-%08d", index)))
	return "frev1:" + hex.EncodeToString(sum[:])
}

func cloneTemporalPath(source TemporalEvidencePath) TemporalEvidencePath {
	result := source
	result.EvidenceKey = append([]EvidenceReference(nil), source.EvidenceKey...)
	result.Lanes = append([]TemporalEvidenceLane(nil), source.Lanes...)
	for laneIndex := range result.Lanes {
		result.Lanes[laneIndex].Nodes = append([]VisualNode(nil), source.Lanes[laneIndex].Nodes...)
		for nodeIndex := range result.Lanes[laneIndex].Nodes {
			node := &result.Lanes[laneIndex].Nodes[nodeIndex]
			node.LabelLines = append([]string(nil), node.LabelLines...)
			node.Node.EvidenceIDs = append([]string(nil), node.Node.EvidenceIDs...)
			node.Node.FocusFindingIDs = append([]string(nil), node.Node.FocusFindingIDs...)
		}
		result.Lanes[laneIndex].Edges = append([]VisualEdge(nil), source.Lanes[laneIndex].Edges...)
		for edgeIndex := range result.Lanes[laneIndex].Edges {
			edge := &result.Lanes[laneIndex].Edges[edgeIndex]
			edge.Points = append([]Point(nil), edge.Points...)
			edge.LabelLines = append([]string(nil), edge.LabelLines...)
			edge.EvidenceRefs = append([]string(nil), edge.EvidenceRefs...)
			edge.Edge.EvidenceIDs = append([]string(nil), edge.Edge.EvidenceIDs...)
			edge.Edge.FocusFindingIDs = append([]string(nil), edge.Edge.FocusFindingIDs...)
		}
		result.Lanes[laneIndex].Notices = append([]ProjectionNotice(nil), source.Lanes[laneIndex].Notices...)
		for noticeIndex := range result.Lanes[laneIndex].Notices {
			result.Lanes[laneIndex].Notices[noticeIndex].EvidenceIDs = append([]string(nil), source.Lanes[laneIndex].Notices[noticeIndex].EvidenceIDs...)
		}
	}
	return result
}

func assertNoDanglingVisualEdges(t *testing.T, path TemporalEvidencePath) {
	t.Helper()
	for _, lane := range path.Lanes {
		nodes := make(map[string]struct{}, len(lane.Nodes))
		for _, node := range lane.Nodes {
			nodes[node.Node.ID] = struct{}{}
		}
		for _, edge := range lane.Edges {
			if _, ok := nodes[edge.Edge.Source]; !ok {
				t.Fatalf("edge %s has absent source %s", edge.Edge.ID, edge.Edge.Source)
			}
			if _, ok := nodes[edge.Edge.Target]; !ok {
				t.Fatalf("edge %s has absent target %s", edge.Edge.ID, edge.Edge.Target)
			}
		}
	}
}

func auditInertSVG(t *testing.T, data []byte) {
	t.Helper()
	if bytes.HasPrefix(data, []byte("<?")) || bytes.Contains(data, []byte("<!DOCTYPE")) || bytes.Contains(data, []byte("<!ENTITY")) || bytes.Contains(data, []byte("<![CDATA[")) {
		t.Fatal("SVG contains a declaration, DTD, entity, or CDATA")
	}
	if bytes.Count(data, []byte("<style>")) != 1 || !bytes.Contains(data, []byte("<style>"+forcedColorStylesheet+"</style>")) {
		t.Fatal("SVG does not contain exactly the fixed forced-colors policy")
	}
	allowedElements := map[string]struct{}{
		"svg": {}, "title": {}, "desc": {}, "g": {}, "rect": {}, "line": {},
		"polyline": {}, "polygon": {}, "circle": {}, "text": {}, "tspan": {}, "style": {},
	}
	decoder := xml.NewDecoder(bytes.NewReader(data))
	for {
		token, err := decoder.Token()
		if err != nil {
			if err.Error() == "EOF" {
				return
			}
			t.Fatal(err)
		}
		switch value := token.(type) {
		case xml.ProcInst, xml.Directive:
			t.Fatalf("SVG contains processing instruction or directive %T", value)
		case xml.StartElement:
			if _, ok := allowedElements[value.Name.Local]; !ok {
				t.Fatalf("SVG contains unsupported element %q", value.Name.Local)
			}
			for _, attribute := range value.Attr {
				name := strings.ToLower(attribute.Name.Local)
				lowerValue := strings.ToLower(attribute.Value)
				if strings.HasPrefix(name, "on") || name == "href" || name == "style" || strings.Contains(lowerValue, "url(") || strings.HasPrefix(lowerValue, "data:") {
					t.Fatalf("SVG contains active or external attribute %s=%q", name, attribute.Value)
				}
			}
		}
	}
}

type stepCancelContext struct {
	done      chan struct{}
	remaining int
}

func newStepCancelContext(trigger int) *stepCancelContext {
	return &stepCancelContext{done: make(chan struct{}), remaining: trigger}
}

func (ctx *stepCancelContext) Deadline() (time.Time, bool) { return time.Time{}, false }

func (ctx *stepCancelContext) Done() <-chan struct{} {
	ctx.remaining--
	if ctx.remaining == 0 {
		close(ctx.done)
	}
	return ctx.done
}

func (ctx *stepCancelContext) Err() error {
	select {
	case <-ctx.done:
		return context.Canceled
	default:
		return nil
	}
}

func (ctx *stepCancelContext) Value(any) any { return nil }
