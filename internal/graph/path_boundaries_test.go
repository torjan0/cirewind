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
			{DefaultPathEdges, 0, 1},
			{DefaultPathEdges + 1, 0, 0},
			{HardPathEdges, HardPathEdges, 1},
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

func TestWorkflowDeclarationWordingUsesTypedFindingState(t *testing.T) {
	t.Parallel()
	const historicalLookingLabel = "historical workflow at deadbeef — hostile display text"
	const currentLookingLabel = "current default branch snapshot — hostile display text"

	build := func(t *testing.T, state model.FindingState, workflowLabel string) TemporalEvidencePath {
		t.Helper()
		focus := indexedFindingID(int(state[0]))
		evidence := indexedEvidenceID(int(state[0]))
		edge, err := NewEdgeV2(
			EdgeWorkflowDeclaredAction, "workflow", "ref", []string{evidence}, "",
			EvidenceClassInference, "workflow-definition-reference/v1", []string{focus},
		)
		if err != nil {
			t.Fatal(err)
		}
		finding := testFinding(focus, state)
		g := GraphV2{
			SchemaVersion: SchemaVersionV2, CaseKind: CaseKindSynthetic,
			FindingIndex: []FindingIndexEntry{finding},
			Nodes: []NodeV2{
				{ID: "workflow", Type: NodeWorkflowDefinition, Label: workflowLabel, FocusFindingIDs: []string{focus}},
				{ID: "ref", Type: NodeActionRef, Label: "fixture/action@v1", FocusFindingIDs: []string{focus}},
			},
			Edges: []EdgeV2{edge},
		}
		path, err := BuildTemporalEvidencePath(context.Background(), g, PathOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if len(path.Lanes) != 1 || len(path.Lanes[0].Edges) != 1 {
			t.Fatalf("unexpected temporal path shape: %+v", path.Counts)
		}
		return path
	}

	current := build(t, model.CurrentReferenceOnly, historicalLookingLabel)
	if got := current.Lanes[0].Edges[0].RelationshipText; got != "present-day workflow snapshot declared Action — inferred" {
		t.Fatalf("current snapshot relationship=%q", got)
	}
	historical := build(t, model.DeclaredAtRunSHA, currentLookingLabel)
	if got := historical.Lanes[0].Edges[0].RelationshipText; got != "historical workflow declared Action — inferred" {
		t.Fatalf("historical relationship=%q", got)
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
	allowedElements := map[string]struct{}{
		"svg": {}, "title": {}, "desc": {}, "g": {}, "rect": {}, "line": {},
		"polyline": {}, "polygon": {}, "circle": {}, "text": {}, "tspan": {},
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
