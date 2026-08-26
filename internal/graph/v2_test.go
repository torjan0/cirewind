package graph

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/xml"
	"fmt"
	"math"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/torjan0/cirewind/internal/model"
)

func TestGraphV2RequiresCanonicalExplicitEvidenceClassAndIdentity(t *testing.T) {
	t.Parallel()
	focus := findingID("a")
	edge, err := NewEdgeV2(EdgeStepExecutedAction, "step", "commit", []string{evidenceID("a")}, "2026-08-19T10:30:00Z", EvidenceClassExactObservation, "", []string{focus})
	if err != nil {
		t.Fatal(err)
	}
	g := GraphV2{
		CaseKind:     CaseKindSynthetic,
		FindingIndex: []FindingIndexEntry{testFinding(focus, model.ConfirmedExecuted)},
		Nodes: []NodeV2{
			{ID: "step", Type: NodeStep, Label: "step", FocusFindingIDs: []string{focus}},
			{ID: "commit", Type: NodeActionCommit, Label: "B", FocusFindingIDs: []string{focus}},
		}, Edges: []EdgeV2{edge},
	}
	if err := g.NormalizeAndValidate(); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(g.Edges[0].ID, "gedge2:") {
		t.Fatalf("v2 ID=%q", g.Edges[0].ID)
	}

	for name, mutate := range map[string]func(*GraphV2){
		"missing class":    func(value *GraphV2) { value.Edges[0].EvidenceClass = "" },
		"wrong ID":         func(value *GraphV2) { value.Edges[0].ID = "gedge2:" + strings.Repeat("0", 64) },
		"missing evidence": func(value *GraphV2) { value.Edges[0].EvidenceIDs = nil },
		"missing focus":    func(value *GraphV2) { value.Edges[0].FocusFindingIDs = nil },
	} {
		t.Run(name, func(t *testing.T) {
			broken := CloneGraphV2(g)
			mutate(&broken)
			if err := broken.NormalizeAndValidate(); err == nil {
				t.Fatal("invalid v2 graph accepted")
			}
		})
	}
}

func TestStableEdgeIDV2SeparatesClassRuleAndLegacyNamespace(t *testing.T) {
	t.Parallel()
	arguments := func(class EvidenceClass, rule string) string {
		id, err := StableEdgeIDV2(EdgeHadTokenPermission, "job", "token", "unknown", class, rule)
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	exact := arguments(EvidenceClassExactObservation, "")
	inferredA := arguments(EvidenceClassInference, "static-a/v1")
	inferredB := arguments(EvidenceClassInference, "static-b/v1")
	if exact == inferredA || inferredA == inferredB {
		t.Fatal("class or rule did not participate in v2 edge identity")
	}
	for _, id := range []string{exact, inferredA, inferredB} {
		if strings.HasPrefix(id, "gedge1:") || !strings.HasPrefix(id, "gedge2:") {
			t.Fatalf("cross-version identity %q", id)
		}
	}
}

func TestKnownGoodComparisonPredicateIsNarrow(t *testing.T) {
	t.Parallel()
	run := model.WorkflowRunID(42)
	first := model.RunAttempt(1)
	second := model.RunAttempt(2)
	anchor := testFinding(findingID("a"), model.ConfirmedExecuted)
	anchor.RunID, anchor.RunAttempt = &run, &first
	anchor.ExactIdentityKind, anchor.ExactIdentity = ExactIdentityActionCommitSHA, "sha1:"+strings.Repeat("1", 40)
	candidate := testFinding(findingID("b"), model.NoMatchConfirmed)
	candidate.RunID, candidate.RunAttempt = &run, &second
	candidate.ExactIdentityKind, candidate.ExactIdentity = ExactIdentityActionCommitSHA, "sha1:"+strings.Repeat("0", 40)
	candidate.ExactKnownGood, candidate.CoverageClosed = true, true
	if !IsKnownGoodComparison(anchor, candidate) {
		t.Fatal("valid same-run exact known-good rerun was not selected")
	}
	for name, mutate := range map[string]func(*FindingIndexEntry){
		"same attempt":    func(value *FindingIndexEntry) { value.RunAttempt = &first },
		"other indicator": func(value *FindingIndexEntry) { value.IndicatorID = "other" },
		"not exact good":  func(value *FindingIndexEntry) { value.ExactKnownGood = false },
		"open coverage":   func(value *FindingIndexEntry) { value.CoverageClosed = false },
		"wrong state":     func(value *FindingIndexEntry) { value.State = model.CurrentReferenceOnly },
	} {
		t.Run(name, func(t *testing.T) {
			changed := candidate
			mutate(&changed)
			if IsKnownGoodComparison(anchor, changed) {
				t.Fatal("unrelated negative admitted as comparison")
			}
		})
	}
}

func TestPathIncludesOnlyTypedSameRunKnownGoodComparison(t *testing.T) {
	t.Parallel()
	run := model.WorkflowRunID(77)
	attemptOne, attemptTwo := model.RunAttempt(1), model.RunAttempt(2)
	executedID, noMatchID := findingID("a"), findingID("b")
	executed := testFinding(executedID, model.ConfirmedExecuted)
	executed.RunID, executed.RunAttempt = &run, &attemptOne
	executed.ExactIdentityKind, executed.ExactIdentity = ExactIdentityActionCommitSHA, "sha1:"+strings.Repeat("1", 40)
	noMatch := testFinding(noMatchID, model.NoMatchConfirmed)
	noMatch.RunID, noMatch.RunAttempt = &run, &attemptTwo
	noMatch.ExactIdentityKind, noMatch.ExactIdentity = ExactIdentityActionCommitSHA, "sha1:"+strings.Repeat("0", 40)
	noMatch.ExactKnownGood, noMatch.CoverageClosed = true, true
	nodes := []NodeV2{
		{ID: "step-b", Type: NodeStep, Label: "attempt 1 step", FocusFindingIDs: []string{executedID}},
		{ID: "commit-b", Type: NodeActionCommit, Label: "B", FocusFindingIDs: []string{executedID}},
		{ID: "attempt-a", Type: NodeRunAttempt, Label: "attempt 2", FocusFindingIDs: []string{noMatchID}},
		{ID: "run-a", Type: NodeWorkflowRun, Label: "run 77", FocusFindingIDs: []string{noMatchID}},
	}
	edgeOne, err := NewEdgeV2(EdgeStepExecutedAction, "step-b", "commit-b", []string{evidenceID("a")}, "unknown", EvidenceClassExactObservation, "", []string{executedID})
	if err != nil {
		t.Fatal(err)
	}
	edgeTwo, err := NewEdgeV2(EdgeAttemptOfRun, "attempt-a", "run-a", []string{evidenceID("b")}, "unknown", EvidenceClassExactObservation, "", []string{noMatchID})
	if err != nil {
		t.Fatal(err)
	}
	g := GraphV2{SchemaVersion: SchemaVersionV2, CaseKind: CaseKindSynthetic, Nodes: nodes, Edges: []EdgeV2{edgeOne, edgeTwo}, FindingIndex: []FindingIndexEntry{executed, noMatch}}
	path, err := BuildTemporalEvidencePath(context.Background(), g, PathOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(path.Lanes) != 2 || path.Lanes[1].Finding.State != model.NoMatchConfirmed {
		t.Fatalf("known-good comparison lanes=%v", laneStates(path.Lanes))
	}

	unrelated := CloneGraphV2(g)
	unrelated.FindingIndex[1].Repository = "fixture/other"
	path, err = BuildTemporalEvidencePath(context.Background(), unrelated, PathOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(path.Lanes) != 1 {
		t.Fatalf("unrelated no-match became visual comparison: %v", laneStates(path.Lanes))
	}
}

func laneStates(lanes []TemporalEvidenceLane) []model.FindingState {
	result := make([]model.FindingState, len(lanes))
	for i := range lanes {
		result[i] = lanes[i].Finding.State
	}
	return result
}

func testFinding(id string, state model.FindingState) FindingIndexEntry {
	entry := FindingIndexEntry{
		FindingRevisionID: id, State: state, ProvenanceLevel: model.L3Strong,
		Repository: "fixture/repository", WorkflowPath: ".github/workflows/demo.yml",
		IndicatorID: "fixture-indicator",
	}
	if state == model.UnknownEvidenceGap {
		entry.ProvenanceLevel = model.L0Unknown
		entry.EvidenceGapReason = "logs expired"
	}
	return entry
}

func testGraphV2(t *testing.T) GraphV2 {
	t.Helper()
	executed, gap, inferred, conflict := findingID("a"), findingID("b"), findingID("c"), findingID("d")
	focusExecuted := []string{executed}
	nodes := []NodeV2{
		{ID: "job", Type: NodeJob, Label: "job & <deploy>", FocusFindingIDs: focusExecuted},
		{ID: "step", Type: NodeStep, Label: "build\x1b[2J\n</text><script>alert(1)</script>\u202e", FocusFindingIDs: focusExecuted},
		{ID: "commit", Type: NodeActionCommit, Label: strings.Repeat("harmless-B-", 45), FocusFindingIDs: focusExecuted},
		{ID: "token", Type: NodeTokenCapability, Label: "contents: write", FocusFindingIDs: focusExecuted},
		{ID: "deploy", Type: NodeDeployment, Label: "deployment observed later", FocusFindingIDs: focusExecuted},
		{ID: "workflow-gap", Type: NodeWorkflowDefinition, Label: "missing historical workflow", FocusFindingIDs: []string{gap}},
		{ID: "workflow-static", Type: NodeWorkflowDefinition, Label: "historical wrapper", FocusFindingIDs: []string{inferred}},
		{ID: "ref-static", Type: NodeActionRef, Label: "fixture/action@v1", FocusFindingIDs: []string{inferred}},
		{ID: "commit-static", Type: NodeActionCommit, Label: "runtime B", FocusFindingIDs: []string{conflict}},
		{ID: "commit-yaml", Type: NodeActionCommit, Label: "declared A", FocusFindingIDs: []string{conflict}},
	}
	makeEdge := func(edgeType EdgeType, source, target, evidence string, class EvidenceClass, rule, finding string) EdgeV2 {
		edge, err := NewEdgeV2(edgeType, source, target, []string{evidence}, "2026-08-19T10:30:00Z", class, rule, []string{finding})
		if err != nil {
			t.Fatal(err)
		}
		return edge
	}
	edges := []EdgeV2{
		makeEdge(EdgeStepExecutedAction, "step", "commit", evidenceID("a"), EvidenceClassExactObservation, "", executed),
		makeEdge(EdgeHadTokenPermission, "job", "token", evidenceID("b"), EvidenceClassInference, "credential-relationship/historical-definition-flow/v1", executed),
		makeEdge(EdgeObservedAfter, "step", "deploy", evidenceID("c"), EvidenceClassTemporalCorrelation, "", executed),
		makeEdge(EdgeWorkflowDeclaredAction, "workflow-static", "ref-static", evidenceID("d"), EvidenceClassInference, "historical-mutable-ref/v1", inferred),
		makeEdge(EdgeContradicts, "commit-static", "commit-yaml", evidenceID("e"), EvidenceClassContradiction, "runtime-static-contradiction/v1", conflict),
	}
	g := GraphV2{
		SchemaVersion: SchemaVersionV2, CaseKind: CaseKindSynthetic,
		Nodes: nodes, Edges: edges,
		FindingIndex: []FindingIndexEntry{
			testFinding(executed, model.ConfirmedExecuted), testFinding(gap, model.UnknownEvidenceGap),
			testFinding(inferred, model.RunInWindowMutableRef), testFinding(conflict, model.ContradictoryEvidence),
		},
		ProjectionNotices: []ProjectionNotice{
			{Code: ProjectionNoticeUnclassifiableLegacyBasis, FindingRevisionID: executed, Relationship: EdgePassedSecretTo, EvidenceIDs: []string{evidenceID("f")}},
			{Code: ProjectionNoticeUnclassifiableLegacyBasis, FindingRevisionID: executed, Relationship: EdgeInheritedSecret, EvidenceIDs: []string{evidenceID("0")}},
		},
	}
	return g
}

func TestTemporalPathAndSVGAreDeterministicOrderIndependentAndDoNotMutate(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	firstInput := testGraphV2(t)
	original := CloneGraphV2(firstInput)
	firstPath, first, err := RenderGraphSVG(ctx, firstInput, PathOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(firstInput, original) {
		t.Fatal("renderer mutated source graph")
	}

	secondInput := CloneGraphV2(firstInput)
	slices.Reverse(secondInput.Nodes)
	slices.Reverse(secondInput.Edges)
	slices.Reverse(secondInput.FindingIndex)
	slices.Reverse(secondInput.ProjectionNotices)
	for i := range secondInput.Nodes {
		slices.Reverse(secondInput.Nodes[i].EvidenceIDs)
		slices.Reverse(secondInput.Nodes[i].FocusFindingIDs)
	}
	for i := range secondInput.Edges {
		slices.Reverse(secondInput.Edges[i].EvidenceIDs)
		slices.Reverse(secondInput.Edges[i].FocusFindingIDs)
	}
	for i := range secondInput.ProjectionNotices {
		slices.Reverse(secondInput.ProjectionNotices[i].EvidenceIDs)
	}
	secondPath, second, err := RenderGraphSVG(ctx, secondInput, PathOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("reversed source ordering changed SVG bytes")
	}
	if !reflect.DeepEqual(firstPath, secondPath) {
		t.Fatal("reversed source ordering changed presentation model")
	}
	if len(first) > MaxSVGBytes {
		t.Fatalf("SVG exceeds hard byte limit: %d", len(first))
	}
	wantDigest := "0815cfa40ef69fe71ebf6fc9b6168c5afa4cde17fdc8a4864a61509b79dcb180"
	if got := fmt.Sprintf("%x", sha256.Sum256(first)); got != wantDigest {
		t.Fatalf("cross-platform SVG golden digest=%s, want %s", got, wantDigest)
	}
}

func TestValidateTemporalEvidencePathFailsClosedWithoutSerialization(t *testing.T) {
	t.Parallel()
	path, err := BuildTemporalEvidencePath(context.Background(), testGraphV2(t), PathOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateTemporalEvidencePath(path); err != nil {
		t.Fatal(err)
	}
	path.Lanes[0].Edges[0].RelationshipText = "unsupported causal claim"
	if err := ValidateTemporalEvidencePath(path); err == nil {
		t.Fatal("noncanonical report relationship wording was accepted")
	}
}

func TestSVGIsValidInertXMLWithRequiredVisualSemantics(t *testing.T) {
	t.Parallel()
	_, data, err := RenderGraphSVG(context.Background(), testGraphV2(t), PathOptions{})
	if err != nil {
		t.Fatal(err)
	}
	allowedElements := map[string]bool{"svg": true, "title": true, "desc": true, "g": true, "rect": true, "line": true, "polyline": true, "polygon": true, "circle": true, "text": true, "tspan": true}
	decoder := xml.NewDecoder(bytes.NewReader(data))
	for {
		token, err := decoder.Token()
		if err != nil {
			if err.Error() == "EOF" {
				break
			}
			t.Fatal(err)
		}
		start, ok := token.(xml.StartElement)
		if !ok {
			continue
		}
		if !allowedElements[start.Name.Local] {
			t.Fatalf("active or unknown SVG element %q", start.Name.Local)
		}
		for _, attr := range start.Attr {
			name := strings.ToLower(attr.Name.Local)
			if strings.HasPrefix(name, "on") || name == "href" || name == "style" || strings.Contains(strings.ToLower(attr.Value), "url(") || strings.HasPrefix(strings.ToLower(attr.Value), "data:") {
				t.Fatalf("unsafe SVG attribute %s=%q", name, attr.Value)
			}
		}
	}
	text := string(data)
	for _, required := range []string{
		colorExact, colorInference, colorTemporal, colorContradiction, colorGap,
		"stroke-dasharray=\"10 7\"", "stroke-dasharray=\"2 7\"",
		"step execution began", "inferred", "observed after — causation not established",
		"contradicts", "UNKNOWN_EVIDENCE_GAP", "visual relationship omitted — legacy evidence basis unavailable",
		"contents: write", "ui-monospace, monospace", "role=\"img\"",
	} {
		if !strings.Contains(text, required) {
			t.Errorf("SVG lacks %q", required)
		}
	}
	for _, prohibited := range []string{"<script", "foreignObject", "javascript:", "cloud role assumed", "attack path", "executed on runner"} {
		if strings.Contains(text, prohibited) {
			t.Errorf("SVG contains prohibited content %q", prohibited)
		}
	}
	if !strings.Contains(text, "&lt;/text&gt;&lt;script&gt;alert(1)&lt;/script&gt;") {
		t.Fatal("hostile label was not safely XML escaped")
	}
}

func TestTemporalPathLimitsOmitWholeSlicesWithoutDanglingEdges(t *testing.T) {
	t.Parallel()
	path, err := BuildTemporalEvidencePath(context.Background(), testGraphV2(t), PathOptions{MaxFindingLanes: 1, MaxNodes: HardPathNodes, MaxEdges: HardPathEdges, MaxEvidenceIDs: HardPathEvidenceIDs})
	if err != nil {
		t.Fatal(err)
	}
	if len(path.Lanes) != 1 || path.Counts.OmittedFindings != path.Counts.TotalFindings-1 {
		t.Fatalf("unexpected bounded selection: %+v", path.Counts)
	}
	for _, lane := range path.Lanes {
		nodes := map[string]bool{}
		for _, node := range lane.Nodes {
			nodes[node.Node.ID] = true
		}
		for _, edge := range lane.Edges {
			if !nodes[edge.Edge.Source] || !nodes[edge.Edge.Target] {
				t.Fatalf("dangling visual edge %s", edge.Edge.ID)
			}
		}
	}
	if _, err := BuildTemporalEvidencePath(context.Background(), testGraphV2(t), PathOptions{MaxFindingLanes: HardPathFindingLanes + 1}); err == nil {
		t.Fatal("over-hard lane budget accepted")
	}
}

func TestTemporalPathHonorsCancellation(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := BuildTemporalEvidencePath(ctx, testGraphV2(t), PathOptions{}); !errorsIsCanceled(err) {
		t.Fatalf("Build error=%v", err)
	}
	path, err := BuildTemporalEvidencePath(context.Background(), testGraphV2(t), PathOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := RenderSVG(ctx, path); !errorsIsCanceled(err) {
		t.Fatalf("Render error=%v", err)
	}
}

func errorsIsCanceled(err error) bool { return err == context.Canceled }

func TestVisibleLabelUsesBoundedRuneGeometry(t *testing.T) {
	t.Parallel()
	lines := visibleLabelLines(strings.Repeat("🙂", 200))
	if len(lines) > 3 {
		t.Fatalf("line count=%d", len(lines))
	}
	totalBytes := 0
	for _, line := range lines {
		if len([]rune(line)) > 32 {
			t.Fatalf("line exceeds 32 runes: %q", line)
		}
		totalBytes += len(line)
	}
	if totalBytes > 192+len("…") {
		t.Fatalf("visible label bytes=%d", totalBytes)
	}
	if !strings.HasSuffix(lines[len(lines)-1], "…") {
		t.Fatal("truncated label lacks visible ellipsis")
	}
}

func TestAcceptedPaletteMeetsLightBackgroundContrastFloors(t *testing.T) {
	t.Parallel()
	for _, color := range []string{colorText} {
		if ratio := contrastRatio(color, colorBackground); ratio < 4.5 {
			t.Errorf("text color %s contrast %.2f < 4.5", color, ratio)
		}
	}
	for _, color := range []string{colorExact, colorInference, colorTemporal, colorContradiction, colorGap, colorBorder} {
		if ratio := contrastRatio(color, colorBackground); ratio < 3 {
			t.Errorf("graph color %s contrast %.2f < 3", color, ratio)
		}
	}
}

func contrastRatio(left, right string) float64 {
	l1, l2 := relativeLuminance(left), relativeLuminance(right)
	if l2 > l1 {
		l1, l2 = l2, l1
	}
	return (l1 + .05) / (l2 + .05)
}

func relativeLuminance(color string) float64 {
	channels := make([]float64, 3)
	for i := range channels {
		value, _ := strconv.ParseUint(color[1+i*2:3+i*2], 16, 8)
		channel := float64(value) / 255
		if channel <= .04045 {
			channels[i] = channel / 12.92
		} else {
			channels[i] = math.Pow((channel+.055)/1.055, 2.4)
		}
	}
	return .2126*channels[0] + .7152*channels[1] + .0722*channels[2]
}
