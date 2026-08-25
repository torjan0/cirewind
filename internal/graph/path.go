package graph

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"

	"github.com/torjan0/cirewind/internal/model"
)

const (
	DefaultPathFindingLanes = 12
	HardPathFindingLanes    = 32
	DefaultPathNodes        = 96
	HardPathNodes           = 256
	DefaultPathEdges        = 144
	HardPathEdges           = 512
	DefaultPathEvidenceIDs  = 256
	HardPathEvidenceIDs     = 512
	MaxSVGBytes             = 8 << 20

	pathCanvasWidth = 1740
	pathTop         = 248
	pathLaneGap     = 28
	pathNodeWidth   = 330
	pathNodeHeight  = 88
	pathRowGap      = 30
)

var pathColumnX = [...]int{36, 456, 876, 1296}

type PathOptions struct {
	MaxFindingLanes int
	MaxNodes        int
	MaxEdges        int
	MaxEvidenceIDs  int
}

type SelectionCounts struct {
	SelectedFindings    int
	TotalFindings       int
	OmittedFindings     int
	SelectedNodes       int
	TotalNodes          int
	OmittedNodes        int
	SelectedEdges       int
	TotalEdges          int
	OmittedEdges        int
	SelectedEvidenceIDs int
	TotalEvidenceIDs    int
	OmittedEvidenceIDs  int
}

type Point struct{ X, Y int }

type VisualNode struct {
	Node       NodeV2
	LocalID    string
	Column     int
	Row        int
	X          int
	Y          int
	Width      int
	Height     int
	FullLabel  string
	LabelLines []string
}

type VisualEdge struct {
	Edge             EdgeV2
	LocalID          string
	Points           []Point
	LabelX           int
	LabelY           int
	RelationshipText string
	EvidenceRefs     []string
	AdditionalRefs   int
}

type EvidenceReference struct {
	CompactID  string
	EvidenceID string
}

type TemporalEvidenceLane struct {
	Finding FindingIndexEntry
	Y       int
	Height  int
	Nodes   []VisualNode
	Edges   []VisualEdge
	Notices []ProjectionNotice
}

// TemporalEvidencePath is a deterministic presentation model shared by the
// standalone SVG and report integration. It contains no independent facts.
type TemporalEvidencePath struct {
	SchemaVersion string
	CaseKind      CaseKind
	Width         int
	Height        int
	Counts        SelectionCounts
	Lanes         []TemporalEvidenceLane
	EvidenceKey   []EvidenceReference
}

func normalizePathOptions(options PathOptions) (PathOptions, error) {
	defaults := []struct {
		value              *int
		defaultValue, hard int
		name               string
	}{
		{&options.MaxFindingLanes, DefaultPathFindingLanes, HardPathFindingLanes, "finding lanes"},
		{&options.MaxNodes, DefaultPathNodes, HardPathNodes, "nodes"},
		{&options.MaxEdges, DefaultPathEdges, HardPathEdges, "edges"},
		{&options.MaxEvidenceIDs, DefaultPathEvidenceIDs, HardPathEvidenceIDs, "evidence IDs"},
	}
	for _, item := range defaults {
		if *item.value == 0 {
			*item.value = item.defaultValue
		}
		if *item.value < 1 || *item.value > item.hard {
			return PathOptions{}, fmt.Errorf("temporal evidence path %s limit must be between 1 and %d", item.name, item.hard)
		}
	}
	return options, nil
}

// BuildTemporalEvidencePath selects complete deterministic finding slices and
// lays them out without mutating graphInput.
func BuildTemporalEvidencePath(ctx context.Context, graphInput GraphV2, options PathOptions) (TemporalEvidencePath, error) {
	if ctx == nil {
		return TemporalEvidencePath{}, errors.New("nil context")
	}
	if err := checkContext(ctx); err != nil {
		return TemporalEvidencePath{}, err
	}
	options, err := normalizePathOptions(options)
	if err != nil {
		return TemporalEvidencePath{}, err
	}
	g := CloneGraphV2(graphInput)
	if err := g.NormalizeAndValidate(); err != nil {
		return TemporalEvidencePath{}, err
	}
	if err := checkContext(ctx); err != nil {
		return TemporalEvidencePath{}, err
	}
	return buildTemporalEvidencePath(ctx, g, options, options.MaxFindingLanes)
}

// buildTemporalEvidencePath consumes an already normalized private graph copy.
// laneLimit may be zero so RenderGraphSVG can omit complete trailing finding
// slices when the fixed SVG byte ceiling is the binding hard limit.
func buildTemporalEvidencePath(ctx context.Context, g GraphV2, options PathOptions, laneLimit int) (TemporalEvidencePath, error) {

	byState := make(map[model.FindingState][]FindingIndexEntry)
	for _, entry := range g.FindingIndex {
		if entry.State != model.NoMatchConfirmed {
			byState[entry.State] = append(byState[entry.State], entry)
		}
	}
	for state := range byState {
		sort.Slice(byState[state], func(i, j int) bool { return findingSortKey(byState[state][i]) < findingSortKey(byState[state][j]) })
	}

	attention := []model.FindingState{
		model.ContradictoryEvidence, model.UnknownEvidenceGap, model.ConfirmedExecuted,
		model.ConfirmedDownloaded, model.ConfirmedCalledWorkflow, model.DeclaredAtRunSHA,
		model.RunInWindowMutableRef, model.PotentialTransitive, model.CurrentReferenceOnly,
	}
	var candidates []FindingIndexEntry
	for _, state := range attention {
		if entries := byState[state]; len(entries) > 0 {
			candidates = append(candidates, entries[0])
		}
	}
	for _, state := range attention {
		if entries := byState[state]; len(entries) > 1 {
			candidates = append(candidates, entries[1:]...)
		}
	}

	selected := make([]FindingIndexEntry, 0, options.MaxFindingLanes)
	selectedNodeIDs := make(map[string]struct{})
	selectedEdgeIDs := make(map[string]struct{})
	selectedEvidence := make(map[string]struct{})
	trySelect := func(entry FindingIndexEntry) bool {
		if len(selected) >= laneLimit {
			return false
		}
		nodeIDs, edgeIDs, evidenceIDs := findingSlice(g, entry.FindingRevisionID)
		newNodes, newEdges, newEvidence := cloneSet(selectedNodeIDs), cloneSet(selectedEdgeIDs), cloneSet(selectedEvidence)
		mergeSet(newNodes, nodeIDs)
		mergeSet(newEdges, edgeIDs)
		mergeSet(newEvidence, evidenceIDs)
		if len(newNodes) > options.MaxNodes || len(newEdges) > options.MaxEdges || len(newEvidence) > options.MaxEvidenceIDs {
			return false
		}
		selected = append(selected, entry)
		selectedNodeIDs, selectedEdgeIDs, selectedEvidence = newNodes, newEdges, newEvidence
		return true
	}
	for i, candidate := range candidates {
		if i&31 == 0 {
			if err := checkContext(ctx); err != nil {
				return TemporalEvidencePath{}, err
			}
		}
		trySelect(candidate)
	}

	// A clean rerun is comparison context only when it matches a selected exact
	// affected anchor under the narrow typed predicate.
	var comparisons []FindingIndexEntry
	for _, candidate := range g.FindingIndex {
		if candidate.State != model.NoMatchConfirmed {
			continue
		}
		for _, anchor := range selected {
			if IsKnownGoodComparison(anchor, candidate) {
				comparisons = append(comparisons, candidate)
				break
			}
		}
	}
	sort.Slice(comparisons, func(i, j int) bool { return findingSortKey(comparisons[i]) < findingSortKey(comparisons[j]) })
	for _, candidate := range comparisons {
		trySelect(candidate)
	}

	fullEvidence := make(map[string]struct{})
	for _, edge := range g.Edges {
		for _, id := range edge.EvidenceIDs {
			fullEvidence[id] = struct{}{}
		}
	}
	for _, notice := range g.ProjectionNotices {
		for _, id := range notice.EvidenceIDs {
			fullEvidence[id] = struct{}{}
		}
	}
	counts := SelectionCounts{
		SelectedFindings: len(selected), TotalFindings: len(g.FindingIndex),
		SelectedNodes: len(selectedNodeIDs), TotalNodes: len(g.Nodes),
		SelectedEdges: len(selectedEdgeIDs), TotalEdges: len(g.Edges),
		SelectedEvidenceIDs: len(selectedEvidence), TotalEvidenceIDs: len(fullEvidence),
	}
	counts.OmittedFindings = max(0, counts.TotalFindings-counts.SelectedFindings)
	counts.OmittedNodes = max(0, counts.TotalNodes-counts.SelectedNodes)
	counts.OmittedEdges = max(0, counts.TotalEdges-counts.SelectedEdges)
	counts.OmittedEvidenceIDs = max(0, counts.TotalEvidenceIDs-counts.SelectedEvidenceIDs)

	evidenceIDs := setValues(selectedEvidence)
	refs := make(map[string]string, len(evidenceIDs))
	evidenceKey := make([]EvidenceReference, len(evidenceIDs))
	for i, id := range evidenceIDs {
		compact := fmt.Sprintf("E%03d", i+1)
		refs[id] = compact
		evidenceKey[i] = EvidenceReference{CompactID: compact, EvidenceID: id}
	}

	nodesByID := make(map[string]NodeV2, len(g.Nodes))
	for _, node := range g.Nodes {
		nodesByID[node.ID] = node
	}
	edgesByID := make(map[string]EdgeV2, len(g.Edges))
	for _, edge := range g.Edges {
		edgesByID[edge.ID] = edge
	}
	currentY, nodeSequence, edgeSequence := pathTop, 0, 0
	lanes := make([]TemporalEvidenceLane, 0, len(selected))
	for laneIndex, finding := range selected {
		if laneIndex&7 == 0 {
			if err := checkContext(ctx); err != nil {
				return TemporalEvidencePath{}, err
			}
		}
		nodeIDs, edgeIDs, _ := findingSlice(g, finding.FindingRevisionID)
		var laneNodes []NodeV2
		for _, id := range setValues(nodeIDs) {
			node := nodesByID[id]
			if presentableNode(node.Type) {
				laneNodes = append(laneNodes, node)
			}
		}
		visualNodes, maxRows := layoutNodes(laneNodes, currentY)
		for i := range visualNodes {
			nodeSequence++
			visualNodes[i].LocalID = fmt.Sprintf("n%04d", nodeSequence)
		}
		positionByID := make(map[string]VisualNode, len(visualNodes))
		for _, node := range visualNodes {
			positionByID[node.Node.ID] = node
		}
		var laneEdges []EdgeV2
		for _, id := range setValues(edgeIDs) {
			edge := edgesByID[id]
			if _, ok := positionByID[edge.Source]; !ok {
				continue
			}
			if _, ok := positionByID[edge.Target]; !ok {
				continue
			}
			laneEdges = append(laneEdges, edge)
		}
		visualEdges := layoutEdges(laneEdges, positionByID, refs, finding)
		for i := range visualEdges {
			edgeSequence++
			visualEdges[i].LocalID = fmt.Sprintf("e%04d", edgeSequence)
		}
		var notices []ProjectionNotice
		for _, notice := range g.ProjectionNotices {
			if notice.FindingRevisionID == finding.FindingRevisionID {
				notices = append(notices, notice)
			}
		}
		extraRows := len(notices)
		if finding.State == model.UnknownEvidenceGap {
			extraRows++
		}
		laneHeight := 88 + max(1, maxRows)*(pathNodeHeight+pathRowGap) + extraRows*58
		lanes = append(lanes, TemporalEvidenceLane{Finding: finding, Y: currentY, Height: laneHeight, Nodes: visualNodes, Edges: visualEdges, Notices: notices})
		currentY += laneHeight + pathLaneGap
	}
	keyHeight := 100 + len(evidenceKey)*25
	height := currentY + keyHeight + 36
	if len(lanes) == 0 {
		height = pathTop + keyHeight + 36
	}
	return TemporalEvidencePath{
		SchemaVersion: TemporalPathSchemaVersion, CaseKind: g.CaseKind,
		Width: pathCanvasWidth, Height: height, Counts: counts,
		Lanes: lanes, EvidenceKey: evidenceKey,
	}, nil
}

// RenderGraphSVG is the convenience path for case generation.
func RenderGraphSVG(ctx context.Context, graphInput GraphV2, options PathOptions) (TemporalEvidencePath, []byte, error) {
	if ctx == nil {
		return TemporalEvidencePath{}, nil, errors.New("nil context")
	}
	if err := checkContext(ctx); err != nil {
		return TemporalEvidencePath{}, nil, err
	}
	options, err := normalizePathOptions(options)
	if err != nil {
		return TemporalEvidencePath{}, nil, err
	}
	g := CloneGraphV2(graphInput)
	if err := g.NormalizeAndValidate(); err != nil {
		return TemporalEvidencePath{}, nil, err
	}
	if err := checkContext(ctx); err != nil {
		return TemporalEvidencePath{}, nil, err
	}
	renderAt := func(laneLimit int) (TemporalEvidencePath, []byte, error) {
		path, buildErr := buildTemporalEvidencePath(ctx, g, options, laneLimit)
		if buildErr != nil {
			return TemporalEvidencePath{}, nil, buildErr
		}
		data, renderErr := RenderSVG(ctx, path)
		return path, data, renderErr
	}
	path, data, renderErr := renderAt(options.MaxFindingLanes)
	if !errors.Is(renderErr, errSVGTooLarge) {
		return path, data, renderErr
	}

	// Serialized size is monotonic for the deterministic prefix selection. Find
	// the largest complete-lane prefix below the fixed byte ceiling rather than
	// repeatedly encoding every smaller prefix.
	low, high := 0, options.MaxFindingLanes-1
	var bestPath TemporalEvidencePath
	var bestData []byte
	for low <= high {
		mid := low + (high-low)/2
		candidatePath, candidateData, candidateErr := renderAt(mid)
		switch {
		case candidateErr == nil:
			bestPath, bestData = candidatePath, candidateData
			low = mid + 1
		case errors.Is(candidateErr, errSVGTooLarge):
			high = mid - 1
		default:
			return TemporalEvidencePath{}, nil, candidateErr
		}
	}
	if bestData == nil {
		return TemporalEvidencePath{}, nil, errSVGTooLarge
	}
	return bestPath, bestData, nil
}

// ValidateRenderableTemporalEvidencePath verifies that path is the exact
// deterministic presentation RenderGraphSVG selects for graphInput. This is
// deliberately stronger than validating path in isolation: the SVG byte
// ceiling can omit a complete trailing suffix of finding lanes, so callers
// must compare against the renderable projection rather than the unrestricted
// default layout.
func ValidateRenderableTemporalEvidencePath(ctx context.Context, graphInput GraphV2, path TemporalEvidencePath, options PathOptions) error {
	if ctx == nil {
		return errors.New("nil context")
	}
	if err := checkContext(ctx); err != nil {
		return err
	}
	if err := ValidateTemporalEvidencePath(path); err != nil {
		return fmt.Errorf("invalid temporal evidence path: %w", err)
	}
	expected, _, err := RenderGraphSVG(ctx, graphInput, options)
	if err != nil {
		return fmt.Errorf("rebuild renderable temporal evidence path: %w", err)
	}
	if !reflect.DeepEqual(expected, path) {
		return errors.New("temporal evidence path disagrees with the typed graph renderable projection")
	}
	return nil
}

func findingSlice(g GraphV2, findingID string) (map[string]struct{}, map[string]struct{}, map[string]struct{}) {
	nodes, edges, evidence := make(map[string]struct{}), make(map[string]struct{}), make(map[string]struct{})
	for _, node := range g.Nodes {
		if containsString(node.FocusFindingIDs, findingID) && presentableNode(node.Type) {
			nodes[node.ID] = struct{}{}
		}
	}
	for _, edge := range g.Edges {
		if !containsString(edge.FocusFindingIDs, findingID) {
			continue
		}
		if _, source := nodes[edge.Source]; !source {
			continue
		}
		if _, target := nodes[edge.Target]; !target {
			continue
		}
		edges[edge.ID] = struct{}{}
		for _, id := range edge.EvidenceIDs {
			evidence[id] = struct{}{}
		}
	}
	for _, notice := range g.ProjectionNotices {
		if notice.FindingRevisionID == findingID {
			for _, id := range notice.EvidenceIDs {
				evidence[id] = struct{}{}
			}
		}
	}
	return nodes, edges, evidence
}

func presentableNode(nodeType NodeType) bool {
	return nodeType != NodeEvidenceObject && nodeType != NodeFinding
}

func containsString(values []string, target string) bool {
	i := sort.SearchStrings(values, target)
	return i < len(values) && values[i] == target
}

func cloneSet(source map[string]struct{}) map[string]struct{} {
	result := make(map[string]struct{}, len(source))
	for key := range source {
		result[key] = struct{}{}
	}
	return result
}

func mergeSet(target, source map[string]struct{}) {
	for key := range source {
		target[key] = struct{}{}
	}
}

func setValues(values map[string]struct{}) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func layoutNodes(nodes []NodeV2, laneY int) ([]VisualNode, int) {
	sort.Slice(nodes, func(i, j int) bool {
		ci, cj := nodeColumn(nodes[i].Type), nodeColumn(nodes[j].Type)
		if ci != cj {
			return ci < cj
		}
		ri, rj := nodeTypeRank(nodes[i].Type), nodeTypeRank(nodes[j].Type)
		if ri != rj {
			return ri < rj
		}
		if nodes[i].Label != nodes[j].Label {
			return nodes[i].Label < nodes[j].Label
		}
		return nodes[i].ID < nodes[j].ID
	})
	rows := [4]int{}
	result := make([]VisualNode, 0, len(nodes))
	for _, node := range nodes {
		column := nodeColumn(node.Type)
		row := rows[column]
		rows[column]++
		full, _ := sanitizeSVGText(node.Label, maxLabelBytes)
		lines := visibleLabelLines(full)
		result = append(result, VisualNode{
			Node: node, Column: column, Row: row, X: pathColumnX[column],
			Y: laneY + 78 + row*(pathNodeHeight+pathRowGap), Width: pathNodeWidth,
			Height: pathNodeHeight, FullLabel: full, LabelLines: lines,
		})
	}
	maxRows := 0
	for _, count := range rows {
		if count > maxRows {
			maxRows = count
		}
	}
	return result, maxRows
}

func nodeColumn(nodeType NodeType) int {
	switch nodeType {
	case NodeRepository, NodeWorkflowDefinition, NodeWorkflowRun, NodeRunAttempt:
		return 0
	case NodeJob, NodeStep:
		return 1
	case NodeReusableWorkflowDefinition, NodeActionRepository, NodeActionRef,
		NodeActionCommit, NodeImmutableActionPackage, NodeActionDefinition:
		return 2
	default:
		return 3
	}
}

func nodeTypeRank(nodeType NodeType) int {
	for index, candidate := range []NodeType{
		NodeRepository, NodeWorkflowDefinition, NodeWorkflowRun, NodeRunAttempt,
		NodeJob, NodeStep, NodeReusableWorkflowDefinition, NodeActionRepository,
		NodeActionRef, NodeActionCommit, NodeImmutableActionPackage, NodeActionDefinition,
		NodeRunner, NodeRunnerGroup, NodeEnvironment, NodeTokenCapability,
		NodeSecretMetadata, NodeOIDCProvider, NodeArtifact, NodePackage, NodeRelease,
		NodeDeployment, NodeRepositoryResource, NodePullRequestChange,
	} {
		if nodeType == candidate {
			return index
		}
	}
	return 1_000
}

func layoutEdges(edges []EdgeV2, nodes map[string]VisualNode, refs map[string]string, finding FindingIndexEntry) []VisualEdge {
	sort.Slice(edges, func(i, j int) bool {
		si, sj := nodes[edges[i].Source], nodes[edges[j].Source]
		ti, tj := nodes[edges[i].Target], nodes[edges[j].Target]
		ki := fmt.Sprintf("%02d/%04d/%02d/%04d/%04d/%s", si.Column, si.Row, ti.Column, ti.Row, edgeTypeRank(edges[i].Type), edges[i].ID)
		kj := fmt.Sprintf("%02d/%04d/%02d/%04d/%04d/%s", sj.Column, sj.Row, tj.Column, tj.Row, edgeTypeRank(edges[j].Type), edges[j].ID)
		return ki < kj
	})
	result := make([]VisualEdge, 0, len(edges))
	for _, edge := range edges {
		source, target := nodes[edge.Source], nodes[edge.Target]
		sx, tx := source.X+source.Width, target.X
		if source.X > target.X {
			sx, tx = source.X, target.X+target.Width
		}
		sy, ty := source.Y+source.Height/2, target.Y+target.Height/2
		mid := (sx + tx) / 2
		points := []Point{{sx, sy}, {mid, sy}, {mid, ty}, {tx, ty}}
		if source.Column == target.Column {
			gutter := max(source.X+source.Width, target.X+target.Width) + 24
			points = []Point{{sx, sy}, {gutter, sy}, {gutter, ty}, {tx, ty}}
		}
		if edge.EvidenceClass == EvidenceClassContradiction {
			bandY := min(source.Y, target.Y) - 16
			points = []Point{{sx, sy}, {sx + sign(tx-sx)*20, sy}, {sx + sign(tx-sx)*20, bandY}, {tx - sign(tx-sx)*20, bandY}, {tx - sign(tx-sx)*20, ty}, {tx, ty}}
		}
		edgeRefs := make([]string, 0, min(8, len(edge.EvidenceIDs)))
		for i, id := range edge.EvidenceIDs {
			if i < 8 {
				edgeRefs = append(edgeRefs, refs[id])
			}
		}
		result = append(result, VisualEdge{
			Edge: edge, Points: points, LabelX: mid, LabelY: min(sy, ty) - 10,
			RelationshipText: relationshipText(edge, edges, finding), EvidenceRefs: edgeRefs,
			AdditionalRefs: max(0, len(edge.EvidenceIDs)-len(edgeRefs)),
		})
	}
	return result
}

func edgeTypeRank(edgeType EdgeType) int {
	for index, candidate := range []EdgeType{
		EdgeRunInRepository, EdgeAttemptOfRun, EdgeJobExecutedInAttempt, EdgeStepInJob,
		EdgeRunInstantiatedWorkflow, EdgeWorkflowDeclaredAction, EdgeWorkflowCalledWorkflow,
		EdgeActionContainsAction, EdgeLocalActionResolvedTo, EdgeRefResolvedTo,
		EdgePackageSourceCommit, EdgeJobPreparedAction, EdgeStepDownloadedAction,
		EdgeStepExecutedAction, EdgeExecutedOnRunner, EdgeRunnerInGroup,
		EdgeHadTokenPermission, EdgeReferencedSecret, EdgePassedSecretTo,
		EdgeInheritedSecret, EdgeTargetedEnvironment, EdgeCrossedEnvironmentGate,
		EdgeEnvironmentSecretEligible, EdgeCouldMintOIDC, EdgeProducedArtifact,
		EdgePublishedPackage, EdgeCreatedRelease, EdgeCreatedDeployment,
		EdgeRepositoryWrite, EdgePullRequestChange, EdgeObservedAfter, EdgeFindingAbout,
		EdgeSupportedByEvidence, EdgeContradicts,
	} {
		if edgeType == candidate {
			return index
		}
	}
	return 1_000
}

func relationshipText(edge EdgeV2, laneEdges []EdgeV2, finding FindingIndexEntry) string {
	text := map[EdgeType]string{
		EdgeRunInRepository:           "run recorded in repository",
		EdgeAttemptOfRun:              "attempt of run",
		EdgeJobExecutedInAttempt:      "job recorded in attempt",
		EdgeStepInJob:                 "step recorded in job",
		EdgeRunInstantiatedWorkflow:   "run instantiated historical workflow",
		EdgeWorkflowDeclaredAction:    workflowDeclarationText(finding),
		EdgeWorkflowCalledWorkflow:    "historical workflow called reusable workflow",
		EdgeActionContainsAction:      "composite definition contains Action",
		EdgeLocalActionResolvedTo:     "local Action resolved at historical commit",
		EdgeRefResolvedTo:             "reference resolved to exact identity",
		EdgePackageSourceCommit:       "package records source commit",
		EdgeJobPreparedAction:         "preparation demonstrated",
		EdgeStepDownloadedAction:      "download demonstrated",
		EdgeStepExecutedAction:        "step execution began",
		EdgeExecutedOnRunner:          "job recorded on runner",
		EdgeRunnerInGroup:             "runner recorded in group",
		EdgeHadTokenPermission:        "token permission capability observed",
		EdgeReferencedSecret:          "secret name referenced",
		EdgePassedSecretTo:            "secret mapped or passed",
		EdgeInheritedSecret:           "secret relationship inherited",
		EdgeTargetedEnvironment:       "targeted environment",
		EdgeCrossedEnvironmentGate:    "environment gate shown crossed",
		EdgeEnvironmentSecretEligible: "environment secret eligible",
		EdgeCouldMintOIDC:             "could mint OIDC token",
		EdgeProducedArtifact:          "artifact created by same job or step",
		EdgePublishedPackage:          "package published by same job or step",
		EdgeCreatedRelease:            "release created by same job or step",
		EdgeCreatedDeployment:         "deployment created by same job or step",
		EdgeRepositoryWrite:           "repository write observed for same job or step",
		EdgePullRequestChange:         "pull-request change observed for same job or step",
		EdgeObservedAfter:             "observed after — causation not established",
		EdgeFindingAbout:              "finding concerns",
		EdgeSupportedByEvidence:       "supported by evidence",
		EdgeContradicts:               "contradicts",
	}[edge.Type]
	if edge.Type == EdgeTargetedEnvironment {
		crossed := false
		for _, other := range laneEdges {
			if other.Type == EdgeCrossedEnvironmentGate && other.Source == edge.Source && other.Target == edge.Target {
				crossed = true
				break
			}
		}
		if !crossed {
			text = "targeted; gate not shown crossed"
		}
	}
	if edge.EvidenceClass == EvidenceClassInference {
		text += " — inferred"
	}
	return text
}

// workflowDeclarationText uses only the typed finding state. Workflow and
// node labels are hostile display data and must never decide whether a
// definition is present-day or historical.
func workflowDeclarationText(finding FindingIndexEntry) string {
	if finding.State == model.CurrentReferenceOnly {
		return "present-day workflow snapshot declared Action"
	}
	return "historical workflow declared Action"
}

func sign(value int) int {
	if value < 0 {
		return -1
	}
	return 1
}

func visibleLabelLines(full string) []string {
	clean, truncated := truncateRunesAndBytes(full, 96, 192)
	runes := []rune(clean)
	var lines []string
	for len(runes) > 0 && len(lines) < 3 {
		limit := min(32, len(runes))
		cut := limit
		if limit < len(runes) {
			for i := limit - 1; i > 0; i-- {
				if runes[i] == ' ' {
					cut = i
					break
				}
			}
		}
		line := strings.TrimSpace(string(runes[:cut]))
		if line == "" {
			line = string(runes[:limit])
			cut = limit
		}
		lines = append(lines, line)
		runes = runes[cut:]
		for len(runes) > 0 && runes[0] == ' ' {
			runes = runes[1:]
		}
	}
	if len(runes) > 0 {
		truncated = true
	}
	if len(lines) == 0 {
		lines = []string{"[unavailable]"}
	}
	if truncated {
		last := []rune(lines[len(lines)-1])
		if len(last) >= 32 {
			last = last[:31]
		}
		lines[len(lines)-1] = strings.TrimSpace(string(last)) + "…"
	}
	return lines
}

func truncateRunesAndBytes(value string, maxRunes, maxBytes int) (string, bool) {
	var builder strings.Builder
	count := 0
	for _, r := range value {
		if count >= maxRunes || builder.Len()+len(string(r)) > maxBytes {
			return builder.String(), true
		}
		builder.WriteRune(r)
		count++
	}
	return builder.String(), false
}
