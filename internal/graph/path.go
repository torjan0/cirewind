package graph

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"github.com/torjan0/cirewind/internal/model"
	"github.com/torjan0/cirewind/internal/sanitize"
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
	MaxSVGHeight            = 1_000_000

	pathTop        = 248
	pathLaneGap    = 28
	pathNodeWidth  = 330
	pathNodeHeight = 108
	pathRowGap     = 30

	// Every relationship receives a separate horizontal track below the node
	// grid. Endpoint stubs reach that track through the fixed column gutters,
	// so a route cannot pass through an unrelated node.
	pathEdgeRouteTop       = 12
	pathEdgeRouteRowHeight = 16
	pathEdgeRouteClassGap  = 12
	pathEdgeRouteBottom    = 12
	pathRouteClearance     = 8
	pathPortInset          = 14
	pathPortPitch          = 16
	pathNodePortCapacity   = 6
	pathRailDistanceMin    = 20
	pathRailPitch          = 16
	pathRouteBankCapacity  = 12
	pathRailDistanceMax    = pathRailDistanceMin + (pathRouteBankCapacity-1)*pathRailPitch
	pathInterBankGap       = 16
	pathLaneRectX          = 24
	pathOuterMargin        = pathLaneRectX + pathRouteClearance + pathRailDistanceMax
	pathColumnGap          = 2*pathRailDistanceMax + pathInterBankGap
	pathCanvasWidth        = 2*pathOuterMargin + 4*pathNodeWidth + 3*pathColumnGap

	// Relationship labels live in a dedicated ledger below each lane's node
	// grid. They never share route midpoints with nodes or with another label.
	pathEdgeLabelRectX      = 52
	pathEdgeLabelRectWidth  = pathCanvasWidth - 122
	pathEdgeLabelRectHeight = 46
	pathEdgeLabelTextX      = 64
	pathEdgeLabelRowHeight  = 52
	pathEdgeLabelTop        = 6
	pathEdgeLabelTextY      = 22
	pathEdgeLabelLineGap    = 19
	pathEdgeLabelBottom     = 16
)

var pathColumnX = [...]int{
	pathOuterMargin,
	pathOuterMargin + pathNodeWidth + pathColumnGap,
	pathOuterMargin + 2*(pathNodeWidth+pathColumnGap),
	pathOuterMargin + 3*(pathNodeWidth+pathColumnGap),
}

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
	LabelRectX       int
	LabelRectY       int
	LabelRectWidth   int
	LabelRectHeight  int
	LabelX           int
	LabelY           int
	LabelLine2Y      int
	LabelLines       []string
	RelationshipText string
	EvidenceRefs     []string
	AdditionalRefs   int
}

type routeEndpointKey struct {
	edgeIndex int
	source    bool
}

type routePortGroup struct {
	nodeID string
	right  bool
}

type routeRailBank struct {
	column int
	right  bool
}

type routeEndpointUse struct {
	key  routeEndpointKey
	node VisualNode
}

type routeEndpoint struct {
	right        bool
	y            int
	railDistance int
}

type EvidenceReference struct {
	CompactID  string
	EvidenceID string
}

const maxProjectionNoticeVisibleRefs = 5

// PresentProjectionNotice returns a bounded visual label and a complete text
// equivalent for one non-finding projection notice. Full evidence identities
// remain available to assistive technology and in the evidence-reference key;
// the fixed SVG row uses only deterministic E### references.
func PresentProjectionNotice(notice ProjectionNotice, key []EvidenceReference) (full, visible string) {
	const lead = "visual relationship omitted — legacy evidence basis unavailable · "
	full = lead + string(notice.Relationship) + " · evidence " + strings.Join(notice.EvidenceIDs, ", ")
	refByEvidence := make(map[string]string, len(key))
	for _, reference := range key {
		refByEvidence[reference.EvidenceID] = reference.CompactID
	}
	refs := make([]string, 0, min(maxProjectionNoticeVisibleRefs, len(notice.EvidenceIDs)))
	for _, evidenceID := range notice.EvidenceIDs {
		if len(refs) == maxProjectionNoticeVisibleRefs {
			break
		}
		if compact := refByEvidence[evidenceID]; compact != "" {
			refs = append(refs, compact)
		}
	}
	if len(refs) == 0 {
		refs = append(refs, "[reference unavailable]")
	}
	visible = lead + string(notice.Relationship) + " · " + strings.Join(refs, ", ")
	if additional := len(notice.EvidenceIDs) - len(refs); additional > 0 {
		visible += fmt.Sprintf(" · +%d more", additional)
	}
	visible, _ = sanitize.TruncateDisplay(visible, 180, 150)
	return full, visible
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
		if !findingFitsRouteGeometry(g, entry.FindingRevisionID) {
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
		visualEdges := layoutEdges(laneEdges, positionByID, refs, finding, currentY, maxRows)
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
		laneHeight := 88 + max(1, maxRows)*(pathNodeHeight+pathRowGap) + edgeRouteBandHeight(laneEdges) + edgeLabelBandHeight(len(visualEdges)) + extraRows*58
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
		if path.Height > MaxSVGHeight {
			return path, nil, errSVGTooLarge
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

func layoutEdges(edges []EdgeV2, nodes map[string]VisualNode, refs map[string]string, finding FindingIndexEntry, laneY, maxRows int) []VisualEdge {
	sort.Slice(edges, func(i, j int) bool {
		si, sj := nodes[edges[i].Source], nodes[edges[j].Source]
		ti, tj := nodes[edges[i].Target], nodes[edges[j].Target]
		ki := fmt.Sprintf("%02d/%04d/%02d/%04d/%04d/%s", si.Column, si.Row, ti.Column, ti.Row, edgeTypeRank(edges[i].Type), edges[i].ID)
		kj := fmt.Sprintf("%02d/%04d/%02d/%04d/%04d/%s", sj.Column, sj.Row, tj.Column, tj.Row, edgeTypeRank(edges[j].Type), edges[j].ID)
		return ki < kj
	})
	ports := layoutRouteEndpoints(edges, nodes)
	result := make([]VisualEdge, 0, len(edges))
	nodeBandEndY := laneY + 88 + max(1, maxRows)*(pathNodeHeight+pathRowGap)
	labelBandY := nodeBandEndY + edgeRouteBandHeight(edges)
	ordinaryRouteCount := 0
	for _, edge := range edges {
		if edge.EvidenceClass != EvidenceClassContradiction {
			ordinaryRouteCount++
		}
	}
	ordinaryRouteIndex, contradictionRouteIndex := 0, 0
	for edgeIndex, edge := range edges {
		source, target := nodes[edge.Source], nodes[edge.Target]
		routeIndex := ordinaryRouteIndex
		if edge.EvidenceClass == EvidenceClassContradiction {
			routeIndex = ordinaryRouteCount + contradictionRouteIndex
			contradictionRouteIndex++
		} else {
			ordinaryRouteIndex++
		}
		routeTrackY := nodeBandEndY + pathEdgeRouteTop + routeIndex*pathEdgeRouteRowHeight
		if edge.EvidenceClass == EvidenceClassContradiction && ordinaryRouteCount > 0 {
			routeTrackY += pathEdgeRouteClassGap
		}
		points := routeEdgeWithEndpoints(
			source,
			target,
			routeTrackY,
			ports[routeEndpointKey{edgeIndex: edgeIndex, source: true}],
			ports[routeEndpointKey{edgeIndex: edgeIndex, source: false}],
		)
		edgeRefs := make([]string, 0, min(8, len(edge.EvidenceIDs)))
		for i, id := range edge.EvidenceIDs {
			if i < 8 {
				edgeRefs = append(edgeRefs, refs[id])
			}
		}
		relationship := relationshipText(edge, edges, finding)
		additionalRefs := max(0, len(edge.EvidenceIDs)-len(edgeRefs))
		labelRectY := labelBandY + pathEdgeLabelTop + edgeIndex*pathEdgeLabelRowHeight
		result = append(result, VisualEdge{
			Edge: edge, Points: points,
			LabelRectX: pathEdgeLabelRectX, LabelRectY: labelRectY,
			LabelRectWidth: pathEdgeLabelRectWidth, LabelRectHeight: pathEdgeLabelRectHeight,
			LabelX: pathEdgeLabelTextX, LabelY: labelRectY + pathEdgeLabelTextY,
			LabelLine2Y:      labelRectY + pathEdgeLabelTextY + pathEdgeLabelLineGap,
			LabelLines:       edgeLabelLines(source, target, edge, relationship, edgeRefs, additionalRefs),
			RelationshipText: relationship, EvidenceRefs: edgeRefs, AdditionalRefs: additionalRefs,
		})
	}
	return result
}

func routeEdge(source, target VisualNode, trackY int) []Point {
	sourceRight, targetRight := routeSides(source, target)
	return routeEdgeWithEndpoints(
		source,
		target,
		trackY,
		routeEndpoint{right: sourceRight, y: source.Y + source.Height/2, railDistance: (pathRailDistanceMin + pathRailDistanceMax) / 2},
		routeEndpoint{right: targetRight, y: target.Y + target.Height/2, railDistance: (pathRailDistanceMin + pathRailDistanceMax) / 2},
	)
}

func routeEdgeWithEndpoints(source, target VisualNode, trackY int, sourceEndpoint, targetEndpoint routeEndpoint) []Point {
	sourcePortX, sourceGutterX := routePort(source, sourceEndpoint)
	targetPortX, targetGutterX := routePort(target, targetEndpoint)
	points := []Point{
		{X: sourcePortX, Y: sourceEndpoint.y},
		{X: sourceGutterX, Y: sourceEndpoint.y},
		{X: sourceGutterX, Y: trackY},
		{X: targetGutterX, Y: trackY},
		{X: targetGutterX, Y: targetEndpoint.y},
		{X: targetPortX, Y: targetEndpoint.y},
	}
	return compactRoute(points)
}

func routeSides(source, target VisualNode) (sourceRight, targetRight bool) {
	return routeSidesForColumns(source.Column, target.Column)
}

func routeSidesForColumns(sourceColumn, targetColumn int) (sourceRight, targetRight bool) {
	if sourceColumn == targetColumn {
		return false, true
	}
	return targetColumn > sourceColumn, sourceColumn > targetColumn
}

func routePort(node VisualNode, endpoint routeEndpoint) (portX, gutterX int) {
	if endpoint.right {
		portX = node.X + node.Width
		return portX, portX + endpoint.railDistance
	}
	portX = node.X
	return portX, portX - endpoint.railDistance
}

func layoutRouteEndpoints(edges []EdgeV2, nodes map[string]VisualNode) map[routeEndpointKey]routeEndpoint {
	portGroups := make(map[routePortGroup][]routeEndpointUse)
	railBanks := make(map[routeRailBank][]routeEndpointUse)
	for edgeIndex, edge := range edges {
		source, target := nodes[edge.Source], nodes[edge.Target]
		sourceRight, targetRight := routeSides(source, target)
		sourceKey := routeEndpointKey{edgeIndex: edgeIndex, source: true}
		targetKey := routeEndpointKey{edgeIndex: edgeIndex, source: false}
		sourceUse := routeEndpointUse{key: sourceKey, node: source}
		targetUse := routeEndpointUse{key: targetKey, node: target}
		portGroups[routePortGroup{nodeID: edge.Source, right: sourceRight}] = append(portGroups[routePortGroup{nodeID: edge.Source, right: sourceRight}], sourceUse)
		portGroups[routePortGroup{nodeID: edge.Target, right: targetRight}] = append(portGroups[routePortGroup{nodeID: edge.Target, right: targetRight}], targetUse)
		railBanks[routeRailBank{column: source.Column, right: sourceRight}] = append(railBanks[routeRailBank{column: source.Column, right: sourceRight}], sourceUse)
		railBanks[routeRailBank{column: target.Column, right: targetRight}] = append(railBanks[routeRailBank{column: target.Column, right: targetRight}], targetUse)
	}
	result := make(map[routeEndpointKey]routeEndpoint, len(edges)*2)
	for group, uses := range portGroups {
		startY := uses[0].node.Y + pathPortInset + (pathNodePortCapacity-len(uses))*pathPortPitch/2
		for index, use := range uses {
			endpoint := result[use.key]
			endpoint.right = group.right
			endpoint.y = startY + index*pathPortPitch
			result[use.key] = endpoint
		}
	}
	for _, uses := range railBanks {
		for index, use := range uses {
			endpoint := result[use.key]
			endpoint.railDistance = pathRailDistanceMin + index*pathRailPitch
			result[use.key] = endpoint
		}
	}
	return result
}

func findingFitsRouteGeometry(g GraphV2, findingRevisionID string) bool {
	nodeIDs, edgeIDs, _ := findingSlice(g, findingRevisionID)
	columns := make(map[string]int, len(nodeIDs))
	for _, node := range g.Nodes {
		if _, selected := nodeIDs[node.ID]; selected && presentableNode(node.Type) {
			columns[node.ID] = nodeColumn(node.Type)
		}
	}
	demand := make(map[routeRailBank]int)
	portDemand := make(map[routePortGroup]int)
	for _, edge := range g.Edges {
		if _, selected := edgeIDs[edge.ID]; !selected {
			continue
		}
		sourceColumn, sourceOK := columns[edge.Source]
		targetColumn, targetOK := columns[edge.Target]
		if !sourceOK || !targetOK {
			continue
		}
		sourceRight, targetRight := routeSidesForColumns(sourceColumn, targetColumn)
		for _, endpoint := range []struct {
			bank routeRailBank
			port routePortGroup
		}{
			{bank: routeRailBank{column: sourceColumn, right: sourceRight}, port: routePortGroup{nodeID: edge.Source, right: sourceRight}},
			{bank: routeRailBank{column: targetColumn, right: targetRight}, port: routePortGroup{nodeID: edge.Target, right: targetRight}},
		} {
			bank := endpoint.bank
			demand[bank]++
			if demand[bank] > pathRouteBankCapacity {
				return false
			}
			portDemand[endpoint.port]++
			if portDemand[endpoint.port] > pathNodePortCapacity {
				return false
			}
		}
	}
	return true
}

func visualEdgesFitRouteBanks(edges []EdgeV2, nodes map[string]VisualNode) bool {
	demand := make(map[routeRailBank]int)
	portDemand := make(map[routePortGroup]int)
	for _, edge := range edges {
		source, sourceOK := nodes[edge.Source]
		target, targetOK := nodes[edge.Target]
		if !sourceOK || !targetOK {
			continue
		}
		sourceRight, targetRight := routeSides(source, target)
		for _, endpoint := range []struct {
			bank routeRailBank
			port routePortGroup
		}{
			{bank: routeRailBank{column: source.Column, right: sourceRight}, port: routePortGroup{nodeID: edge.Source, right: sourceRight}},
			{bank: routeRailBank{column: target.Column, right: targetRight}, port: routePortGroup{nodeID: edge.Target, right: targetRight}},
		} {
			bank := endpoint.bank
			demand[bank]++
			if demand[bank] > pathRouteBankCapacity {
				return false
			}
			portDemand[endpoint.port]++
			if portDemand[endpoint.port] > pathNodePortCapacity {
				return false
			}
		}
	}
	return true
}

func compactRoute(points []Point) []Point {
	result := make([]Point, 0, len(points))
	for _, point := range points {
		if len(result) == 0 || result[len(result)-1] != point {
			result = append(result, point)
		}
	}
	return result
}

func edgeRouteBandHeight(edges []EdgeV2) int {
	if len(edges) == 0 {
		return 0
	}
	hasOrdinary, hasContradiction := false, false
	for _, edge := range edges {
		if edge.EvidenceClass == EvidenceClassContradiction {
			hasContradiction = true
		} else {
			hasOrdinary = true
		}
	}
	classGap := 0
	if hasOrdinary && hasContradiction {
		classGap = pathEdgeRouteClassGap
	}
	return pathEdgeRouteTop + len(edges)*pathEdgeRouteRowHeight + classGap + pathEdgeRouteBottom
}

func edgeLabelBandHeight(edgeCount int) int {
	if edgeCount == 0 {
		return 0
	}
	return pathEdgeLabelTop + edgeCount*pathEdgeLabelRowHeight + pathEdgeLabelBottom
}

func edgeLabelLines(source, target VisualNode, edge EdgeV2, relationship string, refs []string, additionalRefs int) []string {
	first := fmt.Sprintf("%s → %s · %s · %s", source.Node.Type, target.Node.Type, edge.Type, edge.EvidenceClass)
	second := relationship + " · evidence " + strings.Join(refs, " ")
	if additionalRefs > 0 {
		second += fmt.Sprintf(" +%d more", additionalRefs)
	}
	first, _ = sanitizeSVGText(first, 512)
	second, _ = sanitizeSVGText(second, 512)
	return []string{first, second}
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
		EdgeEnvironmentGateSatisfied,
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

func relationshipText(edge EdgeV2, laneEdges []EdgeV2, _ FindingIndexEntry) string {
	if edge.Type == EdgeTargetedEnvironment {
		satisfied := false
		for _, other := range laneEdges {
			if (other.Type == EdgeCrossedEnvironmentGate || other.Type == EdgeEnvironmentGateSatisfied) && other.Source == edge.Source && other.Target == edge.Target {
				satisfied = true
				break
			}
		}
		if edge.EvidenceClass == EvidenceClassInference {
			if !satisfied {
				return "targeted; gate not shown satisfied — environment target inferred"
			}
			return "environment target inferred"
		}
		if !satisfied {
			return "environment target observed; gate not shown satisfied"
		}
		return "environment target observed"
	}
	if edge.Type == EdgeWorkflowDeclaredAction {
		return definitionRelationshipText(edge)
	}
	if edge.Type == EdgeWorkflowCalledWorkflow {
		return definitionRelationshipText(edge)
	}
	if edge.Type == EdgeLocalActionResolvedTo {
		return definitionRelationshipText(edge)
	}
	if edge.Type == EdgeEnvironmentGateSatisfied {
		return environmentGateSatisfiedRelationshipText(edge.DerivationRule)
	}
	if edge.EvidenceClass == EvidenceClassInference {
		if text, ok := map[EdgeType]string{
			EdgeStepInJob:                 "step associated with job by derivation",
			EdgeHadTokenPermission:        "token permission capability inferred",
			EdgeReferencedSecret:          "secret name reference inferred",
			EdgePassedSecretTo:            "secret mapping or passage inferred",
			EdgeInheritedSecret:           "secret inheritance relationship inferred",
			EdgeCrossedEnvironmentGate:    "environment gate crossing inferred",
			EdgeEnvironmentSecretEligible: "environment-secret eligibility inferred; read or use not established",
			EdgeCouldMintOIDC:             "could mint OIDC token — capability inferred; cloud access not established",
			EdgeFindingAbout:              "finding association inferred",
		}[edge.Type]; ok {
			return text
		}
	}
	text := map[EdgeType]string{
		EdgeRunInRepository:           "run recorded in repository",
		EdgeAttemptOfRun:              "attempt of run",
		EdgeJobExecutedInAttempt:      "job recorded in attempt",
		EdgeStepInJob:                 "step recorded in job",
		EdgeRunInstantiatedWorkflow:   "run instantiated historical workflow",
		EdgeActionContainsAction:      "composite definition contains Action",
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
		EdgeTargetedEnvironment:       "environment target observed",
		EdgeCrossedEnvironmentGate:    "environment gate crossing observed",
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
	return text
}

func environmentGateSatisfiedRelationshipText(rule string) string {
	state, ok := EnvironmentGateSatisfiedStateForRule(rule)
	if !ok {
		return "environment gate requirement state unsupported"
	}
	switch state {
	case "approved":
		return "environment gate requirement satisfied — retained approval"
	case "bypassed":
		return "environment gate requirement satisfied — retained bypass; approval not inferred"
	case "crossed":
		return "environment gate requirement satisfied — retained crossing"
	case "not-required":
		return "environment gate requirement satisfied — contemporaneously not required; approval not inferred"
	default:
		return "environment gate requirement state unsupported"
	}
}

// definitionRelationshipText uses only the closed source-basis marker carried
// by the edge. Finding state and hostile node labels cannot safely recover the
// temporal identity of a workflow or local Action definition.
func definitionRelationshipText(edge EdgeV2) string {
	exact := map[EdgeType]string{
		EdgeWorkflowDeclaredAction: "workflow definition declared Action",
		EdgeWorkflowCalledWorkflow: "reusable-workflow call recorded",
		EdgeLocalActionResolvedTo:  "local Action definition resolved",
	}[edge.Type]
	inferred := map[EdgeType]string{
		EdgeWorkflowDeclaredAction: "workflow Action declaration inferred",
		EdgeWorkflowCalledWorkflow: "reusable-workflow call inferred",
		EdgeLocalActionResolvedTo:  "local Action resolution inferred",
	}[edge.Type]
	phrases := map[string]map[EdgeType]string{
		DefinitionBasisHistoricalAtRunRule: {
			EdgeWorkflowDeclaredAction: "historical workflow declared Action",
			EdgeWorkflowCalledWorkflow: "historical workflow called reusable workflow",
			EdgeLocalActionResolvedTo:  "local Action resolved at historical commit",
		},
		DefinitionBasisCurrentSnapshotRule: {
			EdgeWorkflowDeclaredAction: "present-day workflow snapshot declared Action",
			EdgeWorkflowCalledWorkflow: "present-day workflow snapshot called reusable workflow",
			EdgeLocalActionResolvedTo:  "local Action resolved in present-day snapshot",
		},
		DefinitionBasisRuntimeAttemptMetadataRule: {
			EdgeWorkflowCalledWorkflow: "GitHub run-attempt metadata recorded reusable-workflow call",
		},
	}
	if phrase := phrases[edge.DerivationRule][edge.Type]; phrase != "" {
		if edge.EvidenceClass == EvidenceClassInference {
			return phrase + " by derivation"
		}
		return phrase
	}
	if edge.EvidenceClass == EvidenceClassInference {
		return inferred
	}
	return exact
}

func visibleLabelLines(full string) []string {
	clean, byteTruncated := truncateRunesAndBytes(full, 96, 192)
	lines, displayTruncated := sanitize.WrapDisplay(clean, 96, 30, 3)
	if byteTruncated && !displayTruncated {
		last, _ := sanitize.TruncateDisplay(lines[len(lines)-1]+"…", 96, 30)
		lines[len(lines)-1] = last
	}
	return lines
}

// PresentTemporalScope returns a full presentation-safe scope for accessible
// text and a fixed-geometry line for the visual SVG. The underlying finding
// index remains unchanged.
func PresentTemporalScope(value string) (full, visible string) {
	full, _ = sanitize.Presentation(value, 4096)
	visible, _ = sanitize.TruncateDisplay(full, 192, 160)
	return full, visible
}

// TemporalLaneHeader returns the canonical visible lane heading. A scope-
// closed known-good negative is explicitly labeled as comparison context so it
// cannot be mistaken for a case-wide clean conclusion or an affected run.
func TemporalLaneHeader(finding FindingIndexEntry) string {
	header := string(finding.State) + " · " + string(finding.ProvenanceLevel)
	if finding.State == model.NoMatchConfirmed {
		header += " · comparison context"
	}
	return header
}

// TemporalLaneScope keeps the occurrence and indicator visible together. The
// indicator is material when otherwise identical findings represent different
// incident propositions.
func TemporalLaneScope(finding FindingIndexEntry) (full, visible string) {
	parts := []string{"indicator " + finding.IndicatorID, finding.Repository, finding.WorkflowPath}
	if finding.RunID != nil {
		parts = append(parts, "run "+strconv.FormatInt(int64(*finding.RunID), 10))
	}
	if finding.RunAttempt != nil {
		parts = append(parts, "attempt "+strconv.FormatUint(uint64(*finding.RunAttempt), 10))
	}
	if finding.JobID != nil {
		parts = append(parts, "job "+strconv.FormatInt(int64(*finding.JobID), 10))
	}
	return PresentTemporalScope(strings.Join(parts, " · "))
}

// TemporalLaneDescription is the full sanitized text alternative for a lane.
func TemporalLaneDescription(finding FindingIndexEntry) string {
	parts := []string{
		"Canonical finding " + string(finding.State),
		"provenance " + string(finding.ProvenanceLevel),
		"repository " + finding.Repository,
		"workflow " + finding.WorkflowPath,
		"indicator " + finding.IndicatorID,
	}
	if finding.RunID != nil {
		parts = append(parts, "run "+strconv.FormatInt(int64(*finding.RunID), 10))
	}
	if finding.RunAttempt != nil {
		parts = append(parts, "attempt "+strconv.FormatUint(uint64(*finding.RunAttempt), 10))
	}
	if finding.JobID != nil {
		parts = append(parts, "job "+strconv.FormatInt(int64(*finding.JobID), 10))
	}
	if finding.State == model.NoMatchConfirmed {
		parts = append(parts, "known-good rerun comparison context", "not an affected run", "scope-closed negative only")
	}
	if finding.State == model.UnknownEvidenceGap && finding.EvidenceGapReason != "" {
		parts = append(parts, "evidence gap "+finding.EvidenceGapReason)
	}
	value, _ := sanitize.Presentation(strings.Join(parts, "; "), 16<<10)
	return value
}

// PresentTemporalGapReason returns a full presentation-safe reason for the
// text equivalent and a fixed-geometry reason for the visual SVG.
func PresentTemporalGapReason(value string) (full, visible string) {
	full, _ = sanitize.Presentation(value, 4096)
	visible, _ = sanitize.TruncateDisplay(full, 128, 120)
	return full, visible
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
