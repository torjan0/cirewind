package graph

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/torjan0/cirewind/internal/model"
	"github.com/torjan0/cirewind/internal/sanitize"
)

const (
	colorExact            = "#005A9C"
	colorInference        = "#8A4B08"
	colorTemporal         = "#006B4F"
	colorContradiction    = "#B42318"
	colorGap              = "#5F6368"
	colorText             = "#111827"
	colorBorder           = "#334155"
	colorBackground       = "#FFFFFF"
	fontStack             = "ui-monospace, monospace"
	forcedColorStylesheet = "svg{forced-color-adjust:none}"
)

var errSVGTooLarge = errors.New("temporal evidence path exceeds SVG byte limit")

// RenderSVG serializes an inert standalone SVG from a validated presentation
// model. Domain text is emitted only through encoding/xml character data and
// attributes; no raw XML escape hatch exists.
func RenderSVG(ctx context.Context, path TemporalEvidencePath) ([]byte, error) {
	if ctx == nil {
		return nil, errors.New("nil context")
	}
	if err := validateTemporalPath(path); err != nil {
		return nil, err
	}
	if err := checkContext(ctx); err != nil {
		return nil, err
	}

	var output bytes.Buffer
	encoder := xml.NewEncoder(&output)
	root := xml.StartElement{Name: xml.Name{Local: "svg"}, Attr: attrs(
		"xmlns", "http://www.w3.org/2000/svg",
		"role", "img", "aria-labelledby", "tep-title tep-desc",
		"data-cirewind-schema", TemporalPathSchemaVersion,
		"width", strconv.Itoa(path.Width), "height", strconv.Itoa(path.Height),
		"viewBox", fmt.Sprintf("0 0 %d %d", path.Width, path.Height),
	)}
	if err := encoder.EncodeToken(root); err != nil {
		return nil, err
	}
	if err := textElement(encoder, "title", attrs("id", "tep-title"), "Temporal evidence path"); err != nil {
		return nil, err
	}
	description := fmt.Sprintf("%s case; showing %d of %d findings, %d of %d nodes, %d of %d relationships, and %d of %d evidence references. One lane per finding: solid lines are exact observations, dashed lines inferences, dotted lines observed-after correlation without causation, double lines contradictions, and interrupted lines with a question mark evidence gaps.",
		path.CaseKind, path.Counts.SelectedFindings, path.Counts.TotalFindings,
		path.Counts.SelectedNodes, path.Counts.TotalNodes, path.Counts.SelectedEdges,
		path.Counts.TotalEdges, path.Counts.SelectedEvidenceIDs, path.Counts.TotalEvidenceIDs)
	if err := textElement(encoder, "desc", attrs("id", "tep-desc"), description); err != nil {
		return nil, err
	}
	// The fixed accessible palette and white crossover underlays carry
	// relationship topology. Preserve them in forced-colors mode so a crossing
	// cannot be recolored into a false junction. Labels and the ledger remain
	// the non-color semantic equivalents.
	if err := textElement(encoder, "style", nil, forcedColorStylesheet); err != nil {
		return nil, err
	}
	if err := emptyElement(encoder, "rect", attrs("x", "0", "y", "0", "width", strconv.Itoa(path.Width), "height", strconv.Itoa(path.Height), "fill", colorBackground)); err != nil {
		return nil, err
	}
	if err := renderLegend(encoder); err != nil {
		return nil, err
	}
	if err := renderOmissionNotice(encoder, path.Counts); err != nil {
		return nil, err
	}

	for index, lane := range path.Lanes {
		if index&3 == 0 {
			if err := checkContext(ctx); err != nil {
				return nil, err
			}
		}
		if err := renderLane(encoder, lane, path.EvidenceKey); err != nil {
			return nil, err
		}
	}
	keyY := pathTop + 28
	if len(path.Lanes) > 0 {
		last := path.Lanes[len(path.Lanes)-1]
		keyY = last.Y + last.Height + 52
	}
	if err := renderEvidenceKey(ctx, encoder, path.EvidenceKey, keyY); err != nil {
		return nil, err
	}
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	if err := encoder.EncodeToken(root.End()); err != nil {
		return nil, err
	}
	if err := encoder.Flush(); err != nil {
		return nil, err
	}
	if output.Len() > MaxSVGBytes {
		return nil, fmt.Errorf("%w: limit %d bytes", errSVGTooLarge, MaxSVGBytes)
	}
	return output.Bytes(), nil
}

// ValidateTemporalEvidencePath validates the closed presentation contract
// without serializing SVG. Report integration uses this to fail closed before
// emitting any inline representation of the same model.
func ValidateTemporalEvidencePath(path TemporalEvidencePath) error {
	return validateTemporalPath(path)
}

func validateTemporalPath(path TemporalEvidencePath) error {
	if path.SchemaVersion != TemporalPathSchemaVersion {
		return fmt.Errorf("unsupported temporal path schema %q", path.SchemaVersion)
	}
	if !path.CaseKind.valid() {
		return fmt.Errorf("invalid temporal path case kind %q", path.CaseKind)
	}
	if path.Width != pathCanvasWidth || path.Height < 1 || path.Height > MaxSVGHeight {
		return errors.New("invalid temporal path canvas")
	}
	if len(path.Lanes) > HardPathFindingLanes || len(path.EvidenceKey) > HardPathEvidenceIDs {
		return errors.New("temporal path exceeds hard limits")
	}
	if err := validateSelectionCounts(path.Counts); err != nil {
		return err
	}
	refByEvidence := make(map[string]string, len(path.EvidenceKey))
	lastEvidenceID := ""
	for index, ref := range path.EvidenceKey {
		want := fmt.Sprintf("E%03d", index+1)
		if ref.CompactID != want {
			return fmt.Errorf("noncanonical evidence reference %q", ref.CompactID)
		}
		if err := model.EvidenceID(ref.EvidenceID).Validate(); err != nil {
			return fmt.Errorf("invalid evidence key: %w", err)
		}
		if _, exists := refByEvidence[ref.EvidenceID]; exists {
			return fmt.Errorf("duplicate evidence key %q", ref.EvidenceID)
		}
		if index > 0 && ref.EvidenceID <= lastEvidenceID {
			return errors.New("evidence key is not lexicographically ordered")
		}
		refByEvidence[ref.EvidenceID] = ref.CompactID
		lastEvidenceID = ref.EvidenceID
	}
	seenLocalNodes, seenLocalEdges := make(map[string]struct{}), make(map[string]struct{})
	logicalNodes, materialEdges := make(map[string]struct{}), make(map[string]struct{})
	selectedEvidence, selectedFindings := make(map[string]struct{}), make(map[string]struct{})
	nodeSequence, edgeSequence := 0, 0
	expectedY := pathTop
	for _, lane := range path.Lanes {
		if err := validateFindingIndexEntry(lane.Finding); err != nil {
			return err
		}
		if _, exists := selectedFindings[lane.Finding.FindingRevisionID]; exists {
			return fmt.Errorf("duplicate temporal path finding lane %q", lane.Finding.FindingRevisionID)
		}
		selectedFindings[lane.Finding.FindingRevisionID] = struct{}{}
		if lane.Height < 1 || lane.Y != expectedY || lane.Y+lane.Height > path.Height {
			return errors.New("invalid temporal path lane geometry")
		}
		laneNodes := make(map[string]VisualNode, len(lane.Nodes))
		nonExecutedEnvironments := make(map[string]struct{})
		qualifiedPendingEnvironments := make(map[string]struct{})
		targetedEnvironments := make(map[string]struct{})
		satisfiedEnvironments := make(map[string]struct{})
		eligibleEnvironments := make(map[string]struct{})
		rows := [4]int{}
		for _, node := range lane.Nodes {
			if !presentableNode(node.Node.Type) || node.LocalID == "" || node.Width != pathNodeWidth || node.Height != pathNodeHeight || node.Column < 0 || node.Column > 3 || node.Row < 0 {
				return errors.New("invalid temporal path node")
			}
			nodeSequence++
			if node.LocalID != fmt.Sprintf("n%04d", nodeSequence) {
				return fmt.Errorf("noncanonical renderer node ID %q", node.LocalID)
			}
			if _, exists := seenLocalNodes[node.LocalID]; exists {
				return fmt.Errorf("duplicate renderer node ID %q", node.LocalID)
			}
			seenLocalNodes[node.LocalID] = struct{}{}
			if _, exists := laneNodes[node.Node.ID]; exists {
				return fmt.Errorf("duplicate graph node %q in one lane", node.Node.ID)
			}
			if err := boundedText(node.Node.ID, maxIDBytes, false); err != nil || !node.Node.Type.valid() {
				return fmt.Errorf("invalid visual graph node %q", node.Node.ID)
			}
			normalEvidence, err := normalizeEvidenceIDs(node.Node.EvidenceIDs)
			if err != nil || !slices.Equal(normalEvidence, node.Node.EvidenceIDs) {
				return fmt.Errorf("visual graph node %q has noncanonical evidence IDs", node.Node.ID)
			}
			normalFocus, err := normalizeFindingIDs(node.Node.FocusFindingIDs)
			if err != nil || !slices.Equal(normalFocus, node.Node.FocusFindingIDs) {
				return fmt.Errorf("visual graph node %q has noncanonical focus IDs", node.Node.ID)
			}
			if node.Column != nodeColumn(node.Node.Type) || node.X != pathColumnX[node.Column] || node.Y != lane.Y+78+node.Row*(pathNodeHeight+pathRowGap) {
				return fmt.Errorf("noncanonical geometry for graph node %q", node.Node.ID)
			}
			if node.Row != rows[node.Column] {
				return fmt.Errorf("noncanonical row order for graph node %q", node.Node.ID)
			}
			rows[node.Column]++
			full, _ := sanitizeSVGText(node.Node.Label, maxLabelBytes)
			if full == "" {
				full = "[unavailable]"
			}
			if node.FullLabel != full || !slices.Equal(node.LabelLines, visibleLabelLines(full)) {
				return fmt.Errorf("noncanonical label projection for graph node %q", node.Node.ID)
			}
			if !containsString(node.Node.FocusFindingIDs, lane.Finding.FindingRevisionID) {
				return errors.New("visual node lacks lane focus")
			}
			if lane.Finding.State != model.ConfirmedExecuted {
				if _, prohibited := nonExecutedContextNodeTypes[node.Node.Type]; prohibited {
					return fmt.Errorf("visual node %q adds %s context to non-executed finding", node.Node.ID, node.Node.Type)
				}
				if node.Node.Type == NodeEnvironment {
					nonExecutedEnvironments[node.Node.ID] = struct{}{}
				}
			}
			laneNodes[node.Node.ID] = node
			logicalNodes[node.Node.ID] = struct{}{}
		}
		maxRows := 0
		for _, count := range rows {
			maxRows = max(maxRows, count)
		}
		canonicalNodeInput := make([]NodeV2, len(lane.Nodes))
		for index := range lane.Nodes {
			canonicalNodeInput[index] = lane.Nodes[index].Node
		}
		canonicalNodes, canonicalRows := layoutNodes(canonicalNodeInput, lane.Y)
		if canonicalRows != maxRows || len(canonicalNodes) != len(lane.Nodes) {
			return fmt.Errorf("noncanonical node layout in finding lane %q", lane.Finding.FindingRevisionID)
		}
		for index := range canonicalNodes {
			got, want := lane.Nodes[index], canonicalNodes[index]
			if got.Node.ID != want.Node.ID || got.Column != want.Column || got.Row != want.Row || got.X != want.X || got.Y != want.Y ||
				got.Width != want.Width || got.Height != want.Height || got.FullLabel != want.FullLabel || !slices.Equal(got.LabelLines, want.LabelLines) {
				return fmt.Errorf("noncanonical node order or layout in finding lane %q", lane.Finding.FindingRevisionID)
			}
		}
		extraRows := len(lane.Notices)
		if lane.Finding.State == model.UnknownEvidenceGap {
			extraRows++
		}
		laneEdgeValues := edgeValues(lane.Edges)
		if !visualEdgesFitRouteBanks(laneEdgeValues, laneNodes) {
			return fmt.Errorf("finding lane %q exceeds the deterministic route-bank capacity", lane.Finding.FindingRevisionID)
		}
		wantHeight := 88 + max(1, maxRows)*(pathNodeHeight+pathRowGap) + edgeRouteBandHeight(laneEdgeValues) + edgeLabelBandHeight(len(lane.Edges)) + extraRows*58
		if lane.Height != wantHeight {
			return fmt.Errorf("noncanonical height for finding lane %q", lane.Finding.FindingRevisionID)
		}
		labelRects := make([]integerRect, 0, len(lane.Edges))
		for edgeIndex, edge := range lane.Edges {
			if edge.LocalID == "" || !edge.Edge.EvidenceClass.valid() || len(edge.Edge.EvidenceIDs) == 0 {
				return errors.New("invalid temporal path edge")
			}
			if !relationshipAllowsEvidenceClass(edge.Edge.Type, edge.Edge.EvidenceClass) {
				return fmt.Errorf("edge %q relationship %s cannot use evidence class %s", edge.Edge.ID, edge.Edge.Type, edge.Edge.EvidenceClass)
			}
			if err := validateEdgeFindingContext(edge.Edge, lane.Finding); err != nil {
				return fmt.Errorf("edge %q: %w", edge.Edge.ID, err)
			}
			if lane.Finding.State != model.ConfirmedExecuted && edge.Edge.Type == EdgeTargetedEnvironment {
				qualifiedPendingEnvironments[edge.Edge.Target] = struct{}{}
			}
			switch edge.Edge.Type {
			case EdgeTargetedEnvironment:
				targetedEnvironments[edge.Edge.Source+"\x00"+edge.Edge.Target] = struct{}{}
			case EdgeEnvironmentGateSatisfied:
				satisfiedEnvironments[edge.Edge.Source+"\x00"+edge.Edge.Target] = struct{}{}
			case EdgeEnvironmentSecretEligible:
				eligibleEnvironments[edge.Edge.Source] = struct{}{}
			}
			edgeSequence++
			if edge.LocalID != fmt.Sprintf("e%04d", edgeSequence) {
				return fmt.Errorf("noncanonical renderer edge ID %q", edge.LocalID)
			}
			if _, exists := seenLocalEdges[edge.LocalID]; exists {
				return fmt.Errorf("duplicate renderer edge ID %q", edge.LocalID)
			}
			seenLocalEdges[edge.LocalID] = struct{}{}
			source, sourceOK := laneNodes[edge.Edge.Source]
			target, targetOK := laneNodes[edge.Edge.Target]
			if !sourceOK || !targetOK {
				return fmt.Errorf("edge %q has a dangling visual endpoint", edge.Edge.ID)
			}
			rule, knownType := v2EndpointRules[edge.Edge.Type]
			_, sourceAllowed := rule.sources[source.Node.Type]
			_, targetAllowed := rule.targets[target.Node.Type]
			if !knownType || !sourceAllowed || !targetAllowed || edge.Edge.Source == edge.Edge.Target {
				return fmt.Errorf("edge %q has invalid visual endpoints", edge.Edge.ID)
			}
			if edge.Edge.Type == EdgeObservedAfter && edge.Edge.EvidenceClass != EvidenceClassTemporalCorrelation ||
				edge.Edge.EvidenceClass == EvidenceClassTemporalCorrelation && edge.Edge.Type != EdgeObservedAfter ||
				edge.Edge.Type == EdgeContradicts && edge.Edge.EvidenceClass != EvidenceClassContradiction ||
				edge.Edge.EvidenceClass == EvidenceClassContradiction && edge.Edge.Type != EdgeContradicts {
				return fmt.Errorf("edge %q has an invalid evidence classification", edge.Edge.ID)
			}
			if edge.Edge.EvidenceClass == EvidenceClassInference && edge.Edge.DerivationRule == "" {
				return fmt.Errorf("inferred edge %q lacks a derivation rule", edge.Edge.ID)
			}
			if edge.Edge.Type == EdgeEnvironmentGateSatisfied {
				if _, ok := EnvironmentGateSatisfiedStateForRule(edge.Edge.DerivationRule); !ok {
					return fmt.Errorf("inferred ENVIRONMENT_GATE_SATISFIED edge %q has an unsupported derivation rule", edge.Edge.ID)
				}
				if !retainedGateStateHasKnownEventTime(edge.Edge.DerivationRule, edge.Edge.EventTime) {
					return fmt.Errorf("inferred ENVIRONMENT_GATE_SATISFIED edge %q has unknown event time for not-required state", edge.Edge.ID)
				}
			}
			if edge.Edge.Type == EdgeEnvironmentSecretEligible && edge.Edge.DerivationRule != EnvironmentSecretEligibilityRule {
				return fmt.Errorf("ENVIRONMENT_SECRET_ELIGIBLE edge %q has an unsupported derivation rule", edge.Edge.ID)
			}
			wantID, err := StableEdgeIDV2(edge.Edge.Type, edge.Edge.Source, edge.Edge.Target, edge.Edge.EventTime, edge.Edge.EvidenceClass, edge.Edge.DerivationRule)
			if err != nil || edge.Edge.ID != wantID {
				return fmt.Errorf("edge %q lacks its canonical v2 identity", edge.Edge.ID)
			}
			if !containsString(edge.Edge.FocusFindingIDs, lane.Finding.FindingRevisionID) {
				return errors.New("visual edge lacks lane focus")
			}
			normalEvidence, err := normalizeEvidenceIDs(edge.Edge.EvidenceIDs)
			if err != nil || !slices.Equal(normalEvidence, edge.Edge.EvidenceIDs) {
				return fmt.Errorf("edge %q has noncanonical evidence IDs", edge.Edge.ID)
			}
			normalFocus, err := normalizeFindingIDs(edge.Edge.FocusFindingIDs)
			if err != nil || !slices.Equal(normalFocus, edge.Edge.FocusFindingIDs) {
				return fmt.Errorf("edge %q has noncanonical focus IDs", edge.Edge.ID)
			}
			if edge.RelationshipText != relationshipText(edge.Edge, edgeValues(lane.Edges), lane.Finding) {
				return fmt.Errorf("edge %q has noncanonical relationship wording", edge.Edge.ID)
			}
			expectedRectY := lane.Y + 88 + max(1, maxRows)*(pathNodeHeight+pathRowGap) + edgeRouteBandHeight(laneEdgeValues) + pathEdgeLabelTop + edgeIndex*pathEdgeLabelRowHeight
			if edge.LabelRectX != pathEdgeLabelRectX || edge.LabelRectY != expectedRectY ||
				edge.LabelRectWidth != pathEdgeLabelRectWidth || edge.LabelRectHeight != pathEdgeLabelRectHeight ||
				edge.LabelX != pathEdgeLabelTextX || edge.LabelY != expectedRectY+pathEdgeLabelTextY ||
				edge.LabelLine2Y != expectedRectY+pathEdgeLabelTextY+pathEdgeLabelLineGap || len(edge.LabelLines) != 2 {
				return fmt.Errorf("edge %q has invalid relationship-ledger geometry", edge.Edge.ID)
			}
			labelRect := integerRect{X: edge.LabelRectX, Y: edge.LabelRectY, Width: edge.LabelRectWidth, Height: edge.LabelRectHeight}
			if labelRect.X < 0 || labelRect.Y < lane.Y || labelRect.X+labelRect.Width > path.Width || labelRect.Y+labelRect.Height > lane.Y+lane.Height {
				return fmt.Errorf("edge %q relationship label is outside its lane", edge.Edge.ID)
			}
			for _, node := range lane.Nodes {
				if rectanglesOverlap(labelRect, integerRect{X: node.X, Y: node.Y, Width: node.Width, Height: node.Height}) {
					return fmt.Errorf("edge %q relationship label intersects node %q", edge.Edge.ID, node.Node.ID)
				}
			}
			for _, prior := range labelRects {
				if rectanglesOverlap(labelRect, prior) {
					return fmt.Errorf("edge %q relationship label intersects another relationship label", edge.Edge.ID)
				}
			}
			labelRects = append(labelRects, labelRect)
			if len(edge.Points) < 2 {
				return fmt.Errorf("edge %q lacks routed points", edge.Edge.ID)
			}
			for pointIndex, point := range edge.Points {
				if point.X < 0 || point.X > path.Width || point.Y < lane.Y || point.Y > lane.Y+lane.Height {
					return fmt.Errorf("edge %q route leaves its lane", edge.Edge.ID)
				}
				if pointIndex > 0 {
					prior := edge.Points[pointIndex-1]
					if prior.X != point.X && prior.Y != point.Y {
						return fmt.Errorf("edge %q route is not orthogonal", edge.Edge.ID)
					}
				}
			}
			for _, node := range lane.Nodes {
				if node.Node.ID == edge.Edge.Source || node.Node.ID == edge.Edge.Target {
					continue
				}
				if routeIntersectsRect(edge.Points, integerRect{X: node.X - pathRouteClearance, Y: node.Y - pathRouteClearance, Width: node.Width + 2*pathRouteClearance, Height: node.Height + 2*pathRouteClearance}) {
					return fmt.Errorf("edge %q route intersects non-endpoint node %q", edge.Edge.ID, node.Node.ID)
				}
			}
			for _, id := range edge.Edge.EvidenceIDs {
				if refByEvidence[id] == "" {
					return fmt.Errorf("edge %q evidence is absent from key", edge.Edge.ID)
				}
				selectedEvidence[id] = struct{}{}
			}
			wantRefs := make([]string, 0, min(8, len(edge.Edge.EvidenceIDs)))
			for i, id := range edge.Edge.EvidenceIDs {
				if i < 8 {
					wantRefs = append(wantRefs, refByEvidence[id])
				}
			}
			if strings.Join(wantRefs, "\x00") != strings.Join(edge.EvidenceRefs, "\x00") {
				return fmt.Errorf("edge %q has inconsistent compact evidence references", edge.Edge.ID)
			}
			if edge.AdditionalRefs != max(0, len(edge.Edge.EvidenceIDs)-len(wantRefs)) {
				return fmt.Errorf("edge %q has an inconsistent evidence-reference omission count", edge.Edge.ID)
			}
			materialEdges[edge.Edge.ID] = struct{}{}
		}
		for pair := range satisfiedEnvironments {
			if _, ok := targetedEnvironments[pair]; !ok {
				return errors.New("ENVIRONMENT_GATE_SATISFIED lacks the same-lane TARGETED_ENVIRONMENT relationship")
			}
		}
		for environmentID := range eligibleEnvironments {
			qualified := false
			for pair := range satisfiedEnvironments {
				if strings.HasSuffix(pair, "\x00"+environmentID) {
					qualified = true
					break
				}
			}
			if !qualified {
				return fmt.Errorf("ENVIRONMENT_SECRET_ELIGIBLE for environment %q lacks the same-lane target and gate-requirement relationship", environmentID)
			}
		}
		for environmentID := range nonExecutedEnvironments {
			if _, ok := qualifiedPendingEnvironments[environmentID]; !ok {
				return fmt.Errorf("environment node %q lacks a narrow pending target relationship for non-executed finding", environmentID)
			}
		}
		canonicalEdgeInput := make([]EdgeV2, len(lane.Edges))
		for index := range lane.Edges {
			canonicalEdgeInput[index] = lane.Edges[index].Edge
		}
		canonicalEdges := layoutEdges(canonicalEdgeInput, laneNodes, refByEvidence, lane.Finding, lane.Y, maxRows)
		if len(canonicalEdges) != len(lane.Edges) {
			return fmt.Errorf("noncanonical edge layout in finding lane %q", lane.Finding.FindingRevisionID)
		}
		for index := range canonicalEdges {
			got, want := lane.Edges[index], canonicalEdges[index]
			if got.Edge.ID != want.Edge.ID || !slices.Equal(got.Points, want.Points) ||
				got.LabelRectX != want.LabelRectX || got.LabelRectY != want.LabelRectY || got.LabelRectWidth != want.LabelRectWidth || got.LabelRectHeight != want.LabelRectHeight ||
				got.LabelX != want.LabelX || got.LabelY != want.LabelY || got.LabelLine2Y != want.LabelLine2Y || !slices.Equal(got.LabelLines, want.LabelLines) ||
				got.RelationshipText != want.RelationshipText || !slices.Equal(got.EvidenceRefs, want.EvidenceRefs) || got.AdditionalRefs != want.AdditionalRefs {
				return fmt.Errorf("noncanonical edge order or layout in finding lane %q", lane.Finding.FindingRevisionID)
			}
		}
		lastNoticeKey := ""
		for noticeIndex, notice := range lane.Notices {
			if notice.Code != ProjectionNoticeUnclassifiableLegacyBasis || notice.FindingRevisionID != lane.Finding.FindingRevisionID {
				return fmt.Errorf("invalid projection notice in finding lane %q", lane.Finding.FindingRevisionID)
			}
			if _, ok := legacyBasisNoticeRelationships[notice.Relationship]; !ok || len(notice.EvidenceIDs) == 0 {
				return fmt.Errorf("invalid projection notice relationship in finding lane %q", lane.Finding.FindingRevisionID)
			}
			key := string(notice.Relationship) + "\x00" + string(notice.Code)
			if noticeIndex > 0 && key <= lastNoticeKey {
				return fmt.Errorf("projection notices are not canonically ordered in finding lane %q", lane.Finding.FindingRevisionID)
			}
			lastNoticeKey = key
			normalEvidence, err := normalizeEvidenceIDs(notice.EvidenceIDs)
			if err != nil || !slices.Equal(normalEvidence, notice.EvidenceIDs) {
				return fmt.Errorf("projection notice has noncanonical evidence IDs")
			}
			for _, id := range notice.EvidenceIDs {
				if refByEvidence[id] == "" {
					return fmt.Errorf("projection notice evidence is absent from key")
				}
				selectedEvidence[id] = struct{}{}
			}
		}
		expectedY += lane.Height + pathLaneGap
	}
	if len(logicalNodes) > HardPathNodes || len(materialEdges) > HardPathEdges || len(selectedEvidence) > HardPathEvidenceIDs {
		return errors.New("temporal path exceeds hard logical node, edge, or evidence limits")
	}
	if len(refByEvidence) != len(selectedEvidence) {
		return errors.New("evidence key contains an unreferenced or missing selected evidence ID")
	}
	if path.Counts.SelectedFindings != len(selectedFindings) || path.Counts.SelectedNodes != len(logicalNodes) ||
		path.Counts.SelectedEdges != len(materialEdges) || path.Counts.SelectedEvidenceIDs != len(selectedEvidence) {
		return errors.New("temporal path selected counts do not match rendered identities")
	}
	keyHeight := 100 + len(path.EvidenceKey)*25
	wantHeight := expectedY + keyHeight + 36
	if len(path.Lanes) == 0 {
		wantHeight = pathTop + keyHeight + 36
	}
	if path.Height != wantHeight {
		return errors.New("noncanonical temporal path canvas height")
	}
	return nil
}

func validateSelectionCounts(counts SelectionCounts) error {
	triples := [][3]int{
		{counts.SelectedFindings, counts.TotalFindings, counts.OmittedFindings},
		{counts.SelectedNodes, counts.TotalNodes, counts.OmittedNodes},
		{counts.SelectedEdges, counts.TotalEdges, counts.OmittedEdges},
		{counts.SelectedEvidenceIDs, counts.TotalEvidenceIDs, counts.OmittedEvidenceIDs},
	}
	for _, values := range triples {
		if values[0] < 0 || values[1] < values[0] || values[2] != values[1]-values[0] {
			return errors.New("invalid temporal path selection counts")
		}
	}
	return nil
}

func edgeValues(values []VisualEdge) []EdgeV2 {
	result := make([]EdgeV2, len(values))
	for i := range values {
		result[i] = values[i].Edge
	}
	return result
}

func renderLegend(encoder *xml.Encoder) error {
	group := xml.StartElement{Name: xml.Name{Local: "g"}, Attr: attrs("aria-label", "Legend")}
	if err := encoder.EncodeToken(group); err != nil {
		return err
	}
	if err := textElement(encoder, "title", nil, "Evidence relationship legend"); err != nil {
		return err
	}
	if err := textElement(encoder, "text", textAttrs(36, 32, 20, "bold", "start"), "Temporal evidence path"); err != nil {
		return err
	}
	items := []struct {
		x     int
		class EvidenceClass
		label string
	}{
		{36, EvidenceClassExactObservation, "Exact observation — solid"},
		{370, EvidenceClassInference, "Inference — dashed"},
		{684, EvidenceClassTemporalCorrelation, "Observed after; non-causal — dotted"},
		{1120, EvidenceClassContradiction, "Contradiction — double/opposing"},
	}
	for _, item := range items {
		if err := legendLine(encoder, item.x, 72, item.class); err != nil {
			return err
		}
		if err := textElement(encoder, "text", textAttrs(item.x+70, 77, 16, "normal", "start"), item.label); err != nil {
			return err
		}
	}
	if err := emptyElement(encoder, "line", attrs("x1", "36", "y1", "116", "x2", "90", "y2", "116", "stroke", colorGap, "stroke-width", "3", "stroke-dasharray", "12 8")); err != nil {
		return err
	}
	if err := emptyElement(encoder, "circle", attrs("cx", "63", "cy", "116", "r", "11", "fill", colorBackground, "stroke", colorGap, "stroke-width", "2")); err != nil {
		return err
	}
	if err := textElement(encoder, "text", textAttrs(63, 121, 16, "bold", "middle"), "?"); err != nil {
		return err
	}
	if err := textElement(encoder, "text", textAttrs(106, 121, 16, "normal", "start"), "Evidence gap — interrupted with ? marker"); err != nil {
		return err
	}
	return encoder.EncodeToken(group.End())
}

func legendLine(encoder *xml.Encoder, x, y int, class EvidenceClass) error {
	color, dash, width := edgeAppearance(class)
	base := attrs("x1", strconv.Itoa(x), "y1", strconv.Itoa(y), "x2", strconv.Itoa(x+54), "y2", strconv.Itoa(y), "stroke", color, "stroke-width", strconv.Itoa(width))
	if dash != "" {
		base = append(base, xml.Attr{Name: xml.Name{Local: "stroke-dasharray"}, Value: dash})
	}
	if class == EvidenceClassContradiction {
		first, second := append([]xml.Attr(nil), base...), append([]xml.Attr(nil), base...)
		first[1].Value, first[3].Value = strconv.Itoa(y-3), strconv.Itoa(y-3)
		second[1].Value, second[3].Value = strconv.Itoa(y+3), strconv.Itoa(y+3)
		if err := emptyElement(encoder, "line", first); err != nil {
			return err
		}
		return emptyElement(encoder, "line", second)
	}
	return emptyElement(encoder, "line", base)
}

func renderOmissionNotice(encoder *xml.Encoder, counts SelectionCounts) error {
	text := fmt.Sprintf("Showing %d of %d findings · %d of %d nodes · %d of %d relationships · %d of %d evidence references.",
		counts.SelectedFindings, counts.TotalFindings, counts.SelectedNodes, counts.TotalNodes,
		counts.SelectedEdges, counts.TotalEdges, counts.SelectedEvidenceIDs, counts.TotalEvidenceIDs)
	if counts.OmittedFindings+counts.OmittedNodes+counts.OmittedEdges+counts.OmittedEvidenceIDs > 0 {
		text += " Omitted content remains in the complete case outputs."
	}
	if err := emptyElement(encoder, "rect", attrs("x", "36", "y", "158", "width", strconv.Itoa(pathCanvasWidth-72), "height", "52", "rx", "8", "fill", colorBackground, "stroke", colorBorder, "stroke-width", "2")); err != nil {
		return err
	}
	return textElement(encoder, "text", textAttrs(56, 190, 16, "normal", "start"), text)
}

func renderLane(encoder *xml.Encoder, lane TemporalEvidenceLane, key []EvidenceReference) error {
	findingID, _ := sanitizeSVGText(lane.Finding.FindingRevisionID, maxIDBytes)
	group := xml.StartElement{Name: xml.Name{Local: "g"}, Attr: attrs("data-finding-revision", findingID, "aria-label", "Finding lane "+string(lane.Finding.State))}
	if err := encoder.EncodeToken(group); err != nil {
		return err
	}
	header := TemporalLaneHeader(lane.Finding)
	if err := textElement(encoder, "title", nil, header); err != nil {
		return err
	}
	if err := textElement(encoder, "desc", nil, TemporalLaneDescription(lane.Finding)); err != nil {
		return err
	}
	if err := emptyElement(encoder, "rect", attrs("x", "24", "y", strconv.Itoa(lane.Y), "width", strconv.Itoa(pathCanvasWidth-48), "height", strconv.Itoa(lane.Height), "rx", "12", "fill", colorBackground, "stroke", colorBorder, "stroke-width", "2")); err != nil {
		return err
	}
	if err := textElement(encoder, "text", textAttrs(42, lane.Y+30, 18, "bold", "start"), header); err != nil {
		return err
	}
	_, visibleScope := TemporalLaneScope(lane.Finding)
	if err := textElement(encoder, "text", textAttrs(42, lane.Y+56, 16, "normal", "start"), visibleScope); err != nil {
		return err
	}

	for _, edge := range lane.Edges {
		if err := renderEdge(encoder, edge); err != nil {
			return err
		}
	}
	for _, node := range lane.Nodes {
		if err := renderNode(encoder, node); err != nil {
			return err
		}
	}
	noticeY := lane.Y + lane.Height - 34
	if lane.Finding.State == model.UnknownEvidenceGap {
		_, visibleReason := PresentTemporalGapReason(lane.Finding.EvidenceGapReason)
		if err := renderGap(encoder, 52, noticeY-len(lane.Notices)*58, visibleReason); err != nil {
			return err
		}
	}
	for i, notice := range lane.Notices {
		y := noticeY - (len(lane.Notices)-1-i)*58
		if err := renderProjectionNotice(encoder, notice, key, y); err != nil {
			return err
		}
	}
	return encoder.EncodeToken(group.End())
}

func renderNode(encoder *xml.Encoder, node VisualNode) error {
	focus := append([]string(nil), node.Node.FocusFindingIDs...)
	sort.Strings(focus)
	group := xml.StartElement{Name: xml.Name{Local: "g"}, Attr: attrs("id", node.LocalID, "data-node-id", node.Node.ID, "data-node-type", string(node.Node.Type), "data-finding-revisions", strings.Join(focus, " "))}
	if err := encoder.EncodeToken(group); err != nil {
		return err
	}
	if err := textElement(encoder, "title", nil, string(node.Node.Type)+": "+node.FullLabel); err != nil {
		return err
	}
	desc := "Graph node " + node.Node.ID + ". Type " + string(node.Node.Type) + "."
	if len(node.Node.EvidenceIDs) > 0 {
		desc += " Evidence: " + strings.Join(node.Node.EvidenceIDs, ", ") + "."
	}
	if err := textElement(encoder, "desc", nil, desc); err != nil {
		return err
	}
	if err := emptyElement(encoder, "rect", attrs("x", strconv.Itoa(node.X), "y", strconv.Itoa(node.Y), "width", strconv.Itoa(node.Width), "height", strconv.Itoa(node.Height), "rx", "8", "fill", colorBackground, "stroke", colorBorder, "stroke-width", "2")); err != nil {
		return err
	}
	if err := textElement(encoder, "text", textAttrs(node.X+12, node.Y+22, 16, "bold", "start"), string(node.Node.Type)); err != nil {
		return err
	}
	start := xml.StartElement{Name: xml.Name{Local: "text"}, Attr: textAttrs(node.X+12, node.Y+45, 16, "normal", "start")}
	if err := encoder.EncodeToken(start); err != nil {
		return err
	}
	for i, line := range node.LabelLines {
		attributes := attrs("x", strconv.Itoa(node.X+12))
		if i == 0 {
			attributes = append(attributes, xml.Attr{Name: xml.Name{Local: "dy"}, Value: "0"})
		} else {
			attributes = append(attributes, xml.Attr{Name: xml.Name{Local: "dy"}, Value: "19"})
		}
		if err := textElement(encoder, "tspan", attributes, line); err != nil {
			return err
		}
	}
	if err := encoder.EncodeToken(start.End()); err != nil {
		return err
	}
	return encoder.EncodeToken(group.End())
}

func renderEdge(encoder *xml.Encoder, edge VisualEdge) error {
	refs := strings.Join(edge.EvidenceRefs, " ")
	group := xml.StartElement{Name: xml.Name{Local: "g"}, Attr: attrs("id", edge.LocalID, "data-edge-id", edge.Edge.ID, "data-edge-type", string(edge.Edge.Type), "data-evidence-class", string(edge.Edge.EvidenceClass), "data-evidence-refs", refs)}
	if err := encoder.EncodeToken(group); err != nil {
		return err
	}
	if err := textElement(encoder, "title", nil, edge.RelationshipText); err != nil {
		return err
	}
	desc := "Relationship " + string(edge.Edge.Type) + "; class " + string(edge.Edge.EvidenceClass) + "; evidence " + strings.Join(edge.Edge.EvidenceIDs, ", ") + "."
	if edge.Edge.EventTime != "" {
		desc += " Event time " + edge.Edge.EventTime + "."
	}
	if edge.Edge.DerivationRule != "" {
		desc += " Derivation rule " + edge.Edge.DerivationRule + "."
	}
	if err := textElement(encoder, "desc", nil, desc); err != nil {
		return err
	}
	color, dash, width := edgeAppearance(edge.Edge.EvidenceClass)
	points := pointText(edge.Points, 0)
	lineAttrs := attrs("points", points, "fill", "none", "stroke", color, "stroke-width", strconv.Itoa(width))
	if dash != "" {
		lineAttrs = append(lineAttrs, xml.Attr{Name: xml.Name{Local: "stroke-dasharray"}, Value: dash})
	}
	if err := emptyElement(encoder, "polyline", attrs(
		"points", points,
		"fill", "none",
		"stroke", colorBackground,
		"stroke-width", strconv.Itoa(routeUnderlayWidth(edge.Edge.EvidenceClass, width)),
		"stroke-linejoin", "round",
		"stroke-linecap", "butt",
		"aria-hidden", "true",
		"data-route-underlay", "true",
	)); err != nil {
		return err
	}
	if edge.Edge.EvidenceClass == EvidenceClassContradiction {
		first := append([]xml.Attr(nil), lineAttrs...)
		first[0].Value = pointText(edge.Points, -3)
		second := append([]xml.Attr(nil), lineAttrs...)
		second[0].Value = pointText(edge.Points, 3)
		if err := emptyElement(encoder, "polyline", first); err != nil {
			return err
		}
		if err := emptyElement(encoder, "polyline", second); err != nil {
			return err
		}
		if err := arrowPolygon(encoder, edge.Points[len(edge.Points)-2], edge.Points[len(edge.Points)-1], color); err != nil {
			return err
		}
		if err := arrowPolygon(encoder, edge.Points[1], edge.Points[0], color); err != nil {
			return err
		}
	} else {
		if err := emptyElement(encoder, "polyline", lineAttrs); err != nil {
			return err
		}
		if err := arrowPolygon(encoder, edge.Points[len(edge.Points)-2], edge.Points[len(edge.Points)-1], color); err != nil {
			return err
		}
	}
	if err := emptyElement(encoder, "rect", attrs("x", strconv.Itoa(edge.LabelRectX), "y", strconv.Itoa(edge.LabelRectY), "width", strconv.Itoa(edge.LabelRectWidth), "height", strconv.Itoa(edge.LabelRectHeight), "rx", "5", "fill", colorBackground, "stroke", color, "stroke-width", "2")); err != nil {
		return err
	}
	if err := textElement(encoder, "text", textAttrs(edge.LabelX, edge.LabelY, 16, "bold", "start"), edge.LabelLines[0]); err != nil {
		return err
	}
	if err := textElement(encoder, "text", textAttrs(edge.LabelX, edge.LabelLine2Y, 16, "normal", "start"), edge.LabelLines[1]); err != nil {
		return err
	}
	return encoder.EncodeToken(group.End())
}

func routeUnderlayWidth(class EvidenceClass, foregroundWidth int) int {
	if class == EvidenceClassContradiction {
		return 14
	}
	return foregroundWidth + 6
}

type integerRect struct {
	X, Y, Width, Height int
}

func rectanglesOverlap(left, right integerRect) bool {
	return left.X < right.X+right.Width && right.X < left.X+left.Width &&
		left.Y < right.Y+right.Height && right.Y < left.Y+left.Height
}

func routeIntersectsRect(points []Point, rect integerRect) bool {
	for index := 1; index < len(points); index++ {
		from, to := points[index-1], points[index]
		switch {
		case from.Y == to.Y:
			left, right := min(from.X, to.X), max(from.X, to.X)
			if from.Y >= rect.Y && from.Y <= rect.Y+rect.Height && right >= rect.X && left <= rect.X+rect.Width {
				return true
			}
		case from.X == to.X:
			top, bottom := min(from.Y, to.Y), max(from.Y, to.Y)
			if from.X >= rect.X && from.X <= rect.X+rect.Width && bottom >= rect.Y && top <= rect.Y+rect.Height {
				return true
			}
		}
	}
	return false
}

func edgeAppearance(class EvidenceClass) (color, dash string, width int) {
	switch class {
	case EvidenceClassExactObservation:
		return colorExact, "", 2
	case EvidenceClassInference:
		return colorInference, "10 7", 3
	case EvidenceClassTemporalCorrelation:
		return colorTemporal, "2 7", 3
	case EvidenceClassContradiction:
		return colorContradiction, "", 4
	default:
		return colorBorder, "", 2
	}
}

func pointText(points []Point, yOffset int) string {
	values := make([]string, len(points))
	for i, point := range points {
		values[i] = fmt.Sprintf("%d,%d", point.X, point.Y+yOffset)
	}
	return strings.Join(values, " ")
}

func arrowPolygon(encoder *xml.Encoder, from, to Point, color string) error {
	var points string
	switch {
	case to.X > from.X:
		points = fmt.Sprintf("%d,%d %d,%d %d,%d", to.X, to.Y, to.X-12, to.Y-7, to.X-12, to.Y+7)
	case to.X < from.X:
		points = fmt.Sprintf("%d,%d %d,%d %d,%d", to.X, to.Y, to.X+12, to.Y-7, to.X+12, to.Y+7)
	case to.Y > from.Y:
		points = fmt.Sprintf("%d,%d %d,%d %d,%d", to.X, to.Y, to.X-7, to.Y-12, to.X+7, to.Y-12)
	default:
		points = fmt.Sprintf("%d,%d %d,%d %d,%d", to.X, to.Y, to.X-7, to.Y+12, to.X+7, to.Y+12)
	}
	return emptyElement(encoder, "polygon", attrs("points", points, "fill", color, "stroke", color, "stroke-width", "1"))
}

func renderGap(encoder *xml.Encoder, x, y int, reason string) error {
	if err := emptyElement(encoder, "line", attrs("x1", strconv.Itoa(x), "y1", strconv.Itoa(y), "x2", strconv.Itoa(x+80), "y2", strconv.Itoa(y), "stroke", colorGap, "stroke-width", "3", "stroke-dasharray", "12 8")); err != nil {
		return err
	}
	if err := emptyElement(encoder, "circle", attrs("cx", strconv.Itoa(x+40), "cy", strconv.Itoa(y), "r", "13", "fill", colorBackground, "stroke", colorGap, "stroke-width", "3")); err != nil {
		return err
	}
	if err := textElement(encoder, "text", textAttrs(x+40, y+6, 18, "bold", "middle"), "?"); err != nil {
		return err
	}
	return textElement(encoder, "text", textAttrs(x+100, y+6, 16, "bold", "start"), "UNKNOWN_EVIDENCE_GAP — "+reason)
}

func renderProjectionNotice(encoder *xml.Encoder, notice ProjectionNotice, key []EvidenceReference, y int) error {
	full, visible := PresentProjectionNotice(notice, key)
	group := xml.StartElement{Name: xml.Name{Local: "g"}, Attr: attrs(
		"data-projection-notice", "true", "data-relationship", string(notice.Relationship),
	)}
	if err := encoder.EncodeToken(group); err != nil {
		return err
	}
	if err := textElement(encoder, "title", nil, "Partial relationship projection"); err != nil {
		return err
	}
	if err := textElement(encoder, "desc", nil, full); err != nil {
		return err
	}
	if err := emptyElement(encoder, "rect", attrs("x", "52", "y", strconv.Itoa(y-24), "width", strconv.Itoa(pathCanvasWidth-122), "height", "42", "rx", "6", "fill", colorBackground, "stroke", colorGap, "stroke-width", "2", "stroke-dasharray", "8 6")); err != nil {
		return err
	}
	if err := emptyElement(encoder, "circle", attrs("cx", "76", "cy", strconv.Itoa(y-3), "r", "12", "fill", colorBackground, "stroke", colorGap, "stroke-width", "2")); err != nil {
		return err
	}
	if err := textElement(encoder, "text", textAttrs(76, y+3, 16, "bold", "middle"), "i"); err != nil {
		return err
	}
	if err := textElement(encoder, "text", textAttrs(100, y+3, 16, "normal", "start"), visible); err != nil {
		return err
	}
	return encoder.EncodeToken(group.End())
}

func renderEvidenceKey(ctx context.Context, encoder *xml.Encoder, key []EvidenceReference, y int) error {
	group := xml.StartElement{Name: xml.Name{Local: "g"}, Attr: attrs("aria-label", "Evidence reference key")}
	if err := encoder.EncodeToken(group); err != nil {
		return err
	}
	if err := textElement(encoder, "title", nil, "Evidence reference key"); err != nil {
		return err
	}
	if err := textElement(encoder, "text", textAttrs(36, y, 20, "bold", "start"), "Evidence references"); err != nil {
		return err
	}
	for i, ref := range key {
		if i&31 == 0 {
			if err := checkContext(ctx); err != nil {
				return err
			}
		}
		if err := textElement(encoder, "text", textAttrs(36, y+32+i*25, 16, "normal", "start"), ref.CompactID+" · "+ref.EvidenceID); err != nil {
			return err
		}
	}
	return encoder.EncodeToken(group.End())
}

func textAttrs(x, y, size int, weight, anchor string) []xml.Attr {
	return attrs("x", strconv.Itoa(x), "y", strconv.Itoa(y), "fill", colorText,
		"font-family", fontStack, "font-size", strconv.Itoa(size), "font-weight", weight,
		"text-anchor", anchor)
}

func attrs(values ...string) []xml.Attr {
	result := make([]xml.Attr, 0, len(values)/2)
	for i := 0; i+1 < len(values); i += 2 {
		value, _ := sanitizeSVGText(values[i+1], 16_384)
		result = append(result, xml.Attr{Name: xml.Name{Local: values[i]}, Value: value})
	}
	return result
}

func textElement(encoder *xml.Encoder, name string, attributes []xml.Attr, text string) error {
	start := xml.StartElement{Name: xml.Name{Local: name}, Attr: attributes}
	if err := encoder.EncodeToken(start); err != nil {
		return err
	}
	// Selected-edge descriptions can legitimately contain the complete set of
	// up to 512 bounded evidence IDs. Keep that accessible list intact while the
	// final document remains subject to the fixed 8 MiB budget.
	text, _ = sanitizeSVGText(text, 64<<10)
	if err := encoder.EncodeToken(xml.CharData([]byte(text))); err != nil {
		return err
	}
	return encoder.EncodeToken(start.End())
}

func emptyElement(encoder *xml.Encoder, name string, attributes []xml.Attr) error {
	start := xml.StartElement{Name: xml.Name{Local: name}, Attr: attributes}
	if err := encoder.EncodeToken(start); err != nil {
		return err
	}
	return encoder.EncodeToken(start.End())
}

// sanitizeSVGText applies XML-sink sanitization before encoding/xml escaping.
func sanitizeSVGText(value string, maxBytes int) (string, bool) {
	return sanitize.Presentation(value, maxBytes)
}
