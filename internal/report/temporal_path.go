package report

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/torjan0/cirewind/internal/graph"
	"github.com/torjan0/cirewind/internal/model"
)

const (
	pathColorExact         = "#005A9C"
	pathColorInference     = "#8A4B08"
	pathColorTemporal      = "#006B4F"
	pathColorContradiction = "#B42318"
	pathColorGap           = "#5F6368"
	pathColorText          = "#111827"
	pathColorBorder        = "#334155"
	pathColorBackground    = "#FFFFFF"
)

const temporalPathTemplate = `{{define "temporalPath"}}
<p id="temporal-path-help"><a id="temporal-path-text-link" href="#temporal-path-text-summary">Skip to the accessible text equivalent</a> · <a href="graph.svg">Open the standalone graph.svg</a>. The graph is a fixed-scale, two-dimensional scroll region; use arrow or Page keys while it is focused. Both views use the same deterministic presentation model.</p>
<div class="temporal-path" tabindex="0" role="region" aria-labelledby="temporal-path-heading" aria-describedby="temporal-path-help"><svg xmlns="http://www.w3.org/2000/svg" role="img" aria-labelledby="report-tep-title report-tep-desc" data-cirewind-schema="{{.Path.SchemaVersion}}" width="{{.Path.Width}}" height="{{.Path.Height}}" viewBox="0 0 {{.Path.Width}} {{.Path.Height}}">
<title id="report-tep-title">Temporal evidence path</title><desc id="report-tep-desc">{{.Description}}</desc>
<rect x="0" y="0" width="{{.Path.Width}}" height="{{.Path.Height}}" fill="` + pathColorBackground + `"></rect>
<g aria-label="Legend"><title>Evidence relationship legend</title><text x="36" y="32" fill="` + pathColorText + `" font-family="ui-monospace, monospace" font-size="20" font-weight="bold" text-anchor="start">Temporal evidence path</text>
<line x1="36" y1="72" x2="90" y2="72" stroke="` + pathColorExact + `" stroke-width="2"></line><text x="106" y="77" fill="` + pathColorText + `" font-family="ui-monospace, monospace" font-size="16">Exact observation — solid</text>
<line x1="370" y1="72" x2="424" y2="72" stroke="` + pathColorInference + `" stroke-width="3" stroke-dasharray="10 7"></line><text x="440" y="77" fill="` + pathColorText + `" font-family="ui-monospace, monospace" font-size="16">Inference — dashed</text>
<line x1="684" y1="72" x2="738" y2="72" stroke="` + pathColorTemporal + `" stroke-width="3" stroke-dasharray="2 7"></line><text x="754" y="77" fill="` + pathColorText + `" font-family="ui-monospace, monospace" font-size="16">Observed after; non-causal — dotted</text>
<line x1="1092" y1="69" x2="1146" y2="69" stroke="` + pathColorContradiction + `" stroke-width="4"></line><line x1="1092" y1="75" x2="1146" y2="75" stroke="` + pathColorContradiction + `" stroke-width="4"></line><text x="1162" y="77" fill="` + pathColorText + `" font-family="ui-monospace, monospace" font-size="16">Contradiction — double/opposing</text>
<line x1="36" y1="116" x2="90" y2="116" stroke="` + pathColorGap + `" stroke-width="3" stroke-dasharray="12 8"></line><circle cx="63" cy="116" r="11" fill="` + pathColorBackground + `" stroke="` + pathColorGap + `" stroke-width="2"></circle><text x="63" y="121" fill="` + pathColorText + `" font-family="ui-monospace, monospace" font-size="16" font-weight="bold" text-anchor="middle">?</text><text x="106" y="121" fill="` + pathColorText + `" font-family="ui-monospace, monospace" font-size="16">Evidence gap — interrupted with ? marker</text></g>
<rect x="36" y="158" width="1668" height="52" rx="8" fill="` + pathColorBackground + `" stroke="` + pathColorBorder + `" stroke-width="2"></rect><text x="56" y="190" fill="` + pathColorText + `" font-family="ui-monospace, monospace" font-size="16">{{.OmissionText}}</text>
{{range .Lanes}}<g data-graph-item="true" data-visual-lane="true" data-revision="{{.FindingID}}" data-findings="{{.Focus}}" data-finding-revision="{{.FindingID}}" aria-label="Finding lane {{.FindingState}}"><title>{{.Header}}</title><desc>{{.Description}}</desc>
<rect x="24" y="{{.Y}}" width="1692" height="{{.Height}}" rx="12" fill="` + pathColorBackground + `" stroke="` + pathColorBorder + `" stroke-width="2"></rect><text x="42" y="{{.FindingY}}" fill="` + pathColorText + `" font-family="ui-monospace, monospace" font-size="18" font-weight="bold">{{.Header}}</text><text x="42" y="{{.ScopeY}}" fill="` + pathColorText + `" font-family="ui-monospace, monospace" font-size="16">{{.Scope}}</text>
{{range .Edges}}<g id="{{.Edge.LocalID}}" data-edge-id="{{.Edge.Edge.ID}}" data-edge-type="{{.Edge.Edge.Type}}" data-evidence-class="{{.Edge.Edge.EvidenceClass}}" data-evidence-refs="{{range .Edge.EvidenceRefs}}{{.}} {{end}}"><title>{{.Title}}</title><desc>{{.Description}}</desc>{{if .Contradiction}}<polyline points="{{.PointsMinus}}" fill="none" stroke="{{.Color}}" stroke-width="{{.Width}}"></polyline><polyline points="{{.PointsPlus}}" fill="none" stroke="{{.Color}}" stroke-width="{{.Width}}"></polyline><polygon points="{{.Arrow}}" fill="{{.Color}}" stroke="{{.Color}}" stroke-width="1"></polygon><polygon points="{{.ReverseArrow}}" fill="{{.Color}}" stroke="{{.Color}}" stroke-width="1"></polygon>{{else}}<polyline points="{{.Points}}" fill="none" stroke="{{.Color}}" stroke-width="{{.Width}}"{{if .Dash}} stroke-dasharray="{{.Dash}}"{{end}}></polyline><polygon points="{{.Arrow}}" fill="{{.Color}}" stroke="{{.Color}}" stroke-width="1"></polygon>{{end}}<rect x="{{.LabelRectX}}" y="{{.LabelRectY}}" width="{{.LabelRectWidth}}" height="{{.LabelRectHeight}}" rx="5" fill="` + pathColorBackground + `" stroke="{{.Color}}" stroke-width="2"></rect><text x="{{.Edge.LabelX}}" y="{{.Edge.LabelY}}" fill="` + pathColorText + `" font-family="ui-monospace, monospace" font-size="16" font-weight="bold" text-anchor="start">{{.LabelLine1}}</text><text x="{{.Edge.LabelX}}" y="{{.LabelLine2Y}}" fill="` + pathColorText + `" font-family="ui-monospace, monospace" font-size="16" text-anchor="start">{{.LabelLine2}}</text></g>{{end}}
{{range .Nodes}}{{$node := .}}<g id="{{.Node.LocalID}}" data-node-id="{{.Node.Node.ID}}" data-node-type="{{.Type}}" data-finding-revisions="{{.Focus}}"><title>{{.Title}}</title><desc>{{.Description}}</desc><rect x="{{.Node.X}}" y="{{.Node.Y}}" width="{{.Node.Width}}" height="{{.Node.Height}}" rx="8" fill="` + pathColorBackground + `" stroke="` + pathColorBorder + `" stroke-width="2"></rect><text x="{{.TextX}}" y="{{.TypeY}}" fill="` + pathColorText + `" font-family="ui-monospace, monospace" font-size="16" font-weight="bold">{{.Type}}</text><text x="{{.TextX}}" y="{{.LabelY}}" fill="` + pathColorText + `" font-family="ui-monospace, monospace" font-size="16">{{range $index, $line := .Node.LabelLines}}<tspan x="{{$node.TextX}}" dy="{{if $index}}19{{else}}0{{end}}">{{$line}}</tspan>{{end}}</text></g>{{end}}
{{with .Gap}}<line x1="{{.X}}" y1="{{.Y}}" x2="{{.X2}}" y2="{{.Y}}" stroke="` + pathColorGap + `" stroke-width="3" stroke-dasharray="12 8"></line><circle cx="{{.Circle}}" cy="{{.Y}}" r="13" fill="` + pathColorBackground + `" stroke="` + pathColorGap + `" stroke-width="3"></circle><text x="{{.Circle}}" y="{{.TextY}}" fill="` + pathColorText + `" font-family="ui-monospace, monospace" font-size="18" font-weight="bold" text-anchor="middle">?</text><text x="{{.TextX}}" y="{{.TextY}}" fill="` + pathColorText + `" font-family="ui-monospace, monospace" font-size="16" font-weight="bold">UNKNOWN_EVIDENCE_GAP — {{.Reason}}</text>{{end}}
{{range .Notices}}<rect x="52" y="{{.RectY}}" width="1618" height="42" rx="6" fill="` + pathColorBackground + `" stroke="` + pathColorGap + `" stroke-width="2" stroke-dasharray="8 6"></rect><circle cx="76" cy="{{.CircleY}}" r="12" fill="` + pathColorBackground + `" stroke="` + pathColorGap + `" stroke-width="2"></circle><text x="76" y="{{.TextY}}" fill="` + pathColorText + `" font-family="ui-monospace, monospace" font-size="16" font-weight="bold" text-anchor="middle">i</text><text x="100" y="{{.TextY}}" fill="` + pathColorText + `" font-family="ui-monospace, monospace" font-size="16">{{.Text}}</text>{{end}}</g>{{end}}
<g aria-label="Evidence reference key"><title>Evidence reference key</title><text x="36" y="{{.EvidenceKeyY}}" fill="` + pathColorText + `" font-family="ui-monospace, monospace" font-size="20" font-weight="bold">Evidence references</text>{{range .EvidenceKey}}<text x="36" y="{{.Y}}" fill="` + pathColorText + `" font-family="ui-monospace, monospace" font-size="16">{{.CompactID}} · {{.EvidenceID}}</text>{{end}}</g></svg></div>
<p><span id="visual-shown">{{.SelectedFindings}}</span> matching findings shown in the visual; <span id="visual-omitted">{{.OmittedFindings}}</span> matching findings omitted from the visual; see the findings table.</p>
<details id="temporal-path-text" class="path-fallback"><summary id="temporal-path-text-summary">Accessible text equivalent and complete selected-edge evidence</summary><p>{{.OmissionText}}</p><div class="path-legend" aria-label="Evidence relationship legend"><span><strong>EXACT_OBSERVATION</strong> — solid; exact relationship only</span><span><strong>INFERENCE</strong> — dashed; derivation rule shown</span><span><strong>TEMPORAL_CORRELATION</strong> — dotted; observed after, causation not established</span><span><strong>CONTRADICTION</strong> — double/opposing; contradictory evidence</span><span><strong>UNKNOWN_EVIDENCE_GAP</strong> — interrupted with ? marker; missing evidence is not a negative result</span></div>
{{range .Lanes}}<section data-graph-item="true" data-visual-lane="true" data-revision="{{.FindingID}}" data-findings="{{.Focus}}"><h4>{{.Header}}</h4><p>{{.Scope}} · indicator <code>{{.IndicatorID}}</code> · finding revision <code>{{.FindingID}}</code></p>{{with .Gap}}<p class="warning">UNKNOWN_EVIDENCE_GAP — {{.Reason}}</p>{{end}}{{range .Notices}}<p class="classification-unknown">{{.Text}}</p>{{end}}<h5>Selected nodes</h5><ul>{{range .Nodes}}<li><code>{{.Type}}:{{.Node.Node.ID}}</code> — {{.Node.FullLabel}}{{if .Node.Node.EvidenceIDs}}; evidence: {{range .Node.Node.EvidenceIDs}}<code>{{.}}</code> {{end}}{{end}}</li>{{else}}<li>No presentable node selected for this finding lane.</li>{{end}}</ul><h5>Selected material relationships</h5><table class="path-table"><caption>Selected relationships for {{.Header}}</caption><thead><tr><th>Relationship</th><th>Endpoints</th><th>Evidence basis</th><th>Evidence IDs</th></tr></thead><tbody>{{range .Edges}}<tr><td><code>{{.Edge.Edge.Type}}</code><br>{{.Title}}</td><td><code>{{.Edge.Edge.Source}}</code> → <code>{{.Edge.Edge.Target}}</code></td><td>{{.Edge.Edge.EvidenceClass}}{{if .Edge.Edge.DerivationRule}}<br>Rule: <code>{{.Edge.Edge.DerivationRule}}</code>{{end}}{{if .Edge.Edge.EventTime}}<br>Event time: <code>{{.Edge.Edge.EventTime}}</code>{{end}}</td><td>{{range .EvidenceIDs}}<code>{{.}}</code><br>{{end}}</td></tr>{{else}}<tr><td colspan="4">No material relationship selected for this finding lane; an evidence gap is not represented by an invented edge.</td></tr>{{end}}</tbody></table></section>{{end}}
<h4>Evidence reference key</h4><dl>{{range .EvidenceKey}}<dt><code>{{.CompactID}}</code></dt><dd><code>{{.EvidenceID}}</code></dd>{{else}}<dt>None</dt><dd>No selected edge evidence references.</dd>{{end}}</dl></details>{{end}}`

type temporalPathView struct {
	Path             graph.TemporalEvidencePath
	Description      string
	OmissionText     string
	Lanes            []temporalLaneView
	EvidenceKey      []temporalEvidenceReferenceView
	EvidenceKeyY     int
	SelectedFindings int
	OmittedFindings  int
}

type temporalLaneView struct {
	Finding      graph.FindingIndexEntry
	Focus        string
	Header       string
	Scope        string
	Description  string
	Y            int
	Height       int
	FindingY     int
	ScopeY       int
	Nodes        []temporalNodeView
	Edges        []temporalEdgeView
	Gap          *temporalGapView
	Notices      []temporalNoticeView
	FindingState string
	FindingLevel string
	FindingID    string
	IndicatorID  string
}

type temporalNodeView struct {
	Node        graph.VisualNode
	Focus       string
	Title       string
	Description string
	Type        string
	TextX       int
	TypeY       int
	LabelY      int
}

type temporalEdgeView struct {
	Edge            graph.VisualEdge
	Focus           string
	Title           string
	Description     string
	Color           string
	Dash            string
	Width           int
	Points          string
	PointsMinus     string
	PointsPlus      string
	Arrow           string
	ReverseArrow    string
	Contradiction   bool
	LabelRectX      int
	LabelRectY      int
	LabelRectWidth  int
	LabelRectHeight int
	LabelLine1      string
	LabelLine2      string
	LabelLine2Y     int
	EvidenceIDs     []string
}

type temporalGapView struct {
	X      int
	X2     int
	Y      int
	Circle int
	TextX  int
	TextY  int
	Reason string
}

type temporalEvidenceReferenceView struct {
	graph.EvidenceReference
	Y int
}

type temporalNoticeView struct {
	Notice  graph.ProjectionNotice
	Y       int
	RectY   int
	CircleY int
	TextY   int
	Text    string
}

func buildTemporalPathView(path graph.TemporalEvidencePath) temporalPathView {
	counts := path.Counts
	description := fmt.Sprintf("%s case; showing %d of %d findings, %d of %d nodes, %d of %d relationships, and %d of %d evidence references.",
		path.CaseKind, counts.SelectedFindings, counts.TotalFindings,
		counts.SelectedNodes, counts.TotalNodes, counts.SelectedEdges, counts.TotalEdges,
		counts.SelectedEvidenceIDs, counts.TotalEvidenceIDs)
	omission := fmt.Sprintf("Showing %d of %d findings · %d of %d nodes · %d of %d relationships · %d of %d evidence references.",
		counts.SelectedFindings, counts.TotalFindings, counts.SelectedNodes, counts.TotalNodes,
		counts.SelectedEdges, counts.TotalEdges, counts.SelectedEvidenceIDs, counts.TotalEvidenceIDs)
	if counts.OmittedFindings+counts.OmittedNodes+counts.OmittedEdges+counts.OmittedEvidenceIDs > 0 {
		omission += " Omitted content remains in the complete case outputs."
	}

	view := temporalPathView{
		Path: path, Description: description, OmissionText: omission,
		EvidenceKeyY:     276,
		SelectedFindings: counts.SelectedFindings, OmittedFindings: counts.OmittedFindings,
	}
	view.Lanes = make([]temporalLaneView, 0, len(path.Lanes))
	for _, lane := range path.Lanes {
		laneView := temporalLaneView{
			Finding: lane.Finding, Focus: lane.Finding.FindingRevisionID,
			Header: string(lane.Finding.State) + " · " + string(lane.Finding.ProvenanceLevel),
			Scope:  temporalLaneScope(lane.Finding), Description: temporalLaneDescription(lane.Finding),
			Y: lane.Y, Height: lane.Height, FindingY: lane.Y + 30, ScopeY: lane.Y + 56,
			FindingState: string(lane.Finding.State),
			FindingLevel: string(lane.Finding.ProvenanceLevel), FindingID: lane.Finding.FindingRevisionID,
			IndicatorID: lane.Finding.IndicatorID,
		}
		laneView.Nodes = make([]temporalNodeView, 0, len(lane.Nodes))
		for _, node := range lane.Nodes {
			focus := append([]string(nil), node.Node.FocusFindingIDs...)
			sort.Strings(focus)
			description := "Graph node " + node.Node.ID + ". Type " + string(node.Node.Type) + "."
			if len(node.Node.EvidenceIDs) > 0 {
				description += " Evidence: " + strings.Join(node.Node.EvidenceIDs, ", ") + "."
			}
			laneView.Nodes = append(laneView.Nodes, temporalNodeView{
				Node: node, Focus: strings.Join(focus, " "), Title: string(node.Node.Type) + ": " + node.FullLabel,
				Description: description, Type: string(node.Node.Type), TextX: node.X + 12,
				TypeY: node.Y + 22, LabelY: node.Y + 47,
			})
		}
		laneView.Edges = make([]temporalEdgeView, 0, len(lane.Edges))
		for _, edge := range lane.Edges {
			laneView.Edges = append(laneView.Edges, buildTemporalEdgeView(edge, lane.Finding.FindingRevisionID))
		}

		noticeY := lane.Y + lane.Height - 34
		if lane.Finding.State == model.UnknownEvidenceGap {
			gapY := noticeY - len(lane.Notices)*58
			laneView.Gap = &temporalGapView{X: 52, X2: 132, Y: gapY, Circle: 92, TextX: 152, TextY: gapY + 6, Reason: lane.Finding.EvidenceGapReason}
		}
		laneView.Notices = make([]temporalNoticeView, 0, len(lane.Notices))
		for index, notice := range lane.Notices {
			y := noticeY - (len(lane.Notices)-1-index)*58
			laneView.Notices = append(laneView.Notices, temporalNoticeView{
				Notice: notice, Y: y, RectY: y - 24, CircleY: y - 3, TextY: y + 3,
				Text: "visual relationship omitted — legacy evidence basis unavailable · " + string(notice.Relationship) + " · " + strings.Join(notice.EvidenceIDs, ", "),
			})
		}
		view.Lanes = append(view.Lanes, laneView)
	}
	if len(path.Lanes) > 0 {
		last := path.Lanes[len(path.Lanes)-1]
		view.EvidenceKeyY = last.Y + last.Height + 52
	}
	view.EvidenceKey = make([]temporalEvidenceReferenceView, len(path.EvidenceKey))
	for index, reference := range path.EvidenceKey {
		view.EvidenceKey[index] = temporalEvidenceReferenceView{EvidenceReference: reference, Y: view.EvidenceKeyY + 32 + index*25}
	}
	return view
}

func buildTemporalEdgeView(edge graph.VisualEdge, focus string) temporalEdgeView {
	color, dash, width := temporalEdgeAppearance(edge.Edge.EvidenceClass)
	description := "Relationship " + string(edge.Edge.Type) + "; class " + string(edge.Edge.EvidenceClass) + "; evidence " + strings.Join(edge.Edge.EvidenceIDs, ", ") + "."
	if edge.Edge.EventTime != "" {
		description += " Event time " + edge.Edge.EventTime + "."
	}
	if edge.Edge.DerivationRule != "" {
		description += " Derivation rule " + edge.Edge.DerivationRule + "."
	}
	result := temporalEdgeView{
		Edge: edge, Focus: focus, Title: edge.RelationshipText, Description: description,
		Color: color, Dash: dash, Width: width, Points: temporalPointText(edge.Points, 0),
		Contradiction: edge.Edge.EvidenceClass == graph.EvidenceClassContradiction,
		LabelRectX:    edge.LabelRectX, LabelRectY: edge.LabelRectY,
		LabelRectWidth: edge.LabelRectWidth, LabelRectHeight: edge.LabelRectHeight,
		LabelLine1: edge.LabelLines[0], LabelLine2: edge.LabelLines[1], LabelLine2Y: edge.LabelLine2Y,
		EvidenceIDs: append([]string(nil), edge.Edge.EvidenceIDs...),
	}
	if len(edge.Points) >= 2 {
		result.Arrow = temporalArrowPoints(edge.Points[len(edge.Points)-2], edge.Points[len(edge.Points)-1])
		if result.Contradiction {
			result.ReverseArrow = temporalArrowPoints(edge.Points[1], edge.Points[0])
			result.PointsMinus = temporalPointText(edge.Points, -3)
			result.PointsPlus = temporalPointText(edge.Points, 3)
		}
	}
	return result
}

func temporalEdgeAppearance(class graph.EvidenceClass) (color, dash string, width int) {
	switch class {
	case graph.EvidenceClassExactObservation:
		return pathColorExact, "", 2
	case graph.EvidenceClassInference:
		return pathColorInference, "10 7", 3
	case graph.EvidenceClassTemporalCorrelation:
		return pathColorTemporal, "2 7", 3
	case graph.EvidenceClassContradiction:
		return pathColorContradiction, "", 4
	default:
		return pathColorBorder, "", 2
	}
}

func temporalPointText(points []graph.Point, yOffset int) string {
	values := make([]string, len(points))
	for index, point := range points {
		values[index] = fmt.Sprintf("%d,%d", point.X, point.Y+yOffset)
	}
	return strings.Join(values, " ")
}

func temporalArrowPoints(from, to graph.Point) string {
	switch {
	case to.X > from.X:
		return fmt.Sprintf("%d,%d %d,%d %d,%d", to.X, to.Y, to.X-12, to.Y-7, to.X-12, to.Y+7)
	case to.X < from.X:
		return fmt.Sprintf("%d,%d %d,%d %d,%d", to.X, to.Y, to.X+12, to.Y-7, to.X+12, to.Y+7)
	case to.Y > from.Y:
		return fmt.Sprintf("%d,%d %d,%d %d,%d", to.X, to.Y, to.X-7, to.Y-12, to.X+7, to.Y-12)
	default:
		return fmt.Sprintf("%d,%d %d,%d %d,%d", to.X, to.Y, to.X-7, to.Y+12, to.X+7, to.Y+12)
	}
}

func temporalLaneScope(finding graph.FindingIndexEntry) string {
	parts := []string{finding.Repository, finding.WorkflowPath}
	if finding.RunID != nil {
		parts = append(parts, "run "+strconv.FormatInt(int64(*finding.RunID), 10))
	}
	if finding.RunAttempt != nil {
		parts = append(parts, "attempt "+strconv.FormatUint(uint64(*finding.RunAttempt), 10))
	}
	if finding.JobID != nil {
		parts = append(parts, "job "+strconv.FormatInt(int64(*finding.JobID), 10))
	}
	return strings.Join(parts, " · ")
}

func temporalLaneDescription(finding graph.FindingIndexEntry) string {
	parts := []string{
		"Canonical finding " + string(finding.State), "provenance " + string(finding.ProvenanceLevel),
		"repository " + finding.Repository, "workflow " + finding.WorkflowPath, "indicator " + finding.IndicatorID,
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
	return strings.Join(parts, "; ")
}
