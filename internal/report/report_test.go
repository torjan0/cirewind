package report

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"html"
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/torjan0/cirewind/internal/graph"
	"github.com/torjan0/cirewind/internal/model"
)

func fixtureV2Case(t *testing.T, hostileLabel string) Case {
	t.Helper()
	c := fixtureCase()
	rawMaterialized := false
	c.Metadata.SchemaVersion = MetadataSchemaV2
	c.Metadata.CaseContractVersion = CaseContractV2
	c.Metadata.CaseKind = CaseKindSynthetic
	c.Metadata.RawMaterialized = &rawMaterialized
	c.Findings[0].State = string(model.ConfirmedExecuted)
	c.Findings[0].Provenance = string(model.L4Certain)
	c.Findings[0].Workflow = ".github/workflows/demo.yml"
	c.Findings[0].Conclusion = "Exact lifecycle evidence demonstrated that step execution began."
	c.Findings[0].EvidenceGaps = []string{}

	focus := c.Findings[0].FindingRevisionID
	evidenceID := c.Findings[0].EvidenceIDs[0]
	runID := model.WorkflowRunID(c.Findings[0].RunID)
	attempt := model.RunAttempt(c.Findings[0].RunAttempt)
	jobID := model.JobID(c.Findings[0].JobID)
	index := graph.FindingIndexEntry{
		FindingRevisionID: focus, State: model.ConfirmedExecuted, ProvenanceLevel: model.L4Certain,
		Repository: c.Findings[0].Repository, WorkflowPath: ".github/workflows/demo.yml",
		RunID: &runID, RunAttempt: &attempt, JobID: &jobID,
		StepIdentity: c.Findings[0].StepIdentity, IndicatorID: c.Findings[0].IndicatorID,
		ExactIdentityKind: graph.ExactIdentityActionCommitSHA, ExactIdentity: "sha1:" + strings.Repeat("b", 40),
	}
	edge, err := graph.NewEdgeV2(
		graph.EdgeStepExecutedAction, "step", "commit", []string{evidenceID},
		"2026-08-20T00:00:00Z", graph.EvidenceClassExactObservation, "", []string{focus},
	)
	if err != nil {
		t.Fatal(err)
	}
	c.GraphV2 = graph.GraphV2{
		SchemaVersion: graph.SchemaVersionV2, CaseKind: graph.CaseKindSynthetic,
		FindingIndex: []graph.FindingIndexEntry{index},
		Nodes: []graph.NodeV2{
			{ID: "step", Type: graph.NodeStep, Label: "Run fixture/action@v1", EvidenceIDs: []string{evidenceID}, FocusFindingIDs: []string{focus}},
			{ID: "commit", Type: graph.NodeActionCommit, Label: hostileLabel, EvidenceIDs: []string{evidenceID}, FocusFindingIDs: []string{focus}},
		},
		Edges: []graph.EdgeV2{edge},
	}
	path, err := graph.BuildTemporalEvidencePath(context.Background(), c.GraphV2, graph.PathOptions{})
	if err != nil {
		t.Fatal(err)
	}
	c.TemporalPath = path
	return c
}

func fixtureV2CaseWithOmittedLane(t *testing.T) (Case, string) {
	t.Helper()
	c := fixtureV2Case(t, "affected commit")
	c.Findings = []Finding{}
	c.GraphV2 = graph.GraphV2{
		SchemaVersion: graph.SchemaVersionV2,
		CaseKind:      graph.CaseKindSynthetic,
		FindingIndex:  []graph.FindingIndexEntry{},
		Nodes:         []graph.NodeV2{},
		Edges:         []graph.EdgeV2{},
	}

	for index := range graph.DefaultPathFindingLanes + 1 {
		findingID := "find1:" + fmt.Sprintf("%064x", index+1)
		revisionID := "frev1:" + fmt.Sprintf("%064x", index+101)
		evidenceID := "ev1:" + fmt.Sprintf("%064x", index+201)
		runID := model.WorkflowRunID(index + 1)
		attempt := model.RunAttempt(1)
		jobID := model.JobID(index + 1001)
		stepID := fmt.Sprintf("step-%02d", index)
		commitID := fmt.Sprintf("commit-%02d", index)
		stepIdentity := fmt.Sprintf("1/%d/1/%d/step:1/MAIN/1", runID, jobID)

		c.Findings = append(c.Findings, Finding{
			FindingID: findingID, FindingRevisionID: revisionID,
			IncidentID: "SYNTH", IndicatorID: "bounded-indicator",
			Repository: "fixture/repository", Workflow: ".github/workflows/bounded.yml",
			RunID: int64(runID), RunAttempt: int(attempt), JobID: int64(jobID), StepIdentity: stepIdentity,
			State: string(model.ConfirmedExecuted), Provenance: string(model.L4Certain),
			Conclusion:  "Exact lifecycle evidence demonstrated that step execution began.",
			EvidenceIDs: []string{evidenceID}, EvidenceGaps: []string{}, CollectionCoverage: []string{},
		})
		c.GraphV2.FindingIndex = append(c.GraphV2.FindingIndex, graph.FindingIndexEntry{
			FindingRevisionID: revisionID, State: model.ConfirmedExecuted, ProvenanceLevel: model.L4Certain,
			Repository: "fixture/repository", WorkflowPath: ".github/workflows/bounded.yml",
			RunID: &runID, RunAttempt: &attempt, JobID: &jobID, StepIdentity: stepIdentity,
			IndicatorID: "bounded-indicator", ExactIdentityKind: graph.ExactIdentityActionCommitSHA,
			ExactIdentity: "sha1:" + fmt.Sprintf("%040x", index+1),
		})
		c.GraphV2.Nodes = append(c.GraphV2.Nodes,
			graph.NodeV2{ID: stepID, Type: graph.NodeStep, Label: stepIdentity, EvidenceIDs: []string{evidenceID}, FocusFindingIDs: []string{revisionID}},
			graph.NodeV2{ID: commitID, Type: graph.NodeActionCommit, Label: "harmless affected commit", EvidenceIDs: []string{evidenceID}, FocusFindingIDs: []string{revisionID}},
		)
		edge, err := graph.NewEdgeV2(
			graph.EdgeStepExecutedAction, stepID, commitID, []string{evidenceID},
			"2026-08-20T00:00:00Z", graph.EvidenceClassExactObservation, "", []string{revisionID},
		)
		if err != nil {
			t.Fatal(err)
		}
		c.GraphV2.Edges = append(c.GraphV2.Edges, edge)
	}

	path, err := graph.BuildTemporalEvidencePath(context.Background(), c.GraphV2, graph.PathOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if path.Counts.SelectedFindings != graph.DefaultPathFindingLanes || path.Counts.OmittedFindings != 1 {
		t.Fatalf("bounded fixture counts=%+v", path.Counts)
	}
	c.TemporalPath = path
	selected := make(map[string]bool, len(path.Lanes))
	for _, lane := range path.Lanes {
		selected[lane.Finding.FindingRevisionID] = true
	}
	for _, finding := range c.Findings {
		if !selected[finding.FindingRevisionID] {
			return c, finding.FindingRevisionID
		}
	}
	t.Fatal("bounded fixture lacks its omitted finding")
	return Case{}, ""
}

func TestV2CaseRejectsFindingIndexParityDrift(t *testing.T) {
	t.Parallel()
	otherRevision := "frev1:" + strings.Repeat("9", 64)
	otherRunID := model.WorkflowRunID(2)
	otherAttempt := model.RunAttempt(2)
	otherJobID := model.JobID(3)
	tests := []struct {
		name   string
		mutate func(*Case)
	}{
		{name: "revision", mutate: func(c *Case) { c.GraphV2.FindingIndex[0].FindingRevisionID = otherRevision }},
		{name: "state", mutate: func(c *Case) { c.GraphV2.FindingIndex[0].State = model.ConfirmedDownloaded }},
		{name: "provenance", mutate: func(c *Case) { c.GraphV2.FindingIndex[0].ProvenanceLevel = model.L3Strong }},
		{name: "repository", mutate: func(c *Case) { c.GraphV2.FindingIndex[0].Repository = "fixture/other" }},
		{name: "workflow", mutate: func(c *Case) { c.GraphV2.FindingIndex[0].WorkflowPath = ".github/workflows/other.yml" }},
		{name: "run ID", mutate: func(c *Case) { c.GraphV2.FindingIndex[0].RunID = &otherRunID }},
		{name: "run attempt", mutate: func(c *Case) { c.GraphV2.FindingIndex[0].RunAttempt = &otherAttempt }},
		{name: "job ID", mutate: func(c *Case) { c.GraphV2.FindingIndex[0].JobID = &otherJobID }},
		{name: "step identity", mutate: func(c *Case) { c.GraphV2.FindingIndex[0].StepIdentity = "1/1/1/2/step:2/MAIN/1" }},
		{name: "indicator", mutate: func(c *Case) { c.GraphV2.FindingIndex[0].IndicatorID = "other-indicator" }},
		{name: "evidence gap reason", mutate: func(c *Case) { c.GraphV2.FindingIndex[0].EvidenceGapReason = "different retained-evidence gap" }},
		{name: "missing", mutate: func(c *Case) { c.GraphV2.FindingIndex = []graph.FindingIndexEntry{} }},
		{name: "extra", mutate: func(c *Case) {
			extra := c.GraphV2.FindingIndex[0]
			extra.FindingRevisionID = otherRevision
			c.GraphV2.FindingIndex = append(c.GraphV2.FindingIndex, extra)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			c := fixtureV2Case(t, "affected commit")
			// Isolate the report/index contract from graph-edge focus semantics.
			c.GraphV2.Nodes = []graph.NodeV2{}
			c.GraphV2.Edges = []graph.EdgeV2{}
			c.TemporalPath = graph.TemporalEvidencePath{}
			test.mutate(&c)
			if err := c.NormalizeAndValidate(); err == nil || !strings.Contains(err.Error(), "finding-index parity") {
				t.Fatalf("NormalizeAndValidate error=%v, want finding-index parity rejection", err)
			}
		})
	}
}

func fixtureCase() Case {
	revisionID := "frev1:" + strings.Repeat("2", 64)
	evidenceID := "ev1:" + strings.Repeat("4", 64)
	return Case{Metadata: Metadata{CaseID: "case-1", Mode: "replay", IncidentID: "SYNTH", IncidentPackVersion: "1.0.0", CanonicalPackSHA256: strings.Repeat("a", 64), SourcePackSHA256: strings.Repeat("b", 64), EngineVersion: "test", AnalysisTime: "2026-08-20T00:00:00Z", LimitPolicy: "default", Coverage: Coverage{Partial: true, RepositoriesRequested: 1, RepositoriesAccessible: 1, RunsEnumerated: 1, AttemptsEnumerated: 1, JobsEnumerated: 1, LogsMissing: 1, IncompleteEvidence: []string{"<script>alert(1)</script>"}}}, Findings: []Finding{{FindingID: "find1:" + strings.Repeat("1", 64), FindingRevisionID: revisionID, IncidentID: "SYNTH", IndicatorID: "i", Repository: "=hostile/repo", RunID: 1, RunAttempt: 1, JobID: 2, StepIdentity: "</td><script>alert(1)</script>", State: "UNKNOWN_EVIDENCE_GAP", Provenance: "L0_UNKNOWN", Conclusion: "No retained logs != no compromise <img src=x onerror=alert(1)>", EvidenceIDs: []string{evidenceID}, EvidenceGaps: []string{"logs missing"}, CollectionCoverage: []string{"cova1:" + strings.Repeat("3", 64)}}}, Graph: graph.Graph{Nodes: []graph.Node{{ID: "finding", Type: graph.NodeFinding, Label: "<script>", EvidenceIDs: []string{evidenceID}, FocusFindingIDs: []string{revisionID}}, {ID: "evidence", Type: graph.NodeEvidenceObject, Label: evidenceID, EvidenceIDs: []string{evidenceID}, FocusFindingIDs: []string{revisionID}}}, Edges: []graph.Edge{{ID: "edge", Type: graph.EdgeSupportedByEvidence, Source: "finding", Target: "evidence", EvidenceIDs: []string{evidenceID}, FocusFindingIDs: []string{revisionID}}}}}
}

func TestV2SummaryClassificationAndCoveragePrecedeFindings(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		kind CaseKind
		want string
	}{
		{
			name: "synthetic",
			kind: CaseKindSynthetic,
			want: "SYNTHETIC DEMONSTRATION: this case contains harmless fixture evidence, not a real incident or collected organization result.",
		},
		{
			name: "collected",
			kind: CaseKindCollected,
			want: "COLLECTED CASE: this case was derived from collected GitHub evidence; conclusions remain bounded by recorded collection coverage.",
		},
		{
			name: "mixed",
			kind: CaseKindMixed,
			want: "MIXED-PROVENANCE CASE: this case combines collected and synthetic or otherwise mixed source provenance; review provenance before operational use.",
		},
		{
			name: "unknown",
			kind: CaseKindUnknown,
			want: "UNKNOWN CASE CLASSIFICATION: source provenance was not sufficient to classify this case as synthetic, collected, or mixed.",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := fixtureV2Case(t, "affected commit")
			c.Metadata.CaseKind = tc.kind
			c.GraphV2.CaseKind = graph.CaseKind(tc.kind)
			c.TemporalPath.CaseKind = graph.CaseKind(tc.kind)
			var output bytes.Buffer
			if err := WriteSummaryMarkdown(&output, c); err != nil {
				t.Fatal(err)
			}
			markdown := output.String()
			classification := strings.Index(markdown, tc.want)
			partial := strings.Index(markdown, "PARTIAL COVERAGE: some material evidence is unavailable. Totals and conclusions are limited to retained evidence.")
			findings := strings.Index(markdown, "## Finding summary")
			if classification < 0 || partial < 0 || findings < 0 || classification >= findings || partial >= findings {
				t.Fatalf("classification/coverage do not precede findings: classification=%d partial=%d findings=%d\n%s", classification, partial, findings, markdown)
			}
			if tc.kind == CaseKindUnknown && (!strings.Contains(markdown, "not sufficient to classify") || strings.Contains(markdown, "UNKNOWN CASE CLASSIFICATION: this is a collected case")) {
				t.Fatalf("unknown classification is not conservative:\n%s", markdown)
			}
		})
	}
}

func TestV1SummaryMarkdownByteContract(t *testing.T) {
	t.Parallel()
	var output bytes.Buffer
	if err := WriteSummaryMarkdown(&output, fixtureCase()); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(output.Bytes())
	const wantSHA256 = "7a4e7b9358c4286ef12182c70fd25205fda2d840112b6957f66c86410bc5a896"
	if got := fmt.Sprintf("%x", digest); got != wantSHA256 {
		t.Fatalf("v0.1 summary byte contract sha256=%s", got)
	}
}

type temporalSignature struct {
	Schema      string
	Width       string
	Height      string
	ViewBox     string
	FindingIDs  []string
	Nodes       []string
	Edges       []string
	Notices     []projectionNoticeSignature
	EvidenceKey []string
}

type projectionNoticeSignature struct {
	Relationship string
	Description  string
	VisualText   string
}

func inlineSVGFragment(document []byte) ([]byte, error) {
	start := bytes.Index(document, []byte("<svg "))
	if start < 0 {
		return nil, errors.New("inline SVG start is absent")
	}
	end := bytes.Index(document[start:], []byte("</svg>"))
	if end < 0 {
		return nil, errors.New("inline SVG end is absent")
	}
	return document[start : start+end+len("</svg>")], nil
}

func temporalSVGSignature(data []byte) (temporalSignature, error) {
	var result temporalSignature
	var notice *projectionNoticeSignature
	var noticeElement string
	noticeDepth := 0
	decoder := xml.NewDecoder(bytes.NewReader(data))
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			return result, nil
		}
		if err != nil {
			return temporalSignature{}, err
		}
		switch value := token.(type) {
		case xml.StartElement:
			attributes := make(map[string]string, len(value.Attr))
			for _, attribute := range value.Attr {
				attributes[attribute.Name.Local] = attribute.Value
			}
			if value.Name.Local == "svg" {
				result.Schema = attributes["data-cirewind-schema"]
				result.Width = attributes["width"]
				result.Height = attributes["height"]
				result.ViewBox = attributes["viewBox"]
			}
			if finding := attributes["data-finding-revision"]; finding != "" {
				result.FindingIDs = append(result.FindingIDs, finding)
			}
			if nodeID := attributes["data-node-id"]; nodeID != "" {
				result.Nodes = append(result.Nodes, strings.Join([]string{
					nodeID, attributes["data-node-type"], strings.Join(strings.Fields(attributes["data-finding-revisions"]), " "),
				}, "\x00"))
			}
			if edgeID := attributes["data-edge-id"]; edgeID != "" {
				result.Edges = append(result.Edges, strings.Join([]string{
					edgeID, attributes["data-edge-type"], attributes["data-evidence-class"], strings.Join(strings.Fields(attributes["data-evidence-refs"]), " "),
				}, "\x00"))
			}
			if notice != nil {
				noticeDepth++
			} else if value.Name.Local == "g" && attributes["data-projection-notice"] == "true" {
				notice = &projectionNoticeSignature{Relationship: attributes["data-relationship"]}
				noticeDepth = 1
			}
			if notice != nil && (value.Name.Local == "desc" || value.Name.Local == "text") {
				noticeElement = value.Name.Local
			}
		case xml.CharData:
			text := strings.TrimSpace(string(value))
			if notice != nil && text != "" {
				switch noticeElement {
				case "desc":
					notice.Description += text
				case "text":
					notice.VisualText = text
				}
			}
			if strings.HasPrefix(text, "E") && strings.Contains(text, " · ev1:") {
				result.EvidenceKey = append(result.EvidenceKey, text)
			}
		case xml.EndElement:
			if notice == nil {
				continue
			}
			if value.Name.Local == noticeElement {
				noticeElement = ""
			}
			noticeDepth--
			if noticeDepth == 0 {
				result.Notices = append(result.Notices, *notice)
				notice = nil
			}
		}
	}
}

func TestHTMLIsOfflineEscapedAndDeterministic(t *testing.T) {
	t.Parallel()
	var first, second bytes.Buffer
	c := fixtureCase()
	if err := WriteHTML(&first, c); err != nil {
		t.Fatal(err)
	}
	if err := WriteHTML(&second, c); err != nil {
		t.Fatal(err)
	}
	if first.String() != second.String() {
		t.Fatal("HTML is nondeterministic")
	}
	html := first.String()
	for _, bad := range []string{"<script>alert(1)</script>", "<img src=x", "http://", "https://", "unsafe-inline"} {
		if strings.Contains(html, bad) {
			t.Fatalf("HTML contains active/remote content %q", bad)
		}
	}
	if !strings.Contains(html, "Content-Security-Policy") || !strings.Contains(html, "PARTIAL COVERAGE") {
		t.Fatal("HTML lacks CSP or prominent partial coverage")
	}
	styleHash := sha256.Sum256([]byte(stylesheet))
	scriptHash := sha256.Sum256([]byte(filterScript))
	htmlHash := func(sum []byte) string {
		return strings.ReplaceAll(base64.StdEncoding.EncodeToString(sum), "+", "&#43;")
	}
	for _, required := range []string{
		"style-src &#39;sha256-" + htmlHash(styleHash[:]) + "&#39;",
		"script-src &#39;sha256-" + htmlHash(scriptHash[:]) + "&#39;",
		"<script>" + filterScript + "</script>",
		"data-repository=\"PWhvc3RpbGUvcmVwbw\"",
	} {
		if !strings.Contains(html, required) {
			t.Fatalf("HTML lacks CSP/filter contract %q", required)
		}
	}
	if strings.Contains(html, "frame-ancestors") {
		t.Fatal("HTML meta CSP contains frame-ancestors, which browsers ignore outside an HTTP response header")
	}
	for _, dangerousAPI := range []string{
		"innerHTML", "outerHTML", "document.write", "eval(", "fetch(",
		"createElement", "createElementNS", "cloneNode", "appendChild", "insertBefore",
		"replaceChildren", "insertAdjacentHTML",
	} {
		if strings.Contains(filterScript, dangerousAPI) {
			t.Fatalf("constant filter script uses dangerous API %q", dangerousAPI)
		}
	}
}

func TestReportFilterOmissionContractUsesCompleteTableAndPreRenderedLanes(t *testing.T) {
	t.Parallel()
	c, omittedRevision := fixtureV2CaseWithOmittedLane(t)
	var first, second bytes.Buffer
	if err := WriteHTML(&first, c); err != nil {
		t.Fatal(err)
	}
	if err := WriteHTML(&second, c); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.Bytes(), second.Bytes()) {
		t.Fatal("bounded report output is nondeterministic")
	}
	html := first.String()
	if got, want := strings.Count(html, `data-finding-item data-counted="true"`), len(c.Findings); got != want {
		t.Fatalf("complete findings-table rows=%d, want %d", got, want)
	}
	if got, want := strings.Count(html, `data-visual-lane="true"`), 2*c.TemporalPath.Counts.SelectedFindings; got != want {
		t.Fatalf("pre-rendered visual lane elements=%d, want %d", got, want)
	}
	omittedTableRow := `data-finding-item data-counted="true" data-revision="` + omittedRevision + `"`
	if !strings.Contains(html, omittedTableRow) {
		t.Fatal("omitted visual finding is absent from the complete findings table")
	}
	omittedVisualLane := `data-visual-lane="true" data-revision="` + omittedRevision + `"`
	if strings.Contains(html, omittedVisualLane) {
		t.Fatal("omitted finding was materialized as a filter-admissible visual lane")
	}
	shown := fmt.Sprintf(`<span id="visual-shown">%d</span>`, c.TemporalPath.Counts.SelectedFindings)
	omitted := fmt.Sprintf(`<span id="visual-omitted">%d</span>`, c.TemporalPath.Counts.OmittedFindings)
	if !strings.Contains(html, shown) || !strings.Contains(html, omitted) {
		t.Fatalf("initial visual intersection counts are absent: shown=%q omitted=%q", shown, omitted)
	}
	stateOption := `<option value="` + filterKey(string(model.ConfirmedExecuted)) + `">` + string(model.ConfirmedExecuted) + `</option>`
	if !strings.Contains(html, stateOption) {
		t.Fatal("complete findings state is unavailable to the report filter")
	}
}

func TestV2HTMLRendersEscapedDeterministicTemporalEvidencePath(t *testing.T) {
	t.Parallel()
	hostile := `</text><script>alert(1)</script><foreignObject onload="alert(2)">` + "\u001b[31m" + "\u202e"
	c := fixtureV2Case(t, hostile)
	var first, second bytes.Buffer
	if err := WriteHTML(&first, c); err != nil {
		t.Fatal(err)
	}
	if err := WriteHTML(&second, c); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.Bytes(), second.Bytes()) {
		t.Fatal("v2 temporal evidence report is nondeterministic")
	}
	html := first.String()
	for _, forbidden := range []string{
		"</text><script>alert(1)", "<foreignObject", `onload="alert(2)"`,
		"https://", "unsafe-inline", "attack path",
	} {
		if strings.Contains(strings.ToLower(html), strings.ToLower(forbidden)) {
			t.Fatalf("report contains forbidden active or causal content %q", forbidden)
		}
	}
	if strings.Count(html, "http://") != 1 || !strings.Contains(html, `xmlns="http://www.w3.org/2000/svg"`) {
		t.Fatal("report contains an unexpected URL beyond the fixed SVG namespace")
	}
	for _, required := range []string{
		"SYNTHETIC DEMONSTRATION", "Temporal evidence path", "data-cirewind-schema=\"cirewind.temporal-evidence-path/v1alpha1\"",
		"EXACT_OBSERVATION", "Exact observation — solid", "step execution began", "Accessible text equivalent",
		"Open the case-directory graph.svg", `role="region" aria-labelledby="temporal-path-heading"`, `id="temporal-path-text-link"`, `id="temporal-path-text-summary"`, "Skip to the accessible text equivalent",
		"<th>Indicator</th>", "Run-attempt findings", "Complete run-attempt and job finding set", c.Findings[0].EvidenceIDs[0], "img-src &#39;none&#39;",
		"&lt;/text&gt;&lt;script&gt;alert(1)&lt;/script&gt;&lt;foreignObject",
		`id="filter-status" role="status" aria-live="polite" aria-atomic="true"`,
		`id="filter-visual-status"`, `id="filter-no-match-status"`,
		"<h3>CONFIRMED_EXECUTED · L4_CERTAIN — indicator i", "<h4>Selected nodes</h4>",
	} {
		if !strings.Contains(html, required) {
			t.Fatalf("v2 report lacks %q", required)
		}
	}
	if strings.Contains(html, "\u001b") || strings.Contains(html, "\u202e") {
		t.Fatal("terminal or bidi controls survived graph sanitization")
	}
	if strings.Contains(html, "<h5>") {
		t.Fatal("accessible temporal-path fallback skips heading levels")
	}
}

func TestHTMLPresentationSanitizesBidiWithoutChangingMachineEvidence(t *testing.T) {
	t.Parallel()
	c := fixtureV2Case(t, "affected commit")
	hostileIdentity := "visible\u202e-cod\u2066-control"
	hostileText := hostileIdentity + "\x1b[2J\r\nnext"
	c.Findings[0].Repository = hostileIdentity
	c.Findings[0].Workflow = hostileIdentity
	c.Findings[0].StepIdentity = hostileIdentity
	c.Findings[0].Conclusion = hostileText
	c.Findings[0].EvidenceGaps = []string{hostileText}
	c.Metadata.Coverage.IncompleteEvidence = []string{hostileText}
	c.GraphV2.FindingIndex[0].Repository = hostileIdentity
	c.GraphV2.FindingIndex[0].WorkflowPath = hostileIdentity
	c.GraphV2.FindingIndex[0].StepIdentity = hostileIdentity
	c.GraphV2.FindingIndex[0].EvidenceGapReason = hostileText
	path, err := graph.BuildTemporalEvidencePath(context.Background(), c.GraphV2, graph.PathOptions{})
	if err != nil {
		t.Fatal(err)
	}
	c.TemporalPath = path

	var rendered bytes.Buffer
	if err := WriteHTML(&rendered, c); err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"\u202e", "\u2066", "\x1b", "\r", "\nnext"} {
		if strings.Contains(rendered.String(), forbidden) {
			t.Fatalf("HTML presentation retained hostile control %q", forbidden)
		}
	}
	if c.Findings[0].Conclusion != hostileText || c.Findings[0].Repository != hostileIdentity {
		t.Fatal("presentation sanitization changed retained finding evidence")
	}
	var machine bytes.Buffer
	if err := WriteFindingsJSON(&machine, c); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(machine.Bytes(), []byte("\u202e")) || !bytes.Contains(machine.Bytes(), []byte("\u2066")) {
		t.Fatal("machine-readable findings did not retain the original Unicode evidence")
	}
}

func TestInlineTemporalScopeUsesFixedWideTextGeometry(t *testing.T) {
	t.Parallel()
	c := fixtureV2Case(t, strings.Repeat("界", 300))
	wide := strings.Repeat("界", 300)
	c.Findings[0].Repository = wide
	c.Findings[0].Workflow = wide
	c.GraphV2.FindingIndex[0].Repository = wide
	c.GraphV2.FindingIndex[0].WorkflowPath = wide
	path, err := graph.BuildTemporalEvidencePath(context.Background(), c.GraphV2, graph.PathOptions{})
	if err != nil {
		t.Fatal(err)
	}
	c.TemporalPath = path
	view := buildTemporalPathView(path)
	if len(view.Lanes) != 1 || len([]rune(view.Lanes[0].Scope)) > 160 || !strings.HasSuffix(view.Lanes[0].Scope, "…") {
		t.Fatalf("visible scope is not bounded for fixed geometry: %q", view.Lanes[0].Scope)
	}
	if view.Lanes[0].FullScope == view.Lanes[0].Scope || !strings.Contains(view.Lanes[0].FullScope, wide) {
		t.Fatal("accessible text equivalent did not retain the bounded full presentation scope")
	}
	var first, second bytes.Buffer
	if err := WriteHTML(&first, c); err != nil {
		t.Fatal(err)
	}
	if err := WriteHTML(&second, c); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.Bytes(), second.Bytes()) {
		t.Fatal("wide-label HTML presentation is nondeterministic")
	}
}

func TestInlineAndStandaloneTemporalPathsShareIdentitiesEvidenceAndOmissions(t *testing.T) {
	t.Parallel()
	c := fixtureV2Case(t, "affected commit")
	path, standalone, err := graph.RenderGraphSVG(context.Background(), c.GraphV2, graph.PathOptions{})
	if err != nil {
		t.Fatal(err)
	}
	c.TemporalPath = path
	var report bytes.Buffer
	if err := WriteHTML(&report, c); err != nil {
		t.Fatal(err)
	}
	inline, err := inlineSVGFragment(report.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	want, err := temporalSVGSignature(standalone)
	if err != nil {
		t.Fatalf("standalone SVG: %v", err)
	}
	got, err := temporalSVGSignature(inline)
	if err != nil {
		t.Fatalf("inline SVG: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("inline and standalone temporal paths diverged\ninline: %#v\nstandalone: %#v", got, want)
	}
	omission := buildTemporalPathView(path).OmissionText
	if !bytes.Contains(standalone, []byte(omission)) || !bytes.Contains(inline, []byte(omission)) {
		t.Fatalf("inline or standalone SVG lacks canonical omission text %q", omission)
	}
}

func TestInlineAndStandaloneProjectionNoticesBoundVisualTextAndPreserveEvidence(t *testing.T) {
	t.Parallel()
	c := fixtureV2Case(t, "affected commit")
	evidenceIDs := make([]string, 12)
	for index := range evidenceIDs {
		evidenceIDs[index] = "ev1:" + fmt.Sprintf("%064x", index+1)
	}
	c.GraphV2.ProjectionNotices = []graph.ProjectionNotice{{
		Code:              graph.ProjectionNoticeUnclassifiableLegacyBasis,
		FindingRevisionID: c.Findings[0].FindingRevisionID,
		Relationship:      graph.EdgeHadTokenPermission,
		EvidenceIDs:       evidenceIDs,
	}}

	path, standalone, err := graph.RenderGraphSVG(context.Background(), c.GraphV2, graph.PathOptions{})
	if err != nil {
		t.Fatal(err)
	}
	c.TemporalPath = path
	var rendered, repeated bytes.Buffer
	if err := WriteHTML(&rendered, c); err != nil {
		t.Fatal(err)
	}
	if err := WriteHTML(&repeated, c); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rendered.Bytes(), repeated.Bytes()) {
		t.Fatal("report with a projection notice is nondeterministic")
	}

	inline, err := inlineSVGFragment(rendered.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	standaloneSignature, err := temporalSVGSignature(standalone)
	if err != nil {
		t.Fatal(err)
	}
	inlineSignature, err := temporalSVGSignature(inline)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(inlineSignature, standaloneSignature) {
		t.Fatalf("inline and standalone projection-notice presentations diverged\ninline: %#v\nstandalone: %#v", inlineSignature, standaloneSignature)
	}
	if len(standaloneSignature.Notices) != 1 {
		t.Fatalf("projection notice count=%d, want 1", len(standaloneSignature.Notices))
	}
	notice := standaloneSignature.Notices[0]
	wantFull, wantVisible := graph.PresentProjectionNotice(path.Lanes[0].Notices[0], path.EvidenceKey)
	if notice.Relationship != string(graph.EdgeHadTokenPermission) || notice.Description != wantFull || notice.VisualText != wantVisible {
		t.Fatalf("projection notice lost its typed/full/visual contract: %#v", notice)
	}
	if !strings.Contains(notice.VisualText, "E001, E002, E003, E004, E005 · +7 more") || strings.Contains(notice.VisualText, "E006") {
		t.Fatalf("projection-notice visual references are not bounded: %q", notice.VisualText)
	}
	for _, evidenceID := range evidenceIDs {
		if !strings.Contains(notice.Description, evidenceID) {
			t.Fatalf("projection-notice description lost evidence association %q", evidenceID)
		}
	}
	unescapedReport := html.UnescapeString(rendered.String())
	if strings.Count(unescapedReport, wantFull) < 2 {
		t.Fatal("report lacks a full projection-notice description and accessible fallback association")
	}
}

func TestCurrentReferenceReportDoesNotDescribePresentDaySnapshotAsHistorical(t *testing.T) {
	t.Parallel()
	c := fixtureV2Case(t, "unused")
	focus := c.Findings[0].FindingRevisionID
	evidenceID := c.Findings[0].EvidenceIDs[0]
	c.Findings[0].State = string(model.CurrentReferenceOnly)
	c.Findings[0].Provenance = string(model.L1Possible)
	c.Findings[0].Conclusion = "Only the present-day workflow snapshot references the indicator."
	c.Findings[0].RunID, c.Findings[0].RunAttempt, c.Findings[0].JobID = 0, 0, 0
	c.Findings[0].StepIdentity = ""
	c.GraphV2.FindingIndex = []graph.FindingIndexEntry{{
		FindingRevisionID: focus, State: model.CurrentReferenceOnly, ProvenanceLevel: model.L1Possible,
		Repository: c.Findings[0].Repository, WorkflowPath: ".github/workflows/demo.yml",
		IndicatorID: c.Findings[0].IndicatorID,
	}}
	c.GraphV2.Nodes = []graph.NodeV2{
		{ID: "workflow", Type: graph.NodeWorkflowDefinition, Label: "historical at run deadbeef", FocusFindingIDs: []string{focus}},
		{ID: "ref", Type: graph.NodeActionRef, Label: "fixture/action@v1", FocusFindingIDs: []string{focus}},
	}
	edge, err := graph.NewEdgeV2(
		graph.EdgeWorkflowDeclaredAction, "workflow", "ref", []string{evidenceID}, "",
		graph.EvidenceClassExactObservation, graph.DefinitionBasisCurrentSnapshotRule, []string{focus},
	)
	if err != nil {
		t.Fatal(err)
	}
	c.GraphV2.Edges = []graph.EdgeV2{edge}
	c.TemporalPath, _, err = graph.RenderGraphSVG(context.Background(), c.GraphV2, graph.PathOptions{})
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := WriteHTML(&output, c); err != nil {
		t.Fatal(err)
	}
	html := output.String()
	if !strings.Contains(html, "present-day workflow snapshot declared Action") {
		t.Fatal("current-only temporal path lacks explicit present-day snapshot wording")
	}
	if strings.Contains(html, "historical workflow declared Action") {
		t.Fatal("current-only temporal path was mislabeled as a historical declaration")
	}
}

func TestWriteHTMLContextHonorsCancellation(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := WriteHTMLContext(ctx, &bytes.Buffer{}, fixtureV2Case(t, "affected commit"))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("WriteHTMLContext error=%v, want context.Canceled", err)
	}
}

func TestV2HTMLRejectsUnvalidatedOrMisclassifiedTemporalPath(t *testing.T) {
	t.Parallel()
	t.Run("noncanonical relationship", func(t *testing.T) {
		c := fixtureV2Case(t, "affected commit")
		c.TemporalPath.Lanes[0].Edges[0].RelationshipText = "Action executed"
		if err := WriteHTML(&bytes.Buffer{}, c); err == nil || !strings.Contains(err.Error(), "temporal evidence path") {
			t.Fatalf("noncanonical path was not rejected: %v", err)
		}
	})
	t.Run("case classification mismatch", func(t *testing.T) {
		c := fixtureV2Case(t, "affected commit")
		c.TemporalPath.CaseKind = graph.CaseKindCollected
		if err := WriteHTML(&bytes.Buffer{}, c); err == nil || !strings.Contains(err.Error(), "classification disagrees") {
			t.Fatalf("misclassified path was not rejected: %v", err)
		}
	})
	t.Run("missing path", func(t *testing.T) {
		c := fixtureV2Case(t, "affected commit")
		c.TemporalPath = graph.TemporalEvidencePath{}
		if err := WriteHTML(&bytes.Buffer{}, c); err == nil {
			t.Fatal("missing v2 temporal path was accepted")
		}
	})
	t.Run("valid path from different graph", func(t *testing.T) {
		c := fixtureV2Case(t, "affected commit")
		c.TemporalPath.Lanes[0].Finding.IndicatorID = "different-indicator"
		if err := graph.ValidateTemporalEvidencePath(c.TemporalPath); err != nil {
			t.Fatalf("test mutation should remain independently valid: %v", err)
		}
		if err := WriteHTML(&bytes.Buffer{}, c); err == nil || !strings.Contains(err.Error(), "disagrees with the typed graph") {
			t.Fatalf("path from a different graph was not rejected: %v", err)
		}
	})
}

func TestInlineTemporalPathIsValidInertXML(t *testing.T) {
	t.Parallel()
	c := fixtureV2Case(t, `"><image href="https://host.invalid/x"><animate onbegin="alert(1)">`)
	var output bytes.Buffer
	if err := WriteHTML(&output, c); err != nil {
		t.Fatal(err)
	}
	document := output.String()
	start := strings.Index(document, "<svg ")
	if start < 0 {
		t.Fatal("inline SVG fragment is absent")
	}
	end := strings.Index(document[start:], "</svg>")
	if end < 0 {
		t.Fatal("inline SVG fragment is absent")
	}
	fragment := document[start : start+end+len("</svg>")]
	allowed := map[string]bool{
		"svg": true, "title": true, "desc": true, "rect": true, "g": true,
		"text": true, "line": true, "circle": true, "polyline": true,
		"polygon": true, "tspan": true,
	}
	decoder := xml.NewDecoder(strings.NewReader(fragment))
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("inline temporal path is not valid XML: %v", err)
		}
		startElement, ok := token.(xml.StartElement)
		if !ok {
			continue
		}
		if !allowed[startElement.Name.Local] {
			t.Fatalf("inline temporal path emitted non-allowlisted element %q", startElement.Name.Local)
		}
		for _, attribute := range startElement.Attr {
			name := strings.ToLower(attribute.Name.Local)
			value := strings.ToLower(attribute.Value)
			if strings.HasPrefix(name, "on") || name == "href" || strings.Contains(value, "url(") || strings.Contains(value, "javascript:") || strings.Contains(value, "data:") {
				t.Fatalf("inline temporal path emitted unsafe attribute %s=%q", attribute.Name.Local, attribute.Value)
			}
		}
	}
}

func TestCSVNeutralizesFormulaCells(t *testing.T) {
	t.Parallel()
	var output bytes.Buffer
	if err := WriteAffectedRunsCSV(&output, fixtureCase()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "'=hostile/repo") {
		t.Fatalf("formula cell not neutralized: %s", output.String())
	}
}

func TestInlineTemporalPathPreservesCrossoverTopologyInForcedColors(t *testing.T) {
	t.Parallel()
	if !strings.Contains(stylesheet, ".temporal-path svg{") || !strings.Contains(stylesheet, "forced-color-adjust:none") {
		t.Fatal("report stylesheet does not preserve the fixed temporal-path palette in forced-colors mode")
	}
	var output bytes.Buffer
	if err := WriteHTML(&output, fixtureV2Case(t, "affected commit")); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "data-route-underlay=\"true\"") {
		t.Fatal("inline temporal path lacks crossover underlays")
	}
}

func TestAffectedRunsCSVPreservesHeaderPrefixAndIsDeterministic(t *testing.T) {
	t.Parallel()
	c := fixtureCase()
	var first, second bytes.Buffer
	if err := WriteAffectedRunsCSV(&first, c); err != nil {
		t.Fatal(err)
	}
	if err := WriteAffectedRunsCSV(&second, c); err != nil {
		t.Fatal(err)
	}
	if first.String() != second.String() {
		t.Fatal("affected-runs CSV changed across identical writes")
	}
	rows, err := csv.NewReader(strings.NewReader(first.String())).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	wantPrefix := []string{"repository", "workflow", "run_id", "run_attempt", "job_id", "step_identity", "state", "provenance", "conclusion", "evidence_ids", "evidence_gaps"}
	wantSuffix := []string{"finding_context", "indicator_id", "finding_revision_id"}
	if len(rows) != 2 || len(rows[0]) != len(wantPrefix)+len(wantSuffix) || !reflect.DeepEqual(rows[0][:len(wantPrefix)], wantPrefix) || !reflect.DeepEqual(rows[0][len(wantPrefix):], wantSuffix) {
		t.Fatalf("affected-runs CSV header=%v", rows)
	}
	if len(rows[1]) != len(rows[0]) || rows[1][len(wantPrefix)] != "run-scoped-finding" || rows[1][len(wantPrefix)+1] != c.Findings[0].IndicatorID || rows[1][len(wantPrefix)+2] != c.Findings[0].FindingRevisionID {
		t.Fatalf("affected-runs CSV row schema/context=%v", rows[1])
	}
}

func TestAffectedRunsCSVLabelsKnownGoodComparisonAndCurrentReference(t *testing.T) {
	t.Parallel()
	c := fixtureV2Case(t, "affected commit")
	c.GraphV2.Nodes = []graph.NodeV2{}
	c.GraphV2.Edges = []graph.EdgeV2{}
	c.TemporalPath = graph.TemporalEvidencePath{}

	comparison := c.Findings[0]
	comparison.FindingID = "find1:" + strings.Repeat("5", 64)
	comparison.FindingRevisionID = "frev1:" + strings.Repeat("6", 64)
	comparison.RunAttempt = 2
	comparison.JobID = 3
	comparison.StepIdentity = ""
	comparison.State = string(model.NoMatchConfirmed)
	comparison.Conclusion = "Exact runtime identity was known-good within closed retained coverage."
	comparison.EvidenceIDs = []string{"ev1:" + strings.Repeat("7", 64)}
	comparison.CollectionCoverage = []string{"cova1:" + strings.Repeat("8", 64)}
	comparison.CredentialExposure = []Exposure{}
	comparison.ResourceExposure = []Exposure{}
	c.Findings = append(c.Findings, comparison)

	comparisonIndex := c.GraphV2.FindingIndex[0]
	comparisonIndex.FindingRevisionID = comparison.FindingRevisionID
	comparisonIndex.State = model.NoMatchConfirmed
	secondAttempt, comparisonJob := model.RunAttempt(2), model.JobID(3)
	comparisonIndex.RunAttempt = &secondAttempt
	comparisonIndex.JobID = &comparisonJob
	comparisonIndex.StepIdentity = ""
	comparisonIndex.ExactIdentity = "sha1:" + strings.Repeat("c", 40)
	comparisonIndex.ExactKnownGood = true
	comparisonIndex.CoverageClosed = true
	c.GraphV2.FindingIndex = append(c.GraphV2.FindingIndex, comparisonIndex)

	current := c.Findings[0]
	current.FindingID = "find1:" + strings.Repeat("9", 64)
	current.FindingRevisionID = "frev1:" + strings.Repeat("a", 64)
	current.Workflow = ".github/workflows/current.yml"
	current.RunID, current.RunAttempt, current.JobID = 0, 0, 0
	current.StepIdentity = ""
	current.State = string(model.CurrentReferenceOnly)
	current.Provenance = string(model.L1Possible)
	current.Conclusion = "Only present-day repository configuration references the component."
	current.CredentialExposure = []Exposure{}
	current.ResourceExposure = []Exposure{}
	c.Findings = append(c.Findings, current)

	currentIndex := c.GraphV2.FindingIndex[0]
	currentIndex.FindingRevisionID = current.FindingRevisionID
	currentIndex.State = model.CurrentReferenceOnly
	currentIndex.ProvenanceLevel = model.L1Possible
	currentIndex.WorkflowPath = current.Workflow
	currentIndex.RunID, currentIndex.RunAttempt, currentIndex.JobID = nil, nil, nil
	currentIndex.StepIdentity = ""
	c.GraphV2.FindingIndex = append(c.GraphV2.FindingIndex, currentIndex)

	var output bytes.Buffer
	if err := WriteAffectedRunsCSV(&output, c); err != nil {
		t.Fatal(err)
	}
	rows, err := csv.NewReader(strings.NewReader(output.String())).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 4 {
		t.Fatalf("affected-runs CSV row count=%d, want 4: %v", len(rows), rows)
	}
	contextColumn := 11
	contexts := make(map[string][]string, len(rows)-1)
	for _, row := range rows[1:] {
		contexts[row[6]] = row
	}
	if row := contexts[string(model.NoMatchConfirmed)]; row == nil || row[contextColumn] != "known-good-rerun-comparison-not-affected-run" {
		t.Fatalf("known-good comparison CSV context=%v", row)
	}
	if row := contexts[string(model.CurrentReferenceOnly)]; row == nil || row[2] != "" || row[3] != "" || row[4] != "" || row[contextColumn] != "current-reference-only-no-historical-run" {
		t.Fatalf("current-reference CSV identity/context=%v", row)
	}
	if row := contexts[string(model.ConfirmedExecuted)]; row == nil || row[contextColumn] != "run-scoped-finding" {
		t.Fatalf("run-scoped CSV context=%v", row)
	}
}

func TestAffectedRunsCSVContextUsesClosedNonOverlappingValues(t *testing.T) {
	t.Parallel()
	comparisonRevision := "frev1:" + strings.Repeat("e", 64)
	tests := []struct {
		name       string
		finding    Finding
		comparison map[string]bool
		want       string
	}{
		{name: "known-good comparison", finding: Finding{FindingRevisionID: comparisonRevision, State: string(model.NoMatchConfirmed), RunID: 1}, comparison: map[string]bool{comparisonRevision: true}, want: "known-good-rerun-comparison-not-affected-run"},
		{name: "scope-closed no-match", finding: Finding{State: string(model.NoMatchConfirmed), RunID: 1}, comparison: map[string]bool{}, want: "scope-closed-no-match-not-affected-run"},
		{name: "current-only", finding: Finding{State: string(model.CurrentReferenceOnly)}, comparison: map[string]bool{}, want: "current-reference-only-no-historical-run"},
		{name: "no run identity", finding: Finding{State: string(model.UnknownEvidenceGap)}, comparison: map[string]bool{}, want: "finding-without-run-identity"},
		{name: "run scoped", finding: Finding{State: string(model.ConfirmedExecuted), RunID: 1}, comparison: map[string]bool{}, want: "run-scoped-finding"},
	}
	seen := make(map[string]bool, len(tests))
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := affectedRunsCSVContext(test.finding, test.comparison)
			if got != test.want {
				t.Fatalf("context=%q, want %q", got, test.want)
			}
			if seen[got] {
				t.Fatalf("context value %q is not unique", got)
			}
			seen[got] = true
		})
	}
}

func TestAffectedRunsCSVKeepsSameRunFindingsTraceablyDistinct(t *testing.T) {
	t.Parallel()
	c := fixtureCase()
	second := c.Findings[0]
	second.FindingID = "find1:" + strings.Repeat("c", 64)
	second.FindingRevisionID = "frev1:" + strings.Repeat("d", 64)
	second.IndicatorID = "second-indicator"
	c.Findings = append(c.Findings, second)

	var output bytes.Buffer
	if err := WriteAffectedRunsCSV(&output, c); err != nil {
		t.Fatal(err)
	}
	rows, err := csv.NewReader(strings.NewReader(output.String())).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 3 || reflect.DeepEqual(rows[1], rows[2]) {
		t.Fatalf("same-run findings were not distinct: %v", rows)
	}
	if rows[1][12] == rows[2][12] || rows[1][13] == rows[2][13] {
		t.Fatalf("same-run finding identities collapsed: %v", rows)
	}
}

func TestV2PresentationOmitsAbsentJobIdentity(t *testing.T) {
	t.Parallel()
	c := fixtureV2Case(t, "called workflow")
	c.Findings[0].State = string(model.ConfirmedCalledWorkflow)
	c.Findings[0].JobID = 0
	c.Findings[0].StepIdentity = ""
	c.Findings[0].Conclusion = "GitHub recorded the exact reusable-workflow identity for this run attempt."
	c.GraphV2.FindingIndex[0].State = model.ConfirmedCalledWorkflow
	c.GraphV2.FindingIndex[0].JobID = nil
	c.GraphV2.FindingIndex[0].StepIdentity = ""
	c.GraphV2.FindingIndex[0].ExactIdentityKind = graph.ExactIdentityCalledWorkflowSHA
	c.GraphV2.Nodes = []graph.NodeV2{}
	c.GraphV2.Edges = []graph.EdgeV2{}
	path, err := graph.BuildTemporalEvidencePath(context.Background(), c.GraphV2, graph.PathOptions{})
	if err != nil {
		t.Fatal(err)
	}
	c.TemporalPath = path

	var document bytes.Buffer
	if err := WriteHTML(&document, c); err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"job=0", "job 0", "step="} {
		if strings.Contains(document.String(), forbidden) {
			t.Fatalf("absent execution identity rendered as a value %q", forbidden)
		}
	}
	if !strings.Contains(document.String(), "run=1 attempt=1") {
		t.Fatal("present run-attempt identity was omitted")
	}

	var csvOutput bytes.Buffer
	if err := WriteAffectedRunsCSV(&csvOutput, c); err != nil {
		t.Fatal(err)
	}
	rows, err := csv.NewReader(strings.NewReader(csvOutput.String())).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || rows[1][2] != "1" || rows[1][3] != "1" || rows[1][4] != "" || rows[1][5] != "" {
		t.Fatalf("optional CSV execution identity=%v", rows)
	}
}

func TestV2ReportDeduplicatesOnlyLiterallySharedGuidance(t *testing.T) {
	t.Parallel()
	common := "Review every mutable reference covered by the incident pack."
	rotation := "Rotate only credentials supported by the executed finding."
	findings := []Finding{
		{RemediationGuidance: []string{common, rotation}},
		{RemediationGuidance: []string{common}},
	}
	sharedGuidance := sharedRemediationGuidance(findings)
	if !reflect.DeepEqual(sharedGuidance, []string{common}) {
		t.Fatalf("shared guidance=%v", sharedGuidance)
	}
	if residual := subtractStrings(findings[0].RemediationGuidance, sharedGuidance); !reflect.DeepEqual(residual, []string{rotation}) {
		t.Fatalf("finding residual guidance=%v", residual)
	}

	c := fixtureV2Case(t, "affected commit")
	c.Findings[0].RemediationGuidance = []string{common}
	original := append([]string(nil), c.Findings[0].RemediationGuidance...)
	var document bytes.Buffer
	if err := WriteHTML(&document, c); err != nil {
		t.Fatal(err)
	}
	html := document.String()
	if strings.Count(html, common) != 1 || strings.Contains(html, "guidance repeated across findings") || !strings.Contains(html, "Incident-pack guidance associated with this finding") {
		t.Fatalf("single-finding guidance was incorrectly promoted:\n%s", html)
	}
	if !reflect.DeepEqual(c.Findings[0].RemediationGuidance, original) {
		t.Fatal("presentation partition mutated canonical remediation guidance")
	}
}

func TestV2ExecutiveCountsAndFixedLightPalette(t *testing.T) {
	t.Parallel()
	c := fixtureV2Case(t, "affected commit")
	var document bytes.Buffer
	if err := WriteHTML(&document, c); err != nil {
		t.Fatal(err)
	}
	html := document.String()
	edgeCount := 0
	for _, lane := range c.TemporalPath.Lanes {
		edgeCount += len(lane.Edges)
	}
	if got := strings.Count(html, `data-route-underlay="true"`); got != edgeCount {
		t.Fatalf("inline route underlays=%d, want one per selected edge (%d)", got, edgeCount)
	}
	if got := strings.Count(html, `stroke-linejoin="round" stroke-linecap="butt" aria-hidden="true" data-route-underlay="true"`); got != edgeCount {
		t.Fatalf("inline bounded-junction underlays=%d, want %d", got, edgeCount)
	}
	for _, required := range []string{
		"<strong>1</strong> total finding", "<strong>1</strong> confirmed execution", "<strong>0</strong> contradictory-evidence findings", "<strong>0</strong> scope-closed no-match findings",
		"color-scheme:only light", "color:#111827", "background:#FFFFFF",
		"Retained attempt/job log coverage totals retrieved/missing",
		`id="visual-shown-label"`, `id="visual-omitted-label"`,
	} {
		if !strings.Contains(html, required) {
			t.Fatalf("v2 report lacks %q", required)
		}
	}
	if strings.Contains(html, "1 confirmed executions") || strings.Contains(html, "1 findings visible") {
		t.Fatal("singular report count used plural grammar")
	}
}

func TestCountLabelUsesSingularOnlyForOne(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		count int
		want  string
	}{{0, "findings"}, {1, "finding"}, {2, "findings"}} {
		if got := countLabel(test.count, "finding", "findings"); got != test.want {
			t.Fatalf("countLabel(%d)=%q, want %q", test.count, got, test.want)
		}
	}
}

func TestKnownGoodComparisonLabelUsesNarrowRerunPredicate(t *testing.T) {
	t.Parallel()
	runID := model.WorkflowRunID(42)
	first, second := model.RunAttempt(1), model.RunAttempt(2)
	anchor := graph.FindingIndexEntry{
		FindingRevisionID: "anchor", State: model.ConfirmedExecuted,
		Repository: "fixture/repository", WorkflowPath: ".github/workflows/demo.yml",
		RunID: &runID, RunAttempt: &first, IndicatorID: "indicator",
		ExactIdentityKind: graph.ExactIdentityActionCommitSHA, ExactIdentity: "sha1:" + strings.Repeat("a", 40),
	}
	comparison := anchor
	comparison.FindingRevisionID = "comparison"
	comparison.State = model.NoMatchConfirmed
	comparison.RunAttempt = &second
	comparison.ExactIdentity = "sha1:" + strings.Repeat("b", 40)
	comparison.ExactKnownGood = true
	comparison.CoverageClosed = true

	identified := knownGoodComparisonRevisions([]graph.FindingIndexEntry{anchor, comparison})
	if !identified[comparison.FindingRevisionID] {
		t.Fatal("exact coverage-closed rerun was not identified as comparison context")
	}

	generic := comparison
	generic.FindingRevisionID = "generic-no-match"
	generic.ExactKnownGood = false
	identified = knownGoodComparisonRevisions([]graph.FindingIndexEntry{anchor, generic})
	if identified[generic.FindingRevisionID] {
		t.Fatal("generic NO_MATCH_CONFIRMED was mislabeled as a known-good rerun comparison")
	}
	views, _ := buildFindingViews([]Finding{{FindingRevisionID: generic.FindingRevisionID, State: string(model.NoMatchConfirmed)}}, nil, identified)
	if len(views) != 1 || views[0].ComparisonContext {
		t.Fatal("generic NO_MATCH_CONFIRMED presentation acquired comparison language")
	}
}

func TestGenericNoMatchReportDoesNotInventRerunComparison(t *testing.T) {
	t.Parallel()
	c := fixtureV2Case(t, "unused")
	c.Findings[0].State = string(model.NoMatchConfirmed)
	c.Findings[0].Conclusion = "All bounded retained evidence for this scope was examined and no incident match was found."
	c.GraphV2.FindingIndex[0].State = model.NoMatchConfirmed
	c.GraphV2.FindingIndex[0].ExactKnownGood = false
	c.GraphV2.FindingIndex[0].CoverageClosed = true
	c.GraphV2.Nodes = []graph.NodeV2{}
	c.GraphV2.Edges = []graph.EdgeV2{}
	var err error
	c.TemporalPath, err = graph.BuildTemporalEvidencePath(context.Background(), c.GraphV2, graph.PathOptions{})
	if err != nil {
		t.Fatal(err)
	}
	var htmlOutput bytes.Buffer
	if err := WriteHTML(&htmlOutput, c); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(htmlOutput.String(), "Comparison context") || strings.Contains(htmlOutput.String(), "known-good rerun") {
		t.Fatal("generic NO_MATCH_CONFIRMED acquired known-good rerun language")
	}
	if !strings.Contains(htmlOutput.String(), "scope-closed no-match finding") {
		t.Fatal("generic NO_MATCH_CONFIRMED was omitted from the neutral summary")
	}
	var markdown bytes.Buffer
	if err := WriteSummaryMarkdown(&markdown, c); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(markdown.String(), "comparison context") || !strings.Contains(markdown.String(), "Scope-closed no-match findings: 1") {
		t.Fatalf("generic NO_MATCH_CONFIRMED Markdown language is inaccurate:\n%s", markdown.String())
	}
}

func TestFindingNeedsEvidenceOrGap(t *testing.T) {
	t.Parallel()
	c := fixtureCase()
	c.Findings[0].EvidenceGaps = nil
	if err := c.NormalizeAndValidate(); err == nil {
		t.Fatal("unsupported finding accepted")
	}
}

func TestReportRejectsExposureContextWithoutConfirmedExecution(t *testing.T) {
	t.Parallel()
	t.Run("credential", func(t *testing.T) {
		c := fixtureV2Case(t, "affected commit")
		c.Findings[0].State = string(model.ConfirmedDownloaded)
		c.Findings[0].CredentialExposure = []Exposure{{
			Kind: string(model.ExposureGitHubTokenPermission), Capability: "contents:write", Basis: string(model.ExposureBasisRuntimeObserved),
			Conclusion: "The permission was observed; use was not established.", EvidenceIDs: append([]string(nil), c.Findings[0].EvidenceIDs...),
		}}
		if err := c.NormalizeAndValidate(); err == nil || !strings.Contains(err.Error(), "requires a separate CONFIRMED_EXECUTED proposition") {
			t.Fatalf("non-executed credential context was accepted: %v", err)
		}
	})

	t.Run("resource", func(t *testing.T) {
		c := fixtureV2Case(t, "affected commit")
		c.Findings[0].State = string(model.RunInWindowMutableRef)
		c.Findings[0].ResourceExposure = []Exposure{{
			Kind: string(model.ResourceDeployment), Name: "synthetic-deployment", Basis: string(model.CorrelationObservedAfter),
			Conclusion: "Observed later; causation was not established.", EvidenceIDs: append([]string(nil), c.Findings[0].EvidenceIDs...),
		}}
		if err := c.NormalizeAndValidate(); err == nil || !strings.Contains(err.Error(), "requires a separate CONFIRMED_EXECUTED proposition") {
			t.Fatalf("non-executed resource context was accepted: %v", err)
		}
	})
}

func TestFindingsJSONIncludesExplicitEmptyForensicFields(t *testing.T) {
	t.Parallel()
	c := fixtureCase()
	c.Findings[0].Assumptions = nil
	c.Findings[0].ContradictoryEvidence = nil
	c.Findings[0].CredentialExposure = nil
	c.Findings[0].ResourceExposure = nil
	c.Findings[0].RemediationGuidance = nil
	var output bytes.Buffer
	if err := WriteFindingsJSON(&output, c); err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(output.Bytes(), &document); err != nil {
		t.Fatal(err)
	}
	findings, ok := document["findings"].([]any)
	if !ok || len(findings) != 1 {
		t.Fatalf("findings document = %#v", document)
	}
	finding, ok := findings[0].(map[string]any)
	if !ok {
		t.Fatalf("finding = %#v", findings[0])
	}
	for _, field := range []string{"assumptions", "evidenceGaps", "contradictoryEvidence", "potentialCredentialExposure", "potentialResourceExposure", "remediationGuidance", "collectionCoverage"} {
		value, exists := finding[field]
		if !exists {
			t.Fatalf("required forensic field %q is absent", field)
		}
		if _, array := value.([]any); !array {
			t.Fatalf("forensic field %q is not an array: %#v", field, value)
		}
	}
}

func TestFindingsJSONUsesEmptyArrayForZeroFindings(t *testing.T) {
	t.Parallel()
	c := fixtureCase()
	c.Findings = nil
	c.Graph.Nodes = []graph.Node{}
	c.Graph.Edges = []graph.Edge{}
	var output bytes.Buffer
	if err := WriteFindingsJSON(&output, c); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), `"findings": []`) {
		t.Fatalf("zero findings did not serialize as an explicit array: %s", output.String())
	}
}

func TestCaseRejectsMultipleSelectedRevisionsForOneLogicalFinding(t *testing.T) {
	t.Parallel()
	c := fixtureCase()
	second := c.Findings[0]
	second.FindingRevisionID = "frev1:" + strings.Repeat("5", 64)
	c.Findings = append(c.Findings, second)
	if err := c.NormalizeAndValidate(); err == nil || !strings.Contains(err.Error(), "multiple finding revisions") {
		t.Fatalf("logical finding collision was not rejected: %v", err)
	}
}

func TestCountsRecognizesCanonicalWriteTokenExposureKind(t *testing.T) {
	t.Parallel()
	c := fixtureCase()
	c.Findings[0].CredentialExposure = []Exposure{{
		Kind: string(model.ExposureGitHubTokenPermission), Capability: "contents:write", Basis: "runtime-observed",
		Conclusion: "Effective permission was observed; use is not inferred.", EvidenceIDs: append([]string(nil), c.Findings[0].EvidenceIDs...),
	}}
	if got := c.Counts().WriteTokenJobs; got != 1 {
		t.Fatalf("write-token job count = %d, want 1", got)
	}
	c.Findings[0].CredentialExposure[0].Capability = "contents:read"
	if got := c.Counts().WriteTokenJobs; got != 0 {
		t.Fatalf("read-only token counted as write-capable: %d", got)
	}
}

func TestCountsDoesNotCallAJobReferenceASecretFlow(t *testing.T) {
	t.Parallel()
	c := fixtureCase()
	c.Findings[0].CredentialExposure = []Exposure{{
		Kind: string(model.ExposureSecretReferencedByJob), Name: "REFERENCED_ONLY", Basis: "historical-definition-reference",
		Conclusion: "The job definition referenced the name; passage was not established.", EvidenceIDs: append([]string(nil), c.Findings[0].EvidenceIDs...),
	}}
	if got := c.Counts().NamedSecretFlows; got != 0 {
		t.Fatalf("job-only reference counted as a secret flow: %d", got)
	}
	c.Findings[0].CredentialExposure[0].Kind = string(model.ExposureSecretPassedToStep)
	c.Findings[0].CredentialExposure[0].Basis = "historical-definition-flow"
	if got := c.Counts().NamedSecretFlows; got != 1 {
		t.Fatalf("evidence-backed step flow count = %d, want 1", got)
	}
}

func TestFreshV2CaseRejectsEmptyOrUnknownCredentialBasis(t *testing.T) {
	t.Parallel()
	for _, basis := range []string{"", "removed-basis-v0"} {
		basis := basis
		t.Run(map[bool]string{true: "empty", false: "unknown"}[basis == ""], func(t *testing.T) {
			c := fixtureV2Case(t, "affected commit")
			c.Findings[0].CredentialExposure = []Exposure{{
				Kind: string(model.ExposureSecretPassedToStep), Name: "SYNTHETIC_ONLY", Basis: basis,
				Conclusion:  "A synthetic historical mapping was retained; access was not proven.",
				EvidenceIDs: append([]string(nil), c.Findings[0].EvidenceIDs...),
			}}
			if err := c.NormalizeAndValidate(); err == nil || !strings.Contains(err.Error(), "credential-exposure basis") {
				t.Fatalf("fresh v2 case accepted basis %q: %v", basis, err)
			}
		})
	}
}
