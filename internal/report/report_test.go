package report

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/torjan0/cirewind/internal/graph"
	"github.com/torjan0/cirewind/internal/model"
)

func fixtureCase() Case {
	revisionID := "frev1:" + strings.Repeat("2", 64)
	evidenceID := "ev1:" + strings.Repeat("4", 64)
	return Case{Metadata: Metadata{CaseID: "case-1", Mode: "replay", IncidentID: "SYNTH", IncidentPackVersion: "1.0.0", CanonicalPackSHA256: strings.Repeat("a", 64), SourcePackSHA256: strings.Repeat("b", 64), EngineVersion: "test", AnalysisTime: "2026-08-20T00:00:00Z", LimitPolicy: "default", Coverage: Coverage{Partial: true, RepositoriesRequested: 1, RepositoriesAccessible: 1, RunsEnumerated: 1, AttemptsEnumerated: 1, JobsEnumerated: 1, LogsMissing: 1, IncompleteEvidence: []string{"<script>alert(1)</script>"}}}, Findings: []Finding{{FindingID: "find1:" + strings.Repeat("1", 64), FindingRevisionID: revisionID, IncidentID: "SYNTH", IndicatorID: "i", Repository: "=hostile/repo", RunID: 1, RunAttempt: 1, JobID: 2, StepIdentity: "</td><script>alert(1)</script>", State: "UNKNOWN_EVIDENCE_GAP", Provenance: "L0_UNKNOWN", Conclusion: "No retained logs != no compromise <img src=x onerror=alert(1)>", EvidenceIDs: []string{evidenceID}, EvidenceGaps: []string{"logs missing"}, CollectionCoverage: []string{"cova1:" + strings.Repeat("3", 64)}}}, Graph: graph.Graph{Nodes: []graph.Node{{ID: "finding", Type: graph.NodeFinding, Label: "<script>", EvidenceIDs: []string{evidenceID}, FocusFindingIDs: []string{revisionID}}, {ID: "evidence", Type: graph.NodeEvidenceObject, Label: evidenceID, EvidenceIDs: []string{evidenceID}, FocusFindingIDs: []string{revisionID}}}, Edges: []graph.Edge{{ID: "edge", Type: graph.EdgeSupportedByEvidence, Source: "finding", Target: "evidence", EvidenceIDs: []string{evidenceID}, FocusFindingIDs: []string{revisionID}}}}}
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
	for _, dangerousAPI := range []string{"innerHTML", "outerHTML", "document.write", "eval(", "fetch("} {
		if strings.Contains(filterScript, dangerousAPI) {
			t.Fatalf("constant filter script uses dangerous API %q", dangerousAPI)
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

func TestFindingNeedsEvidenceOrGap(t *testing.T) {
	t.Parallel()
	c := fixtureCase()
	c.Findings[0].EvidenceGaps = nil
	if err := c.NormalizeAndValidate(); err == nil {
		t.Fatal("unsupported finding accepted")
	}
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
