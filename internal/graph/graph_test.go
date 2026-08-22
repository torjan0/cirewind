package graph

import (
	"strings"
	"testing"
)

func evidenceID(character string) string { return "ev1:" + strings.Repeat(character, 64) }
func findingID(character string) string  { return "frev1:" + strings.Repeat(character, 64) }

func TestMaterialEdgesRequireEvidenceAndValidEndpoints(t *testing.T) {
	t.Parallel()
	g := Graph{
		Nodes: []Node{{ID: "finding", Type: NodeFinding, Label: "CONFIRMED_EXECUTED"}, {ID: "evidence", Type: NodeEvidenceObject, Label: evidenceID("a")}},
		Edges: []Edge{{ID: "edge", Type: EdgeSupportedByEvidence, Source: "finding", Target: "evidence"}},
	}
	if err := g.NormalizeAndValidate(); err == nil {
		t.Fatal("evidence-free graph edge accepted")
	}
	g.Edges[0].EvidenceIDs = []string{evidenceID("a")}
	if err := g.NormalizeAndValidate(); err != nil {
		t.Fatal(err)
	}

	// This was the old, semantically incorrect graph shape. Adjacency to a
	// repository is not evidence support for a finding.
	g.Nodes[1] = Node{ID: "repository", Type: NodeRepository, Label: "acme/repo"}
	g.Edges[0].Source, g.Edges[0].Target = "repository", "finding"
	if err := g.NormalizeAndValidate(); err == nil {
		t.Fatal("repository-to-finding SUPPORTED_BY_EVIDENCE edge accepted")
	}
}

func TestGraphNormalizesDeterministicallyAndValidatesFocus(t *testing.T) {
	t.Parallel()
	g := Graph{
		Nodes: []Node{
			{ID: "run", Type: NodeWorkflowRun, Label: "run 7", EvidenceIDs: []string{evidenceID("b"), evidenceID("a"), evidenceID("a")}, FocusFindingIDs: []string{findingID("c"), findingID("b")}},
			{ID: "attempt", Type: NodeRunAttempt, Label: "attempt 2"},
		},
		Edges: []Edge{{ID: "edge", Type: EdgeAttemptOfRun, Source: "attempt", Target: "run", EvidenceIDs: []string{evidenceID("b")}, FocusFindingIDs: []string{findingID("c")}}},
	}
	if err := g.NormalizeAndValidate(); err != nil {
		t.Fatal(err)
	}
	if got := g.Nodes[1].EvidenceIDs; len(got) != 2 || got[0] != evidenceID("a") || got[1] != evidenceID("b") {
		t.Fatalf("evidence IDs=%v", got)
	}
	if got := g.Nodes[1].FocusFindingIDs; len(got) != 2 || got[0] != findingID("b") {
		t.Fatalf("focus finding IDs=%v", got)
	}

	g.Nodes[0].FocusFindingIDs = []string{"not-a-finding"}
	if err := g.NormalizeAndValidate(); err == nil {
		t.Fatal("invalid focus finding ID accepted")
	}
}

func TestGraphRejectsHostileOrUnboundedLabels(t *testing.T) {
	t.Parallel()
	for _, label := range []string{"line\x1b[31mforged", "nul\x00value", strings.Repeat("x", maxLabelBytes+1)} {
		g := Graph{Nodes: []Node{{ID: "node", Type: NodeFinding, Label: label}}}
		if err := g.NormalizeAndValidate(); err == nil {
			t.Fatalf("hostile graph label accepted: %q", label[:min(len(label), 20)])
		}
	}
}
