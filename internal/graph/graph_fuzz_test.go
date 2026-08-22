package graph

import (
	"encoding/json"
	"reflect"
	"testing"
)

func FuzzNormalizeGraph(f *testing.F) {
	valid, err := json.Marshal(Graph{
		SchemaVersion: SchemaVersion,
		Nodes: []Node{
			{ID: "finding", Type: NodeFinding, Label: "UNKNOWN_EVIDENCE_GAP"},
			{ID: "evidence", Type: NodeEvidenceObject, Label: evidenceID("a")},
		},
		Edges: []Edge{{ID: "edge", Type: EdgeSupportedByEvidence, Source: "finding", Target: "evidence", EvidenceIDs: []string{evidenceID("a")}}},
	})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(valid)
	f.Add([]byte(`{"nodes":[{"id":"x","type":"Finding","label":"\u001b"}]}`))
	f.Add([]byte{0xff})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			data = data[:1<<20]
		}
		var first, second Graph
		firstDecode := json.Unmarshal(data, &first)
		secondDecode := json.Unmarshal(data, &second)
		if (firstDecode == nil) != (secondDecode == nil) {
			t.Fatal("graph JSON acceptance is nondeterministic")
		}
		if firstDecode != nil {
			return
		}
		firstErr := first.NormalizeAndValidate()
		secondErr := second.NormalizeAndValidate()
		if (firstErr == nil) != (secondErr == nil) {
			t.Fatal("graph validation acceptance is nondeterministic")
		}
		if firstErr != nil {
			if firstErr.Error() != secondErr.Error() {
				t.Fatal("graph validation diagnostic is nondeterministic")
			}
			return
		}
		if !reflect.DeepEqual(first, second) {
			t.Fatal("graph normalization is nondeterministic")
		}
	})
}
