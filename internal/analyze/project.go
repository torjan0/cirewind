package analyze

import (
	"fmt"

	"github.com/torjan0/cirewind/internal/archive"
	"github.com/torjan0/cirewind/internal/graph"
	"github.com/torjan0/cirewind/internal/incident"
	"github.com/torjan0/cirewind/internal/report"
)

// ProjectGraphs rebuilds the frozen compatibility graph and the v0.2 typed
// graph from persisted source facts and selected finding revisions. It does no
// incident matching and performs no I/O. Case generation uses this boundary
// after reopening case.db so presentation artifacts cannot become their own
// source of truth.
func ProjectGraphs(snapshot archive.Snapshot, findings []report.Finding, pack *incident.ValidatedPack) (graph.Graph, graph.GraphV2, error) {
	if pack == nil {
		return graph.Graph{}, graph.GraphV2{}, fmt.Errorf("validated incident pack is nil")
	}
	idx, err := buildIndex(snapshot)
	if err != nil {
		return graph.Graph{}, graph.GraphV2{}, err
	}
	legacy := buildGraph(idx, findings)
	if err := legacy.NormalizeAndValidate(); err != nil {
		return graph.Graph{}, graph.GraphV2{}, fmt.Errorf("normalize frozen graph: %w", err)
	}
	// Case classification is derived from persisted collection provenance. It
	// is never accepted from report text, metadata supplied by a caller, or an
	// already-rendered graph.
	projected, err := buildGraphV2(idx, legacy, findings, pack, caseKind(snapshot))
	if err != nil {
		return graph.Graph{}, graph.GraphV2{}, err
	}
	return legacy, projected, nil
}
