# ADR 0010: The temporal graph is generated

## Status

Accepted for v0.1.

## Date

2026-08-20

## Context

Relationships among workflows, attempts, Actions, credentials, runners, resources, evidence, and findings are easier to explore as a temporal graph. However, CIRewind's product claim is the evidence bundle. Allowing graph data to be edited or persisted independently would introduce a second truth source and could create visually persuasive edges that lack forensic support.

## Decision

- Generate graph nodes and edges from finalized case-database records. The graph has no independent ingestion or mutation API.
- Require every material edge to cite one or more stable evidence IDs and, when derived, a versioned rule and its input relationships. Unsupported visual adjacency is prohibited.
- Preserve event time and collection time where applicable. Do not collapse attempt-specific jobs, mutable declarations, resolved SHAs, or evidence revisions into one timeless node.
- Represent contradictions and evidence gaps explicitly. Visual styling, path finding, grouping, and rollups must not strengthen a semantic state or imply credential use, cloud-role assumption, or causation.
- Produce deterministic, schema-versioned graph exports. A cached projection must bind to the case snapshot/hash and be safely discardable and rebuildable.
- Use bounded finding-centered views for large cases and locally bundled, offline report assets. No graph database or remote renderer is required in v0.1.

## Consequences

- Every displayed relationship remains auditable back to source evidence and can be regenerated after report changes.
- Users cannot annotate the graph as if an annotation were collected evidence; analyst notes need their own provenance-aware model if added later.
- Projection queries and browser rendering require scale limits and degradation tests.
- Graph-oriented queries may be less convenient than a native graph store, but they cannot diverge from the relational evidence model.

## Revisit criteria

An optional graph index may be considered if measured cases cannot meet bounded traversal/query goals with SQLite. It must remain derived, content-bound to a case snapshot, reproducible, and disposable; it cannot originate or override findings.
