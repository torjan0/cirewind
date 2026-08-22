# ADR 0001: SQLite rather than Neo4j

## Status

Accepted for v0.1, subject to the feasibility-spike checks below.

## Date

2026-08-20

## Context

CIRewind is a single-user, local CLI whose durable product is a portable evidence bundle. Its dominant operations are exact-key joins across repositories, runs, attempts, jobs, observations, evidence, findings, and two timestamps. It also needs transactions, constraints, migrations, deterministic exports, and simple offline handoff. A graph is useful for traversal and presentation, but it is not the source of forensic truth.

Running Neo4j would add a service lifecycle, authentication and packaging work, a synchronization boundary, and another persisted representation. None of those costs improves the fidelity of source collection. SQLite can represent the temporal evidence model with normalized tables, foreign keys, indexes, recursive common-table expressions, and append-oriented evidence records in one case or archive file.

The preferred pure-Go SQLite driver is provisional until the spike measures correctness, supported build targets, performance, binary size, licensing, and security-maintenance posture.

## Decision

- Use SQLite as the authoritative structured store for each case and archive. Keep the append-only JSONL evidence ledger as the independently hashable evidence stream described by the evidence model.
- Model graph nodes and edges relationally. Generate graph exports and report views from finalized relational records; do not permit graph-only facts or writes.
- Enforce foreign keys, typed constraints, schema migrations, stable identifiers, and indexes for run-attempt identity, content hashes, event time, collection time, and evidence links.
- Use transactions for collection checkpoints and derivation commits. Finalization must checkpoint transient SQLite sidecars before manifest generation.
- Do not require Neo4j, another graph service, or a hosted database in v0.1.

## Consequences

- A case remains portable, queryable offline, and simple to include in a verifiable bundle.
- Collection, evidence, coverage, and finding consistency can be guarded with relational constraints and transactions.
- Recursive graph traversal and very large visual projections may require carefully indexed queries and bounded, finding-centered views.
- A pure-Go driver may impose performance, file-format, or security-update tradeoffs. The storage interface and migration tests must isolate that choice without weakening the SQLite contract.
- SQLite is not evidence by itself: source-object hashes, evidence IDs, derivation links, and the manifest remain necessary.

## Revisit criteria

Reconsider the driver or add an optional derived graph index only if reproducible workloads exceed agreed query or ingestion budgets, required traversals cannot be implemented safely with indexed SQL/recursive CTEs, or a later multi-user mode requires concurrent remote writers. Any future graph store must remain rebuildable from the case database and must never become an independent source of findings.
