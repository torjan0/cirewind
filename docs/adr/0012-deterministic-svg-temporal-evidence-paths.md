# ADR 0012: Deterministic SVG temporal evidence paths

## Status

Accepted for v0.2 on 2026-08-22.

## Date

2026-08-22

## Context

ADR 0010 makes the temporal graph a disposable evidence-linked projection rather
than a truth source. The v0.1 report exports `graph.json` but shows nodes and
edges as lists. That is auditable but does not make the most important temporal
relationships understandable at a glance.

A generic graph library or browser force layout would introduce nondeterminism,
active assets, dependency/provenance work, and a tendency to imply causality
through proximity. Embedding a pre-rendered untrusted SVG or allowing report
data to control SVG markup would add an injection boundary. A server-side graph
service would violate offline/privacy/product constraints.

The visual must preserve downloaded versus executed, capability versus use,
temporal correlation versus causation, contradiction, gaps, exact identifiers,
and evidence-ID traceability.

## Decision

- Generate an inert, deterministic `graph.svg` from a typed presentation
  envelope loaded from authoritative relational facts plus validated
  output-contract metadata used only for aggregate capability/coverage labels, and
  include it as a fixed manifested v0.2 case file. `graph.json` and SVG remain
  derived exports, not parallel truth sources.
- Call the visual a **temporal evidence path**. Do not call it an attack path,
  compromise path, or proof of blast radius.
- Use a fixed semantic-lane layout with integer coordinates, fixed dimensions,
  stable sort keys, deterministic wrapping and box dimensions derived from
  bounded rune counts, and no random/force-directed/browser layout. Use a
  generic local monospace stack only; do not embed proprietary fonts or measure
  fonts at runtime.
- Version the graph export to require a closed edge `EvidenceClass`:
  `EXACT_OBSERVATION`, `INFERENCE`, `TEMPORAL_CORRELATION`, or
  `CONTRADICTION`. The evidence projector assigns it from the underlying fact
  basis; the renderer validates and displays it. Do not derive it from finding
  provenance or silently default a legacy Boolean. Render evidence gaps as
  nodes/notices rather than invented edges.
- Preserve a frozen v1 compatibility projector and `gedge1` identity solely for
  edge-cache/hash drift checks. v2 emits distinct `gedge2` identities that include
  class and derivation rule; cross-version IDs are never compared or aliased.
- For a retained v1 archive whose credential relationship has no classifiable
  basis, preserve the finding/exposure but omit that v2 edge and emit the closed
  `UNCLASSIFIABLE_LEGACY_BASIS` presentation notice. Never guess a class from
  its kind, provenance, or legacy inferred Boolean.
- Distinguish classes with explicit relationship labels, a legend,
  shapes/badges, and line patterns in addition to color. The accepted light-
  background palette is exact observation `#005A9C` solid; inference `#8A4B08`
  dashed; temporal correlation `#006B4F` dotted; contradiction `#B42318` with a
  double/heavy opposing marker; evidence gap `#5F6368` with an interrupted line
  and explicit gap marker; text `#111827`; neutral border `#334155`; background
  `#FFFFFF`. Require text contrast of at least 4.5:1 and graphical-object
  contrast of at least 3:1. Do not add severity or risk scoring.
- Require every visible material edge to map one-to-one to an existing graph edge
  and display references to one or more of that edge's stable evidence IDs.
- Encode output through a closed inert SVG element/attribute vocabulary. Prohibit
  script, event handlers, links, external/data references, images,
  `foreignObject`, animation, DTD/entities, and raw trusted markup.
- Use one presentation model for standalone SVG and report integration. Render
  inline report SVG through normal escaped template fields, not by inserting the
  serialized document as trusted HTML. Keep a semantic HTML text equivalent.
- Apply explicit selection and byte/node/edge/evidence budgets. Omit complete
  deterministic finding slices with visible counts; never create aggregate or
  dangling edges.
- Add an explicit v0.2 case-contract version so new cases require `graph.svg`, a
  trusted source-derived case classification, and `rawMaterialized` distinct from
  source/archive raw availability. Keep the shipped v0.1 verifier behavior for
  required base files plus any safe manifested regular extras; unknown legacy
  extras remain integrity-checked but are never consumed as evidence.
- Keep the existing SQLite schema. After writing/finalizing a new case, reopen
  `case.db` read-only, rehydrate canonical facts/findings/typed gap facts/analysis
  mode, and project graph v1alpha2 from those typed facts. Aggregate coverage and
  capability summaries may come from strictly validated manifested metadata but
  cannot create relationships. Compare the v2 projection with its pre-database
  expectation and separately compare the frozen v1 projection with the existing
  edge cache/hash before rendering. Never recover typed data from labels.
- Keep `graph.json` as the complete machine-readable projection. SVG is a
  presentation artifact and cannot originate or override a finding.

The full serialization, layout, accessibility, limit, and language contract is
defined by
[`TEMPORAL_EVIDENCE_PATH_SPEC.md`](../TEMPORAL_EVIDENCE_PATH_SPEC.md).

## Consequences

- A sample screenshot can communicate the temporal execution/evidence chain
  without a hosted renderer or remote asset.
- Identical normalized cases produce identical SVG bytes, enabling manifest and
  golden verification.
- Dense cases show a deliberately selected affected subgraph plus explicit
  omission counts; investigators use report details and `graph.json` for the
  complete projection.
- The implementation maintains two renderers over one presentation model
  (standalone XML and inline HTML template), which requires equality tests.
- Fixed lanes are less visually compact than force-directed layout but are more
  stable, reviewable, accessible, and resistant to causal overreading.
- The case output contract changes for v0.2, so generator/verifier compatibility
  must be version-aware rather than one global filename slice.
- A read-only relational rehydration/projector path is new implementation work,
  but archive and case database formats remain unchanged.

## Alternatives rejected

- **Graphviz or another subprocess:** adds executable/dependency/cross-platform
  surface and complicates deterministic distribution.
- **Browser force-directed JavaScript:** nondeterministic, harder to audit,
  inaccessible without script, and visually implies unsupported proximity.
- **Remote renderer/CDN library:** violates offline, privacy, and no-remote-assets
  rules.
- **Canvas or raster screenshot only:** weak accessibility and evidence-ID
  traceability; no standalone vector artifact.
- **Raw SVG inserted as trusted HTML:** creates an unnecessary injection
  boundary.
- **Lists only:** retains auditability but fails the v0.2 adoption objective.
- **Neo4j or persisted editable graph:** conflicts with ADR 0001/0010 and creates
  a second truth source.
- **Persist new presentation-only node/class/focus tables and migrate all
  archives:** creates writable forensic-store migration/recovery risk for an
  adoption feature even though existing canonical fact/finding tables contain
  the necessary inputs.

## Acceptance conditions

- ADR acceptance is recorded above; implementation must conform to the accepted
  decision.
- Golden, fuzz, injection, XML allowlist, CSP/browser, accessibility, limit,
  manifest, legacy-case, and cross-platform determinism tests pass.
- The synthetic visual includes direct, inferred, temporal, contradictory, and
  evidence-gap treatments without weakening any canonical finding.
- Every visible edge maps to existing evidence IDs, and no prohibited causal or
  credential language appears.
- New v0.2 graph exports reject missing/unknown evidence classes, and
  database-to-JSON-to-SVG consistency tests prove that static inferred
  credential/definition flows cannot appear as exact observations.
- Existing archive-store bytes/schema/source facts and finalized v1 case
  verification remain compatible; presentation work performs no archive
  migration. A new replay under v0.2 emits a new v0.2 case contract rather than
  claiming byte identity with a pre-v0.2 case.

## Revisit criteria

Revisit the lane/layout algorithm only if measured large affected subgraphs are
unusable within documented bounds. Any replacement must remain deterministic,
offline, inert, evidence-linked, accessible, and derived. Revisit SVG itself
only if a supported platform cannot safely display it; a replacement may not
introduce remote rendering or make a visual authoritative.
