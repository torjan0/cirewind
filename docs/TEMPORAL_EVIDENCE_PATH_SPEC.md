# Deterministic temporal evidence path specification

Status: accepted v0.2 presentation contract as of 2026-08-22.

The temporal evidence path is a bounded visual projection of the case graph. It
is not an attack path, compromise path, blast-radius proof, risk score, or source
of forensic truth. The normalized relational facts, evidence objects, findings,
and coverage records in `case.db` remain authoritative. `graph.json`,
`graph.svg`, and the report view are derived projections.

## Design goals

- Make exact observations, deterministic inference, temporal correlation,
  contradiction, and evidence gaps distinguishable in one screenshot.
- Preserve the exact distinctions between download, preparation, step start,
  execution, capability, eligibility, and later resource events.
- Make every displayed material edge auditable through stable evidence IDs.
- Produce byte-identical inert SVG for identical normalized input.
- Remain useful with color disabled, JavaScript disabled, no network, keyboard or
  screen-reader navigation, and small displays.
- Fail boundedly and visibly on large or hostile graph content.

## Relationship to the existing graph and case store

The presentation builder consumes trusted output-contract metadata plus a typed
case projection loaded read-only from finalized `case.db`. It does not consume
`graph.json`, parse display labels, query GitHub, re-derive findings, add facts,
or persist independent truth. `FocusFindingIDs` controls presentation membership
only and never acts as evidence.

The current SQLite schema already retains the normalized archive facts,
observations, evidence links, typed coverage-gap facts,
incident/indicator definitions, complete finding revisions, and analysis mode
needed to regenerate material graph relationships. Validated trusted
output-contract metadata supplies aggregate capability/coverage summaries that
v1 case databases do not store; it may label or summarize the visual but cannot
create nodes, edges, findings, or evidence. v0.2
therefore does **not** migrate case or archive stores solely for presentation.
Existing v1 archives remain v1 read/write, and finalized v1 cases remain
immutable/verifiable. This keeps adoption work out of forensic-store migration.

The v0.2 derived graph export uses `cirewind.graph/v1alpha2`. A new read-only
case-projection loader queries typed relational columns/JSON fields. The legacy
`graph_projection_edges` table is a hash-indexed audit/cache of selected v1 edge
fields; because it omits nodes, focus IDs, and full fact basis, it is never the
renderer input or a parallel authority.

Compatibility and v2 identity are deliberately separate:

- a frozen compatibility projector regenerates the complete v1alpha1 graph and
  its existing `gedge1` IDs using exactly the v1 tuple (type, endpoints, event
  time, rule, and inferred Boolean); its normalized rows, evidence references,
  and snapshot hash must equal the legacy cache;
- the v1alpha2 projector consumes the same typed facts but gives each edge a new
  `gedge2` ID over schema version, type, endpoints, normalized event time,
  `EvidenceClass`, and normalized derivation rule; and
- v2 IDs are never compared with or substituted for `gedge1` IDs. A class or
  rule change must change `gedge2`; collision or cross-version alias tests fail
  closed.

The compatibility projection exists only as a drift guard. It is not serialized
as the v2 graph, and no legacy cache row is upgraded or rewritten.

The case writer must:

1. write source facts, evidence, coverage, findings, and the existing edge audit
   cache coherently to `case.db`, then close/checkpoint and verify the database;
2. reopen `case.db` read-only and load typed facts, findings, typed gap facts,
   incident context, analysis mode, and evidence relationships; separately
   validate the output-contract metadata used for aggregate coverage text;
3. regenerate and compare the frozen v1 compatibility projection with the
   stored edge cache/hash, then project `cirewind.graph/v1alpha2`, including
   explicit edge evidence classes, entirely from those relational facts;
4. compare the database-derived v2 projection with the pre-database in-memory
   v2 expected projection as a separate drift guard; and
5. build `graph.json`, `graph.svg`, report, and manifested metadata from the
   database-derived projection before atomic case publication.

This preserves SQLite as the source of truth and makes projection drift a
case-generation failure. `graph.json` remains the complete machine-readable
derived export, never an authority parallel to SQLite. v0.1 bundles need only
continue to verify under their legacy case contract; v0.2 does not rewrite their
reports or databases.

The typed presentation envelope also contains, without parsing display labels:

- case classification (`synthetic`, `collected`, `mixed`, or `unknown`) and
  collection coverage;
- a finding index keyed by finding revision ID with canonical state, provenance,
  repository, workflow path, run ID, attempt, job ID, step identity, and
  indicator ID;
- closed node type, stable node ID, sanitized-at-sink display label, evidence
  IDs, and focus finding IDs; and
- closed edge type, stable endpoints, `EvidenceClass`, event time, sorted
  evidence IDs, focus finding IDs, and derivation rule when required.

Missing required typed sort or semantic fields fail v0.2 rendering. The builder
must never recover them by parsing a human-readable label.

The v0.1 graph validator already requires unique IDs, closed node/edge types,
valid endpoints, bounded valid UTF-8 labels, deterministic ordering, at least one
evidence ID per edge, and a derivation rule for every inferred edge. Those checks
remain prerequisites.

The renderer adds a presentation-only schema identifier:

```text
cirewind.temporal-evidence-path/v1alpha1
```

This identifier describes layout and SVG serialization. It does not version the
forensic graph or alter an edge's meaning.

## Node vocabulary

Only the existing closed graph node types may appear. They are grouped into
visual lanes as follows:

| Visual role | Allowed graph node types |
|---|---|
| Scope and source | `Repository`, `WorkflowDefinition`, `ReusableWorkflowDefinition` |
| Temporal execution context | `WorkflowRun`, `RunAttempt`, `Job`, `Step` |
| Action identity and resolution | `ActionRepository`, `ActionRef`, `ActionCommit`, `ImmutableActionPackage`, `ActionDefinition` |
| Execution environment | `Runner`, `RunnerGroup`, `Environment` |
| Credential capability/relationship | `TokenCapability`, `SecretMetadata`, `OIDCProvider` |
| Downstream context | `Artifact`, `Package`, `Release`, `Deployment`, `RepositoryResource`, `PullRequestChange` |
| Provenance and conclusion | `EvidenceObject`, `Finding` |

`EvidenceObject` nodes stay in the evidence key/textual fallback by default so
they do not overwhelm the primary path. `Finding` is rendered as the lane header
and scope anchor. Neither rule removes them from `graph.json`.

An `UNKNOWN_EVIDENCE_GAP` finding is rendered as an explicit gap node or lane
notice. The renderer must not invent a connecting edge to make it visually fit.

## Edge vocabulary

All existing closed relationships remain available. The visible wording must
preserve their individual semantics.

| Category | Relationships |
|---|---|
| Execution containment | `RUN_IN_REPOSITORY`, `ATTEMPT_OF_RUN`, `JOB_EXECUTED_IN_ATTEMPT`, `STEP_IN_JOB`, `RUN_INSTANTIATED_WORKFLOW` |
| Historical declaration/call | `WORKFLOW_DECLARED_ACTION`, `WORKFLOW_CALLED_WORKFLOW`, `ACTION_CONTAINS_ACTION`, `LOCAL_ACTION_RESOLVED_TO` |
| Exact resolution/package | `REF_RESOLVED_TO`, `PACKAGE_SOURCE_COMMIT` |
| Preparation and execution | `JOB_PREPARED_ACTION`, `STEP_DOWNLOADED_ACTION`, `STEP_EXECUTED_ACTION` |
| Runner context | `EXECUTED_ON_RUNNER`, `RUNNER_IN_GROUP` |
| Credential and environment | `HAD_TOKEN_PERMISSION`, `REFERENCED_SECRET`, `PASSED_SECRET_TO`, `INHERITED_SECRET`, `TARGETED_ENVIRONMENT`, `CROSSED_ENVIRONMENT_GATE`, `ENVIRONMENT_SECRET_ELIGIBLE`, `COULD_MINT_OIDC` |
| Direct resource attribution | `PRODUCED_ARTIFACT`, `PUBLISHED_PACKAGE`, `CREATED_RELEASE`, `CREATED_DEPLOYMENT`, `REPOSITORY_WRITE`, `PULL_REQUEST_CHANGE` |
| Temporal-only resource context | `OBSERVED_AFTER` |
| Finding provenance | `FINDING_ABOUT`, `SUPPORTED_BY_EVIDENCE` |
| Conflict | `CONTRADICTS` |

The renderer may omit a relationship from the bounded primary canvas only under
the explicit selection/limit policy below. It may not merge two edge types,
reverse direction, replace them with an unlabeled arrow, or create a roll-up
edge. `graph.json` exposes the complete normalized projection. The accessible
fallback exposes the exact selected subgraph plus explicit complete-graph and
omission counts.

## Evidence-basis classification

Every v0.2 graph edge has a required closed `EvidenceClass` field with exactly
one of these values:

- `EXACT_OBSERVATION`
- `INFERENCE`
- `TEMPORAL_CORRELATION`
- `CONTRADICTION`

The evidence projector assigns this class from the underlying fact basis. The
SVG renderer validates and displays it; it must not infer a class from edge type,
finding provenance, or a legacy Boolean. Assignment follows this precedence:

1. a material disagreement represented by `CONTRADICTS` is `CONTRADICTION`;
2. an `OBSERVED_AFTER` relationship is `TEMPORAL_CORRELATION`;
3. a relationship whose basis is `static-inferred`,
   `historical-definition-flow`, or another derivation rule is `INFERENCE` and
   must name that rule;
4. a relationship directly supported by runtime observation, exact historical
   content, or exact GitHub-recorded identity is `EXACT_OBSERVATION`, limited to
   the proposition expressed by that edge.

The current `Inferred` Boolean is insufficient because some credential and
definition-flow edges carry an inferred basis while that field is false. New
v0.2 graph writers therefore must emit `EvidenceClass`; silent defaulting is
prohibited. Existing manifested v0.1 graph/report files continue to verify under
their v1 contract and are not silently relabeled or upgraded. Every newly
generated v0.2 graph is projected from relational facts and has an explicit
class.

Retained v1 archives require a narrow compatibility rule because a legal legacy
credential exposure can have an empty or now-unrecognized `basis`. Replay must
preserve that canonical finding, source exposure fact, evidence links, counts,
and archive bytes. Because the frozen findings schema requires a nonempty
presentation basis, an empty source basis is rendered as the explicit
non-classifying value `legacy-unclassified`; a bounded safe unrecognized value
is preserved verbatim. It omits only the v1alpha2 relationship that cannot be
classified without invention and emits a scoped presentation notice with closed
code `UNCLASSIFIABLE_LEGACY_BASIS`, the finding revision ID, affected
relationship, and the source evidence IDs. The notice appears in `graph.json`
projection notices, the SVG lane, and the accessible fallback; it is not an
edge, canonical finding state, provenance level, or replacement
collection-coverage fact. The
visual states that its relationship projection is partial. It must not infer a
class from relationship type, finding provenance, exposure kind, the legacy
`Inferred` Boolean, or renderer defaults. New v0.2 facts—including the embedded
demo—still reject an empty or unknown basis instead of taking this legacy path.

The projector has a reviewed relationship/basis table, including at least:

| Relationship/fact basis | Required class |
|---|---|
| runtime-observed permission and its exact access level | `EXACT_OBSERVATION` for `HAD_TOKEN_PERMISSION` |
| static-inferred or historical-definition-flow permission/secret mapping | `INFERENCE` with rule |
| `COULD_MINT_OIDC` derived from an observed or inferred permission | `INFERENCE` with the capability rule; never cloud reachability |
| directly observed environment target or approval/bypass gate transition | `EXACT_OBSERVATION` limited to that event |
| gate “crossed” reconstructed from job start without indispensable approval/bypass evidence | `INFERENCE` with rule, or no crossed edge when the canonical predicate is not satisfied; never silently exact |
| environment-secret eligibility derived from gate/job/metadata facts | `INFERENCE` with rule |
| exact Action download or lifecycle start | `EXACT_OBSERVATION` for download or start respectively |
| `JOB_EXECUTED_IN_ATTEMPT` API/model membership without lifecycle start | `EXACT_OBSERVATION` only of containment; visible label is “job recorded in attempt,” never “job executed” |
| later resource with only temporal ordering | `TEMPORAL_CORRELATION` |

Every edge projector—not only credential and environment code—is audited against
this table. `EvidenceClass` and derivation rule participate in edge identity and
normalization. If exact and inferred bases support the same relationship type,
endpoints, and time, they remain distinct evidence-preserving edges; coalescing
may not relabel inference as exact or discard either evidence chain.

`EXACT_OBSERVATION` means the displayed relationship is directly supported by
the cited evidence object(s); it does not promote the associated finding to
`L4_CERTAIN`, imply runtime execution, or override the finding state. A static
historical declaration can therefore be an exact observation of declaration
while still not being execution.

The v2 presentation projector may attach a directly evidenced
`TARGETED_ENVIRONMENT` relationship to a selected non-executed finding lane even
when the finding's `potentialCredentialExposure` and
`potentialResourceExposure` arrays are empty. This is contextual graph
projection from the underlying environment/job fact, not a finding mutation or
reachability claim. For a waiting, pending, or unstarted job it may show only the
target and neutral gate status; it must not add `CROSSED_ENVIRONMENT_GATE`,
`ENVIRONMENT_SECRET_ELIGIBLE`, token, secret, OIDC, runner, downstream-resource,
or execution reachability. The v1 compatibility projection remains byte-for-
byte unchanged.

Canonical finding evidence gap is a node/lane treatment, not an edge
classification. The four edge treatments plus the canonical finding-gap
treatment are:

| Basis | Accepted color | Stroke and shape | Required visible wording/non-color cue |
|---|---|---|---|
| `EXACT_OBSERVATION` | `#005A9C` | solid, 2 px | Exact relationship label, such as “step execution began” or “download demonstrated” |
| `INFERENCE` | `#8A4B08` | dashed | `inferred`; derivation rule available in detail |
| `TEMPORAL_CORRELATION` | `#006B4F` | dotted | `observed after — causation not established` |
| `CONTRADICTION` | `#B42318` | double/heavy treatment with opposing marker | `contradicts` |
| evidence gap | `#5F6368` | interrupted line plus explicit gap marker | canonical `UNKNOWN_EVIDENCE_GAP` and gap reason |

The remaining accepted light-background colors are text `#111827`, neutral
border `#334155`, and background `#FFFFFF`. These values are versioned renderer
constants, not theme input. The SVG and report include an explicit visible
legend and an explicit relationship label for every material edge.

`UNCLASSIFIABLE_LEGACY_BASIS` uses a separate, narrow projection-partial notice:
a thin dashed gray notice box with an `i` badge and the exact lead “visual
relationship omitted — legacy evidence basis unavailable.” It must not use the
canonical evidence-gap `?` treatment, say that the underlying evidence is
missing, create or relabel an `UNKNOWN_EVIDENCE_GAP` finding, or increment any
finding-state, provenance, credential-exposure, or collection-coverage count.
The preserved finding/exposure remains available in the finding details with its
original wording; the notice describes only why one visual edge is absent.

Color is supplementary. Pattern, shape/badge, relationship label, and legend
must independently convey the class. Ordinary text has contrast of at least
4.5:1 and meaningful graphical objects have contrast of at least 3:1 against
adjacent colors. No severity color, traffic-light score, numeric risk,
animation, glow, or pulse is permitted.

## Required semantic wording

- `STEP_EXECUTED_ACTION`: “step execution began” or “step execution completed,”
  according to the underlying lifecycle evidence.
- `STEP_DOWNLOADED_ACTION` / `JOB_PREPARED_ACTION`: “download demonstrated” or
  “preparation demonstrated”; never “executed.”
- `HAD_TOKEN_PERMISSION`: name the observed/inferred permission and access level;
  never say a write occurred unless separately evidenced.
- `PASSED_SECRET_TO` / `INHERITED_SECRET`: “mapped,” “passed,” or “inherited”;
  never “read,” “used,” “leaked,” or “exfiltrated.”
- `COULD_MINT_OIDC`: “could mint OIDC token”; never “cloud access,” “role
  assumed,” or `CLOUD_IDENTITY_REACHABLE`.
- `TARGETED_ENVIRONMENT` without `CROSSED_ENVIRONMENT_GATE`: “targeted; gate not
  shown crossed.” No environment-secret eligibility edge may be inferred.
- `OBSERVED_AFTER`: “observed after — causation not established.”
- `EXECUTED_ON_RUNNER`: classify only from the recorded basis; never infer
  persistence, compromise, internal access, or lateral movement.
- `JOB_EXECUTED_IN_ATTEMPT` is a legacy machine relationship name whose visual
  wording is “job recorded in attempt” unless separate lifecycle evidence proves
  a start. Its exact class proves containment only, never execution. A skipped or
  environment-gated job must not acquire execution wording from this edge.
- Current and historical workflow definitions, run attempts, caller SHAs, called
  workflow SHAs, Action commits, and package digests remain separate nodes.

## Finding-centered selection

The primary SVG is deliberately bounded. Selection occurs before layout and is
stable:

1. Build one pre-rendered default selection from all non-
   `NO_MATCH_CONFIRMED` findings. There is no active browser filter at generation
   time and the standalone SVG has no alternate selection mode in v0.2.
2. Add a `NO_MATCH_CONFIRMED` finding only as labeled comparison context when
   typed fields prove it has the same indicator ID, repository, workflow path,
   and run ID as an already selected `CONFIRMED_EXECUTED` or
   `CONFIRMED_DOWNLOADED` finding, a different attempt, an exact known-good
   identity, and mechanically closed coverage. No other state is an anchor.
   This admits the synthetic restored-A attempt without pairing unrelated
   components or flooding the visual with organization-wide negatives. It
   remains a no-match lane, never an affected-run count.
3. Partition the graph by sorted `FocusFindingIDs`.
4. Give every represented canonical state one lane before adding a second lane
   for a state, when the lane budget allows.
5. Within a state, sort by repository, workflow, run ID, run attempt, job ID,
   step identity, indicator ID, and finding revision ID.
6. Fill remaining lanes in this review-attention order, which is not a risk
   score: `CONTRADICTORY_EVIDENCE`, `UNKNOWN_EVIDENCE_GAP`,
   `CONFIRMED_EXECUTED`, `CONFIRMED_DOWNLOADED`,
   `CONFIRMED_CALLED_WORKFLOW`, `DECLARED_AT_RUN_SHA`,
   `RUN_IN_WINDOW_MUTABLE_REF`, `POTENTIAL_TRANSITIVE`,
   `CURRENT_REFERENCE_ONLY`, `NO_MATCH_CONFIRMED`.
7. Include only complete edges whose source and target nodes are selected.
8. Report exact selected/total finding, node, edge, and evidence-reference counts.

HTML filters may only hide or intersect whole lanes already present in this
pre-rendered bounded selection. They do not admit omitted lanes, change evidence
classification, or create browser-side layout/relationships. For every filter
state, a precomputed full finding index supplies selected/total and omitted
matching-finding counts; when any matching finding is outside the visual budget,
the report says “N matching findings omitted from visual; see findings table.” A
separate filtered SVG/export command is out of scope for v0.2.

## Deterministic layout

Use semantic lanes and integer geometry; do not use force-directed or random
layout.

Each finding lane has four fixed columns:

1. repository, workflow, run, and attempt context;
2. job and step execution identity;
3. Action ref/commit/package/definition or reusable workflow;
4. token, secret, OIDC, environment, runner, and downstream resource context.

For non-executed lanes, column 4 is empty except for the narrowly allowed
environment-target/gate context above or an evidence-gap notice. It is never
filled by copying exposure objects from another attempt or job.

Within a lane:

- render the canonical state and provenance in the header;
- sort nodes by a closed node-type rank, sanitized display label, and stable node
  ID;
- sort edges by source column/row, target column/row, edge-type rank, and edge ID;
- route edges orthogonally through fixed integer gutters and ports;
- reserve a separate band for contradiction edges;
- keep temporal correlation visually separate from direct resource attribution;
- repeat a node visually across lanes if necessary while retaining the same
  `data-node-id`; repetition is presentation, not a new identity.

Coordinates, wrapping, and canvas size may depend only on normalized input and
versioned integer constants. They may not depend on random seeds, wall time,
locale, timezone, Go map order, floating-point physics, browser measurement,
installed fonts, platform text rendering, output path, or screen size.

Use fixed node dimensions and the generic local monospace stack
`ui-monospace, monospace` only for display. No font file is remote or embedded,
and no proprietary font is bundled. Layout never measures a runtime or browser
font. Calculate wrapping and box dimensions from a versioned fixed-cell model:
at most three lines, at most 32 Unicode runes per line, and at most 192 UTF-8
bytes total after SVG-sink sanitization. Break only at rune boundaries and use a
visible ellipsis when either limit truncates the label. The complete bounded
sanitized label remains in its `<title>`/`<desc>`.

## Evidence-ID traceability

Every visible material edge:

- maps one-to-one to an existing `graph.Edge.ID`;
- carries at least one existing full stable evidence ID;
- exposes edge type, event time when present, inference rule when present, and
  sorted evidence IDs in accessible detail;
- shows compact stable references such as `E001` that map to full IDs in a
  visible evidence-reference key.

Evidence references are assigned by lexicographically sorting the union of
selected edge evidence IDs. Each edge shows at most eight compact references
followed by `+N more`; its `<desc>` includes the complete selected list within
the hard evidence budget. The key lists each compact reference and full evidence
ID exactly once.

Node adjacency, shared color, placement, an omission count, and a finding focus
membership are not evidence. A renderer-created edge is prohibited.

## SVG serialization contract

The standalone document begins with no DTD or processing instruction and uses a
fixed root:

```xml
<svg xmlns="http://www.w3.org/2000/svg"
     role="img"
     aria-labelledby="tep-title tep-desc"
     data-cirewind-schema="cirewind.temporal-evidence-path/v1alpha1"
     viewBox="0 0 WIDTH HEIGHT">
```

Required deterministic child order:

1. `<title id="tep-title">Temporal evidence path</title>`;
2. `<desc id="tep-desc">` naming the exact `synthetic`, `collected`, `mixed`, or
   `unknown` case classification, selected totals, and any omissions;
3. fixed local definitions if arrow markers are used;
4. background and legend;
5. explicit limit/omission notice;
6. finding lanes in selected order;
7. evidence-reference key.

Renderer-local element IDs are sequential (`n0001`, `e0001`) and never derived
from hostile content. Node groups expose escaped closed attributes:

```text
data-node-id
data-node-type
data-finding-revisions
```

Edge groups expose:

```text
data-edge-id
data-edge-type
data-evidence-class
data-evidence-refs
```

Full evidence IDs remain in `<desc>` and the key rather than a potentially huge
attribute. Every node and edge group has a concise `<title>` and `<desc>`.

## Hostile-label and SVG security

The output is constructed through a fixed encoder/template vocabulary. No domain
value is converted to trusted HTML/XML or inserted as raw markup.

Before XML escaping, the SVG sink:

- validates or replaces invalid UTF-8;
- removes terminal escape sequences, C0/C1 controls, carriage returns, bidi
  controls, NUL, XML-invalid code points, and prohibited Unicode noncharacters;
- flattens line boundaries to visible spaces;
- enforces full and visible byte limits without splitting UTF-8;
- records an explicit truncation indicator where truncation occurred.

Hostile strings may appear only as escaped text, `<title>`, `<desc>`, or bounded
data-attribute values. They never become element names, raw attributes, IDs,
classes, styles, CSS, fragment names, geometry, file paths, URLs, or references.

The allowed standalone element vocabulary is limited to inert SVG primitives
needed by the renderer, such as `svg`, `title`, `desc`, `defs`, `marker`, `g`,
`rect`, `line`, `polyline`, `path`, `polygon`, `circle`, `text`, and `tspan`.
The exact allowlist is tested. The following are prohibited:

- `script`, `foreignObject`, `image`, `a`, `iframe`, audio/video, and animation;
- any `on*` event attribute;
- external or data `href`/`xlink:href`;
- CSS import, remote font, URL-valued style, or external `url()`;
- DTD, XML entity, processing instruction, CDATA carrying input, or embedded raw
  HTML/JSON;
- forms, storage, network APIs, or JavaScript;
- untrusted fragment references. Fixed renderer-owned same-document arrow marker
  references are permitted and allowlisted.

Prefer presentation attributes over a generated stylesheet. The file must be
valid XML and no larger than its fixed budget.

## Report integration

`graph.svg` is a standalone fixed case output and is covered by the manifest.
The report renders the identical visual model inline through ordinary
`html/template` fields and fixed SVG elements. It must not inject the serialized
SVG with a trusted-HTML escape hatch.

Inline rendering preserves the report's one-file offline behavior and current
`img-src 'none'`, `connect-src 'none'`, `object-src 'none'`, `base-uri 'none'`,
and `form-action 'none'` CSP. The fixed report stylesheet/script hashes are
regenerated from reviewed constants. The report may offer a fixed relative link
to `graph.svg`; it does not automatically fetch it.

Keep a semantic HTML `<details>` fallback containing the selected nodes,
relationships, exact evidence IDs, omission counts, and legend. With CSS, SVG,
or JavaScript unavailable, the distinction remains readable. Existing finding
filters may show/hide whole pre-laid-out lanes, but never compute or alter
relationships in the browser.

## Case contract and backward verification

`graph.svg` becomes required for newly generated v0.2 cases and appears exactly
once in `manifest.sha256`. Removing or modifying it fails verification.

Implementation must not make retained v0.1 case bundles unverifiable. Separate:

- filenames allowed for staging;
- the v0.1 fixed case contract;
- the v0.2 fixed case contract.

Use collection metadata schema `cirewind.collection-metadata/v1alpha2` with
required `caseContractVersion: cirewind.case/v1alpha2` and required closed
`caseKind: synthetic|collected|mixed|unknown`. Derive it only from trusted
orchestration plus validated persisted source provenance:

- the embedded demo and fixture-only archives/replays are `synthetic`;
- live GitHub investigations and live-only archives/replays are `collected`;
- a supported case containing both source classes is `mixed`; and
- absent, legacy-ambiguous, contradictory, or unsupported provenance is
  `unknown` and is displayed conspicuously rather than guessed.

Replay inherits its validated input provenance; invoking `replay` does not turn
fixture evidence into collected evidence. Pack, repository, workflow, archive
filename, path, and report text cannot select this value. The public sample
accepts only `synthetic`. These rules prevent hostile evidence from making a
collected or ambiguous case appear to be the built-in demonstration. New
generators also write required Boolean `rawMaterialized`. This records whether
raw evidence objects were materialized into this case directory; it is distinct
from `rawLogsRetained` or archive capability, which may be true even when a
compact output case contains no `raw/`. The value must equal the existing
`case_raw_materialized` database metadata after database integrity validation.
The embedded demo and public sample set it to `false`. The verifier
first hashes the manifested metadata, strictly parses its schema/contract pair,
then enforces that version's exact base file set and its bounded raw-retention
rule. Legacy metadata `v1alpha1` with no contract field is accepted only under
the shipped safe-manifested-extra compatibility behavior described below.
`v1alpha2` without the field or a mismatched schema/contract pair is rejected.
A manifested `graph.svg` in a legacy case remains an integrity-checked unknown
extra and is never parsed, projected, or treated as a recognized v2 output.
Selection never relies on an unparsed engine-version string. This is
compatibility handling, not permission for arbitrary optional files in the
strict v0.2 contract.

Legacy v0.1 verification keeps its shipped compatibility behavior: the eight
required base files must be present, and any additional safe, manifested regular
file remains integrity-checked; directories are ignored and links/non-regular
entries are rejected. Unknown legacy extras are never consumed by the v2
projector or treated as recognized evidence. This deliberately preserves prior
verification rather than retroactively imposing a new raw descriptor contract.
The v0.2 terminal and structured verification result lists each such file with
the fixed status “integrity-checked unknown legacy extra; not parsed or v2
safety-validated.” Successful hash verification must not imply that a legacy
`graph.svg` or any other unknown extra passed the v2 content-security contract.

The v0.2 contract is strict. It accepts optional retained raw evidence only when
validated `rawMaterialized` is true and every additional manifested
entry is a bounded regular file named
`raw/<lowercase-64-hex-sha256>.bin` that matches an evidence descriptor's hash,
length, and retained-raw status. Symlinks, hard links, unreferenced raw entries,
hash/name mismatches, nested directories, and any other extra file fail
verification. Exactly one structural `raw/` directory may exist when metadata
declares materialization, including when it contains zero objects; directories are not
manifest entries. A v0.2 raw-disabled case must contain no `raw/` directory. The v0.2
base set is the fixed v1alpha2 file set plus only this descriptor-bound raw set.
Demo and public-sample cases are always raw-disabled.

The two public JSON contracts are documented by
`schema/graph-v1alpha2.json` and
`schema/collection-metadata-v1alpha2.json`. Both reject unknown fields and
unknown closed-enum values. Golden drift tests compare code serialization and
strict parsing with those schema artifacts, including `EvidenceClass`,
`caseKind`, `caseContractVersion`, and `rawMaterialized`. The schema documents
describe structure and safety constraints; they do not make a graph or case
factually true.

CIRewind v0.2 does not regenerate an old case in place or synthesize
`graph.svg` into a v0.1 bundle. Every newly generated v0.2 case uses relational
facts and the explicit `EvidenceClass` contract above. Replaying a v1 archive in
v0.2 therefore creates a new v0.2 case with the new fixed files/metadata; it does
not promise byte identity with a pre-v0.2 replay case. The input archive's schema,
bytes, source facts, and extractor provenance remain unchanged, and existing
finalized v1 cases continue to verify under the legacy contract.

## Size limits and degradation

The full graph retains its existing 100,000-node/250,000-edge validation limits.
The visual limits are intentionally much lower:

| Limit | Default | Hard |
|---|---:|---:|
| Finding lanes | 12 | 32 |
| Logical nodes | 96 | 256 |
| Material edges | 144 | 512 |
| Unique evidence IDs | 256 | 512 |
| Visible label | 192 bytes / 3 lines | same |
| Full sanitized label | existing graph maximum, 4,096 bytes | same |
| SVG bytes | target below 2 MiB | 8 MiB |

Hard limits are compile-time/versioned policy in v0.2, not incident-pack
settings. Exceeding a default produces a deterministic “showing X of Y” notice.
Exceeding a hard bound omits complete deterministic finding slices until within
budget and records exact omission counts. Never emit a dangling edge, silently
truncate evidence IDs, synthesize a grouped relationship, or change the case
finding count.

Aggregation is text-only. If shown, a count names its selected population and
member finding revision IDs or a deterministic digest; it is not a graph node or
edge and implies no shared causal path.

## Accessibility requirements

- The document and every material node/edge have nonempty accessible names and
  descriptions.
- The root uses `role="img"`, `<title>`, `<desc>`, and `aria-labelledby`.
- Visible relationship labels, line patterns, node shapes/badges, and the legend
  distinguish all evidence classes without color.
- Body text has a minimum effective size of 16 px at default zoom; ordinary-text
  contrast is at least 4.5:1 and graphical-object contrast is at least 3:1.
- The `viewBox` scales without a forced bitmap size and remains usable at 200%
  zoom and narrow viewport widths.
- DOM/reading order follows lane then column order; it does not follow routed
  line geometry.
- Relationship wording and evidence references are visible or present in the
  adjacent textual fallback, never tooltip-only.
- The report includes a keyboard-readable HTML equivalent.

W3C guidance supports naming inline SVG with a title referenced by
`aria-labelledby`. Retrieved 2026-08-22:

- [W3C WAI — Images: Tips and Tricks](https://www.w3.org/WAI/tutorials/images/tips/)
- [SVG 2 — Accessibility support](https://www.w3.org/TR/SVG/access.html)

Manual screen-reader, keyboard, high-contrast, and 200% zoom review remains a
release gate; automated DOM checks do not complete it.

## Sample visual acceptance oracle

The synthetic demo visual must display:

- an exact `STEP_EXECUTED_ACTION` path for B;
- a separate B download/preparation path with no execution edge;
- a rule-derived transitive or mutable-reference relationship;
- an `OBSERVED_AFTER` deployment edge labeled non-causal;
- a `CONTRADICTS` relationship;
- a disconnected or appropriately supported `UNKNOWN_EVIDENCE_GAP` treatment;
- separate rerun attempts and current/historical definition identities;
- `contents: write` as capability, a named-secret mapping/passing relationship,
  OIDC minting capability, a self-hosted runner classification, and a targeted
  but not crossed environment gate.

The visual, report text fallback, `graph.json`, `findings.json`, and database
findings must agree on selected identifiers and counts. No downloaded-only case
may contain an execution edge.

## Required tests

1. Byte-identical SVG for identical normalized input across repeated runs,
   reversed source ordering, and supported OS/architecture builds.
2. Renderer does not mutate the input graph and performs no network or process
   operation.
3. An XML parser accepts output; an allowlist audit rejects active/external
   elements, handlers, DTD/entities, unsafe URLs, and untrusted fragments.
4. Hostile corpus includes closing SVG/script strings, quotes, ampersands,
   control/bidi/terminal sequences, CR/LF, invalid UTF-8, XML-invalid runes,
   noncharacters, huge Unicode strings, formula prefixes, and URL-shaped labels.
5. Browser audit confirms inline rendering, exact CSP hashes, zero remote
   requests, no severe console errors, and synchronized report filters.
6. Golden synthetic SVG contains all five visual treatments and the exact
   required non-causal/capability language.
7. Semantic regression asserts no execution edge for skipped/downloaded-only,
   neutral containment wording for skipped/environment-gated job records, no
   cloud-role edge for OIDC, no gate/secret eligibility for pending environment,
   no causal deployment wording, and no attempt merging.
8. Every visible node/edge maps to an existing graph identity; every edge has at
   least one valid full evidence ID.
9. Boundary tests cover each default/hard limit, explicit omissions, no dangling
   edges, and hard 8 MiB output.
10. Fuzz visual-model construction and encoding for panic freedom, bounded
    allocation, deterministic output, valid XML, and absence of active content.
11. Manifest tests cover valid, changed, missing, extra, symlinked, v0.1/v0.2
    raw-disabled cases, raw-enabled cases with zero and multiple objects, and
    descriptor/name/hash/tamper failures. Legacy unknown extras remain accepted
    but appear in terminal/structured verification with the exact bounded status
    above and are never content-parsed.
12. Manual accessibility checklist passes on the exact release candidate.
13. Replaying a retained v1 archive with an empty credential basis preserves
    findings, counts, source exposure facts, and archive bytes; uses
    `legacy-unclassified` only in the schema-valid presentation exposure; omits
    only the unclassifiable v2 edge,
    emits the distinct scoped projection notice in every presentation without
    changing UNKNOWN/finding/provenance/exposure/coverage counts or claiming the
    evidence itself is missing, and performs no network call.

## Prohibited language

The visual, legend, alt text, report, README, and sample site must not use these
phrases unless separately supported by direct evidence outside this projection:

- “attack path,” “compromise path,” or “blast radius” as the visual's name;
- “secret accessed/stolen/leaked/exfiltrated” from existence or mapping;
- “cloud role assumed,” “cloud compromised,” or “cloud reachable” from
  `id-token: write`;
- “runner compromised/persistent” from self-hosted classification;
- “deployment caused by the attacker” from event order;
- “safe” or “not compromised” from current tags, current YAML, missing logs, or a
  run merely falling outside an imprecise window;
- “executed” from download or preparation alone;
- “independently verified” for an internally generated SVG or manifest check.

The required neutral terms are “temporal evidence path,” “observed,” “supported
by,” “inferred,” “download demonstrated,” “step execution began,” “potentially
reachable,” “eligible,” “could mint,” “observed after,” “contradicts,” and
“evidence gap,” as the underlying relationship permits.
