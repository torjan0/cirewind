# CIRewind incident-pack specification

Status: implemented experimental-v0.1 `v1alpha1` contract
Planning date: 2026-08-20
Media type: `application/yaml` input; canonical JSON internal form
Maximum v0.1 pack size: 2 MiB

The local validator and synthetic pack are offline-tested. No real-world pack is
release-ready, and pack validation does not verify source truth. See
[IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md).

## Purpose

An incident pack is declarative incident knowledge. It tells CIRewind which repositories, paths, immutable identities, mutable references, time windows, and literal indicators are relevant, with provenance for each claim. It cannot execute code, select arbitrary network targets, or override evidence semantics.

Packs describe claims about an incident. They do not by themselves prove that a run downloaded or executed anything. The finding engine combines a validated pack with collected evidence under [EVIDENCE_MODEL.md](EVIDENCE_MODEL.md).

## Design principles

- Safe data, not detection programs.
- Exact immutable identities where primary sources provide them.
- Source precision and uncertainty are preserved, never rounded into false exactness.
- Indicator IDs, source IDs, component IDs, and window IDs are stable within an incident.
- A digest is meaningful only with a typed subject namespace and algorithm.
- Matching is deterministic, offline, and versioned.
- Unknown fields are rejected in v0.1 rather than ignored.
- A pack URL is provenance text; CIRewind never fetches it because a pack requested it.
- Pack confidence can cap but never raise finding provenance.
- Real incident packs contain only primary-source-verified values. Synthetic fixtures are unmistakably synthetic.

## Top-level structure

```yaml
apiVersion: cirewind.dev/v1alpha1
kind: GitHubActionsIncident
metadata:
  id: CIR-SYNTHETIC-0001
  packVersion: 1.0.0
  title: Synthetic mutable-tag fixture
  publishedAt: "2026-08-20T00:00:00Z"
  updatedAt: "2026-08-20T00:00:00Z"
  labels:
    - synthetic
  sources:
    - id: synthetic-lab-protocol
      type: synthetic-fixture
      title: CIRewind harmless lab protocol
      publisher: CIRewind test suite
      url: https://example.invalid/cirewind/synthetic-lab
      publishedAt: "2026-08-20T00:00:00Z"
      retrievedAt: "2026-08-20T00:00:00Z"
      sourceRevision: fixture-v1
      sourceSha256: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
      notes: This URL and digest are synthetic test data.
spec:
  description: Harmless synthetic data for testing a moved v1 tag.
  components:
    - id: harmless-action
      type: github-action
      repository:
        owner: cirewind-fixtures
        name: harmless-action
      subpaths:
        - ""
  windows:
    - id: synthetic-exposure
      start: "2026-08-19T10:00:00Z"
      end: "2026-08-19T11:00:00Z"
      bounds: "[)"
      sourcePrecision: second
      approximation: exact
      sourceRefs:
        - synthetic-lab-protocol
  indicators:
    - id: synthetic-compromised-commit
      componentId: harmless-action
      kind: action-commit
      value:
        gitObject:
          algorithm: sha1
          value: "1111111111111111111111111111111111111111"
      windowRefs:
        - synthetic-exposure
      confidence: L4_CERTAIN
      sourceRefs:
        - synthetic-lab-protocol
    - id: synthetic-mutable-ref
      componentId: harmless-action
      kind: mutable-action-ref
      value:
        ref: v1
      windowRefs:
        - synthetic-exposure
      confidence: L4_CERTAIN
      sourceRefs:
        - synthetic-lab-protocol
    - id: synthetic-action-package
      componentId: harmless-action
      kind: digest
      value:
        subject: github-action-package
        algorithm: sha256
        digest: "2222222222222222222222222222222222222222222222222222222222222222"
      windowRefs:
        - synthetic-exposure
      confidence: L4_CERTAIN
      sourceRefs:
        - synthetic-lab-protocol
  knownGood:
    - id: synthetic-known-good-commit
      componentId: harmless-action
      kind: action-commit
      value:
        gitObject:
          algorithm: sha1
          value: "0000000000000000000000000000000000000000"
      confidence: L4_CERTAIN
      sourceRefs:
        - synthetic-lab-protocol
  remediation:
    guidance:
      - Replace the synthetic mutable reference with the known-good fixture SHA.
    credentialRotationTriggers:
      - id: synthetic-direct-execution
        whenStates:
          - CONFIRMED_EXECUTED
        guidance: Rotate only fake lab credentials assigned to this fixture.
        confidence: L4_CERTAIN
        sourceRefs:
          - synthetic-lab-protocol
```

Every value above is synthetic. `example.invalid` is reserved for examples. The repeated hexadecimal values are not claims about a real repository, commit, package, or incident.

## Field definitions

### Envelope

| Field | Type | Required | Semantics |
| --- | --- | --- | --- |
| `apiVersion` | exact string | Yes | `cirewind.dev/v1alpha1`; selects schema and canonicalization rules |
| `kind` | exact string | Yes | `GitHubActionsIncident` |
| `metadata` | object | Yes | Stable identity, human context, versions, and sources |
| `spec` | object | Yes | Components, windows, indicators, known-good qualifiers, and remediation |

### Metadata

| Field | Type | Required | Validation |
| --- | --- | --- | --- |
| `id` | string | Yes | 3–100 ASCII characters, uppercase/lowercase letters, digits, `.`, `_`, `-`; globally stable, not display text |
| `packVersion` | semantic version string | Yes | Canonical SemVer without a leading `v`; immutable once published |
| `title` | plain UTF-8 string | Yes | 1–200 characters after NFC normalization; no control characters or HTML interpretation |
| `publishedAt` | RFC 3339 UTC instant | Yes | Must end in `Z`; source publication time, not incident start |
| `updatedAt` | RFC 3339 UTC instant | Yes | At or after `publishedAt` |
| `labels` | unique string array | No | Lowercase conservative token grammar; sorted canonically |
| `sources` | source array | Yes | At least one; IDs unique; every claim references one or more source IDs |

Descriptions, notes, and guidance are plain text. Renderers may apply a deliberately restricted CommonMark subset in a future schema, but v0.1 escapes and displays them as text. Embedded HTML is rejected or rendered inert; `javascript:` and other active links are never created.

### Source provenance

| Field | Required | Meaning |
| --- | --- | --- |
| `id` | Yes | Pack-local stable source key |
| `type` | Yes | `primary-advisory`, `github-advisory-database`, `source-repository`, `vendor-incident-report`, `government-advisory`, or `synthetic-fixture` |
| `title` | Yes | Plain source title |
| `publisher` | Yes | Source publisher/maintainer identity as text |
| `url` | Yes | HTTPS provenance locator, or `https://example.invalid/...` for fixtures; never fetched during validation/evaluation |
| `publishedAt` | When known | Source's stated publication instant and precision in `timePrecision` if not exact |
| `retrievedAt` | Yes | UTC collection time used by pack reviewer |
| `sourceRevision` | When available | Git commit, advisory revision, release, or snapshot identifier |
| `sourceSha256` | When a stable snapshot is archived | SHA-256 of reviewed source bytes, not of a secret or credential |
| `timePrecision` | No | `second`, `minute`, `hour`, `day`, or `unknown`; applies to the source timestamp |
| `notes` | No | Plain explanation of conflicts or limitations |

A marketing page may be supplemental, but it is not sufficient attribution for a compromised SHA, digest, or exact exposure boundary when a primary advisory/repository record exists. Each indicator carries its own `sourceRefs`; top-level sources do not implicitly support every indicator.

### Components

Each component defines a normalized subject, not an indicator by itself.

| Field | Required | Semantics |
| --- | --- | --- |
| `id` | Yes | Pack-local stable key |
| `type` | Yes | `github-action`, `reusable-workflow`, `embedded-tool`, or `repository` |
| `repository.owner` | Yes | GitHub owner; matched case-insensitively while preserving original |
| `repository.name` | Yes | GitHub repository name; matched case-insensitively |
| `repository.id` | No | Immutable GitHub numeric repository ID when primary evidence verifies it |
| `subpaths` | No | Unique normalized repository-relative paths; empty string means repository root; path comparison is case-sensitive |
| `workflowPaths` | Required for reusable workflow | Exact `.github/workflows/*.yml` or `.yaml` paths |
| `aliases` | No | Historical owner/name pairs with their own source attribution; never inferred from redirects |

Paths use `/`, contain no empty interior segment, `.`, `..`, backslash, NUL, percent-encoded traversal, or leading slash. A subpath identifies where an Action definition lives; it is not a filesystem extraction target.

### Exposure windows

Windows are component/indicator-specific. One incident-wide interval is not assumed.

| Field | Required | Semantics |
| --- | --- | --- |
| `id` | Yes | Unique stable window ID |
| `start` | Yes unless source has no lower bound | UTC RFC 3339 string |
| `end` | Yes unless source has no upper bound | UTC RFC 3339 string later than `start` |
| `bounds` | Yes | One of `[)`, `[]`, `()`, `(]`; exactly preserves source/reviewer boundary inclusivity |
| `sourcePrecision` | Yes | `second`, `minute`, `hour`, `day`, or `unknown`; precision of the underlying claim, not merely string syntax |
| `approximation` | Yes | `exact`, `source-rounded`, `conservative-expanded`, or `unknown` |
| `originalClaim` | Required unless `exact` | Plain source wording or concise faithful paraphrase; not used as executable logic |
| `sourceRefs` | Yes | Sources supporting the endpoints/uncertainty |
| `notes` | No | Reviewer rationale for any conservative expansion |

The engine compares timestamps according to `bounds`; it does not invent seconds. A date-level advisory may be represented with explicit UTC endpoints selected by reviewers, `sourcePrecision: day`, and `approximation: conservative-expanded`. That reduced precision caps provenance and is visible in reports. An unbounded or unknown interval is allowed only when the indicator kind can be evaluated without promoting a time-window state; it cannot support `RUN_IN_WINDOW_MUTABLE_REF` at `L3_STRONG` or `L4_CERTAIN`.

Each match records which timestamp kind was tested: parsed preparation time, parsed step-begin time, job start, run start, or run creation. A proxy timestamp reduces provenance.

### Indicators

Every indicator has:

| Field | Required | Meaning |
| --- | --- | --- |
| `id` | Yes | Unique pack-local stable key |
| `componentId` | Usually | Component being described; omitted only for standalone network/log IOCs with an explicit scope |
| `kind` | Yes | One of the closed v0.1 kinds below |
| `value` | Yes | Kind-specific structured object; never an untyped scalar |
| `windowRefs` | When time-dependent | One or more component windows; union semantics, each preserved separately |
| `confidence` | Yes | `L4_CERTAIN`, `L3_STRONG`, `L2_PROBABLE`, `L1_POSSIBLE`, or `L0_UNKNOWN`, describing confidence in the incident claim |
| `sourceRefs` | Yes | One or more supporting source IDs |
| `notes` | No | Plain qualification; no matching behavior |

Pack confidence is not finding provenance. A finding's provenance is no higher than the weakest material incident claim and runtime derivation input.

#### Closed v0.1 indicator kinds

| Kind | Required `value` fields | Match semantics |
| --- | --- | --- |
| `action-commit` | `gitObject.algorithm`, `gitObject.value` | Full typed Git object ID; exact repository/subpath from component |
| `reusable-workflow-commit` | `gitObject.algorithm`, `gitObject.value`, optional exact `path` | Full typed Git object ID plus called workflow path |
| `mutable-action-ref` | `ref` | Exact Git ref text after syntax validation; only within referenced windows |
| `mutable-workflow-ref` | `ref`, exact `path` | Exact reusable-workflow ref and path within window |
| `digest` | `subject`, `algorithm`, `digest`, optional `path`, `platform` | Exact typed digest; no matching across subject namespaces |
| `log-literal` | `literal`, `caseSensitive`, `scope` | Bounded literal byte/text search only in retained eligible log material |
| `domain` | `domain`, `match` | Canonical IDNA ASCII exact host, or explicit `subdomains` mode; no regex/glob |
| `ip-address` | `address` | Canonical IPv4/IPv6 exact address; v0.1 does not accept arbitrary ranges unless a later schema adds a typed CIDR kind |
| `repository-name` | `owner`, `name`, optional `path` | Exact normalized GitHub repository identity IOC |
| `release-version` | `version` | Exact component version string; not ordered semantically unless a later typed range kind exists |

Allowed digest subjects are closed and typed:

- `github-action-package`
- `executable-file`
- `oci-manifest`
- `release-asset`
- `workflow-artifact`

Allowed v0.1 algorithm is `sha256`. A GitHub immutable Action package digest matches only `github-action-package`; it must not match an executable or OCI digest with the same hex value. The archived observation retains GitHub's source commit SHA and package version as separate fields.

The YAML wire name `value.digest` maps to the normalized domain field `{subject, algorithm, value}`. This spelling difference is explicit; it never permits a digest to become an untyped string.

`log-literal.scope` is one of `runner-control`, `setup`, `step`, or `any-retained-log`. Default compact archives normally preserve structured runner-control observations, not arbitrary log text. Replaying a new `log-literal` against material that was not archived yields `UNKNOWN_EVIDENCE_GAP`; it does not yield no match. Raw-log opt-in can provide broader future literal replay at a privacy cost.

No regular-expression indicator is supported in `v1alpha1`. A later schema may add a linear-time engine, anchored syntax subset, pattern-length cap, and compile/match budgets, but it must not silently reinterpret v0.1 packs.

### Known-good identities

`knownGood` uses the same ID/component/kind/value/confidence/source structure as immutable indicators but is a qualifier, not a negative incident match. It supports responder context and contradictions. Rules:

- Only immutable `action-commit`, `reusable-workflow-commit`, and typed `digest` are allowed.
- An identity cannot be both affected and known-good for the same component/namespace. Validation rejects the pack.
- A current tag resolving to a known-good commit does not negate historical runtime evidence of an affected commit.
- A known-good identity with weaker provenance never suppresses a stronger affected identity.

### Remediation and credential-rotation triggers

`remediation.guidance` is a list of plain-text recommendations with no commands that CIRewind will execute. Shell-looking text is rendered inert.

Each rotation trigger has a stable ID, one or more normative finding states, optional closed-schema exposure predicates, plain guidance, confidence, and one or more source references. All except exposure predicates are required. It is a recommendation rule only. CIRewind never retrieves or rotates credentials and never runs a command from guidance.

Only these finding state strings are valid:

- `CONFIRMED_EXECUTED`
- `CONFIRMED_DOWNLOADED`
- `CONFIRMED_CALLED_WORKFLOW`
- `DECLARED_AT_RUN_SHA`
- `RUN_IN_WINDOW_MUTABLE_REF`
- `POTENTIAL_TRANSITIVE`
- `CURRENT_REFERENCE_ONLY`
- `NO_MATCH_CONFIRMED`
- `UNKNOWN_EVIDENCE_GAP`
- `CONTRADICTORY_EVIDENCE`

## Indicator-to-evidence semantics

The pack matcher emits an indicator match, not a finding state. The semantic engine applies the evidence rules:

| Incident claim plus case evidence | Maximum applicable state before contradiction/gap rules |
| --- | --- |
| Affected exact Action source ID/digest observed in same-attempt runtime resolution plus a uniquely mapped lifecycle-begin observation | `CONFIRMED_EXECUTED` |
| Affected exact Action source ID/digest plus completed runner preparation, without correlated lifecycle-begin evidence | `CONFIRMED_DOWNLOADED` |
| Affected exact reusable-workflow SHA in GitHub attempt metadata | `CONFIRMED_CALLED_WORKFLOW` |
| Historical definition at its evidenced commit declares the affected immutable identity, no runtime resolution | `DECLARED_AT_RUN_SHA` |
| Historical definition declares an affected mutable ref and the relevant evidenced/proxy timestamp is in a declared window | `RUN_IN_WINDOW_MUTABLE_REF` |
| Reviewed dependency chain reaches affected component without exact runtime identity | `POTENTIAL_TRANSITIVE` |
| Only collection-time/current workflow or ref state matches | `CURRENT_REFERENCE_ONLY` |
| All indicator-relevant coverage complete and no match | `NO_MATCH_CONFIRMED` |
| A material required coverage unit is unavailable | `UNKNOWN_EVIDENCE_GAP` |
| Material evidence propositions disagree | `CONTRADICTORY_EVIDENCE` |

The exact precedence and promotion prohibitions are normative in [EVIDENCE_MODEL.md](EVIDENCE_MODEL.md). Indicator confidence and approximate windows may lower provenance within the `L4_CERTAIN` through `L0_UNKNOWN` ladder but cannot substitute for a weaker semantic state.

## Matching normalization

- Owner/repository names: Unicode is rejected for pack identifiers in v0.1; ASCII is compared case-insensitively and stored in lowercase canonical form.
- Repository paths and workflow paths: UTF-8 NFC, `/` separators, case-sensitive, no path traversal.
- Git refs: NFC, no control/NUL, no `@{`, backslash, leading/trailing slash, repeated slash, or other `git-check-ref-format`-invalid forms; comparison is exact and case-sensitive.
- Git commit objects: `{algorithm, value}` is required. v0.1 accepts `sha1` with exactly 40 hexadecimal characters and `sha256` with exactly 64, normalizes hex to lowercase, and rejects abbreviations/unknown algorithms. The algorithm is part of identity. Git object SHA-256 is never interchangeable with a package/file digest that happens to use SHA-256.
- Digests: lowercase canonical hex of the algorithm's exact length; algorithm and subject are part of identity.
- Domains: IDNA ASCII form, lowercase, no URL/path/port/userinfo; exact/subdomain behavior must be explicit.
- IP: standard library canonical address; IPv4-mapped IPv6 normalization policy is fixed by validator tests.
- Literals: valid UTF-8, 1–4,096 bytes, no NUL, terminal escape, or newline; exact bytes after documented line-ending normalization. Case-insensitive matching is Unicode-simple-fold only if tests prove stable behavior; otherwise v0.1 requires `caseSensitive: true`.
- Arrays representing sets are deduplicated and sorted in canonical form. Source order is not matching precedence.

## Deterministic safe validation

Validation is a pure function of pack bytes, schema version, and validator policy version.

### Parse limits

- At most 2 MiB input bytes, one UTF-8 document, no BOM.
- At most 20,000 YAML nodes, nesting depth 32, 5,000 mapping entries, 5,000 sequence entries, 64 KiB per scalar, and the tighter field limits above.
- Anchors, aliases, merge keys, custom tags, duplicate keys, multiple documents, non-string mapping keys, NaN/infinity, and implicit timestamp coercion are rejected.
- Every timestamp is a quoted string and parsed explicitly.
- Unknown fields and unknown enum values are errors.
- Parser cancellation and CPU budget are enforced.

### Semantic validation order

1. Enforce byte/encoding/document limits before constructing the full graph.
2. Build a location-preserving AST and reject unsafe YAML features/duplicates.
3. Validate exact envelope and field types with closed enums.
4. Normalize values while retaining original text for diagnostics.
5. Check unique IDs and all component/window/source references.
6. Check timestamp ordering, explicit bounds, precision, and approximation explanations.
7. Check typed full Git object IDs, typed digest length/namespace, paths, refs, domains, IPs, and literal limits.
8. Require source attribution for every indicator, known-good identity, window, and rotation trigger.
9. Reject affected/known-good conflicts, duplicate normalized indicators, empty components, and ambiguous overlapping claims that assign incompatible semantics.
10. Produce canonical JSON with sorted object keys/set arrays and hash it with SHA-256.
11. Return all deterministic diagnostics in source-location order; never fetch source URLs.

Validation success means structurally safe and internally consistent. It does not certify incident truth. Reports must display pack ID/version/hash and validation policy.

## Canonicalization and stable identity

The canonical pack hash is SHA-256 over canonical JSON after schema-defined normalization. It is not a signature. The original YAML byte hash is also retained because comments and source spelling are excluded from canonical JSON.

The pack-instance indicator identity is `pack canonical hash + indicator ID`. The logical `finding_id` remains stable across reviewed pack updates for the same incident/API-schema-major/indicator/subject/proposition; “API-schema major” is the major encoded by `apiVersion` (for example, `v1` in `cirewind.dev/v1alpha1`), not the major component of `metadata.packVersion`. The exact pack hash participates in the append-only `finding_revision_id`. This permits a corrected source or window to create a traceable revision rather than silently replacing a proposition.

Changing a source, window, affected identity, known-good identity, or rotation trigger requires a new `packVersion` and canonical hash. Whitespace/comment-only edits change the original-byte hash but not the canonical hash.

## Schema-version policy

- `apiVersion` controls syntax and semantics. v0.1 supports only `cirewind.dev/v1alpha1`.
- Alpha schemas may change incompatibly. A validator must reject unsupported versions and provide no best-effort interpretation.
- `metadata.packVersion` versions the incident data independently. Any semantic change increments it; previously published versions remain immutable.
- Patch pack versions may correct prose/source locators without changing indicator semantics only if the canonical data change is reviewed and release notes state it.
- Adding an optional field to an alpha schema still requires a validator/tool release because unknown fields are rejected.
- A future stable schema must ship an explicit, testable migration/canonicalization tool. CIRewind never silently rewrites an old pack during investigation.
- Replay records both original and canonical pack hashes plus schema/validator versions, so later tools can reproduce the exact interpretation.

## Community pack review

### Submission requirements

- DCO sign-off and Apache-2.0-compatible contribution rights for the pack text/fixtures.
- One incident per stable ID, immutable versioned file, schema validation, canonical hash, and changelog entry.
- Primary-source URL/revision/retrieval date for every immutable identity and exposure boundary.
- No compromised SHA, digest, ref window, domain, or IP copied only from an unsourced secondary list when a primary source can be obtained.
- Deterministic positive, negative, boundary, contradiction, and evidence-gap fixtures using synthetic repositories/run data.
- No secret values, leaked customer data, payload code, executable snippets, or instructions CIRewind could run.
- A source-conflict note when primary sources disagree; disputed values remain excluded or explicitly lower confidence until resolved.

### Maintainer review

1. Automated safety/schema/canonicalization tests.
2. Mechanical cross-check of every indicator against pinned source revision/snapshot.
3. Independent reviewer verifies time precision, boundary semantics, repository/subpath, digest namespace, and known-good status.
4. Security reviewer checks that literals/guidance cannot trigger output or terminal injection and that no sensitive data entered fixtures.
5. At least two maintainer approvals for real incident data; one must reproduce immutable identities from primary sources.
6. Merge preserves DCO. Pack release records Git commit, YAML byte hash, canonical hash, reviewer identities, and tool schema version.

Pack signing/index distribution is a post-v0.1 question. In v0.1, users trust the local file and its reviewed repository provenance; CIRewind reports hashes but does not claim authenticity.

## Real-pack verification requirements

The intended initial incidents are research targets, not preapproved pack contents:

- tj-actions/changed-files, March 2025.
- Reviewdog transitive compromise, March 2025.
- Trivy ecosystem compromise, March 2026.
- Xygeni mutable-tag compromise, 2026.

No real pack should be created until [research/INCIDENT_SOURCE_NOTES.md](research/INCIDENT_SOURCE_NOTES.md) blockers are resolved. As of the planning review:

- Primary sources conflict on the first patched tj-actions/changed-files version.
- Reviewdog wrapper-to-transitive-version mappings require exact historical metadata verification.
- Trivy's large IOC tables require deterministic mechanical extraction plus human review and typed digest assignment.
- The Xygeni timeline is approximate/date-level and must not be represented as exact seconds.

When a source provides only a range, prefix, tag, or approximate date, the pack must preserve that uncertainty. It must not fabricate a full compromised SHA or precise exposure instant.

## Forward compatibility

- Readers reject unknown `apiVersion`, fields, kinds, digest subjects, and matching modes.
- New indicator behavior requires a new schema version; new source/prose metadata can be introduced only with an explicit compatibility decision.
- Machine output preserves unknown packs as opaque evidence if importing a newer case, but does not evaluate them.
- Stable IDs are never recycled across different incidents or indicators.
- Future signatures wrap canonical hash and release metadata; signature bytes do not alter indicator identity.
- Future cloud-trust indicators belong to a separate typed schema section and cannot reinterpret `id-token: write` as role reachability.

## Prohibited pack content and behavior

- Executable scripts, binaries, serialized objects, wasm, macros, or plugins.
- Shell, PowerShell, JavaScript, Go templates, expression languages, or arbitrary commands as evaluator input.
- Pack-directed HTTP/DNS/Git/API requests, webhooks, callbacks, or include/import URLs.
- Embedded HTML, SVG, CSS, active links, data URLs, or remote report assets.
- Unrestricted regular expressions, globs that cross repository/path semantics, or user-defined matching code.
- Secret values, hashes of secret values, authentication headers, cookies, signed URLs, or leaked application output.
- Short commit SHAs presented as exact, untyped digests, ambiguous local times, or silently inclusive boundaries.
- Instructions that mutate repositories, rotate credentials, or contact third parties automatically.

## Pack-related evidence

Each case records:

- Original local path as a sanitized display value, not a trust signal.
- Original bytes SHA-256 and byte length.
- Canonical JSON SHA-256 and canonicalizer version.
- Schema/validator version, validation time, diagnostics, and validation policy/limit hash.
- Metadata source provenance exactly as declared.
- Analysis session and every indicator ID that supported a finding.
- Whether the pack came from a bundled release, explicit local file, or another user-selected source.

This supports review and repeatability without claiming a hash is a signature or that a valid pack is factually correct.
