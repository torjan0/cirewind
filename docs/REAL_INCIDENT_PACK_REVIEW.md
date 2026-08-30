# Real incident-pack review protocol

Status: accepted v0.2 governance and review-data contract as of 2026-08-22.

This protocol applies only to real incident packs. Synthetic fixtures continue
to use the existing incident-pack schema and unmistakably synthetic provenance.
Nothing in this document marks any current candidate reviewed.

## Governing principle

An incident pack is a versioned set of claims used for matching. It is not
evidence that a particular workflow downloaded or executed an Action, and
`cirewind pack validate` proves deterministic schema/safety conformance—not
factual truth.

Real incident intelligence must be independently falsifiable. Every material
field is mapped to primary sources, every conflict and approximation remains
visible, and human approval binds to exact pack bytes. Automated tooling may
prepare, compare, and validate a packet; it can never approve factual content or
count as an independent reviewer.

The canonical finding states, provenance levels, derivation rules, and mandatory
invariants do not change when a pack becomes reviewed.

## Status model

Review status is governance metadata outside
`cirewind.dev/v1alpha1`. It must not be added to the pack in a way that lets pack
authors assert their own trust state.

| Status | Meaning | Distribution rule |
|---|---|---|
| `research` | Source leads and unresolved notes; no valid candidate is asserted. | Research directory only; never offered to users as a pack. |
| `candidate` | Pack validates and has a complete author-side packet, but required human approvals are incomplete. | Candidate directory only; excluded from releases, sample commands, reviewed index, and adoption claims. |
| `review_in_progress` | Exact candidate hash is under human review. | Same restrictions as `candidate`. |
| `reviewed` | Exact original and canonical hashes have all required current approvals and tests. | Eligible for reviewed directory and release consideration; not automatically shipped. |
| `superseded` | A newer reviewed pack version replaces it without deleting history. | Retained and indexed as historical. |
| `withdrawn` | Factual, safety, licensing, or provenance concern makes the version unsuitable. | Retained as a tombstone/record; pack bytes are not promoted or advertised. |

Allowed transitions are:

```text
research -> candidate -> review_in_progress -> reviewed -> superseded
                    \-> withdrawn
review_in_progress -> candidate        (approval failed or became stale)
reviewed -> withdrawn                   (post-review defect; never erase history)
superseded -> withdrawn                 (later defect; retain supersession history)
```

Any material pack change after an approval returns the new content to
`candidate`, increments `metadata.packVersion`, and requires new approvals.
Whitespace/comment-only changes that preserve the canonical hash still change
the original byte hash and therefore require an explicit reviewer determination
and new byte-level approval record before promotion.

## Directory and packet layout

The intended repository layout is:

```text
incidents/
  synthetic/
  candidates/
    INCIDENT_ID/
      PACK_VERSION.yaml
  reviewed/
    INCIDENT_ID/
      PACK_VERSION.yaml
review-packets/
  INCIDENT_ID/
    PACK_VERSION/
      candidate-content/
        pack.yaml
        packet.json
        review-policy.json
        claims.json
        sources.json
        conflicts.json
        expected-findings.json
        validation.json
        fixtures/
        candidate-content-manifest.sha256
      approvals/
        REVIEW_ID/
          review.json            # canonical machine-readable record
          REVIEW.md              # deterministic rendering of review.json
      platform-approvals.json    # normalized external GitHub observation
      promotion-record.json       # created only during promotion
      review-record-manifest.sha256
pack-review-policy.json
review-registry.json
```

Paths are generated from separately validated safe IDs, never from untrusted
titles, repository names, URLs, or arbitrary pack fields. Candidate and reviewed
directories are physically separate. Promotion copies the exact approved bytes;
it does not regenerate or normalize YAML.

The packet, retained policy, source, claim, conflict, pre-review assertion,
approval, normalized platform snapshot, promotion, and registry records have
closed versioned JSON schemas in
`schema/`, backed by strict typed decoding. Unknown and duplicate keys, trailing
values, unsafe text, unsafe paths, and over-limit content are rejected. JSON
records used as hash inputs must be in deterministic canonical form. The typed
candidate validation record and expected-finding oracle are strictly decoded
against closed schemas and must use canonical JSON. Markdown is explanatory only
and cannot override JSON status, conflicts, or claims.

No packet contains executable scripts, payload code, arbitrary regular
expressions, secret values, customer evidence, authentication material, embedded
HTML, templated requests, or a URL that validation follows automatically.

## Repository-maintainer tooling surface

The governance workflow is repository-maintainer tooling, not a new public
`cirewind` CLI surface in v0.2. The shipped CLI retains only
`cirewind pack validate PACK.yaml`, whose success means schema and safety
conformance. Review/promotion operations are implemented as a reviewed,
network-disabled Go tool at `tools/packreview` with thin Make targets; release
archives and install documentation do not advertise it as an end-user command.

The tool has these closed operations:

| Operation | Required input | Output/mutation |
|---|---|---|
| `validate-unit` | review-unit root and expected candidate commit C | Canonical validation JSON on stdout; no writes. |
| `build-candidate-manifest` | immutable `candidate-content/` root and explicit output path inside it | Atomically creates/replaces only `candidate-content-manifest.sha256`; never edits reviewed content. |
| `build-fixture-manifest` | immutable `candidate-content/fixtures/` root and its fixed manifest path | Atomically creates/replaces only `fixtures/manifest.sha256`; never executes or retrieves fixture content. |
| `render-review` | canonical human-supplied `review.json` and fixed sibling output path | Atomically renders only `REVIEW.md`; it does not create or change an approval decision. |
| `render-review-body` | canonical human-authored pre-review assertion | Emits only the exact fixed ASCII body that the human may submit with a GitHub review; it does not synthesize assertion fields, create a review, or write a file. |
| `normalize-platform-approvals` | bounded local JSON projected from GitHub's list-reviews endpoint plus caller-supplied exact C, workflow-source commit, and run context | Atomically writes only fixed-name `platform-approvals.json`; accepts no credential, performs no network request, and creates no approval. |
| `check-approvals` | review-unit root, C, candidate-manifest hash, and normalized platform snapshot | Canonical policy result on stdout; no approval creation and no writes. |
| `promote` | caller/CI-verified worktree with `HEAD == C`, only explicitly allowlisted post-approval review inputs, exact current root review policy, exact approval files and normalized platform snapshot, and explicit promotion time | Rejects a candidate whose retained policy is stale, then copies the byte-identical approved pack and writes the promotion record/review-record manifest; never commits, pushes, tags, or edits the registry. |
| `validate-candidate-tree` | repository root plus externally supplied exact `HEAD` C | Validates all retained review units: registered history uses its recorded C, unregistered content uses supplied C, active unpromoted content must match current policy, and completed history retains its recorded policy; no writes or factual-review claim. |
| `validate-governance` | repository root | Validates the canonical review policy, append-only registry, reviewed-tree closure, and retained review units named by registry history; permits honestly empty pre-review state and unregistered candidate-C content awaiting later registry history, and makes no factual-review claim. |
| `verify-registry` | repository root and registry entry/commit P being checked | Canonical verification result on stdout; no writes. |

Every operation rejects unknown flags, unexpected files, symlinks and special
files in bounded trees, hash drift, unsafe IDs and paths, and over-limit fields.
It performs no network request, process execution, Git credential lookup,
commit, push, or approval generation. Exit status `0` means the requested
deterministic operation succeeded, `2` means bounded validation/policy failure,
`1` means a sanitized operational failure, and cancellation maps to `130`.
Diagnostics identify JSON-pointer/file paths without source contents or host
secrets. Make targets are aliases only; JSON schemas and this table are the
contract.

Git state is deliberately outside the core tool's trust boundary. The tool
accepts C and P as externally supplied full commit identities and checks the
content and records bound to them, but it does not invoke Git and cannot prove
that `HEAD` equals either identity or that protected history has not moved. The
fixed `scripts/pack-review-git-guard.sh` wrapper verifies the exact worktree
root and full expected `HEAD`, then rejects every staged, unstaged, and untracked
path outside an explicit maintainer-controlled allowlist. With no allowlist the
worktree must be clean. Rename detection is disabled so both delete and add
paths remain visible; ignored untracked material and gitlink/submodule changes
are included rather than silently disappearing. Arguments derived from a pack,
log, fixture, or other hostile input must never control that allowlist.

The lifecycle necessarily has two different Git-state checks. Candidate
validation and human review operate on clean exact commit C. Candidate CI must
run `validate-candidate-tree` with externally supplied exact `HEAD` C. It
validates every retained review unit, using registry-bound C for existing history
and the supplied `HEAD` for unregistered candidate content. An unregistered
candidate is valid at C: requiring the registry in C to name C would create an
impossible commit self-reference. The append-only registry may first record C
only in a later commit.

After qualifying humans approve C on GitHub, the normalized platform snapshot
and human review records are materialized on a promotion branch whose `HEAD` is
still C; only their fixed review-record destinations may be allowlisted as dirty
inputs. The promotion output is then committed as P. A later clean registry
commit names P without naming itself and revalidates the retained snapshot,
approval policy, review-unit identity, reviewed bytes, and manifests. A
successful core-tool or Git-guard result is structural evidence only, not
promotion authorization or a claim that the incident facts are true.

The limits are intentionally narrower than the general case format: individual
review JSON files are bounded to 16 MiB with JSON depth at most 64; manifested
regular files are bounded to 64 MiB each, 256 MiB total, 2,000 files, and 16
path components; approval directories are bounded to 100. Repository-level
governance walks also impose global entry, file, incident, version, and depth
bounds and reject empty or symlinked tree shapes. The fixed file and
path allowlists reject archive-like expansion, links, device files, active
fixture content, credential-like material, and case-folded path collisions.
Crossing a limit is a recorded validation failure, not permission to truncate or
silently omit review material.

## Immutable candidate content and manifests

`candidate-content/` is the immutable review unit. `pack.yaml` is byte-identical
to the corresponding candidate pack, and `packet.json` describes only immutable
content:

| Field | Requirement |
|---|---|
| `schemaVersion` | Closed review-packet schema, initially `cirewind.review-packet/v1alpha1`. |
| `incidentId` | Exactly equals pack metadata ID. |
| `packVersion` | Exactly equals pack metadata pack version. |
| `reviewUnitPackPath` | Fixed value `pack.yaml`; no candidate/reviewed promotion path. |
| `originalPackSha256` | SHA-256 of exact YAML bytes. |
| `canonicalPackSha256` | Validator-produced canonical JSON SHA-256. |
| `packSchemaVersion` | Exact `apiVersion`. |
| `validatorVersion` | Closed incident-validator policy version; unsupported retained versions fail rather than silently using current rules. |
| `validatorPolicySha256` | Hash identifying safety/semantic limits. |
| `reviewPolicySha256` | Hash of the canonical `review-policy.json` retained inside candidate content. |
| `claimsSha256` | Hash of canonical claims file. |
| `sourcesSha256` | Hash of canonical source ledger. |
| `conflictsSha256` | Hash of the authoritative structured conflict ledger. |
| `expectedFindingsSha256` | Hash of deterministic test oracle. |
| `fixtureManifestSha256` | Hash of the synthetic fixture manifest. |
| `conflictIds` | Sorted conflicts that remain relevant. |

`packet.json` contains no candidate commit, review status, promotion path,
approval list, reviewer decision, or self-hash. This avoids data that would have
to change after review or depend on the Git commit containing itself.

`candidate-content-manifest.sha256` covers every regular material file below
`candidate-content/` except itself, including its retained
`review-policy.json`, with canonical sorted relative paths. The
candidate is frozen in Git commit C after this manifest is generated. Human
approvals created in later commits bind both C and the SHA-256 of the exact
candidate-content manifest bytes. Nothing below `candidate-content/` may change
after approval; any change creates a new review unit and makes every old approval
inapplicable.

Approvals are deliberately outside the candidate-content manifest so there is
no approval/manifest hash cycle. At promotion,
`review-record-manifest.sha256` covers the finalized approval records, retained
`platform-approvals.json`, and `promotion-record.json`, excluding itself. The
promotion record binds C, the candidate-content manifest hash, exact pack hashes,
the SHA-256 of the retained normalized platform snapshot, reviewed destination,
approval IDs, promotion time, and resulting status; it does not contain the hash
of the Git commit that contains it. A later append-only registry commit records
the prior promotion content commit P and references that review-record manifest.
Registry verification reruns approval-policy checks against the retained
snapshot rather than trusting the promotion record's approval list. The registry
never records its own containing commit. Neither approvals nor candidate content
recursively hash the registry or a manifest that includes them. These manifests
provide integrity support, not signatures or independent factual review.

## Primary-source requirements

Material facts use this hierarchy:

1. affected-project maintainer security advisory or incident report;
2. immutable repository objects and exact GitHub API responses, including full
   commits, tag objects with observation time, signed releases, package metadata,
   and digests;
3. a GitHub-reviewed Advisory Database record pinned to an exact database commit;
4. government advisory or original researcher's technical report as
   corroboration or for an indicator explicitly adopted by the maintainer;
5. secondary reporting only as a lead, never the sole authority for a
   compromised SHA/digest, affected ref, window, known-good identity, IOC, or
   impact claim.

Every source is re-retrieved during candidate preparation; the 2026-08-20
[`INCIDENT_SOURCE_NOTES.md`](research/INCIDENT_SOURCE_NOTES.md) ledger is a lead
and conflict inventory, not authority to copy a value without revalidation.

The review tool does not fetch a URL from pack or packet content. A researcher
explicitly retrieves a source, records provenance, and supplies bounded local
bytes to an offline hashing/extraction command. Redirect chains, request headers,
and credentials are never retained. Full source snapshots are committed only
after copyright, license, privacy, and size review; otherwise retain stable
locators, immutable revisions, hashes, and a minimal lawful excerpt or faithful
paraphrase.

## Source ledger

Every `sources.json` entry contains:

- stable source ID;
- source class and publisher;
- title and HTTPS locator;
- publication/update time and stated precision when known;
- retrieval time in UTC;
- immutable source revision/object ID when available;
- media type and reviewed-byte length;
- SHA-256 of the exact reviewed source object;
- archival location, or explicit reason the bytes are not redistributed;
- license/redistribution assessment;
- relationship to superseded source revisions;
- bounded notes and conflict IDs.

A live mutable page without a recorded revision and reviewed-byte hash may guide
research but cannot alone support a material reviewed field.

## Source-to-field claim matrix

`claims.json` contains one row per material scalar, list member, structured IOC,
window endpoint, and semantic omission decision. A top-level source list never
implicitly supports every indicator.

Required row fields are:

| Field | Meaning |
|---|---|
| `claimId` | Stable ID within incident/version. |
| `canonicalPointer` | RFC 6901 JSON Pointer into the frozen canonical pack for a present value; array indices are valid because the canonical bytes are hash-bound. `null` for a deliberate omission. |
| `semanticSelector` | Stable semantic identity across ordering, such as `indicator:<id>/field:<name>` or `component:<id>/window:start`. |
| `omittedSlot` | Closed field/indicator slot intentionally omitted, with `canonicalPointer: null`; absent for present values. |
| `normalizedValue` or `valueSha256` | Exact normalized value, or hash when repeating sensitive-by-policy text is unnecessary. No secret value is allowed. |
| `semanticRole` | Component, subpath, ref, compromised SHA, package digest, known-good SHA, window, literal, IOC, remediation, rotation trigger, or other closed role. |
| `sourceIds` | One or more source-ledger IDs directly supporting this field. |
| `sourceLocations` | Stable section/line/object-pointer locators within each source. |
| `transformation` | `verbatim`, `normalized`, `mechanically-extracted`, or `reviewer-derived`. |
| `sourcePrecision` | `second`, `minute`, `hour`, `day`, or `unknown` where temporal. |
| `approximation` | `exact`, `source-rounded`, `conservative-expanded`, or `unknown`. |
| `derivation` | Deterministic normalization/expansion description; required unless verbatim. |
| `conflictIds` | Every primary-source disagreement touching the value. |
| `authorAssessment` | Inclusion, omission, or blocked, with bounded rationale. |

The matrix also records deliberate omissions such as “known-good identity
excluded because primary sources disagree.” This prevents a later contributor
from treating absence as an overlooked field. Reviewer decisions never mutate
`claims.json`; they live only in approval and promotion records.

Validation derives a typed material inventory from the canonical incident pack
instead of trusting the author to declare what is material. The inventory
includes matching identities and namespaces, component repositories and
subpaths, window endpoints and precision, mutable refs, full Git objects,
immutable package digests, known-good identities, literal/contextual IOCs,
remediation guidance, and credential-rotation triggers. Every present material
scalar must have exactly one correctly value-bound claim row; each supported
omission must use a closed omission slot whose selector resolves to a semantic
slot that is actually absent from that exact pack. Component subpath, affected
ref, known-good identity, immutable package digest, window endpoint, IOC,
remediation-guidance, and credential-rotation omissions are the only supported
classes. A role/slot mismatch, an omission selector for a present value, or an
absent window endpoint whose source precision/approximation is strengthened is
rejected. Source references and source locations must close in both directions,
conflict links must be symmetric, orphan sources are rejected, and a critical
matching claim cannot rely only on a secondary lead. This structural closure
establishes traceability, not the truth of the underlying source or the soundness
of a human interpretation.

## Identity and time rules

- A Git commit indicator states its algorithm and uses the complete lowercase
  object ID; abbreviated or algorithm-less values are rejected.
- Package digests retain algorithm and subject namespace. A digest for an image,
  release archive, or immutable Action package is not interchangeable.
- Repository identity and affected subpath are explicit. A repository-level
  claim is not applied to unrelated Action subpaths.
- Every mutable ref has a component-specific window. A tag name is never a
  timeless compromised identity.
- Source timezone, boundary inclusivity, and precision are retained. Date- or
  minute-level claims are not rendered as exact seconds.
- `conservative-expanded` endpoints name the expansion policy, original claim,
  and reviewer decision. They cap provenance as defined by the pack spec.
- Known-good identities receive independent source/object review. “Patched
  version” alone is insufficient when a tag could have moved.
- A wrapper commit is not placed in `compromisedSHAs` merely because its metadata
  referenced an affected nested Action.
- Broad domains/common strings remain contextual IOCs and cannot independently
  establish high-confidence run execution.

## Conflict handling

Every conflict has an ID, affected claim IDs, all competing source IDs, a neutral
description, materiality, and disposition:

- `excluded`: omit the disputed value;
- `encoded-uncertain`: represent source precision/approximation exactly where the
  current schema can do so safely;
- `resolved`: human reviewers select a value with documented primary-source
  rationale;
- `blocking`: no reviewed pack may be produced.

Sources are never averaged, silently prioritized, or converted into a wider
unlabeled window. If a conflict affects match scope and cannot be represented
without false precision, it is blocking. Remediation prose may describe
disagreement, but prose never causes matching.

## Candidate preparation workflow

1. Assign incident ID and new semantic pack version.
2. Create an isolated candidate branch and packet directory.
3. Retrieve current primary sources explicitly and build the bounded source
   ledger.
4. Build the claim matrix before writing matching fields.
5. Record all conflicts and omissions.
6. Write the declarative pack; run strict validation and canonicalization.
7. Add deterministic synthetic positive, negative, boundary, contradiction, and
   evidence-gap fixtures. Do not include real victim data or malware.
8. Generate expected findings and prove the pack never promotes missing evidence
   or download-only evidence.
9. Produce the fixture and candidate-content manifests and exact hashes.
10. Freeze candidate content in commit C, record C outside the immutable review
    unit, have each reviewer author and inspect their bounded pre-review
    assertion, render its exact fixed review body, and request the required
    human reviews against C plus the candidate-content manifest hash.
11. After the required GitHub approvals exist on exact C, run the repository-
    controlled snapshot workflow to verify the pull-request head and normalize
    the bounded list-reviews response. Retain the resulting
    `platform-approvals.json` and its artifact identity; do not retain review
    bodies or credentials. The normalized record retains only each review
    body's SHA-256 so a referenced approval can be compared to the reviewer's
    fixed assertion body.
12. On a promotion branch still rooted at C, materialize only the fixed approval,
    snapshot, promotion, reviewed-copy, and manifest paths. Commit the resulting
    content as P only after offline policy and identity checks pass.

The candidate author may respond to review with a new commit, but every prior
approval becomes stale after any material change. Do not amend or force-move a
reviewed commit without creating a new review unit.

Human review occurs against frozen candidate commit C. Approval records are
then materialized on a separate promotion branch based on C; adding those JSON
records does not move the candidate review head or redefine C. Promotion content
commit P adds only approval/promotion records and the byte-identical reviewed
copy. A subsequent registry commit may reference P. A content change anywhere
under `candidate-content/` requires a new C and fresh reviews.

## Human approval requirements

The accepted v0.1 specification requires at least two maintainer approvals for
real incident data. v0.2 adds outside factual review; it does not silently reduce
the existing gate.

At the planning baseline only one eligible project maintainer is identified.
Each candidate assigns a human **preparer-of-record** who owns the source
transcription and DCO submission responsibility for automation-assisted changes.
That person cannot approve the same candidate. Before promotion, the project
must therefore staff two distinct eligible project-maintainer approvers who are
neither that candidate's preparer nor its source transcriber. If Maksim is the
preparer, two additional maintainers are needed; if a non-maintainer outside
contributor prepares it, Maksim plus one additional eligible maintainer may fill
the two slots. Repository review authority and conflict disclosures are
recorded. This is a blocking governance/staffing gate; an automated account,
alternate account of the same person, or outside-review slot cannot substitute.

For Reviewdog, tj-actions, and any optional Xygeni pack:

- at least two maintainer approvals on the exact final pack/packet commit;
- at least one independent outside technical reviewer who is not the candidate
  author, source transcriber, or an automated account;
- one approver reproduces immutable identities and validation from the recorded
  source objects;
- one security review covers hostile data, fixture privacy, and non-executable
  pack content.

For Trivy:

- the same two-maintainer gate;
- two distinct independent outside technical reviewers;
- both outside reviewers independently check component namespaces/windows and
  the mechanical IOC extraction output;
- the maintainer's final release acceptance is additional and cannot substitute
  for either outside review.

An outside reviewer discloses employment, project, vendor, incident-response,
and authorship conflicts relevant to the incident. For these v0.2 launch packs,
“outside” means external to the CIRewind maintainer/core implementation team,
not the pack author or source transcriber, and not an automated account or
implementation session. Every approval slot is a distinct human identity; the
two Trivy outside reviewers are also independent from each other. A reviewer may
have limited GitHub access to submit a review; access alone does not destroy
independence, but the relationship is recorded.

Compatible external roles may overlap when independence remains real and
recorded. The public-lab reproducer may also perform cold-reader/accessibility
review. A pack reviewer may also perform final skeptical review if they did not
author or transcribe the material being reviewed. One reviewer may cover more
than one declared review scope, but cannot independently review material they
authored. Role overlap does not let one person occupy two distinct Trivy outside-
reviewer slots or reduce any required reviewer count.

If the project cannot obtain the required number of maintainers/reviewers, the
pack remains `candidate` and the coordinated v0.2 release gate is NO-GO. The
project may later accept an ADR explicitly changing this policy, but planning or
automation cannot waive it.

## Approval record

Each `approvals/REVIEW_ID/review.json` is the canonical machine-readable review
record. `approvals/REVIEW_ID/REVIEW.md` is generated deterministically from that
JSON and is never an alternate authority. Generation drift, handwritten Markdown
changes, or disagreement between the two fails validation. `review.json`
records:

- review-record schema version and stable review ID;
- reviewer public identity and declared role;
- independence/conflict disclosure;
- incident ID and pack version;
- exact original and canonical pack SHA-256 values;
- exact frozen candidate commit C and PR review URL/database ID;
- SHA-256 of `candidate-content-manifest.sha256` bytes, plus claims, sources,
  conflicts, fixtures, and validator-policy hashes copied from the immutable
  review unit;
- review scope: identity, time, transitive mapping, IOC extraction, remediation,
  hostile-input/privacy, or complete;
- commands/tool versions used for offline reproduction;
- source-object hashes actually checked;
- decision: `approve`, `request_changes`, or `abstain`;
- UTC review time and bounded rationale;
- known limitations accepted without resolving them.

Before submitting a GitHub review, the reviewer writes the closed canonical
`cirewind.review-assertion/v1alpha1` record containing all material fields known
before submission. `packreview render-review-body --review FILE` validates that
human-authored record and emits the exact fixed ASCII review body:

```text
CIRewind review assertion v1 sha256:<canonical-assertion-sha256>
```

The assertion binds the official repository and pull-request number as well as
C, content/policy hashes, reviewer identity and role, independence/conflict
declaration, scopes, reproduction commands, exact checked source objects,
decision, rationale, and limitations. Only GitHub-assigned review URL/database
ID and the post-submission record time are outside that pre-review assertion.
The final `review.json` records both the assertion hash and exact body hash.
Changing any material assertion field after the GitHub review therefore makes
the platform body hash disagree and fails approval. The tool does not create an
approval or populate any reviewer assertion.

An approval record is a transparent provenance record, not a cryptographic
signature unless a future signing ADR adds that claim. CI can verify structure,
hash binding, review identity uniqueness, and that required records exist. CI
cannot determine whether a reviewer read a source or whether a claim is true.
The JSON and generated Markdown cannot certify themselves. A qualifying
independent human approval requires a GitHub pull-request approval whose reviewed
head is exact frozen candidate commit C; the JSON records that external review
URL/database identity and commit binding. Any material candidate change changes
C, makes that PR approval stale for promotion, and requires fresh approval.

GitHub can require review and dismiss stale approvals when new commits change a
pull request, but the project still records exact pack hashes because repository
administrators may have override powers. Source retrieved 2026-08-22:

- [GitHub Docs — About protected branches](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches)
- [GitHub Docs — About pull request reviews](https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/reviewing-changes-in-pull-requests/about-pull-request-reviews)

### External platform-observation boundary

`platform-approvals.json` is a bounded, normalized observation of the GitHub PR
review surface. It binds the repository, pull request, candidate head C,
observation time, exact workflow-source commit, identified workflow run/attempt,
hash of the exact projected response supplied to the normalizer, and each
observed review database ID, reviewer database identity, account type, state,
commit, submission time, dismissal state, and SHA-256 of the exact review body.
The body itself is discarded. The offline tool requires the
human `review.json` reference and this normalized observation to agree exactly.
It rejects a non-`User` account, a missing or dismissed review, a review on
another commit, a stale prior approval when a later captured review changes the
effective state, a mismatched PR, and a preparer/author/source-transcriber
self-review. It also requires every recorded checked-source ID and hash to agree
with the exact retained `sources.json`; an identity-scope reviewer must cover
every source object behind the closed identity-role claim set. Maintainer
eligibility, the only official repository from which reviews may qualify, and
minimum role/scope counts come from the review policy retained inside immutable
candidate content. A new or actively unpromoted candidate must retain the exact
current repository policy, while already promoted history is reverified against
its retained policy. The Trivy profile retains its higher outside-reviewer
floor.

The local `normalize-platform-approvals` adapter accepts either one review array
or a bounded outer array of review-page arrays. Input is limited to 8 MiB and
2,000 observations before the final normalized-record limit of 100; parsing
stops at the count bound. The adapter rejects duplicate JSON keys,
mixed/malformed page shapes, unsupported review states, and unsafe identities;
it drops pending reviews and ignores fields outside the closed projection. It
accepts ordinary or empty review bodies, hashes their exact UTF-8 bytes, and
discards the text; only a review later referenced by `review.json` must match a
fixed CIRewind assertion body. It
normalizes reviewer logins and commit IDs to lowercase, sorts the bounded
submitted observations by review database ID, records the SHA-256 of the exact
projected input, and writes canonical JSON with restrictive permissions.

The manually dispatched `.github/workflows/pack-review-snapshot.yml` adapter
uses only `contents: read` and `pull-requests: read`, and its job runs only when
the selected dispatch ref is the repository's default branch. It checks out
exact `github.sha` and builds the normalizer before any step receives
`GH_TOKEN`. The token-bearing step validates C and the pull-request number,
requires `head.sha == C`, projects only the required review fields, captures the
projection twice and requires byte equality, caps each transient capture at
8 MiB while it is written, then
rechecks the pull-request head. `gh api --paginate --jq` emits one projected
array per page. Current GitHub CLI rejects combining `--slurp` with `--jq`, so
the workflow does not request that unsupported flag combination. A later
credential-free step uses `jq -cs 'add'` to combine the bounded page stream into
one array, invokes the prebuilt normalizer with
`workflowSourceCommit == github.sha`, hashes the result, and transfers only
`platform-approvals.json` and its manifest while recording the artifact ID. The
projected response—including transient review-body text—and prebuilt helper are
removed in an always-run cleanup step.

This workflow output is point-in-time process evidence, not platform attestation
or proof of factual review, human independence, or pack truth. Before promotion,
a human must inspect the exact run URL/ID/attempt, selected default-branch ref,
workflow-source commit, pull-request approval on C, artifact identity, and
hashes. Detached local JSON can be fabricated and is never sufficient. Promotion
records require `promotedAt` to be no earlier than `observedAt` and no more than
15 minutes later. Both values are retained record fields: that interval is a
structural chronology check, not authenticated wall-clock freshness. The
offline verifier cannot detect a dismissal or new review created after the
captured response. A later discovered revocation or conflict therefore requires
the append-only withdrawal/correction process. Primary behavior references,
retrieved 2026-08-30:

- [GitHub CLI manual — `gh api` pagination and jq behavior](https://cli.github.com/manual/gh_api)
- [GitHub CLI source — `gh api` flag constraints at revision `40b742f`](https://github.com/cli/cli/blob/40b742f76d68e6b1f472942a6368db4b5d765641/pkg/cmd/api/api.go)
- [GitHub REST API — list reviews for a pull request](https://docs.github.com/en/rest/pulls/reviews?apiVersion=2022-11-28#list-reviews-for-a-pull-request)

The core tool neither calls GitHub nor authenticates the observation. A checked-
in snapshot, its response hash, `review.json`, and generated `REVIEW.md` are not
signatures and cannot prove that the account belongs to the represented human,
that the reviewer is independent, or that the reviewer performed the stated
work. The repository-controlled read-only CI adapter that acquires the GitHub
response, the exact PR approval on C, repository governance, and human conflict
disclosure are the external evidence boundary. No local record may describe that
boundary as self-certified approval.

## Rules preventing self-approval

- The candidate author cannot approve their own pack.
- The person or session that transcribed a claim cannot be the only person who
  validates it against the source.
- Bots, CI, language models, automated assistants, generated comments, schema
  validators, and test output never count as a human approval.
- Codex, or any other automated implementation session, may prepare candidate
  material but may not create an approving record, change status to `reviewed`,
  or satisfy an independence gate.
- An automated session may not create an approval record with an `approve`
  decision, mark status `reviewed`, or describe review as independent.
- A maintainer cannot satisfy the outside-review requirement by approving their
  own candidate under a second account or role.
- Approval must be recorded after the final candidate commit exists and bind to
  its exact hashes.
- Copying a prior approval to a new version is prohibited.
- Repository merge permission is not factual approval; the registry and exact
  review records must also satisfy policy.

## Promotion and immutable history

Promotion to `reviewed` is deterministic and human-triggered:

1. Revalidate the exact candidate bytes and immutable candidate content at C.
2. Confirm every approval binds C and the exact candidate-content manifest hash
   and that no approval is stale; require the recorded promotion time to fall
   within the retained platform snapshot's inclusive 15-minute chronology
   interval, without treating that unauthenticated interval as proof of current
   wall-clock freshness.
3. Confirm required reviewer counts/roles and no unresolved blocking conflict.
4. Copy exact YAML bytes to `incidents/reviewed/INCIDENT_ID/PACK_VERSION.yaml`.
5. On a promotion branch based on C, materialize approvals and the retained
   normalized platform snapshot, create `promotion-record.json` with the
   snapshot hash, copy the reviewed bytes, and generate the non-self-referential
   review-record manifest covering all of those records. Commit this content as
   P; the record itself does not predict P.
6. In a later append-only registry commit, add an entry binding reviewed path,
   pack/review-unit/review-record hashes, C, P, approval IDs,
   schema/validator version, and promotion time. The registry entry does not
   name its own commit.
7. Run release safety, semantic, fixture, candidate-content-manifest, and
   review-record-manifest tests.

Published pack versions are immutable. A correction creates a new pack version,
new candidate, new finding revisions through the existing canonical-hash model,
and new approvals. Old bytes and approval records remain available. Withdrawal
adds a tombstone and warning; it does not erase history or silently substitute a
new file.

Candidate branches must not be squashed/rebased after exact-hash approval unless
all reviewers reapprove the resulting commit and bytes.

The promotion operation is idempotent only when all existing destination bytes
are already exact. It fails closed rather than overwriting a different reviewed
pack, promotion record, or review manifest, and it rolls back files newly
created by a failed operation. It never edits `review-registry.json`. Registry
history is a separate, later append-only human-authored change: the verifier
checks allowed status transitions, immutable candidate/promotion identity,
supersession closure, exact reviewed-tree registration, byte identity with the
candidate, manifests, pack hashes, policy hash, and the supplied promotion
content commit P. It does not prove Git history append-only by itself; protected
branch policy and the caller/CI Git precondition remain necessary.

## Required test matrix

Every candidate includes:

- schema/safety/canonicalization validation;
- original and canonical hash golden tests;
- exact positive SHA/digest tests where supplied;
- known-good negative tests where supplied and independently verified;
- exposure-window start/end and inclusivity tests at the source's actual
  precision;
- one just-before and one just-after boundary case without fabricated timing;
- mutable ref without runtime SHA, with provenance capped appropriately;
- runtime exact SHA contradicting static declaration;
- downloaded-only and skipped lifecycle, proving no
  `CONFIRMED_EXECUTED` promotion;
- missing logs/definition, proving `UNKNOWN_EVIDENCE_GAP` rather than clean no
  match;
- current-only reference separated from historical evidence;
- component/subpath and digest-namespace isolation;
- transitive wrapper test that does not relabel the wrapper commit compromised;
- hostile title, source, remediation, literal, repository, and IOC text;
- deterministic replay and finding revision IDs;
- a closed `fixtures/index.json` whose safe scenario-ID-derived paths reference
  canonical compact archive snapshots; validation replays each snapshot through
  the production offline derivation path and compares exact finding identity,
  state, provenance, supporting evidence or explicit gap, and coverage
  assessment IDs against `expected-findings.json`;
- explicit forbidden-state rows, including downloaded-only scenarios that must
  never derive `CONFIRMED_EXECUTED`, and rejection of unindexed scenario files;
- source-to-field coverage test: every material canonical path has at least one
  claim row and every referenced source/conflict exists;
- review-policy test that candidates cannot enter reviewed index without exact
  non-stale human records.

Real malware, victim logs, secrets, payload execution, IOC network contact, and
Action checkout/execution are prohibited in tests. Fixtures use synthetic
repositories, times, logs, and harmless identifiers while exercising the real
pack's matching fields.

## Candidate-specific admission decisions

These are work instructions, not reviewed facts. Recheck the primary sources
listed in the research ledger before transcribing anything.

### March 2025 Reviewdog/action-setup

- Treat the current direct-component/ref/full-object notes only as research
  hypotheses. A packet may proceed only after primary-source revalidation
  establishes each proposed value and namespace.
- Decide and document minute-boundary inclusivity without inventing seconds.
- Exclude every wrapper/version mapping until exact historical wrapper metadata
  proves that nested declaration for the relevant wrapper commit.
- Never call wrapper commits compromised merely because they were transitively
  exposed.

### March 2025 tj-actions/changed-files

- Do not assume an exact malicious object from the research label. Include one
  only if primary-source revalidation yields a full object identity in the
  correct namespace and the claim matrix binds it.
- Treat the published date-level period with its real precision; a conservative
  expansion requires an explicit claim row and reviewer approval.
- Omit disputed patched/known-good versions until immutable objects and the
  source conflict are resolved.
- Treat published tag examples as examples unless a primary record establishes
  a complete set.

### March 2026 Trivy ecosystem

- Keep each Action/binary/package/image component in its own typed namespace and
  exposure window.
- Preserve every approximate boundary as approximate.
- Mechanically extract large IOC tables into typed deterministic records, record
  the extractor/version/input hash/output hash, and have both outside reviewers
  reproduce the extraction.
- A digest or object belonging to one component never spills into another
  component by string equality alone.

### Xygeni (optional)

- Xygeni is a nonblocking candidate and is excluded from the v0.2 release by
  default.
- Promote it only if primary evidence establishes the exact malicious identity,
  affected ref, source-precision-aware timing and conflicts, and the packet has
  deterministic fixtures plus the required independent review.
- If sources remain internally imprecise or conflicting, retain `research`,
  create a blocked/withdrawn packet, or omit the mutable-window indicator while
  preserving any independently exact identity.
- If those gates are not all met, retain it for a later release. Never broaden
  it merely to complete a fourth pack.

## Pack versioning and release distribution

- `apiVersion` continues to govern syntax/semantics; v0.2 does not silently
  accept unknown pack fields.
- `metadata.packVersion` changes for every semantic source/window/identity/IOC or
  remediation-trigger change.
- Reviewed packs may ship inside release archives, as a separate hash-addressed
  reviewed-pack bundle, or both only after the maintainer decides the
  distribution contract and tests hash identity across copies.
- Candidate packs are never bundled with the binary or shown in a quickstart.
- A reviewed-pack index records exact hashes and approval record IDs; it does not
  cause automatic network retrieval.
- CIRewind never contacts a pack registry or source URL during validation,
  investigation, archive, replay, demo, or report viewing.

## Release gate

For the coordinated v0.2.0 release:

- Reviewdog, tj-actions, and Trivy must be `reviewed` at exact release-tree
  hashes under this protocol.
- Trivy must have two independent outside approvals.
- Xygeni is excluded by default and never blocks v0.2; inclusion requires every
  candidate-specific promotion gate above.
- All required approval records remain unchecked/open until actual humans approve
  them.
- Any discovered source conflict, stale approval, changed candidate byte,
  privacy/licensing issue, or semantic overclaim returns the affected pack to
  candidate/withdrawn and blocks its release gate.

The maintainer may release product-owned adoption functionality under a
different version/scope if external gates cannot be met, but it must not label
that release as satisfying this coordinated v0.2.0 plan without a new explicit
decision record.

## Current implementation and review state

The v0.2 worktree contains the offline schemas, strict typed validators,
maintainer tool, Git precondition guard, read-only platform-snapshot workflow,
snapshot retention/revalidation, registered-history closure, and production-path
fixture replay described above. Candidate-C CI discovery/validation must remain
separate from registry-history validation so C never has to contain its own
commit identity. The checked-in review policy deliberately has no fabricated
eligible-maintainer identities, and the registry is honestly empty. The complete
synthetic machine fixture now exercises all ten finding states, inclusive-start
and exclusive-end boundaries, contradiction and evidence-gap conclusions, exact
coverage/gap oracle checks, and an isolated downloaded-only scenario that
forbids `CONFIRMED_EXECUTED`. This does not satisfy a real candidate's factual
fixtures or the human/topology gates.

Candidate change-set separation is the separate default-branch
`.github/workflows/pack-review-candidate-policy.yml` `pull_request_target`
workflow, not a job whose definition can be replaced by the candidate under
test. It checks out the exact base commit containing the
trusted guard, materializes the exact pull-request head only as inert Git data,
verifies both event commit identities, and runs only the trusted-base guard with
`contents: read`. It never builds, tests, sources, imports, or otherwise
executes the head tree. The explicit checkout-v7 unsafe-PR opt-in is therefore
limited to data inspection and is guarded by acceptance tests that prohibit
head-controlled command paths. GitHub documents both the elevated trust of
[`pull_request_target`](https://docs.github.com/en/actions/reference/security/securely-using-pull_request_target)
and the requirement that its workflow file exist on the
[default branch](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#pull_request_target);
retrieved 2026-08-30. A force-push race fails the exact-head comparison and
requires the subsequent synchronization event to rerun the policy. This gate
begins governing later PR events only after its trusted workflow and guard land
on the default branch; the bootstrap infrastructure PR remains subject to the
ordinary reviewed CI path.

A candidate-stage review unit may omit `approvals/` because Git cannot retain
an empty directory. That exception ends as soon as review begins or any review
or promotion material exists. Every present approvals directory remains a real,
non-link, closed tree, and approval checking or promotion still requires actual
policy-satisfying review records.

That implementation is governance infrastructure, not a real incident-content
review. As of 2026-08-30, no Reviewdog, tj-actions, Trivy, or Xygeni candidate in
this repository has completed the required independent human review, no
automated session has authority to populate an independent approval, and no real
pack is eligible to be described as `reviewed`. Tooling tests can use
unmistakably synthetic people, source records, packs, and platform observations
to prove policy mechanics; those fixtures are never evidence of an external
approval. `PACK-022` remains open until an actual qualifying human GitHub review
of exact C exists; `PACK-023` remains open until a real C-to-P-to-later-registry
history passes the accepted topology; and `PACK-024` remains open pending the
`PACK-023` dependency plus the complete CI/governance qualification and final
workflow security audit.
