# CIRewind test strategy

Status: v0.1 verification contract; bounded v0.1.1 release gates completed
Planning date: 2026-08-20
Normative semantics: [EVIDENCE_MODEL.md](EVIDENCE_MODEL.md)
Threat model: [THREAT_MODEL.md](THREAT_MODEL.md)

The exact v0.1.1 release completed the bounded local, controlled-live, hosted,
draft, provenance, publication, and post-public checks recorded in
[IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md) and ADR 0011. That evidence
does not satisfy every broader live, sustained-fuzz, scale, or native-platform
compatibility contract in this document; those open contracts remain future
qualification work rather than implicit support claims.

## Quality objective

The test suite must make a false forensic promotion harder than an explicit evidence gap. It verifies not merely that parsers return data, but that every result remains scoped to the correct repository, run, attempt, job, step lifecycle, event time, collection time, incident indicator, and source evidence.

The suite has four layers:

1. Deterministic unit/property/golden tests run on every change without network access.
2. Stateful mock-GitHub and case/archive integration tests run without network access.
3. Hostile-input, fuzz, scale, cross-platform, and browser-security qualification.
4. An opt-in controlled GitHub.com forensic lab using harmless Actions and fake secrets.

No test executes fetched third-party Action code. The controlled lab executes only reviewed, harmless fixture Actions owned by the lab project.

## Release gates

Within the qualification envelope accepted by ADR 0011, a v0.1 release cannot
proceed unless:

- The controlled explicit-repository feasibility gates incorporated by ADR
  0011's release decision rule pass. Broader hard gates in
  [PLAN.md](PLAN.md) remain roadmap contracts and are not presented as
  satisfied.
- The exact ten finding-state spellings are enforced by schema/DB/API/report contract tests.
- All eight mandatory invariants have a positive test and a prohibited-conclusion test.
- Scenarios A–P pass deterministic acceptance fixtures; the central A→B→A scenario passes live.
- Background/concurrent-step scenario Q proves no inference from YAML order alone.
- Every exact execution test supplies both exact runtime identity and an independent structural lifecycle-start observation in the same attempt/job.
- Every download test establishes preparation completion, not merely a pre-download announcement.
- Every negative test closes incident-relevant coverage; deleting one required source changes the result away from `NO_MATCH_CONFIRMED`.
- Archive replay passes with DNS/HTTP/process creation disabled.
- The fuzz/security/cross-platform/scale subset required by ADR 0011 passes
  under the published configurations. Broader contracts below remain
  compatibility work until their original acceptance criteria are satisfied.
- Test fixtures contain no real secret values, customer data, compromised payloads, or fabricated real-incident identities.

## Deterministic test harness

### Injected nondeterminism

Tests inject and record:

- UTC clock and monotonic sequence source.
- Stable ID/hash vectors.
- Mock HTTP transport and DNS prohibition.
- Filesystem abstraction only where needed for platform fault injection; path security is also tested on real filesystems.
- Rate-limit/reset clock and retry jitter seed.
- Worker count and deterministic result ordering.
- Semantic engine, parser grammar, schema, API, and pack-policy versions.

Production collection order may vary, but queries/reports sort by stable domain keys. Given fixed archive bytes, pack bytes, configuration, semantic/parser versions, and clock, normalized replay output must be byte-identical.

### Fixture provenance

Every fixture has a sidecar manifest expressed as test data containing:

- Fixture ID and synthetic/live-controlled origin.
- GitHub API version and source endpoint class.
- Runner version and pinned runner-source commit relevant to log grammar.
- Repository/run/attempt/job/step synthetic identities.
- Original-capture date, sanitization method, and post-sanitization hash.
- Expected observations, gaps, findings, and prohibited findings.
- Whether complete raw bytes are present.

Controlled captures use only lab repositories and fake values. Sanitized bytes are new fixture evidence; the suite does not pretend their hash is the live original's hash. Golden updates are never automatic in CI and require semantic-review approval.

## Unit tests

### Identity and canonicalization

- Repository rename/transfer preserves numeric identity and appends name observations.
- `logical_source_id`, `evidence_id`, and `observation_id` match published RFC 8785 canonical vectors.
- Identical source bytes/retention descriptor deduplicate evidence while a recollection appends an observation.
- Changed bytes retain logical source and create a new evidence ID.
- Finding logical ID stays stable while a changed state/evidence set appends a new `finding_revision_id` with `supersedes_revision_id`.
- Subject identity differs across repository, attempt, job, step number, lifecycle phase, and occurrence.
- Untrusted job/step names never alter identity.
- Typed Git object ID (algorithm plus full value), typed digest namespace, repository, ref, path, domain, IP, timestamp precision, and incident-window bound normalization have golden vectors.

### Time and intervals

- Collection scope `[from,to)` boundaries include `from` and exclude `to` after local API filtering.
- Incident windows obey explicit `[)`, `[]`, `()`, or `(]` pack bounds without synthesizing source precision.
- Approximate/partial-overlap event intervals cap provenance and retain ambiguity.
- Preparation time outranks job/run proxy time for mutable-ref matching.
- Collection time never enters incident-window matching.
- Background step intervals that overlap remain unordered absent an explicit synchronization edge.
- Explicit wait/dependency edges create only the documented happens-before relations.

### Run enumeration and partitioning

- Counts 0, 1, 999 close a leaf; 1,000 and above split.
- Inclusive API split boundaries are deduplicated with no omitted run.
- Random run multisets partition into exactly the locally in-range unique run IDs.
- A one-second bucket at/above the ceiling produces `DENSITY_CEILING` and cannot close coverage.
- Pagination repeats, omissions, changing `total_count`, empty intermediate pages, duplicate run IDs, and out-of-range rows produce typed diagnostics.
- A rerun attempt or environment-delayed job in the exposure interval whose parent run was created before `from` is discovered through the provisional 65-day parent-run watch; a separate proof is required before reducing the bound to 35 days.
- The run is reread after collection; newly appearing attempts are collected or `LIVE_STATE_RACE` is recorded.

### Runtime grammars and state machine

- Traditional exact Action SHA line, immutable package version/source SHA/digest group, runner permission group, runner facts, setup completion, failure, and structural lifecycle frames.
- The download announcement alone creates `resolution_observed`/`download_announced`, not `preparation_completed` and not `CONFIRMED_DOWNLOADED`.
- Successful setup after awaited preparation can create a versioned inferred `preparation_completed` observation.
- Lifecycle start can imply earlier preparation but preserves both derivation inputs.
- Truncation after every byte/line/group boundary produces stable partial observations and gaps.
- A lookalike line in an application step is never a runner control observation.
- Duplicate names, duplicate Action refs, repeated pre/main/post handlers, and matrix labels map structurally or remain ambiguous.
- A pre handler, main handler, and post handler each have separate lifecycle identity; any observed affected lifecycle start can support execution.
- A skipped main does not erase an observed pre lifecycle.
- Unknown runner/log grammar never falls back to substring-based execution.

### Historical YAML and resolver

- Duplicate keys, aliases, expressions, anchors, source spans, `action.yml`/`action.yaml`, JavaScript/Docker/composite metadata, and bounded parse failures.
- Full SHA, mutable branch/tag, repository subpath, reusable workflow, local `./`, and self-repository `$/` remain distinct syntax kinds.
- `$/path` binds to the containing definition repository/commit; nested reusable/composite contexts do not accidentally bind to the top caller.
- `./path` records checkout/workspace candidates and mutation uncertainty; it cannot become an exact Action commit without evidence.
- Composite/reusable cycles and depths terminate deterministically.
- A wrapper Action lifecycle does not prove embedded lifecycle execution.
- Current mutable-ref lookup never fills a missing historical runtime SHA.
- `head_sha`, trigger SHA, workflow-definition SHA, caller SHA, called SHA, and Action SHA cannot be assigned interchangeably.

### Credential/resource semantics

- Effective setup-log token permissions outrank static inference.
- Static permission reconstruction applies enterprise/org/repo default, workflow, job, reusable monotonic restriction, fork/Dependabot adjustment, and records missing historical settings.
- An executed affected Action can reach `github.token` permissions without explicit YAML mapping; download-only cannot.
- Secret existence, policy eligibility, historical reference, job mapping, step pass, inheritance, environment eligibility, and audit-provided name are separate propositions.
- Job/workflow `env` flow reaches only lifecycles that began; step `env`/`with` reaches only that step.
- A secret used by another concurrent or unordered step does not flow to the affected step without explicit evidence.
- `secrets: inherit` advances one reusable call hop and never automatically crosses the next.
- Current secret/environment metadata never backdates itself.
- Waiting/rejected/unstarted environment jobs have no environment-secret eligibility.
- `id-token: write` plus affected lifecycle start yields `OIDC_MINTING_CAPABILITY` only.
- Runner labels do not establish persistence/network access.
- Direct resource attribution and temporal `OBSERVED_AFTER` are distinct; neither implies maliciousness/causation.

### Incident packs and finding rules

- Exact strict schema, size/node/depth/scalar limits, no alias/merge/tag/duplicate/unknown field, and canonical hash vectors.
- Every indicator kind, typed digest namespace, time precision/bounds, source reference, affected/known-good conflict, and rotation trigger.
- Source/indicator order permutation does not change canonical hash or findings.
- Pack `L4_CERTAIN` cannot raise weak case evidence above its own support.
- Each row of the deterministic state matrix in [EVIDENCE_MODEL.md](EVIDENCE_MODEL.md) has a positive, disqualifier, companion-contradiction, and coverage-gap test.
- No other state string is accepted.

### Store, graph, outputs, and manifest

- Migrations, foreign keys, CHECK constraints, schema/application ID, finding revisions, bitemporal observations, interruption recovery, WAL checkpoint/finalization, and corruption detection.
- Every material graph edge has evidence; removing evidence makes projection validation fail.
- Graph projection is deterministic and cannot write back to evidence tables.
- HTML, JSON, JSONL, CSV, Markdown, and collection metadata match goldens under hostile strings.
- Manifest paths are canonical/sorted, cover every finalized regular file except the manifest itself, and detect content/addition/removal changes according to policy.
- A manifest does not produce an authenticity claim.

## Property and metamorphic tests

| Property | Generator/transformation | Required invariant |
| --- | --- | --- |
| Partition completeness | Random timestamps, duplicates, inclusive boundaries, arbitrary page splits | Output unique runs equals mathematical `[from,to)` set or an explicit terminal gap |
| Coverage accounting | Random expected/collected/not-applicable/gap trees | `expected = collected + not_applicable + gaps`; no negative/duplicate counts |
| No false execution | Add/remove/reorder forged strings and skipped records | `CONFIRMED_EXECUTED` appears only with exact identity + structural lifecycle start |
| No false download completion | Truncate after announcement or corrupt archive | `CONFIRMED_DOWNLOADED` requires preparation completion/stronger lifecycle proof |
| Attempt isolation | Clone records to another attempt/job and perturb names | Findings never cross execution keys |
| Evidence monotonicity | Add unrelated evidence/gaps | Existing direct proposition remains; unrelated data cannot change its state |
| Revision append-only | Add stronger or contradictory evidence | New finding revision/companion finding; old revision/evidence remains unchanged |
| Current/historical separation | Replace current YAML/ref with any value | Historical runtime findings do not change |
| Order independence | Permute API pages, worker completion, pack sets, DB row insertion | Normalized outputs/findings identical |
| Parser totality | Arbitrary bounded bytes | No panic; deterministic success/gap; cancellation honored |
| Graph traceability | Project any accepted case | Every material edge reaches one or more evidence objects |
| Replay closure | Disable all network/process access | Identical structured indicators replay; missing unretained literals become gaps |
| Non-causation | Add temporally later resource | Wording/relation remains `OBSERVED_AFTER` unless direct attribution evidence is added |
| Concurrency order | Swap/overlap background step intervals | No happens-before/flow edge without non-overlap or explicit synchronization |

## Golden tests

Golden corpora include:

- Runner setup logs across pinned GitHub-hosted/self-hosted versions, traditional and immutable Actions, successful/failed/truncated preparation.
- Job/attempt ZIP layouts, partial rerun archives, job-log fallback, duplicate/case-colliding entry names.
- Step logs for JavaScript, Docker, composite, local, `$/`, pre/main/post, conditional skip, failure, cancellation, background/parallel/wait.
- Exact caller/called workflow API/GraphQL/audit records and event-specific definitions.
- Historical workflow and Action metadata ASTs including hostile/dynamic/duplicate/deep cases.
- All incident-pack indicator kinds, approximate windows, typed digests, unsafe packs, and synthetic conflict packs.
- Case/archive database versions and every required output.
- Hostile report corpus with HTML/script delimiters, terminal controls, bidi, invalid UTF-8 representations, CSV formulas, long Unicode, and path characters.

Each golden stores structured expected observations/findings, not only a whole-output snapshot. Reviewers must be able to see which semantic predicate changed.

## Stateful mock GitHub API tests

The mock server implements only documented endpoints and captures requests. It never accepts an accidental write method.

### Required behaviors

- Organization repository pagination, private/inaccessible repositories, renamed repository IDs, explicit repositories, and GitHub App installation visibility.
- Workflow-run `created` filter, 100-page size, 1,000-result ceiling, split overlaps, one-second saturation, and rerun parent lookback.
- Run snapshots with attempts 1..N, attempt resources, attempt-specific `referenced_workflows`, jobs, and latest-attempt races.
- Full-rerun, failed-job-rerun, and single-job-rerun membership; partial ZIP contains only rerun jobs.
- Attempt-log 302 with one-minute link, immediate download, expiry, one safe renewal, unexpected second redirect, HTTP downgrade, private-IP target, no authorization forwarding, and sanitized signed query.
- Job-log fallback and disagreement between attempt/job log content.
- REST exact-SHA Contents/blob retrieval, 404/403/409, deleted/renamed/private called repositories, both metadata filenames, and media/size limits.
- GraphQL `WorkflowRun.file` exact/ambiguous/unavailable behavior as a spike-gated source.
- Audit `prepared_workflow_job` records with/without unique job correlation; job-name-only ambiguity must remain unlinked.
- Actions/environments/reviews/deployments/artifacts/packages/releases/rulesets/runners/secret-metadata optional permissions and current-state timestamps.
- Primary rate exhaustion, secondary throttling, abuse response, `Retry-After`, reset, transient 5xx/network failure, cancellation, and retry-budget exhaustion.
- `401`, `403`, `404`, `410` if returned by a fixture, `422`, `429`, `5xx`, malformed JSON, wrong media type, huge/streaming body, and inconsistent content length.

Assertions cover method, route, pinned API version, safe parameters, request count, pagination, absence of writes, absence of credentials on redirect, evidence hashing, typed gaps, resume state, and coverage reconciliation.

## Integration tests

### Investigate

Use a stateful mock organization containing multiple repositories, dense windows, all attempts, nested definitions, log grammars, optional enrichment failures, and downstream resources. Assert required case files, findings, revisions, evidence links, coverage totals, graph projection, permission wording, and manifest.

### Archive

Run overlapping incremental collections with late observations, a rerun of a 29-day-old parent, an environment-delayed job from a 34-day-old parent, and a time-shifted/pre-aged later-attempt fixture whose parent is 60 days old. Assert the provisional rolling 65-day watch finds all applicable attempts/jobs, plus stable deduplication, append-only collection observations, hole-aware discovery/watch coverage, and no raw logs by default. A 35-day optimization test must first prove the documented lifetime's parent anchor.

### Replay

Open the archive read-only under a transport that fails every network/process attempt. Evaluate multiple synthetic packs, including a later exact SHA/digest and a later arbitrary log literal whose raw bytes were not retained. Exact structured indicators must match; the unavailable literal must produce `UNKNOWN_EVIDENCE_GAP`. Fixed-input outputs are byte-identical.

### Pack validation

Validation makes no filesystem changes except reading the selected local file, no network/process calls, returns stable diagnostics ordered by source location, and differentiates structural validity from factual trust.

### Crash and disk faults

Inject cancellation, short write, fsync failure, disk full, process interruption between SQLite and JSONL operations, stale WAL/SHM, output rename failure, and manifest failure. A recovery must either resume a complete logical batch or mark it incomplete; it must never present a finalized manifest over a torn case.

## Controlled forensic lab

### Safety constraints

- Dedicated organization and repositories with no production resources.
- Only reviewed synthetic Go/JavaScript/composite fixture Actions that print fixed harmless identifiers and timestamps; no network exfiltration, credential display, obfuscation, persistence, destructive operation, or third-party target.
- Secrets are named `CIREWIND_FAKE_*` and contain inert random fixture text. CIRewind never retrieves or prints their values.
- Environment approvals use lab maintainers only.
- Self-hosted runner is an ephemeral isolated lab VM/container with no production network route or reusable credential.
- Tag movement and log deletion, if used, are explicit maintainer lab actions outside the read-only CIRewind product. Deterministic missing-log fixtures remain the release test.
- Captures are reviewed and sanitized before entering the repository.

### Central A→B→A acceptance protocol

1. Create harmless Action commit A whose only observable behavior is a fixed `fixture-version=A` notice, and harmless commit B with `fixture-version=B`. Neither reads environment values or makes network requests.
2. Point controlled mutable tag `v1` to A. Pin fixture commit IDs in the lab record.
3. Create historical workflows containing direct, skipped, composite, reusable, and two-axis matrix uses of `owner/harmless-action@v1`, plus full-SHA controls.
4. Move `v1` to B and record the exact administrative event time/source.
5. Trigger the matrix across relevant events/runners. Include a remote Action step with `if: false`, a normal executed step, a failed job suitable for partial rerun, and a reusable workflow pinned by mutable ref.
6. Wait for terminal jobs and collect independent expected run/attempt/job IDs, setup/lifecycle evidence, and referenced-workflow SHAs.
7. Restore `v1` to A and change the current default-branch workflow so present state appears safe.
8. Perform a full rerun, a failed-job rerun, and a single-job rerun. Move the reusable-workflow tag between operations to validate documented full/partial behavior. Do not assume repository Action behavior; record each attempt's logs.
9. Run CIRewind after restoration, then archive the compact evidence. Remove raw logs from the test input and replay the B incident pack offline.
10. Verify per attempt/job/step:

   - Exact same-attempt runtime resolution of B plus its correlated lifecycle start → `CONFIRMED_EXECUTED`.
   - B plus completed setup and a skipped main with no pre/post → `CONFIRMED_DOWNLOADED`.
   - Announcement followed by setup failure → neither confirmed downloaded nor executed; a gap.
   - Exact affected reusable workflow in attempt metadata → `CONFIRMED_CALLED_WORKFLOW`, without claiming all jobs ran.
   - Attempts resolving A do not inherit B findings.
   - Matrix children remain separate job IDs/findings.
   - Current tag/workflow A does not alter historical B results.
   - Replay reproduces normalized B findings without GitHub or raw logs.

The protocol passes only if no result depends on querying the restored current tag.

## Scenario acceptance matrix A–P

| ID | Controlled setup | Required positive result | Required negative assertion / evidence |
| --- | --- | --- | --- |
| A | Direct repository Action declared by mutable tag; runtime resolves harmless affected B | Executed occurrence is `CONFIRMED_EXECUTED`; with runtime removed but exact historical ref/window present, a separate fixture yields `RUN_IN_WINDOW_MUTABLE_REF` | Current A target never clears B; merely in-window run never claims B executed |
| B | Exact composite metadata calls affected Action | Static `ACTION_CONTAINS_ACTION`; exact same-attempt child runtime resolution plus child lifecycle start supports `CONFIRMED_EXECUTED`, while exact resolution plus completed preparation alone supports `CONFIRMED_DOWNLOADED` | Static metadata or wrapper start alone never proves child resolution/start |
| C | Exact reusable workflow calls composite which calls affected Action | Attempt exact called SHA gives `CONFIRMED_CALLED_WORKFLOW`; evidence-backed nested chain; child state follows its own runtime evidence | Calling workflow does not mean every nested job/step executed; secrets do not jump call levels |
| D | Remote affected Action prepared in setup; top-level main condition false; no pre/post lifecycle | `CONFIRMED_DOWNLOADED` only after setup completion is proven; API/log step is skipped | Download announcement alone is insufficient; no `CONFIRMED_EXECUTED` |
| E | Full rerun after mutable tag moves/restores | Separate attempt maps and findings show exact SHA resolved in each rerun; documented reusable workflow full rerun re-resolves its ref | No Action/called-workflow SHA copied from another attempt; original SHA/ref/privilege facts remain separate identifiers |
| F | Failed-job and single-job reruns after reusable-workflow ref moves | Attempt metadata retains first-attempt called-workflow SHA as documented; only rerun jobs belong to new attempt | Jobs absent from partial attempt remain attached to earlier attempt; no fictitious combined attempt |
| G | Fake repository/org secret directly mapped to affected step `with`/`env`; affected lifecycle starts | Existence/reference/pass/step reachability edges are separate and named; printed token handled separately | No secret value/non-empty/read/exfiltration claim; secret used only by another step is not attributed |
| H | `secrets: inherit` A→B; B references one fake name and calls C with/without forwarding | Inheritance declared at A→B; known eligible set if contemporaneous; referenced name reaches appropriate B step; B→C only if passed again | “All secrets reached every nested workflow/step” is prohibited |
| I | Environment approval is required and intentionally withheld/rejected; job never starts | `TARGETED_ENVIRONMENT` plus waiting/rejected gate evidence; no environment-secret eligibility | No Action execution or environment-secret access claim |
| J | Executed affected Action job has effective `id-token: write`; no cloud trust policy exists | `OIDC_MINTING_CAPABILITY` with permission/lifecycle evidence | No `CLOUD_IDENTITY_REACHABLE`, token-request, exchange, or role-assumption claim |
| K | Affected job on isolated ephemeral self-hosted runner | Runner ID/name/group/labels and self-hosted classification with evidence | No persistence, lateral movement, internal-resource, or label-truth claim |
| L | Harmless fork PR triggers `pull_request_target`; base workflow does not execute PR code | Correct base workflow definition/event identity and effective token permissions; actors kept separate | PR head SHA is not used as universal workflow commit; no automatic secret availability/use claim |
| M | Two-axis matrix with duplicate-looking hostile display names | Each API job ID produces independent attempt/job/step findings and coverage | Names do not merge jobs or forge log boundaries |
| N | Attempt/job logs absent, expired, deleted, forbidden, truncated, or unsupported grammar variants | Typed coverage object and `UNKNOWN_EVIDENCE_GAP` when material | Never `NO_MATCH_CONFIRMED` or “safe” from missing logs |
| O | Historical exact workflow contains affected ref; current default branch removes/changes it | Historical state derives only from exact historical bytes; current snapshot can separately be `CURRENT_REFERENCE_ONLY` if applicable | Present-day YAML never substitutes for historical definition |
| P | Synthetic exact historical YAML pins SHA A while same-occurrence runtime fixture resolves affected B | Preserve both propositions and emit `CONTRADICTORY_EVIDENCE`; if structural join remains exact, companion B execution/download finding may remain | Never silently select static or runtime evidence; mutable-ref→SHA is not itself contradictory |

### Additional scenario Q — concurrent/background steps

Use current GitHub.com background `run` and `uses` syntax with two harmless overlapping steps, an explicit wait in one branch, fake secret flow confined to one step, and a later artifact/deployment fixture. Required results:

- Per-step start/end intervals and explicit synchronization edges are retained.
- Overlapping steps are unordered; YAML/API step number creates no before/after, file flow, secret flow, or causation edge.
- The explicit wait orders only the waited step and its documented successor.
- Resource language is direct attribution when an ID join exists, otherwise `OBSERVED_AFTER` only when timing actually establishes it.

The primary source for this current behavior is GitHub's [workflow syntax for background steps](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#jobsjob_idstepsbackground) and [parallel-steps changelog](https://github.blog/changelog/2026-06-25-actions-steps-can-now-be-run-in-parallel/) (retrieved 2026-08-20).

## Event semantics matrix

Each event fixture preserves API `head_sha`, trigger SHA/ref, workflow-definition candidate/commit, actor, triggering actor, fork/base/head repository IDs, and event time separately.

| Event | Required test focus |
| --- | --- |
| `push` | Historical workflow and trigger commit/ref; mutable Action setup time |
| `pull_request` | Merge/head/base distinctions, fork token/secret restrictions, approval/skip states |
| `pull_request_target` | Base/default workflow context, elevated token risk, no automatic attribution to PR head |
| `workflow_run` | Triggering run identity versus current workflow definition; privilege boundary; chain depth |
| `issue_comment` | Default-branch workflow eligibility, comment actor/event payload versus checked-out code |
| `repository_dispatch` | Default-branch workflow context and external actor/client payload as hostile data |
| `workflow_dispatch` | Selected ref/input provenance and triggering actor |
| `schedule` | Default-branch/current-at-event workflow candidate and delayed execution time |
| `workflow_call` | Caller/called exact SHAs, nested depth, permissions, named/inherited secrets |

Claims follow the per-event primary documentation in [GITHUB_DATA_SOURCES.md](GITHUB_DATA_SOURCES.md); uncertain caller-commit behavior is a spike outcome, not encoded as a convenient test assumption.

## Mandatory invariant regression tests

The test oracle and user-facing methodology fixture contain these exact strings:

| Invariant | Positive oracle | Prohibited mutation |
| --- | --- | --- |
| `Action downloaded != Action executed` | Scenario D and failed-preparation fixture distinguish states | Replacing preparation with execution fails |
| `Repository possesses a secret != affected step could read that secret` | G/H separate existence, policy, reference, pass, lifecycle | Existence-only reachability fails |
| `id-token: write != cloud role assumed` | J emits minting only | Role assumption from permission fails |
| `Workflow ran during incident window != compromised SHA executed` | Mutable-ref/window without runtime stays non-execution | In-window promotion fails |
| `Current tag points to a safe commit != historical runs were safe` | A/E preserve B after restore A | Current lookup changing history fails |
| `No retained logs != no compromise` | N emits gap | Missing log negative fails |
| `Deployment followed an affected step != attacker caused the deployment` | Q/resource fixture uses observed-after | Causal wording/edge fails |
| `Present-day workflow YAML != historical workflow definition` | O keeps both bitemporal snapshots | Current YAML substitution fails |

A repository-wide text test verifies each sentence appears verbatim in this document and [EVIDENCE_MODEL.md](EVIDENCE_MODEL.md).

## Fuzzing

### Targets

- ZIP central directory, entry iterator, duplicate/path/type logic, streaming decompression, and log-layout classifier.
- Traditional/immutable setup groups, permissions, runner metadata, structural step frames, timestamps, concurrent interleaving, and truncation state machines.
- Workflow/Action YAML AST, anchors/aliases/duplicates, expression reference extraction, matrix, composite/reusable/local/self resolution.
- Incident-pack YAML strict parser, canonicalizer, time/ref/path/domain/IP/digest/literal normalizers, and cross-reference validator.
- API JSON decoders and error sanitizer.
- SQLite imported archive header/schema/row validator and evidence/derivation DAG verifier.
- HTML/JavaScript-data/JSON/JSONL/CSV/Markdown/terminal encoders.

### Assertions

No panic, data race, uncontrolled allocation, unbounded recursion, filesystem escape, network/process call, token-like test marker in diagnostics, invalid output, or nondeterministic result. Cancellation completes within the harness deadline. Any accepted execution finding satisfies the exact identity/lifecycle predicate. Fuzz corpus crashes become permanent regression seeds.

Fuzz runs have short per-change budgets and longer scheduled/release budgets; published reports include toolchain, seeds/corpus hash, elapsed executions, and resource caps rather than claiming exhaustive safety.

## Security regression tests

- ZIP Slip variants, absolute/UNC/drive/backslash/ADS paths, symlink/device/FIFO mode, duplicate/case collision, bomb ratios, false sizes, CRC/truncation, excess files, and nested archive bytes.
- YAML alias bomb, deep structures, duplicate permissions/uses, custom tags, implicit timestamps, giant expressions/scalars, invalid UTF-8.
- ANSI CSI/OSC/DCS, clipboard/hyperlink controls, CR/newline log splitting, bidi overrides, NUL, confusables, and giant names.
- HTML closing tags, event attributes, script/style/comment delimiters, U+2028/U+2029, malicious URLs, graph labels, CSP mutation, and browser no-network assertions.
- CSV formula prefixes `=`, `+`, `-`, `@`, tab, CR plus quotes/newlines/delimiters.
- SQL metacharacters, malicious imported schema/views/triggers, application ID mismatch, oversized rows, corrupt pages, extensions/ATTACH attempts.
- Output symlink swap, non-empty destination, reserved names, case collision, long paths, temporary-file race, permissions/ACL failure.
- Redirect credential leak, signed-query persistence, multiple/downgrade/private-network redirect, unbounded body, proxy diagnostics.
- Pack script/template/regex/HTML/include/network attempts, unknown field/version, ambiguous/untyped digest, approximate time represented as exact.
- Raw logs absent by default; explicit raw mode labels sensitivity and respects byte limits.
- Telemetry/no-remote-assets scan of binary behavior and generated report references.

The repeatable Linux reference gates are `make safety-audit` and
`make browser-audit`. The former traces offline commands for network syscalls and
child exec; the latter exercises a freshly generated report through WebDriver and
checks its CSP hashes, local-only request set, console, and filters. Neither gate
replaces the supported-platform/browser matrix. The current observation is
recorded in
[`validation/2026-08-21-offline-safety-and-browser.md`](validation/2026-08-21-offline-safety-and-browser.md).

## Deterministic replay tests

For a fixed archive, pack, policy, semantic/parser versions, and clock:

- Run replay at least twice with randomized worker scheduling and database row order.
- Compare canonical database exports, findings JSON, CSV, HTML, Markdown, graph projection, ledger, collection metadata, and manifest bytes.
- Verify archive file is byte-unchanged and opened read-only.
- Deny DNS, HTTP, socket connection, and child process creation.
- Add a new exact SHA/digest pack and verify it matches retained structured observations.
- Add a new log literal absent from compact retained data and verify an explicit replay coverage gap.
- Change only current/ref metadata in another archive observation and verify historical findings are unchanged.
- Change semantic rule version and assert a new analysis/finding revision is explicit, never a silent mutation.

## Cross-platform qualification

Primary release targets are Linux, macOS, and Windows on amd64 and arm64 where the selected Go/SQLite dependency supports them. For each supported target:

- Build with CGO disabled under the intended reproducible flags.
- Run unit/integration/golden tests available on the platform.
- Verify SQLite migrations, locking, WAL finalization, owner-only permissions/ACL behavior, atomic rename, path canonicalization, long path/case semantics, newline handling, and browser report opening.
- Generate a case and replay it on another OS; normalized semantic outputs must match, while platform metadata may differ in documented fields.
- Verify no platform-specific external command is required.

A target whose owner-only case permissions or SQLite integrity cannot be assured is not advertised as supported merely because it compiles.

## Scale and performance tests

Performance tests use generated metadata and safe repetitive log structures, never production data.

| Profile | Repositories | Runs | Attempts/jobs | Log/control volume | Purpose |
| --- | ---: | ---: | ---: | ---: | --- |
| Small | 100 | 10,000 | 25,000 | 5 GiB streamed | Per-change regression |
| Medium | 1,000 | 100,000 | 300,000 | 50 GiB streamed/mostly discarded | Release qualification |
| Large metadata | 10,000 | 1,000,000 | 3,000,000 | Structured observations only | Index/query/graph/coverage scaling |

Release benchmark reports publish hardware, Go/SQLite versions, worker/byte limits, data generator seed, DB size, wall/CPU time, peak RSS, disk write volume, requests, and report size.

Objective gates:

- Peak live parser/download memory is bounded by configured weighted buffers and does not grow with total streamed log bytes.
- Increasing records 10× from small to medium causes no worse than 15× CPU time or database size for equivalent data; any superlinear query is profiled/fixed or documented as a blocker.
- Large-metadata peak RSS stays below 2 GiB on the published reference machine; SQLite cache settings and queue budgets are included.
- Request count equals the endpoint plan plus bounded retries/overlap; no per-finding refetch.
- SQLite indexes support attempt finding, evidence trace, coverage reconciliation, and finding-centered graph queries without full-table nested scans in query plans.
- HTML defaults to a finding-centered subgraph and remains usable; full graph export does not require rendering all nodes at once.
- Cancellation under load stops scheduling immediately and drains/aborts bounded work without corrupting the store.

These are qualification thresholds, not calendar or customer-runtime promises. Phase 0/9 may tighten them based on measured evidence.

## Coverage and state acceptance table

At least one deterministic fixture must emit each state for the intended reason:

| State | Canonical fixture |
| --- | --- |
| `CONFIRMED_EXECUTED` | Direct exact B resolution + structural B lifecycle start |
| `CONFIRMED_DOWNLOADED` | Remote B preparation completed + skipped main/no lifecycle |
| `CONFIRMED_CALLED_WORKFLOW` | Attempt metadata exact affected called SHA |
| `DECLARED_AT_RUN_SHA` | Proven historical workflow pins affected full SHA; runtime absent |
| `RUN_IN_WINDOW_MUTABLE_REF` | Proven historical mutable ref + started job interval within pack window + runtime gap |
| `POTENTIAL_TRANSITIVE` | Exact historical wrapper/composite chain to affected component; runtime boundary unresolved |
| `CURRENT_REFERENCE_ONLY` | Only current workflow snapshot references affected component |
| `NO_MATCH_CONFIRMED` | Bounded scope with all pack-required evidence/classes parsed and no indicator match |
| `UNKNOWN_EVIDENCE_GAP` | Required attempt log/definition/grammar unavailable |
| `CONTRADICTORY_EVIDENCE` | Fixed historical SHA A versus same-occurrence runtime B |

For each, mutate away one indispensable input and assert the state either weakens, becomes a gap, or disappears according to the normative matrix. No fixture obtains a stronger state by adding only pack confidence, current state, or temporal proximity.

## Test traceability and ownership

Every builder task links to test IDs in `TASKS.md`. Suggested test ID prefixes are:

- `ID-*` identity/schema
- `COL-*` collection/coverage
- `LOG-*` runtime grammars
- `RES-*` historical resolution
- `EXP-*` credentials/resources
- `PACK-*` incident packs
- `CASE-*` store/output/manifest
- `SEC-*` hostile input
- `LAB-A` through `LAB-Q`
- `PERF-*` scale
- `XPLAT-*` platform

A semantic change requires updating the normative evidence model, a decision-table test, affected goldens, and a finding revision/engine version. A test-only golden update cannot redefine product semantics.

## Primary sources for test oracles

Retrieved 2026-08-20:

- [GitHub Actions runner, pinned source references](https://github.com/actions/runner/tree/258d6c857db3519913f7deb6004b60172f8043ae) — runner setup, preparation, condition, and lifecycle boundaries.
- [GitHub-maintained audit-actions-workflow-runs, pinned parser](https://github.com/github/audit-actions-workflow-runs/blob/1e536cc1af05a5e37a69d0c8dd479ec6ca2685bf/audit_workflow_runs_utils.js) — traditional and immutable setup grammar precedent.
- [REST workflow runs](https://docs.github.com/en/rest/actions/workflow-runs?apiVersion=2026-03-10) and [workflow jobs](https://docs.github.com/en/rest/actions/workflow-jobs?apiVersion=2026-03-10) — attempts, logs, jobs, steps, runner fields, and search ceiling.
- [Using workflow run logs](https://docs.github.com/en/actions/how-tos/monitor-workflows/use-workflow-run-logs) — partial rerun log scope and deletion.
- [Reusing workflow configurations](https://docs.github.com/en/actions/reference/workflows-and-actions/reusing-workflow-configurations) — nested workflows, permissions, and rerun behavior.
- [Workflow syntax](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax) — events/permissions/local/self/background syntax.
- [Artifact/log retention](https://docs.github.com/en/organizations/managing-organization-settings/configuring-the-retention-period-for-github-actions-artifacts-and-logs-in-your-organization) — retention variability and non-retroactivity.
