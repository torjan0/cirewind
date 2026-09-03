# CIRewind implementation status

Published-release status snapshot: **2026-08-22**. Unreleased v0.2 worktree note
updated **2026-09-02**.

updated **2026-09-03**.

Release decision: **GO and published for experimental v0.1.1 inside
[`ADR 0011`](adr/0011-experimental-v0-1-qualification-envelope.md)'s bounded
qualification envelope**. Release tree
`006baad681fe594b1961158de66b3fa6813f26db` passed the required PR merge-object
matrix. Exact release commit `d4954356e733af42500061885dae36996281547e`
passed local deep qualification and the required `main` CI matrix, followed by
clean-clone reproduction, protected tag, draft, attestation, downloaded-asset,
and separate publication gates. GitHub Release
[`v0.1.1`](https://github.com/torjan0/cirewind/releases/tag/v0.1.1) is public,
latest, and immutable. The earlier protected `v0.1.0` candidate remains
unpublished after its workflow correctly failed closed before draft creation.
Open compatibility and scale work below remains nonblocking only within the
explicit experimental limits; this is not a production-readiness claim.

This document distinguishes implemented behavior from live qualification and
from known limits. A passing fixture is not a claim about every GitHub runner,
organization, credential, or expired object.

## Qualification vocabulary

- **Offline-tested** — exercised with deterministic local fixtures and no
  credential or network dependency.
- **Mock-tested** — exercised at an external boundary against a local controlled
  transport or normalized response fixture.
- **Controlled live-qualified** — exercised read-only against harmless private
  GitHub.com lab objects, with identifiers retained outside the public tree.
- **Public live-observed** — exercised read-only against a public GitHub.com
  object but not a controlled oracle.
- **Experimental limitation** — available behavior whose compatibility or
  completeness is not a v0.1 support claim; output must expose partial coverage.
- **Release blocker** — a candidate-integrity, security, evidence-semantic, or
  publication gate still required on the exact release revision.

## v0.2 adoption branch status

The published product remains v0.1.1. The `v0.2-adoption` worktree contains
unreleased adoption work and must not be read as a v0.2 release or qualification
claim. The accepted forensic semantics remain unchanged: the ten canonical
finding states, five provenance identifiers, eight mandatory invariants, and
attempt/job-specific identity are still the authority.

Real incident-pack governance infrastructure is implemented in the current
worktree under `internal/packreview`, `tools/packreview`, and the closed schemas
under `schema/`. It provides:

- strict, bounded packet, retained review-policy, source, typed claim, conflict,
  pre-review assertion, human review, normalized platform-observation,
  promotion, and append-only registry records;
- pre-decode retained-JSON shape enforcement for required fields and explicit
  nulls, with `Claim.canonicalPointer` as the sole schema-authorized nullable
  value, plus path-bearing-field rejection before any derived filesystem read;
- deterministic candidate, fixture, and review-record manifests with fixed
  allowlists, exact byte/hash bindings, link/path/collision checks, and bounded
  file/depth/total-size limits;
- a clean-checkout review-unit contract that permits Git's unavoidable absence
  of an empty `approvals/` directory only at candidate stage and requires the
  real closed directory as soon as review or promotion material exists;
- a material-inventory validator derived from the canonical incident pack,
  including source-to-field and source-location closure, typed identity and
  digest namespaces, temporal precision, deliberate omissions bound to semantic
  slots that are actually absent, symmetric conflicts, and secondary-source
  restrictions;
- deterministic inert `REVIEW.md` rendering from canonical human-supplied
  `review.json`, plus an exact fixed review-body renderer from a separately
  human-authored material assertion; neither representation creates or
  authenticates an approval;
- a bounded local adapter for the GitHub list-reviews response plus a manually
  dispatched, read-only repository workflow gated to the selected default
  branch; it builds the normalizer before token use, projects/captures review
  metadata twice, byte-compares it, rechecks exact C, then normalizes without a
  credential and transfers the canonical snapshot with its hash and artifact ID;
- offline comparison of exact review records to an externally acquired,
  normalized GitHub PR-review snapshot, including candidate-head, PR, reviewer,
  account type, latest effective state, dismissal, exact body hash, official
  policy repository, role, scope, self-review, checked-source closure, and
  policy-count checks;
- closed fixture-index replay through the production offline derivation path,
  with exact finding/state/provenance/evidence-or-gap/coverage-ID comparison,
  forbidden-state checks, and rejection of unindexed scenario snapshots;
- idempotent no-overwrite promotion of byte-identical approved candidate YAML,
  plus retained platform-snapshot hashing and separate promotion/review-record
  manifests, with the two retained timestamps constrained to an inclusive
  15-minute record-chronology interval; this structural check is not an
  authenticated wall-clock freshness claim; and
- reviewed-tree and append-only registry verification, including allowed status
  transitions, immutable history, supersession closure, exact promoted bytes,
  manifest bindings, bounded closed-tree traversal, revalidation of retained
  platform approvals and retained validator/review-policy versions, validation
  of review units retained in registry history, and an externally supplied
  promotion content commit P.

The maintainer-only tool intentionally performs no network request, process or
Git execution, credential lookup, approval creation, commit, push, tag, release,
or registry mutation. The fixed Git guard requires exact `HEAD == C` and a clean
candidate worktree, or—only during post-approval materialization—an explicit
maintainer-controlled allowlist of fixed review-record paths. Rename sources,
ignored untracked files, and gitlink/submodule changes remain visible to this
check. Candidate change-set separation runs in the dedicated default-branch
`.github/workflows/pack-review-candidate-policy.yml` `pull_request_target`
workflow: only the exact trusted-base script executes,
the pull-request head is checked out solely as inert Git data, permissions are
read-only, and the workflow executes no head-controlled file, build, test,
dependency, or hook. The gate begins governing subsequent PR events only after
the trusted workflow and guard land on the default branch. This avoids both a
policy definition controlled by the candidate and an initial-PR bootstrap
failure. Qualifying GitHub
approvals are obtained against C. Candidate CI must invoke the candidate-tree
command with externally supplied `HEAD` C; that command validates every retained
unit. Existing registered history retains its recorded C, while unregistered
candidate content binds to the supplied C; the registry at C cannot be required
to name C because that would be a commit self-reference. The
normalized snapshot and human records are then materialized without redefining
C, promotion output is committed as P, and later append-only registry history
may name C and P without naming its own containing commit. Protected history and
acquisition/authentication of the GitHub observation remain external caller/CI
responsibilities. A checked-in normalized snapshot is not self-authenticating.
It is point-in-time process evidence: a human must verify the exact workflow
run/ref/source commit, PR approval on C, artifact identity, and hashes, and the
offline verifier cannot discover a later dismissal or review. A detached local
snapshot is not platform proof.
The adapter behavior follows the [GitHub CLI pagination/jq contract](https://cli.github.com/manual/gh_api),
the CLI's [source-enforced `--slurp`/`--jq` exclusion at revision `40b742f`](https://github.com/cli/cli/blob/40b742f76d68e6b1f472942a6368db4b5d765641/pkg/cmd/api/api.go),
and the [GitHub REST list-reviews endpoint](https://docs.github.com/en/rest/pulls/reviews?apiVersion=2022-11-28#list-reviews-for-a-pull-request),
retrieved 2026-08-30.
The candidate-policy trust split follows GitHub's
[`pull_request_target` security guidance](https://docs.github.com/en/actions/reference/security/securely-using-pull_request_target)
and [event semantics](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#pull_request_target),
including the explicit checkout-v7 opt-in used only for inert head inspection;
retrieved 2026-08-30.

The infrastructure landed on `main` in PR #4 as commit
`200fde2e8ef651545b6da1ab2b598ddb88820555`, and hosted CI run
[`33336075460`](https://github.com/torjan0/cirewind/actions/runs/33336075460)
passed all ten jobs at that commit, including the incident-pack review contract
job. That satisfies the bounded criteria of `PACK-020` and `PACK-021`;
implementation presence is still not a factual-review result. The targeted
synthetic machine fixture matrix now covers all ten finding states, inclusive-
start/exclusive-end boundaries, contradiction, evidence gaps, exact coverage/gap
oracle checks, and a downloaded-only scenario that forbids
`CONFIRMED_EXECUTED`. `PACK-024` remains open because its `PACK-023` dependency,
complete CI/governance run, and final workflow security audit are not yet closed.
The checked-in policy intentionally names no fabricated eligible maintainers, so
a real promotion remains fail-closed.

The 2026-08-30 pre-commit path-confinement variant audit found and corrected an
accumulate-then-dereference validation family before publication. Its
repository-wide sink review found no active recurrence, and the adjacent
retained-JSON schema/runtime audit covers all current governance document types.
See
[`2026-08-30-pack-review-path-variant-audit.md`](validation/2026-08-30-pack-review-path-variant-audit.md).
The final local governance pass then completed normal/race/vet, Action and shell
lint, vulnerability, license, secret-history, syscall-safety, six-target build,
demo, manifest, and disposable-clean-tree exact-HEAD checks. The exact local
scope and remaining hosted/human gates are recorded in
[`2026-08-30-pack-review-governance-qualification.md`](validation/2026-08-30-pack-review-governance-qualification.md).

No real incident pack has been independently reviewed, promoted, or made
release-ready. No automated session, local JSON record, deterministic Markdown
rendering, schema result, manifest, or normalized snapshot counts as an
independent human approval. Reviewdog and tj-actions still require the accepted
outside-human and maintainer gates; Trivy still requires two distinct outside
reviewers in addition to the maintainer policy; Xygeni remains nonblocking and
excluded by default. `PACK-022` and `PACK-023` remain open because their accepted
criteria require an actual qualifying GitHub human approval against C and a real
C-to-P-to-later-registry history, respectively.

### Exportable public-lab source

The current uncommitted v0.2 worktree contains an offline exportable source
package for the separate harmless A-to-B-to-A laboratory. It does not create or
configure a GitHub repository. The local implementation includes:

- deterministic owner/repository-specialized Git history, a Git bundle and
  sidecar object-manifest contract, immutable marker A/B commits and annotated
  fixture tags, a lightweight disposable `v1`, Apache-2.0 licensing, DCO text,
  and minimal read-only workflow permissions;
- direct, composite, reusable, skipped, matrix, and rerun workflow definitions,
  with only the synthetic marker reference mutable and no secret, environment,
  self-hosted runner, external service, or third-party Action requirement;
- an exact-object tag-move tool that accepts only a repository-matching
  GitHub.com remote in production, pre-reserves its observation record before a
  mutation, requires an exact old-object lease and literal acknowledgement,
  preserves uncertain outcomes as uncertain, and emits exact restoration
  guidance rather than claiming success from an interrupted push;
- bounded, closed run, reproduction, tag-observation, pack-input, stable-index,
  and object-manifest records, plus a privacy-warning issue form; and
- cross-binding from exact install/restore observations to the pack input and
  synthetic incident pack, and from that input through run and reproduction
  records to the attempt/job-specific qualification oracle. Download/preparation
  alone remains insufficient for `CONFIRMED_EXECUTED`.

Targeted offline package and command tests cover deterministic construction,
two empty-repository imports, Git object/ref topology, hostile records and
labels, local-only mutation fault injection, output-path replacement, repository
controlled Git filters, transport-environment overrides, interrupted pushes,
exact evidence edges, conservative finding language, privacy rejection, and
the stable reproduction index. Local filesystem remotes exist only behind a
test-only policy; the production command rejects them before invoking Git.

The final public-lab-specific local closure regenerated the checked artifacts,
compared them byte-for-byte with an independent deterministic generation, and
passed bundle verification, two empty-repository imports, strict full Git
object checks, source/history/privacy/license/DCO/workflow-permission audits,
generated-workflow `actionlint`, marker syscall observation, shell lint, focused
normal tests, focused race tests, and focused vet. The checked bundle is 39,656
bytes with SHA-256
`16f41eac01532e764d2ed0518db2a7dafcbcd3bd6bcea5f8e4e9e23385667b99`;
the 20,838-byte object manifest has SHA-256
`199f914b9fbc6aaf1d5cf8ed41f8734f594d072c8475d22725855d527aa682da`.
Those results satisfy the bounded local criteria for `LAB-PUBLIC-001`,
`LAB-PUBLIC-002`, `LAB-PUBLIC-004`, and `LAB-PUBLIC-005`. The same exact
worktree also passed the isolated clean-cache whole-repository preflight:
normal and race tests, vet, reachable-vulnerability and license checks, six
cross-platform builds, deterministic demo generation, and case-manifest
verification. Hosted, maintainer, outside-human, and final v0.2 release gates
remain separate and open.

GitHub-hosted confirmation of the skipped-step preparation grammar remains
`LAB-PUBLIC-003`; authorized live qualification and repository creation remain
`LAB-PUBLIC-006` through `LAB-PUBLIC-008`; one genuinely independent
outside-human reproduction remains `LAB-PUBLIC-009`; and maintainer acceptance
plus release-identity closure remain `LAB-PUBLIC-010` and `LAB-PUBLIC-011`. No
external repository, mutable remote tag, workflow run, publication, independent
reproduction, or human review is claimed. The local scope and open gates are
recorded in the
[`2026-08-31 public-lab local qualification`](validation/2026-08-31-public-lab-local-qualification.md).

A 2026-09-02 pre-commit security audit of that same uncommitted batch left every
artifact identity unchanged. It pinned the tag-control Git boundary's hook path
to the null device, rejected option-shaped remote arguments at the boundary
allowlist, removed a dead empty-overlay exception from the bundle builder,
stopped a pre-Git policy rejection from printing a remote-readback diagnostic,
added an ordinary `go test` guard that fails on every hosted CI target when the
checked artifacts drift from deterministic regeneration, marked the bundle as a
binary Git attribute, and documented that the isolated boundary makes SSH the
practical authenticated transport while `actionlint`, `strace`, and the shell
negative tests remain Linux-local gates. Its commands, results, and the items
that remain outside local validation are recorded in the
[`2026-09-02 public-lab batch audit`](validation/2026-09-02-public-lab-batch-audit.md).

## CLI status

| Command | Status | Qualification boundary |
| --- | --- | --- |
| `cirewind --help`, `help`, `version` | Implemented and offline-tested | Release builds inject version, source revision, and build time, and those values are authoritative. An unstamped build reports the Go module version and the VCS revision the toolchain embedded, marks a modified worktree, and otherwise reports `dev` or `unknown`; the versioned `go install` shape is exercised offline through a file-based module proxy by `make go-install-check` on the host and by `make go-install-qualify` in a clean minimal container, both cold and warm, as recorded in the [2026-09-03 lane prequalification](validation/2026-09-03-go-install-lane-qualification.md). Installation lanes and prerequisites are documented in [`INSTALLATION.md`](INSTALLATION.md). |
| `pack validate` | Implemented and offline-tested | Strict parse, semantic validation, deterministic canonical JSON and hashes; validation does not prove source truth. |
| `investigate` | Implemented; mock-tested and controlled explicit-repository live-qualified | Organizations are supported syntactically and by mock transport, but dense-window and organization-visibility completeness are experimental. |
| `archive` | Implemented; offline-, mock-, and controlled live-qualified | Compact incremental facts, checkpoints, overlap, watched-parent refresh, raw opt-in, idempotency, and interruption recovery. |
| `replay` | Implemented and offline-tested | No GitHub client or network path; re-derives findings without rewriting archived source facts. |
| `verify` | Implemented and offline-tested | Detects added, missing, or changed case files; integrity, not authenticity or legal certification. |
| `make demo` | Implemented and offline-tested | Generates every required case output and asserts deterministic synthetic counts; deliberately partial coverage. |

Network authentication is read from `CIREWIND_GITHUB_TOKEN`, `GITHUB_TOKEN`, or
`GH_TOKEN` in that order. No command accepts a token value flag. Replay, pack
validation, verification, and the demo are network-independent.

## Evidence and domain model

Implemented and tested:

- separate repository, workflow path, workflow definition object, trigger object,
  caller object, called reusable-workflow object, Action source object, immutable
  digest, run, attempt, job, step, event, actor, triggering actor, event time, and
  collection time;
- material job-execution identity based on repository plus
  `run_id + run_attempt + job_id`, without merging reruns;
- exactly ten finding states and five provenance identifiers defined once in the
  domain model and checked against schemas/docs;
- deterministic evidence and finding IDs, SHA-256 content hashes, derivation
  inputs, parser versions, redaction/raw status, source requests, supported
  findings, and explicit collection errors;
- bitemporal event/collection observations, versioned derivation rules,
  contradictions, coverage closure, and evidence-gap findings; and
- validation that a finding has evidence IDs or an explicit evidence-gap reason.

All findings and material graph edges are evidence-linked. Missing retained
evidence cannot produce `NO_MATCH_CONFIRMED`.

## Storage, archive, and case integrity

The pure-Go SQLite implementation provides migrations, schema/application IDs,
foreign keys, parameterized SQL, transactions, content deduplication, idempotent
archive batches, checkpoints, normalized compact facts, and restrictive Unix
permissions where supported. Imported databases are checked against an allowlist
of expected schema objects and normalized DDL rather than trusted as arbitrary
SQLite.

Evidence JSONL is append-only within a case generation pass. Finalized cases:

- checkpoint WAL and select a read-only-friendly journal mode before hashing;
- run integrity and foreign-key checks;
- contain a fixed expected file set plus opt-in `raw/`;
- reject unsafe/non-empty destinations and unsafe parent symlinks; and
- detect file-set or byte changes through `manifest.sha256`.

Incremental archives remain WAL-capable. Replay uses a WAL-aware read-only path
that can see committed facts after process interruption. A clean archive close
checkpoints/removes sidecars; finalized-case readers reject any unexpected WAL,
shared-memory, rollback-journal, link, or special-file sidecar.

Raw-enabled archives consist of the database and a content-addressed `.raw/`
sidecar. Raw loss becomes a capability gap unless raw case materialization was
explicitly required, in which case generation fails closed. No raw log is
retained by default.

## Incident packs

The `cirewind.dev/v1alpha1` pack implementation provides strict YAML decoding,
canonicalization, JSON Schema, semantic checks, source/indicator provenance,
component windows, mutable refs, typed full Git objects, immutable digests,
known-good objects, literal log indicators, remediation, and rotation triggers.

Limits cover bytes, nodes, depth, maps, sequences, scalars, counts, strings,
paths, and cancellation. YAML anchors, aliases, merge keys, custom tags,
duplicate/unknown fields, implicit timestamps, active markup, regex fields,
executable content, and pack-directed requests are rejected. Only explicitly
synthetic packs ship in v0.1; there are no fabricated real incident indicators.

## GitHub.com collection

The read-only transport and collector implement:

- explicit API version and user agent;
- bounded pagination, concurrency, deadlines, retry/backoff/jitter, primary and
  secondary rate handling, same-origin relocation, temporary log-object redirect
  isolation, conditional request metadata, and sanitized errors;
- organization enumeration and explicit repository resolution;
- recursive created-time run partitioning and local half-open filtering;
- every observed attempt, attempt-specific jobs, attempt/job logs, matrix job
  separation, actors, event context, and coverage accounting;
- per-repository archive checkpoints, 15-minute overlap, and provisional 65-day
  parent discovery/watch for reruns and delayed jobs;
- historical contents and Git object/tag/commit routes;
- attempt-level referenced reusable workflows; and
- conservative run-scoped artifact, pending-deployment, and approval context.

Partial permissions do not abort unrelated collection. Authentication failure,
denial, hidden/deleted resources, retention loss, malformed content, parser
limits, unsupported syntax, contradictions, and transient failures are typed,
persisted, scoped, sanitized, and surfaced in coverage.

Public read-only observations covered a repository relocation, separate attempts,
an exact called-workflow object, retained metadata after log loss, consolidated
attempt ZIP layout, and traditional repository-Action setup facts. The controlled
private lab qualified explicit-repository collection for the central A→B→A tag
movement and the scenarios described below.

The following are experimental rather than v0.1 completeness claims:

- an organization with an unsplittable saturated second at GitHub's result
  ceiling;
- representative classic PAT, fine-grained PAT, and GitHub App installations;
- every retention/rate-limit/abuse response;
- enterprise audit and GraphQL enrichment; and
- full secret, package, release, deployment, and runner inventories.

## Hostile log ingestion and lifecycle semantics

ZIP ingestion is bounded by download, extracted total, file, count, path,
compression-ratio, and cancellation limits. It rejects traversal, absolute or
ambiguous paths, links, devices, duplicate case-folded names, archive permissions,
and malformed declarations.

The parsers recognize traditional repository-Action downloads, immutable package
version/source/digest groups, token permissions, secret source, complete job
identity, runner version/image/OS, repository-hosted classification evidence,
step lifecycle, skip, failure, truncation, and gaps. Traditional split logs and
the current root consolidated whole-job shape are supported without relying on a
single timestamp width or indentation.

Lifecycle is explicit:

`DECLARED → RESOLVED → DOWNLOADED/PREPARED → STEP_STARTED → STEP_COMPLETED`

`RUNTIME_IOC_OBSERVED` is a separate observation. Resolution/download alone never
supports execution. The controlled lab established direct B execution, B
download with a skipped step, and B-versus-restored-A attempt separation with no
download-only false execution.

Live immutable Action package output, all pre/post forms, every runner version,
localization, and ambiguous dynamic/custom names remain unqualified. The parser
fails closed with a gap. The immutable package grammar and digest precedence are
fixture/mock-tested.

## Historical resolution

The resolver fetches historical workflow and Action content through the API and
never checks out, executes, builds, imports, or installs it. It supports remote
repository Actions, JavaScript/Docker leaf definitions, composites, local
declarations, same/cross-repository reusable workflows, nested calls, cache keys,
cycles, maximum depth, and path validation.

Runtime Action source objects and called-workflow objects remain distinct from
caller workflow, trigger, and current refs. Annotated reusable-workflow tag
objects are retained separately from a bounded, positively verified peeled
commit used for exact content retrieval. Peel cycles, depth, type mismatch, or
missing routes produce a gap without binding content.

Exact runtime/local workspace bytes cannot be proven from GitHub content APIs
alone in all events. `head_sha` is never substituted as a universal identity.
Static/runtime disagreement preserves both propositions and derives
`CONTRADICTORY_EVIDENCE`.

## Matching, exposure, graph, and reports

Incident matching is deterministic and prioritizes exact package digest, exact
Action source object, exact GitHub-recorded reusable-workflow object, historical
immutable declaration, mutable ref plus component window, transitive reachability,
current-only configuration, then missing evidence. Exact known-good or runtime
evidence cannot be overridden by mutable-ref inference.

Exposure derivation distinguishes:

- runtime-observed versus static-inferred effective `GITHUB_TOKEN` permissions;
- secret existence, job reference, affected-step pass, reusable mapping,
  one-hop inheritance, and environment eligibility;
- environment targeting from gate crossing;
- `OIDC_MINTING_CAPABILITY` from any cloud trust or role assumption; and
- GitHub-hosted, self-hosted, and unknown runner classification.

The collector does not retrieve secret values. It does not derive cloud identity
reachability, runner persistence, exfiltration, or downstream malicious causation.
Optional resources remain run-scoped context unless an exact join exists.

Case generation produces deterministic HTML, JSON, CSV, JSONL, SQLite, graph,
Markdown, metadata, and manifest outputs. The graph is derived from `case.db` and
focuses on affected evidence. HTML is self-contained with strict CSP and escaped
data; CSV formulas and terminal controls are neutralized.

## Controlled qualification

The sanitized
[`controlled-lab record`](validation/2026-08-22-controlled-lab-qualification.md)
documents:

- direct affected execution and downloaded-only skip;
- mutable tag B at one attempt and restored A at another;
- separate full/failed/single-job rerun attempts;
- direct, composite, reusable-workflow, and exact historical reconstruction;
- explicit secret mapping, `secrets: inherit`, blocked environment, OIDC
  capability only, hosted/self-hosted runner context, matrix separation,
  `pull_request_target`, missing logs, historical drift, and contradiction; and
- exact called-workflow tag-object preservation plus peeled-commit retrieval.

The final raw-disabled archive retained 591 compact facts, 353 evidence objects,
9 explicit baseline coverage gaps, 22 attempts, and 24 jobs. Offline replay
produced 56 findings: 12 `CONFIRMED_EXECUTED`, 2 `CONFIRMED_DOWNLOADED`, 37
`POTENTIAL_TRANSITIVE`, and 5 `UNKNOWN_EVIDENCE_GAP`. Both direct-composite and
reusable-composite paths retained exact parent and child lifecycle starts and
completions; the skipped control retained no lifecycle. SQLite, CLI and
independent manifest verification, and the offline Chromium/CSP audit passed.

Private GitHub identifiers and controlled incident values are intentionally not
published. The public repository contains only generic synthetic packs and
fixtures.

## Security and performance qualification

Local release work includes default/race/vet suites, offline no-network/process
audits, CSP/browser injection checks, dependency vulnerability analysis, license
verification, cross-builds, Wine Windows compatibility, reproducibility checks,
SPDX validation, and a final bounded fuzz campaign of 15,668,442 inputs across
13 parser/domain targets without a failure.

An extended three-minute ZIP campaign executed 4.3 million inputs without a
crash or accepted boundary violation. A streaming parser processed 5 GiB and
50 GiB synthetic aggregate workloads with near-linear wall/CPU growth and stable
RSS; neither created lifecycle observations from setup evidence.

Relational scale on the documented Linux reference host:

| Profile | Repositories | Runs | Executions | Result |
| --- | ---: | ---: | ---: | --- |
| Small | 100 | 10,000 | 25,000 | 7.22 s, PASS |
| Medium | 1,000 | 100,000 | 300,000 | 173.68 s, PASS |
| Large | 10,000 | 1,000,000 | 3,000,000 target | exceeded 2 hours, unsupported |

The medium profile is the measured v0.1 relational envelope. The large process
timed out during synchronous commit before findings, integrity, or checkpoint
stages and is not a passing database. Replay independently rejects more than
1,000,000 facts or 256 MiB of compact snapshot data. See the
[`fuzz/scale record`](validation/2026-08-21-fuzz-scale-hardening.md).

## Hosted release qualification

The qualified public product-source baseline
`7c548ebb56c1a5fecb55b65aebd8f582ae5dc6ba` passed private hosted CI run
[`32553126718`](https://github.com/torjan0/cirewind/actions/runs/32553126718):
six Linux/macOS/Windows architecture jobs plus race, reachable-vulnerability,
and reproducible-release-contract jobs all completed successfully. A clean
clone of that remote revision reproduced the documented offline build, tests,
pack validation, demo outputs, and manifest verification.

After the visibility transition, read-only workflow defaults, full-SHA pinning,
the selected-Action allowlist, dependency alerts/security updates, private
vulnerability reporting, secret scanning/push protection, both protected
release environments, and an active no-bypass `refs/tags/v*` deletion/non-fast-
forward ruleset were verified. Public hosted-CI run
[`32553662965`](https://github.com/torjan0/cirewind/actions/runs/32553662965)
then passed the same nine-job matrix for the exact baseline. A remote-object
Gitleaks, TruffleHog, tree, and settings recheck was clean. Final candidate
revision `2088f133df395f472180848ba6e929919c743b0d` then passed all nine jobs in
public CI run
[`32554210398`](https://github.com/torjan0/cirewind/actions/runs/32554210398).
`main` is protected by an active no-bypass ruleset that blocks deletion and
non-fast-forward updates and requires the nine observed CI check contexts. See the
[`hosted-release qualification record`](validation/2026-08-22-hosted-release-qualification.md).

The protected annotated `v0.1.0` tag identifies that final candidate revision.
Authenticated release run
[`32554866238`](https://github.com/torjan0/cirewind/actions/runs/32554866238)
passed exact tag/commit validation, double-build reproducibility, native smoke,
all subject attestations, distribution verification, environment verification,
and build-provenance verification. It then failed closed at the first release
creation command because the runner's GitHub CLI does not support
`--notes-from-tag` together with `--repo`. Asset comparison and publication were
skipped. The Releases API contained no `v0.1.0` release, so no draft, published
release, or release asset was created. The workflow artifact and attestations
remain candidate evidence, not published release assets.

The release-creation compatibility fix was reviewed in
[PR #1](https://github.com/torjan0/cirewind/pull/1). All nine required checks
passed in PR CI run
[`32556616946`](https://github.com/torjan0/cirewind/actions/runs/32556616946)
on GitHub-generated merge object `c916b0b8174ec5c561bf34f60c1d65ae224cc6fa`;
the run was associated with PR head
`a1ec0cb23f2a5204781a9ccf17393139181aa2c4`. The change was squash-merged as
`a56a880c4fadf2ab85945b3b96099b5b2cf62a25`, and all nine checks passed
again at that exact `main` object in CI run
[`32556880171`](https://github.com/torjan0/cirewind/actions/runs/32556880171).
Those runs qualified the recovery source path only. Release preparation was then
reviewed in [PR #2](https://github.com/torjan0/cirewind/pull/2). Run
[`32557676966`](https://github.com/torjan0/cirewind/actions/runs/32557676966)
was associated with PR head `3dba4ceb2115f1092b57a124c64347889c0c9136`
and passed all nine required checks on GitHub-generated merge object
`62b9d8a9d55c081ba55fd9af8be84b8228498e8d`. Exact squash commit
`d4954356e733af42500061885dae36996281547e`
passed the same matrix on `main` in run
[`32557942570`](https://github.com/torjan0/cirewind/actions/runs/32557942570).

Protected annotated tag object
`c7fa1e8b7ddedd7c27e8df423161b9735227cd3e` peels to that commit. Draft run
[`32559258464`](https://github.com/torjan0/cirewind/actions/runs/32559258464)
passed exact tag validation, two byte-identical builds, credential-free smoke,
SLSA provenance covering all 14 subjects, protected draft creation, and
downloaded-asset byte comparison. Separate publication run
[`32559856110`](https://github.com/torjan0/cirewind/actions/runs/32559856110)
repeated the build/provenance checks, revalidated the exact existing draft, and
passed the separately protected publication job. Public release ID `374862445`
was published at `2026-08-22T07:43:52Z` with 14 uploaded assets and is immutable.
Fresh anonymous downloads matched GitHub digests and the independent local
candidate; checksums, six SPDX documents, both SLSA provenance bundles, source
archives, links, native Linux smoke, locked-down container smoke, and Windows
amd64 Wine compatibility smoke passed. Wine and cross-build results are labeled
as such rather than native qualification.

## Release outcome and remaining nonblocking work

No release blocker remains inside ADR 0011's bounded experimental envelope. The
final GO covers the exact v0.1.1 release above. It does not close the broader
aggregate tasks for organization saturation, every authentication profile,
additional runner grammars, full optional-resource joins, native qualification
of every cross-built target, or scale above the measured guards. Those items
remain open in `TASKS.md`; failures inside the published envelope would again be
blocking for a patch release.

## Incident-content limitation

No real-world incident pack is release-ready. This does not block the core binary
or schema, but any real pack is a separate reviewed content release. Every value
must have primary-source provenance, exact precision, deterministic fixtures,
conflict review, exact-content GitHub PR approval, and the independent human
review required by the accepted policy; otherwise use synthetic data. The v0.2
offline governance tooling can validate structure and recorded bindings, but it
cannot establish factual truth, reviewer identity or independence, GitHub
authenticity, or a clean/immutable Git history by itself.
