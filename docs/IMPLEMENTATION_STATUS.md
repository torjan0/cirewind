# CIRewind implementation status

Status snapshot: **2026-08-22**

Release decision: **product candidate GO for an experimental v0.1 inside
[`ADR 0011`](adr/0011-experimental-v0-1-qualification-envelope.md), publication
still NO-GO pending candidate and publication gates**. The final
controlled archive/replay, exact-revision local qualification, private hosted
CI, public hosted CI, clean-clone/offline reproduction, remote-object security
scan, and repository-control checks passed at
`2088f133df395f472180848ba6e929919c743b0d`. The repository is public and that
revision is retained as the protected, unpublished `v0.1.0` candidate tag.
Candidate build/provenance checks passed, but draft creation failed closed before
any GitHub Release existed. The recovery source was reviewed and merged through
PR #1 and passed the required PR and `main` CI matrices. `v0.1.1` is the recovery
publication target; its tag, official artifact/attestation run, protected draft
inspection, final GO, publication, and public verification remain open.

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

## CLI status

| Command | Status | Qualification boundary |
| --- | --- | --- |
| `cirewind --help`, `help`, `version` | Implemented and offline-tested | Release builds inject version, source revision, and build time. |
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
SPDX validation, and fuzz campaigns at 11 parser/domain boundaries.

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
This qualifies the recovery source path only; no `v0.1.1` tag, official
artifact, attestation, draft, or release was created by either CI run.

## Release blockers

The release-creation correction and recovery-source CI are complete. Before the
public release, the exact `v0.1.1` candidate must still:

1. complete and qualify the final pre-tag documentation revision at its exact
   `main` object;
2. create the exact protected annotated `v0.1.1` tag;
3. build and attest the official artifacts, create and inspect the protected
   draft, and download and smoke every draft asset; and
4. record final GO, approve the separate publication gate, publish the
   byte-identical draft through the protected release workflow, and verify the
   release and attestations from an unauthenticated view.

Failures inside the ADR 0011 qualification envelope are blocking. The explicit
experimental limitations above are non-blocking only while they remain visible
in output and documentation.

## Incident-content limitation

No real-world incident pack is release-ready. This does not block the core binary
or schema, but any real pack is a separate reviewed content release. Every value
must have primary-source provenance, exact precision, deterministic fixtures,
conflict review, and independent maintainer review; otherwise use synthetic data.
