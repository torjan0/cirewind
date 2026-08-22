# Competitive boundaries

Status: implementation-planning baseline
Research cut-off and retrieval date: 2026-08-20
Scope: GitHub.com and open-source or GitHub-native tools relevant to GitHub Actions dependency inventory, workflow security, and incident reconstruction

## Decision in one sentence

CIRewind is the temporal, attempt-aware evidence and exposure-reconstruction layer. It must interoperate with current-state inventory and security-analysis tools, but it must not reproduce their scanners, BOMs, attack modules, or consumer maps.

The defensible product boundary is not “a better GitHub Actions scanner.” It is a case system that can answer, with evidence provenance and explicit gaps, what a particular `run_id + run_attempt + job_id` downloaded, what demonstrably began execution, which historical definitions led to it, and which credentials or resources were eligible at that time.

## Source and comparison method

Capabilities below are based on upstream documentation and source repositories as they existed at the pinned revisions in the source ledger. “Not documented” means the cited public interface or output does not make that claim; it is not proof that no private branch or future release can do it. Marketing descriptions were not used when a repository disagreed with them.

| Project | Revision inspected | Published license evidence |
|---|---|---|
| ABOM | [`6dd6c79`](https://github.com/JulietSecurity/abom/tree/6dd6c79f0ec7a63165bd92608fd02ba5f31541d6) | [Apache-2.0](https://github.com/JulietSecurity/abom/blob/6dd6c79f0ec7a63165bd92608fd02ba5f31541d6/LICENSE) |
| gh-blast-radius | [`a54413b`](https://github.com/DivyamK1234/gh-blast-radius/tree/a54413b4b38a626a9ec464c7c5558e4403c3b3d5) | [MIT](https://github.com/DivyamK1234/gh-blast-radius/blob/a54413b4b38a626a9ec464c7c5558e4403c3b3d5/LICENSE) |
| Heisenberg SSC Health Check | [`2112f8e`](https://github.com/AppOmni-Labs/heisenberg-ssc-health-check/tree/2112f8eb29b80a4501a6a0fc49983cc8e724f58e) | [MIT](https://github.com/AppOmni-Labs/heisenberg-ssc-health-check/blob/2112f8eb29b80a4501a6a0fc49983cc8e724f58e/LICENSE) |
| Trajan | [`b8c7792`](https://github.com/praetorian-inc/trajan/tree/b8c7792ecc0f4eba92282d3facbeca08b6b262c9) | [Apache-2.0](https://github.com/praetorian-inc/trajan/blob/b8c7792ecc0f4eba92282d3facbeca08b6b262c9/LICENSE) |
| GitHub audit-actions-workflow-runs | [`1e536cc`](https://github.com/github/audit-actions-workflow-runs/tree/1e536cc1af05a5e37a69d0c8dd479ec6ca2685bf) | [MIT](https://github.com/github/audit-actions-workflow-runs/blob/1e536cc1af05a5e37a69d0c8dd479ec6ca2685bf/LICENSE) |
| StepSecurity trivy-compromise-scanner | [`506f4e1`](https://github.com/step-security/trivy-compromise-scanner/tree/506f4e12e2f0a2d5917c1c27adccf78813503b9b) | [LICENSE says MIT](https://github.com/step-security/trivy-compromise-scanner/blob/506f4e12e2f0a2d5917c1c27adccf78813503b9b/LICENSE); README says Apache-2.0 |
| zizmor | [`80dd296`](https://github.com/zizmorcore/zizmor/tree/80dd2963cf0eb8edf25f9eb76e750151b5bb08fa) | [MIT](https://github.com/zizmorcore/zizmor/blob/80dd2963cf0eb8edf25f9eb76e750151b5bb08fa/LICENSE) |
| Gato | [`57a0072`](https://github.com/praetorian-inc/gato/tree/57a007289957f2aa48adcf2c4f85b6cd073d0a00) | [Apache-2.0](https://github.com/praetorian-inc/gato/blob/57a007289957f2aa48adcf2c4f85b6cd073d0a00/LICENSE) |

The GitHub Dependency Graph is a hosted GitHub capability rather than an importable project, so it is cited to official product documentation rather than assigned a repository revision.

## Capability map

| System | Demonstrated strength | Historical runtime evidence | Smallest documented result identity | Boundary relative to CIRewind |
|---|---|---|---|---|
| GitHub Dependency Graph | Parses step-level Action and job-level reusable-workflow `uses` references and shows owner, workflow file, and declared version or SHA. | No incident-log claim; GitHub documents the graph as updating from default-branch manifests. | Repository manifest dependency | Native current inventory and advisory surface, not a reconstruction of a retained run attempt. |
| ABOM | Recursively resolves Actions, composite Actions, reusable workflows, and heuristically recognized embedded tools; emits native JSON, CycloneDX, and SPDX. | Its optional tag/branch resolution records where a ref points at BOM-generation time. That is not proof of what a historical runner fetched. | Workflow dependency node at scan time | Do not rebuild a general Actions BOM, advisory checker, or current ref resolver. |
| gh-blast-radius | Builds an organization consumer graph for shared reusable workflows and composite Actions, records passed inputs, and compares producer revisions for breaking changes. | No run-log or incident evidence claim in the cited interface. | Current producer/consumer edge | Do not build generic shared-workflow impact or PR breakage analysis. |
| Heisenberg | Extracts current `uses` entries, enriches repository health/advisories, detects unpinned refs, and resolves organization-internal shared Actions to third-party dependencies. | No run-log or attempt claim in the cited Actions mode. | Repository/workflow/current Action reference | Do not build dependency-health scoring, package SBOM, or current Actions inventory. |
| Trajan | Broad CI/CD collection, normalization, vulnerability rules, graphing, taint/gate analysis, and authorized attack verification. | Its cited public architecture is a security assessment pipeline, not an incident-grade run-attempt evidence contract. | Normalized configuration fact/finding; graph node/edge | Do not become a current-state attack graph, generic vulnerability scanner, or exploitation/verification tool. |
| audit-actions-workflow-runs | Parses runner setup logs for exact Action source SHAs and immutable Action package version/source-SHA/digest fields. | Yes, from retained workflow-run logs. | Published output contains `run_id`, not attempt, job, or step identity. | Treat its parsers and fixtures as a resolution-format oracle; CIRewind must add preparation-completion proof, attempt/job scope, execution-start evidence, provenance, gaps, and exposure analysis. |
| trivy-compromise-scanner | Enumerates repositories/runs in a fixed incident window, downloads logs, and searches log files for known Trivy Action/SHA patterns. | Yes, incident-specific retained logs. | Published JSON/CSV is run-level and includes matching file/snippet. | Do not hardcode incidents or stop at grep-like matching. Generalize knowledge into reviewed packs and preserve case evidence. |
| zizmor | Static analysis and remediation of workflow/Action definitions, including injection, credential, permission, and reference hazards; supports local and GitHub-ref inputs and machine-readable formats. | Can inspect a selected source ref, but makes no claim that the definition instantiated or executed in a run. | Static source finding | Do not replace a workflow linter or generic CI security SAST. |
| Gato | GitHub enumeration, workflow/run-log analysis for self-hosted-runner risks, artifact secret scanning, and active attack/post-exploitation features. | Uses some run logs, but its goal is enumeration and attack. | Repository/security finding or attack result | Do not add exploitation, secret-value scanning, persistence, or attack verification. The repository is archived and points users to Trajan. |

Primary sources for the table:

- GitHub documents that the dependency graph recognizes `jobs[*].steps[*].uses` and `jobs.<job_id>.uses`, displays declared versions or SHAs, and updates with default-branch changes: [Secure use reference](https://docs.github.com/en/actions/reference/security/secure-use#understanding-dependencies-in-your-workflows), [dependency-graph data model](https://docs.github.com/en/code-security/concepts/supply-chain-security/dependency-graph-data#static-analysis).
- ABOM's recursive, embedded-tool, output, and ref-resolution behavior is in its [pinned README](https://github.com/JulietSecurity/abom/blob/6dd6c79f0ec7a63165bd92608fd02ba5f31541d6/README.md). The README itself warns that tags and branches are mutable.
- gh-blast-radius documents its crawler, graph, inputs, local JSON store, and diff engine in its [pinned README](https://github.com/DivyamK1234/gh-blast-radius/blob/a54413b4b38a626a9ec464c7c5558e4403c3b3d5/README.md).
- Heisenberg's Actions mode and CSV schema are in its [pinned README](https://github.com/AppOmni-Labs/heisenberg-ssc-health-check/blob/2112f8eb29b80a4501a6a0fc49983cc8e724f58e/README.md).
- Trajan documents collection, normalization, rules, graph generation, and separately opted-in attacks in its [pinned README](https://github.com/praetorian-inc/trajan/blob/b8c7792ecc0f4eba92282d3facbeca08b6b262c9/README.md).
- audit-actions-workflow-runs documents its run-level schema in the [README](https://github.com/github/audit-actions-workflow-runs/blob/1e536cc1af05a5e37a69d0c8dd479ec6ca2685bf/README.md); the pinned [collector](https://github.com/github/audit-actions-workflow-runs/blob/1e536cc1af05a5e37a69d0c8dd479ec6ca2685bf/audit_workflow_runs.js) and [parser](https://github.com/github/audit-actions-workflow-runs/blob/1e536cc1af05a5e37a69d0c8dd479ec6ca2685bf/audit_workflow_runs_utils.js) show that it parses setup-job download lines, including immutable package fields.
- trivy-compromise-scanner documents fixed incident defaults, output fields, and log matching in its [pinned README](https://github.com/step-security/trivy-compromise-scanner/blob/506f4e12e2f0a2d5917c1c27adccf78813503b9b/README.md).
- zizmor's current static-analysis scope is in its [pinned README](https://github.com/zizmorcore/zizmor/blob/80dd2963cf0eb8edf25f9eb76e750151b5bb08fa/README.md) and [official usage documentation](https://docs.zizmor.sh/usage/).
- Gato's archived/deprecated status and enumeration/attack features are in its [pinned README](https://github.com/praetorian-inc/gato/blob/57a007289957f2aa48adcf2c4f85b6cd073d0a00/README.md).

## Project-by-project boundary and integration stance

### GitHub Dependency Graph

What already exists: native current/default-branch inventory of Action and reusable-workflow declarations, with advisory integration. This is the correct place for routine “what do we declare now?” questions.

CIRewind boundary: never present dependency-graph absence as historical safety. The graph is useful discovery input and a present-day comparison point only. If ingested, every edge is labeled `CURRENT_REFERENCE_ONLY`, records collection time, and cannot upgrade a historical finding.

Integration opportunity: allow a later importer to seed repository/action candidates and compare them with the historical case. Keep the native graph as a cited external source rather than copying it into the runtime truth model without provenance.

### ABOM

What already exists: a general Actions BOM with recursive composite/reusable-workflow traversal, embedded-tool heuristics, advisory matching, and standard BOM exports.

CIRewind boundary: historical resolution must start from a run attempt and exact evidence, not from ABOM's current scan or scan-time ref resolution. “Resolved now” and “resolved when the job prepared Actions” are different facts. Embedded-tool signatures can support `POTENTIAL_TRANSITIVE`; they cannot prove download or execution.

Integration opportunity: a later importer can accept ABOM native JSON, CycloneDX, or SPDX as supplemental static evidence. Imported nodes remain source-labeled and cannot produce `CONFIRMED_DOWNLOADED` or `CONFIRMED_EXECUTED`. Cross-tool golden fixtures are more attractive than embedding ABOM's resolver in v0.1.

Reuse stance: although its Apache-2.0 license is compatible with CIRewind's intended Apache-2.0 distribution in general, the pinned project is young and its resolver semantics are optimized for BOM generation. Do not add it as a core library without a separate API-stability, transitive-license, network-behavior, and forensic-semantics review.

### gh-blast-radius

What already exists: deterministic organization-wide producer/consumer mapping and schema-diff impact for shared workflows and composite Actions.

CIRewind boundary: CIRewind reconstructs the exact historical caller/callee chain for an observed run attempt. It does not answer generic “what breaks if we change this shared workflow?” questions and does not post PR breakage comments.

Integration opportunity: later accept its graph JSON as a current topology hint or export CIRewind's historically observed caller edges in a separately versioned interchange form. Do not silently merge present-day consumer edges into historical run provenance.

### Heisenberg

What already exists: package and Actions supply-chain health checks, current workflow extraction, advisory enrichment, pinning checks, and organization-specific shared-Action resolution.

CIRewind boundary: no health score, popularity/maintenance score, generic package SBOM, or current-only incident search belongs in the core product. Those are adjacent discovery functions.

Integration opportunity: a Heisenberg CSV may seed candidates, with each row stored as externally derived static evidence and `CURRENT_REFERENCE_ONLY` unless stronger case evidence exists.

### Trajan

What already exists: broad multi-platform CI/CD security assessment, normalized facts, declarative detection rules, graphs, and separately authorized attack plans. Its graph already includes repositories, workflows, jobs, secrets, runners, and environments.

CIRewind boundary: the CIRewind graph is a projection of the evidence-backed case database, not the primary claim or a generic attack-path engine. CIRewind remains read-only and never imports or exposes Trajan attack plans, payloads, exploitability validation, secret dumping, or persistence.

Integration opportunity: later link a CIRewind case to Trajan JSON/JSONL posture findings by repository and historical workflow commit. Those findings remain a separate “configuration security” namespace; they do not change forensic finding states.

Upstream inconsistency: Praetorian's March 2026 announcement claimed Jenkins support, while the pinned repository README's platform table listed Jenkins as “coming soon.” CIRewind planning follows the repository snapshot and does not repeat the broader claim without revalidation. See the [publisher announcement](https://www.praetorian.com/blog/building-bridges-breaking-pipelines-introducing-trajan/) and [pinned repository README](https://github.com/praetorian-inc/trajan/blob/b8c7792ecc0f4eba92282d3facbeca08b6b262c9/README.md).

### GitHub audit-actions-workflow-runs

What already exists: the strongest directly reusable research precedent. It extracts `owner/repo/path`, declared version, exact source SHA, immutable package version, and package digest from retained runner setup logs.

CIRewind boundary: the parsed runner line proves exact runtime resolution and entry into the download routine, not by itself that preparation completed or that the corresponding step began. The published record is run-level. At the inspected revision, repository enumeration and run listing use single `per_page: 100` requests in one collection path, and the output omits `run_attempt`, `job_id`, and step identity. CIRewind must not inherit those semantic, scale, or identity limits.

Integration opportunity:

- Treat the upstream parser's fixture lines as a compatibility corpus.
- Offer a later import for its single-line JSON records, mapping them conservatively to exact-resolution/download-announcement evidence with unknown completion and unknown attempt/job when those identifiers cannot be recovered.
- Independently implement the hardened parser/state machine needed for hostile ZIP/log inputs and execution-start correlation.
- If any MIT-licensed implementation text is copied, preserve the GitHub copyright and license notice and document modifications.

Do not reuse its incident-specific secret-decoding utility: CIRewind must never retrieve, decode, hash, verify, or retain secret values.

### StepSecurity trivy-compromise-scanner

What already exists: a focused and useful response tool for one disclosed event. It enumerates repositories and runs, downloads retained log ZIPs, tolerates purged-log 404s, and matches known action/SHA patterns in log text.

CIRewind boundary: a hardcoded map plus regex/snippet result is not the CIRewind evidence model. CIRewind needs declarative, reviewed packs; exact attempt/job/step scope; separate download and execution states; reusable/composite provenance; exposure semantics; archive/replay; and evidence hashes.

Integration opportunity: use its public JSON/CSV as a migration hint and its incident patterns only after independently checking them against primary incident sources. A match imported from this tool must be recollected or remain externally derived; it cannot automatically become `CONFIRMED_EXECUTED`.

Licensing blocker: the pinned `LICENSE` file is MIT, while the pinned README says Apache-2.0. Do not copy source until the discrepancy is resolved or an explicit legal/repository-owner determination is recorded. Consuming documented output does not require embedding its code.

### zizmor

What already exists: mature static analysis and fixes for workflow/Action security mistakes, with SARIF, JSON, GitHub annotations, local inputs, and remote `@ref` collection.

CIRewind boundary: generic workflow security findings—including expression injection, credential persistence, overbroad permissions, and impostor references—belong in zizmor or a similar linter. CIRewind may reconstruct the historical definition that contained such a flaw but does not become the general detector.

Integration opportunity: later attach a zizmor SARIF/JSON report run against the exact historical workflow commit as supplemental evidence. Keep its severity taxonomy separate from CIRewind's incident semantic states.

### Gato

What already exists: GitHub Actions security enumeration and active offensive workflows, including self-hosted-runner discovery, artifact secret scanning, command execution, and secret exfiltration. The repository was archived in April 2026 and directs users to Trajan.

CIRewind boundary: no attack, exploitation, fork-PR creation, workflow creation, artifact secret-value scanning, or runner persistence code is in scope. A forensic resolver must not acquire offensive side effects merely because the target is a security tool.

Integration opportunity: none in v0.1. Public documentation can inform threat scenarios and synthetic tests, but importing an archived offensive codebase would enlarge dependency and safety risk without advancing the evidence contract.

## What CIRewind must not duplicate

- Current/default-branch Action inventory or advisory presentation: GitHub Dependency Graph and Heisenberg already cover it.
- A general current-state recursive Actions BOM: ABOM covers it.
- Organization consumer/producer and shared-workflow breaking-change analysis: gh-blast-radius covers it.
- Generic CI/CD vulnerability rules, taint analysis, current attack paths, or exploit validation: Trajan and zizmor cover those classes; Gato covers offensive GitHub enumeration/attack.
- A single-incident hardcoded log grep: trivy-compromise-scanner demonstrates the pattern but not the general product.
- Merely extracting exact Action SHAs from setup logs: audit-actions-workflow-runs already proves that capability.
- Secret discovery in artifacts or decoding leaked values: outside the product contract and incompatible with CIRewind's no-secret-values rule.

A proposed v0.1 feature that only does one of those things should be rejected, moved to an integration adapter, or justified as a narrow prerequisite for temporal reconstruction.

## What remains genuinely differentiated

CIRewind is differentiated only if the complete chain is delivered:

1. Every materially distinct run attempt, keyed at least by `run_id + run_attempt + job_id`.
2. Exact runner resolution evidence plus a separately validated preparation-completion boundary, including Action source IDs and immutable package digests.
3. Independent evidence that the corresponding step began before assigning `CONFIRMED_EXECUTED`.
4. Historical caller workflow, called reusable-workflow SHA, composites, and local Actions reconstructed without executing fetched code.
5. Conservative credential/resource eligibility at the affected job: effective `GITHUB_TOKEN` permissions, named-secret flow, reusable-workflow mapping/inheritance, environment-gate state, OIDC minting capability, and runner context.
6. Explicit contradiction and evidence-gap outcomes rather than absence-as-safety.
7. A verifiable case bundle with source provenance, event and collection time, hashes, parser versions, derivations, and coverage errors.
8. A compact pre-incident archive and deterministic replay after GitHub evidence expires.

No compared system documents this whole contract in the inspected sources. The claim must still be demonstrated in the feasibility spike; it is a target boundary, not a market assertion.

## Interoperability and import policy

No external scanner binary should be invoked automatically in v0.1. Imports, if later added, are data-only, opt-in, hostile-input parsed, and assigned a distinct logical source. An importer must declare:

- the upstream project and exact version/revision;
- original record identity and content hash;
- whether the record represents current configuration, a log match, or runtime download evidence;
- identifiers absent from the source, especially attempt/job/step;
- the maximum CIRewind finding state it may support;
- parse warnings, dropped fields, and provenance loss.

Maximum state rules for likely imports:

| Input | Maximum state without CIRewind-native corroboration |
|---|---|
| GitHub Dependency Graph, ABOM, gh-blast-radius, Heisenberg | `CURRENT_REFERENCE_ONLY` |
| zizmor report against a proven historical workflow commit | `DECLARED_AT_RUN_SHA` for matching declarations; static security findings remain supplemental |
| audit-actions-workflow-runs record | Exact runtime-resolution/download-announcement observation only; `CONFIRMED_DOWNLOADED` additionally requires independent preparation-completion evidence and unambiguous attempt/job recovery |
| trivy-compromise-scanner match | Depends on the matched log line; never upgrade merely from its run-level “finding” label |
| Trajan configuration/graph finding | Supplemental posture evidence; no automatic CIRewind incident state |

## Licensing and maintenance policy

Repository-level MIT and Apache-2.0 licenses are generally compatible with an Apache-2.0 CIRewind distribution, but that does not eliminate required notices, attribution, patent/NOTICE obligations, asset licenses, or transitive dependency review. Before source reuse:

1. Pin the upstream revision and record the copied files and purpose.
2. Review the exact license file, any `NOTICE`, vendored assets, generated files, and transitive dependencies.
3. Preserve MIT copyright/license text for copied MIT code.
4. Preserve Apache-2.0 notices and mark modified files where required.
5. Prefer protocol/output interoperability or independent implementation when upstream semantics do not preserve forensic provenance.
6. Do not copy from trivy-compromise-scanner until its MIT-versus-Apache inconsistency is resolved.
7. Do not import archived offensive Gato code into the read-only collector.

This is an engineering policy, not legal advice. A release checklist must include an automated license inventory and human review of newly incorporated code or assets.

## Boundary tests for maintainers

Before accepting a major feature, ask:

- Does it improve reconstruction of a specific historical attempt, preserve expiring evidence, or explain a conservative exposure conclusion?
- Can every material conclusion point to evidence objects and distinguish event time from collection time?
- Would the feature be more naturally implemented by ABOM, gh-blast-radius, Heisenberg, Trajan, zizmor, or GitHub's dependency graph?
- Does it accidentally turn “downloaded” into “executed,” “secret exists” into “step could read it,” or “id-token: write” into “cloud role assumed”?
- Does it require executing external scanner or Action code? If yes, it violates the v0.1 architecture.

If the first two answers are no, the feature is outside CIRewind's core even if it is useful security tooling.

## Revalidation triggers

Repeat this survey before the first public release and at least for each minor release when:

- an upstream adds run-attempt or archive/replay support;
- GitHub exposes a native historical Actions execution ledger;
- audit-actions-workflow-runs changes its result identity or parser format;
- ABOM adds historical-run evidence rather than scan-time resolution;
- Trajan adds incident evidence/chain-of-custody semantics;
- a proposed dependency is imported rather than used only as an external data source;
- any inspected project's license or maintenance status changes.
