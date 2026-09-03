# Changelog

All notable changes to CIRewind are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and releases use
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Reviewdog `action-setup` v1 tag compromise candidate packet
  (`review-packets/CIR-REVIEWDOG-ACTION-SETUP-2025/1.0.0`) with a full source
  ledger, claim matrix, conflict ledger, generated fixture scenarios, and
  replayed expected-finding oracle; it is a candidate only, with no human
  review, and is absent from reviewed, release, and sample indexes.
- tj-actions/changed-files 2025 candidate packet
  (`review-packets/CIR-TJ-ACTIONS-CHANGED-FILES-2025/1.0.0`) with a
  day-precision, conservatively expanded window, non-exhaustive example tags,
  an excluded patched-version conflict, and the same generated fixture family;
  a candidate only, with no human review.
- `packreview assemble-candidate`, which canonicalizes hand-authored packet
  ledgers, generates fixture snapshots through the shared synthetic archive
  builder, replays them into the expected-finding oracle, and writes the
  packet, validation record, and manifests deterministically.
- Trivy ecosystem 2026 candidate packet
  (`review-packets/CIR-AQUASECURITY-TRIVY-2026/1.0.0`) under the `trivy-v0.2`
  profile: three components with four separate minute-precision windows whose
  approximate endpoints stay visible, 75 derived and stated original
  trivy-action tag names, the seven setup-trivy tags, and 41 mechanically
  extracted release-asset and OCI manifest digests; a candidate only, with no
  human review.
- `internal/packextract` and `packreview extract-indicators`, which transform
  pinned primary-source bytes into sealed, typed, sorted extraction records
  (input hash, extractor version, recorded normalizations, output hash) with
  no network use, and the `CIR-AQUASECURITY-TRIVY-2026` fixture family with a
  synthetic-archive runtime writer that carries a package digest.

### Documentation

- Record the completed protected v0.1.1 draft, publication, and anonymous
  post-public verification sequence.

## [0.1.1] - 2026-08-22

First experimental public release. It contains the evidence-first, deliberately
bounded v0.1 feature set recorded under the retained `v0.1.0` candidate below;
it is not a universal GitHub Actions completeness claim.

### Fixed

- The authenticated release workflow now materializes release notes from the
  already-verified annotated tag and passes them through `--notes-file` while
  retaining explicit repository scoping. This avoids the GitHub CLI's
  incompatible `--notes-from-tag` and `--repo` combination without weakening
  the tag, environment, distribution, or provenance gates.

### Release recovery

The protected `v0.1.0` candidate tag was not published: authenticated release run
[`32554866238`](https://github.com/torjan0/cirewind/actions/runs/32554866238)
passed the exact build, reproducibility, smoke, subject-attestation, distribution,
and provenance-verification checks, then failed closed before draft creation
because the runner's GitHub CLI rejects `--notes-from-tag` together with
`--repo`. No GitHub Release or release asset was created, and the publication
job did not run. The immutable candidate tag is retained as an audit record;
the corrected workflow was subsequently exercised under the new `v0.1.1` tag.

The recovery source change was reviewed in
[PR #1](https://github.com/torjan0/cirewind/pull/1). All nine required checks
passed in PR CI run
[`32556616946`](https://github.com/torjan0/cirewind/actions/runs/32556616946)
on GitHub-generated merge object `c916b0b8174ec5c561bf34f60c1d65ae224cc6fa`;
the run was associated with PR head
`a1ec0cb23f2a5204781a9ccf17393139181aa2c4`. The change was squash-merged as
`a56a880c4fadf2ab85945b3b96099b5b2cf62a25`, and all nine checks passed
again at that exact `main` object in CI run
[`32556880171`](https://github.com/torjan0/cirewind/actions/runs/32556880171).
Those results qualified the recovery source only. Final release preparation was
reviewed in [PR #2](https://github.com/torjan0/cirewind/pull/2), and exact release
commit `d4954356e733af42500061885dae36996281547e` passed the required `main` CI
matrix in run
[`32557942570`](https://github.com/torjan0/cirewind/actions/runs/32557942570).

### Release verification

- Protected draft run
  [`32559258464`](https://github.com/torjan0/cirewind/actions/runs/32559258464)
  reproduced and attested all 14 release subjects, ran the Linux amd64 smoke,
  then uploaded, downloaded, and byte-compared all 14 successfully.
- Separate publication run
  [`32559856110`](https://github.com/torjan0/cirewind/actions/runs/32559856110)
  revalidated the exact existing draft and published it through the protected
  `release-publish` environment without replacing an asset.
- The public [v0.1.1 release](https://github.com/torjan0/cirewind/releases/tag/v0.1.1)
  is immutable. Anonymous downloads matched GitHub's SHA-256 digests and the
  independent candidate; checksums, six SPDX documents, both SLSA
  build-provenance bundles covering all 14 release subjects, source archives,
  and documented smoke boundaries passed.

## [0.1.0] - 2026-08-22 (unpublished candidate)

This protected candidate was never published as a GitHub Release. Its contents
describe the intended first experimental release: evidence-first and
deliberately bounded, not a universal GitHub Actions completeness claim.

### Added

- Read-only GitHub.com `investigate` for organizations or repeated explicit
  repositories, with recursive UTC time partitioning, every visible run attempt,
  attempt-specific jobs and logs, bounded retries, rate metadata, checkpointed
  partial coverage, and sanitized errors.
- Incremental compact `archive`, deterministic offline `replay`, strict
  declarative `pack validate`, case-manifest `verify`, and version/help commands.
- Exact attempt/job identity, traditional repository-Action source objects,
  immutable-package source/digest parsing, GitHub-recorded reusable-workflow
  objects, and separately retained annotated-tag/peeled-commit identities.
- Non-executing historical resolution for remote Actions, composite Actions,
  reusable workflows, and local Action declarations, with bounded depth, cycle
  handling, exact historical fetches where supported, contradictions, and
  explicit local-workspace gaps.
- Separate declaration, resolution, download, preparation, step-start,
  step-completion, and runtime-IOC observations. Only a separately correlated
  step start can support `CONFIRMED_EXECUTED`.
- The ten canonical finding states and five canonical provenance levels, stable
  evidence/finding IDs, event and collection time, derivation chains, coverage
  records, contradictions, and evidence-backed graph edges.
- Conservative exposure relationships for effective `GITHUB_TOKEN` permissions,
  direct named-secret flow, reusable secret mapping/inheritance, environment gate
  context, OIDC minting capability, and runner classification. No secret values,
  cloud-role assumption, runner persistence, or downstream causation is claimed.
- Pure-Go SQLite case/archive stores, migrations, foreign-key/integrity checks,
  content deduplication, interruption recovery, append-only JSONL evidence, and
  SHA-256 manifests.
- Self-contained offline HTML, JSON, CSV, JSONL, SQLite, graph, and Markdown case
  outputs with strict CSP, output escaping, terminal sanitization, and spreadsheet
  formula neutralization.
- Opt-in content-addressed raw-log custody. Raw logs remain off by default; a
  raw-enabled database and its `.raw/` sidecar form one archive set.
- Strict incident-pack YAML parsing and JSON Schemas. Packs cannot contain
  executable hooks, shell, HTML, pack-directed requests, or unrestricted regex.
- A credential-free deterministic demo, A–Q synthetic acceptance inventory,
  mock GitHub transport suite, hostile ZIP/YAML/log/report fixtures, fuzz targets,
  race checks, browser/offline safety audits, and relational scale harness.
- Deterministic CGO-disabled release archives for Linux, macOS, and Windows
  amd64/arm64, target SPDX documents, complete applicable dependency notices,
  SHA-256 sums, and a pinned manual GitHub attestation/release workflow.
- Apache-2.0 license, DCO contribution process, privacy and security policies,
  threat model, architecture decisions, issue templates, and dependency updates.

### Security

- ZIP ingestion rejects traversal, absolute or ambiguous paths, links, duplicate
  names, excess files, per-file/aggregate size overruns, and compression-ratio
  violations.
- Incident packs, GitHub JSON, workflows, Action metadata, logs, SQLite archives,
  graph labels, and report fields are treated as hostile and processed under
  explicit size/depth/cancellation limits.
- API redirects are bounded and same-origin until a validated temporary log
  object hop; authorization is never forwarded to the storage origin.
- Finalized cases reject unexpected SQLite sidecars. Archive replay can recover
  committed facts from an interruption WAL, while clean close checkpoints and
  removes sidecars.
- The minimum Go toolchain is 1.25.13 following pre-release reachable-
  vulnerability analysis.

### Qualification and limitations

- A harmless controlled GitHub.com tag-movement lab qualified explicit-
  repository direct execution, downloaded-only skip, attempt separation, rerun
  identity, reusable-workflow tag peeling, conservative credentials, runner
  classification, and missing-log gaps for the observed runner grammar.
- Live organization saturation, every PAT/GitHub App profile, immutable Action
  package logs, all runner versions, unarchived local workspace bytes, and broad
  resource inventories are not v0.1 support claims.
- The measured relational envelope is 1,000 repositories, 100,000 runs, and
  300,000 attempt/job/fact executions. Replay rejects more than 1,000,000 facts
  or 256 MiB of materialized compact data. A 3,000,000-execution reference run
  exceeded the two-hour qualification budget and is unsupported.
- Cross-built archives are not equivalent to native runtime qualification.
  Consult the release record and implementation status for the platforms that
  completed native smoke tests.
- No verified real-world incident pack is included. The bundled pack and lab
  inputs are unmistakably synthetic.

[Unreleased]: https://github.com/torjan0/cirewind/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/torjan0/cirewind/releases/tag/v0.1.1
[0.1.0]: https://github.com/torjan0/cirewind/tree/v0.1.0
