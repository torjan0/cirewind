# CIRewind v0.1 public-release checklist

Status snapshot: **2026-08-22 — v0.1.1 published, immutable, and independently
verified**

This checklist is the final authority log for publishing the experimental v0.1
release. It applies the bounded qualification decision in
[`ADR 0011`](adr/0011-experimental-v0-1-qualification-envelope.md); it does not
waive the canonical evidence semantics, hostile-input rules, or release-candidate
integrity requirements.

The repository is public. The protected `v0.1.0` tag remains an unpublished
candidate audit record after its release workflow failed closed before draft
creation. Recovery source and release preparation were reviewed in
[PR #1](https://github.com/torjan0/cirewind/pull/1) and
[PR #2](https://github.com/torjan0/cirewind/pull/2). Run
[`32557676966`](https://github.com/torjan0/cirewind/actions/runs/32557676966)
was associated with PR head `3dba4ceb2115f1092b57a124c64347889c0c9136`
and passed all nine required checks on GitHub-generated merge object
`62b9d8a9d55c081ba55fd9af8be84b8228498e8d`.
The final squash commit `d4954356e733af42500061885dae36996281547e`
passed the same nine checks on `main` in run
[`32557942570`](https://github.com/torjan0/cirewind/actions/runs/32557942570).

Protected annotated tag object
`c7fa1e8b7ddedd7c27e8df423161b9735227cd3e` peels to that exact commit. The
protected draft run
[`32559258464`](https://github.com/torjan0/cirewind/actions/runs/32559258464)
built, reproduced, and attested all 14 subjects, ran the Linux amd64 smoke, then
uploaded, downloaded, and byte-compared all 14 successfully. The separate
protected publication run
[`32559856110`](https://github.com/torjan0/cirewind/actions/runs/32559856110)
repeated those checks, proved the existing draft exact immediately before
publication, and published it without replacing an asset. GitHub Release
[`v0.1.1`](https://github.com/torjan0/cirewind/releases/tag/v0.1.1), release ID
`374862445`, was published at `2026-08-22T07:43:52Z`; it is non-prerelease,
latest, and immutable. See the
[`hosted-release qualification record`](validation/2026-08-22-hosted-release-qualification.md)
for the bounded GO and verification evidence.

## Gate A — reviewed source tree

- [x] Review `git status`, all untracked files, and the complete staged diff.
  Exclude caches, binaries, temporary directories, generated cases, databases,
  WAL/SHM files, archives, raw logs, editor data, and machine-specific paths.
- [x] Confirm only the generic synthetic incident pack is shipped. Search for
  private controlled repository names, run/job/object IDs, real incident values,
  customer data, personal paths, signed URLs, and production evidence.
- [x] Scan staged content for credentials, authorization headers, token prefixes,
  private keys, secret values, shell history, and accidental raw logs.
- [x] Confirm `AGENTS.md` is present and that source, docs, commits, release notes,
  and generated artifacts contain no assistant, agent, or automation authorship
  credit.
- [x] Verify Apache-2.0, DCO instructions, complete applicable dependency notices,
  privacy/security policies, issue templates, and incident-pack review rules.
- [x] Verify all third-party Actions are pinned by reviewed full object IDs and
  match `.github/actions-pins.json`; actionlint and shellcheck must pass.
- [x] Confirm local Markdown links and schema references resolve and no checked-in
  schema depends on an unowned project website.
- [x] Confirm the ten state identifiers, five provenance identifiers, and eight
  mandatory invariant sentences match model, schemas, fixtures, README, evidence
  model, test strategy, and report output.
- [x] Configure the human maintainer Git identity and create a DCO-signed commit
  without an assistant/tool co-author trailer.

## Gate B — exact-candidate deep qualification

- [x] Run one fresh raw-disabled controlled explicit-repository archive with the
  candidate binary, replay the private synthetic incident, verify the case, and
  record only sanitized counts/results in the controlled-lab document.
- [x] Confirm the central A→B→A result: affected B executed in the direct control,
  B downloaded but not executed in the skipped control, rerun attempts retain
  B-versus-restored-A separately, and current tag state changes neither result.
- [x] Confirm reusable-workflow tag object and peeled commit remain separate;
  full/failed/single-job reruns do not merge attempts; ambiguous composite child
  lifecycle remains a gap unless the strict exact join succeeds.
- [x] Confirm direct named-secret mapping, one-hop `secrets: inherit`, blocked
  environment, `OIDC_MINTING_CAPABILITY` only, hosted/self-hosted classification,
  matrix separation, missing-log unknown, drift, and contradiction language.
- [x] Confirm every finding links evidence or an explicit gap, all material graph
  edges link evidence, report/JSON/CSV/database counts agree, and required empty
  arrays serialize as `[]` rather than `null`/omission.
- [x] Confirm archive replay after committed-WAL interruption and finalized case
  sealing; manifest verification must survive ordinary read-only SQLite
  inspection and reject unexpected sidecars or changed files.
- [x] Run `gofmt` verification, `go mod tidy -diff`, `go mod verify`,
  `go test ./... -count=1`, `go vet ./...`, and `go test -race ./... -count=1`.
- [x] Run the checked-in fuzz seed corpora and the documented sustained parser
  campaigns. Keep `SEC-002` open as a broad future campaign; the v0.1 release
  claim is limited to the recorded targets/budgets.
- [x] Run the small and medium relational profiles and confirm indexed query
  plans. Keep 3,000,000 executions unsupported; do not relabel the two-hour
  timeout as a pass.
- [x] Run reachable-vulnerability, license bundle, offline safety/strace,
  browser/CSP/injection, schema, action-pin, shell, and credential/private-data
  audits.
- [x] Run `make demo` into a new directory, assert finding counts and required
  outputs, verify its manifest, and inspect the self-contained report offline.
- [x] Run deterministic release packaging twice, byte-compare it, validate every
  SPDX document independently, run supported native/container/Wine smokes with
  their limits stated, and verify tamper rejection.
- [x] From the exact reviewed index, run
  `CIREWIND_PREFLIGHT_REQUIRE_STAGED=1 make preflight` and retain the command
  summary outside the repository.

## Gate C — private publication and hosted CI

- [x] Push the reviewed signed-off `main` commit to the private remote. Do not
  force-push or include any file outside the reviewed index.
- [x] Wait for every configured Linux, macOS, and Windows CI job; fix failures in
  a new reviewed commit and repeat the exact-candidate local gates.
- [x] Perform a clean clone from GitHub and reproduce build, tests, pack
  validation, demo, expected case outputs, and manifest verification using the
  published instructions.
- [x] Keep default workflow permissions read-only and enable dependency alerts,
  secret scanning/push protection, and private vulnerability reporting where
  GitHub makes them available.
- [x] Protect `main` against force push/deletion and require only check names that
  have actually run. Configure rules compatible with the solo-maintainer model.
- [x] Create `release-draft` and `release-publish` environments with the exact
  reviewer, no-admin-bypass, and `tag:v*` policy required by
  [`RELEASE_PROCESS.md`](RELEASE_PROCESS.md); inspect both through the read-only
  verifier.
- [x] Enable an active repository ruleset for `refs/tags/v*` that blocks tag
  deletion and non-fast-forward updates and permits no bypass actor.
- [x] Re-run public-source scans against the Git object GitHub received, not only
  the working tree.

## Gate D — public v0.1 recovery release (`v0.1.1` target)

Checked `v0.1.0` items below record completed historical actions only. They do
not close any final `v0.1.1` draft, asset, publication, or verification gate.

- [x] Confirm public-visibility CI run
  [`32554210398`](https://github.com/torjan0/cirewind/actions/runs/32554210398)
  completes successfully for the exact
  `2088f133df395f472180848ba6e929919c743b0d` revision.
- [x] Record a final **GO** confirming all failures inside ADR 0011's supported
  envelope are closed and all remaining limitations are explicitly documented.
  The decision is GO for the bounded experimental v0.1.1 release, not for the
  broader compatibility tasks that remain open in `TASKS.md`.
- [x] Change repository visibility to public and verify private vulnerability
  reporting, dependency alerts/security updates, secret scanning and push
  protection, release-tag rules, read-only workflow defaults, SHA pinning, and
  the selected-Action allowlist remain configured after the visibility change.
- [x] Create the reviewed annotated `v0.1.0` tag from exact green revision
  `2088f133df395f472180848ba6e929919c743b0d` and push only that tag. The active
  no-bypass tag ruleset protects it from deletion or non-fast-forward change.
- [x] Dispatch the initial `v0.1.0` workflow with `publish=false` and approve the
  draft gate. Run
  [`32554866238`](https://github.com/torjan0/cirewind/actions/runs/32554866238)
  passed all exact build, reproducibility, smoke, subject-attestation,
  distribution, environment, and provenance-verification checks, then failed
  closed before draft creation because the GitHub CLI rejects
  `--notes-from-tag` together with `--repo`. No draft, release, or release asset
  was created; publication was skipped.
- [x] Correct and review the release-creation invocation. PR #1 CI run
  [`32556616946`](https://github.com/torjan0/cirewind/actions/runs/32556616946)
  was associated with PR head `a1ec0cb23f2a5204781a9ccf17393139181aa2c4`
  and passed all nine required checks on GitHub-generated merge object
  `c916b0b8174ec5c561bf34f60c1d65ae224cc6fa`. Squash commit
  `a56a880c4fadf2ab85945b3b96099b5b2cf62a25` passed the same nine checks at
  that exact `main` object in run
  [`32556880171`](https://github.com/torjan0/cirewind/actions/runs/32556880171).
  This closes recovery-source qualification only.
- [x] Complete and qualify the final pre-tag documentation revision at exact
  green `main` object `d4954356e733af42500061885dae36996281547e`, create
  protected annotated tag object `c7fa1e8b7ddedd7c27e8df423161b9735227cd3e`,
  and push only `v0.1.1`.
- [x] Dispatch the corrected workflow for `v0.1.1` with `publish=false`; build
  and attest the official artifacts, approve the draft gate, then verify version
  metadata, source revision, checksums, archive contents, SPDX documents,
  license indexes, build provenance, signer workflow/ref, and every downloaded
  draft asset byte. Run `32559258464` completed successfully; immutable workflow
  artifact `9472359966` carried the exact subjects to the protected draft job.
- [x] Independently smoke the downloaded release on each advertised runtime-
  qualified platform. Linux amd64 passed natively with credentials unset and in
  a network-disabled, read-only-root container. Windows amd64 passed the same
  compatibility smoke under Wine and remains labeled non-native; the other
  published targets are cross-build-qualified only.
- [x] Dispatch the separate `v0.1.1` `publish=true` run, ensure its draft job
  accepts only the exact existing draft, and approve the publication gate only
  after that job passes. Ensure the publish job re-verifies and publishes without
  rebuilding or substitution. Run `32559856110` completed successfully; its
  independently reproduced subjects arrived as immutable workflow artifact
  `9472527249`.
- [x] Verify the public `v0.1.1` tag, release page, immutable assets,
  `SHA256SUMS`, GitHub attestations, source archives, README links, `SECURITY.md`,
  and changelog from an unauthenticated view. All 14 assets downloaded without
  credentials; their GitHub digests, local SHA-256 values, and independent
  candidate bytes agree. Both SLSA build-provenance bundles covering all 14
  release subjects were retrieved without credentials and verified locally
  against the exact signer workflow, source ref, and release commit.
- [x] Update this snapshot with the release URL, workflow run IDs, attestation
  verification result, and nonblocking follow-up—without credentials, private
  lab identifiers, or assistant credit.

## Explicit nonblocking v0.1 limitations

The following do not block the experimental release only because the product and
output claims are narrowed accordingly:

- organization completeness at an unsplittable 1,000-result second;
- complete live classic PAT, fine-grained PAT, and GitHub App qualification;
- live immutable Action package grammar and every runner version/localization;
- exact runtime bytes for unarchived local Actions;
- full package/release/deployment/secret/runner inventory and causal joins;
- runtime qualification on a target that has only been cross-built or exercised
  through Wine; and
- relational inputs above 300,000 executions or replay snapshots above the
  1,000,000-fact/256-MiB guards.

These conditions must produce partial coverage, an explicit gap, an unsupported
result, or accurate compatibility language. They may not be silently treated as
successful evidence.
