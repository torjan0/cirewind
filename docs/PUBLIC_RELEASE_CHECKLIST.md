# CIRewind v0.1 public-release checklist

Status snapshot: **2026-08-22 — release candidate, not yet published**

This checklist is the final authority log for publishing the experimental v0.1
release. It applies the bounded qualification decision in
[`ADR 0011`](adr/0011-experimental-v0-1-qualification-envelope.md); it does not
waive the canonical evidence semantics, hostile-input rules, or release-candidate
integrity requirements.

At this snapshot, the local repository is on unborn `main`, the configured
GitHub remote is private and empty, and no commit, CI run, tag, draft, attestation,
or release exists. The repository owner has authorized a push and public release
only after every applicable gate below is green. Do not publish early.

## Gate A — reviewed source tree

- [ ] Review `git status`, all untracked files, and the complete staged diff.
  Exclude caches, binaries, temporary directories, generated cases, databases,
  WAL/SHM files, archives, raw logs, editor data, and machine-specific paths.
- [ ] Confirm only the generic synthetic incident pack is shipped. Search for
  private controlled repository names, run/job/object IDs, real incident values,
  customer data, personal paths, signed URLs, and production evidence.
- [ ] Scan staged content for credentials, authorization headers, token prefixes,
  private keys, secret values, shell history, and accidental raw logs.
- [ ] Confirm `AGENTS.md` is present and that source, docs, commits, release notes,
  and generated artifacts contain no assistant, agent, or automation authorship
  credit.
- [ ] Verify Apache-2.0, DCO instructions, complete applicable dependency notices,
  privacy/security policies, issue templates, and incident-pack review rules.
- [ ] Verify all third-party Actions are pinned by reviewed full object IDs and
  match `.github/actions-pins.json`; actionlint and shellcheck must pass.
- [ ] Confirm local Markdown links and schema references resolve and no checked-in
  schema depends on an unowned project website.
- [ ] Confirm the ten state identifiers, five provenance identifiers, and eight
  mandatory invariant sentences match model, schemas, fixtures, README, evidence
  model, test strategy, and report output.
- [ ] Configure the human maintainer Git identity and create a DCO-signed commit
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
- [ ] Run `gofmt` verification, `go mod tidy -diff`, `go mod verify`,
  `go test ./... -count=1`, `go vet ./...`, and `go test -race ./... -count=1`.
- [ ] Run the checked-in fuzz seed corpora and the documented sustained parser
  campaigns. Keep `SEC-002` open as a broad future campaign; the v0.1 release
  claim is limited to the recorded targets/budgets.
- [ ] Run the small and medium relational profiles and confirm indexed query
  plans. Keep 3,000,000 executions unsupported; do not relabel the two-hour
  timeout as a pass.
- [ ] Run reachable-vulnerability, license bundle, offline safety/strace,
  browser/CSP/injection, schema, action-pin, shell, and credential/private-data
  audits.
- [ ] Run `make demo` into a new directory, assert finding counts and required
  outputs, verify its manifest, and inspect the self-contained report offline.
- [ ] Run deterministic release packaging twice, byte-compare it, validate every
  SPDX document independently, run supported native/container/Wine smokes with
  their limits stated, and verify tamper rejection.
- [ ] From the exact reviewed index, run
  `CIREWIND_PREFLIGHT_REQUIRE_STAGED=1 make preflight` and retain the command
  summary outside the repository.

## Gate C — private publication and hosted CI

- [ ] Push the reviewed signed-off `main` commit to the private remote. Do not
  force-push or include any file outside the reviewed index.
- [ ] Wait for every configured Linux, macOS, and Windows CI job; fix failures in
  a new reviewed commit and repeat the exact-candidate local gates.
- [ ] Perform a clean clone from GitHub and reproduce build, tests, pack
  validation, demo, expected case outputs, and manifest verification using the
  published instructions.
- [ ] Keep default workflow permissions read-only and enable dependency alerts,
  secret scanning/push protection, and private vulnerability reporting where
  GitHub makes them available.
- [ ] Protect `main` against force push/deletion and require only check names that
  have actually run. Configure rules compatible with the solo-maintainer model.
- [ ] Create `release-draft` and `release-publish` environments with the exact
  reviewer, no-admin-bypass, and `tag:v*` policy required by
  [`RELEASE_PROCESS.md`](RELEASE_PROCESS.md); inspect both through the read-only
  verifier.
- [ ] Re-run public-source scans against the Git object GitHub received, not only
  the working tree.

## Gate D — public v0.1.0 release

- [ ] Record a final **GO** confirming all failures inside ADR 0011's supported
  envelope are closed and all remaining limitations are explicitly documented.
- [ ] Change repository visibility to public only after Gate C is green; verify
  private vulnerability reporting, security features, rules, and Actions remain
  configured after the visibility change.
- [ ] Create the reviewed annotated `v0.1.0` tag from the exact green `main`
  revision and push only that tag.
- [ ] Dispatch the release workflow with `publish=false`; approve the draft gate,
  then verify version metadata, source revision, checksums, archive contents,
  SPDX documents, license indexes, build provenance, signer workflow/ref, and
  every downloaded asset byte.
- [ ] Independently smoke the downloaded release on each advertised runtime-
  qualified platform. Label cross-build-only or Wine-only targets accurately.
- [ ] Dispatch the separate `publish=true` run, approve the publication gate,
  ensure it accepts the exact existing draft without rebuilding/substitution,
  and publish it.
- [ ] Verify the public tag, release page, immutable assets, `SHA256SUMS`, GitHub
  attestations, source archives, README links, `SECURITY.md`, and changelog from
  an unauthenticated view.
- [ ] Update this snapshot with the release URL, workflow run IDs, attestation
  verification result, and any nonblocking follow-up—without adding credentials,
  private lab identifiers, or assistant credit.

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
