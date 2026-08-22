# Release authentication and Windows compatibility validation — 2026-08-21

Status: **source-controlled gate passed locally; GitHub authority and native
platform gates not yet exercised**

This record covers static validation of the manual release workflow, official
action-pin retrieval, exact build-provenance policy, and a Windows amd64
compatibility smoke under Wine. No GitHub release, draft, attestation, tag,
workflow dispatch, push, pull request, or other GitHub write was performed.

## Primary-source findings

All sources were retrieved on 2026-08-21.

- GitHub's [artifact-attestation how-to](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations)
  specifies `id-token: write`, `contents: read`, and `attestations: write` for
  binary provenance; `actions/attest` with only `subject-path` generates build
  provenance; and verification uses `gh attestation verify`.
- GitHub's [attestation concepts](https://docs.github.com/en/actions/concepts/security/artifact-attestations)
  state that attestations bind bytes to repository/workflow build identity, use
  public Sigstore for public repositories and GitHub's private Sigstore for
  private repositories, and do not establish that an artifact is secure.
- The [`gh attestation verify` manual](https://cli.github.com/manual/gh_attestation_verify)
  recommends constraining the signer workflow and exposes exact signer/source
  digest and source-ref policy flags. It also supports rejecting self-hosted
  attesting runners.
- GitHub's [deployment-environment reference](https://docs.github.com/en/actions/reference/workflows-and-actions/deployments-and-environments)
  documents required reviewers, prevention of self-review, selected tag rules,
  and administrator bypass. Required reviewers on Free/Pro/Team are available
  only for public repositories.
- GitHub states that enabling prevention of self-review makes the workflow
  initiator unable to approve even when that person is a required reviewer. A
  single-person repository therefore cannot combine that setting with a manual
  approval by its only authorized maintainer.
- The [environment REST reference](https://docs.github.com/en/rest/deployments/environments#get-an-environment)
  documents that `Actions: read` is sufficient for a private fine-grained token
  to inspect an environment and exposes its reviewer protection rules.
- The [deployment branch-policy REST reference](https://docs.github.com/en/rest/deployments/branch-policies?apiVersion=2026-03-10)
  documents read access, selected-policy enumeration, and distinct `branch` and
  `tag` rule types.
- The [`gh release create` manual](https://cli.github.com/manual/gh_release_create)
  documents `--verify-tag`, draft creation, exact asset arguments, and that
  release immutability begins only after publication. The
  [`gh release edit` manual](https://cli.github.com/manual/gh_release_edit)
  documents publishing an existing draft with `--draft=false`.

Artifact attestations are available to public repositories on current plans.
Private or internal repository use requires GitHub Enterprise Cloud. That plan
and visibility prerequisite is an external gate; it was not assumed locally.

## Official action-pin verification

Each tag below was queried directly from the named official repository with
`git ls-remote --tags https://github.com/OWNER/REPOSITORY.git
refs/tags/VERSION refs/tags/VERSION^{}`. The checked-in security boundary is the
full object ID, not the mutable-looking version comment.

| Action | Reviewed tag | Exact object ID |
|---|---:|---|
| [`actions/attest`](https://github.com/actions/attest) | `v4.2.2` | `1e69f48acb82d1966a394da916b4c1698aa569d6` |
| [`actions/checkout`](https://github.com/actions/checkout) | `v7.0.1` | `3d3c42e5aac5ba805825da76410c181273ba90b1` |
| [`actions/download-artifact`](https://github.com/actions/download-artifact) | `v8.0.1` | `3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c` |
| [`actions/setup-go`](https://github.com/actions/setup-go) | `v7.0.0` | `b7ad1dad31e06c5925ef5d2fc7ad053ef454303e` |
| [`actions/upload-artifact`](https://github.com/actions/upload-artifact) | `v7.0.1` | `043fb46d1a93c77aae656e7c1c64a875d1fc6a0a` |

`.github/actions-pins.json` records the same data. The offline acceptance test
parses every workflow, rejects any nonlocal action not pinned by a 40-hex ID,
requires a matching reviewed ledger entry, and rejects unused ledger entries.

The pinned `actions/attest` README and `action.yml` were also retrieved by exact
object ID. They confirm that provenance mode is selected when `subject-path` is
provided without an SBOM/custom predicate and that multiple path subjects are
included in one attestation.

## Manual workflow policy exercised statically

`.github/workflows/release-candidate.yml` was parsed by actionlint and by the
offline Go policy test. The tests proved:

- the sole trigger is `workflow_dispatch`;
- permissions default to none and are declared per job;
- checkout credentials are never persisted and checkout uses the exact tag ref;
- the build job alone can mint an OIDC token and write attestations;
- the draft and publish jobs alone have `contents: write`, and neither can mint
  OIDC tokens;
- all fourteen distribution-root files are attested before immutable-ID upload;
- attestation verification precedes every possible release creation;
- the separate `release-draft` and `release-publish` environments are named;
- those jobs fail closed unless the environment API shows exactly the
  repository-owner user as the sole reviewer, self-review prevention disabled,
  administrator bypass disabled, selected-policy mode, and exactly one `tag:v*`
  deployment policy;
- draft and publish consume the build artifact ID and do not rerun release
  packaging;
- draft assets are downloaded and byte-compared; and
- publication rechecks the tag, distribution, attestations, draft status, and
  exact remote bytes before `gh release edit --draft=false`.

Local static checks cannot prove the repository's current environment settings,
although the workflow re-reads and enforces them before either write. No
source-controlled check can prove that an authorized reviewer will make a sound
decision; that remains a human authority boundary.

## Solo-maintainer approval decision

The current repository is owned and maintained by `torjan0`. The workflow passes
`GITHUB_REPOSITORY_OWNER` to the read-only environment verifier and accepts only
that exact user as the sole required reviewer. `prevent_self_review` must be
`false`, because GitHub otherwise blocks the initiator from approving and the
solo maintainer has no independent reviewer. The verifier additionally requires
`can_admins_bypass=false`, selected custom deployment policies, and exactly one
tag policy named `v*`; its `Actions: read` permission cannot change these
settings.

This is not independent review. It retains an explicit approval pause and audit
event but leaves one person able to initiate and approve. The compensating
controls are an exact existing annotated tag at `GITHUB_SHA`, exact source and
signer attestation policy, no administrator bypass, no branch deployment rule,
immutable artifact-ID handoff, byte comparison of the draft, and a separate
manual publication gate. The documented operating sequence is a
`publish=false` run, human inspection of the resulting draft and exact assets,
then a separate `publish=true` run and approval. If a second trusted maintainer
is added, enable prevention of self-review and require that independent person.

A read-only `GET /repos/torjan0/cirewind/environments` on 2026-08-21 returned
`total_count: 0`. Neither release environment is configured yet; no settings
were created or changed during this validation.

## Six-target CI matrix validation

The exact native CI labels are `ubuntu-24.04`, `ubuntu-24.04-arm`,
`macos-15-intel`, `macos-15`, `windows-2025`, and `windows-11-arm`. GitHub's
[hosted-runner reference](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)
currently maps these to Linux amd64/arm64, macOS Intel/arm64, and Windows
amd64/arm64 respectively. The offline policy test pins that exact six-entry
matrix, and actionlint 1.7.12 accepts both workflow files. This is static syntax
and documented-label validation; it does not claim that any of those hosted jobs
has run successfully until GitHub records the matrix run.

## Windows amd64 compatibility under Wine

Environment:

- Linux x86-64 host;
- Wine 9.0 (`Ubuntu 9.0~repack-4build3`);
- `CGO_ENABLED=0` Windows amd64 archive built with Go 1.25.13;
- Wine prefix, Go caches, temporary paths, extraction, case outputs, and the
  approximately 37 MB six-target synthetic distribution all under a dedicated
  non-workspace scratch directory;
- supported token variables unset; and
- no Docker command, package installation, or live GitHub request.

The first run exposed a real Windows defect: an absolute drive path such as
`Z:\\...\\archive.db` was encoded into a SQLite URI without the leading slash,
so SQLite interpreted `Z:` as an invalid URI authority. `internal/store` now
normalizes drive-letter file URIs to `file:///Z:/...`; a Windows-specific unit
assertion covers the format.

After rebuilding the synthetic distribution, Wine successfully ran:

```text
cirewind version
cirewind --help
cirewind investigate --help
cirewind pack validate incidents\synthetic\mutable-tag.yaml
cirewind archive --import-fixture synthetic --store ...
cirewind replay --archive ... --incident ... --out ...
cirewind verify ...
```

Observed terminal result:

```text
Windows/amd64 archive compatibility smoke passed under Wine (not native Windows qualification)
```

This demonstrates a substantial Windows user-space compatibility path. It is
not native Windows runtime, installer, ACL, antivirus, path-length, console, or
endpoint qualification and must never be reported as such.

## Commands and results

All Go temporary/cache paths were redirected to the designated large-work
filesystem.

```text
actionlint .github/workflows/ci.yml .github/workflows/release-candidate.yml
  PASS
shellcheck scripts/verify-release-ref.sh scripts/verify-release-attestations.sh \
  scripts/verify-release-environment.sh scripts/compare-release-assets.sh \
  scripts/smoke-release-wine.sh scripts/release.sh
  PASS
go test ./internal/acceptance -run 'TestReleaseWorkflow|TestActionPins|TestCIUsesExactSixTarget|TestReleaseEnvironmentPolicy' -count=1
  PASS
go test ./internal/store -count=1
  PASS
go test ./...
  PASS
go vet ./...
  PASS
go test -race ./internal/store ./internal/acceptance
  PASS
GOOS=windows GOARCH=amd64 go test -c ./internal/store; wine store.test.exe ...
  PASS: Windows URI regression and create/open/header round trip
make release-test RELEASE_WORK_ROOT=...
  PASS: two six-target builds byte-identical; Linux native smoke and tamper rejection
scripts/smoke-release-wine.sh ...
  PASS under Wine 9.0
```

No attestation verification was claimed locally: the installed GitHub CLI is
2.45.0 and does not provide the policy-complete attestation command used by the
workflow. The helper intentionally checks required CLI flags and fails before a
network request if a future runner is too old.

## Remaining release blockers

- Configure and independently inspect both protected environments: sole reviewer
  `torjan0`, self-review prevention disabled for the solo-maintainer exception,
  administrator bypass disabled, selected-policy mode, and exactly one `tag:v*`
  rule. Then exercise both approval pauses and retain their run evidence.
- Make the repository public or use a GitHub Enterprise Cloud private/internal
  repository before expecting GitHub artifact attestations and required-review
  gates to work together.
- Execute the workflow from a reviewed real annotated tag; inspect the generated
  SLSA statements; verify every downloaded subject; and retain the run URL and
  attestation IDs in the eventual release record.
- Run native smoke on Windows and macOS, and runtime smoke on trusted arm64
  hosts. Cross-compilation and Wine do not close those platform gates.
- Complete the product-level public collection/evidence-persistence blocker in
  [`2026-08-21-public-readonly-qualification.md`](2026-08-21-public-readonly-qualification.md): not every redirect/storage, explicit-repository resolution, or parent-stabilization response is yet persisted as its own compact observation.
- Re-run the complete release, SPDX, safety, browser, test, vet, and race gates
  on the eventual tagged commit. This record authenticates no future bytes.
