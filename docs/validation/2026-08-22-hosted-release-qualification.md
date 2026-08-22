# Hosted release qualification — 2026-08-22

Status: **v0.1.1 published and immutable; protected v0.1.0 candidate retained
as an unpublished audit record**

This record captures only sanitized release-readiness facts for the public
repository. It contains no controlled-lab identifiers, credentials, raw logs, or
private evidence.

## Qualified source baseline

The product-source baseline
`7c548ebb56c1a5fecb55b65aebd8f582ae5dc6ba` was pushed to `main` with a DCO
sign-off. While the repository was private, GitHub Actions CI run
[`32553126718`](https://github.com/torjan0/cirewind/actions/runs/32553126718)
completed successfully from that exact object on 2026-08-22 UTC. All nine jobs
passed:

- tests on `linux-amd64`, `linux-arm64`, `darwin-amd64`, `darwin-arm64`,
  `windows-amd64`, and `windows-arm64`;
- the race detector;
- the reachable-vulnerability scan; and
- the reproducible release-packaging contract.

A separate clean clone of the remote revision reproduced the documented build
and default tests, validated the synthetic pack, ran the offline demonstration,
confirmed the required case-file set and expected synthetic counts, and verified
`manifest.sha256`. These checks used no GitHub credential for the product command
path and made no live-collection claim.

The final `v0.1.0` candidate revision
`2088f133df395f472180848ba6e929919c743b0d` included the reviewed public-release
status record. Public CI run
[`32554210398`](https://github.com/torjan0/cirewind/actions/runs/32554210398)
completed successfully from that exact object. All six native-platform test,
vet, and build jobs, the race detector, the reachable-vulnerability scan, and
the reproducible release-packaging contract passed.

## Public repository controls

After the repository became public, the following settings were read back from
GitHub on 2026-08-22 UTC:

- the default branch is `main` and default workflow permissions are read-only;
- Actions are limited to the five reviewed full-SHA patterns represented in
  `.github/actions-pins.json`, with SHA pinning required;
- dependency alerts and automated security updates are enabled;
- private vulnerability reporting is enabled;
- secret scanning and push protection are enabled;
- `release-draft` and `release-publish` each require the repository owner as the
  sole reviewer, permit self-review for the documented solo-maintainer case,
  disable administrator bypass, and accept only the custom `tag:v*` policy; and
- the active `Protect release tags` ruleset covers `refs/tags/v*`, blocks
  deletion and non-fast-forward changes, and has no bypass actor.

The optional non-provider secret patterns and secret-validity checks were not
enabled. The active `Protect main` ruleset now covers the default branch with no
bypass actor, blocks deletion and non-fast-forward updates, requires linear
history and pull requests, and requires the nine check contexts observed in the
successful public CI run.

The exact Git object received by GitHub was checked independently of the working
tree. Gitleaks, TruffleHog, and the repository-tree policy audit reported no
findings, and the settings read-back matched the controls above.

## Protected v0.1.0 candidate attempt

Public-visibility CI run
[`32553662965`](https://github.com/torjan0/cirewind/actions/runs/32553662965)
completed successfully from the same exact source baseline on 2026-08-22 UTC.
Its six Linux/macOS/Windows architecture jobs, race detector,
reachable-vulnerability scan, and reproducible release-packaging contract all
passed. The subsequent final candidate run `32554210398` passed the same nine
checks at `2088f133df395f472180848ba6e929919c743b0d`.

The reviewed annotated `v0.1.0` tag points to that exact final candidate commit
and is protected from deletion and non-fast-forward change. Authenticated
release run
[`32554866238`](https://github.com/torjan0/cirewind/actions/runs/32554866238)
then established the following bounded result:

- exact dispatch/tag/commit validation, two byte-identical builds, the native
  Linux smoke, all fourteen subject attestations, and immutable workflow-artifact
  transfer passed;
- the protected draft job revalidated the tag and distribution and successfully
  verified every expected build-provenance subject before any release creation;
- draft creation failed closed because the installed GitHub CLI rejects
  `gh release create --notes-from-tag` when `--repo` is also supplied; and
- the release-asset comparison was skipped, the publication job was skipped,
  and the GitHub Releases API reported no draft or published release for
  `v0.1.0`.

The retained Actions workflow artifact is candidate transport, not a GitHub
Release asset. No draft, published release, or release asset was created. The
failed invocation did not weaken or bypass the tag, environment, distribution,
or provenance checks; it prevented the first release write.

Because the protected `v0.1.0` tag is an immutable audit record, it will not be
moved or reused. `v0.1.1` was selected as the recovery publication target. Its
corrected workflow revision, final CI, annotated tag, protected draft inspection,
downloaded-asset smoke, separate publication approval, and unauthenticated
release verification were open at that point in
[`PUBLIC_RELEASE_CHECKLIST.md`](../PUBLIC_RELEASE_CHECKLIST.md).

## Recovery-source qualification

The release-creation correction was reviewed in
[PR #1](https://github.com/torjan0/cirewind/pull/1). PR CI run
[`32556616946`](https://github.com/torjan0/cirewind/actions/runs/32556616946)
was associated with PR head `a1ec0cb23f2a5204781a9ccf17393139181aa2c4`
and checked out GitHub-generated merge object
`c916b0b8174ec5c561bf34f60c1d65ae224cc6fa`. All nine required jobs passed on
that merge object: six Linux/macOS/Windows architecture jobs, the race detector,
the reachable-vulnerability scan, and the reproducible release-packaging
contract. The PR was squash-merged to `main` as
`a56a880c4fadf2ab85945b3b96099b5b2cf62a25`. Main push CI run
[`32556880171`](https://github.com/torjan0/cirewind/actions/runs/32556880171)
passed the same nine checks at that exact `main` commit.

Those results qualified the reviewed recovery source path only. Neither run used
a `v0.1.1` tag or created official release artifacts, attestations, a draft, or
a release. The remaining gates were completed separately as recorded below.

## Final v0.1.1 source and local qualification

Release preparation was reviewed in
[PR #2](https://github.com/torjan0/cirewind/pull/2). Run
[`32557676966`](https://github.com/torjan0/cirewind/actions/runs/32557676966)
was associated with PR head `3dba4ceb2115f1092b57a124c64347889c0c9136`
and passed all nine required jobs on GitHub-generated merge object
`62b9d8a9d55c081ba55fd9af8be84b8228498e8d`.
The PR was squash-merged as
`d4954356e733af42500061885dae36996281547e`; main run
[`32557942570`](https://github.com/torjan0/cirewind/actions/runs/32557942570)
passed the same six Linux/macOS/Windows target jobs, race detector,
reachable-vulnerability scan, and release-packaging contract at that exact
object. An anonymous clean clone reproduced the exact tree
`006baad681fe594b1961158de66b3fa6813f26db`, passed strict Git-object checks,
and remained clean.

The final source revision passed the complete documented local preflight,
default tests, vet, race detector, reachable-vulnerability and license checks,
six-target cross-build, credential-free demo, manifest verification, browser
and safety audits, actionlint, shellcheck, static analysis, and release-contract
tamper tests. Final bounded fuzz campaigns executed 15,668,442 inputs across 13
targets without a failure. A 5 GiB aggregate parser run produced no false
lifecycle evidence. The medium relational profile completed at 1,000
repositories, 100,000 runs, and 300,000 executions with integrity and indexed
query checks passing; larger inputs remain outside the documented envelope.

Two official local builds produced byte-identical 14-file distributions for six
targets. `SHA256SUMS` has SHA-256
`c1f45182395985bbdd868c9f59bcf1d55fc566d4248ce59f6bf07de4bbcc8e37`;
all six SPDX 2.3 documents passed independent `spdx-tools` 0.8.5 validation.
Linux amd64 passed the complete archive smoke natively with credentials unset
and in a network-disabled, read-only-root container. Windows amd64 passed the
same compatibility smoke under Wine; this is not native Windows qualification.
The remaining published targets are cross-build-qualified only.

## Protected tag, draft, and publication

Protected annotated tag object
`c7fa1e8b7ddedd7c27e8df423161b9735227cd3e` identifies `v0.1.1` and peels to
the exact final source commit. The tag remains unsigned. Asset build provenance
is supplied separately by the two GitHub SLSA attestations; tag and publication
authorization rely on the documented GitHub ruleset and protected-environment
controls. The active tag ruleset permits no deletion, non-fast-forward update,
or bypass.

The protected `publish=false` run
[`32559258464`](https://github.com/torjan0/cirewind/actions/runs/32559258464)
completed successfully. Its build job validated the exact tag/commit, built the
distribution twice with byte-identical output, ran the credential-free Linux
smoke, attested all 14 subjects, and transferred immutable workflow artifact
`9472359966`. After the `release-draft` approval, the draft job revalidated the
tag, distribution, environment policy, and provenance for every subject before
creating the draft. It then downloaded all draft assets and byte-compared them
to the verified subjects.

Independent draft review downloaded the 14 assets into a fresh directory and
confirmed exact equality with the separately built local candidate, GitHub API
digests, `SHA256SUMS`, archive/build graphs, license indexes, and all six SPDX
documents. Both SLSA build-provenance statements covering all 14 release
subjects verified against exact signer workflow
`.github/workflows/release-candidate.yml`, source ref `refs/tags/v0.1.1`, and
source/signer digest `d4954356e733af42500061885dae36996281547e`.

The separate `publish=true` run
[`32559856110`](https://github.com/torjan0/cirewind/actions/runs/32559856110)
also completed successfully. It independently reproduced and attested the same
subjects in workflow artifact `9472527249`, passed the protected draft gate,
accepted and byte-compared only the existing exact draft, then stopped at the
separate `release-publish` gate. After approval, the publish job again verified
the tag, distribution, provenance, environment policy, and immediate draft
asset set before changing the already-verified draft to public without rebuilding
or replacing an asset.

GitHub Release [`v0.1.1`](https://github.com/torjan0/cirewind/releases/tag/v0.1.1),
release ID `374862445`, was published at `2026-08-22T07:43:52Z`. Anonymous REST
and HTML checks report `draft=false`, `prerelease=false`, `immutable=true`, and
the same release as latest. Exactly 14 uploaded assets are present: six archives,
six SPDX documents, `release-metadata.json`, and `SHA256SUMS`. Every public API
size/digest matches freshly downloaded bytes, and the release notes exactly
match the reviewed tag-derived notes. Source tar/zip archives, README, security
policy, changelog, and every release-note link are publicly reachable.

The deterministic `release-metadata.json` intentionally records
`authentication.authenticated: false`; it describes reproducible local build
metadata and is not mutated after publication. The separately stored GitHub
statements supply authenticated build-provenance claims for the public subjects.

For a credential-independent provenance check, the two matching SLSA
build-provenance bundles were retrieved through GitHub's anonymous public
attestation API and verified locally against the exact signer/source policy. An
anonymous exact-tag clone peels to the
release commit and passes strict Git-object checks. The public release list
contains no `v0.1.0` release, and its release-by-tag endpoint returns `404`.

## Scope of the conclusion

The facts above establish the final GO and completed publication gates for the
bounded experimental v0.1.1 envelope accepted in ADR 0011. They establish an
exact immutable public release-asset set and hash-verifiable GitHub provenance;
they do not certify that the software is secure, production-ready, or complete
for every GitHub.com organization, credential type, runner grammar, retained
evidence condition, or input above the measured scale envelope. Cross-build and
Wine results are not native qualification. Operators must still review coverage
and evidence gaps, and the open compatibility work in `TASKS.md` remains open.
