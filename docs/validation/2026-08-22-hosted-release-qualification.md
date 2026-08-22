# Hosted release qualification — 2026-08-22

Status: **protected v0.1.0 candidate retained; recovery source qualified; no
v0.1.1 tag, draft, or release**

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
moved or reused. `v0.1.1` is the recovery publication target. Its corrected
workflow revision, final CI, annotated tag, protected draft inspection,
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

Those results qualify the reviewed recovery source path only. Neither run used
a `v0.1.1` tag or created official release artifacts, attestations, a draft, or
a release. The final pre-tag revision, protected annotated tag, official build
and provenance run, draft and downloaded-asset inspection, final GO,
publication, and unauthenticated public verification remain open.

## Scope of the conclusion

The facts above establish a qualified source baseline and verified provenance
for the retained workflow subjects. They do not establish a release-asset set,
a published v0.1, or final publisher verification for downloaded assets. They
also do not qualify GitHub.com behavior outside the documented experimental
envelope. Publication remains blocked pending the final pre-tag qualification
and the complete tagged `v0.1.1` artifact, draft, GO, publication, and public-
verification sequence.
