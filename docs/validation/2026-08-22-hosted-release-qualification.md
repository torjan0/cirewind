# Hosted release qualification — 2026-08-22

Status: **pre-tag qualification; publication not yet authorized by this record**

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
enabled. `main` was not yet protected at this snapshot; its release-required
check names must be selected from completed public runs rather than guessed.

The exact Git object received by GitHub was checked independently of the working
tree. Gitleaks, TruffleHog, and the repository-tree policy audit reported no
findings, and the settings read-back matched the controls above.

## Open publication gates

Public-visibility CI run
[`32553662965`](https://github.com/torjan0/cirewind/actions/runs/32553662965)
completed successfully from the same exact source baseline on 2026-08-22 UTC.
Its six Linux/macOS/Windows architecture jobs, race detector,
reachable-vulnerability scan, and reproducible release-packaging contract all
passed. The final documentation revision must still receive its applicable
integrity and hosted checks before tagging.

No `v0.1.0` tag, protected draft run, GitHub build-provenance attestation,
release asset, or publication result is asserted here. Those gates remain open
in [`PUBLIC_RELEASE_CHECKLIST.md`](../PUBLIC_RELEASE_CHECKLIST.md).

## Scope of the conclusion

The facts above establish a qualified public, pre-tag source baseline and
repository readiness for the protected release workflow. They do not establish
publisher authenticity for local candidate bytes, attest the final release
assets, qualify GitHub.com behavior outside the documented experimental
envelope, or make the v0.1 publication decision.
