# Security policy

CIRewind processes hostile workflow definitions, logs, archives, incident packs,
repository metadata, SQLite files, and report fields. Reports about parser
escapes, token disclosure, report injection, unsafe archive handling, evidence
corruption, or forensic overclaiming are especially important.

## Supported versions

CIRewind v0.1 is experimental. Security fixes are made only on the newest patch
release in the current `0.1.x` line.

| Version | Security support |
| --- | --- |
| Latest `0.1.x` patch | Best-effort security fixes |
| Older `0.1.x` patches | Upgrade to the latest patch |
| Unreleased `main` | Development review; no compatibility guarantee |
| Unofficial binaries or modified snapshots | Not supported by this project |

This policy does not promise incident-response completeness, a response-time
service level, or support for evidence outside the qualification envelope in
[`ADR 0011`](docs/adr/0011-experimental-v0-1-qualification-envelope.md).

## Report a vulnerability privately

Use this repository's **Security** tab, select **Report a vulnerability**, and
open a private GitHub Security Advisory. That route is the project's confidential
reporting channel. Do not put vulnerability details in a public issue, discussion,
pull request, or workflow log.

Include only sanitized material:

- the affected released version or source revision;
- operating system and architecture;
- a minimal reproduction using synthetic data;
- the expected and observed security boundary;
- impact and preconditions; and
- a suggested mitigation, if known.

Never include GitHub tokens, secret values, private workflow logs, private
repository content, production case bundles, temporary signed URLs, private
keys, or unredacted personal data. Replace identifiers consistently and use a
harmless fixture.

Reports are acknowledged, investigated, and coordinated on a best-effort basis.
The advisory may be used for private discussion, a patch, a CVE request, and
coordinated disclosure. Public disclosure should wait until affected users have
a reasonable opportunity to update.

The v0.1 release is gated on GitHub private vulnerability reporting being
enabled immediately after the repository becomes public and before release
assets are published. If the **Report a vulnerability** control is absent, the
confidential route is not operational; do not disclose details publicly.

## Security boundaries

Expected behavior includes:

- GitHub access is read-only.
- Authentication material is neither logged nor persisted.
- Incident-pack content cannot initiate network requests or execute code.
- Downloaded Action code is parsed as data and never executed, built, imported,
  or installed.
- Raw workflow logs are not retained by default.
- Report, JSON, CSV, terminal, YAML, SQLite, path, redirect, and archive
  boundaries treat content as hostile.
- Missing evidence reduces coverage; it never produces a false negative.
- A case manifest supports integrity checking, not publisher authentication or
  legal chain-of-custody certification.

The detailed threat model and residual risks are documented in
[`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).

## Out of scope

Feature requests, intended conservative limitations, and non-sensitive bugs
belong in the issue tracker. Reports requiring exploitation of systems not owned
by the reporter or explicitly authorized for testing are not accepted. Do not
send real credentials or use CIRewind's project infrastructure as an attack
target.
