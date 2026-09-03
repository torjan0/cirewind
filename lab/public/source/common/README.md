# CIRewind public A-to-B-to-A lab

This repository is a harmless, synthetic laboratory for independently testing
CIRewind's temporal GitHub Actions evidence reconstruction. Its fixed marker
Action prints one of these public strings:

```text
cirewind-lab-marker=A
cirewind-lab-marker=B
```

Neither marker is malicious or compromised. Marker B is called the affected
synthetic marker only because the laboratory incident pack selects its exact
commit as an indicator.

## Safety boundary

The basic laboratory:

- uses only GitHub-hosted runners;
- grants `GITHUB_TOKEN` only `contents: read`;
- defines no repository, organization, or environment secrets;
- does not use `pull_request_target`;
- does not use third-party Actions;
- does not inspect the environment, repository contents, credentials, or runner;
- does not make network requests from a workflow step;
- does not upload artifacts or mutate packages, releases, deployments, or
  repository contents; and
- prints only fixed public markers. The rerun fixture additionally exits with a
  fixed nonzero status after printing its marker.

Do not add real credentials, production targets, exfiltration behavior, or
untrusted pull-request execution to this repository.

## History contract

The reviewed import history contains separate commits for governance, marker A,
marker B, wrapper support, reusable-workflow support, and consumer workflows.
Immutable annotated fixture tags identify A and B. The disposable lightweight
`v1` tag is the only intentionally movable ref.

Moving `v1` is an explicit maintainer operation governed by the protocol. The
CIRewind binary never moves it. A completed exercise restores `v1` to A and
verifies the exact remote object before claiming reset success.

Tag control uses a dedicated clone on `main` at exact import I and accepts only
the repository-matching GitHub.com HTTPS or SSH remote in production; local
filesystem remotes are test-only. It mutates exact reviewed objects without
inspecting worktree content or invoking repository-controlled clean filters.
Each observation output is pre-reserved outside that clone before any remote
mutation. Provenance is published from a separate clone to protected,
append-only, non-default `refs/heads/observations`, never to `main`.

The GitHub repository database ID supplied to tag control is explicitly an
operator assertion and must later be cross-checked against GitHub run/API
evidence. Git transport alone cannot verify it.

The complete protocol, exact object manifest, expected findings, and
reproduction form are published with the reviewed laboratory import. A current
`v1 -> A` observation must never be used to rewrite or clear historical evidence
that a run attempt downloaded or began executing B.

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md) before
submitting a change. Contributions use Developer Certificate of Origin sign-off;
this project does not require a contributor license agreement.
