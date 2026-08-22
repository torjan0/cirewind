# Contributing to CIRewind

CIRewind welcomes focused contributions that preserve its conservative forensic semantics. The project is experimental, so start by reading [`README.md`](README.md), the accepted records in [`docs/adr/`](docs/adr/), and the planning document most relevant to the change.

By participating, you agree to the [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).

## Before opening a change

- Search existing issues and pull requests.
- Keep the change within CIRewind's historical GitHub Actions evidence scope.
- State whether behavior is implemented, experimental, planned, or not live-validated.
- Do not bundle unrelated formatting or refactoring.
- Never add tokens, secret values, private logs, real private repository data, or production evidence bundles.
- Use synthetic fixtures for exploit-shaped input and incident examples.

For substantial changes to evidence semantics, case storage, collection behavior, incident-pack interpretation, or trust boundaries, open a design issue first and update or add an architecture decision record as part of the eventual change.

## Development setup

Use the Go version declared in [`go.mod`](go.mod). Default development and test commands require no credentials or network access after dependencies are available.

```sh
make build
make test
make vet
make race
```

Before submitting Go changes:

```sh
gofmt -w path/to/changed.go
go test ./...
go vet ./...
go test -race ./...
git diff --check
```

Keep tests deterministic. Do not make the default suite depend on live GitHub, cloud credentials, Docker, a browser, a self-hosted runner, or external services. Live integration tests must be explicit opt-in tests against resources controlled for CIRewind testing.

## Forensic review checklist

Every change must preserve these distinctions:

```text
Action downloaded != Action executed
Repository possesses a secret != affected step could read that secret
id-token: write != cloud role assumed
Workflow ran during incident window != compromised SHA executed
Current tag points to a safe commit != historical runs were safe
No retained logs != no compromise
Deployment followed an affected step != attacker caused the deployment
Present-day workflow YAML != historical workflow definition
```

Do not introduce alternative names for the canonical finding states or provenance levels. A finding requires supporting evidence IDs or an explicit evidence-gap record. Missing or denied data must remain visible in coverage and confidence.

## Hostile-input requirements

Treat workflow YAML, Action metadata, logs, ZIP archives, incident packs, repository-controlled names, API errors, artifact metadata, and report fields as attacker-controlled. New parsers and renderers require limit tests, malformed-input tests, injection tests, and fuzz seed coverage appropriate to the boundary.

Downloaded Action code must never be executed, imported, built, installed, or checked out when API content retrieval is sufficient. Incident packs cannot contain executable hooks, arbitrary network requests, or untrusted HTML.

## Incident-pack contributions

Real-world packs must cite primary sources for every affected full SHA, immutable digest, mutable reference, and exposure window. Do not infer missing indicators or create plausible-looking values. If primary evidence is unavailable, contribute an explicitly synthetic fixture instead.

A real pack should receive review from at least two maintainers or subject-matter reviewers before release. Review must cover source provenance, identifier accuracy, time-zone and window boundaries, schema validity, ambiguous repository or subpath matching, remediation language, and absence of executable content.

## Dependencies and CI Actions

Keep dependencies minimal and explain why a new dependency is needed at a trust boundary. GitHub Actions used by this repository must be first-party where practical and pinned to a full commit SHA resolved from the official source repository. Do not guess a pin. Include the human-readable release tag in a comment and verify updates at review time.

## Developer Certificate of Origin

Contributions use the [Developer Certificate of Origin 1.1](https://developercertificate.org/) instead of a custom contributor license agreement. Sign off each commit:

```sh
git commit -s -m "Describe the change"
```

The sign-off certifies that you have the right to submit the contribution under the project's license. It must use your real name and an email address you are authorized to use. Pull requests with missing sign-offs should be corrected before merge.

Authorship and contribution records must identify the human contributors responsible for the change; do not add tool-generated author or co-author attribution.

## Pull requests

Explain the forensic conclusion affected, the evidence needed to support it, failure and partial-coverage behavior, tests added, and any live-validation gap. Update user-facing documentation when command behavior or output changes. Do not claim completion of an item whose objective acceptance criterion is not met.
