# Exportable public-lab local qualification

Date: 2026-08-31

Branch: `lab/public-a-b-a-source`

Status: local, uncommitted engineering qualification. This record establishes
neither a public laboratory nor GitHub-hosted behavior. No repository was
created, no remote ref was changed, no workflow was dispatched, and no outside
human reproduced or independently reviewed the exercise.

## Qualified local scope

This pass exercised the exportable harmless A-to-B-to-A source package:

- deterministic G/A/B/W/R/I Git history and owner-specialized workflow bytes;
- exact annotated fixture-tag objects, peeled A/B commits, lightweight `v1`,
  and import commit I;
- fixed-output marker A and B definitions;
- direct, composite, reusable, skipped, matrix, and rerun workflow source;
- a fail-closed exact-object tag-move plan, lease, readback, recovery path, and
  machine-readable observation record;
- pre-case pack-input and synthetic-pack generation bound to exact source
  objects and immutable record bytes;
- bounded tag-move, pack-input, run, reproduction, and stable-index schemas;
- a complete attempt/job-specific oracle that keeps downloaded-only evidence
  below `CONFIRMED_EXECUTED`; and
- deterministic checked artifacts plus negative closure tests.

The owner-specialized artifact must be imported into a new, separately owned
repository. A normal GitHub fork is not qualified because its committed
repository-Action `uses:` values would still name the original owner/repository.
The default branch must remain exact import commit I during qualification;
provenance and observations belong on a separate protected, append-only,
non-default records branch.

## Deterministic artifact identity

| File | Bytes | SHA-256 | Mode |
| --- | ---: | --- | ---: |
| `lab/public/artifacts/cirewind-lab.bundle` | 39,656 | `16f41eac01532e764d2ed0518db2a7dafcbcd3bd6bcea5f8e4e9e23385667b99` | `0644` |
| `lab/public/artifacts/object-manifest.json` | 20,838 | `199f914b9fbc6aaf1d5cf8ed41f8734f594d072c8475d22725855d527aa682da` | `0644` |

The canonical artifact records marker A commit
`afb628b57608bae0397cdb0d2201103c4e6a1f2e`, marker B commit
`941f217e2d8b8c9bce64cedfcc07a0dd749eb831`, and import commit I
`a9ca057fb991b5860c48c855d506e36eab07c221`. These are Git object names;
SHA-256 of the complete artifact bytes provides the separate retained integrity
binding.

## Commands and results

The following checks passed against the final local bytes:

```text
make PUBLIC_LAB_REQUIRE_ACTIONLINT=1 public-lab-check
make public-lab-syscall-audit
go test ./internal/publiclab ./tools/publiclab -count=1
go vet ./internal/publiclab ./tools/publiclab
go test -race ./internal/publiclab ./tools/publiclab -count=1
go test ./... -count=1
go vet ./...
go test -race ./... -count=1
go mod verify
go mod tidy -diff
shellcheck scripts/public-lab-artifacts.sh \
  scripts/public-lab-marker-audit.sh \
  scripts/test-public-lab-artifacts.sh
gitleaks dir --no-banner --redact --exit-code 1 .
make preflight
```

The closure regenerated the bundle and manifest and compared both byte-for-byte
with the checked artifacts. It also ran `git bundle verify`, two independent
imports, strict full `git fsck`, complete object/file/ref comparison, schema and
oracle tests, generated-workflow `actionlint`, and negative tests for artifact
byte drift, hostile or unexpected entries, and symlinks. Artifact-bound record
validation rejects an external schema directory, binds the captured schema and
oracle bytes to the object manifest by byte length, SHA-256, and Git blob ID,
and rejects an in-memory manifest model that differs from the exact manifest
bytes.

The isolated clean-cache preflight additionally passed the whole-repository
normal and race suites, vet, pack-review governance validation, zero reachable
vulnerabilities, license validation, six CGO-disabled OS/architecture builds,
the offline synthetic demo, and case-manifest verification. The vulnerability
scanner reported one advisory in a required module but no imported or called
vulnerable symbol.

The Linux marker audit used `strace` and observed the two fixed marker commands
printing their expected public string with no child process, IP endpoint, or
filesystem mutation. The final directory secret scan reported no leak. Test
fixtures construct unmistakably synthetic credential-shaped rejection inputs at
runtime so secret-scanning rules can remain clean without weakening parser
coverage.

Tool versions:

- Go `1.25.13` (`linux/amd64`)
- Git `2.43.0`
- actionlint `1.7.12`
- strace `6.8`

No AWS resource was needed or launched. Infrastructure cost attributable to
this qualification pass is therefore `$0.00`.

## Semantic result

- Download announcement or completed preparation alone cannot satisfy
  `CONFIRMED_EXECUTED`.
- The skipped oracle requires exact-B preparation and forbids any exact-B
  lifecycle start.
- Original B and restored-A rerun attempts remain separate by run, attempt, and
  job identity.
- Exact observations, pack inputs, later run facts, and conclusions remain
  separate records; the incident pack is never derived from a finding or case.
- A failed, interrupted, or unreconciled tag operation cannot claim a confirmed
  target; a post-push readback failure is durably representable as
  `OUTCOME_UNKNOWN` without inventing a current target or restoration lease.
- Record validation and privacy scanning are rejection controls, not proof of
  factual truth, platform behavior, or absence of all sensitive material.

The ten finding states, five provenance identifiers, and eight mandatory
forensic invariants are unchanged.

## Gates intentionally still open

- `LAB-PUBLIC-003`: GitHub-hosted observation that the exact skipped-workflow
  grammar prepares B without starting its lifecycle.
- `LAB-PUBLIC-006`: authorized internal live A-to-B-to-A qualification and
  reset against a disposable staging repository.
- `LAB-PUBLIC-007` and `LAB-PUBLIC-008`: maintainer authorization, creation,
  configuration, execution, and publication of the separate public lab.
- `LAB-PUBLIC-009`: one genuinely independent outside-human reproduction
  against the exact qualified release candidate.
- `LAB-PUBLIC-010` and `LAB-PUBLIC-011`: maintainer acceptance/indexing and
  published-release identity recheck.

Local automation cannot close these external-state and human gates.
