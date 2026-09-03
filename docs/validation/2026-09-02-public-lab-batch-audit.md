# Public-lab batch pre-commit security audit

Date: 2026-09-02

Branch: `lab/public-a-b-a-source` at `200fde2e8ef651545b6da1ab2b598ddb88820555`
(equal to `origin/main` at audit time), with the uncommitted public-lab batch.

Status: local, uncommitted engineering audit of the exportable public-lab
source package recorded in the
[`2026-08-31 local qualification`](2026-08-31-public-lab-local-qualification.md).
No repository was created, no remote ref was changed, no workflow was
dispatched, nothing was pushed, and no outside human reviewed or reproduced
anything. This record supersedes the 2026-08-31 command results for the batch
as it will be committed, because the audit changed Go source, tests, scripts,
and documentation. The checked artifact identities did not change.

## Scope reviewed

The complete dirty diff and every untracked public-lab file were read,
including `internal/publiclab`, `tools/publiclab`, `lab/public`, the object
manifest schema, the three shell scripts, the Makefile targets, and the four
modified tracked documents. Review focused on the tag-move policy and Git
boundary, record and schema closure, artifact binding, the generated workflow
and marker Action bytes, and the documentation claims listed in the handoff.

## Properties confirmed by reading and by test

- Only lightweight `refs/tags/v1` can be targeted, only between the exact
  reviewed A and B commits, only with the literal acknowledgement, and only
  through one `--force-with-lease=refs/tags/v1:<exact-old>` push. Branch,
  fixture-tag, release-tag, wildcard, and same-target requests fail before any
  Git command.
- A readback equal to the requested target is reported as success only when
  the same invocation also produced exactly one forced-update porcelain
  record; an interrupted push, a failed readback, a concurrent change, and a
  same-target race are preserved as `INTERRUPTED`, `OUTCOME_UNKNOWN`,
  `CONCURRENT_CHANGE`, and `REMOTE_TARGET_REACHED_UNCONFIRMED`. Pack-input
  generation accepts only two `CONFIRMED_APPLIED` records.
- Observation output is pre-reserved outside the tag-control clone with
  `O_EXCL`, and pathname, parent, and descriptor identity are rechecked before
  every write; replacement of the path or parent fails without touching the
  replacement.
- Network Git operations run in an isolated bare Git directory that borrows
  only a validated closed object store. Global and system configuration,
  `GIT_*` transport, credential, hook, trace, and object-redirect variables are
  discarded; repository-local URL rewrites, `core.fsmonitor`, and clean filters
  cannot execute. The boundary never invokes a shell and bounds output.
- No error string, record, or terminal line carries the remote URL, command
  output, worktree path, or authentication material; tests inject synthetic
  token-shaped output and assert it does not surface.
- Marker A and B differ by one byte of fixed output and read no environment,
  file, credential, or network endpoint; the source audit and Linux `strace`
  observation agree with the pinned bytes.
- All seven record schemas are closed (`additionalProperties: false`), bounded
  by length and item limits, and validated with a loader that has no URL
  scheme registered, so no reference can be fetched. Record strings are scanned
  for credential shapes and exact private paths before schema diagnostics are
  constructed.
- `CONFIRMED_EXECUTED` requires a cited same-step `LIFECYCLE_STARTED` or
  `LIFECYCLE_COMPLETED` observation; `CONFIRMED_DOWNLOADED` requires
  `PREPARATION_COMPLETED` and forbids any lifecycle start; `DOWNLOAD_ANNOUNCED`
  supports neither. Rerun attempts must be contiguous, job IDs may not repeat
  across attempts, and rerun jobs must bind an immediately prior job.
- The repository database ID is carried only under the
  `OPERATOR_ASSERTED_PREFLIGHT_REQUIRES_RUN_CROSSCHECK` basis, the CLI flag is
  named `--assert-repository-id`, and run-record validation requires equality
  with the later collected record.
- Schema, scanner, privacy-attestation, and fixture results are described as
  rejection controls throughout the specification, protocol, lab README, issue
  form, and reset checklist, never as proof of factual truth or complete
  privacy.
- The ten finding states, five provenance identifiers, eight mandatory
  invariants, and `run_id + run_attempt + job_id` identity are unchanged.

## Defects found and fixed

1. **Hook path relied on an undocumented fallback.** The Git boundary passed
   `core.hooksPath=` (empty). Git resolves that to hook paths directly under
   the filesystem root, which is disabled only by root ownership of `/`. The
   boundary now passes the null device, which can never contain a hook.
   File: `internal/publiclab/gitboundary.go`.
2. **Boundary allowlist did not shape the remote argument.** The `ls-remote`
   and `push` allowlist entries validated every fixed position except the
   remote itself, so a caller that bypassed policy validation could have
   supplied an option-shaped value such as `--upload-pack=`. The allowlist now
   rejects empty or option-shaped remotes. Test:
   `TestAllowedGitInvocationRejectsOptionShapedRemotes`.
3. **Policy rejection printed a remote-readback diagnostic.** When
   `PlanV1Move` rejected a request before any Git command (for example a
   one-character acknowledgement mismatch), the CLI attempted to encode a
   record from an empty result, failed, and printed that the remote state was
   unconfirmed and must be read back. No remote had been contacted. The CLI
   now reports that the move was rejected before any Git command or remote
   contact and that no observation record was written; the pre-reserved path
   is released. Test added inside
   `TestPlanAndMoveV1OperateOnlyOnExactDisposableTag`.
4. **Dead empty-overlay exception.** `readOverlay` permitted an empty
   `marker-b` overlay; the overlay contains one file and an empty marker B
   overlay would make A and B identical. The exception was removed so every
   overlay must contain at least one file.
5. **Hosted CI could not detect artifact drift.** No test compared the
   checked-in bundle and manifest with regeneration, and `ci.yml` does not run
   `make public-lab-check`. `TestCheckedArtifactsMatchDeterministicRegeneration`
   now runs under the ordinary `go test ./...` matrix on all six targets.
6. **Bundle Git attribute.** `.gitattributes` now marks
   `lab/public/artifacts/cirewind-lab.bundle` as `binary`. Git already
   detected it as binary under `text=auto`, and the filtered and unfiltered
   blob IDs were identical before and after the change, so the stored bytes are
   unaffected.
7. **Cosmetic.** The `publiclab` usage text had one tab-indented line and
   `scripts/public-lab-artifacts.sh` had two tab-indented lines; both now use
   the surrounding two-space indentation.

## Documentation corrections

- HTTPS remotes pass policy validation, but the isolated boundary discards
  credential helpers, global configuration, and prompts, so an authenticated
  HTTPS push has no credential source and fails closed before any ref changes.
  The specification, lab README, and tool usage now state that SSH through the
  operator's normal agent or key is the practical production transport.
- Git object IDs depend only on source bytes; bundle bytes and their SHA-256
  additionally depend on the compressor of the Go toolchain pinned in
  `go.mod`. The lab README now states the artifact identity under that
  toolchain.
- The handoff observation that `formatRecovery` repeats the phrase "reviewed
  known-good target" was checked: the phrase appears once, and the second
  occurrence of the same object ID is the deliberately separate restore target.
  No change. The phrase "evidence claim or precondition" appears once in
  `docs/PUBLIC_LAB_SPEC.md`. No change.
- `provenance.go` retains a final `refs/heads/` URL check that is unreachable
  after `immutableRecordRevision`; it was left in place as harmless defense in
  depth.

## Hosted CI decision

`make public-lab-check` is not added to `ci.yml`. The Go tests it runs already
execute in the hosted `go test ./...` and `go test -race ./...` jobs, and the
new drift-guard test now closes the one gap that mattered, the checked
artifacts diverging from source. The remaining shell-level content is
`actionlint` on the generated workflows, the artifact negative tests, and the
marker source audit; `make public-lab-syscall-audit` additionally needs Linux
`strace`. `actionlint` and `strace` are not preinstalled on hosted runners and
would require a downloaded third-party binary, and the syscall audit observes
a fixed `printf` whose exact bytes the Go tests already pin. These therefore
remain documented Linux-local gates, recorded in `lab/public/README.md`, and
this record is the evidence that they passed for the batch.

## Files changed by this audit

Tracked: `.gitattributes`, `TASKS.md`, `docs/IMPLEMENTATION_STATUS.md`,
`docs/PUBLIC_LAB_SPEC.md`.

Untracked batch files edited: `internal/publiclab/gitboundary.go`,
`internal/publiclab/gitboundary_test.go`, `internal/publiclab/bundle.go`,
`tools/publiclab/main.go`, `tools/publiclab/main_test.go`,
`lab/public/README.md`, `scripts/public-lab-artifacts.sh`.

Untracked batch files added: `internal/publiclab/checked_artifact_test.go`
and this record.

Nothing under `lab/public/source` or `lab/public/artifacts` changed.

## Artifact identity

| File | Bytes | SHA-256 | Mode |
| --- | ---: | --- | ---: |
| `lab/public/artifacts/cirewind-lab.bundle` | 39,656 | `16f41eac01532e764d2ed0518db2a7dafcbcd3bd6bcea5f8e4e9e23385667b99` | `0644` |
| `lab/public/artifacts/object-manifest.json` | 20,838 | `199f914b9fbc6aaf1d5cf8ed41f8734f594d072c8475d22725855d527aa682da` | `0644` |

Object IDs remain G `574b978aa906a8651d4bc94165a80ad78bc2bb68`, A
`afb628b57608bae0397cdb0d2201103c4e6a1f2e`, B
`941f217e2d8b8c9bce64cedfcc07a0dd749eb831`, W
`71c0379d1ab6082c9bcd5e5a374704d537b0b520`, R
`f7442b6ef0fe635a6a5c319ad3f52d019b8c5027`, and I
`a9ca057fb991b5860c48c855d506e36eab07c221`. `make public-lab-check`
regenerated both artifacts and compared them byte for byte with the checked
files.

## Commands and results

All commands ran on the final audited bytes from the repository root with
`GOTOOLCHAIN=go1.25.13`.

| Command | Result |
| --- | --- |
| `git diff --check` | PASS |
| `sha256sum lab/public/artifacts/*` | PASS, identities above |
| `make PUBLIC_LAB_REQUIRE_ACTIONLINT=1 public-lab-check` | PASS, 26 s |
| `make public-lab-syscall-audit` | PASS |
| `go test ./internal/publiclab ./tools/publiclab -count=1` | PASS |
| `go vet ./internal/publiclab ./tools/publiclab` | PASS |
| `go test -race ./internal/publiclab ./tools/publiclab -count=1` | PASS, 110 s |
| `go test ./... -count=1` | PASS, 71 s |
| `go vet ./...` | PASS |
| `go test -race ./... -count=1` | PASS, 179 s |
| `go mod verify` | PASS |
| `go mod tidy -diff` | PASS, empty diff |
| `shellcheck` on the three public-lab scripts | PASS |
| `gitleaks dir --no-banner --redact --exit-code 1 .` | PASS, no leaks |
| `make preflight` | PASS, 505 s |
| `gofmt -l internal/publiclab tools/publiclab` | PASS, no output |

Tool versions: Go `1.25.13` (`linux/amd64`, selected through the `go.mod`
toolchain pin), Git `2.43.0`, actionlint `1.7.12`, ShellCheck `0.9.0`,
strace `6.8`, gitleaks (locally built; no version string).

No AWS resource was needed or launched. Infrastructure cost attributable to
this audit is `$0.00`.

## Not validated locally

- `git ls-remote` peeled-ref output against GitHub.com. The readback requires
  exactly six refs including both `^{}` entries, which local bare remotes
  return only when the peeled patterns are requested explicitly. GitHub is
  expected to peel, and a difference fails closed, but this is untested until
  `LAB-PUBLIC-006`.
- Authenticated SSH push through the isolated boundary against GitHub.com.
- GitHub-hosted preparation of marker B by the exact `skipped.yml` grammar
  (`LAB-PUBLIC-003`).
- Anything outside Linux amd64 for the shell-level gates. The hosted CI
  outcome for the Go suite on all six targets is recorded in the follow-up
  section below.

## Gates intentionally still open

`LAB-PUBLIC-003`, `LAB-PUBLIC-006` through `LAB-PUBLIC-011`, and every
maintainer, publication, outside-human, and final v0.2 release gate remain
open. No task status changed in `TASKS.md`.

## Hosted CI run and Windows follow-up

The audited batch was committed as `d7075197aef373a1efe456f8e86554a8c79ae3b7`
with a DCO sign-off, pushed only to `refs/heads/lab/public-a-b-a-source`, and
exercised by the authorized `workflow_dispatch` run
[`33705754157`](https://github.com/torjan0/cirewind/actions/runs/33705754157).
`main` was not changed and no pull request was opened.

| Job | Result |
| --- | --- |
| Test (linux-amd64), Test (linux-arm64) | success |
| Test (darwin-amd64), Test (darwin-arm64) | success |
| Race detector | success |
| Reachable vulnerability scan | success |
| Incident-pack review contract | success |
| Reproducible release packaging contract | success |
| Test (windows-amd64) | failure |
| Test (windows-arm64) | failure |

Only `internal/publiclab` failed, and only on Windows. Two causes, neither in
a policy, artifact, schema, or record contract:

1. **Null-device spelling.** The tag-control Git boundary and the bundle test
   helper passed `os.DevNull` (`NUL` on Windows) through `GIT_CONFIG_SYSTEM`
   and `GIT_CONFIG_GLOBAL`, and the boundary hooks path used the same value.
   The Git for Windows build on the arm64 runner rejects that with
   `unable to access 'NUL': Invalid argument`, so every Git-backed test there
   failed before reaching its assertion; the amd64 build accepted it. Git for
   Windows translates the literal `/dev/null` to its null device, so the
   boundary and helper now use that spelling everywhere.
2. **POSIX-only fixture paths.** The provenance test supplied
   `/synthetic/absolute/remote.git`, which is not an absolute path on Windows
   and was correctly rejected by the test-only local-remote policy; the
   reproduction cross-binding test and two schema-directory helpers
   concatenated paths with forward slashes, which the clean-path reader
   rejects on Windows. All now use `filepath.Join`.

Follow-up commit files: `internal/publiclab/gitboundary.go`,
`internal/publiclab/bundle_test.go`, `internal/publiclab/provenance_test.go`,
`internal/publiclab/records_test.go`. Artifact identities are unchanged.

| Follow-up check | Result |
| --- | --- |
| `gofmt -l internal/publiclab tools/publiclab` | PASS, no output |
| `go vet` for linux, windows/amd64, and windows/arm64 targets | PASS |
| `go test -c` for windows/amd64 and windows/arm64 test binaries | PASS, compiles |
| `go test ./internal/publiclab ./tools/publiclab -count=1` | PASS |
| `go test -race ./internal/publiclab ./tools/publiclab -count=1` | PASS, 106 s |
| `go test ./... -count=1`, `go vet ./...`, `go test -race ./... -count=1` | PASS, 40 s, vet PASS, race 180 s |
| `make PUBLIC_LAB_REQUIRE_ACTIONLINT=1 public-lab-check` | PASS, 13 s |
| `git diff --check` | PASS |

The Windows runtime behavior of the fix is validated only by the next hosted
run on the branch; no Windows host is available locally.
