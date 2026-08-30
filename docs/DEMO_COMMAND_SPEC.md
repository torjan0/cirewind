# `cirewind demo` command specification

Status: accepted v0.2 command contract as of 2026-08-22.

This specification is normative for the v0.2 synthetic demonstration. It does
not change incident matching, finding derivation, or the meaning of manifest
integrity. It does require versioned v0.2 case-file and graph-projection
contracts so the new SVG can be reproduced without weakening v0.1 verification
compatibility; the SQLite schema remains v1.

## Purpose

`cirewind demo` gives a new user a credential-free proof of the complete offline
case path using unmistakably synthetic evidence. It must demonstrate the
A-to-B-to-A temporal distinction, downloaded-versus-executed separation,
credential-capability language, evidence gaps, contradictions, deterministic
reporting, and manifest verification without requiring a source checkout.

It is not a live investigation, a benchmark of GitHub collection, a real
incident, or proof that every GitHub-hosted grammar is supported.

## CLI contract

```text
Usage:
  cirewind demo --out CASE_DIR

Generates and verifies a deterministic synthetic case without credentials or
network access. The destination must not already exist. No raw logs are retained.
```

The only v0.2 flag is:

| Flag | Required | Meaning |
|---|---:|---|
| `--out PATH` | yes | New case output directory. It is resolved and protected by the existing case-file path policy. |

The command accepts no positional arguments and no `--force`, `--raw-logs`,
`--incident`, `--archive`, `--fixture`, token, network, browser-launch, clock, or
count-override flag. Hidden test-only flags are prohibited; deterministic time is
part of the embedded bundle contract.

Exit codes follow the root CLI contract:

| Exit | Meaning |
|---:|---|
| `0` | Case generated, internal oracle passed, and manifest verified. |
| `1` | Validation, derivation, generation, oracle, or verification failed. |
| `2` | Invalid command syntax or output option. |
| `130` | Context cancellation or deadline. |

`cirewind help demo` and `cirewind demo --help` must print the same command
contract. Root help must identify demo as offline and credential-free.

## Embedded input architecture

The executable contains one immutable, versioned demonstration bundle:

```text
DemoBundle
├── fixture version
├── normalized compact archive snapshot factory
├── synthetic incident-pack YAML bytes
├── fixed analysis time
├── expected finding counts
├── expected exposure counts
└── expected final file names
```

The current `internal/demodata.Snapshot` factory is the baseline and is extended
through its existing typed facts, not replaced by precomputed findings. It
creates a fresh normalized snapshot for every invocation and already fixes
source event and collection time at `2026-08-19T10:30:00Z`. The v0.2 bundle
fixes replay analysis time at `2026-08-20T00:00:00Z`.

The v0.1 baseline snapshot has ten findings but does not contain a paired,
same-run exact restored-A attempt. The v0.2 fixture changes the synthetic pack
and snapshot without changing matching semantics:

1. Add a path-isolated `paired-rerun-action` component with exactly one affected
   `action-commit` indicator B and one exact known-good commit A. It has no
   digest or second mutable-ref indicator that could independently emit another
   no-match for the same observation.
2. Move—not copy—the existing run 1001 attempt-1 lifecycle observation to that
   component. This replaces the old component's executed proposition, so the
   overall `CONFIRMED_EXECUTED` count remains one; the old component still has
   its existing downloaded-only proposition.
3. Add only run 1001 attempt 2 and its distinct job with complete exact runtime
   A evidence after `v1` is restored. Keep one coherent run/workflow fact; do
   not call a helper that emits conflicting duplicate run metadata merely to add
   the attempt.
4. Move the existing pending `production-fixture` environment fact off run 1001
   attempt 1, whose affected Action lifecycle demonstrably started, and attach it
   to the run 1005 mutable-window subject. Make run 1005's run, attempt, and sole
   job a coherent nonterminal waiting state with empty conclusions; the job is
   explicitly unstarted and has no lifecycle observation while retaining only
   its historical mutable declaration. Do not leave a terminal-success parent
   run or attempt around a waiting child job. The environment remains targeted
   with its gate not crossed and has no environment-secret eligibility. The v2
   graph may show that target as evidence-linked context in the run 1005 finding
   lane, but it does not add a potential credential/resource exposure to the
   finding or change the v1 projection.

Both attempts retain distinct job-execution identities. The A attempt may
produce exactly one `NO_MATCH_CONFIRMED` only if every coverage predicate
required by the canonical no-match rule is closed. A table-driven pre-freeze
derivation test must prove the full per-indicator result set—not merely “at least
one no-match.” If any count differs, implementation stops to revise and review
the oracle rather than forcing a negative conclusion or claiming the embedded
demo proves A-to-B-to-A.

A cross-fact fixture validator rejects `JobStarted: false` on any job that also
has an Action lifecycle start/completion or a started/completed job status. For
a run with one pending gated job, it also rejects a terminal-success run or
attempt, a nonempty conclusion on the run/attempt/job, and disagreement among
their nonterminal statuses. It rejects a pending/not-crossed gate paired with
environment-secret eligibility as well. This validation is part of the oracle,
not merely visual styling. The implementation must use status spellings already
accepted by GitHub normalization; it must not invent a new domain enum or alter
collection semantics merely to satisfy this fixture.

The v0.2 demo also removes every empty credential basis. The affected execution
contains runtime-observed effective `contents: write` and `id-token: write`
permission facts; the direct fake-secret pass uses
`historical-definition-flow`. `OIDC_MINTING_CAPABILITY` is derived from the
runtime-observed `id-token: write` fact under the versioned OIDC capability rule.
Its graph relationship remains `INFERENCE` with that rule even though the
indispensable permission was runtime-observed. It never creates a cloud-provider,
trust-policy, role-assumption, token-request, or token-exchange claim. Empty or
unknown basis fails the v2 demo oracle instead of receiving a renderer default.

Because this adds a component, indicator, known-good identity, attempt, and
expected finding, the synthetic incident pack is published as immutable
`metadata.packVersion: 2.0.0`, its source revision becomes `fixture-v2`, and the
embedded bundle/oracle identifier becomes `cirewind.demo/v2`. Original and
canonical hashes and every generated fixture/golden are regenerated. The
existing `1.0.0` meaning is never edited in place or presented as the v0.2
oracle.

The pack remains declarative YAML. A copy colocated below `internal/demodata` is
embedded with Go's compile-time embedding facility and passed through the same
strict incident validator as an external pack. The human-readable
`incidents/synthetic/mutable-tag.yaml` remains checked in and included in release
source/distribution material. A blocking test requires the public and embedded
bytes, original SHA-256, and canonical SHA-256 to match. This deliberate
duplication is necessary because an embedded file cannot be selected through a
parent-directory path.

No incident field controls an output path, clock, expected count, network
destination, template, or executable behavior.

## In-process execution sequence

The command executes exactly this sequence:

1. Parse `--out` and check context cancellation.
2. Construct a fresh embedded snapshot.
3. Validate the embedded YAML with the production incident-pack parser,
   canonicalizer, schema, and semantic validator.
4. Derive findings in replay mode using the production matcher and the fixed
   analysis time.
5. Validate the derived case and compare it with the versioned synthetic oracle.
6. Generate the case through the production case generator, including
   `graph.json`, `graph.svg`, report, SQLite database, evidence ledger, and
   metadata.
7. Verify `manifest.sha256` through the production verifier.
8. Print a terminal-safe synthetic summary and paths.

Implementation should extract one shared snapshot-to-case helper used by replay
and demo. It must accept a normalized snapshot, validated pack, analysis time,
derivation mode, output path, and raw-source policy. It must not duplicate
matching rules or recursively invoke the CLI.

The command must not:

- create a temporary archive merely to deserialize its own in-memory snapshot;
- open a socket, initialize a GitHub client, resolve authentication, or honor
  proxy configuration;
- execute a child process or launch a browser;
- read the current working directory, Git repository, home directory, public
  pack path, or user configuration to obtain demo inputs;
- persist an intermediate archive or raw log;
- mutate global clocks, environment variables, or package state.

Temporary private staging created by the existing case builder is permitted and
must be removed on failure or cancellation. Neither its randomized
`.cirewind-case-*` basename nor its absolute parent path may appear in CLI
diagnostics; failures retain only a safe operational category while preserving
internal error causality for programmatic checks.

## Determinism contract

For identical executable version, embedded bundle version, platform-independent
SQLite encoding contract, and output-path-independent content, two successful
runs to different destinations produce byte-identical material files and
identical manifests.

Determinism requires:

- fixed event, collection, and analysis times from the bundle;
- stable finding, evidence, graph, row, JSON object, CSV row, Markdown, SVG, and
  manifest order;
- deterministic case/finding/evidence IDs already derived from canonical inputs;
- no current time, hostname, username, absolute output path, temporary path,
  random value, locale, timezone, map iteration order, or process ID in output;
- no SQLite field whose byte representation varies across supported platforms;
- no HTML/SVG coordinate derived from browser or platform font measurement;
- a versioned fixture/oracle identifier in test diagnostics.

If whole-file SQLite bytes cannot be made cross-platform identical while the
logical database is identical, the implementation must stop and document a
narrower byte-determinism claim before release. It may not silently exclude
`case.db` from the manifest or comparison. Same-platform repeated output remains
a minimum blocking requirement.

## Overwrite and filesystem policy

- `--out` is required and must not resolve to a filesystem root or home root.
- If the final path exists as any entry—file, directory, or symlink—the command
  fails before modifying it.
- Existing ancestors are checked under the current symlink/canonicalization
  policy. Source-derived names never become paths.
- The case is built in an owner-only sibling staging directory and published
  atomically only after all required files validate.
- Files use owner-only permissions where supported; the directory uses owner-only
  permissions under the existing case policy.
- Concurrent attempts to publish the same output yield at most one complete
  case. The loser fails without altering the winner.
- Cancellation removes only CIRewind's private staging path. It never recursively
  removes the requested destination or an unrelated path.
- v0.2 has no overwrite or cleanup flag.

## Output contract

Successful output contains exactly:

```text
affected-runs.csv
case.db
collection-metadata.json
evidence.jsonl
findings.json
graph.json
graph.svg
report.html
summary.md
manifest.sha256
```

`raw/` is absent. All output is marked synthetic in case metadata, report, SVG
description, Markdown summary, and terminal summary. Coverage remains visibly
partial because the fixture deliberately contains a missing-evidence case.

The manifest covers all nine material files other than itself and the verifier
rejects a changed, missing, extra, symlinked, or non-regular case entry under the
strict v0.2 case contract. Successful generation is not reported until verification
passes.

## Versioned synthetic result oracle

The existing v0.1 baseline has ten findings with zero
`NO_MATCH_CONFIRMED`. The intended v0.2 fixture adds the closed, exact restored-A
attempt above. The release oracle therefore has exactly eleven findings:

| Canonical state | Count |
|---|---:|
| `CONFIRMED_EXECUTED` | 1 |
| `CONFIRMED_DOWNLOADED` | 1 |
| `CONFIRMED_CALLED_WORKFLOW` | 1 |
| `DECLARED_AT_RUN_SHA` | 1 |
| `RUN_IN_WINDOW_MUTABLE_REF` | 1 |
| `POTENTIAL_TRANSITIVE` | 2 |
| `CURRENT_REFERENCE_ONLY` | 1 |
| `NO_MATCH_CONFIRMED` | 1 |
| `UNKNOWN_EVIDENCE_GAP` | 1 |
| `CONTRADICTORY_EVIDENCE` | 1 |
| **Total** | **11** |

The first-screen synthetic context has exactly:

- one affected job with write-capable `GITHUB_TOKEN` permission;
- one named-secret flow to an affected step;
- one affected job with `OIDC_MINTING_CAPABILITY`;
- one affected job on a self-hosted runner;
- one deployment observed after an affected step;
- one environment that was targeted but whose gate was not crossed.

These are relationship/capability counts. The oracle must reject language or
edges that claim a secret value was read, a cloud role was assumed, a runner was
persistent, an environment secret was eligible without a crossed gate, or the
later deployment was attacker-caused.

The `NO_MATCH_CONFIRMED` row is a release acceptance predicate, not permission
to synthesize safety. Its finding must bind the restored-A attempt and cite the
exact known-good runtime evidence plus mechanically complete coverage. Changing
the fixture or derivation rules requires an explicit oracle-version change,
review of all ten states, regeneration of the sample site, and a README/count
consistency update. A generic total-only assertion is insufficient.

## Verification and terminal output

Successful output is concise and deterministic except for the sanitized path:

```text
SYNTHETIC DEMO — PARTIAL COVERAGE
findings: 11
CONFIRMED_EXECUTED: 1
CONFIRMED_DOWNLOADED: 1
RUN_IN_WINDOW_MUTABLE_REF: 1
UNKNOWN_EVIDENCE_GAP: 1
NO_MATCH_CONFIRMED: 1
manifest: verified
network requests: 0
case: PATH
report: PATH/report.html
```

The existing complete canonical count summary may print additional states, but
state labels and count order must be stable. The first line must say both
`SYNTHETIC` and `PARTIAL COVERAGE`. Output paths and all errors pass through the
terminal sanitizer. The command does not print embedded source bytes, fake
secret names unnecessarily, environment contents, tokens, or absolute temporary
paths.

Manifest verification supports integrity checking only. Demo and report text
must not describe it as authenticity, signing, independent verification, legal
certification, or chain-of-custody certification.

## Compatibility with `make demo`

The developer interface remains:

```text
make demo
make demo DEMO_OUT=/new/case/path
```

`scripts/demo.sh OUTPUT BINARY` remains accepted because browser and release
automation use its positional interface. In v0.2 it becomes a thin fail-fast
wrapper around:

```text
BINARY demo --out OUTPUT
```

The command owns pack validation, case generation, exact count/oracle checks,
output-file checks, and manifest verification. The shell wrapper must not become
a second semantic implementation. It may independently invoke `verify` after
the command as a release smoke assertion, but it must not maintain a second list
of finding predicates.

Archive import and replay retain their independent tests. First-class demo does
not justify deleting `archive --import-fixture synthetic`, the public synthetic
pack, or replay's fixed-clock fixture support while tests or qualification still
use them.

## Performance target

- `T_demo` starts immediately before installed-binary invocation and stops only
  after every required case output exists and the command's case-manifest
  verification succeeds.
- `T_total` starts immediately before the documented installation command and
  stops at the same successful case-manifest verification point.
- Launch-blocking hosts are Ubuntu 24.04 amd64 with 2 vCPU and 4 GiB RAM, and
  macOS 15 arm64 with Homebrew already installed. Windows 11 amd64 is measured
  for information and cannot independently block v0.2.
- Run five clean trials per launch-blocking lane, each with a new output
  directory and no CIRewind cache. For five values, p50 is the third value after
  ascending sort.
- Required `T_demo`: p50 at most 15 seconds and no individual run over 30
  seconds.
- Required `T_total`: p50 at most 120 seconds and no individual run over 180
  seconds.
- Browser opening is a separate smoke test and is outside both timers.
- Peak RSS and output size are recorded on reference hosts. The demo must remain
  comfortably below general replay/case limits; an initial budget is 256 MiB RSS
  and 32 MiB total output, subject to measurement and tightening.

Tests must use monotonic duration measurement. A performance miss never changes
fixture semantics or skips verification. Network download variability is
reported separately from binary execution. Record all five raw values, host and
architecture, allocated CPU/memory, acquisition lane, tool versions, and command
transcript; do not publish only the median.

## Required tests

### CLI and filesystem

- Root help and both demo help forms are exact golden tests.
- Missing `--out`, empty path, positional input, unknown flag, and forbidden
  flag return usage errors.
- Existing file, directory, symlink, root, home root, hostile parent, and
  concurrent destination cases leave existing content unchanged.
- Context cancellation removes private staging and returns the established code.
- Terminal-control, newline, bidi, and oversized path diagnostics are inert and
  bounded.
- An injected post-builder error containing the private staging path reaches CLI
  stderr only as a safe path-withheld operational diagnostic.
- A per-call GitHub-client factory spy observes zero client constructions during
  `demo`; no package-global hook is permitted.

### Embedded bundle and semantics

- Embedded and public pack bytes and both hashes match.
- Pack validation uses production validation and makes no outbound request.
- Two separately constructed snapshots normalize identically and do not share
  mutable storage.
- Every canonical state count matches the table.
- The paired rerun uses one run ID, distinct attempt/job execution identities,
  exact B evidence on attempt 1, and exact known-good A evidence plus closed
  coverage on attempt 2; present-day ref state is not evidence for either.
- The downloaded/skipped finding has no execution observation or
  `STEP_EXECUTED_ACTION` edge.
- Attempts remain distinct; present-day `v1 -> A` does not alter historical B.
- Missing logs produce `UNKNOWN_EVIDENCE_GAP`, never `NO_MATCH_CONFIRMED`.
- Credential, OIDC, environment, runner, and resource statements preserve all
  mandatory invariants.
- Every finding cites evidence IDs or its explicit gap evidence record.

### Offline and determinism

- Run the installed binary from an empty, unrelated current directory with no
  repository checkout.
- Unset token variables and set deliberately unusable proxy variables; output is
  unchanged.
- On supported Unix CI, a syscall audit rejects socket creation/connect and
  child `exec` during the command. Equivalent platform-native inspection or a
  deny-all network sandbox is used elsewhere where available.
- A transport spy at the GitHub client boundary records zero construction and
  zero calls.
- Two outputs compare byte-for-byte, including `case.db`, and manifests match.
- Reversed input-fact order produces the same output.
- Supported release binaries smoke-test demo outside their extracted source
  layout.
- The command passes with no browser, Docker, GitHub CLI, Git, or shell available
  in `PATH`.

### Output and presentation

- Exact file set matches this specification and `raw/` is absent.
- Standalone verification succeeds; one-byte mutation and removal fail.
- Report, SVG, JSON, CSV, Markdown, SQLite, ledger, and terminal totals agree.
- Browser audit loads the report offline and checks CSP, no remote requests,
  hostile-label safety, graph visibility, and partial coverage.
- `graph.svg` passes the temporal-path security and accessibility suite.

## Failure model

| Failure | Required behavior |
|---|---|
| Embedded pack fails validation | Abort before output publication; report bounded internal bundle failure. |
| Synthetic oracle mismatch | Abort; identify the mismatched state/count without publishing a case. |
| Case generation fails | Remove private staging; preserve any existing target; do not expose the private staging basename or absolute path in CLI diagnostics. |
| Manifest verification fails | Verify the complete private staging case before atomic publication. On failure, abort, remove only owned staging, leave the requested destination absent, and never print a verified-case message. Post-publication verification remains a defense-in-depth repeat, not the first check. |
| SVG limit reached | Generate an explicit bounded omission notice; never silently omit material relationships or alter findings. |
| Context canceled | Stop scheduling work, close stores, remove private staging, return cancellation. |
| Unsupported platform permission semantics | Generate under documented safe fallback and record it; never claim Unix mode enforcement. |

## Implementation order

1. Define the bundle/oracle API and embedded/public drift guard.
2. Extract the production snapshot-to-case helper without behavior changes.
3. Add parser, help, dispatch, and terminal output.
4. Add command unit/integration/offline/determinism tests.
5. Convert `scripts/demo.sh` to a thin wrapper and keep `make demo` stable.
6. Add `graph.svg` to the v0.2 fixed case contract when the renderer lands,
   while retaining verification compatibility for existing v0.1 cases.
7. Add release-binary, clean-directory, browser, syscall, and performance gates.

The demo command is complete only when all seven steps and the final `graph.svg`
contract pass. A command that merely imports a fixture or prints placeholder
counts is not complete.
