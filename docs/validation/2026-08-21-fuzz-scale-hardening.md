# Fuzz, hostile-input, and relational scale qualification — 2026-08-21

Status: bounded local qualification with concrete defects corrected. This does
not complete the broader `SEC-002`, `PERF-001`, or `PERF-002` research tasks,
but it establishes the measured experimental-v0.1 envelope accepted in
[`ADR 0011`](../adr/0011-experimental-v0-1-qualification-envelope.md).

## Scope and reference environment

The qualification used generated/synthetic data only. No GitHub credential,
cloud credential, production log, secret value, or network-backed test was
provided to these commands. Fuzz corpora, Go caches, temporary build files, and
large databases were kept on an external scratch volume, outside the repository
and the system `/tmp` filesystem.

Reference host:

| Property | Value |
| --- | --- |
| Kernel/architecture | Linux 6.8.0-100-generic, x86_64 |
| Processor | Intel Core i7-7700, 4 cores / 8 logical CPUs |
| Memory | 15 GiB |
| Go | 1.25.13 |
| SQLite | 3.53.3 through `modernc.org/sqlite` |
| SQLite writer policy | one connection, WAL, `synchronous=FULL`, foreign keys on |
| Generator seed | `20260821` |

The repeatable environment prefix was:

```sh
export QUAL_ROOT=/path/on/a/non-workspace-volume/cirewind-fuzz-scale
mkdir -p "$QUAL_ROOT/tmp" "$QUAL_ROOT/gocache" "$QUAL_ROOT/results"
export TMPDIR="$QUAL_ROOT/tmp"
export GOTMPDIR="$QUAL_ROOT/tmp"
export GOCACHE="$QUAL_ROOT/gocache"
export GOTOOLCHAIN=go1.25.13
export GOFLAGS=-mod=readonly
```

The volume had more than 400 GiB free at the start. The repository received no
generated database, raw log, fuzz cache, or case bundle from these runs.

## Fuzz campaigns

Each command used Go's native fuzz driver and four workers unless the table says
otherwise:

```sh
/usr/bin/time -v go test ./internal/PACKAGE -run '^$' \
  -fuzz '^TARGET$' -fuzztime=DURATION -parallel=4
```

`Max RSS` is the maximum resident set reported by `/usr/bin/time` for the Go
test/build process tree. It is useful for regression comparison, but is not an
isolated parser steady-state measurement because compilation/linking and fuzz
worker processes are included.

| Package / target | Budget | Executions | New interesting inputs | Max RSS (KiB) | Result |
| --- | ---: | ---: | ---: | ---: | --- |
| `logparse/FuzzReadZIPHostileBoundary` | 60 s | 1,911,071 | not separately retained | 231,716 | PASS |
| `logparse/FuzzParse` | 60 s | 3,314,721 | not separately retained | 125,768 | PASS |
| `incident/FuzzValidate` | 60 s | 1,321,706 | not separately retained | 115,712 | PASS |
| `workflow/FuzzParseWorkflow` | 60 s | 1,206,610 | not separately retained | 112,128 | PASS |
| `sanitize/FuzzTerminalAndCSVCell` | 30 s | 2,534,035 | not separately retained | 87,296 | PASS |
| `githubapi/FuzzResponseSanitizers` | 30 s | 170,744 | not separately retained | 207,976 | PASS |
| `githubapi/FuzzDecodeGitHubJSON` | 30 s | 754,654 | not separately retained | 217,216 | PASS |
| `archive/FuzzDecodeSnapshot` | 30 s | 924,775 | not separately retained | 920,976 | PASS |
| `graph/FuzzNormalizeGraph` | 30 s | 1,880,994 | not separately retained | 114,432 | PASS |
| `logparse/FuzzParseActionLifecycleIdentity` | 30 s | 1,948,138 | not separately retained | 130,856 | PASS |
| `workflow/FuzzParseActionMetadata` | 30 s | 1,144,343 | not separately retained | 112,128 | PASS |
| enhanced `logparse/FuzzParse` semantic assertion | 30 s | 1,320,793 | not separately retained | 144,912 | PASS |
| ZIP target, two workers | 3 min | 4,315,865 | 32 (71 total target corpus) | 120,916 | PASS |

The extended ZIP campaign consumed 3:01.41 wall time, 381.04 seconds user CPU,
and 24.93 seconds system CPU. It exercised 4,315,865 inputs without a crash,
path escape, out-of-budget accepted entry, or invalid accepted entry identity.

After all campaigns, the external fuzz cache contained 1,909 corpus objects,
146,785 logical bytes (7,979,008 allocated bytes), with this deterministic
path-and-content listing hash:

```text
sha256:3459d581b0df009c94d8b04f1bd2f1c5e6a810e84e5adfdff9a64ff2e17d2032
```

The target distribution was:

| Target | Corpus objects |
| --- | ---: |
| `archive/FuzzDecodeSnapshot` | 63 |
| `githubapi/FuzzDecodeGitHubJSON` | 264 |
| `githubapi/FuzzResponseSanitizers` | 29 |
| `graph/FuzzNormalizeGraph` | 225 |
| `incident/FuzzValidate` | 168 |
| `logparse/FuzzParse` | 254 |
| `logparse/FuzzParseActionLifecycleIdentity` | 195 |
| `logparse/FuzzReadZIPHostileBoundary` | 61 |
| `sanitize/FuzzTerminalAndCSVCell` | 173 |
| `workflow/FuzzParseActionMetadata` | 257 |
| `workflow/FuzzParseWorkflow` | 220 |

Go's fuzz command did not expose a reproducible mutation RNG seed. The checked-in
seed inputs and the final corpus hash are therefore the reproducibility anchors;
the execution counts are observations, not deterministic expectations.

### Semantic assertions added

The campaigns now assert more than absence of a panic:

- arbitrary setup-log bytes cannot create lifecycle-start or lifecycle-complete
  observations;
- lifecycle observations cannot escape the exact expected Action, repository,
  run, attempt, job, step, or lifecycle phase supplied by trusted structure;
- application `run:`-step lookalikes cannot become Action lifecycle evidence;
- an accepted ZIP entry is canonical, unique under case folding, regular,
  bounded by declared/extracted size, and within the exact compression ratio;
- terminal/diagnostic output is deterministic, valid UTF-8, bounded in bytes,
  and contains no retained control or authentication sentinel;
- GitHub JSON, incident packs, workflows, Action metadata, archive snapshots,
  and graph normalization have deterministic acceptance and diagnostics; and
- accepted archive/graph structures retain their validation invariants.

These checks preserve the product rule that only a structurally correlated
lifecycle start can independently support `CONFIRMED_EXECUTED`.

## Defects found and corrected

1. Diagnostic truncation checked the byte ceiling before appending a rendered
   rune or escape. A multibyte rune or escaped control could therefore make the
   result exceed 4,096 bytes. Rendering is now atomic against the remaining
   byte budget, with a boundary regression for UTF-8, ESC, and bidi controls.
2. The terminal sanitizer could append the three-byte Unicode replacement rune
   when only one or two bytes remained. It now stops before exceeding the exact
   caller budget and has an invalid-UTF-8 regression.
3. ZIP compression-ratio enforcement used integer division. At an 8:1 limit,
   an 801:100 entry was incorrectly accepted because `801/100` truncated to 8.
   The comparison now uses quotient and remainder without multiplication
   overflow. Zero-size and `uint64` boundary regressions are included.
4. Finding-centered graph lookups by source or target had no supporting index
   and degraded to a projection-table scan. The schema now includes
   `(analysis_id, source_id)` and `(analysis_id, target_id)` indexes. A query-plan
   regression fails if either lookup stops using its index.

No fuzz input produced a false `CONFIRMED_EXECUTED` conclusion. The fuzzers
exercise parser/domain boundaries; they do not themselves derive an entire
finding or prove every downstream presentation encoder.

## Cancellation, race, and deterministic regressions

Cancellation regressions cover sustained text readers and pre-cancelled ZIP
iteration. The parser stops with `context.Canceled`; the ZIP handler is not
entered after pre-cancellation.

The following targeted race suite passed:

```sh
go test -race \
  ./internal/logparse ./internal/incident ./internal/workflow \
  ./internal/githubapi ./internal/archive ./internal/graph \
  ./internal/sanitize ./internal/store ./internal/qualification -count=1
```

Observed totals were 67.43 seconds wall time and 822,248 KiB process-tree max
RSS. The following also passed after the changes:

```sh
go test ./... -count=1
go vet ./...
```

## Aggregate streaming-log qualification

`TestAggregateLogParserQualification` generated one bounded 1 MiB setup-log
chunk and repeatedly streamed it through the production parser. It did not
materialize a 5 or 50 GiB input and asserted that no lifecycle observation was
created from setup evidence.

| Volume | Parser wall | Process wall | User CPU | System CPU | Max RSS | HeapAlloc after run | HeapSys after run | Result |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| 5,368,709,120 bytes (5 GiB) | 15.349 s | 15.66 s | 16.65 s | 0.45 s | 147,584 KiB | 2,498,080 B | 11,960,320 B | PASS |
| 53,687,091,200 bytes (50 GiB) | 164.091 s | 164.48 s | 170.26 s | 4.29 s | 148,480 KiB | 3,673,008 B | 16,154,624 B | PASS |

Ten times the aggregate bytes required 10.69 times the parser wall time and
10.21 times the combined user/system CPU, while process RSS stayed within 896
KiB of the small observation. Current heap remained in the low MiB range. Total
allocation grew with processed bytes, as expected for repeated parsing, while
live memory did not. This satisfies the documented 15× CPU/live-memory
objective for this safe repetitive setup-log workload only.

The command was:

```sh
CIREWIND_LOG_SCALE_BYTES=5368709120 \
  /usr/bin/time -v go test ./internal/qualification \
  -run '^TestAggregateLogParserQualification$' -count=1 -v

CIREWIND_LOG_SCALE_BYTES=53687091200 \
  /usr/bin/time -v go test ./internal/qualification \
  -run '^TestAggregateLogParserQualification$' -count=1 -v
```

## Relational store qualification

`TestSyntheticStoreScaleQualification` uses the real migration schema and
SQLite integrity/finalization path. It inserts repositories, runs, separate
attempts/jobs, compact archive facts, and a deterministic 10% subset of
findings, revisions, coverage, evidence links, and graph edges. It then runs
`EXPLAIN QUERY PLAN` plus 100 iterations for each critical lookup and rejects a
full scan of the principal table.

It is intentionally a relational-storage harness: inserts are generated
directly through parameterized SQL. It does **not** exercise GitHub collection,
snapshot decoding, incident matching, replay, HTML report generation, or live
request accounting.

| Profile | Repositories | Runs | Attempts/jobs | DB bytes | Insert wall | Test wall | User CPU | System CPU | Max RSS | Result |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| Small | 100 | 10,000 | 25,000 | 32,555,008 | 6.002 s | 7.22 s | 4.00 s | 1.67 s | 152,448 KiB | PASS |
| Medium | 1,000 | 100,000 | 300,000 | 389,857,280 | 162.366 s | 173.68 s | 46.32 s | 21.42 s | 146,048 KiB | PASS |
| Large | 10,000 | 1,000,000 | 3,000,000 target | 2,921,562,112 interrupted | not reached | 2:00:03 | 298.23 s | 199.26 s | 147,200 KiB | **TIMEOUT** |

Medium has 10× the repositories/runs and 12× the executions represented in the
small profile. CPU grew 11.95× and database bytes grew 11.98×, within the
documented 15× gate for equivalent data. Wall time grew about 24× because the
single-writer harness intentionally commits 10,000-row chunks under
`synchronous=FULL`; it is not a throughput promise. No SQLite cache-size override
was applied.

All checked lookup plans used bounded indexes:

- attempt-scoped findings: `idx_findings_subject`;
- finding revisions: `idx_revisions_finding`;
- evidence and coverage links: their primary-key autoindexes;
- finding-centered graph source/target: `idx_graph_source` and
  `idx_graph_target`; and
- archive subject identity: `idx_archive_facts_subject`.

The 100-iteration lookup groups took approximately 2.4–4.0 milliseconds on both
small and medium databases. This demonstrates point-lookup plan stability; it
does not qualify broad report aggregation or browser rendering.

The large profile did not complete. The Go test's fixed two-hour alarm fired
while SQLite was performing `fsync` during a 10,000-row transaction commit in
the attempt/job/fact population loop. It had not begun the query-plan,
integrity-check, or final WAL-checkpoint stages, so its partially populated file
is not reported as a valid large database. At process exit the external files
were:

| File | Bytes | Mode |
| --- | ---: | --- |
| Main database | 2,921,562,112 | `0600` |
| WAL | 246,264,792 | `0600` |
| Shared memory | 491,520 | `0600` |

GNU time reported 201,154,872 filesystem-output blocks (102,991,294,464 bytes,
or 95.918 GiB when interpreted as Linux 512-byte `ru_oublock` units) and 36,072
input blocks. The high write amplification and inability to finish before the
explicit wall-time budget block any claim that this large profile is supported;
low RSS does not convert the outcome into a pass. The profile is outside the
narrowed experimental-v0.1 envelope rather than a passing release result.

A post-exit, read-only committed-row count completed in 20.18 seconds:

| Relation | Committed rows |
| --- | ---: |
| Repositories | 10,000 |
| Workflow runs | 1,000,000 |
| Attempts | 2,830,000 |
| Jobs | 2,830,000 |
| Archive facts | 2,830,000 |
| Findings | 0 |

Thus 94.3% of the target execution rows had committed, but the sparse
finding/coverage/graph stage had not started. A separate read-only SQLite
`quick_check` did not return within a bounded 120-second post-exit probe.
Recoverability and integrity of the interrupted artifact are therefore not
claimed; it must not be used as a replay source or a successful benchmark.

The completed measured relational envelope on this host is therefore the
medium profile: 1,000 repositories, 100,000 runs, and 300,000 attempt/job/fact
executions. The 3,000,000-execution target remains unqualified.

The opt-in harness requires a new absolute output path and otherwise skips:

```sh
CIREWIND_SCALE_PROFILE=small \
CIREWIND_SCALE_DB="$QUAL_ROOT/results/scale-small.db" \
  /usr/bin/time -v go test ./internal/qualification \
  -run '^TestSyntheticStoreScaleQualification$' -count=1 -v -timeout=2h
```

## Qualification-envelope interpretation and remaining work

This record deliberately leaves the broad `SEC-002`, `PERF-001`, and `PERF-002`
planning contracts open. For experimental v0.1, the completed medium profile is
the supported measured relational envelope; the large profile is explicitly
unsupported and does not block release while that limit remains visible.

- The current archive snapshot path reads and normalizes all compact facts into
  memory, rejects more than 1,000,000 facts, and enforces a 256 MiB aggregate
  JSON ceiling. The documented large profile contains 3,000,000 attempts/jobs.
  Therefore the current end-to-end archive/replay design cannot pass that
  profile even if the relational database remains within its memory limit.
  Replay needs a bounded paged/streaming path before organization-scale support
  can be claimed.
- The relational harness does not measure live GitHub request count, retry and
  overlap cost, collector queue weights, per-response provenance, report size,
  full graph export, or cancellation during concurrent collection.
- The small/medium process-accounted filesystem write totals were not retained;
  finalized database bytes are reported. A release-grade rerun must publish
  write volume along with the other required metrics.
- The large relational profile exceeded its two-hour test budget while
  committing generated rows and never reached its own final query/integrity
  gates. Its interrupted files are retained only as external qualification
  evidence, not as a valid case/archive or a passing benchmark.
- Fuzz duration is bounded and local. Output encoders, imported hostile SQLite
  files, concurrent lifecycle interleaving, and every configured resource cap
  still need their complete release campaigns. Passing a target does not prove
  absence of parser/runtime vulnerabilities.
- `FuzzDecodeSnapshot` had the highest process-tree RSS (about 899 MiB). That
  includes build/link/fuzz-worker overhead and is not evidence of a live-memory
  breach, but it warrants isolated allocation profiling before closing the
  archive-validator fuzz gate.
- This run covers one Linux amd64 host. It does not replace Linux/macOS/Windows
  runtime qualification, browser review, controlled GitHub.com lab evidence,
  clean-clone CI, or a maintainer release decision.

The corrected defects and passing tests materially improve the hostile-input
baseline. They do not make missing evidence safe, do not weaken any forensic
state predicate, and do not independently qualify GitHub collection or the exact
release candidate. Those gates remain separate.
