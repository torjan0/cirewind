# Public GitHub.com read-only qualification — 2026-08-21

Status: limited live qualification of public, read-only collection paths;
**not** a feasibility-spike GO or v0.1 release-qualification record.

## Scope and handling

- Every GitHub operation was a REST `GET` against public repositories. No
  repository, ref, workflow, setting, issue, release, or other remote resource
  was created or changed.
- The client sent `X-GitHub-Api-Version: 2026-03-10`. GitHub.com's responses
  selected that version through `X-GitHub-Api-Version-Selected` during these
  observations.
- An existing GitHub CLI credential was supplied only to the child process
  through `CIREWIND_GITHUB_TOKEN`. Its value, authorization headers, cookies,
  request URLs, and temporary signed log URLs were never printed or retained.
- Attempt and job log bodies were streamed either into the bounded compact
  collector or directly to `io.Discard`. Raw retention was disabled. No log
  bytes or response bodies from these public runs were added to the repository.
- The toolchain was Go 1.25.13. Temporary binaries, archives, and Go caches were
  placed on the designated scratch filesystem rather than `/tmp`.

Public GitHub state and retention can change. Public run, job, repository-object,
workflow-object, log-content, and ZIP-content identifiers were retained in the
private qualification transcript but are intentionally omitted here. They are
not bundled fixtures or real-world incident indicators.

## Observed facts

### Run-containing compact collection

A network-backed `cirewind archive` pass collected one established public
repository over a requested 20-minute interval. The collector applied the
provisional 65-day parent discovery window and observed
10 parent runs, 10 attempts, and 10 jobs. The resulting compact archive had:

- one collection session and one checkpoint with 10 watched parents;
- 153 evidence observations and 252 normalized facts;
- 20 exact repository-Action resolutions, 20 download announcements, and 20
  completed-preparation observations from 10 consolidated setup frames;
- zero Action lifecycle-start observations, because the public API step names
  were custom labels rather than the supported exact default `Run owner/repo@ref`
  form;
- 10 material gaps for unavailable exact caller workflow-definition identity;
  and
- no raw-retained evidence and no raw sidecar.

SQLite `quick_check` returned `ok` and `foreign_key_check` returned no rows. The
partial result is the intended conservative behavior: the collector did not
reuse `head_sha` as caller-workflow identity and did not promote custom-labeled
steps to execution merely because their whole-job log contained lifecycle-like
groups.

### Exact called-workflow attempt metadata

For one public reusable-workflow-bearing run, attempt 1, GitHub returned one
attempt-specific job and one `referenced_workflows` entry. The entry named a
public reusable workflow at a mutable branch and included an exact
called-workflow object ID. The attempt and first job logs were available and
were streamed to a discard sink.

This observation establishes that the implemented R5 decoder can retain an
exact called-workflow SHA for this one attempt. It does not establish nested
completeness or full-versus-partial rerun behavior.

### Repository relocation and two attempts

An old public repository slug returned a `301` on GitHub's API to the same
repository under its current name. A bounded same-origin relocation led to the
current object without exposing credentials to another origin.

That public run reported two attempts:

- attempt 1 was completed with conclusion `action_required`, returned zero jobs,
  and its attempt-log route returned `404`; and
- attempt 2 was completed successfully, returned two attempt-specific jobs, and
  retained attempt and job logs.

The client kept the attempts separate and accepted the zero-job attempt without
inventing skipped jobs. This public run does not reveal which GitHub rerun form
created attempt 2 and therefore does not close failed-job or single-job rerun
semantics.

### Retained metadata with expired logs

For one older public run, attempt 1, GitHub still returned parent, attempt, and
two job objects. The attempt-log route
returned endpoint-specific `410 Gone` while confirming selected API version
`2026-03-10`, and its logs were unavailable. The collector now classifies that
combination as `RETENTION_OR_DELETION`, not as a global REST API-version failure.
A log `410` without selected-version confirmation remains an API-version error.
The observation does not distinguish configured expiry from explicit deletion
without independent evidence.

### Request and rate metadata

Successful response metadata included request IDs, the requested and selected
REST API versions, primary rate-limit fields, media type, byte length, response
hash, and collection times. Created-time probe/list queries found their selected
runs. The low-volume observations did not approach pagination, primary-rate, or
secondary-rate ceilings and are not a scale result.

### Current attempt-log ZIP layout qualification

The attempt archives from two unrelated public repositories did **not** use the
checked-in fixture layout of `job/1_Set up job.txt` plus per-step files:

| Public observation | ZIP bytes | Regular entries | Legacy setup entries | Consolidated layout |
| --- | ---: | ---: | ---: | --- |
| Public repository Action run | 34,233 | 2 | 0 | one numbered top-level job log; one nested `system.txt` |
| Public reusable-workflow run | 26,601 | 2 | 0 | one numbered top-level job log; one nested `system.txt` |

For the first archive, the top-level job log was 240,125 bytes and the nested
system log was 601 bytes. Without retaining either body, a bounded structural
scan of the top-level file counted one runner-version marker, one token-permission
group, two repository-Action download announcements, and 29 group starts. The
same file contained normal Action lifecycle groups. Its API job separately
reported a successful `Set up job` step followed by ordinary and post steps.

This shape is consistent with the GitHub-maintained audit utility's pinned
fallback: it first searches for `1_Set up job.txt`, and when absent searches
numbered top-level `0_` log entries for Action-download records
([pinned source lines 135–173](https://github.com/github/audit-actions-workflow-runs/blob/1e536cc1af05a5e37a69d0c8dd479ec6ca2685bf/audit_workflow_runs_utils.js#L135-L173)).
That utility establishes parsing precedent for exact download records, not
CIRewind's stronger preparation-completion or step-lifecycle semantics.

The bounded consolidated grammar implemented after the initial observation:

- accepts only a regular root entry named exactly `0_<job>.txt`;
- treats the filename label only as a correlation attribute and requires it to
  identify exactly one already validated API job;
- independently requires the runner's exact `Complete job name: <API job name>`
  record before framing succeeds;
- accepts an optional UTF-8 BOM only on the first record and timestamp fractions
  wider than nanoseconds only by deterministic truncation for comparison;
- isolates setup at that complete-job-name boundary, so later application
  errors or Action-download lookalikes cannot become preparation evidence;
- validates the Action-download block against the pinned GitHub-maintained audit
  grammar, including structurally complete immutable-package groups; and
- emits an Action lifecycle frame only for a unique API step with the exact
  default name `Run owner/repo@ref`, unique timing/number identity, non-skipped
  status, a complete first runner group, and an exact same-job setup identity.

The collector rerun over all 10 public attempts produced the 60 setup facts
listed above. For the public repository Action run, it preserved two exact
repository Action identities with separate resolution, download-announcement,
and preparation-completion states. It emitted no lifecycle facts because that
job's API steps used custom names. This qualifies current consolidated setup
framing for those public repository-Action records; it does not qualify
immutable packages, pre/post phases, other runner versions, or an
execution-positive oracle.

The raw ZIP and extracted whole-job entry used for the focused parser check were
removed immediately after the check. The full collector rerun retained only
compact structured evidence and hashes.

## Defects found and corrected

1. The JSON client previously rejected GitHub's same-origin repository
   rename/transfer `301` as malformed. It now follows at most three same-origin
   API relocations, rejects cross-origin targets and cycles, and retains each
   response in the metadata chain.
2. Log acquisition previously required the first API response to be the final
   `302` temporary-object redirect. It now safely handles a bounded same-origin
   API relocation before that `302`, without forwarding authorization to the
   temporary storage host.
3. A generic `410` remains an unsupported-version signal, but a `410` from an
   attempt/job log acquisition that also confirms the requested selected API
   version is now a distinct `RETENTION_OR_DELETION` gap.
4. Compact response projections previously discarded method, allowlisted
   parameters, requested/selected API versions, ETag, rate-limit, retry, and
   timing fields. Those safe fields are now retained where a compact projection
   contains a response chain.
5. The collector previously recognized only legacy split attempt logs. It now
   applies the bounded versioned consolidated grammar above while preserving the
   legacy path. Offline hostile fixtures cover non-unique job labels, forged
   groups/downloads, later errors, multiple Actions, immutable groups, skipped,
   cancelled, download-only, and exact default-named lifecycle cases.

The consolidated grammar remains deliberately narrow. A changed layout, an
ambiguous name, a custom Action step name, or an incomplete group produces a
gap or withholds lifecycle promotion rather than triggering substring matching.

Offline regression tests cover same-origin relocation, cross-origin credential
isolation, redirect cycles, log API relocation, endpoint-specific `410`, gap
mapping, selected-version headers, and safe compact response projection. The
live harness is opt-in and skips in the default credential-free suite.

## Remaining collection-provenance limitation

Not every transport leg is yet materialized as its own compact evidence object.
In particular, a successful log evidence envelope records the logical API route,
allowlisted parameters, final content type/length/hash, and collection interval,
while the transport's initial API redirect metadata and temporary-storage
response metadata are not separately persisted by the live collector. Explicit
repository resolution and parent-stabilization response chains also need a
complete audit against the normative per-response provenance contract. This
limits provenance detail; it does not change the hash of downloaded log bytes.
It remains release work rather than being silently called complete.

## What this does not prove

These public, read-only observations do not satisfy:

- the controlled mutable-tag A→B→A protocol or downloaded-versus-executed
  runner-grammar gates;
- a controlled execution-positive or immutable-package qualification for the
  observed consolidated whole-job attempt-log layout;
- controlled full, failed-job, and single-job reruns or reusable-workflow
  re-resolution semantics;
- signed-log URL expiry followed by delayed reacquisition and bounded renewal;
- organization visibility, private-repository access, or the classic PAT,
  fine-grained PAT, and GitHub App permission matrix;
- current organization-scale partition saturation, concurrency, abuse-limit, or
  provisional 65-day watch cost;
- exact caller workflow identity across event types, environment gates,
  self-hosted runners, secret flow, OIDC, or downstream-resource attribution; or
- `P0-016=GO` or the v0.1 definition of done.

## Reproduction boundary

The opt-in test is `TestLiveReadOnlyRunQualification` in
`internal/githubapi/live_readonly_test.go`. It requires an explicitly selected
public repository, completed run, and attempt through `CIREWIND_LIVE_*`
environment variables. Missing-log, zero-job, and exact-called-SHA expectations
are explicit flags. It stores no response body and streams logs to `io.Discard`.
Default tests remain offline and skip this test unless
`CIREWIND_LIVE_READONLY=1` is deliberately set.
