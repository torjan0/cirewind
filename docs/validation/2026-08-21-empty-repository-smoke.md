# Empty-repository GitHub.com smoke — 2026-08-21

Status: narrow live transport validation; **not** a feasibility-spike GO or v0.1
qualification record.

## Scope and handling

- Target: the public, empty `torjan0/cirewind` repository.
- Command path: network-backed `cirewind archive`, first as a new archive and
  then as an immediate checkpoint resume.
- Toolchain: Go 1.25.13.
- Authentication: an existing GitHub CLI credential was passed to the child
  process through `CIREWIND_GITHUB_TOKEN`. The token, headers, and credential
  value were not printed, persisted, copied into a URL, or retained in this
  record.
- Raw retention: disabled. No raw sidecar was created.
- Temporary archive and build files: removed after validation.

## Observed behavior

The client issued only these GitHub.com REST `GET` route families:

- `/repos/{owner}/{repo}`
- `/repos/{owner}/{repo}/hash-algorithm`
- `/repos/{owner}/{repo}/actions/runs`

No non-`GET` request was observed. The first collection used the provisional
65-day parent-discovery horizon. The second collection used the persisted
checkpoint and 15-minute overlap. Because the repository had no workflow runs,
the resulting archive contained two collection sessions, two batches, one
repository, zero runs, one checkpoint, and an explicit empty watched-parent
array. Both invocations reported complete coverage and zero gaps for this narrow
scope. SQLite `quick_check` returned `ok`, and the foreign-key check returned no
rows.

The first attempt exposed a local normalization defect: cloning an explicit
empty watched-parent array through a nil slice converted it to `nil`, which the
checkpoint contract correctly rejects. The archive transaction did not commit
that invalid batch. The clone logic and regressions were corrected, after which
both new-archive and resume paths passed. Nil watched-parent input remains
invalid; only an explicit empty array represents a valid empty watch set.

Before and after the smoke, the remote repository had no branch or tag. No
repository setting, content, ref, workflow, issue, release, or other GitHub
resource was created or modified.

## What this does not prove

An empty repository cannot validate workflow runs, attempts, attempt-specific
jobs, logs and redirects, Action preparation or lifecycle grammars, immutable
packages, called reusable workflows, reruns, actors, runners, environments,
permissions, retention loss, rate-limit behavior, result ceilings, or
organization visibility. It does not satisfy the controlled A→B→A lab, any
representative credential-permission matrix, or `P0-016=GO`.
