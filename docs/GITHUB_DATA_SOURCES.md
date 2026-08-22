# GitHub Data Sources and Collection Contract

Status: normative v0.1 collection contract; bounded explicit-repository controlled validation complete, broader compatibility matrix incomplete
Target: GitHub.com
Research cutoff and retrieval date for every linked source: **2026-08-20**

Implemented and mock-tested transport behavior is summarized in
[IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md). A dated
[public read-only qualification](validation/2026-08-21-public-readonly-qualification.md)
observed selected run/attempt/job/log routes, one exact called-workflow SHA, a
same-origin repository relocation, and retained metadata with an unavailable log.
The bounded
[controlled explicit-repository qualification](validation/2026-08-22-controlled-lab-qualification.md)
validated the documented A-to-B-to-A, rerun, reusable-workflow, composite,
credential, runner, and retention-loss paths for its observed grammar. Broader
endpoint, permission-profile, runner-version, organization-saturation, immutable-
package, and scale claims remain unqualified even when client code, fixtures, or
one public observation exists.

## 1. Purpose and epistemic labels

This document defines what CIRewind may collect from GitHub, how it must paginate and correlate that data, and which conclusions each source can support. It is not a promise that GitHub retains every source. The collector must preserve both successful responses and explicit coverage gaps.

Statements are classified as follows:

- **Verified** — stated in current GitHub documentation, the GitHub-maintained Actions runner, or another GitHub-maintained repository linked here.
- **Design decision** — conservative CIRewind behavior derived from verified constraints.
- **Inference** — plausible interpretation that must never be represented as GitHub-documented fact.
- **Spike validation required** — behavior that must be measured against controlled GitHub.com runs before it becomes an evidence rule.

These labels matter. In particular, a successful API call is not evidence that other inaccessible repositories, attempts, logs, or secrets do not exist. Authentication scope and repository selection are part of collection coverage.

## 2. API baseline

CIRewind v0.1 shall send these headers on every REST request:

| Header | Value | Reason |
|---|---|---|
| `Accept` | `application/vnd.github+json` unless an endpoint requires raw or archive media | GitHub's recommended REST media type. |
| `X-GitHub-Api-Version` | `2026-03-10` | Current supported REST API version at the research cutoff. |
| `Authorization` | bearer token, supplied only to `api.github.com` and never persisted | Authentication; omitted only for intentionally unauthenticated public-repository tests. |
| `User-Agent` | stable CIRewind name and version | Required by GitHub REST and useful for incident support. |

**Verified.** GitHub REST is calendar-versioned. Requests without a version currently default to `2022-11-28`; a specified API version that is no longer supported returns `410 Gone`. GitHub documents a minimum 24-month support period after a new version is released. Pinning avoids silently changing response semantics. See [REST API versions](https://docs.github.com/en/rest/about-the-rest-api/api-versions).

**Design decision.** Record the requested API version, response
`X-GitHub-Api-Version-Selected` (or the legacy/alternate
`X-GitHub-Api-Version` response spelling when present), request path and
non-secret parameters, status, request ID, rate-limit headers, ETag, collection
time, response media type, byte count, and SHA-256 for every retained response.
Never retain authorization headers, cookies, or signed redirect URLs. The
selected-header spelling was also observed on GitHub.com during the dated
[public read-only qualification](validation/2026-08-21-public-readonly-qualification.md).

GraphQL has no equivalent dated version header. GraphQL-derived evidence must therefore record the queried schema fields, a CIRewind extractor version, and collection time. REST remains the normative source for run/attempt/job enumeration; GraphQL is optional corroboration until the validation spike establishes its historical behavior.

## 3. Coverage envelope and collection order

The required collection order is:

1. Resolve the authorized repository universe and record exclusions.
2. Enumerate runs in recursively partitioned creation-time windows per repository.
3. Read the current `run_attempt` for every run and request every integer attempt from `1` through that value.
4. List attempt-specific jobs and download attempt- and/or job-specific logs while retained.
5. Retrieve the executed caller workflow and every referenced reusable workflow at an exact commit when that identity is available.
6. Resolve repository Actions, composite Actions, and same-repository Actions without executing fetched content.
7. Collect credential, environment, runner, and downstream-resource context with separately declared permissions.
8. Persist each response or failure as evidence, then derive findings. A derivation must never conceal source unavailability.

The collector must snapshot its coverage envelope: organization or explicit repository selectors, token kind, installation ID where relevant, visible repository IDs, inaccessible or skipped repository IDs when known, time interval, collection start/end, API version, enabled enrichments, and permission probes. A report may claim `NO_MATCH_CONFIRMED` only inside that recorded envelope and only if required retained evidence was actually examined.

Identifier sources must remain separate:

| Identifier | Primary source | What it must not replace |
|---|---|---|
| trigger/event SHA | R3/R5 `head_sha` plus event/PR context | caller definition, called workflow, Action source, or package digest |
| caller workflow-definition commit | validated executed-file/audit/event-specific resolver, then C1 | trigger SHA by default; present-day workflow YAML |
| called reusable-workflow commit | R5 `referenced_workflows[].sha` | caller/trigger SHA or declared mutable `ref` |
| Action source commit | exact runner preparation log, optionally corroborated by C1 metadata | workflow/reusable SHA or current tag target |
| immutable Action package digest | runner immutable-package log `sha256` field | Action source commit or release-asset/container/artifact digest |
| run attempt/job | R5 route plus R6 job ID | run ID alone or a job name |

Every identifier carries its own repository/namespace, algorithm/type, raw value, source evidence, event time where available, and collection time.

Use GitHub numeric or node IDs as identity keys where supplied. Repository names, owner names, actor logins, workflow/job/step names, branches, and tags are mutable and hostile display attributes; preserve their event/collection-time observations but never use them alone to merge evidence.

## 4. Core REST endpoint matrix

All routes below are relative to `https://api.github.com`. `FG/App permission` means the minimum documented fine-grained personal access token, GitHub App user token, or GitHub App installation token permission. Classic PAT scopes are summarized separately in section 12.

### 4.1 Repository discovery and runs

| ID | Route / data source | Required fields | Pagination and filters | FG/App permission | Evidence use and limitations |
|---|---|---|---|---|---|
| R1 | `GET /orgs/{org}/repos` | repository `id`, `node_id`, `name`, `full_name`, `private`, `visibility`, `archived`, `disabled`, `fork`, `owner`, `default_branch`, `updated_at` | `per_page<=100`, `page`; select the intended `type` explicitly | Repository **Metadata: read** | Organization-owned repositories visible to the credential. Public data is available without authentication. It does not reveal private repositories hidden from the credential. [List organization repositories](https://docs.github.com/en/rest/repos/repos?apiVersion=2026-03-10#list-organization-repositories). |
| R2 | `GET /installation/repositories` | same identity/visibility fields plus `repository_selection` context retained from installation metadata | `per_page<=100`, `page` | Installation token; only repositories accessible to that installation | Normative repository universe for a GitHub App installation. Do not substitute R1 and imply the App covers every organization repository. [List repositories accessible to the app installation](https://docs.github.com/en/rest/apps/installations?apiVersion=2026-03-10#list-repositories-accessible-to-the-app-installation). |
| R2b | `GET /user/installations` then `GET /user/installations/{installation_id}/repositories` | installation account/ID, App permissions, repository selection, per-repository user access | `per_page<=100`, `page` | GitHub App **user access token** | Corresponding coverage discovery for a user access token; access is the intersection of App, installation, and user. Do not call R2 with the wrong App token type. [User-token installation endpoints](https://docs.github.com/en/rest/apps/installations?apiVersion=2026-03-10#list-app-installations-accessible-to-the-user-access-token). |
| R3 | `GET /repos/{owner}/{repo}/actions/runs` | `id`, `node_id`, `run_number`, `run_attempt`, `workflow_id`, `path`, `event`, `status`, `conclusion`, `created_at`, `run_started_at`, `updated_at`, `head_sha`, `head_branch`, `actor`, `triggering_actor`, `pull_requests`, `repository`, `head_repository`, `check_suite_id`, API/HTML/log/jobs URLs | `per_page<=100`, `page`; `created` plus optional actor/branch/event/status/check suite/head SHA filters; **1,000-result ceiling whenever any documented search filter is used** | Repository **Actions: read** | Required run discovery. There is no organization-wide Actions-run list in this v0.1 design; query each repository. `head_sha` is the trigger/event SHA, not a universal workflow-definition, called-workflow, or Action SHA. [List workflow runs for a repository](https://docs.github.com/en/rest/actions/workflow-runs?apiVersion=2026-03-10#list-workflow-runs-for-a-repository). |
| R4 | `GET /repos/{owner}/{repo}/actions/runs/{run_id}` | all R3 fields, especially current/highest `run_attempt`, `triggering_actor`, `referenced_workflows`, timing/status | one object | Repository **Actions: read** | Refreshes a run and discovers its current attempt count. A run that is still queued or in progress must be revisited; the first observation is not final. [Get a workflow run](https://docs.github.com/en/rest/actions/workflow-runs?apiVersion=2026-03-10#get-a-workflow-run). |
| R5 | `GET /repos/{owner}/{repo}/actions/runs/{run_id}/attempts/{attempt_number}` | full run metadata for that attempt; `run_attempt`, `run_started_at`, status/times, actor/triggering actor, `referenced_workflows[].path/.sha/.ref`, `previous_attempt_url` | no list endpoint; probe the closed integer range `1..R4.run_attempt` | Repository **Actions: read** | Required attempt snapshot. `referenced_workflows.sha` is exact reusable-workflow identity recorded by GitHub for the attempt and can support `CONFIRMED_CALLED_WORKFLOW`. Which times are attempt-specific, direct-vs-transitive completeness, and behavior for inaccessible repositories require spike validation. [Get a workflow run attempt](https://docs.github.com/en/rest/actions/workflow-runs?apiVersion=2026-03-10#get-a-workflow-run-attempt). |
| R6 | `GET /repos/{owner}/{repo}/actions/runs/{run_id}/attempts/{attempt_number}/jobs` | job `id`, `node_id`, `run_id`, `workflow_name`, `head_sha`, `head_branch`, `status`, `conclusion`, `started_at`, `completed_at`, `name`, `steps[].number/name/status/conclusion/started_at/completed_at`, `labels`, `runner_id`, `runner_name`, `runner_group_id`, `runner_group_name`, `run_url`, `check_run_url`, API/HTML URLs | `per_page<=100`, `page` | Repository **Actions: read** | Required job inventory. The response does not supply `run_attempt`, so bind it from the requested R6 route. Primary execution identity is `(run_id, run_attempt, job_id)`. Matrix variants are distinct job IDs; names are hostile, expression-influenced, and non-unique. [List jobs for a workflow run attempt](https://docs.github.com/en/rest/actions/workflow-jobs?apiVersion=2026-03-10#list-jobs-for-a-workflow-run-attempt). |
| R7 | `GET /repos/{owner}/{repo}/actions/runs/{run_id}/jobs?filter=all` | same as R6 | `per_page<=100`, `page`; `filter=all` includes prior executions | Repository **Actions: read** | Corroborating discovery/fallback only. Attempt-specific R6 is authoritative because R7 does not by itself provide a safe attempt join for every job. [List jobs for a workflow run](https://docs.github.com/en/rest/actions/workflow-jobs?apiVersion=2026-03-10#list-jobs-for-a-workflow-run). |

**Design decision.** Explicit-repository mode resolves each repository with `GET /repos/{owner}/{repo}` and records a failure independently. Organization mode must compare R1 with R2/R2b or installation metadata when an App token is used. Repositories omitted by credential selection are `not_collected`, not `no_match`.

Always paginate R6: GitHub currently allows a matrix to create 256 jobs, already exceeding one 100-item page, and a workflow can contain additional jobs. [Actions limits](https://docs.github.com/en/actions/reference/limits).

### 4.2 Attempt-specific logs

| ID | Route | Response behavior | Permission | Required handling |
|---|---|---|---|---|
| L1 | `GET /repos/{owner}/{repo}/actions/runs/{run_id}/attempts/{attempt_number}/logs` | `302 Found` to a temporary archive URL; GitHub documents that the redirect expires after **one minute** | Repository **Actions: read** | Do not enable a client behavior that forwards `Authorization` to a different host. Validate the redirect scheme/host policy, fetch immediately, bound compressed/uncompressed sizes and entries, hash the downloaded bytes, and never persist the signed URL. [Download workflow run attempt logs](https://docs.github.com/en/rest/actions/workflow-runs?apiVersion=2026-03-10#download-workflow-run-attempt-logs). |
| L2 | `GET /repos/{owner}/{repo}/actions/jobs/{job_id}/logs` | `302 Found` to temporary plain-text log; redirect expires after **one minute** | Repository **Actions: read** | Required per-job fallback and useful compact archive source. Bind it to the R6 job in the same attempt; never infer an attempt from the job name. [Download job logs](https://docs.github.com/en/rest/actions/workflow-jobs?apiVersion=2026-03-10#download-job-logs-for-a-workflow-run). |
| L3 | `GET /repos/{owner}/{repo}/actions/runs/{run_id}/logs` | redirect to the run log archive | Repository **Actions: read** | Latest/current-run convenience only; do not use it in place of L1 for historical attempts. [Download workflow run logs](https://docs.github.com/en/rest/actions/workflow-runs?apiVersion=2026-03-10#download-workflow-run-logs). |

The first request/redirect metadata and the final downloaded object are two evidence observations with a derivation relationship. The initial API response establishes the logical source; the content hash establishes the acquired bytes. Signed query strings are secret-adjacent and must be redacted before any logging or evidence persistence.

**Limited live observation and qualification, 2026-08-21.** Two public L1 archives used one
numbered top-level whole-job log plus a nested `system.txt` per observed job and
contained no `1_Set up job.txt` or per-step entry. The top-level log contained
runner setup, Action-download, permission, and lifecycle groups. GitHub's
maintained audit utility likewise falls back from `1_Set up job.txt` to a
top-level `0_` log when extracting Action-download records
([pinned source](https://github.com/github/audit-actions-workflow-runs/blob/1e536cc1af05a5e37a69d0c8dd479ec6ca2685bf/audit_workflow_runs_utils.js#L135-L173)).
This supports an exact-download parsing precedent only; it does not by itself
prove a preparation-completion or lifecycle boundary. CIRewind now recognizes
only a regular root `0_<job>.txt` whose label maps to exactly one validated R6
job and whose runner-owned setup contains one exact
`Complete job name: <API job name>` boundary. The versioned grammar isolates
setup before application output and validates the download block against the
pinned audit grammar. A raw-disabled public collector rerun produced exact
resolution, announcement, and preparation observations for 20 repository
Actions across 10 attempts. It produced no lifecycle observations because the
R6 Action steps used custom names: execution promotion remains limited to a
structurally complete first runner group joined to one non-skipped, exact
default-named `Run owner/repo@ref` R6 step and the same-job setup identity.
Legacy split entries remain supported. Ambiguous or changed shapes fail to gaps
or withhold lifecycle promotion; no arbitrary job-output substring fallback is
used. See the
[sanitized qualification record](validation/2026-08-21-public-readonly-qualification.md).

### 4.3 Historical repository content

| ID | Route | Fields/media | Permission | Limits and use |
|---|---|---|---|---|
| C1 | `GET /repos/{owner}/{repo}/contents/{path}?ref={full_git_object_id}` | path, blob object ID, size, encoding/content, download/API URLs; request raw media when appropriate | Repository **Contents: read** | Fetch historical workflow YAML and `action.yml`/`action.yaml` only after resolving an exact typed Git object ID. The Contents API supports files up to 100 MB with media-type limitations; files over 100 MB are unsupported and directory listings cap at 1,000 entries. Never omit `ref`, follow a branch/tag after collection, or fall back to the current default branch silently. [Get repository content](https://docs.github.com/en/rest/repos/contents?apiVersion=2026-03-10#get-repository-content). |
| C2 | `GET /repos/{owner}/{repo}/git/blobs/{file_sha}` | blob SHA, size, encoding/content; raw media supported | Repository **Contents: read** | Bounded fallback once a trusted Git tree/blob SHA has been resolved. GitHub documents a 100 MB blob limit. [Get a blob](https://docs.github.com/en/rest/git/blobs?apiVersion=2026-03-10#get-a-blob). |
| C2a | `GET /repos/{owner}/{repo}/git/tags/{tag_sha}` | annotated tag object's own full SHA, tag name/node ID, and target object's exact `type` plus full SHA | Repository **Contents: read**; public resources may be unauthenticated | Reads an annotated **tag object**, not a lightweight tag reference and not a commit. Preserve the requested/returned tag object separately from its typed target. A `404` establishes only that this tag-object request was unavailable; it does **not** prove the supplied object ID is a commit. GitHub documents `200`, `404`, and `409`, and describes these Git-database endpoints as annotated-tag-only. CIRewind also accepts the Git-valid `tag` target type defensively for bounded nested-tag peeling, but that response shape still requires controlled live validation because the current create-tag documentation enumerates `commit`, `tree`, and `blob`. [Get a tag](https://docs.github.com/en/rest/git/tags?apiVersion=2026-03-10#get-a-tag). |
| C3 | `GET /repos/{owner}/{repo}/actions/workflows` and `/workflows/{workflow_id}` | workflow ID/node ID, name, path, state, created/updated times | Repository **Actions: read**; list uses `per_page<=100` | Current workflow registry metadata only. It can resolve an ID/path label but not the historical YAML bytes or definition commit for a run. [Workflows endpoints](https://docs.github.com/en/rest/actions/workflows?apiVersion=2026-03-10). |
| C4 | `GET /repos/{owner}/{repo}/hash-algorithm` | repository `hash_algorithm` | Repository **Metadata: read**; public resources may be unauthenticated | Current Git object-hash algorithm capability. Store Git object IDs with an algorithm and as opaque full strings; do not hardcode 40 hexadecimal characters. [Get repository hash algorithm](https://docs.github.com/en/rest/repos/repos?apiVersion=2026-03-10#get-the-hash-algorithm-for-a-repository). |

Content is hostile input. The resolver may parse YAML and Action metadata but must not execute, import, build, check out, or run it. For a repository Action resolved to an exact Action source SHA, request both metadata names in a deterministic order and retain each `404`; do not guess that absence of `action.yml` means an `action.yaml` never existed.

Cache historical content only under immutable keys such as `(repository_id, commit_object_algorithm, full_commit_object_id, normalized_path, returned_blob_algorithm, full_blob_object_id)`. Preserve and verify the returned blob object ID and size. Never let a response obtained through a branch/tag key populate an immutable cache entry merely because the branch happened to point at that commit during collection.

Cache C2a only by `(repository_id, object_algorithm, full_tag_object_id)` and
retain every hop's response metadata. The transport validates that the returned
tag object ID exactly equals the requested ID and that both the tag and target
IDs are complete lowercase hexadecimal values of the repository's independently
observed hash algorithm. Peeling is a later derivation over these observations,
not an in-place rewrite of the recorded reusable-workflow SHA. See the
[2026-08-21 tag-endpoint validation note](validation/2026-08-21-git-tag-endpoint.md).

GitHub's current API exposes a repository hash algorithm, so schema fields for trigger, workflow, caller, Action, tree, and blob object IDs must carry `algorithm` (known or unknown) plus the full value. Normalize hexadecimal case for comparison while preserving the raw value. An incident pack or parser that accepts only 40-character SHA-1 is not forward-compatible; a digest such as `sha256:...` remains a different identifier type from a Git SHA-256 object ID.

## 5. Created-time search and recursive partitioning

**Verified.** R3 accepts a `created` search parameter using GitHub date/range syntax and caps searches using `created` (or any of the other documented search filters) at 1,000 results. Each page holds at most 100. See [R3](https://docs.github.com/en/rest/actions/workflow-runs?apiVersion=2026-03-10#list-workflow-runs-for-a-repository) and GitHub's [date search syntax](https://docs.github.com/en/search-github/getting-started-with-searching-on-github/understanding-the-search-syntax#query-for-dates).

The `created` filter discovers workflow runs, not attempts by their rerun time. GitHub permits a rerun for up to 30 days after the initial run, while the documented maximum lifetime of a workflow run—including execution, waiting, and approval—is 35 days. Therefore an attempt or delayed job executing inside the incident interval can belong to a run created before `--from`. The cited documentation does not explicitly establish that the 35-day lifetime is anchored to original parent creation across later rerun attempts. See [Re-running workflows and jobs](https://docs.github.com/en/actions/how-tos/manage-workflow-runs/re-run-workflows-and-jobs) and [Actions limits](https://docs.github.com/en/actions/reference/limits).

**Design decision.** Until the lifetime anchor is proven by the spike, combine the two independently documented maxima and query R3 over `[from - 65 days, to)` to discover eligible parent runs. This is intentionally conservative, not a GitHub-stated 65-day rule. Collect every attempt of each discovered run, then retain separate times for original run creation, attempt observation, job/step start and completion, log lines, and collection. Apply an incident exposure window to the most specific supported runtime event time, not blindly to `run.created_at`. A missing attempt/job time remains unknown; it must not be filtered out as safe. Archive polling must likewise revisit recently created run IDs so later reruns or delayed jobs are ingested. A reduction to 35 days requires captured proof that it is a safe parent-eviction boundary.

R3 has no documented `updated` filter and R5 has no “list attempts” route. The portable read-only archive strategy is therefore to re-enumerate the provisional rolling 65-day R3 discovery horizon, compare each returned `(run_id, run_attempt)` with the archive checkpoint, and fetch only newly observed attempts/jobs/logs. Expire a run from this watch set only after the configured conservative horizon, a successful final refresh, and a boundary overlap. The Enterprise audit rerun event can accelerate discovery but cannot replace this scan because audit access is optional. At high volume this cost is a feasibility metric; reducing the horizon to `--since` would silently miss reruns or delayed jobs.

CIRewind shall use this deterministic partition algorithm:

1. Normalize the user interval to UTC. Preserve the exact user input and compute the expanded discovery interval above. Model internal intervals as half-open.
2. Translate it to the API's inclusive range. Because inclusive endpoints can overlap adjacent partitions, intentionally overlap the split boundary and deduplicate strictly by repository ID plus `run_id`.
3. Request pages by following the response `Link` relation; do not manufacture page URLs. Use `per_page=100`.
4. If the response reports `total_count >= 1000`, if ten full pages are observed, or if any other response indicates truncation, bisect the time interval and recurse.
5. Continue until each leaf returns fewer than 1,000 results. Persist the partition tree, query bounds, response counts, pages, duplicates, and completion state.
6. If the smallest supported timestamp bucket still contains 1,000 or more runs, stop claiming that the filtered query is exhaustive. A separately validated fallback may paginate the **unfiltered** R3 collection to completion and filter locally, because GitHub documents the 1,000 ceiling specifically for filtered searches; do not assume ordering or an unlimited history until the spike proves it. Otherwise record `window_saturated` and produce `UNKNOWN_EVIDENCE_GAP`. Do not partition by actor, event, status, or mutable branch unless an independently exhaustive partition proof has been designed and tested.
7. Refresh runs observed as queued/in-progress and perform a bounded overlap scan at the collection watermark so a run created during pagination is not omitted.

**Spike validation required.** Confirm the accepted timestamp precision and inclusive-boundary behavior on GitHub.com, how `total_count` is represented when the 1,000 ceiling applies, whether run ordering stays stable while new runs arrive, that R3 `created` remains the original run time across reruns, and whether the 35-day lifetime is anchored to the original parent. Determine which R5/R6/log timestamp most reliably identifies attempt preparation/execution. Until measured, the implementation must retain the provisional 65-day combined lookback, overlapping windows, and ID deduplication rather than an assumed boundary convention.

An empty page from one request is not automatically exhaustive. The leaf is complete only when all pages were followed, no retryable error remains, and the token's repository access was established.

## 6. Attempts and rerun semantics

### 6.1 Required identity rules

- A workflow `run_id` persists across reruns; `run_attempt` identifies an attempt.
- Jobs must be stored under `(repository_id, run_id, run_attempt, job_id)` even if `job_id` appears globally unique.
- A rerun of failed jobs or one job need not execute every job. Absence from that attempt is not a skipped job unless GitHub provides a job/step record establishing that state.
- Never merge attempt conclusions. A mutable Action or reusable-workflow reference can resolve differently between attempts.
- Preserve both `actor` and `triggering_actor`. They answer different questions.

**Verified.** GitHub permits rerunning all jobs, failed jobs, or a specific job and its dependents. Reruns use the original triggering actor's privileges and the original `GITHUB_SHA` and `GITHUB_REF`; a workflow can be rerun for up to 30 days and up to 50 times. See [Re-running workflows and jobs](https://docs.github.com/en/actions/how-tos/manage-workflow-runs/re-run-workflows-and-jobs).

**Verified.** For called reusable workflows, a full rerun of all jobs uses the reusable workflow at the currently specified reference. A failed-job or specific-job rerun uses the same called-workflow commit SHA as the first attempt. See [Behavior of reusable workflows when re-running jobs](https://docs.github.com/en/actions/concepts/workflows-and-actions/reusing-workflow-configurations#behavior-of-reusable-workflows-when-re-running-jobs).

**Spike validation required.** GitHub's documentation does not establish equivalent pin/re-resolution behavior for every ordinary step-level repository Action. Runtime logs must remain primary. Validate full, failed-job, and single-job reruns after moving a controlled Action tag; validate which attempt endpoints exist, how non-rerun jobs appear, whether all earlier attempts remain addressable while logs exist, and whether R5 `referenced_workflows` returns all nested calls or only a subset.

### 6.2 Referenced reusable workflows

R5's `referenced_workflows[].sha` is an exact GitHub-recorded called-workflow SHA for that attempt. Store separately:

- caller repository, path, and exact workflow-definition commit;
- trigger SHA and ref;
- each called repository, path, declared `ref`, and recorded exact `sha`;
- which attempt produced the metadata;
- source response and collection time.

Fetch a called file with C1 at the recorded `sha`. Never assume the caller's `head_sha` equals the called SHA. Recurse only through supported workflow syntax and maintain cycle/depth guards. GitHub currently documents nesting of a caller plus up to nine reusable workflows (ten levels total); permissions can only be maintained or reduced through the chain. See [Nesting reusable workflows](https://docs.github.com/en/actions/how-tos/reuse-automations/reuse-workflows#nesting-reusable-workflows).

If a referenced private workflow repository is inaccessible, retain its exact metadata but mark content reconstruction incomplete. Exact recorded identity can still support `CONFIRMED_CALLED_WORKFLOW` for an incident indicator matching that SHA; it cannot support claims about nested contents that were not retrieved.

## 7. Runtime log semantics

### 7.1 What GitHub logs can and cannot establish

**Verified.** GitHub workflow logs include special job-setup and job-completion steps; GitHub-hosted setup logs include runner-image information. GitHub describes logs as workflow output and warns in its incident-response guidance that workflow logs capture standard output, not every filesystem write, network operation, or silent background process. See [Using workflow run logs](https://docs.github.com/en/actions/how-tos/monitor-workflows/use-workflow-run-logs) and [Security incident investigation tools](https://docs.github.com/en/code-security/reference/security-incident-response/investigation-tools#workflow-runs-and-logs).

The GitHub-maintained but explicitly unsupported [`github/audit-actions-workflow-runs`](https://github.com/github/audit-actions-workflow-runs) tool documents/parses current runner setup-log records including:

- repository Action preparation: `Download action repository 'OWNER/REPO@REF' (SHA:...)`;
- immutable Action package groups with version, source commit SHA, and `sha256` digest.

The parser source is the most precise GitHub-maintained reference for those strings: [audit_workflow_runs_utils.js](https://github.com/github/audit-actions-workflow-runs/blob/main/audit_workflow_runs_utils.js). Current pinned runner source emits the repository “Download action” line before it awaits archive download and extraction ([ActionManager.cs, pinned lines 1183–1225](https://github.com/actions/runner/blob/258d6c857db3519913f7deb6004b60172f8043ae/src/Runner.Worker/ActionManager.cs#L1183-L1225)). The runner repository is [actions/runner](https://github.com/actions/runner).

That GitHub-maintained parser currently searches per-job archive entries whose basename is `1_Set up job.txt` and top-level entries beginning `0_`. Those names are observed implementation grammar, not a documented stable API contract. CIRewind locates only the bounded legacy or root consolidated forms, associates them through the validated attempt/job inventory, and fails to a parser gap when a candidate cannot be uniquely and structurally bound.

Do not search arbitrary user-step output for these literals and promote a match to runner evidence: hostile workflow code can print convincing setup or `Run ...` lines. Require runner-owned archive/step structure, expected phase ordering, R6 metadata, and a versioned grammar. Preserve the bounded raw span so a reviewer can distinguish a runner control record from user output; a literal execution-looking line alone is not proof.

The exact line supports runtime resolution and entry into the download routine, not completed download/preparation and not execution. CIRewind must separately validate a preparation-completion boundary, use versioned fixture-tested extractors, and preserve the literal bounded source span and content hash. An unrecognized runner version, missing completion boundary, or changed log grammar is an evidence gap, not a negative match.

### 7.2 Downloaded versus executed

The following evidence policy is mandatory:

| Observation | Maximum conclusion |
|---|---|
| Setup log announces exact Action source ID or immutable package digest, but completion is absent/ambiguous | Preserve exact runtime resolution; `UNKNOWN_EVIDENCE_GAP` for whether preparation completed unless another applicable static state is independently supported |
| Exact Action source ID/digest plus a validated completed-preparation boundary, but no correlated lifecycle start | `CONFIRMED_DOWNLOADED` |
| Attempt metadata records exact called reusable-workflow SHA | `CONFIRMED_CALLED_WORKFLOW` |
| Historical YAML declares an exact Action SHA but runtime logs are absent | `DECLARED_AT_RUN_SHA` |
| Historical YAML declares a mutable affected ref during its incident window but no runtime resolution survives | `RUN_IN_WINDOW_MUTABLE_REF` |
| Exact same-attempt runtime resolution plus a deterministically matched runner-owned lifecycle-start marker; GitHub job-step `started_at` corroborates when available | eligible for `CONFIRMED_EXECUTED` |
| Action preparation demonstrably completed before evaluation and its step is skipped, or the step match is ambiguous | no stronger than `CONFIRMED_DOWNLOADED` |

**Spike validation required.** Establish exact preparation-completion boundaries, runner lifecycle markers, and joins for direct JavaScript (including `pre`, main, and `post` handlers), Docker, composite, immutable-package, matrix, conditional/skipped, cancelled, and failed steps. Treat each Action lifecycle phase as a separately observed execution event; do not assume the visible main-step marker is the first code from that Action. Test whether composite nested Actions appear in setup, execution, or both and whether log grouping is stable. Until this validation passes, the collector may emit exact-resolution observations, but must feature-gate `CONFIRMED_DOWNLOADED` and `CONFIRMED_EXECUTED` for unsupported grammars.

GitHub.com now permits `run` and `uses` steps to run in the background and provides explicit wait/cancel/parallel constructs. YAML order and step number are therefore not a universal happens-before relation. Store step intervals and synchronization edges; do not infer secret/file/resource flow across overlapping unsynchronized steps. See [workflow syntax for background steps](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#jobsjob_idstepsbackground).

Preparation records need not be one-to-one with declared steps: the same Action/ref can appear more than once, and the runner may prepare shared dependencies before individual conditions are known. Preserve the set of candidate step identities. Do not assign a download to a specific repeated step by list order alone; an execution conclusion requires a step-specific join, while an attempt-level exact download may remain valid.

Action code that downloads tools internally is generally opaque to GitHub's Action-resolution metadata. Only retained log literals, explicit immutable digests, or another independently attributable evidence source may identify those tools. Do not treat the outer Action SHA as proof of every embedded runtime dependency.

## 8. Executed caller workflow and GraphQL

### 8.1 Current GraphQL schema

**Verified.** The current GraphQL Actions schema exposes `WorkflowRun.runAttempt` and `WorkflowRun.file`. `WorkflowRun.file` returns a `WorkflowRunFile`, described by GitHub as an “executed workflow file,” with `path`, `repositoryFileUrl`, `repositoryName`, `viewerCanReadRepository`, and related URL fields. See [WorkflowRun](https://docs.github.com/en/graphql/reference/actions#workflowrun) and [WorkflowRunFile](https://docs.github.com/en/graphql/reference/actions#workflowrunfile).

CIRewind may query the REST run's `node_id` through GraphQL `node(id:)` and retain this object as corroborating evidence. It must not parse a commit from `repositoryFileUrl` and call it immutable until validated.

**Spike validation required.** Determine:

1. whether `repositoryFileUrl` contains an exact commit SHA for each supported event and reusable-workflow case, rather than a mutable ref or UI indirection;
2. whether the file is the caller, a called reusable workflow, or context-dependent;
3. whether earlier attempts can be addressed independently or the node always reflects the current attempt;
4. null/error behavior when the caller or called repository is private/inaccessible;
5. the token permissions and GraphQL cost at organization scale.

Until those tests pass, GraphQL is not the sole source for the workflow-definition commit. A URL is a locator, not itself content; fetch bytes through C1 at a separately validated full SHA.

REST run/attempt `path` values can include a suffix such as `.github/workflows/build.yml@main`. Preserve the raw field and parse path/ref separately. A branch/tag suffix is declaration context, not an immutable workflow-definition commit; even a SHA-looking suffix must be cross-checked before C1 retrieval.

### 8.2 Caller resolution hierarchy

Use the first available exact source, retaining contradictions rather than overwriting them:

1. validated exact executed-file identity from GraphQL, if the spike passes;
2. exact workflow reference/SHA from the optional audit record in section 9;
3. event-specific reconstruction from immutable event payload fields and repository Git history;
4. run `path` plus `head_sha` only when the event semantics prove that `head_sha` is the workflow-definition commit;
5. otherwise mark the caller definition unavailable.

Present-day default-branch YAML is never a historical fallback. It may be collected separately as `CURRENT_REFERENCE_ONLY` context.

## 9. Enterprise Cloud organization audit evidence

### 9.1 Source and availability

**Verified.** `GET /orgs/{org}/audit-log` is an organization-owner capability documented for GitHub Enterprise Cloud. It supports phrase queries, time qualifiers, `per_page<=100`, and cursor pagination through `Link`. Classic PAT access requires `read:audit_log`; fine-grained PAT and GitHub App access uses organization **Administration: read**. See [Get the audit log for an organization](https://docs.github.com/en/enterprise-cloud@latest/rest/orgs/orgs?apiVersion=2026-03-10#get-the-audit-log-for-an-organization) and [Reviewing the audit log](https://docs.github.com/en/enterprise-cloud@latest/organizations/keeping-your-organization-secure/managing-security-settings-for-your-organization/reviewing-the-audit-log-for-your-organization).

Use a bounded phrase equivalent to `action:workflows.prepared_workflow_job created:...` and follow cursors. Audit collection is optional enrichment, not a baseline dependency, because many organizations are not Enterprise Cloud, tokens may lack owner/Administration access, and retention is shorter than many investigations.

### 9.2 `workflows.prepared_workflow_job`

**Verified.** GitHub documents `workflows.prepared_workflow_job` as being generated when a workflow job is started. It is not displayed in the audit-log web UI; it can be obtained through the REST API, export, or streaming. Documented fields include:

- `workflow_run_id`, `job_name`, `job_workflow_ref`;
- `calling_workflow_refs`, `calling_workflow_shas`;
- `environment_name`, `secrets_passed`;
- `is_hosted_runner`;
- `runner_id`, `runner_name`, `runner_labels`, `runner_owner_type`;
- `runner_group_id`, `runner_group_name`;
- `imposer_repo` and normal audit actor/repository/timestamp metadata.

See GitHub's [organization audit event reference for workflows](https://docs.github.com/en/organizations/keeping-your-organization-secure/managing-security-settings-for-your-organization/audit-log-events-for-your-organization#workflows).

Limitations are material:

- The documented event does **not** include an Actions `job_id` or `run_attempt`.
- `job_name` is user-controlled and non-unique; matrix jobs may share or derive names.
- The event reference lists `calling_workflow_refs`, `calling_workflow_shas`, and `job_workflow_ref` but does not define array ordering/pairing, nesting completeness, or whether every ref-shaped string is immutable. Preserve the raw arrays and validate their relationship before deriving call edges.
- `secrets_passed` lists secret names provided to the job. It does not show secret values, prove that an affected step could reference each secret, or prove actual access/exfiltration.
- A prepared/start event cannot represent an environment-blocked job that never starts.
- Audit retention and token/plan availability may omit the incident window.

**Design decision.** Store this event as optional corroboration. Correlate it only when `workflow_run_id`, event time, workflow refs, runner attributes, and job metadata yield a unique candidate. If multiple attempts/jobs remain possible, keep the event unattached or attached as ambiguous evidence; never merge attempts to force a join. Pair `workflows.rerun_workflow_run` (which documents `run_attempt` and rerun type) only as supporting temporal evidence, not as proof of a particular job join.

**Verified retention.** The organization audit log documents a 180-day event window. Only the most recent three months are displayed by default, so a `created` range is required for older retained events. This does not extend the retention of an event, guarantee that every plan emits every field, or apply to other audit products. CIRewind must record the query interval and oldest/newest returned event and validate prepared-job availability in the lab organization. See [Reviewing the organization audit log](https://docs.github.com/en/organizations/keeping-your-organization-secure/managing-security-settings-for-your-organization/reviewing-the-audit-log-for-your-organization#accessing-the-audit-log).

## 10. Workflow and Action reconstruction semantics

### 10.1 Repository and immutable-package Actions

- `uses: owner/repository[/path]@ref` can name a branch, tag, or full commit SHA. Runtime preparation logs are required to prove how a mutable ref resolved for an attempt.
- At an exact downloaded Action source SHA, retrieve `action.yml` and `action.yaml` through C1. Parse the metadata syntax for JavaScript, Docker, or composite actions; recurse through composite `uses` steps with cycle/depth/byte limits. [Metadata syntax for GitHub Actions](https://docs.github.com/en/actions/reference/workflows-and-actions/metadata-syntax).
- An immutable Action package log record has a package version, source commit SHA, and package digest. Preserve all three as separate identifiers. Do not call the digest an Action source SHA or a container digest.
- `uses: docker://image:tag` is a registry image reference, not a GitHub repository Action. GitHub's workflow syntax does not provide a general historical registry digest API for it; without a captured digest, retain only the declared ref. [Using a Docker Hub action](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#example-using-a-docker-hub-action).

### 10.2 Same-repository and local Actions

GitHub now documents `uses: $/path/to/action` for an Action in the same repository at the running workflow/Action commit. It requires runner `2.336.0` or later and is GitHub.com-only at the research cutoff. See [same-repository Action syntax](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#example-using-an-action-in-the-same-repository-as-the-workflow-at-the-running-commit-recommended) and GitHub's [2026-07-30 changelog](https://github.blog/changelog/2026-07-30-reference-same-repository-actions-with-self-repository-syntax/). Resolve `$` relative to the exact executing repository commit; do not treat it as a mutable default-branch lookup.

Archive the runner version when available. A historical `$` declaration on an older self-hosted runner cannot be assumed to have run successfully; reconcile it with status/log evidence and retain a contradiction if the sources materially disagree.

By contrast, `uses: ./path/to/action` refers to the checked-out workspace. GitHub documents that the repository must be checked out first. The bytes may therefore come from another checkout ref/repository or may have been modified by earlier commands. The workflow-definition commit alone cannot prove the local Action's runtime bytes. See [local Action syntax](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#example-using-an-action-in-the-same-repository-as-the-workflow).

**Design decision.** For `./` Actions, reconstruct the declared path and checkout provenance only when logs and historical steps establish it. If checkout/ref/workspace mutation is ambiguous, emit a transitive possibility/evidence gap, not an exact runtime identity. Never check out or execute the repository to “resolve” it.

### 10.3 Reusable workflows and secrets

- Reusable workflows are called at job level. A reference may target another repository/ref or use `./.github/workflows/file.yml` in the same commit and repository as the caller. Expressions are not allowed in the `uses` value. [Calling a reusable workflow](https://docs.github.com/en/actions/how-tos/reuse-automations/reuse-workflows#calling-a-reusable-workflow).
- `secrets: inherit` is supported for directly called workflows in the same organization or enterprise. Named secret mappings and inheritance apply only across the direct call boundary; a deeper workflow must receive/pass secrets again. [Passing secrets to nested workflows](https://docs.github.com/en/actions/how-tos/reuse-automations/reuse-workflows#passing-secrets-to-nested-workflows).
- `on.workflow_call` does not support passing an environment from the caller. If a called workflow job names an environment and an environment secret has the same name as a passed secret, GitHub documents that the environment secret is used. Model this as environment eligibility/gate evidence in the called job, not as the caller's named-secret mapping. [Reusable workflow environment-secret warning](https://docs.github.com/en/actions/how-tos/reuse-automations/reuse-workflows#using-inputs-and-secrets-in-a-reusable-workflow).
- Reconstruct each call edge at its exact caller/callee SHA. Do not flatten nested calls into one workflow or assume that a secret available to the caller was available to every descendant job/step.

## 11. Credential, environment, runner, and resource sources

### 11.1 Source matrix

| ID | Route/source | Needed fields | Minimum FG/App permission | Temporal/evidentiary limits |
|---|---|---|---|---|
| P1 | Job setup log, `GITHUB_TOKEN Permissions` group | permission name/value as printed for that job attempt | **Actions: read** via L1/L2 | Preferred effective-attempt evidence. Parser format must be fixture-tested. It says what the token could do, not what it did. |
| P2 | `GET /repos/{owner}/{repo}/actions/permissions/workflow` | `default_workflow_permissions`, `can_approve_pull_request_reviews` | Repository **Administration: read** | Current repository setting only; static fallback, never historical fact. [Get default workflow permissions for a repository](https://docs.github.com/en/rest/actions/permissions?apiVersion=2026-03-10#get-default-workflow-permissions-for-a-repository). |
| P3 | `GET /orgs/{org}/actions/permissions/workflow` | organization defaults | Organization **Administration: read** | Current organization setting only. [Get default workflow permissions for an organization](https://docs.github.com/en/rest/actions/permissions?apiVersion=2026-03-10#get-default-workflow-permissions-for-an-organization). |
| P4 | `GET /repos/{owner}/{repo}/actions/permissions`, repository `/selected-actions`; organization `/orgs/{org}/actions/permissions`, `/repositories`, `/selected-actions` | enabled policy, allowed Action/reusable-workflow policy, `sha_pinning_required` where returned, selected-repository coverage | Repository or organization **Administration: read**, matching route | Current execution policy only. Useful to explain collection-time configuration, never to prove what was permitted for a historical attempt. [Actions permissions endpoints](https://docs.github.com/en/rest/actions/permissions?apiVersion=2026-03-10). |
| P5 | Repository and organization `.../actions/permissions/artifact-and-log-retention` routes | retention days | Repository or organization **Administration: read**, matching route | Current configured retention only; expiry/deletion must be inferred from the actual source response, not this setting. [Artifact and log retention endpoints](https://docs.github.com/en/rest/actions/permissions?apiVersion=2026-03-10). |
| P6 | Organization/repository `.../actions/permissions/fork-pr-workflows-private-repos` and organization `.../fork-pr-contributor-approval` | whether fork workflows run, write tokens/secrets are sent, approval requirements | Repository or organization **Administration: read**, matching route | Current private-fork/approval policy. This is a static fallback for event analysis, not proof of historical settings. Enterprise policy can override organization/repository settings. [Fork PR Actions permission endpoints](https://docs.github.com/en/rest/actions/permissions?apiVersion=2026-03-10). |
| P7 | `GET /repos/{owner}/{repo}/actions/permissions/access` | private-repository Action/reusable-workflow `access_level` | Repository **Administration: read** | Current sharing policy for a private Action/workflow repository. It can explain why historical content is inaccessible now but cannot prove the policy at event time. [Get access restrictions](https://docs.github.com/en/rest/actions/permissions?apiVersion=2026-03-10#get-the-level-of-access-for-workflows-outside-of-the-repository). |
| S1 | `GET /repos/{owner}/{repo}/actions/secrets` | name, created/updated times only; list `per_page<=100`, `page` | Repository **Secrets: read** | Current metadata, never values; cannot prove historical existence or step access. [List repository secrets](https://docs.github.com/en/rest/actions/secrets?apiVersion=2026-03-10#list-repository-secrets). |
| S2 | `GET /repos/{owner}/{repo}/actions/organization-secrets` | visible shared org-secret names/visibility metadata; list `per_page<=100`, `page` | Repository **Secrets: read** | Current view of org secrets accessible to the repo, not historical eligibility. [List organization secrets for a repository](https://docs.github.com/en/rest/actions/secrets?apiVersion=2026-03-10#list-organization-secrets-for-a-repository). |
| S3 | `GET /orgs/{org}/actions/secrets` and selected-repository routes | name, visibility, selected repository metadata, times; lists `per_page<=100`, `page` | Organization **Secrets: read**; organization privileges/policy also apply | Optional owner/admin view; current only. Never retrieve, hash, compare, or store values. [List organization secrets](https://docs.github.com/en/rest/actions/secrets?apiVersion=2026-03-10#list-organization-secrets). |
| S4 | `GET /repos/{owner}/{repo}/environments/{environment_name}/secrets` | environment secret names/times; list `per_page<=100`, `page` | Repository **Environments: read** | Current metadata only. [List environment secrets](https://docs.github.com/en/rest/actions/secrets?apiVersion=2026-03-10#list-environment-secrets). |
| E1 | `GET /repos/{owner}/{repo}/environments` and `/environments/{name}` | names, protection rules, reviewers, wait timer, deployment branch/tag policy; list `per_page<=100`, `page` | Repository **Actions: read** | Current configuration; plan/visibility restrictions apply. It cannot prove historical gates. [Environments endpoints](https://docs.github.com/en/rest/deployments/environments?apiVersion=2026-03-10). |
| E2 | `GET /repos/{owner}/{repo}/actions/runs/{run_id}/pending_deployments` | environment and wait/protection state | Repository **Actions: read** | Point-in-time pending state; may disappear after approval/rejection. [Get pending deployments for a workflow run](https://docs.github.com/en/rest/actions/workflow-runs?apiVersion=2026-03-10#get-pending-deployments-for-a-workflow-run). |
| E3 | `GET /repos/{owner}/{repo}/actions/runs/{run_id}/approvals` | approval state, comment, environments, user, time if supplied | Repository **Actions: read** | Review history, combined with job start/setup, can support gate-crossing. Absence does not prove no gate existed. [Get review history for a workflow run](https://docs.github.com/en/rest/actions/workflow-runs?apiVersion=2026-03-10#get-the-review-history-for-a-workflow-run). |
| O1 | `GET /repos/{owner}/{repo}/actions/oidc/customization/sub` | `use_default`, included claim keys and immutable-subject configuration where returned | Repository **Actions: read** | Current subject template only; cannot establish historical token claims or external trust. Public resources may be queried unauthenticated. [Get repository OIDC customization](https://docs.github.com/en/rest/actions/oidc?apiVersion=2026-03-10#get-the-customization-template-for-an-oidc-subject-claim-for-a-repository). |
| O2 | `GET /orgs/{org}/actions/oidc/customization/sub` and current custom-property inclusion routes | organization subject claim keys / property inclusions | Organization **Administration: read** | Optional current organization template, subject to organization access. Classic PAT read uses `read:org` for the subject-template route; enterprise property sources require separate enterprise administration. [Actions OIDC endpoints](https://docs.github.com/en/rest/actions/oidc?apiVersion=2026-03-10). |
| H1 | R6 plus setup logs | runner ID/name/group, labels, hosted setup image/runner version | Repository **Actions: read** | Best historical attempt context. Blank IDs/names must remain unknown rather than guessed. |
| H2 | `GET /orgs/{org}/actions/runners` | id, name, OS, status, busy, ephemeral, version, labels; `per_page<=100`, `page` | Organization **Self-hosted runners: read** | Current inventory only; deleted/re-registered runners may not match historical state. [List self-hosted runners for an organization](https://docs.github.com/en/rest/actions/self-hosted-runners?apiVersion=2026-03-10#list-self-hosted-runners-for-an-organization). |
| H3 | `GET /repos/{owner}/{repo}/actions/runners` | same runner fields; `per_page<=100`, `page` | Repository **Administration: read** | Current repository-visible inventory only. [List self-hosted runners for a repository](https://docs.github.com/en/rest/actions/self-hosted-runners?apiVersion=2026-03-10#list-self-hosted-runners-for-a-repository). |
| H4 | `GET /orgs/{org}/actions/runner-groups` | group id/name, visibility, selected repo/workflow policy, inherited/restricted fields; `per_page<=100`, `page` | Organization **Self-hosted runners: read** | Current group configuration, not historical. [List self-hosted runner groups](https://docs.github.com/en/rest/actions/self-hosted-runner-groups?apiVersion=2026-03-10#list-self-hosted-runner-groups-for-an-organization). |

### 11.2 Credential conclusions

GitHub calculates `GITHUB_TOKEN` permission from enterprise/organization/repository defaults, then workflow and job declarations, then fork/Dependabot restrictions; `pull_request_target` is a special context. See [How permissions are calculated for a workflow job](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#how-permissions-are-calculated-for-a-workflow-job).

Therefore:

- P1 is preferred and labeled observed effective permissions for the specific job attempt.
- P2/P3 plus historical YAML/event semantics are a fallback labeled inferred. Current settings must carry collection time and cannot be backdated.
- A named secret is separately modeled as existing, referenced by YAML, passed to a job/workflow, passed to a step, inherited, or environment-eligible. None means “read” without step-specific evidence.
- GitHub states that a job cannot access environment secrets until required approval rules pass. A job that never starts because approval was withheld must not be labeled exposed. See [Deployment protection rules and environment secrets](https://docs.github.com/en/actions/reference/workflows-and-actions/deployments-and-environments).
- E3 is review history, not a complete historical configuration ledger for wait timers, branch restrictions, administrator bypass, or custom GitHub App protection rules. A historical job start plus its exact environment declaration can support that the job crossed the effective gate; absent review records cannot explain which rule allowed it.
- **Plan limits are evidence coverage.** Environment secrets are available to public repositories on GitHub Free and to private/internal repositories on GitHub Pro, Team, or Enterprise. GitHub Free/Pro/Team expose required reviewers and wait timers only for public repositories; private-repository use of those gates therefore requires an eligible Enterprise plan. Deployment branch/tag rules have their own documented plan/visibility limits. A `404`/empty response must not be interpreted as “no environment” until plan and repository access are established. [Deployments and environments plan notes](https://docs.github.com/en/actions/reference/workflows-and-actions/deployments-and-environments).
- `id-token: write` establishes `OIDC_MINTING_CAPABILITY` only. GitHub's OIDC provider and token claims do not reveal whether an external cloud trust policy accepted the identity. `CLOUD_IDENTITY_REACHABLE` requires separate relying-party policy evidence. [OpenID Connect](https://docs.github.com/en/actions/concepts/security/openid-connect).

As of July 2026, GitHub documents repository-ID-based immutable default OIDC subjects for newly created repositories and for certain renames/transfers, while older repositories can retain or opt into the earlier/name-based behavior. O1/O2 are collection-time settings, so CIRewind v0.1 must not reconstruct an exact historical `sub` from present settings. Preserve owner/repository numeric IDs and event/environment context for a future trust-policy adapter, but report only minting capability now. See [OIDC immutable subject claims](https://docs.github.com/en/actions/reference/security/oidc#immutable-subject-claims).

### 11.3 Optional downstream correlation

These endpoints are enrichments and must use language such as “produced by the run” where GitHub supplies a direct run association, or “observed after” where only temporal correlation exists. They do not establish attacker causation.

| ID | Route | Fields / pagination | Permission | Correlation rule |
|---|---|---|---|---|
| D1 | `GET /repos/{owner}/{repo}/actions/runs/{run_id}/artifacts` | artifact id/name/size/expired, created/updated/expires, digest, archive URL; `per_page<=100` | Repository **Actions: read** | Directly associated with `run_id`; the listed artifact object has no attempt/job/step identity. Across reruns, attribute only with independent log/time evidence or leave ambiguous. Treat archive contents as hostile and raw download as opt-in. [List workflow run artifacts](https://docs.github.com/en/rest/actions/artifacts?apiVersion=2026-03-10#list-workflow-run-artifacts). |
| D2 | `GET /repos/{owner}/{repo}/deployments` and deployment statuses | id, ref/SHA, task, environment, actor, timestamps/status; `per_page<=100` | Repository **Deployments: read** | Filter/correlate by immutable SHA and time where possible. A deployment after an affected step is not proof the attacker caused it. [List deployments](https://docs.github.com/en/rest/deployments/deployments?apiVersion=2026-03-10#list-deployments). |
| D3 | `GET /repos/{owner}/{repo}/releases` and release assets | id, tag, target commitish, author, created/published times, assets and asset digests where supplied; `per_page<=100` | Repository **Contents: read** | No generic job association. Correlate conservatively by exact commit, actor, and time; preserve ambiguity. [List releases](https://docs.github.com/en/rest/releases/releases?apiVersion=2026-03-10#list-releases). |
| D4 | `GET /orgs/{org}/packages?package_type=...` and package-version routes | package/version IDs, names, type, repository, visibility, timestamps, metadata; endpoint-specific page bounds | Authentication and package ACLs; classic PAT generally needs `read:packages`; App/user-token support is endpoint-specific | Optional and auth-fragmented; no general run/job join. Page-number multiplied by page size is documented to cap at 10,000 for the organization list. Record incomplete package types/ACLs. [List packages for an organization](https://docs.github.com/en/rest/packages/packages?apiVersion=2026-03-10#list-packages-for-an-organization). |
| D5 | `GET /repos/{owner}/{repo}/rulesets?includes_parents=true` | ruleset IDs, source/type, enforcement, bypass actors, rules; `per_page<=100`, `page` | Repository **Metadata: read** | Present-day policy context only. It cannot prove what protected the repository at event time. [Get all repository rulesets](https://docs.github.com/en/rest/repos/rules?apiVersion=2026-03-10#get-all-repository-rulesets). |
| D6 | `GET /repos/{owner}/{repo}/immutable-releases`; `immutable` on release objects | whether immutable releases are currently enabled/enforced; whether a returned release is immutable | Repository **Administration: read** for the settings check; D3 permission for release objects | Current/release context only. `404` is the documented disabled response for the settings check, but only after admin-read access is established. This policy does not replace the attempt log's exact Action package source SHA and digest. [Check immutable releases for a repository](https://docs.github.com/en/rest/repos/repos?apiVersion=2026-03-10#check-if-immutable-releases-are-enabled-for-a-repository), [release response](https://docs.github.com/en/rest/releases/releases?apiVersion=2026-03-10#list-releases). |
| D7 | `GET /repos/{owner}/{repo}/commits?since=...&until=...` | commit SHA, parents, commit author/committer and dates, GitHub actor IDs when available, signature verification; `per_page<=100`, `page` | Repository **Contents: read** | Candidate repository writes in a time range. Git author/committer dates are part of commit data and can be manipulated; this is not a server-side audit timestamp or job attribution. [List commits](https://docs.github.com/en/rest/commits/commits?apiVersion=2026-03-10#list-commits). |
| D8 | `GET /repos/{owner}/{repo}/pulls?state=all` plus pull commits/files/reviews as enabled | PR ID/number, head/base repos and SHAs, user, created/updated/merged times; list `per_page<=100`, `page` | Repository **Pull requests: read** | Candidate PR changes/current history. There is no run/job causality field; force pushes, deletion, and inaccessible forks can leave gaps. [List pull requests](https://docs.github.com/en/rest/pulls/pulls?apiVersion=2026-03-10#list-pull-requests). |

D7/D8 and richer audit correlation may remain optional adapters in v0.1. Without a direct GitHub run association, correlation must retain the rule, time tolerance, candidates, and competing explanations. `repository write reachable` is a token capability; `repository write occurred` needs a write event; `affected step caused write` needs direct attribution.

## 12. Authentication and permissions matrix

### 12.1 Recommended profiles

CIRewind should probe capabilities at startup and enable each source independently. It must never request write permission.

| Profile | Fine-grained PAT / GitHub App repository permissions | Organization permissions | Classic PAT scopes | Provides |
|---|---|---|---|---|
| Core private-repository collection | **Metadata: read**, **Actions: read**, **Contents: read** | none | `repo` | R1–R7, L1–L3, C1–C2 for repositories the token can read. |
| Secrets metadata enrichment | **Secrets: read**, **Environments: read** | optional **Secrets: read** | `repo`; organization secret inventory also requires appropriate `admin:org` access | S1–S4. Values are never available through list endpoints and must never be requested. |
| Settings and runner enrichment | repository **Administration: read** | **Administration: read**, **Self-hosted runners: read** as needed | `repo`, plus `admin:org` for organization settings/runners | P2/P3, H2–H4 and current Actions policies. |
| Enterprise audit enrichment | none additional at repository level | **Administration: read**; caller must meet documented owner/Enterprise Cloud constraints | `read:audit_log` | Organization audit API and prepared-job/rerun events. |
| Downstream resources | **Deployments: read**, **Contents: read**, **Actions: read**, optional **Pull requests: read** | package access varies | `repo`, optionally `read:packages` | D1–D8 within resource ACLs. |

Use GitHub's generated permission references as the final implementation checklist: [fine-grained PAT endpoint permissions](https://docs.github.com/en/rest/authentication/permissions-required-for-fine-grained-personal-access-tokens) and [GitHub App endpoint permissions](https://docs.github.com/en/rest/authentication/permissions-required-for-github-apps).

### 12.2 Token-type differences

- **Classic PAT.** Broad `repo` grants private repository access subject to the user's own access. Organization runner/settings/audit/package enrichments require additional scopes shown above. Organizations can forbid classic PATs.
- **Fine-grained PAT.** Bound to one resource owner and selected repositories, with individually approved permissions. Organization policy may require approval. Repository selection is part of the case envelope.
- **GitHub App installation token.** Bound to the App installation's selected repositories and installed permissions. R2, not a global organization list, defines what the installation can collect. GitHub documents installation access tokens as expiring after one hour; a long collection must refresh through an explicitly configured App credential flow or checkpoint and stop for a renewed token. It must not turn a mid-scan `401` into complete coverage. [Generating an installation access token](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-an-installation-access-token-for-a-github-app).
- **GitHub App user token.** Further constrained by both App permissions and the user/installation context; it must not be assumed equivalent to an installation token.
- **Public unauthenticated.** Some metadata and public run endpoints work without authentication, but the 60-request/hour primary limit and private/inaccessible ambiguity make this unsuitable for organization-scale investigations.

Enterprise organizations using SAML SSO may require a classic PAT to be separately authorized, while fine-grained PAT authorization follows organization approval/policy. An unauthorized private repository can appear as `404`; record SSO/authorization probes where available. See [Authorizing a personal access token for SSO](https://docs.github.com/en/enterprise-cloud@latest/authentication/authenticating-with-single-sign-on/authorizing-a-personal-access-token-for-use-with-single-sign-on).

**Design decision.** Provide a preflight report listing each source as `available`, `permission_denied`, `plan_unavailable`, `repository_not_selected`, `not_requested`, or `unverified`. Do not abort core collection because an optional enrichment is unavailable.

## 13. Events, forks, and trigger context

Event semantics determine where the workflow file came from and what credentials could be available. Collect the run event, head repository, head/base refs and SHAs available through run/PR/event metadata, actor and triggering actor. Consult the exact event documentation rather than treating `head_sha` uniformly: [Events that trigger workflows](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows).

Required conservative rules:

- `pull_request` commonly runs against a merge commit/context and fork-originated PRs receive restricted credentials. Repository settings and private-fork policy can alter behavior; capture the event and settings evidence rather than hardcoding one token conclusion.
- `pull_request_target` runs in the base/default-branch context. GitHub warns that running untrusted PR code in this event can expose write permissions or secrets. Its `GITHUB_SHA` is the last commit on the pull request's base branch, not the contributor head. Never retrieve the contributor's current branch and call it the executed workflow definition.
- `workflow_run` runs in the default-branch context and can access secrets/write tokens even if the triggering workflow could not. It is a new run and must be analyzed as such, with the triggering run linked separately.
- `issue_comment`, `repository_dispatch`, `workflow_dispatch`, `push`, `schedule`, and `workflow_call` have distinct SHA/ref/file-selection rules. Persist the event payload identifiers available to the run; do not infer one universal workflow commit.
- For fork pull requests, `head_repository` and base `repository` are distinct. GitHub normally restricts secrets and token permissions for untrusted forks, but organization/private-fork settings and `pull_request_target` are exceptions. Use P1 where retained.
- Dependabot pull requests are treated similarly to forked PRs for secrets/token restrictions. Record the actor and event rather than inferring solely from branch names.

Historical caller resolution tests must cover every v0.1 event type listed in the product scope. Failure to prove the definition commit yields `UNKNOWN_EVIDENCE_GAP`; substituting current YAML is prohibited.

## 14. Rate limits, retries, and concurrency

**Verified primary limits at the research cutoff:**

- unauthenticated REST: 60 requests/hour;
- authenticated user requests: normally 5,000/hour; certain GitHub Enterprise Cloud-associated user/App requests receive 15,000/hour;
- GitHub App installation requests: at least 5,000/hour; for a non-Enterprise-Cloud installation, add 50/hour for each repository above 20 and 50/hour for each organization user above 20, capped at 12,500/hour; an Enterprise Cloud organization installation receives 15,000/hour;
- primary limits are exposed in `x-ratelimit-limit`, `remaining`, `used`, `reset`, and `resource`;
- secondary controls include no more than 100 concurrent REST+GraphQL requests, generally 900 REST points/minute and 2,000 GraphQL points/minute, no more than 90 seconds of API CPU time per 60 seconds of real time (at most 60 seconds for GraphQL), and undisclosed abuse heuristics that can change.

See [Rate limits for the REST API](https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api). The implementation must not target those maxima.

**Design decision.** Use a global credential-aware limiter with low bounded concurrency, per-host redirect controls, and separate queues for metadata and large log downloads. On `403`/`429`, honor `Retry-After`; otherwise wait until `x-ratelimit-reset` for a depleted primary limit. For secondary limits without a header, stop and exponentially back off from at least one minute with jitter and a case-wide deadline. Continuing to hammer after a limit response can lead to integration bans. Follow [GitHub REST best practices](https://docs.github.com/en/rest/using-the-rest-api/best-practices-for-using-the-rest-api).

Follow pagination only through the response's `Link` relations, with a same-origin/API-path policy. See [Using pagination](https://docs.github.com/en/rest/using-the-rest-api/using-pagination-in-the-rest-api). Conditional requests with ETags can reduce primary-limit use when GitHub returns an authorized `304`; the archived evidence must still retain request/ETag/collection metadata and point to the previously hashed object.

Retries are allowed only for idempotent reads. Bound attempts and elapsed time; persist terminal failure. Never retry a redirected signed URL after expiry—request a fresh redirect from GitHub instead.

## 15. Retention and disappearance

**Verified.** GitHub Actions logs and artifacts default to 90-day retention. Public repositories can configure 1–90 days; private repositories can configure 1–400 days, subject to organization/enterprise limits. Retention changes apply to new artifacts/logs, not retroactively to existing objects. See [Configuring artifact and log retention](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/enabling-features-for-your-repository/managing-github-actions-settings-for-a-repository#configuring-the-retention-period-for-github-actions-artifacts-and-logs-in-your-repository).

Workflow runs and artifacts can also be deleted before configured expiry; deleting a run deletes its logs and artifacts. See [Removing workflow artifacts](https://docs.github.com/en/actions/how-tos/manage-workflow-runs/remove-workflow-artifacts).

When Enterprise audit is available, `workflows.delete_workflow_run` and `artifact.destroy` can corroborate why an object disappeared and identify a run. They do not recover the deleted bytes or convert the gap into a negative finding. See [workflow audit events](https://docs.github.com/en/organizations/keeping-your-organization-secure/managing-security-settings-for-your-organization/audit-log-events-for-your-organization#workflows) and [artifact audit events](https://docs.github.com/en/organizations/keeping-your-organization-secure/managing-security-settings-for-your-organization/audit-log-events-for-your-organization#artifact).

Retention consequences:

| Lost source | What remains possible | Required conclusion constraint |
|---|---|---|
| Attempt/job logs | Exact R5 reusable-workflow SHA and historical declarations may survive; archive may preserve prior extraction | No new `CONFIRMED_DOWNLOADED`/`CONFIRMED_EXECUTED` from static YAML alone. |
| Run/attempt API metadata | Archived case/ledger may be replayed | Live GitHub absence is an evidence gap; do not collapse attempts. |
| Historical Git commit/repository access | Previously hashed retrieved content may be used | Do not refetch a mutable ref and treat it as historical. |
| Audit events | Core run/log evidence remains | Secret-passed and caller/runner corroboration becomes unknown. |
| Current secret/environment/runner settings | Attempt logs/YAML may remain | Do not infer past configuration from absent current metadata. |

This is why archive is a core mode. Archive collection should preserve compact structured run, attempt, job, setup-log extractions, historical workflow/Action metadata, hashes, errors, and provenance before source expiry. Raw logs remain opt-in.

A content hash of a discarded log proves which bytes were once observed but cannot answer a newly published literal-log IOC. Compact replay is complete only for the structured fields/extractions the archive preserved. A pack requiring an unarchived literal must yield `UNKNOWN_EVIDENCE_GAP`; users who need future arbitrary-log replay must opt into raw-log retention with its privacy and storage costs. Do not use a probabilistic index as verifiable positive evidence.

## 16. Failure responses and fallbacks

GitHub's general semantics are documented in [Troubleshooting the REST API](https://docs.github.com/en/rest/using-the-rest-api/troubleshooting-the-rest-api). Endpoint pages remain authoritative for endpoint-specific status codes.

| Observation | Possible meanings | Required collector behavior |
|---|---|---|
| `401` | missing, invalid, revoked, or expired credential | Stop using that credential; retain sanitized error/request ID; mark remaining scope uncollected. |
| `403` | insufficient permission, SSO/policy/IP-allow-list block, feature/plan restriction, primary/secondary rate limit | Inspect rate headers and documented SSO header state without trusting error text as safe; redact any authorization URL. Distinguish when possible, otherwise retain ambiguity. Retry only documented rate/transient cases. |
| `404` | object genuinely absent/deleted **or** private/inaccessible | Never label “does not exist” without independent access proof. For a missing attempt/log/content object, record `UNKNOWN_EVIDENCE_GAP`; try documented bounded alternatives such as L2 after L1 or C2 after C1. |
| `410` | unsupported API version or unavailable/removed resource, depending on the endpoint | Use endpoint-specific classification. Treat a generic versioned JSON API failure as collector incompatibility; for L1/L2 use `RETENTION_OR_DELETION` only when the response confirms the requested selected API version, without asserting expiry versus deletion. |
| `422` | invalid parameters/validation failure, or abuse/spam response | Correct deterministic request bugs; otherwise retain error. Never skip a partition silently. |
| `429` | rate limit | Honor `Retry-After`/reset; bounded retry. |
| `5xx`, network timeout | transient GitHub/network failure | Retry idempotent reads with backoff/deadline; terminal failure remains a coverage gap. |
| `302` for logs | expected temporary download redirect | Apply L1/L2 redirect controls; hash final bytes; signed URL never retained. |
| malformed/truncated ZIP, YAML, JSON, or log | hostile/corrupt/incomplete source | Preserve original hash/status when safely acquired, stop bounded parser, record parser error; do not infer no match. |

The dated
[public read-only qualification](validation/2026-08-21-public-readonly-qualification.md)
observed endpoint-specific `410 Gone` from an old attempt-log route while its
parent, attempt, and jobs remained readable; the response also selected the
requested `2026-03-10` API version. For L1/L2, CIRewind therefore maps `410` to
the conservative `RETENTION_OR_DELETION` gap only with that selected-version
confirmation. It does not claim whether configured expiry or explicit deletion
caused the loss. A `410` without selected-version confirmation, or from ordinary
versioned JSON routes, remains `API_VERSION_UNSUPPORTED` unless that endpoint's
contract supplies another meaning.

Fallbacks must be ordered and explicit:

- attempt log archive -> individual job logs -> archived structured ledger -> evidence gap;
- Contents file at exact commit -> blob at previously resolved exact blob SHA -> archived hashed content -> evidence gap;
- effective permissions in job setup log -> historical YAML plus contemporaneous defaults/event rules -> inferred capability -> unknown;
- exact reusable SHA from R5 -> validated audit/GraphQL exact identity -> immutable historical declaration -> mutable-window/transitive state -> unknown;
- environment approval history plus job start -> gate crossed; pending/blocked evidence -> not crossed at observation; absent data -> unknown.

Every terminal failure becomes an evidence object containing logical source, repository/run/attempt/job keys, sanitized request parameters, status/error class, collection time, retry history, and permission/retention interpretation. API error strings are hostile and must be escaped in every report.

## 17. GitHub-hosted and self-hosted runner context

R6 runner fields, setup logs, and prepared-job audit records are historical evidence. H2–H4 are current inventory/configuration enrichment.

- For GitHub-hosted jobs, retain runner image label/version/link where logged. GitHub states hosted runners are newly provisioned virtual machines for jobs (with documented exceptions such as larger/managed configurations); do not infer persistence solely from a label. [GitHub-hosted runners](https://docs.github.com/en/actions/reference/runners/github-hosted-runners).
- For self-hosted jobs, retain runner ID, name, OS, labels, group, ephemeral flag/version if contemporaneously available, and evidence gaps. A self-hosted classification is context for possible persistence; it does not prove persistence or compromise.
- Current runner status/labels can change or a runner ID can disappear. Never overwrite historical R6/log/audit fields with H2–H4.
- GitHub recommends ephemeral self-hosted runners for autoscaling and notes external log forwarding for ephemeral runners; this is operational context, not proof that external telemetry exists for the case. [Self-hosted runner autoscaling and ephemeral runners](https://docs.github.com/en/actions/reference/runners/self-hosted-runners#ephemeral-runners-for-autoscaling).

If runner sources disagree, retain `CONTRADICTORY_EVIDENCE` rather than choosing the current inventory.

## 18. GitHub Enterprise Server exclusion

CIRewind v0.1 targets GitHub.com only. This is a correctness boundary, not merely a packaging preference.

GitHub Enterprise Server exposes version-specific REST documentation and release-dependent Actions behavior; GitHub.com's `2026-03-10` API, current GraphQL Actions schema, immutable Action packages, log grammar, and retention/plan capabilities cannot be assumed across GHES releases. The new `$` same-repository Action syntax is explicitly unavailable on GHES at the cutoff. Compare the versioned [GHES Actions REST reference](https://docs.github.com/en/enterprise-server@3.21/rest/actions) with the GitHub.com-only [same-repository syntax announcement](https://github.blog/changelog/2026-07-30-reference-same-repository-actions-with-self-repository-syntax/).

Adding GHES later requires a compatibility matrix by GHES release, configurable API base and TLS trust, fixture logs from each supported runner/server combination, schema capability probes, and separate acceptance criteria. v0.1 must reject non-GitHub.com API bases with a clear unsupported-target error rather than produce partially valid forensic conclusions.

## 19. Verified limitations and claims CIRewind must not make

| Limitation | Consequence |
|---|---|
| Logs are retained output, not full host/network telemetry | No claim of actual exfiltration, command execution side effects, or cloud-role assumption without direct evidence. |
| Action setup may happen before step conditions are evaluated | Download is not execution. |
| `head_sha` represents event/trigger context | It cannot stand in for workflow definition, caller, called workflow, Action source, or package digest. |
| Secret APIs expose metadata, and mostly current state | Secret existence is not step readability; never retrieve values. |
| Current settings/rulesets/runners can differ from historical state | Label them collection-time context or inferred fallback. |
| R3 filtered search caps at 1,000 | Recursive partition; a saturated minimum bucket is an explicit gap. |
| Temporary log URLs expire in one minute | Acquire immediately; archive hashes/structured extraction. |
| Private inaccessible objects can look like `404` | Missing is not safe/no-match. |
| Audit prepared-job events lack job ID and attempt | Optional ambiguous corroboration; never force a join. |
| `$` and GraphQL Actions fields are recent GitHub.com features | Capability-probe and retain spike results; do not generalize to GHES or old runners. |
| A downstream artifact/deployment/release follows a run | Temporal/direct-run association is not attacker causation. |

## 20. Feasibility-spike validation register

The two-week spike must turn each item below into a dated fixture plus a recorded GitHub response. A failed validation becomes a v0.1 limitation, not an undocumented heuristic.

| Question | Experiment | Go criterion | No-go / scope-reduction criterion |
|---|---|---|---|
| Can resolution, completed preparation, and execution be distinguished? | Direct, skipped, cancelled, failed, composite, matrix, JS, Docker, and immutable-package steps; compare R6 timing and L1/L2 markers | Announcement, completed preparation, and lifecycle start are independently deterministic across supported runner fixtures without false promotion | Ambiguous completion disables `CONFIRMED_DOWNLOADED`; ambiguous lifecycle join disables `CONFIRMED_EXECUTED` for the affected grammar. |
| Are all attempts addressable? | Full, failed-job, and single-job reruns; request every R5/R6/L1 integer attempt | Earlier attempt metadata/jobs/logs are retrievable and do not merge | Missing/ambiguous prior attempts become explicit gaps; archive must collect promptly. |
| How do ordinary Action refs behave on rerun? | Move controlled `v1` between attempts and restore | Each attempt's logs independently identify actual preparation | No static rerun rule is adopted; runtime/archived evidence only. |
| What parent-run watch bound safely captures in-window reruns and delayed jobs? | Use a pre-aged parent if available plus time-shifted deterministic fixtures; compare R3/R5/R6 times and determine whether the 35-day lifetime is anchored to original creation | Provisional 65-day query finds the parent; reducing to 35 days is allowed only with reproducible anchor proof and boundary overlap | Keep 65 days and publish its request cost; the CLI must never query only `[from,to)` by parent creation. |
| Is reusable identity complete? | Multi-level reusable -> composite -> Action, mutable callee ref; all rerun types | R5 SHAs match controlled commits and chain shape is known | Support only returned exact edges; unresolved nesting is `POTENTIAL_TRANSITIVE`/gap. |
| Does GraphQL identify executed caller immutably? | Query `WorkflowRun.file`, `repositoryFileUrl`, `runAttempt` for each event/rerun and inaccessible caller | Exact commit extraction is stable, permission behavior known, previous attempts correctly bounded | GraphQL stays corroboration only. |
| Can caller workflow commit be recovered for each event? | `push`, `pull_request`, `pull_request_target`, `workflow_run`, `issue_comment`, `repository_dispatch`, `workflow_dispatch`, `schedule`, `workflow_call` | Exact C1 fetch agrees with executed fixture for each supported path | Event is reported unsupported for exact declaration or yields a gap; never use current YAML. |
| Is R3 partition exhaustive? | Generate >1,000 runs in a broad window and boundary runs at split timestamps, or use a controlled/mocked replay plus feasible live density; probe full unfiltered pagination as a saturated-leaf fallback | Partition tree returns every known run exactly once after dedup, and either validates or rejects the fallback explicitly | Organization-scale investigate cannot claim complete for saturated leaves. |
| Can audit events be joined safely? | Enable Enterprise audit; nested reusable workflows, matrix/reruns with duplicate job names, and secret mappings; test ref/SHA array pairing | Unique joins and call-array semantics are demonstrable using multiple fields; ambiguity preserved | Audit remains unattached/raw corroboration only. |
| Do environment conclusions hold? | Approved, rejected, timed-out, and never-approved jobs | Gate-crossing requires approval evidence plus job start; blocked job never labeled secret-eligible | Environment exposure remains unknown where history is insufficient. |
| Are runner formats stable? | GitHub-hosted and self-hosted runner, current runner versions, audit and R6 comparison | Classification and parser version recorded; contradictions surfaced | Unknown runner/log version is a gap rather than guessed. |

## 21. Primary-source catalog

Sources below were retrieved on **2026-08-20** unless a later dated validation
note is linked inline. The Git tag-object endpoint was added and retrieved on
**2026-08-21**. Inline links above point to the precise endpoint or behavior.
This catalog is the review checklist for future updates.

### REST/API behavior

- [REST API versions](https://docs.github.com/en/rest/about-the-rest-api/api-versions)
- [Workflow runs REST endpoints](https://docs.github.com/en/rest/actions/workflow-runs?apiVersion=2026-03-10)
- [Workflow jobs REST endpoints](https://docs.github.com/en/rest/actions/workflow-jobs?apiVersion=2026-03-10)
- [Repositories REST endpoints](https://docs.github.com/en/rest/repos/repos?apiVersion=2026-03-10)
- [Repository contents REST endpoints](https://docs.github.com/en/rest/repos/contents?apiVersion=2026-03-10)
- [Git blobs REST endpoints](https://docs.github.com/en/rest/git/blobs?apiVersion=2026-03-10)
- [Git tags REST endpoints](https://docs.github.com/en/rest/git/tags?apiVersion=2026-03-10)
- [Rate limits for REST](https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api)
- [REST best practices](https://docs.github.com/en/rest/using-the-rest-api/best-practices-for-using-the-rest-api)
- [REST troubleshooting](https://docs.github.com/en/rest/using-the-rest-api/troubleshooting-the-rest-api)
- [Fine-grained PAT permissions](https://docs.github.com/en/rest/authentication/permissions-required-for-fine-grained-personal-access-tokens)
- [GitHub App permissions](https://docs.github.com/en/rest/authentication/permissions-required-for-github-apps)

### Actions semantics and maintained implementations

- [Actions workflow syntax](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax)
- [Workflow syntax: background steps](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#jobsjob_idstepsbackground)
- [Events that trigger workflows](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows)
- [Reusing workflow configurations](https://docs.github.com/en/actions/concepts/workflows-and-actions/reusing-workflow-configurations)
- [Reusing workflows](https://docs.github.com/en/actions/how-tos/reuse-automations/reuse-workflows)
- [Action metadata syntax](https://docs.github.com/en/actions/reference/workflows-and-actions/metadata-syntax)
- [Actions limits](https://docs.github.com/en/actions/reference/limits)
- [Re-running workflows and jobs](https://docs.github.com/en/actions/how-tos/manage-workflow-runs/re-run-workflows-and-jobs)
- [Using workflow run logs](https://docs.github.com/en/actions/how-tos/monitor-workflows/use-workflow-run-logs)
- [GitHub security incident investigation tools](https://docs.github.com/en/code-security/reference/security-incident-response/investigation-tools)
- [GitHub Actions runner source](https://github.com/actions/runner)
- [GitHub-maintained audit-actions-workflow-runs](https://github.com/github/audit-actions-workflow-runs)
- [GraphQL Actions schema](https://docs.github.com/en/graphql/reference/actions)
- [Organization audit workflow events](https://docs.github.com/en/organizations/keeping-your-organization-secure/managing-security-settings-for-your-organization/audit-log-events-for-your-organization#workflows)

### Context and enrichment

- [Actions secrets endpoints](https://docs.github.com/en/rest/actions/secrets?apiVersion=2026-03-10)
- [Actions permissions endpoints](https://docs.github.com/en/rest/actions/permissions?apiVersion=2026-03-10)
- [Deployment environments endpoints](https://docs.github.com/en/rest/deployments/environments?apiVersion=2026-03-10)
- [Self-hosted runners endpoints](https://docs.github.com/en/rest/actions/self-hosted-runners?apiVersion=2026-03-10)
- [Self-hosted runner groups endpoints](https://docs.github.com/en/rest/actions/self-hosted-runner-groups?apiVersion=2026-03-10)
- [Artifacts endpoints](https://docs.github.com/en/rest/actions/artifacts?apiVersion=2026-03-10)
- [Deployments endpoints](https://docs.github.com/en/rest/deployments/deployments?apiVersion=2026-03-10)
- [Releases endpoints](https://docs.github.com/en/rest/releases/releases?apiVersion=2026-03-10)
- [Packages endpoints](https://docs.github.com/en/rest/packages/packages?apiVersion=2026-03-10)
- [Repository rulesets endpoints](https://docs.github.com/en/rest/repos/rules?apiVersion=2026-03-10)
- [Commits endpoints](https://docs.github.com/en/rest/commits/commits?apiVersion=2026-03-10)
- [Pull requests endpoints](https://docs.github.com/en/rest/pulls/pulls?apiVersion=2026-03-10)
- [Artifact and log retention](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/enabling-features-for-your-repository/managing-github-actions-settings-for-a-repository#configuring-the-retention-period-for-github-actions-artifacts-and-logs-in-your-repository)

## 22. Maintenance rule

Before each CIRewind release, rerun the capability probes, review GitHub's REST changelog and current GraphQL schema, update the pinned API version only through an ADR/reviewed migration, and refresh affected fixtures. A changed response shape or log grammar must fail closed into an evidence gap. It must never silently downgrade `CONFIRMED_EXECUTED`, `CONFIRMED_DOWNLOADED`, or `CONFIRMED_CALLED_WORKFLOW` provenance.
