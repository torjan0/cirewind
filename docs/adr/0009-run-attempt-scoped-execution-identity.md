# ADR 0009: Execution identity is scoped to run attempt and job

## Status

Accepted and normative.

## Date

2026-08-20

## Context

A GitHub Actions run may be rerun in full or in a subset such as failed or selected jobs. Mutable Action or reusable-workflow references, retained metadata, triggering actor, and available logs may differ between attempts. `head_sha`, workflow path, job name, and run ID alone cannot identify everything that ran. Merging attempts could turn one attempt's exact resolution into a claim about another.

The external minimum execution identity is `run_id + run_attempt + job_id`. CIRewind also needs repository identity to prevent cross-repository ambiguity and survive name changes.

## Decision

- Use `(repository_id, run_id, run_attempt, job_id)` as the primary job-execution key. Require a positive attempt number, including attempt 1. Preserve the externally meaningful `run_id + run_attempt + job_id` tuple in every finding and export concerning job execution.
- Scope runtime observations, step identities, Action resolutions, permissions, runner context, credential reachability, and downstream correlations to that key. Never join a setup-log observation from one attempt or job to a lifecycle marker in another.
- Store repository, workflow path, workflow-definition Git object ID, trigger Git object ID, caller workflow Git object ID, called reusable-workflow Git object ID, Action-source Git object ID, typed package digest, event, actor, triggering actor, event time, and collection time as separate fields. Each Git object ID carries its algorithm plus full value; digest namespaces remain distinct. Do not substitute `head_sha` for any of them.
- Enumerate and preserve every visible attempt and the jobs actually represented for that attempt. A failed-job or single-job rerun does not imply that unlisted jobs executed again; missing expected evidence becomes a typed coverage gap.
- Bind called workflows and mutable Actions using attempt-specific recorded runtime evidence when available. Do not re-resolve a historical mutable ref against its current target.
- Keep original actor/trigger context and rerun initiator metadata separate. Do not infer or recalculate effective privileges from the later actor alone.

## Consequences

- Findings can distinguish a tag target or called workflow that changed between attempts.
- Schemas, caches, fixture names, and report URLs need composite keys and cannot use run ID or job display name as shorthand internally.
- Partial reruns create intentionally sparse attempt/job sets. Coverage accounting is required to distinguish “not rerun,” “not returned,” and “evidence unavailable.”
- Workflow-level propositions without a job remain representable, but they cannot be upgraded to job execution until a job-scoped join is supported.

## Revisit criteria

If GitHub exposes a stronger immutable execution identifier, store it as an additional identifier and validate it in the controlled lab. Never use a new identifier to merge previously separate attempts unless primary evidence and migration fixtures prove semantic equivalence.
