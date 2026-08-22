# ADR 0006: GitHub.com only in v0.1

## Status

Accepted for v0.1.

## Date

2026-08-20

## Context

GitHub Enterprise Server spans server and API versions, deployment-specific retention and authentication policies, runner versions, and feature availability. CIRewind's core claims depend on exact attempt, log, workflow, and reusable-workflow evidence. Claiming GHES support without a versioned compatibility lab would make evidence semantics depend on an untested installation.

GitHub Enterprise Cloud organizations hosted on GitHub.com still use the GitHub.com target, although optional capabilities vary by plan and operator permissions.

## Decision

- Support GitHub.com as the only execution evidence platform in v0.1. This includes public/private repositories and supported Enterprise Cloud organizations hosted on GitHub.com, subject to observed permissions and feature availability.
- Exclude GitHub Enterprise Server from collection, compatibility claims, fixtures, and support guarantees. Fail configuration that attempts to select a GHES API host rather than silently operating with partial semantics.
- Version GitHub API requests as documented, record request parameters and relevant response metadata, and represent unavailable plan-, repository-, or permission-dependent enrichments as coverage gaps.
- Permit only the GitHub.com API/content endpoints and validated, short-lived download redirects required by reviewed collectors. This scope decision does not authorize arbitrary hosts found in fetched data.
- Keep provider/transport boundaries explicit enough that GHES can be evaluated later without weakening the domain and evidence contracts.

## Consequences

- The feasibility spike and v0.1 compatibility matrix can test one evolving platform deeply.
- GHES operators receive a clear unsupported result instead of findings built on uncertain endpoint or log behavior.
- Some organizations cannot use v0.1 even if most endpoints appear similar.
- GitHub.com behavior can still vary by plan, token type, repository visibility, retention, and permissions; those variations remain explicit evidence coverage, not assumed support.

## Revisit criteria

Consider GHES only after v0.1 semantics are stable and the project has a versioned server/runner compatibility matrix, controlled GHES fixtures, endpoint and permission research, retention tests, and a release/support policy for server versions. Adding a configurable base URL alone is insufficient.
