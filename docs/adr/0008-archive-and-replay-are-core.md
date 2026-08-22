# ADR 0008: Archive and replay are core capabilities

## Status

Accepted for v0.1.

## Date

2026-08-20

## Context

Historical logs and definitions may expire or become inaccessible before an incident is disclosed. An investigation-only tool would then confuse missing evidence with safety. The product's strategic value depends on preserving a privacy-aware execution ledger in advance and applying later incident knowledge without relying on mutable GitHub state.

Archive and replay are therefore part of the evidence contract, not optional reporting polish.

## Decision

- Ship `archive` and `replay` in v0.1 alongside `investigate` and incident-pack validation. The v0.1 definition of done is not met without all four modes.
- Use the same normalized identifiers, source/evidence objects, coverage model, historical resolver contracts, semantic state engine, and schema across live investigation and archived evidence.
- Make archive collection incremental, content-deduplicated, checkpointed, and attempt-preserving. Revisit a provisional rolling 65-day parent-run watch set—the conservative combination of documented 30-day rerun eligibility and 35-day run lifetime—until the spike proves a shorter parent-anchored bound. Collection never rewrites an earlier observation merely because a later observation differs.
- Make replay network-disabled by construction: no GitHub client, DNS/HTTP path, pack-directed I/O, or current-ref lookup participates. Replay consumes an immutable archive snapshot, validated pack bytes, explicit policy, semantic-engine/parser versions, and an injected case clock.
- Given identical inputs and supported versions, replay must produce byte-stable normalized findings and deterministic ordered exports apart from explicitly documented container metadata. Every conclusion cites archived evidence; missing archive capability produces a gap.
- Preserve archive schema/version, extractor capabilities, hashes, collection errors, raw-retention status, and migration provenance so replay cannot imply evidence that was never saved.

## Consequences

- Newly published incidents can be evaluated after source retention loss when the necessary structured evidence was archived.
- Archive schema stability, migrations, deterministic fixtures, and compatibility policy become release-critical work.
- Collection and storage cost arrive in v0.1 instead of being deferred.
- Replay cannot recover discarded raw content, repair every old extractor error, or prove facts outside archived coverage. It must report those limits.
- The common analysis engine reduces semantic drift between live and offline cases.

## Revisit criteria

Storage formats, retention profiles, and compatibility windows may evolve from measured cases, but archive/replay remain core unless the product contract itself changes. Any migration that could alter historical findings requires reproducible before/after fixtures, preserved original hashes, and explicit derivation-version behavior.
