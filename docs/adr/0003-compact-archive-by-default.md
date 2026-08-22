# ADR 0003: Compact archive by default

## Status

Accepted for v0.1.

## Date

2026-08-20

## Context

GitHub evidence can disappear under retention policies, so CIRewind must preserve incident-agnostic execution facts before an incident is published. Full logs and API payloads can be large and can contain sensitive application output despite masking. Keeping everything by default would increase privacy, custody, and storage risk and would make routine organization-wide archival harder to justify.

A compact archive cannot guarantee answers to every future indicator. In particular, a literal that appeared only in discarded free-form output cannot be recovered later. Replay must describe that limitation as coverage, not silently treat it as a negative match.

## Decision

- Archive by default the normalized, incident-agnostic evidence needed by supported v0.1 analyzers: repository/run/attempt/job identity; typed exact Action source-ID and immutable-package observations; distinct download-announcement and preparation-completion observations; structurally identified lifecycle observations; effective token-permission observations; runner and reusable-workflow metadata; historical workflow and Action-definition bytes needed for reconstruction; secret-name flow metadata without values; collection requests, errors, coverage, hashes, parser versions, and derivation provenance.
- Deduplicate content-addressed historical-definition payloads and exact evidence objects while appending every collection observation, logical source association, event time, collection time, and run-attempt association.
- Do not retain complete logs or unrelated raw API response bodies in the default archive. Record their source hash and byte length when safely available, whether the original was retained, and which normalized extractor capabilities ran.
- Make the archive capability-aware. Replay must know which evidence classes and extractor versions are present. A future pack requiring an unpreserved evidence class yields an explicit coverage gap and must not produce `NO_MATCH_CONFIRMED` from that missing class.
- Support incremental checkpoints without merging materially different run attempts or overwriting earlier observations.

## Consequences

- Routine archival has a smaller storage footprint and lower exposure to sensitive build output.
- New incidents involving Action SHAs, immutable digests, declarations, and preserved structured observations can be evaluated after upstream logs expire.
- Future free-form log indicators may be unanswerable unless the operator explicitly retained raw logs. Reports must say so.
- Extractor defects cannot always be repaired from a compact archive; parser version and coverage metadata therefore become part of the evidence contract.
- Schema evolution and content deduplication require migration, integrity, and deterministic-replay tests.

## Revisit criteria

Expand the default archive only when a bounded evidence class has demonstrated broad future incident value, can be stored without secret values, has an explicit retention/privacy budget, and has deterministic extraction semantics. A request for complete future re-parsing belongs to the explicit raw-retention mode rather than silently changing the default.
