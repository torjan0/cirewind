# ADR 0004: Raw logs are opt-in

## Status

Accepted for v0.1.

## Date

2026-08-20

## Context

Run and job logs are valuable source evidence but may contain application output, personal data, credentials accidentally printed outside GitHub's masking rules, terminal controls, and attacker-crafted text. Retaining every log by default creates a disproportionate privacy and custody burden. At the same time, some forensic workflows need exact source bytes for independent re-parsing.

## Decision

- Fetch logs when required for analysis, process them with strict streaming and archive limits, and discard complete log bodies after compact evidence extraction unless the operator explicitly enables raw retention.
- Raw retention requires an explicit command option and an explicit case/archive destination. It is never activated by an incident pack, configuration embedded in fetched content, or report interaction.
- When retained, store exact source bytes separately under the case's `raw/` area with restrictive permissions, content hash, byte length, media type, source identifier, collection time, redaction status, and manifest coverage. Never store request authorization headers or CIRewind authentication material.
- Do not intentionally identify, extract, index, or copy secret values from logs. Warn that an opted-in exact raw object may nevertheless contain sensitive values that GitHub did not mask. Any redacted derivative is a separate evidence object and must not be mislabeled as the original.
- Never render raw bytes directly in HTML, terminal output, CSV, paths, or SQL. Viewing/exporting uses the same escaping, terminal-control removal, size bounds, and evidence labeling as every hostile input.
- A compact structured evidence record remains the default even when raw retention is enabled, so findings do not depend on an unsafe presentation path.

## Consequences

- Default cases minimize unnecessary retention of sensitive build output.
- Operators who need independent parser review can preserve exact inputs with an explicit custody decision.
- Discarded raw logs cannot later be re-parsed for newly discovered free-form indicators or extractor fixes; replay records the resulting evidence gap.
- Opted-in cases require stronger handling, sharing, deletion, and access-control discipline. GitHub masking is not treated as a confidentiality guarantee.

## Revisit criteria

Revisit retention controls if a supported evidence source cannot be reduced without losing the product's core execution distinction, or if field experience supports a safer bounded intermediate representation. Raw retention must remain explicit unless a future major version adopts a separately reviewed privacy and custody contract.
