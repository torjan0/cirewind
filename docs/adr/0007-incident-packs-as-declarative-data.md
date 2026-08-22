# ADR 0007: Incident packs are declarative data

## Status

Accepted and normative.

## Date

2026-08-20

## Context

Incident knowledge changes independently of the binary and benefits from public review, source attribution, deterministic validation, and offline replay. Packs are also an untrusted supply-chain input. Allowing scripts, templates, arbitrary requests, embedded HTML, or unrestricted expressions would give a pack author code execution, network access, denial-of-service primitives, or report-injection paths.

## Decision

- Represent incident knowledge as a versioned declarative document beginning with `apiVersion: cirewind.dev/v1alpha1` and `kind: GitHubActionsIncident`.
- Restrict packs to schema-defined identifiers, component exposure windows, exact SHAs and digests, mutable refs, subpaths, typed literal IOCs, known-good values, source provenance, confidence, guidance, and rotation triggers. Matching and finding derivation remain reviewed CIRewind engine behavior, not pack-supplied logic.
- Prohibit executable scripts, shell commands, templated network requests, embedded HTML, environment expansion, file includes, and outbound requests. Unrestricted regular expressions are prohibited; any future pattern field requires a schema revision, a complexity-bounded engine, explicit length limits, and adversarial tests.
- Parse with duplicate-key rejection, alias/expansion and depth limits, strict types, bounded counts and strings, typed Git object IDs, typed digest namespaces, explicit time bounds/precision/approximation, deterministic validation, and canonical hashing. Unknown or ambiguous security-relevant fields are rejected rather than ignored.
- Preserve the exact pack bytes, canonical hash, schema version, pack version, source attribution per indicator, and validation result with the case.
- Admit real incident indicators only when reviewers can verify them against primary sources. Clearly marked synthetic fixtures must use reserved/non-real values and must never be presented as a real incident pack.
- Require community submissions to pass schema, safety, determinism, source-provenance, duplicate/overlap, and fixture tests plus human review under the documented pack-review policy.

## Consequences

- New incident knowledge can be reviewed and applied offline without shipping arbitrary code.
- Packs cannot implement bespoke parsing or collection; the binary must add a reviewed typed capability when needed.
- Strict rejection may delay packs whose primary advisories are incomplete or ambiguous, but avoids fabricating indicators or silently guessing windows.
- Schema and pack versions become evidence inputs and must be preserved in finding derivations.

## Revisit criteria

Add fields through a backwards-compatible schema change only when semantics remain deterministic and safe. Use a new API version for changed meanings or validation behavior. Do not add executable extension points; new matching capabilities belong in reviewed engine code with bounded inputs.
