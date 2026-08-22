# ADR 0002: Semantic evidence states rather than a risk score

## Status

Accepted and normative.

## Date

2026-08-20

## Context

Incident responders must distinguish what was declared, downloaded, executed, called, inferred, contradicted, or lost to retention. A single numeric risk score would blend different propositions and could make a weak static indication appear equivalent to exact runtime evidence. It would also obscure evidence gaps and encourage unsupported claims about secret access, cloud-role assumption, or downstream causation.

The evidence model already defines ten mutually named semantic states and a separate provenance ladder. Provenance expresses the support for a proposition, not its severity or remediation priority.

## Decision

- Every finding has exactly one of these state values, spelled exactly as shown:
  - `CONFIRMED_EXECUTED`
  - `CONFIRMED_DOWNLOADED`
  - `CONFIRMED_CALLED_WORKFLOW`
  - `DECLARED_AT_RUN_SHA`
  - `RUN_IN_WINDOW_MUTABLE_REF`
  - `POTENTIAL_TRANSITIVE`
  - `CURRENT_REFERENCE_ONLY`
  - `NO_MATCH_CONFIRMED`
  - `UNKNOWN_EVIDENCE_GAP`
  - `CONTRADICTORY_EVIDENCE`
- Attach one internal provenance value, `L4_CERTAIN` through `L0_UNKNOWN`, to the finding's bounded proposition. Reports emphasize the semantic state; the level may support filtering and machine-readable output.
- Keep different propositions as separate findings even when they concern the same run attempt or step. Exact runtime evidence for one proposition does not erase a contradiction or coverage gap concerning another.
- Permit prioritization views only as transparent, non-evidentiary sorting over preserved findings. Do not persist or present an opaque aggregate risk score as a conclusion.
- Derive states with versioned deterministic rules and cited evidence IDs. Absence may become `NO_MATCH_CONFIRMED` only when the required, bounded coverage proof is complete; otherwise use `UNKNOWN_EVIDENCE_GAP` where applicable.

## Consequences

- Users can tell runtime fact from historical declaration, possibility, contradiction, and absence of evidence.
- Filtering is more verbose than comparing one number, and case rollups must retain all underlying states instead of collapsing them.
- Adding or changing a state is a schema and compatibility event. Existing stored findings must retain their original state semantics and derivation version.
- Severity, business impact, credential-rotation policy, and evidence provenance remain distinct dimensions.

## Revisit criteria

Add a semantic state only when a real proposition cannot be represented without ambiguity, fixtures demonstrate the distinction, and a versioned schema migration preserves previous meaning. Do not revisit this decision merely to simplify dashboards or produce a single executive score.
