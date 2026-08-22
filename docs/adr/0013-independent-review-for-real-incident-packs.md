# ADR 0013: Independent review for real incident packs

## Status

Accepted for v0.2 on 2026-08-22.

## Date

2026-08-22

## Context

Incident-pack safety/schema validation can prove that data is bounded,
declarative, internally consistent, and deterministic. It cannot prove that a
SHA, digest, mutable-ref window, known-good identity, IOC, or remediation claim
is factually correct.

CIRewind's initial real incidents contain difficult source conditions: moved
tags, abbreviated Git objects, approximate times, transitive wrappers,
component-specific namespaces, large IOC tables, and conflicting patched-version
claims. A pack written and “qualified” only by the same author or automated
session would not provide external falsifiability.

The existing incident-pack specification requires at least two maintainer
approvals for real data. The v0.2 adoption release also requires outside human
review and, for the multi-component Trivy incident, two independent outside
reviewers.

## Decision

- Keep review status outside the frozen `cirewind.dev/v1alpha1` pack schema.
  Authors cannot make a pack trusted by setting a field in the pack.
- Separate `research`, `candidate`, `review_in_progress`, `reviewed`,
  `superseded`, and `withdrawn` states in a deterministic registry.
- Require a source-to-field claim matrix for every material pack value and
  deliberate omission. Bind source-object hashes, claims, fixtures, validator
  policy, original YAML hash, and canonical pack hash in an immutable candidate-
  content manifest. Freeze that content in commit C; later approval records bind
  C plus the manifest hash and remain outside it, avoiding a self-referential
  hash cycle. A separate promotion/review-record manifest covers approvals and
  the promotion record.
- Preserve source precision and conflicts. Exclude or explicitly encode
  uncertainty; never silently average sources or invent exact identities/times.
- Retain the existing two-maintainer approval requirement for every real pack.
  Add at least one independent outside technical reviewer for each pack. For the
  v0.2 launch packs, outside reviewers are external to the CIRewind
  maintainer/core implementation team and occupy distinct human approval slots.
- Name a human preparer-of-record for every candidate. That person owns source
  transcription/DCO responsibility and cannot fill either maintainer approval
  slot for the same candidate. Staff two distinct eligible non-preparer,
  non-transcriber project maintainers before promotion.
- Require two distinct independent outside technical reviewers for the March
  2026 Trivy ecosystem pack. Both reproduce component/window/IOC extraction
  checks. Maintainer acceptance does not substitute for either.
- Disqualify the candidate author/source transcriber, bots, CI, automated
  assistants, generated approvals, and schema validators from independent review
  credit.
- Bind each approval to the exact candidate commit, candidate-content manifest,
  and pack hashes. Any material change makes
  approval stale and requires a new pack version/review cycle.
- Store each review record as canonical `review.json` with a deterministically
  generated `REVIEW.md` human view. JSON is the machine-readable source of truth,
  but it cannot certify itself: independent human approval requires a GitHub
  pull-request approval against the exact reviewed commit. A material change
  invalidates that PR approval and its recorded review.
- Permit compatible external human roles to overlap only when the reviewer did
  not author or transcribe the material they independently review. A lab
  reproducer may also perform cold-reader/accessibility review, and a pack
  reviewer may also perform final skeptical review under that rule. Role overlap
  never reduces required distinct reviewer counts, including Trivy's two outside
  reviewers.
- Treat Xygeni as a nonblocking candidate excluded from the v0.2 release by
  default. It can be promoted only with exact malicious identity, affected ref,
  source-precision-aware timing, recorded conflicts, deterministic fixtures, and
  independent review satisfying this decision.
- Keep published versions and approval history immutable. Corrections create new
  versions; withdrawal adds a visible tombstone and never erases the reviewed
  record.
- Exclude candidates from release archives, reviewed indexes, quickstarts,
  sample-site claims, and commands presented as ready for incident response.
- Treat missing required human review as a release gate, not as an implementation
  task automation can complete or waive.

The complete packet/status/approval/test contract is defined by
[`REAL_INCIDENT_PACK_REVIEW.md`](../REAL_INCIDENT_PACK_REVIEW.md).

## Consequences

- Real packs take longer to ship and depend on reviewer availability.
- A candidate without two eligible non-author/non-transcriber project-maintainer
  approvers cannot be promoted. With only Maksim identified at baseline, this
  means at least one additional maintainer if Maksim can approve that candidate,
  or two additional maintainers if Maksim is its preparer-of-record.
- Candidate research can proceed and remain useful without being mislabeled
  reviewed.
- Users can trace each material field to reviewed source objects and see
  unresolved conflict/precision decisions.
- Exact approval/hash records improve accountability but do not become digital
  signatures or guarantees of truth.
- Trivy has a deliberately higher review cost because one pack spans multiple
  components, windows, and namespaces.

## Alternatives rejected

- **Schema validation alone:** proves format, not facts.
- **Single author/maintainer self-review:** provides no independent
  transcription or source check.
- **Automated factual approval:** tools cannot judge source authority, conflicts,
  or incident context and cannot be independently accountable.
- **Trust a secondary IOC list:** risks namespace loss, stale values, and
  fabricated precision.
- **Put `reviewed: true` in the pack:** lets data assert its own trust and makes
  status easy to copy without history.
- **Mutable “latest” pack with overwritten history:** breaks replay and finding
  revision provenance.
- **Delay all review tooling until after candidate creation:** encourages facts
  that cannot be mapped or reproduced.

## Acceptance conditions

- ADR acceptance and the reviewer-count policy are recorded above.
- Strict review schemas, registry transition checks, manifests, hash binding,
  source-claim coverage, stale-approval detection, and candidate-exclusion tests
  pass.
- Required human approvals exist on exact final content; no automated or
  self-authored record is counted.
- Reviewdog, tj-actions, and Trivy pass their candidate-specific stop conditions;
  Trivy has two independent outside approvals.

## Revisit criteria

Revisit reviewer counts only through a public decision record explaining how the
replacement preserves independence and source-to-field verification. A shortage
of reviewers or desired release date is not by itself evidence that a lower bar
is safe. Pack signing/transparency logs may be added later, but signatures cannot
replace factual review.
