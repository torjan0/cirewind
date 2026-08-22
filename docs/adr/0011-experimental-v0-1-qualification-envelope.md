# ADR 0011: Experimental v0.1 qualification envelope

## Status

Accepted for v0.1.

## Date

2026-08-22

## Context

The original plan intentionally set a broad release bar: live organization-scale
collection, every credential form, dense-window saturation, multiple runner and
immutable-package grammars, and exact joins for optional GitHub resources. That
bar was useful for finding evidence-model defects, but it combines the minimum
defensible product with a much larger compatibility program.

The controlled GitHub.com lab now exercises the central product claim against
explicit repositories: a harmless mutable tag moved from safe commit A to test
commit B and back to A; attempts retained their own exact runtime identities;
download-only evidence remained distinct from a step start; reusable-workflow
objects and peeled commits remained distinct; missing logs remained gaps; and
credential conclusions stayed conservative. The credential-free offline demo,
archive/replay path, hostile-input tests, case outputs, and manifest verification
provide the deterministic release baseline.

Not every GitHub.com deployment shape has equivalent live evidence. In
particular, organization result-ceiling behavior, every PAT/GitHub App permission
profile, immutable Action package log output, every runner version, and exact
optional-resource joins are mock- or fixture-qualified only. Treating those as
implicitly supported would be misleading. Blocking all public evaluation until
that compatibility matrix is exhaustive would also hide a useful, bounded tool.

## Decision

CIRewind v0.1 is an **experimental, evidence-first release** with the following
qualification envelope:

- The supported live collection target is GitHub.com. Controlled live
  qualification covers explicitly selected repositories and the documented lab
  grammar. Organization enumeration and recursive date partitioning are present,
  but organization-wide completeness—especially an unsplittable 1,000-result
  second—is not a v0.1 support claim. Saturation or inaccessible scope must
  produce partial coverage.
- Runtime conclusions are supported only for grammars and exact joins the
  collector recognizes. Unknown runner layouts, ambiguous custom/dynamic names,
  missing logs, local workspace bytes, and absent historical definitions produce
  gaps or lower semantic states. They never fall back to substring execution
  claims or `head_sha` as a universal identity.
- Classic PAT, fine-grained PAT, and GitHub App differences follow the official
  source matrix, but the full live permission matrix is not qualified in v0.1.
  Optional denial is expected to degrade coverage rather than abort unrelated
  collection.
- Traditional repository-Action records are live-qualified. Immutable Action
  package parsing and digest precedence are fixture- and mock-qualified until a
  controlled live immutable-package record is available. Reports expose that
  capability boundary.
- Historical remote Action, composite Action, and reusable-workflow resolution
  is supported when exact source objects are retained. Annotated called-workflow
  tag objects and peeled commits are separate evidence. Runtime local Action
  workspace bytes remain unprovable from GitHub data alone and therefore remain
  a gap.
- Effective token permissions, named-secret mapping or inheritance, environment
  eligibility, OIDC minting capability, and runner classification are reported
  only where the documented exact evidence join succeeds. Secret inventories,
  cloud trust, runner persistence, and causal downstream-resource claims are not
  v0.1 features.
- Artifacts and other optional resources are context only when a defensible
  run/attempt/job join exists. Full package, release, deployment, secret, and
  runner inventories are not collected merely because a REST route exists.
- Offline pack validation, compact archive/replay, case generation, focused graph
  generation, and manifest verification are core supported v0.1 behaviors. Replay
  performs no network access and cannot recover facts the archived extractor did
  not retain.
- The measured compact relational envelope is 300,000 facts. Replay rejects a
  snapshot above 1,000,000 facts or 256 MiB of materialized compact data. A
  3,000,000-fact reference run exceeded the two-hour qualification budget; it is
  outside the v0.1 envelope rather than evidence of supported scale.
- Release archives may be published for the targets produced by the reviewed
  CGO-disabled build. Only platforms with recorded native runtime results are
  described as runtime-qualified; cross-compilation or Wine is labeled as such.

The ten canonical finding states, five provenance identifiers, eight mandatory
invariants, evidence traceability requirements, hostile-input boundaries, and
read-only/no-secret/no-execution rules are not narrowed. A finding without
supporting evidence or an explicit evidence-gap record is invalid.

## Release decision rule

The experimental release may proceed when the controlled explicit-repository
lab, deterministic offline demo, manifest verification, default test suite,
race detector, vet, hostile-input audits, dependency/license checks, and release
packaging gates pass on the exact candidate revision. Failures inside the
qualification envelope remain blocking. Unqualified items listed above are
non-blocking only when documentation and output coverage state them explicitly.

This decision permits public evaluation; it does not describe CIRewind as
production-ready, complete for every organization, or a substitute for responder
judgment. Operators must review coverage before acting on a negative or lower-
confidence result.

## Consequences

- v0.1 can be released with a narrow, testable claim rather than an implied
  universal GitHub Actions reconstruction claim.
- Dense organizations, unfamiliar runner layouts, unavailable logs, local
  Actions, and denied optional permissions will often yield partial cases.
- Compatibility evidence can expand incrementally without changing the semantic
  model or weakening earlier gaps.
- Performance work above the measured compact envelope is deferred; the hard
  snapshot guards remain security and reliability boundaries.

## Revisit criteria

Expand the envelope only with retained, sanitized live observations and matching
offline regressions. Candidate expansions include organization saturation and
rate-limit behavior, representative token types, live immutable packages,
additional runner layouts, precise downstream-resource joins, and streaming
replay beyond the current snapshot guard. No expansion may weaken the mandatory
invariants or turn absent evidence into a negative conclusion.
