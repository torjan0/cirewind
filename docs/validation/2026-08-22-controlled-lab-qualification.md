# Controlled GitHub.com lab qualification — 2026-08-22

Status: **GO for the controlled explicit-repository qualification inside the
experimental v0.1 envelope**. Hosted CI, repository controls, release
attestations, and publication remain separate gates.

This is a sanitized public record. The controlled repositories, object IDs,
run IDs, job IDs, actors, and artifact hashes are intentionally omitted. They
remain in the maintainer's private qualification record and are not product
fixtures or incident indicators.

## Scope and handling

The lab used private repositories containing harmless synthetic Actions and
workflows. A mutable `v1` tag was moved from safe commit A to harmless test
commit B, workflows were run, selected jobs were rerun, and the tag was restored
to A before collection conclusions were reviewed. Fake secret names and harmless
marker output were used. No exfiltration, destructive behavior, production
target, or real secret value participated.

Collection used an existing process-only read credential. CIRewind made only
read requests. Raw-log retention was disabled, so the qualification archive kept
compact facts, hashes, parser versions, request provenance, coverage, and errors
rather than log bodies. Authentication material and temporary signed URLs were
neither printed nor retained. Databases and generated cases stayed outside the
repository.

The scenarios correspond to the public A–P definitions in
[`TEST_STRATEGY.md`](../TEST_STRATEGY.md#scenario-acceptance-matrix-ap). Labels
below identify semantics, not private GitHub objects.

## Central A→B→A result

The controlled runs established all three necessary runtime boundaries:

1. a runner-owned resolution/download record identified exact Action source B;
2. completed preparation established that B was downloaded; and
3. a separately correlated lifecycle frame established that the matching Action
   step began.

The direct affected run retained B as `CONFIRMED_EXECUTED`. The condition-skipped
control retained B as `CONFIRMED_DOWNLOADED` and had no execution lifecycle. A
full rerun preserved attempt 1 with B and attempt 2 with restored A under the
same parent run without merging the jobs or identities. Present-day tag state did
not alter either historical conclusion.

This is the central feasibility result: exact runtime evidence, not the current
tag or current workflow, decides which attempt downloaded or began the test
commit. No downloaded-only control was promoted to `CONFIRMED_EXECUTED`.

## Historical and transitive reconstruction

- Direct repository Action metadata was retrieved at the evidenced source object
  and parsed without executing it.
- A composite wrapper and its nested repository Action were reconstructed from
  exact historical metadata. Wrapper and child occurrences remained distinct.
  In both the direct-composite and reusable-workflow variants, the final
  candidate retained exact parent and child lifecycle start and completion
  records. The strict child join used the runner-owned marker immediately after
  the parent frame; the parent start alone was not treated as child execution.
- A reusable workflow calling a composite wrapper retained the GitHub-recorded
  called-workflow tag object separately from the peeled commit used to retrieve
  exact content.
- Failed-job and single-job reruns stayed on their own attempt and job identities;
  the recorded called-workflow object was not silently replaced by a current ref.
- Historical definitions and current default-branch content remained separate.
  Deliberately disagreeing exact declaration/runtime evidence produced
  `CONTRADICTORY_EVIDENCE` rather than selecting one source silently.
- Local workspace content that could not be proven from an exact retained object
  remained an evidence gap. CIRewind did not check out or execute fetched code.

Dynamic or otherwise ambiguous nested step names remain outside the recognized
live grammar. They produce a scoped gap rather than a permissive transitive
execution claim.

## Credential, environment, and runner conclusions

- Runtime-observed effective `GITHUB_TOKEN` permissions remained distinct from
  static reconstruction.
- Direct fake named-secret flow was reported only for the affected step whose
  exact historical `env`/`with` mapping and lifecycle supported it.
- `secrets: inherit` was represented as a reusable-workflow inheritance
  relationship, not proof that every repository or organization secret was read.
- A job blocked at an environment gate received no environment-secret eligibility
  or Action-execution conclusion.
- `id-token: write` produced only `OIDC_MINTING_CAPABILITY`; no cloud identity,
  token exchange, role assumption, or cloud compromise was claimed.
- GitHub-hosted and controlled self-hosted runner classifications used retained
  runner-owned evidence. No persistence or lateral-movement claim was inferred.

Downstream objects, where present, were described only as context or as observed
after a job. The lab provides no basis to claim malicious causation.

## Missing and partial evidence

A dedicated missing-log control was collected once compact facts had been
retained and then had its server-side logs removed. A later collection preserved
the metadata and classified the unavailable log route as a retention/deletion
gap. Replay produced `UNKNOWN_EVIDENCE_GAP`; it did not produce
`NO_MATCH_CONFIRMED` or a clean bill of health.

Other bounded gaps remained visible for unsupported workflow/log syntax,
unavailable exact caller identity, ambiguous matrix correlation, or missing
historical content. Positive findings include scoped gap explanations in JSON,
CSV, HTML, and the relational case instead of serializing absent collections as
`null`.

## Integrity and recovery checks

- Run attempts and jobs remained keyed by repository, run, attempt, and job; no
  materially different attempt was merged.
- Every finding linked to retained evidence or an explicit gap record, and every
  material graph edge linked supporting evidence.
- SQLite integrity and foreign-key checks passed for the audited archive and
  generated case.
- The generated manifest verified, and a byte change, missing file, or unexpected
  file caused verification to fail.
- Finalized case databases were checkpointed and sealed without WAL sidecars
  before manifest generation. Ordinary read-only inspection did not invalidate a
  case.
- Replay accepted committed archive facts still present in a crash-recovery WAL,
  while finalized-case readers rejected unexpected sidecars. A clean archive
  close checkpointed and removed sidecars.
- Raw retention remained disabled; no `raw/` case directory was emitted.

## Coverage boundary

This lab qualifies the controlled explicit-repository path and the runner
records it generated. It does not prove:

- completeness for a GitHub organization with an unsplittable 1,000-result
  second;
- every classic PAT, fine-grained PAT, or GitHub App visibility combination;
- live immutable Action package grammar;
- every GitHub-hosted or self-hosted runner version and localization;
- current package, release, deployment, or secret-inventory joins; or
- exact runtime bytes for an unarchived local workspace Action.

These are explicit experimental-v0.1 limitations under
[`ADR 0011`](../adr/0011-experimental-v0-1-qualification-envelope.md), not implied
successful coverage.

## Final candidate archive and replay

The fresh raw-disabled archive completed with:

- 591 normalized compact facts;
- 353 evidence objects;
- 9 explicit baseline coverage gaps;
- 22 separate run attempts; and
- 24 separate jobs.

SQLite `quick_check` returned `ok`, `foreign_key_check` returned no rows, and no
raw sidecar or case `raw/` directory existed. The nine archive coverage gaps are
not finding counts: they record conservative ambiguity, unavailable PR-base
context, retention loss, and unrecognized setup layout at their affected scopes.

Offline replay produced 56 findings:

| Canonical state | Count |
| --- | ---: |
| `CONFIRMED_EXECUTED` | 12 |
| `CONFIRMED_DOWNLOADED` | 2 |
| `CONFIRMED_CALLED_WORKFLOW` | 0 |
| `DECLARED_AT_RUN_SHA` | 0 |
| `RUN_IN_WINDOW_MUTABLE_REF` | 0 |
| `POTENTIAL_TRANSITIVE` | 37 |
| `CURRENT_REFERENCE_ONLY` | 0 |
| `NO_MATCH_CONFIRMED` | 0 |
| `UNKNOWN_EVIDENCE_GAP` | 5 |
| `CONTRADICTORY_EVIDENCE` | 0 |

One downloaded-only finding is the condition-skipped control; the other retains
exact preparation with deliberately ambiguous matrix lifecycle correlation. The
large transitive count is a set of evidence-linked dependency propositions, not
37 unique compromised runs. Zero counts mean that this particular private pack
did not select those propositions; they do not erase the separate reusable,
drift, contradiction, and no-match regression coverage.

The direct-composite and reusable-composite controls each retained exact parent
and child starts and completions. The skipped control had no lifecycle. Tag-move
rerun attempts remained separate, and failed-job/single-job rerun attempts 1, 2,
and 3 remained strict. Direct secret mapping, one-hop inheritance, OIDC
capability-only language, and runner classification matched their expected
evidence boundaries.

Both `cirewind verify` and an independent `sha256sum --check manifest.sha256`
accepted the finalized case. Its SQLite `quick_check` returned `ok` and its
foreign-key check returned no rows. Chromium 147 loaded the report with one
local file request, zero external requests, zero console errors, verified CSP
hashes, and a working state filter showing the two downloaded-only findings.

Exact private arguments and paths remain in the maintainer transcript. The
sanitized command shape was:

```sh
cirewind archive --repo <controlled-repository> --from <utc-start> --to <utc-end> --store <archive.db>
cirewind replay --archive <archive.db> --incident <controlled-pack.yaml> --out <case-directory>
cirewind verify <case-directory>
(cd <case-directory> && sha256sum --check manifest.sha256)
```

The ephemeral controlled pack stayed outside the repository and was deleted
after qualification. Transient raw downloads used to inspect the controlled
runner grammar were also deleted. No private repository, run, job, object, or
artifact identifier was copied into this public record.
