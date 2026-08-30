# Incident-pack review path-confinement variant audit

Date: 2026-08-30

Status: local pre-commit engineering validation. No reviewed real incident pack,
external approval, release, or remote publication is established by this record.

## Result

A pre-commit review found one root-cause family in the new incident-pack review
governance implementation: decoded path or identifier fields could be recorded
as invalid in an accumulated diagnostic set and still reach a host-filesystem
read before the validator returned the error. The invalid review material could
not pass validation and file bytes were not returned, but the behavior violated
the hostile-input boundary and could expose a bounded local file existence or
content-equality oracle.

Severity was assessed as **medium**, with **high confidence**. The affected
flows were corrected before commit or publication. A repository-wide variant
hunt found no active recurrence after the correction and no confirmed instance
outside `internal/packreview`.

## Root cause and corrected flows

The root-cause statement used for the audit was:

> A hostile decoded path or identifier reaches a host-filesystem operation
> after non-fatal validation records an error but before that error becomes a
> control-flow guard.

The corrected flows are:

1. `SourceRecord.archivePath` could use a `fixtures/` prefix while traversing
   outside `candidate-content/` before the accumulated safe-path error was
   returned.
2. `Packet.incidentId` and `Packet.packVersion` could influence the derived
   candidate-copy path before their accumulated identifier errors were
   returned.
3. Registry incident/version identifiers and `reviewedPath` could influence
   review-unit or reviewed-pack reads before registry validation errors were
   returned.

`ValidateUnit` now rejects all path-bearing packet and source fields before any
content-derived filesystem lookup. Governance validation now returns every
policy or registry semantic error before registry fields can influence tree
traversal, review-unit lookup, or reviewed-pack reads. Fixture scenario paths
were reviewed as an adjacent look-alike and were already safe because only a
validated scenario ID and its exact derived path can reach a read.

## Search methodology

The audit generalized one element at a time from the exact archived-source
sink to the full repository. All results were read in context.

| Level | Pattern family | Tool | Matches reviewed | Active after fix |
|---|---|---:|---:|---:|
| Exact | `SourceRecord.ArchivePath` joined below candidate content | `rg` | 1 | 0 |
| Path conversion | Production `filepath.FromSlash` joins | `rg` | 8 | 0 |
| Struct-field join | Non-test `filepath.Join` with a struct field | Semgrep | 11 | 0 |
| Filesystem surface | Non-test `filepath.Join` candidates | Semgrep and `rg` | 36 | 0 |
| Direct sink | Struct fields passed to `os.*` filesystem calls | Semgrep | 3 | 0 |
| Control-flow intersection | Diagnostic accumulation plus a filesystem sink before the corresponding error return | manual data-flow review | all candidates above | 0 |

The search also covered `os.Open`, `os.OpenFile`, `os.ReadFile`, `os.Lstat`,
`os.Stat`, `os.Remove`, `os.Mkdir`, and `os.Rename`, decoded fields whose names
end in `Path`, and identifier fields used by path constructors. Broader patterns
that matched remote GitHub repository paths, diagnostic-only paths, or explicit
operator-selected CLI paths were stopped at triage because they did not share
the host-filesystem trust boundary.

## False-positive groups

- Case manifest entries are rejected by the relative-path contract before
  access; raw case paths are derived from validated SHA-256 values and exact
  descriptor equality.
- Release license paths fail immediately unless they are canonical relative
  paths. Release artifact descriptor names must match the fixed distribution
  layout before reads.
- Archive raw-object paths are derived only from validated SHA-256 values;
  transient source paths are process-created and are not serialized input.
- ZIP entry names are validated before content is opened and are never
  extracted to the host filesystem.
- Workflow and Action paths are normalized before GitHub API retrieval and do
  not become local filesystem paths.
- Maintainer-tool, store, and ledger paths are explicit operator-selected
  locations, not incident-pack-controlled paths with accumulate-and-continue
  validation.

One informational design constraint remains: reusable-workflow resolution
relies on the production `ContentSource` enforcing repository-path safety. A
future filesystem-backed `ContentSource` would require a fresh confinement
review.

## Regression guards

`internal/packreview/path_confinement_test.go` exercises:

- an archived-source traversal aimed at an existing out-of-tree marker;
- an unsafe packet identity aimed at an existing escaped hard-linked candidate
  copy; and
- invalid registry `reviewedPath`, incident ID, and pack version values.

The tests require the direct path diagnostic and prohibit downstream
read-derived diagnostics, demonstrating rejection before dereference. Future
review code should fail CI whenever a decoded path or path-forming identifier
can reach a host-filesystem sink after only a non-fatal diagnostic. Prefer an
immediate return or a dedicated validated/derived path value.

## Retained JSON shape parity

The adjacent retained-record boundary was also checked against all 14 review
schemas and all 13 concrete governance document types consumed by the local
tool. The streaming shape pass now rejects, before typed decoding:

- explicit `null` for every non-nullable scalar, object, array, and array
  element;
- omission of every exported field whose JSON contract is not `omitempty`.

The complete strict-decoding pipeline additionally rejects duplicate keys,
unknown fields, trailing values, excessive nesting, excessive object members,
excessive array values, invalid UTF-8, byte-order marks, and oversized files.

`Claim.canonicalPointer` is the sole intentional nullable field and carries an
explicit Go metadata tag corresponding to the schema's nullable branch.
Optional fields may still be omitted, and schema-valid empty arrays remain
distinct from omitted or `null` arrays. Reflection-backed regression tests
inventory every current Go slice path and exercise missing required fields,
explicit nulls, null array elements, optional omission, and semantic non-empty
requirements. Adding a new retained record field therefore requires the test
inventory and strict-decoder contract to remain aligned.

This is parser/schema conformance evidence, not evidence that any incident-pack
claim is factually true or independently reviewed.
