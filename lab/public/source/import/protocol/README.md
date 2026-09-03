# Public A-to-B-to-A protocol

This protocol produces harmless public evidence for testing whether CIRewind
keeps historical Action identity separate from the current state of a mutable
tag. Marker A and marker B print fixed public strings only. B is an affected
synthetic marker, not malware or a real compromise.

The checked-in object manifest is authoritative for the import commit, marker A
and B commits, annotated fixture-tag objects, peeled commits, and initial
lightweight `v1` target. Do not substitute short hashes or confuse an annotated
tag object with the commit to which it peels.

An ordinary GitHub fork is not a qualified laboratory. Repository Action and
reusable-workflow `uses:` bytes are bound to the repository name selected by
`BuildForRepository`; a plain fork would continue to call the original
repository. Generate an owner-specialized bundle with the
`--repository OWNER/REPOSITORY` argument to `go run ./tools/publiclab build` and
import it into a new, separately owned, empty repository. Its specialized object
manifest and import commit are authoritative.

## Authority boundary

Building, importing, or validating this source package does not authorize a
remote repository change. A live exercise requires the maintainer's explicit
authorization for the operator-asserted disposable repository database ID,
owner/name, remote URL, reviewed main commit, and A/B transition. Git transport
cannot verify the asserted ID. CIRewind itself never moves a tag.

The tag-control tool accepts only `refs/tags/v1`, an exact A-to-B or B-to-A
transition, a literal acknowledgement, and an exact expected-old-object lease.
It verifies the reviewed main and immutable fixture-tag topology before and
after the push. A readback target alone does not prove that this invocation made
the change; an unconfirmed same-target race fails.

`refs/heads/main` remains exactly import commit I through qualification. Publish
the sidecar and observations on protected, append-only, non-default
`refs/heads/observations`. The branch advances only by fast-forward, and every
published object is cited using its immutable full commit URL and content hash.
Record publication must not change the workflow-definition commit. Use a
separate publication clone; a linked worktree is not an accepted boundary. The
tag-control clone remains on `main` at I.

The tag-control Git boundary does not inspect worktree content or claim that it
is clean. It validates the branch, exact object topology, and exact remote, then
pushes reviewed object IDs. Avoiding `status`, `diff`, and similar content
inspection also avoids repository-controlled clean filters. Production accepts
only a repository-matching GitHub.com HTTPS or SSH remote; local filesystem
remotes are test-only.

## Sequence

1. Generate the bundle for the exact destination by passing
   `--repository OWNER/REPOSITORY` to `publiclab build`, import it into a new
   empty repository, and verify the bundle, object manifest, owner/name, remote
   URL, `main -> I`, annotated fixture tags, and `v1 -> A`. Supply the GitHub
   repository database ID only as `--assert-repository-id`: Git cannot observe
   it, so qualification must later cross-check the assertion against run/API
   evidence.
2. Create protected non-default `refs/heads/observations` without advancing
   `main`, and commit the exact sidecar manifest there from a separate clone.
   Dispatch and record a baseline only if the qualification plan calls for one.
3. Move `v1` from exact A to exact B with `publiclab move-v1`, using exact policy
   objects, the literal acknowledgement, and a new
   `--observation-out` file outside the tag-control clone. The output is
   pre-reserved before remote mutation. Preserve the output record whether the
   command confirms success or reports a reconciled failure; proceed only after
   it confirms exact B.
4. Dispatch direct, composite, reusable, skipped, matrix, and rerun-control
   workflows. Record every `run_id + run_attempt + job_id`; display names and
   `head_sha` are not execution identity.
5. Wait for terminal job states and retained logs. Do not restore early merely
   to shorten the protocol.
6. Restore `v1` from exact B to exact A with a second `publiclab move-v1`
   invocation, exact lease, literal acknowledgement, and a new
   `--observation-out` file outside the tag-control clone. The output is
   pre-reserved before remote mutation. Read back A before claiming success.
   Restoration is the first recovery action after any failure while B is
   installed.
7. Run `publiclab render-pack-input` with the reviewed source/schema/artifact,
   exact install and restore observation records, a canonical UTC `--created-at`,
   and a new `--out` path. Commit both tag-move records and the generated
   pack-input record under their record IDs in one immutable commit on
   `refs/heads/observations`. Generate the synthetic pack with `publiclab
   render-pack` only after all three exact derivation blobs have that immutable
   full-commit URL. The pack is derived from this pre-case input, not from a run
   record, finding, or case. Commit the generated pack later on
   `refs/heads/observations` without advancing `main`.
8. Request full-workflow, failed-jobs, and single-job reruns after restoration.
   Record new attempts and job IDs without assuming their Action or called-
   workflow identity.
9. Collect a raw-disabled CIRewind case, verify its manifest, compare it with
   `expected-findings.seed.json`, and preserve every discrepancy or evidence
   gap. The seed is not a live oracle and contains no invented run identity.
10. Generate and publish the run record as a later immutable commit on
    `refs/heads/observations`, leaving `main` at I. Validate it with the exact
    pack-input bytes so the operator-asserted repository database ID and exact
    A-to-B-to-A observations are cross-checked against the later collected
    run/API record. Reproduction validation requires both that run record and
    the same pack input. Complete [reset-checklist.md](reset-checklist.md).

The mutating and pack-input command shapes are:

```text
go run ./tools/publiclab move-v1 \
  --worktree ABSOLUTE_TAG_CONTROL_CLONE \
  --repository OWNER/REPOSITORY --assert-repository-id REPOSITORY_DATABASE_ID \
  --remote REVIEWED_GITHUB_COM_HTTPS_OR_SSH_REMOTE \
  --reviewed-main IMPORT_COMMIT_I \
  --commit-a MARKER_A_COMMIT --commit-b MARKER_B_COMMIT \
  --fixture-a-tag-object FIXTURE_A_TAG_OBJECT \
  --fixture-b-tag-object FIXTURE_B_TAG_OBJECT \
  --expected-old MARKER_A_COMMIT --new-target MARKER_B_COMMIT \
  --ack "I acknowledge moving OWNER/REPOSITORY refs/tags/v1 from MARKER_A_COMMIT to MARKER_B_COMMIT" \
  --observation-out ABSOLUTE_EVIDENCE_DIR/install-tag-move.json

# Repeat move-v1 for restoration with expected-old B, new-target A, the exact
# B-to-A acknowledgement, and
# --observation-out ABSOLUTE_EVIDENCE_DIR/restore-tag-move.json.

go run ./tools/publiclab render-pack-input \
  --source lab/public/source \
  --schema-dir lab/public/source/import/protocol \
  --artifact-dir OWNER_SPECIALIZED_ARTIFACT_DIR \
  --install-record ABSOLUTE_EVIDENCE_DIR/install-tag-move.json \
  --restore-record ABSOLUTE_EVIDENCE_DIR/restore-tag-move.json \
  --created-at CANONICAL_UTC_RFC3339_TIME \
  --out ABSOLUTE_EVIDENCE_DIR/PACK_INPUT_RECORD.json

# Commit ABSOLUTE_EVIDENCE_DIR/PACK_INPUT_RECORD.json as
# observations/PACK_INPUT_RECORD_ID.json in the same immutable commit as the
# exact install and restore records on refs/heads/observations, then:
go run ./tools/publiclab render-pack \
  --source lab/public/source \
  --schema-dir lab/public/source/import/protocol \
  --artifact-dir OWNER_SPECIALIZED_ARTIFACT_DIR \
  --record ABSOLUTE_EVIDENCE_DIR/PACK_INPUT_RECORD.json \
  --install-record ABSOLUTE_EVIDENCE_DIR/install-tag-move.json \
  --restore-record ABSOLUTE_EVIDENCE_DIR/restore-tag-move.json \
  --record-source-url https://github.com/OWNER/REPOSITORY/blob/PACK_INPUT_COMMIT/observations/PACK_INPUT_RECORD_ID.json \
  --record-source-worktree ABSOLUTE_SEPARATE_OBSERVATIONS_CLONE \
  --out ABSOLUTE_EVIDENCE_DIR/SYNTHETIC_INCIDENT_PACK.yaml

go run ./tools/publiclab validate-record \
  --source lab/public/source \
  --schema-dir lab/public/source/import/protocol \
  --artifact-dir OWNER_SPECIALIZED_ARTIFACT_DIR \
  --kind run-record \
  --record ABSOLUTE_EVIDENCE_DIR/RUN_RECORD.json \
  --pack-input-record ABSOLUTE_EVIDENCE_DIR/PACK_INPUT_RECORD.json

go run ./tools/publiclab validate-record \
  --source lab/public/source \
  --schema-dir lab/public/source/import/protocol \
  --artifact-dir OWNER_SPECIALIZED_ARTIFACT_DIR \
  --kind reproduction-record \
  --record ABSOLUTE_EVIDENCE_DIR/REPRODUCTION_RECORD.json \
  --run-record ABSOLUTE_EVIDENCE_DIR/RUN_RECORD.json \
  --pack-input-record ABSOLUTE_EVIDENCE_DIR/PACK_INPUT_RECORD.json
```

## Records and synthetic pack

`run-record.template.json` and `reproduction-record.template.json` are
deliberately invalid until every `null`, empty live-evidence collection, and
template notice is replaced or removed. Validate completed records locally;
schema success is not factual review and privacy attestations still require a
human check.

The synthetic incident pack is generated only from the schema-valid,
manifest-bound **pack-input record** created from the exact install and restore
tag-move records. Its affected B commit and known-good A commit come from the
object manifest. Its mutable-ref window is conservatively bounded by actual
remote A, B, and restored-A observations; local wall-clock guesses are not
accepted. The generator requires an immutable public URL for the exact pack-
input record and never follows that URL. The incident identity and pack version
must be exercise-content-specific: changing repository-bound objects, the
observed interval, or any other material pack input cannot silently produce new
bytes under the same immutable version. The pack-input record ID is
content-bound to its canonical material fields. That ID does not authenticate
itself: pack generation verifies the exact install, restore, and pack-input JSON
blobs, their hashes and derivation relationship, together at the immutable
observations commit in the source URL. Verification uses the separate
observations clone and does not follow the URL.

Schema validation, privacy attestations, and automated scanners are rejection
controls only. They do not prove absence of sensitive or hostile content; a
human must review the exact records and case bytes before publication.

`reproductions/index.json` is intentionally empty until an outside human record
has been anonymously downloaded, manifest-verified, evidence-checked, privacy-
checked, and accepted by a human maintainer. Generated or automated review
cannot populate that index.

## Mandatory interpretation

- A downloaded or prepared Action is not necessarily an executed Action.
- A current `v1 -> A` observation cannot clear historical exact-B evidence.
- A run window alone cannot prove that B executed.
- Missing logs produce an evidence gap, not a clean bill of health.
- The lab creates no credential, cloud-role, persistence, deployment-causation,
  exfiltration, or malicious-impact claim.
