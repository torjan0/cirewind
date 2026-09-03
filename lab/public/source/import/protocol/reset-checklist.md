# Reset checklist

Reset is incomplete until every item below is observed and recorded. A command
returning success is not a substitute for remote readback.

- [ ] The exact owner/name still matches the protocol record, and the
      operator-asserted repository database ID has been cross-checked against
      later GitHub run/API evidence; the Git tag-control transport did not
      observe or verify that database ID.
- [ ] Remote `refs/tags/v1` directly identifies exact marker A, not marker B or
      an annotated tag object.
- [ ] `refs/tags/fixture-a` retains its reviewed annotated tag-object ID and
      peels to exact A.
- [ ] `refs/tags/fixture-b` retains its reviewed annotated tag-object ID and
      peels to exact B.
- [ ] Remote `refs/heads/main` retains the reviewed owner-specialized import
      commit I; no provenance or observation publication advanced it.
- [ ] Protected non-default `refs/heads/observations` contains the exact
      sidecar, install/restore tag-move observations, pack-input, generated
      pack, and run record as append-only commits; the exact install, restore,
      and pack-input derivation blobs coexist at the immutable pack-input source
      commit, and every cited record URL uses a full immutable commit and its
      recorded content hash verifies.
- [ ] No exercise workflow remains queued or in progress.
- [ ] Default workflow permissions remain read-only and no wildcard exception
      can move fixture or release tags.
- [ ] No secret, variable, environment, deployment key, package credential,
      self-hosted runner, webhook, or GitHub App was created for the basic lab.
- [ ] Public runs and immutable records were retained; history was not deleted
      or rewritten to make the outcome appear clean.
- [ ] The final raw-disabled case manifest verifies.
- [ ] Schema validation, privacy attestations, and automated scans passed, and a
      human inspected the exact publication bytes; none of these checks is
      recorded as proof that sensitive material cannot exist.
- [ ] Expired, inaccessible, denied, truncated, or contradictory evidence is
      recorded as coverage/error data and, where conclusion-blocking,
      `UNKNOWN_EVIDENCE_GAP`.

Do not force-push a branch, move or recreate an immutable fixture/release tag,
delete run history, or rotate unrelated credentials as part of reset. If exact A
cannot be read back, stop further workflow dispatches, preserve the observed
state, and escalate; do not claim successful restoration.
