# ADR 0014: Solo-maintainer v0.2.0 release with waived human gates

## Status

Accepted by the maintainer on 2026-09-09. Amends the v0.2.0 release scope set
by ADR 0013 and the v0.2 adoption plan for this release only. ADR 0013 remains
in force for every future pack promotion.

## Date

2026-09-09

## Context

The v0.2 adoption plan gates the release on acts by other people: two eligible
non-preparer maintainers and independent outside reviewers for each real
incident pack (`V02-G06`), an outside reproduction of the public harmless lab
(`V02-G07`), a human accessibility and cold-reader pass (`ADO-025`, `ADO-026`),
and a human consistency gate (`ADO-099`). The project has one maintainer, who
prepared all three candidate packs, so no maintainer approval slot can be
filled by anyone who exists. One round of outreach between 2026-09-03 and
2026-09-08 produced no reviewer, no co-maintainer, and one decline. On
2026-09-09 the maintainer decided to release v0.2.0 as a solo maintainer rather
than wait for people who may never come.

## Decision

- v0.2.0 ships with an empty reviewed-pack index. The Reviewdog, tj-actions,
  and Trivy 2026 packs stay `candidate` in the review registry, enter no
  archive, and are described as reviewed nowhere. ADR 0013's approval
  requirements are unchanged; they are not met, and nothing in this release
  says otherwise.
- The public harmless lab (`LAB-PUBLIC-006` through `LAB-PUBLIC-011`) is not
  part of v0.2.0. No independent reproduction exists.
- The human gates `ADO-025`, `ADO-026`, `ADO-099`, and the manual part of
  `SITE-003` are waived for v0.2.0 by maintainer decision. Their automated
  portions still run in the release-candidate freeze. The waiver is recorded in
  `TASKS.md`; the tasks stay open and are not marked complete.
- `DIST-007A`, the hosted qualification at a prerelease tag, is skipped. The
  protected release workflow's own reproducible double build, byte comparison,
  and attestation at the `v0.2.0` tag stand in for it.
- The release-candidate freeze (`DIST-007`) may close with an empty
  reviewed-pack index and an unpublished lab. `docs/RELEASE_PROCESS.md` is
  amended for this release only; every other freeze condition still applies.
- The maintainer performs `V02-G09` alone: reviews the exact candidate tree and
  authorizes staged publication.
- Release notes and the README state what shipped and what did not: no reviewed
  real incident pack, no independent reproduction, no outside accessibility or
  cold-reader review. `ADO-015` and `ADO-031` measurements on the reference
  systems did not happen and stay open.
- The `SITE-008` preflight found that the `Protect main` ruleset (pull request
  required, squash merges only, linear history, no bypass actors) cannot admit
  the fast-forward activation the adoption plan requires, and a squash merge
  would put a different commit than the tagged one on the default branch. For
  the activation push only, the maintainer adds a temporary repository-admin
  bypass to that ruleset, pushes the exact tagged commit as a non-force
  fast-forward, and restores the ruleset immediately afterwards. The activation
  creates no commit, and both ruleset changes are recorded in the release
  record.
- Homebrew tap publication (`DIST-004`, `DIST-005`), Pages deployment
  (`SITE-006`, `SITE-007`), and default-branch activation (`DIST-009`) remain
  maintainer steps after the tag. Each is recorded in the ledger when done.

## Consequences

- The real-incident material a v0.2.0 user can run is the synthetic
  demonstration pack plus any candidate the user loads on purpose, at the
  user's own risk and with the candidate's unreviewed status visible.
- Any claim of "reviewed" or "independently reproduced" in v0.2.0 material is a
  defect to be corrected in a later version.
- Future promotions of the three candidates still need the approvals ADR 0013
  requires, bound to their frozen commits, from people other than the preparer.
- The v0.2.0 README links to the versioned Pages site. Those links resolve only
  after the maintainer completes `SITE-006` and `SITE-007`.
