# Pack approval runbook

The maintainer-side sequence from "reviews requested" to "pack promoted", with
the exact identities of the three v0.2 candidates. It complements
[`REAL_INCIDENT_PACK_REVIEW.md`](REAL_INCIDENT_PACK_REVIEW.md) (the policy) and
[`OUTSIDE_REVIEWER_PROCEDURE.md`](OUTSIDE_REVIEWER_PROCEDURE.md) (the
reviewer's side). Every step below either asks a person for a decision or runs
a deterministic check; no step creates an approval by itself.

## The candidates

| Incident pack | Pull request | Frozen candidate commit C | Candidate manifest SHA-256 | Profile and required approvals |
| --- | --- | --- | --- | --- |
| `CIR-REVIEWDOG-ACTION-SETUP-2025` 1.0.0 | #12 | `61f973caabb986566d10c0c6a88e7946e21cd9c7` | `bbdc33dec45069092f48dde80bf493e6f0f2fa1e94e68b895486d64d598ebf57` | `standard-v0.2`: two maintainers, one outside reviewer |
| `CIR-TJ-ACTIONS-CHANGED-FILES-2025` 1.0.0 | #13 | `7d103e9dc845eb4c32d164a2e77f151b47d8af55` | `3f4682671db321d3c47d0a807d9be3c934429bcf6d4aac4080824756473cf0e8` | `standard-v0.2`: two maintainers, one outside reviewer |
| `CIR-AQUASECURITY-TRIVY-2026` 1.0.0 | #14 | `ecb5f830d772446fc6b7032197b1883c8426dc49` | `c84e751dfe14659eb0600fa86785c0cc9770986f904e334fe3ec083e95dc7900` | `trivy-v0.2`: two maintainers, two distinct outside reviewers each covering component namespace, IOC extraction, and time |

The preparer of record and source transcriber of all three is `torjan0`, who
therefore cannot fill any approval slot on them. The registry binds each C and
manifest hash; if a candidate branch is changed for any material reason, the
packet is re-assembled, a new C is registered, and every review starts over.

## 0. Freeze the review head first

GitHub records a review against the pull request head at submission time, the
snapshot workflow refuses a pull request whose head is not C, and
`check-approvals` rejects an approval recorded on any other commit. The stacked
candidate branches (#12, #13, #14) carry the registry record and later merges
after each packet commit, so a review submitted on them as they stand would not
count. Before requesting reviews:

1. Land the tooling pull request (#11) on `main`.
2. Give the pack a review pull request whose head is exactly C: either move the
   candidate branch back to C or open a fresh branch pushed from C, based on
   `main`. Once the head is C, nothing is merged into that branch until the
   promotion step.
3. Review in dependency order, Reviewdog, then tj-actions, then Trivy, because
   each later packet commit's history contains the earlier packets; a later
   pack's review pull request shows only its own material once the earlier pack
   has been promoted and merged.
4. Keep the `research` and `candidate` registry records off the review head.
   They are already recorded on the stacked branches after C and travel with the
   promotion branch, which is rooted at C and may include them.

## 1. Staff the reviews

- Identify two eligible project maintainers who did not prepare or transcribe
  the candidate, and the outside reviewer or reviewers. Record who fills which
  slot and every disclosed relationship before anyone starts.
- Send each reviewer the procedure link pinned to C:
  `https://github.com/torjan0/cirewind/blob/<C>/docs/OUTSIDE_REVIEWER_PROCEDURE.md`.
- Keep the pull request head at C. Do not merge anything into the candidate
  branch while reviews are open; a docs merge would move the head and
  invalidate reviews in progress.

## 2. Confirm each review as it lands

For each submitted GitHub review:

1. Check that the review's commit is exactly C and that its body is the single
   fixed line the reviewer's assertion renders (`packreview render-review-body`).
2. Obtain the reviewer's assertion file through the pull request and store it,
   unmodified, as `approvals/<reviewId>/review.json` inside the review unit on
   a promotion branch rooted at C (never on the candidate branch).
3. Generate the Markdown twin with `packreview render-review --review
   approvals/<reviewId>/review.json --out approvals/<reviewId>/REVIEW.md`;
   validation later rejects any hand edit to either file.

## 3. Capture the platform observation

Once every required approval exists on exact C, dispatch the repository's
`Capture incident-pack review snapshot` workflow with the pull request number
and C. It verifies the head, projects the list-reviews response without any
credential reaching the normalizer, and uploads `platform-approvals.json` as an
immutable artifact whose ID it records. Download that artifact; retain the run
URL, run ID, attempt, and artifact ID.

To reproduce the normalization locally from a saved list-reviews response:

```sh
go build -o /tmp/packreview ./tools/packreview
/tmp/packreview normalize-platform-approvals --source reviews.json --out platform-approvals.json \
  --repository torjan0/cirewind --pull-request <PR> --candidate-commit <C> \
  --observed-at <RFC3339> --workflow-source-commit <workflow commit> \
  --workflow-run-url <run URL> --workflow-run-id <run id> --workflow-run-attempt <attempt>
```

## 4. Check the policy offline

```sh
/tmp/packreview check-approvals --root review-packets/<incident>/<version> \
  --candidate-commit <C> --candidate-manifest-sha256 <manifest sha256> \
  --platform-approvals platform-approvals.json
```

The check reports each missing slot, an approval on the wrong commit, a body
hash that does not match a stored assertion, a reviewer who is the preparer,
a reused identity, or a Trivy outside review that lacks a required scope. Fix
the staffing, never the records.

## 5. Promote

On the promotion branch rooted at C, with a clean tree and `HEAD == C`:

```sh
/tmp/packreview promote --root review-packets/<incident>/<version> --repository-root . \
  --candidate-commit <C> --candidate-manifest-sha256 <manifest sha256> \
  --platform-approvals platform-approvals.json --promoted-at <RFC3339>
```

Promotion materializes only the approval, snapshot, promotion, reviewed-copy,
and manifest paths and refuses everything else. Commit the result as P, then
append the `reviewed` registry record that references P, and run
`packreview validate-governance --repository-root .` and
`packreview verify-registry --repository-root . --promotion-content-commit <P>`.

## 6. After promotion

- Release packaging picks up reviewed packs from the registry automatically;
  candidates stay excluded.
- The task ledger entries `PACK-032`, `PACK-042`, and `PACK-053` close only
  with the names of the approving humans and the promotion commit recorded.
