# Outside reviewer procedure for candidate incident packs

This is the step-by-step companion to
[`REAL_INCIDENT_PACK_REVIEW.md`](REAL_INCIDENT_PACK_REVIEW.md), written for a
reviewer who is external to the CIRewind maintainer and implementation team and
has not authored or transcribed the candidate under review. It tells you what
to reproduce, what to check for each review scope, and how to record the
result so the project's tooling can bind your GitHub review to the exact bytes
you looked at. Nothing in this procedure creates an approval by itself; only
your GitHub pull-request review on the exact frozen commit does that.

## Before you start

- Confirm you are independent: not the candidate's preparer or source
  transcriber, not a maintainer of the affected project, and not an automated
  account. Write down every employment, vendor, incident-response, or
  authorship relationship to the incident; you will record it verbatim in the
  conflict disclosure field.
- Work offline from a fresh clone. You need Go at the exact version in
  `go.mod` (`GOTOOLCHAIN=auto` fetches it), `git`, `sha256sum`, and, only for
  re-retrieving sources, the GitHub CLI or `curl`.
- Do not push anything to the candidate branch. A review that changes bytes is
  a change request, not an approval; the candidate commit would move and every
  existing review would go stale.

## The candidates

| Incident pack | Pull request | Frozen candidate commit C | Review unit | Profile |
| --- | --- | --- | --- | --- |
| `CIR-REVIEWDOG-ACTION-SETUP-2025` 1.0.0 | #12 | `61f973caabb986566d10c0c6a88e7946e21cd9c7` | `review-packets/CIR-REVIEWDOG-ACTION-SETUP-2025/1.0.0` | `standard-v0.2` |
| `CIR-TJ-ACTIONS-CHANGED-FILES-2025` 1.0.0 | #13 | `7d103e9dc845eb4c32d164a2e77f151b47d8af55` | `review-packets/CIR-TJ-ACTIONS-CHANGED-FILES-2025/1.0.0` | `standard-v0.2` |
| `CIR-AQUASECURITY-TRIVY-2026` 1.0.0 | #14 | `ecb5f830d772446fc6b7032197b1883c8426dc49` | `review-packets/CIR-AQUASECURITY-TRIVY-2026/1.0.0` | `trivy-v0.2` |

The commit C is the one recorded as `candidateCommit` in `review-registry.json`;
if the registry on the pull request head names a different commit, review that
one and note the discrepancy. Your GitHub review must be submitted while the
pull request head is exactly C.

## Step 1: get the exact bytes

```sh
git clone https://github.com/torjan0/cirewind.git
cd cirewind
git fetch origin pull/<PR>/head:candidate
git checkout <C>
git rev-parse HEAD            # must print C
```

Everything you review lives under the review unit's `candidate-content/`
directory: `pack.yaml`, `sources.json`, `claims.json`, `conflicts.json`,
`review-policy.json`, `packet.json`, `validation.json`,
`expected-findings.json`, `candidate-content-manifest.sha256`, and
`fixtures/` (generated scenario snapshots, archived redistributable sources,
and for Trivy the sealed extraction records).

## Step 2: reproduce the structure

```sh
go build -o /tmp/packreview ./tools/packreview
/tmp/packreview validate-unit --root <review unit> --candidate-commit <C>
/tmp/packreview validate-governance --repository-root .
go test ./internal/packreview ./internal/packfixtures ./internal/packextract
```

`validate-unit` recomputes the candidate-content manifest, checks every
ledger against the pack, and replays the fixtures through the production
derivation into the committed oracle. A pass means the packet is internally
consistent; it says nothing about whether the sources are true. Record the
tool identity you used (`git rev-parse HEAD` is the version) in the assertion.

Record the bindings you are approving by reading them, not by trusting the
pull-request text:

```sh
cat <review unit>/candidate-content/packet.json
sha256sum <review unit>/candidate-content/candidate-content-manifest.sha256
```

`packet.json` carries `originalPackSha256`, `canonicalPackSha256`,
`claimsSha256`, `sourcesSha256`, `conflictsSha256`, `fixtureManifestSha256`,
`validatorPolicySha256`, and `reviewPolicySha256`; the `sha256sum` line is the
`candidateManifestSha256` binding.

## Step 3: identity scope

Re-retrieve every source in `sources.json` yourself, by the method its `notes`
field records (for example `gh api repos/OWNER/REPO/security-advisories/GHSA-...`
for a GitHub REST advisory object, or the pinned commit path in the
`github/advisory-database` repository), hash the bytes, and compare with
`reviewedSha256` and `reviewedByteLength`. Then check that every claim in
`claims.json` whose role is `compromised-sha`, `ref`, `package-digest`, or
`component` points at text that really exists in the source it cites.

- A live advisory that has been edited since the recorded `updatedAt` will
  hash differently. That is a finding, not a failure: record the new revision
  and hash in your assertion and decide whether the change is material.
- The Reviewdog and tj-actions malicious objects were removed from their
  repositories, so identity rests on the advisory statements; say so in your
  limitations rather than treating a 404 as an error.
- Every checked source goes into `sourceObjectsChecked` with the hash you
  computed. The identity scope requires at least one.

## Step 4: time scope

For every window in `pack.yaml`, read the source text the window claims cite
and confirm: the stated precision (`day`, `minute`) matches what the source
actually says; the `approximation` label is honest (`source-rounded` where the
publisher marked a boundary approximate, `conservative-expanded` where the
preparer widened it); `originalClaim` quotes the source; and each linked
conflict in `conflicts.json` explains the disagreement without inventing a
tighter boundary. Reject any window that turns a date-only or tilde-marked
statement into an exact instant.

## Step 5: Trivy only, component namespace and IOC extraction

The `trivy-v0.2` profile requires both outside reviewers to cover
`component-namespace`, `ioc-extraction`, and `time` independently.

1. Retrieve the maintainer advisory object and the current tag listing
   yourself and hash them:

   ```sh
   gh api repos/aquasecurity/trivy/security-advisories/GHSA-69fq-xp46-6x23 > advisory.json
   gh api --paginate repos/aquasecurity/trivy-action/git/matching-refs/tags/ > tags.json
   sha256sum advisory.json tags.json
   ```

   Compare with `sources.json` (`ghsa-maintainer`, `trivy-action-tags`). If
   the advisory has been edited since retrieval, note the new hash; the
   committed extraction record is still bound to the reviewed bytes.

2. Re-run the mechanical extraction and compare the sealed records:

   ```sh
   /tmp/packreview extract-indicators --extractor trivy-2026-advisory-tables \
     --source advisory.json --out my-tables.json
   /tmp/packreview extract-indicators --extractor trivy-2026-action-tag-inventory \
     --source tags.json --out my-tags.json --unrestored 0.0.10,0.34.1,0.34.2
   cmp my-tables.json <review unit>/candidate-content/fixtures/extraction/trivy-2026-advisory-tables.json
   cmp my-tags.json   <review unit>/candidate-content/fixtures/extraction/trivy-2026-action-tag-inventory.json
   ```

   Byte-identical output means the committed records are what the extractor
   produces from those bytes. If your advisory bytes differ from the reviewed
   ones, compare the `digests`, `network`, and `originalTags` arrays instead
   and record any difference.

3. Check namespaces by hand: every `release-asset` digest in `pack.yaml` comes
   from the Executable binaries table and every `oci-manifest` digest from the
   Container images table; no digest is attached to an Action component; the
   `trivy-action` refs are the derived original names (`0.28.0`, not
   `v0.28.0`); the `setup-trivy` refs are exactly `v0.2.0` to `v0.2.6`; and the
   `trivy` component carries no ref. Confirm the pack states that one of the
   advisory's 76 affected tag names could not be recovered.

4. Confirm the omissions are deliberate: no known-good identity, no Action
   package digest, and no encoded domain, address, or version literal, each
   with a claim row explaining why, and the literals carried in the guidance.

## Step 6: hostile input and privacy scope

Every fixture snapshot under `fixtures/scenarios/` must be synthetic: the
reserved consumer repository names (`cirewind-fixtures/...`), synthetic object
IDs, no payload text, no credential shapes, no victim names, and no raw logs.
A quick check:

```sh
grep -rEl 'ghp_|github_pat_|-----BEGIN|AKIA[0-9A-Z]{16}|gist\.github' <review unit>/candidate-content/fixtures && echo FOUND
```

Nothing should print. Also confirm `pack.yaml` contains no executable content
and that `sources.json` archives only redistributable objects under
`fixtures/sources/`.

## Step 7: write the assertion and submit the review

Write a `cirewind.review-assertion/v1alpha1` record before you submit anything
on GitHub. Every field is yours to fill; the tooling never invents one.

```json
{
  "schemaVersion": "cirewind.review-assertion/v1alpha1",
  "reviewId": "review.<your-login>.<incident-id-lowercase>",
  "reviewer": { "login": "<your GitHub login>", "databaseId": <your numeric GitHub user id> },
  "declaredRole": "outside-technical",
  "independent": true,
  "conflictDisclosure": "<every relationship to the incident, or an explicit statement that there is none>",
  "incidentId": "<incident id>",
  "packVersion": "1.0.0",
  "candidateCommit": "<C>",
  "bindings": {
    "candidateManifestSha256": "<sha256sum of candidate-content-manifest.sha256>",
    "originalPackSha256": "<from packet.json>",
    "canonicalPackSha256": "<from packet.json>",
    "claimsSha256": "<from packet.json>",
    "sourcesSha256": "<from packet.json>",
    "conflictsSha256": "<from packet.json>",
    "fixtureManifestSha256": "<from packet.json>",
    "validatorPolicySha256": "<from packet.json>",
    "reviewPolicySha256": "<from packet.json>"
  },
  "repository": "torjan0/cirewind",
  "pullRequestNumber": <PR number>,
  "scopes": ["identity", "time"],
  "commands": [
    { "tool": "packreview", "version": "<C>", "arguments": ["validate-unit", "--root", "<review unit>", "--candidate-commit", "<C>"] }
  ],
  "sourceObjectsChecked": [
    { "sourceId": "<sourceId from sources.json>", "sha256": "<hash you computed>" }
  ],
  "decision": "approve",
  "rationale": "<what you checked and what you concluded, in your own words>",
  "knownLimitations": ["<every limitation you accept without resolving it>"]
}
```

Your numeric GitHub user id is `gh api user --jq .id`. List only the scopes
you actually reviewed; a Trivy outside review must include
`component-namespace`, `ioc-extraction`, and `time`. Scopes are chosen from
`identity`, `time`, `transitive-mapping`, `ioc-extraction`, `remediation`, `hostile-input-privacy`, `component-namespace`, `complete`; use `complete` only if you reviewed everything. Then:

```sh
/tmp/packreview render-review-body --review assertion.json
```

The command validates the record and prints one fixed ASCII line. Submit a
GitHub pull-request review on the pull request whose head is exactly C, with
that line as the entire review body and the decision you recorded
(`approve` or `request_changes`; an `abstain` record is a comment review).
Then send the assertion file to the maintainer through the pull request so it
can be stored as the canonical `approvals/<reviewId>/review.json` beside the
generated `REVIEW.md`. Changing any assertion field after submission makes the
body hash disagree and voids the approval; if you need to change your mind,
submit a new review with a new assertion.

## What your approval means

It means you reproduced the identities and validations you listed, checked the
scopes you declared, and accept the limitations you wrote down. It does not
mean the incident narrative is complete or that any run in any repository was
affected; CIRewind derives that later from evidence, never from a pack alone.
