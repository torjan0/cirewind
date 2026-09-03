# Incident source notes

Status: research ledger, not an incident pack
Retrieval date: 2026-08-20
Advisory Database snapshot: [`github/advisory-database@fa95208`](https://github.com/github/advisory-database/tree/fa95208a0a9d23397334d6d71255ba089f49a067)
Intended audience: incident-pack authors and reviewers

## Use of this document

This file separates primary-source facts from interpretation and unresolved gaps for the four intended initial incidents. It is deliberately not valid pack YAML. Nothing here should be copied into a real pack without completing the admission checklist below and reviewing the current primary sources again.

The incident description tells CIRewind what indicators to look for; it never dictates the finding state. Even when an advisory says every referencing workflow “executed” malicious code, CIRewind must still distinguish a declaration, preparation/download, and a step that demonstrably began for each run attempt.

## Source hierarchy

Use this order for pack facts:

1. A security advisory or incident report published by the affected repository's maintainers.
2. Immutable repository objects and exact GitHub API responses: full commits, tags with recorded observation time, signed releases, immutable package metadata, or artifact digests.
3. GitHub's reviewed Advisory Database record, preferably at a pinned database commit.
4. A government alert or original researcher's technical report as corroboration or for an indicator the maintainer explicitly adopts.
5. Secondary reporting only as a lead. It is never the sole authority for a compromised SHA, digest, affected ref, or exposure window.

Source rank is not the same as CIRewind's `L4_CERTAIN`–`L0_UNKNOWN` evidence provenance. A maintainer advisory can establish that a SHA is an incident indicator, but only case evidence can establish whether a particular job downloaded or executed it.

## Indicator admission checklist

Before a value enters a real pack, reviewers must confirm all of the following:

- The indicator has at least one primary source URL, source publication/update time, retrieval time, and a locally calculated SHA-256 of the retrieved source object.
- Git object identifiers declare their algorithm and use the full lowercase hexadecimal value: 40 characters for SHA-1 or 64 for SHA-256. Abbreviated or algorithm-less Git object names are rejected.
- SHA-256 digests are 64 lowercase hexadecimal characters and retain their namespace, such as `sha256:` for an OCI digest.
- Repository identity and any affected subpath are explicit. A repository-level indicator must not be silently applied to an unrelated Action subpath.
- Every mutable ref has a component-specific time window. A ref name by itself is not a timeless malicious version.
- Window boundaries state timezone, inclusivity, and precision. Source words such as “approximately,” `~`, or date-only ranges remain approximate; pack authors must not manufacture seconds.
- A conservative widened window, if policy permits one, is labeled as a derived value and cites the exact derivation. It is not represented as the publisher's observation.
- Known-good commits are independently verified. “Patched version” metadata is not enough when a tag was moved or recreated.
- Literal log indicators are narrowly contextual. Common domains or generic strings are not promoted to high-confidence incident matches by themselves.
- Each transitive relationship identifies the wrapper component and the affected nested component. A safe wrapper commit may still have resolved a mutable nested ref.
- Conflicting sources are resolved or encoded as a documented ambiguity; they are never silently averaged.
- A second reviewer reproduces the transcription from the source snapshot and the deterministic pack-validation result.

## Primary-source ledger

All entries were retrieved on 2026-08-20.

| Incident | Maintainer primary sources | Pinned normalized record | Important source status |
|---|---|---|---|
| tj-actions/changed-files, March 2025 | [Maintainer GHSA-mw4p-6x4p-x5m5](https://github.com/tj-actions/changed-files/security/advisories/GHSA-mw4p-6x4p-x5m5), [v46.0.1 security release note](https://github.com/tj-actions/changed-files/releases/tag/v46.0.1) | [GHSA-mrrh-fwg8-r2c3 JSON](https://github.com/github/advisory-database/blob/fa95208a0a9d23397334d6d71255ba089f49a067/advisories/github-reviewed/2025/03/GHSA-mrrh-fwg8-r2c3/GHSA-mrrh-fwg8-r2c3.json) | Primary sources agree on the bad commit and date range, but disagree on the first patched version. Exact UTC boundaries are not published there. |
| reviewdog transitive compromise, March 2025 | [Maintainer GHSA-qmg3-hpqr-gqvc](https://github.com/reviewdog/reviewdog/security/advisories/GHSA-qmg3-hpqr-gqvc), [maintainer incident issue #2079](https://github.com/reviewdog/reviewdog/issues/2079) | [GHSA-qmg3-hpqr-gqvc JSON](https://github.com/github/advisory-database/blob/fa95208a0a9d23397334d6d71255ba089f49a067/advisories/github-reviewed/2025/03/GHSA-qmg3-hpqr-gqvc/GHSA-qmg3-hpqr-gqvc.json) | Exact minute-level UTC window is published. Advisory commit names are abbreviated; full objects were independently resolved through GitHub. |
| Trivy ecosystem compromise, March 2026 | [Maintainer GHSA-69fq-xp46-6x23](https://github.com/aquasecurity/trivy/security/advisories/GHSA-69fq-xp46-6x23), [initial incident discussion #10425](https://github.com/aquasecurity/trivy/discussions/10425), [conclusion #10462](https://github.com/aquasecurity/trivy/discussions/10462) | [GHSA-69fq-xp46-6x23 JSON](https://github.com/github/advisory-database/blob/fa95208a0a9d23397334d6d71255ba089f49a067/advisories/github-reviewed/2026/03/GHSA-69fq-xp46-6x23/GHSA-69fq-xp46-6x23.json) | Maintainer advisory is comprehensive but marks several boundaries approximate. It covers Actions, binaries, packages, and container images with different windows. |
| Xygeni mutable `v5` tag, March 2026 | [Maintainer GHSA-f8q5-h5qh-33mh](https://github.com/xygeni/xygeni-action/security/advisories/GHSA-f8q5-h5qh-33mh), [discovery issue #54](https://github.com/xygeni/xygeni-action/issues/54) | [GHSA-f8q5-h5qh-33mh JSON](https://github.com/github/advisory-database/blob/fa95208a0a9d23397334d6d71255ba089f49a067/advisories/github-reviewed/2026/03/GHSA-f8q5-h5qh-33mh/GHSA-f8q5-h5qh-33mh.json) | The GHSA's incident-report reference remained a placeholder at retrieval. Its window and duration are approximate and internally imprecise. |

## tj-actions/changed-files, March 2025

### Verified primary-source facts

- The affected component is the GitHub Action repository `tj-actions/changed-files`.
- The maintainer advisory identifies the full compromised commit as `0e58ed8671d6b60d0890c21b07f8835ace038e67` and says mutable tags were repointed to it.
- The maintainer advisory and release note describe the incident as active on March 14–15, 2025. They do not provide exact UTC start/end instants.
- The malicious behavior read runner process memory and printed encoded material into workflow logs. That establishes the incident mechanism; it does not establish which secrets were present in or recovered from a given victim job.
- The maintainer advisory lists `v1.0.0`, `v35.7.7-sec`, and `v44.5.1` as examples of tags that pointed to the compromised commit.
- The current tags were repaired after the incident. That present-day state says nothing about the historical resolution of an earlier run.

Sources: [maintainer advisory](https://github.com/tj-actions/changed-files/security/advisories/GHSA-mw4p-6x4p-x5m5), [maintainer release note](https://github.com/tj-actions/changed-files/releases/tag/v46.0.1), and [GitHub-reviewed record](https://github.com/advisories/GHSA-mrrh-fwg8-r2c3).

### Candidate pack material after review

| Candidate | Source precision | Safe interpretation |
|---|---|---|
| Repository `tj-actions/changed-files` | Exact | Component identity only. |
| Compromised full SHA above | Exact | Exact runtime SHA match can support download/execution findings according to case evidence. |
| March 14–15, 2025 | Date-only | Mutable-ref exposure window candidate with date precision; not an exact RFC3339 boundary. |
| The three named tags | Exact names, incomplete set | Individual mutable-ref indicators; do not call the list exhaustive. |
| Literal `B64_BLOB=` | Exact literal shown by the advisory | Contextual log indicator only; it must never cause CIRewind to decode or store the following value. |

### Conflicts and insufficient evidence

- The maintainer GHSA lists `46.0.0` as patched, while the GitHub-reviewed record lists `46.0.1`. A real pack should rely on verified full known-good commits rather than choosing one version field without explanation.
- The package range `<=45.0.7` is not a list of immutable compromised SHAs. It must not be converted into a timeless assertion that every commit associated with every earlier release was malicious.
- The exact beginning and end of the tag-repointing window are not in the cited primary sources. Date-to-second boundaries would be fabricated.
- The three listed tags are examples, not a proven complete tag inventory. Do not extrapolate every major/minor tag without archived ref observations or runtime SHA evidence.
- `gist.githubusercontent.com` is a common hosting domain. The advisory mentions it in the attack path, but the bare domain is too broad to be a high-confidence standalone IOC.

### Prohibited conclusions

- “Every repository using changed-files was compromised.”
- “Every run on March 14–15 executed the bad commit.”
- “All repository or organization secrets were exposed.”
- “No current reference means the historical run was safe.”
- “The encoded log blob may be decoded and stored in the case.”

### Pack readiness

The bad SHA and component identity are ready for peer-reviewed transcription. The pack schema can preserve date precision and a labeled conservative expansion, but a high-precision mutable-ref window remains blocked pending exact primary evidence. Reviewers must choose and document the conservative date-boundary policy; patched/known-good values still require conflict resolution.

Candidate status (2026-09-03): the sources above were re-retrieved with recorded hashes and a candidate packet was prepared at `review-packets/CIR-TJ-ACTIONS-CHANGED-FILES-2025/1.0.0` with the dates read as UTC calendar days under a labeled `conservative-expanded` window, the three example tags encoded as non-exhaustive mutable refs, the patched-version disagreement excluded, and no log literal or domain encoded. The malicious commit object is no longer served by the GitHub API. It remains a candidate without human review.

## Reviewdog transitive compromise, March 2025

### Verified primary-source facts

- The maintainer advisory says `reviewdog/action-setup@v1` was compromised on 2025-03-11 from 18:42 through 20:31 UTC.
- The advisory identifies malicious abbreviated object `f0d342d`. GitHub's commit endpoint resolved it on the retrieval date to full commit [`f0d342d24037bb11d26b9bd8496e0808ba32e9ec`](https://github.com/reviewdog/action-setup/commit/f0d342d24037bb11d26b9bd8496e0808ba32e9ec).
- The advisory calls `3f401fe` the fix/retag object. GitHub resolved it to [`3f401fe1d58fe77e10d665ab713057375e39b887`](https://github.com/reviewdog/action-setup/commit/3f401fe1d58fe77e10d665ab713057375e39b887). It is a remediation candidate, not automatically a CIRewind `knownGoodSHA` until its content and tag history are reviewed.
- The maintainer lists transitive affected Actions: `reviewdog/action-shellcheck`, `reviewdog/action-composite-template`, `reviewdog/action-staticcheck`, `reviewdog/action-ast-grep`, and `reviewdog/action-typos` because they used `reviewdog/action-setup@v1`.
- The maintainer's later issue update says a compromised contributor PAT was used to overwrite the tag and that audit review found only `v1` affected.

Sources: [maintainer GHSA](https://github.com/reviewdog/reviewdog/security/advisories/GHSA-qmg3-hpqr-gqvc) and [maintainer incident thread](https://github.com/reviewdog/reviewdog/issues/2079).

### Candidate pack material after review

| Candidate | Source precision | Safe interpretation |
|---|---|---|
| `reviewdog/action-setup`, ref `v1` | Exact | Mutable nested component during the stated window. |
| Full malicious SHA above | Exact Git object | Exact runtime match for the nested Action. |
| 2025-03-11 18:42 through 20:31 UTC | Minute precision | Preserve the publisher's minute precision; do not synthesize seconds. Boundary inclusivity still requires review. |
| Five named wrapper repositories | Exact names | Transitive candidates. Historical wrapper metadata must prove the nested declaration for the exact wrapper commit. |

### Conflicts and insufficient evidence

- The GHSA displays `v1` as both affected and patched. This is a temporal tag event, not a conventional immutable semver vulnerability; generic version-range matching is insufficient.
- The incident issue includes threshold-like wrapper versions, but the notation and exact historical dependency at each wrapper SHA need verification in each wrapper repository before encoding version constraints.
- A wrapper pinned by full SHA can still have called the mutable `action-setup@v1`. The wrapper SHA is not itself a compromised SHA and must not be placed in `compromisedSHAs` merely because it was transitively exposed.
- The source phrase “regardless of version or pinning method” describes the wrapper's nested mutable dependency. It does not mean a skipped wrapper step or a job outside the exposure window executed the malicious commit.
- The reviewdog-to-tj-actions causal chain is discussed by maintainers and original researchers, but the two packs should remain independently testable. A relationship between incidents is not evidence that a victim run matched both.

### Prohibited conclusions

- “A SHA-pinned reviewdog wrapper was safe” without resolving its historical nested Action.
- “Every execution of the five wrapper Actions was compromised.”
- “The wrapper Action commit equals the malicious action-setup commit.”
- “The compromised PAT or affected user's identity is known to CIRewind.”

### Pack readiness

The direct component, bad full SHA, ref, and minute-level window are strong candidates. Wrapper version/subpath mappings need repository-by-repository historical verification and deterministic fixtures before the transitive portion is accepted.

Candidate status (2026-09-03): the sources above were re-retrieved with recorded hashes and a candidate packet was prepared at `review-packets/CIR-REVIEWDOG-ACTION-SETUP-2025/1.0.0` encoding only the direct component, full object, `v1` ref, and rounded minute-precision window; wrapper mappings and the retag object are omitted with recorded rationale. It remains a candidate without human review.

## Trivy ecosystem compromise, March 2026

### Verified primary-source facts

The maintainer GHSA separates four exposure windows:

| Component | Maintainer-published window (UTC) | Precision caveat |
|---|---|---|
| Trivy binary/image v0.69.4 | 2026-03-19 18:22 to approximately 21:42 | Start is artifact-availability time; end is approximate. |
| `aquasecurity/trivy-action` | Approximately 2026-03-19 17:43 to 2026-03-20 05:40 | Both boundaries are marked approximate. |
| `aquasecurity/setup-trivy` | Approximately 2026-03-19 17:43 to 21:44 | Both boundaries are marked approximate. |
| Docker Hub images v0.69.5 and v0.69.6 | 2026-03-22 15:43 to approximately 2026-03-23 01:40 | End is approximate; this was a direct registry push, not a GitHub workflow release. |

The same advisory states:

- 76 of 77 pre-0.35.0 `trivy-action` tags were force-pushed to malicious content; 0.35.0 was not affected.
- All seven then-existing `setup-trivy` tags were replaced; safe v0.2.6 was recreated during remediation and older tags were not restored under the same names.
- Explicit `version: latest` in `trivy-action` could obtain the bad Trivy binary during the binary window.
- A SHA-pinned older `trivy-action` could still be transitively exposed through its mutable `setup-trivy` dependency. The pinned wrapper SHA is not thereby malicious.
- The advisory publishes primary IOC tables for executable SHA-256 values, OCI image digests, network indicators, and fallback repository naming.
- Malicious tags/artifacts were removed or repaired, so current repository and registry state cannot clear historical exposure.

Sources: [maintainer GHSA](https://github.com/aquasecurity/trivy/security/advisories/GHSA-69fq-xp46-6x23), [initial maintainer incident discussion](https://github.com/aquasecurity/trivy/discussions/10425), and [maintainer conclusion](https://github.com/aquasecurity/trivy/discussions/10462).

### Candidate pack material after review

- Separate component records and windows for `trivy-action`, `setup-trivy`, the Trivy binary/package, and container images. Do not collapse them into one global window.
- Exact Action SHAs only after extracting full values from primary repository objects or the maintainer's accepted IOC data. Short release-chain SHAs in narrative prose are not pack-ready.
- The maintainer's executable hashes and OCI digests, ingested mechanically from a pinned source snapshot and independently length/format checked. Manual retyping of the large table is avoidable risk.
- Literal domain/IP and fallback repository-name indicators, each scoped to its incident behavior and unable by itself to prove Action execution or data theft.
- Known-safe versions as remediation metadata; known-good SHAs only after resolving and reviewing their immutable objects.

### Conflicts and insufficient evidence

- Approximate boundaries must not be normalized into source-claimed exact RFC3339 instants. Use the implemented `sourcePrecision`, `approximation`, `originalClaim`, and boundary fields to preserve the source's precision and any explicitly derived conservative search window.
- “Any tag prior to 0.35.0” and “76 of 77 tags” require an exact historical tag inventory before a pack enumerates individual refs. A numeric range is not a substitute for observed ref movement.
- `setup-trivy@v0.2.6` has distinct bad and later safe historical identities. Current resolution alone is specifically misleading.
- Old SHA-pinned `trivy-action` commits described as transitively exposed must not be added to `compromisedSHAs`; their nested resolution belongs in dependency-chain rules.
- Docker Hub v0.69.5/v0.69.6 publication did not originate from a GitHub workflow. CIRewind v0.1 cannot claim organization-wide discovery of direct Docker pulls unless retained logs independently contain those exact immutable digests.
- Executable archive hashes and OCI manifest digests are different namespaces. They cannot share an untyped `digest` field.
- The incident extends beyond GitHub Actions. The real pack must clearly state which indicators CIRewind can match in v0.1 and which are retained solely for contextual/log matching.

### Prohibited conclusions

- “All Trivy users were compromised.”
- “All pre-0.35.0 Action commits were malicious.”
- “A current safe v0.2.6 tag proves an earlier run was safe.”
- “A Trivy deployment after a matching job was attacker-caused.”
- “No network IOC in GitHub logs proves no exfiltration.”
- “The March 22 Docker Hub event was a GitHub Actions run.”

### Pack readiness

The schema supports component-specific approximate windows and typed digest namespaces. The maintainer source is sufficiently detailed to begin a real pack, but full Action SHA extraction, typed assignment of the large IOC table, boundary decisions, and deterministic source-to-pack review remain required; manual transcription is not sufficient.

## Xygeni mutable-tag compromise, March 2026

### Verified primary-source facts

- The affected component is `xygeni/xygeni-action` at mutable ref `v5`.
- The maintainer GHSA identifies full malicious commit `4bf1d4e19ad81a3e8d4063755ae0f482dd3baf12`.
- The GHSA says the tag pointed to a commit from an unmerged pull request. Main-branch history therefore cannot be used as a proxy for what the Action ref resolved to.
- The GHSA describes the affected period only as approximately March 3–10, 2026 and also calls it approximately six days.
- It publishes the network indicators `91.214.78.178` and `security-verify.91.214.78.178.nip.io`.
- It gives `13c6ed2797df7d85749864e2cbcf09c893f43b23` as the verified safe v6.4.0 commit candidate and says the compromised `v5` tag was removed.
- The GHSA explicitly says no confirmed downstream-user exploitation had been established at publication.

Sources: [maintainer GHSA](https://github.com/xygeni/xygeni-action/security/advisories/GHSA-f8q5-h5qh-33mh), [GitHub-reviewed record](https://github.com/advisories/GHSA-f8q5-h5qh-33mh), and [issue #54](https://github.com/xygeni/xygeni-action/issues/54).

### Candidate pack material after review

| Candidate | Source precision | Safe interpretation |
|---|---|---|
| Repository, ref `v5`, malicious full SHA | Exact | Core mutable-ref and exact-runtime indicators. |
| Approximately March 3–10, 2026 | Date-only and approximate | Search-window lead; not exact start/end. |
| IP and DNS name | Exact literals | Corroborating log/network indicators; not proof of successful callback. |
| Safe full SHA above | Exact value in GHSA | Candidate `knownGoodSHA`, subject to independent object/content review. |

### Conflicts and insufficient evidence

- The approximately March 3–10 span and “approximately six days” description do not provide exact endpoints and are not arithmetically precise enough to infer them. No exact timestamp should be invented.
- The maintainer GHSA page shows affected version `v5`, while the normalized GitHub Advisory Database expresses an ecosystem range introduced at 5 and fixed at 6.4.0. For this tag-poisoning incident, the exact bad SHA plus mutable `v5` window is safer than treating every immutable 5.x/6.x commit as compromised.
- The GHSA references an incident blog with a placeholder URL; a dedicated Xygeni incident report was not located in primary-source search by the retrieval date.
- The advisory's statement that any referencing workflow executed the implant is too coarse for CIRewind. A declaration, a runner download, a skipped step, and a begun step remain distinct case outcomes.
- An unmerged malicious commit can remain fetchable in the Git object store. Absence from current branches and deletion of `v5` are not evidence of historical safety.

### Prohibited conclusions

- “Every run referencing `@v5` executed the implant.”
- “A declaration of `@v5` proves the malicious SHA resolved.”
- “The C2 endpoint was contacted” without case network/log evidence.
- “Downstream exploitation or secret theft occurred.”
- “The normalized affected semver range is a list of bad commits.”

### Pack readiness

The component, ref, bad SHA, network literals, and candidate known-good SHA are primary-sourced. The schema can preserve approximate/date-level boundaries without false precision, but a production pack still requires either a primary exact timeline or a reviewed conservative expansion with explicit day precision and boundary semantics.

## Cross-incident reconstruction lessons

| Incident | Why current YAML/ref state is insufficient | Required CIRewind evidence path |
|---|---|---|
| tj-actions | Many tags were restored after pointing at one bad commit. | Attempt/job setup log exact SHA, then step-start correlation. |
| reviewdog | A pinned wrapper could call a mutable nested `action-setup@v1`. | Historical wrapper metadata plus nested runtime download; never stop at top-level pin. |
| Trivy | Different Actions, binary downloads, and registry artifacts had different windows; a ref was bad and later recreated safe. | Component-specific pack rules, exact Action SHA/digest logs, composite/transitive reconstruction, typed digests. |
| Xygeni | A tag pointed to an unmerged commit and was later deleted. | Runtime SHA evidence or conservative mutable-ref/window state; current branch/tag lookup is non-probative. |

The sources repeatedly use broad phrases such as “used,” “affected,” or “executed.” Those phrases are remediation guidance, not permission to collapse CIRewind's mandatory semantic states.

## What must never enter a real pack

- Synthetic SHA, digest, IP, domain, repository, ref, date, or window presented as a real incident value.
- An abbreviated commit SHA.
- A secondary article's indicator that cannot be found in a primary source or immutable repository object.
- A regex copied from an incident scanner without bounded-engine review and primary-source validation.
- Exact seconds added to a date-only or approximate source without a labeled derivation.
- A current tag target represented as the historical target.
- A semver vulnerability range mechanically converted into compromised immutable commits for a temporal tag-poisoning event.
- A wrapper commit mislabeled as malicious merely because it called a compromised mutable dependency.
- Payload scripts, shell commands, embedded HTML, templated network requests, or any other executable incident content.
- Secret values, leaked log blobs, decoded runner memory, authentication material, or hashes of secrets.
- Claims of exfiltration, cloud-role assumption, deployment causation, or attacker success without direct case evidence.
- A source URL with no retrieval metadata or source-object hash.

## Required follow-up before checking in real packs

1. Apply the implemented window-precision, approximation, boundary, and typed-digest fields consistently, and record reviewer decisions for every approximate or inclusive boundary.
2. Resolve the tj-actions 46.0.0 versus 46.0.1 patched-version conflict or omit the disputed version in favor of verified full known-good SHAs.
3. Reconstruct and peer-review the exact reviewdog wrapper-to-action-setup dependency mappings at historical wrapper SHAs.
4. Mechanically extract Trivy's full Action indicators and hash/digest tables from a pinned primary source, then independently reproduce the result.
5. Seek an exact Xygeni timeline or explicitly accept a date-precision pack with conservative, labeled search behavior.
6. Build synthetic fixtures for all four incident shapes before introducing real values into tests. Synthetic fixtures must use unmistakably reserved repositories, fake hashes, fake secrets, and non-routable network indicators.
7. Require two-maintainer review, source diff, deterministic validation, and a tagged, hash-recorded pack release for each real incident pack. Cryptographic pack signing remains a later-version design question.

Until those steps are complete, these incidents are validated research targets, not release-ready packs.
