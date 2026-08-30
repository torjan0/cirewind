# Incident-pack governance local qualification

Date: 2026-08-30

Branch: `v0.2-adoption`

Status: local pre-commit engineering qualification. No commit, push, pull
request, real incident candidate, human approval, promotion, release, or
repository-setting change is established by this record.

## Scope

This pass qualified the generic v0.2 incident-pack governance foundation:

- closed retained-record schemas and strict Go decoders;
- candidate, fixture, source, claim, conflict, review, promotion, and registry
  validation;
- deterministic review rendering and integrity manifests;
- exact-C Git guards and candidate/infrastructure change-set separation;
- read-only platform-review snapshot normalization;
- deterministic promotion and append-only registry verification;
- synthetic fixture replay through the production offline analysis path; and
- release-archive exclusion of candidate and review-governance material.

It did not evaluate the factual truth of a real incident pack and did not
substitute automation for required human review.

## Corrective findings closed before qualification

1. Invalid decoded path-bearing fields could accumulate a diagnostic but reach
   a derived filesystem lookup before return. Path and identifier validation is
   now a hard precondition. The repository-wide variant method and residual
   boundary are recorded in
   [`2026-08-30-pack-review-path-variant-audit.md`](2026-08-30-pack-review-path-variant-audit.md).
2. Go decoding could erase the distinction between omitted values and explicit
   JSON `null`. A bounded streaming shape pass now enforces required fields and
   rejects non-schema nulls before typed decoding. `Claim.canonicalPointer` is
   the sole intentional nullable value.
3. A clean Git checkout cannot retain an empty `approvals/` directory. The tree
   contract now permits absence only at candidate stage with no review or
   promotion material; review-in-progress and later states require the real
   closed directory.
4. The candidate change-set gate originally lived in candidate-modifiable
   `pull_request` CI and could not bootstrap while its trusted-base script was
   absent. It now uses the dedicated default-branch
   `.github/workflows/pack-review-candidate-policy.yml`
   `pull_request_target` workflow. Only the exact trusted-base guard executes;
   the exact PR head is inert Git data, permissions are `contents: read`, and
   identity drift fails closed. GitHub's
   [`pull_request_target` security guidance](https://docs.github.com/en/actions/reference/security/securely-using-pull_request_target)
   and [event semantics](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#pull_request_target)
   were retrieved 2026-08-30.
5. A pre-existing byte-identical reviewed-pack destination could alias a
   candidate input through a hard link. Promotion now requires the reviewed
   pack to be a physically distinct file from both immutable candidate copies,
   while preserving idempotency for separate byte-identical files.

No remaining code or security blocker was found in the bounded governance
foundation after these corrections.

## Commands and results

The following checks passed against the final local bytes:

```text
git diff --check
go mod verify
go mod tidy -diff
actionlint -shellcheck shellcheck .github/workflows/*.yml
shellcheck scripts/pack-review-git-guard.sh \
  scripts/pack-review-candidate-change-guard.sh \
  scripts/test-pack-review-git-guard.sh \
  scripts/test-pack-review-candidate-change-guard.sh
sh scripts/test-pack-review-git-guard.sh
sh scripts/test-pack-review-candidate-change-guard.sh
go test ./... -count=1
go vet ./...
go test -race ./... -count=1
go run ./tools/packreview validate-governance --repository-root .
make safety-audit
gitleaks dir --no-banner --redact --exit-code 1 .
gitleaks git --no-banner --redact --exit-code 1 .
sh scripts/preflight.sh
```

The final fresh-cache preflight additionally passed:

- the deterministic demo qualification harness;
- reachable-vulnerability analysis with no vulnerability found;
- third-party license checks;
- CGO-disabled builds for Linux, macOS, and Windows on amd64 and arm64;
- the complete 11-finding synthetic demo; and
- offline `cirewind.case/v1alpha2` manifest verification.

The syscall audit observed no network syscall and no child execution beyond the
invoked binary for pack validation, fixture archive, replay, case verification,
demo, and governance validation. The secret scans found no leak in the current
tree or the 13-commit reachable Git history.

Because the working tree is intentionally uncommitted, the production Git guard
correctly rejects it as a candidate input. A disposable clean Git snapshot of
the exact file set was therefore used to run `make pack-review-clean`,
`make pack-review-check`, and the final clean check. Exact-HEAD candidate-tree
validation passed; the disposable snapshot was then removed. This establishes
local behavior only, not GitHub-hosted or commit authenticity.

## Semantic result

- The ten canonical finding states and five provenance identifiers are
  unchanged.
- The downloaded-versus-executed fixture still forbids
  `CONFIRMED_EXECUTED` for downloaded-only evidence.
- No credential, secret, OIDC, cloud-role, deployment-causation, or missing-log
  predicate was strengthened.
- The empty checked-in maintainer policy and registry remain fail-closed.
- Candidate packs, review packets, approval records, and reviewed-pack plumbing
  remain outside release artifacts.

## Gates intentionally still open

- `PACK-019`: named eligible human maintainers and outside reviewers.
- `PACK-020` and `PACK-021`: exact committed bytes and hosted CI qualification.
- `PACK-022`: a qualifying human GitHub approval against exact candidate C.
- `PACK-023`: a real C-to-P-to-later-registry history.
- `PACK-024`: its `PACK-023` dependency, hosted complete governance CI, and the
  final workflow review on the exact committed revision.
- Every real Reviewdog, tj-actions, and Trivy candidate and its factual source
  review; Trivy still requires two outside reviewers.

The generic foundation is ready for a reviewable infrastructure commit, but no
real pack is eligible to be called reviewed or release-ready.
