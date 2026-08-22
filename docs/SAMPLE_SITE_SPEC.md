# Synthetic sample site specification

Status: accepted v0.2 GitHub Pages contract as of 2026-08-22.

The sample site lets a visitor understand CIRewind without installing software,
cloning the repository, authenticating to GitHub, or trusting a real incident
pack. It contains only deterministic synthetic output.

This planning pass does not enable Pages, create a workflow, deploy a site,
change the repository homepage, or claim public availability.

## Goals

- Show the exact temporal value proposition and evidence path immediately.
- Make the complete raw-disabled synthetic case viewable and downloadable.
- Keep all content static, offline-capable, privacy-preserving, and inert.
- Generate the site from the same embedded demo/oracle used by the installed CLI.
- Verify every sample case before deployment and bind it to an exact release
  source revision.
- Preserve the experimental qualification and partial-coverage warning.

## Non-goals

- Hosted investigation, archive upload, case sharing service, analytics,
  telemetry, comments, authentication, search API, or dynamic pack registry.
- Rendering real victim data or a candidate real incident as fact.
- Replacing the case manifest with Pages deployment metadata.
- Claiming GitHub Pages supplies custom forensic custody, authenticity, or legal
  certification.
- Loading a CDN, remote font, remote image, external script, iframe, analytics
  pixel, social embed, or service worker.
- Enabling Discussions or other repository settings as a hidden implementation
  side effect. Discussions are a separate optional maintainer decision.

## Static architecture

The source repository owns a small deterministic site template and generator.
The build creates a fresh private staging tree; checked-in report fields and
pack content never control output paths.

```text
site source/template
       + exact release source revision
       + embedded synthetic demo bundle
                         |
                         v
               build cirewind binary
                         |
                         v
            cirewind demo --out case-a
            cirewind demo --out case-b
                         |
          verify both + byte-compare all files
                         |
                         v
              deterministic site generator
                         |
                         v
              staged Pages artifact audit
                         |
                         v
             protected Pages deployment job
```

The site generator copies only an allowlisted set of generated outputs and writes
fixed HTML from escaped structured data. It does not parse arbitrary HTML from
the report, pack, or GitHub metadata. It has no network client and performs no
child process beyond the reviewed build orchestration around the CLI.

Recommended repository structure during implementation:

```text
site/
  README.md
  templates/index.html.tmpl
  assets/                 # locally owned fixed assets only, if any
  generated/              # deterministic reviewed sample snapshot, if committed
scripts/
  build-sample-site.*
```

Any generated snapshot committed for README image stability is mechanically
regenerated and checked for a clean diff in CI. It is never hand-edited.

## Published tree

The Pages artifact has no symlink or hard link and contains:

```text
index.html
v0.2.0/
  index.html
  site-manifest.sha256
  graph.svg
  findings.json
  summary.md
  sample-case/
    report.html
    graph.svg
    graph.json
    findings.json
    affected-runs.csv
    summary.md
    collection-metadata.json
    evidence.jsonl
    case.db
    manifest.sha256
  downloads/
    cirewind-synthetic-case-v0.2.0.tar.gz
    SHA256SUMS
  provenance.json
```

The exact versioned path is immutable in site policy. The root is a generated
copy/landing link for the current stable sample; it does not silently change the
content under `/v0.2.0/`. Future deployments must retain old versioned trees or
explicit tombstones. Each prior tree or tombstone is checked in or supplied as
a hash-locked release input; site generation never fetches the currently
deployed Pages site to reconstruct history.

The browsable top-level `graph.svg`, `findings.json`, and `summary.md` are
byte-identical copies from the case. The only case manifest remains beside the
files it covers under `sample-case/`; copying it to another directory would make
its relative paths misleading. `sample-case/` contains the complete fixed
raw-disabled case and no `raw/`. The deterministic tar archive
contains exactly that case tree with sorted entries, fixed timestamps, numeric
owner/group zero, normalized safe modes, no links, and no host paths. Its
SHA-256 appears in `SHA256SUMS` and on the page.

The complete synthetic raw-disabled case, including `case.db` and
`evidence.jsonl`, is published both as allowlisted individual files and inside
the archive after the same privacy, hostile-data, and size audit. This is a
resolved v0.2 distribution decision; an audit failure blocks the site rather
than silently publishing a partial “complete case.”

`v0.2.0/site-manifest.sha256` covers every regular file below the versioned
directory except itself, including the case manifest, case files, archive,
download checksum, and provenance record. It is distinct from
`sample-case/manifest.sha256`, which verifies only the case contract. Both use
canonical sorted relative paths; modifying, omitting, or adding a versioned file
fails the site audit. The mutable root `index.html` is outside the immutable
version manifest and contains only a fixed current-version landing/link.

## Landing-page content hierarchy

The exact top-to-bottom hierarchy is:

1. **Headline:** “Reconstruct which GitHub Action commit actually ran—even after
   a mutable tag was restored.” Do not use “prove compromise.”
2. **Temporal evidence path:** the generated `graph.svg` displayed as a
   same-origin `<img>` with useful `alt`; adjacent link opens the standalone SVG.
3. **Result counts:** all key counts from the synthetic oracle, including a
   conspicuous `SYNTHETIC — PARTIAL COVERAGE` label.
4. **Primary actions:** “Open sample report,” “Download verified sample case,”
   and “View manifest.”
5. **Two-minute local command:** fast installation lane followed by
   `cirewind demo --out cirewind-demo` and `cirewind verify cirewind-demo`.
6. **What the A-to-B-to-A case demonstrates:** B executed, B downloaded without
   execution, attempts remain separate, restored A does not rewrite history,
   missing logs remain gaps.
7. **Mandatory distinctions:** the eight exact invariants from the evidence
   model, unedited.
8. **Installation lanes:** fast evaluation first; high-assurance checksums,
   SBOM, provenance, and attestations clearly linked and not displaced.
9. **Experimental qualification and limitations:** supported envelope, partial
   coverage, and what GitHub evidence alone cannot prove.
10. **Privacy and provenance:** synthetic-only, no analytics/telemetry, no
    uploads, exact generator revision, case manifest digest, and regeneration
    instructions.

The first normal desktop viewport contains items 1–5 and the word
`experimental`. The warning is not buried; it follows the concrete value rather
than preceding every result.

The fast-evaluation block uses one of these exact released lanes and never a
moving branch or `curl | sh` installer:

```text
brew install torjan0/tap/cirewind
cirewind demo --out cirewind-demo
cirewind verify cirewind-demo
```

or, for users with the supported Go toolchain:

```text
go install github.com/torjan0/cirewind/cmd/cirewind@v0.2.0
cirewind demo --out cirewind-demo
cirewind verify cirewind-demo
```

These exact blocks and their predictable versioned URLs are reviewed and frozen
in the release-candidate commit, but that commit does not become the default
branch while the commands are still unqualified. Publishing the immutable tag
can make the candidate README visible through the tag briefly before all public
lanes pass; the repository landing page remains on the prior release during that
interval. After the tagged Go install, Homebrew, Pages, release-download, and
north-star preview checks pass, coordinated activation is a leased fast-forward
of the default branch to the already tagged commit, not a new README edit or
commit. The high-assurance lane links to
the complete release set and its current checksum/attestation procedure.

The blocking reference hosts are Ubuntu 24.04 amd64 with 2 vCPU and 4 GiB RAM,
and macOS 15 arm64 with Homebrew already installed. Windows 11 amd64 is
informational. Each blocking lane runs five clean trials with a new output
directory and no CIRewind cache. `T_demo` spans installed-binary invocation
through successful case-manifest verification: p50 at most 15 seconds and no
run over 30 seconds. `T_total` spans the documented installation command through
that same verification point: p50 at most 120 seconds and no run over 180
seconds. Browser opening is a separate smoke test. Homebrew retains and records
normal auto-update behavior; the `go install` lane includes any automatic Go
toolchain download. Bottles remain deferred for v0.2.

## Required synthetic counts

The site reads its counts from validated `findings.json` and checks them against
the demo oracle. It never maintains independent handwritten totals.

| Finding state | Count |
|---|---:|
| `CONFIRMED_EXECUTED` | 1 |
| `CONFIRMED_DOWNLOADED` | 1 |
| `CONFIRMED_CALLED_WORKFLOW` | 1 |
| `DECLARED_AT_RUN_SHA` | 1 |
| `RUN_IN_WINDOW_MUTABLE_REF` | 1 |
| `POTENTIAL_TRANSITIVE` | 2 |
| `CURRENT_REFERENCE_ONLY` | 1 |
| `NO_MATCH_CONFIRMED` | 1 |
| `UNKNOWN_EVIDENCE_GAP` | 1 |
| `CONTRADICTORY_EVIDENCE` | 1 |
| **Total** | **11** |

The adoption summary also shows one write-capable token job, one named-secret
flow, one OIDC-minting-capable job, and one affected self-hosted-runner job, each
labeled synthetic and phrased as capability/relationship. It does not claim a
write, secret read, cloud-role assumption, runner persistence, or malicious
deployment.

## Links

Use fixed relative same-origin paths for sample content:

- `./v0.2.0/sample-case/report.html`
- `./v0.2.0/graph.svg`
- `./v0.2.0/findings.json`
- `./v0.2.0/summary.md`
- `./v0.2.0/sample-case/manifest.sha256`
- `./v0.2.0/site-manifest.sha256`
- `./v0.2.0/downloads/cirewind-synthetic-case-v0.2.0.tar.gz`
- `./v0.2.0/downloads/SHA256SUMS`
- fixed repository source/release links chosen by trusted build configuration,
  not a pack or report field.

The only additional external navigation allowed in v0.2 is the exact reviewed
HTTPS stable reproduction-index URL under
`github.com/torjan0/cirewind-lab/tree/main/reproductions`. Its host, owner,
repository, branch, and path are build-time constants; a report, pack, registry,
or label cannot alter them. Render it without `target`, with `rel="noreferrer"`,
and include it in deterministic link/redirect auditing. Individual immutable
reproduction commit links are followed from that external index, not injected
into the frozen site.

No user-controlled URL is made clickable. Do not use any other external URL,
URL shortener, tracking
parameters, `javascript:`, data URLs, automatic downloads, `target=_blank`, or
pack source URLs as site navigation.

The exact release-candidate README contains the predictable final HTTPS Pages
URL and versioned installation commands before freeze. It stays off the default
branch until the authorized public deployment and anonymous lane checks pass.
Activation uses an expected-old-tip lease to fast-forward the default branch to
that exact tagged commit; it does not substitute URLs, regenerate imagery, or
create a post-freeze documentation commit. The prior default-branch tip is
merge-frozen from RC qualification through activation. Divergence, or a URL
shape that cannot be known before freeze, is a NO-GO requiring a new release
candidate; do not merge or rebase around the audited tag and do not use a
placeholder or post-freeze edit.

## Content security policy

The landing page requires no JavaScript. A meta policy uses a hash for the fixed
inline stylesheet and denies everything else, for example:

```text
default-src 'none';
img-src 'self';
style-src 'sha256-...';
script-src 'none';
connect-src 'none';
font-src 'none';
media-src 'none';
object-src 'none';
frame-src 'none';
worker-src 'none';
manifest-src 'none';
base-uri 'none';
form-action 'none'
```

The exact serialized one-line policy and stylesheet hash are golden-tested. The
design does not rely on project-controlled response headers because the cited
Pages workflow contract does not define a per-file custom-header mechanism. The
implementation audit must record the actual deployed headers. The project must
not claim that a meta policy supplies `frame-ancestors`,
`X-Content-Type-Options`, or download headers. Security must also come from inert
content and safe embedding. If GitHub later documents a supported header
mechanism, it may add defense in depth after primary-source and live validation;
it does not replace the content rules.

The standalone SVG contains only the allowlisted inert primitives in
[`TEMPORAL_EVIDENCE_PATH_SPEC.md`](TEMPORAL_EVIDENCE_PATH_SPEC.md). The landing
page embeds it with `<img>`, never `<object>`, `<embed>`, `<iframe>`, or inline
untrusted markup. The case report retains its own strict meta CSP and inline
trusted visual model.

## Privacy contract

- No analytics, beacon, telemetry, cookies, local/session storage, service
  worker, comment widget, form, search request, font service, CDN, or third-party
  embed.
- No GitHub token, Authorization header, signed redirect, credential, secret
  value/hash, raw log, private repo name, user home path, host name, or private
  lab record in source or generated output.
- The page sets a `no-referrer` policy in markup where supported.
- All example identities are unmistakably synthetic or public project/lab
  references reviewed for publication.
- GitHub states that it logs and stores a visitor's IP address for security when
  a Pages site is visited; see
  [What is GitHub Pages?](https://docs.github.com/en/pages/getting-started-with-github-pages/what-is-github-pages)
  (retrieved 2026-08-22). The privacy notice therefore says the project itself
  adds no telemetry rather than claiming that no infrastructure logs exist.
- The site never uploads, accepts, or processes a visitor's case.

## Deterministic regeneration

The sample is built from an exact annotated v0.2 release tag or exact approved
release commit. The workflow verifies tag-to-commit binding and supplies the
same deterministic version/commit/build-date values as release tooling.

For the same source revision/toolchain/site policy:

- generate two demo cases into separate temporary paths;
- verify both manifests;
- compare all material bytes including `case.db` and `graph.svg`;
- create two site trees and byte-compare them;
- generate and verify the versioned site manifest after all versioned content is
  staged, excluding only that manifest itself;
- create deterministic archives twice and compare hashes;
- ensure generated files contain no staging/output path or wall-clock time;
- record source revision, Go version, generator schema, demo bundle version,
  and case/archive hashes in `provenance.json`.

Deployment time, run ID, and Pages URL are not embedded in deterministic sample
bytes. They may appear only in GitHub deployment metadata outside the site
artifact. Previous version trees come only from reviewed, locally available,
hash-locked inputs and are byte-compared to their recorded site manifests.

## GitHub Actions workflow design

Use separate validation and deployment paths.

### Pull request and `main` validation

- Trigger on `pull_request`, `push` to `main`, and explicit validation dispatch.
- Top-level `permissions: {}`; build job receives `contents: read` only.
- Never use `pull_request_target`.
- Checkout without persisted credentials.
- Build the CLI, run tests relevant to demo/site/SVG, generate twice, verify,
  compare, scan, and audit links/CSP/browser behavior.
- Do not deploy from a pull request, fork, or unreviewed branch.

### Protected deployment

- The deployment workflow and any manually dispatched release workflow already
  exist in the pre-activation default-branch base. GitHub documents that a
  `workflow_dispatch` trigger receives events only when its workflow file is on
  the default branch; selecting the immutable tag as the run ref does not remove
  that prerequisite.
- Manual dispatch names an existing annotated `v0.2.0` tag and is run at that
  exact ref, or an equally strict release-published trigger is separately
  accepted.
- Revalidate annotated tag, checked-out commit, release status, and exact sample
  hashes before upload.
- Build job uses `contents: read` only.
- Upload the allowlisted Pages artifact once under a trusted name unique to the
  workflow run/attempt; record the upload Action's returned `artifact_id`, retain
  CIRewind's locally computed site-tree/site-manifest and deterministic archive
  hashes, and make the deploy job
  depend on that exact build job. Do not claim the upload Action returns a
  digest or that a local site/archive hash identifies the artifact-service
  object.
- Pass that exact trusted name to `deploy-pages`. Its current public input is
  `artifact_name`, not artifact ID, so the workflow must not claim ID-addressed
  deployment. The returned ID plus local hashes leaves an explicit uploaded-byte
  identity trust gap. If a separately implemented pre-deploy API download or
  identity/digest check
  requires `actions: read`,
  add it only after primary-source and mock/dry-run validation; otherwise keep
  the documented minimum `pages: write` and `id-token: write` permissions.
- Deployment uses the protected `github-pages` environment and records the URL
  as deployment output.
- Concurrency prevents simultaneous production deployments; cancellation never
  leaves a partially assembled artifact because Pages deploys one complete
  uploaded artifact.

GitHub documents that custom Pages workflows use `configure-pages`,
`upload-pages-artifact`, and `deploy-pages`; the deploy job requires at least
`pages: write` and `id-token: write`, and the uploaded archive must not contain
symbolic or hard links. CSP behavior follows the W3C specification. Platform and
security sources retrieved 2026-08-22:

- [GitHub Docs — Using custom workflows with GitHub Pages](https://docs.github.com/en/pages/getting-started-with-github-pages/using-custom-workflows-with-github-pages)
- [GitHub Docs — Workflow syntax for `workflow_dispatch`](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#onworkflow_dispatch)
- [GitHub Docs — Configuring a publishing source](https://docs.github.com/en/pages/getting-started-with-github-pages/configuring-a-publishing-source-for-your-github-pages-site)
- [GitHub source — `upload-pages-artifact` action contract](https://github.com/actions/upload-pages-artifact/blob/main/action.yml)
- [GitHub source — `deploy-pages` action contract](https://github.com/actions/deploy-pages/blob/main/action.yml)
- [W3C — Content Security Policy Level 3](https://www.w3.org/TR/CSP/)

Every workflow Action is pinned to a full commit verified from its source
repository at implementation time and recorded in `.github/actions-pins.json`.
This plan intentionally provides no guessed pins.

## Generated-asset allowlist

The build fails if the staged artifact contains:

- an entry not in the versioned allowlist;
- a symlink, hard link, device, socket, FIFO, executable bit, or unsafe path;
- a file over its type-specific budget or aggregate artifact budget;
- `raw/`, a raw log, a token-shaped/private-key value, or credential header;
- source maps, package-manager caches, Git metadata, temporary files, OS metadata,
  or developer paths;
- an external URL in HTML/CSS/SVG other than fixed visible project
  source/release links and the one exact lab reproduction-index URL reviewed by
  policy;
- an active SVG element/attribute or CSP-violating HTML primitive.

The Pages archive remains well below GitHub's platform maximum; CIRewind applies
a tighter initial aggregate budget of 64 MiB and records any later reviewed
change.

## Accessibility and responsive behavior

- Semantic heading order follows the content hierarchy.
- The graph has meaningful alt text and adjacent text-equivalent relationships.
- Count tables include headers and do not encode meaning by color alone.
- Links have descriptive visible names and visible keyboard focus.
- Fixed content remains usable at 320 CSS pixels, 200% zoom, dark/light forced
  colors, and with images/CSS/JavaScript disabled.
- No motion, autoplay, hover-only content, drag-only interaction, or canvas.
- A manual screen-reader and keyboard review is recorded on the release
  candidate.

## Required tests and release evidence

1. Fresh exact-tag builds generate byte-identical case, site, and archive twice.
2. The case manifest, versioned site manifest, and download checksum verify; a
   one-byte mutation fails.
3. Generated counts equal the demo oracle and all state names are canonical.
4. Static server/browser audit records zero third-party requests and no severe
   console/CSP errors.
5. Network-denied local copy loads landing page, report, and SVG; relative links
   work under the GitHub project Pages base path.
6. HTML/SVG/JSON/Markdown fields containing hostile markup remain inert.
7. CSP hash, no-script behavior, no-form behavior, no-service-worker behavior,
   no remote assets, and no analytics are mechanically checked.
8. Pages artifact rejects links, unexpected entries, unsafe modes/paths, raw
   evidence, credential patterns, and size overflow.
9. Accessibility automation plus manual keyboard/screen-reader/zoom/contrast
   review passes.
10. PR/fork workflow has read-only permissions and cannot deploy; deployment
    workflow uses only reviewed permissions/environment.
11. All Action pins resolve to source-verified full commits and the repository
    selected-Action policy allows exactly the required set.
12. After authorized deployment, anonymously fetch every linked artifact,
    reverify bytes/checksums, inspect response/content types, and compare the
    public report/counts with the release tree.

## Maintainer-only gates

Maksim must explicitly authorize or perform:

- enabling GitHub Pages with Actions as the publishing source;
- approving additions to the repository's selected-Action allowlist;
- creating/reviewing protection for the `github-pages` environment;
- authorizing the first production deployment;
- visually reviewing the exact public output and downloads;
- setting the repository homepage URL;
- placing the recorded default-branch tip under a temporary merge freeze and
  later authorizing its leased fast-forward to the exact tagged release-
  candidate commit only after pre-staged links resolve;
- deciding whether Discussions are enabled as a separate community feature.

No local build, documentation checkbox, or automated test changes repository
settings or satisfies these gates.
