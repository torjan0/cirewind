# Synthetic sample site

This directory documents the deterministic synthetic sample site described in
[`docs/SAMPLE_SITE_SPEC.md`](../docs/SAMPLE_SITE_SPEC.md). Nothing here is
deployed by the repository yet. The read-only validation workflow (`SITE-004`),
the protected exact-tag deployment workflow (`SITE-005`), and the manual
keyboard, screen-reader, zoom, and contrast review (`SITE-003`) remain open in
[`TASKS.md`](../TASKS.md).

## What the generator does

`tools/samplesite` builds one immutable versioned tree from one verified,
raw-disabled synthetic case produced by `cirewind demo`:

```text
index.html                         mutable root link to the current version
v<VERSION>/
  index.html                       landing page rendered from typed data
  site-manifest.sha256             covers every regular file below v<VERSION>/ except itself
  graph.svg, findings.json, summary.md   byte-identical copies of the case files
  sample-case/                     the complete case, including case.db and manifest.sha256
  downloads/cirewind-synthetic-case-v<VERSION>.tar.gz   deterministic archive of sample-case/
  downloads/SHA256SUMS             SHA-256 of the archive
  provenance.json                  source commit, Go version, schema, bundle, counts, digests
```

The generator never parses report, pack, or GitHub content as markup. The
landing page is rendered by `html/template` from a fixed template and typed
values; every count is derived from `findings.json` and compared against the
embedded demo oracle before rendering. The case is copied only after
`manifest.sha256` verifies, the exact file set matches the oracle, and the
metadata declares a synthetic, raw-disabled case under the v0.2 contract.

Every build stages into a private directory, audits the staged tree, and only
then renames it to the requested output, which must not already exist. The
audit rejects: files outside the exact allowlist; symbolic links, hard links,
special files, and executable bits; files over their type budget or an aggregate
budget of 64 MiB; `raw/`; private-key, token, and credential-header shapes;
home, temporary, and Windows profile paths; active or external SVG constructs;
HTML primitives the content security policy forbids; external URLs other than
the fixed project, versioned release, and lab reproduction-index links; and any
mismatch between the case manifest, the site manifest, the download checksum,
and the provenance record.

## Determinism and provenance

`provenance.json` records the source commit, Go toolchain, generator schema,
demo bundle identity and fixture version, the case manifest digest, the archive
name, digest, and length, and the canonical state counts. It contains no wall
clock time, run identifier, host name, or path. Two builds from the same
revision and toolchain produce byte-identical trees; the build script proves
this by generating two demo cases and two sites and comparing every byte before
publishing one copy.

## Regenerating and verifying

```sh
make sample-site SITE_VERSION=0.2.0 SITE_OUT=DIR
```

runs `scripts/build-sample-site.sh`, which requires a clean working tree unless
`CIREWIND_SITE_ALLOW_DIRTY=1` is set for a local trial. The script builds the
CLI and the generator, generates and verifies two demo cases, byte-compares
them, builds two sites, byte-compares them, verifies one, and moves it to `DIR`.

```sh
go run ./tools/samplesite verify --site DIR --version 0.2.0
```

re-audits a published tree and prints the case manifest, archive, and site
manifest digests. `make sample-site-check` runs the package tests and an
end-to-end build, verify, and one-byte tamper check.

## Prior version trees

Later versions keep earlier versioned trees or tombstones beside the current
tree. Each prior tree is supplied to `samplesite build` as a locally available,
hash-locked input in the form `--prior VERSION@SITE_MANIFEST_SHA256@DIR`; the
generator verifies the recorded manifest against the supplied digest and against
every file, copies the tree verbatim, and never fetches the deployed site.
`samplesite verify` takes the same locks without the directory
(`--prior VERSION@SITE_MANIFEST_SHA256`).

## External links and privacy

The generated pages contain exactly three external destinations: the project
repository, the versioned release page, and the lab reproduction index. All
carry `rel="noreferrer"`, and the pages send no referrer, load no script, font,
frame, form, storage, or remote asset, and embed the graph only as a same-origin
image under a hashed-style, deny-by-default content security policy. GitHub
Pages platform logging is outside the site's control and is described on the
page rather than denied.
