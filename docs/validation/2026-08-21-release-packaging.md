# Release-packaging qualification record — 2026-08-21

Status: **local release-packaging sub-gate passed; v0.1 release gate not passed**

This record covers deterministic candidate construction, target-specific module
inventory, integrity verification, native offline smoke, and one isolated Linux
container smoke. It does not qualify live GitHub evidence semantics, non-native
runtime behavior, publisher identity, or the overall v0.1 definition of done.

## Environment

- Host: Linux 6.8.0-100-generic, x86-64.
- CPU: Intel Core i7-7700, 8 logical CPUs.
- Memory: 16,315,872 KiB reported by `/proc/meminfo`.
- Toolchain: `go1.25.13` from `go.mod`.
- Release builds: `CGO_ENABLED=0`, `GOENV=off`, `GOWORK=off`, empty
  `GOEXPERIMENT`, `GOFIPS140=off`, `GOAMD64=v1` or `GOARM64=v8.0`,
  `-trimpath`, `-buildvcs=false`, and an empty linker build ID.
- All temporary build caches and artifacts were placed on the separately
  designated large-work filesystem. No candidate entered the project tree.

The root filesystem reached zero reported free blocks during broader concurrent
qualification. No image was pulled or built for this work, no further container
commands were run after the recorded smoke, and unrelated Docker images,
containers, and volumes were not modified.

## Deterministic annotated-tag fixture

`scripts/test-release.sh` constructed a disposable Git repository from the
current nonignored source set, using an explicitly synthetic author and a fixed
UTC commit/tag time. It created annotated tag `v0.0.0-repro.test` at temporary
fixture commit:

```text
6b36d8fb8845eac64f7aaabaa5fb9d937e3e6e65
```

That object identifies only the deleted fixture repository. It is not a project
release commit or a real incident indicator.

The test invoked the full clean-tag wrapper twice. Each invocation created a new
`git archive` source snapshot, built all six targets, generated target SPDX and
license bundles, finalized checksums, and ran the deep verifier. The comparison
reported exact byte equality for every output file.

Observed result:

```text
release distributions are byte-for-byte reproducible
native release smoke passed for linux/amd64 (network credentials unset)
release packaging contract passed for clean annotated-tag snapshot, all six archives, native runtime, and tamper rejection
```

The native executable successfully ran `version`, root help, offline
`investigate --help`, synthetic `pack validate`, synthetic archive import,
offline replay/case generation, and case-manifest verification. Appending one
byte to a material external SPDX file caused release verification to fail as
required. The two test distributions and fixture Git repository were removed by
validated temporary-directory cleanup.

## Archive, SBOM, and license observations

A separate one-pass, explicitly synthetic container candidate contained exactly:

- six platform archives: deterministic tar+gzip for Linux/macOS and ZIP for
  Windows;
- six external SPDX 2.3 JSON documents;
- `release-metadata.json`; and
- `SHA256SUMS` covering all preceding root files.

Its total distribution size was 36,967,985 bytes. The Linux amd64 SPDX document
contained the CIRewind root package, exact Go toolchain, and nine modules present
in that binary's `debug/buildinfo`, with one `DEPENDS_ON` relationship per
runtime/toolchain dependency. Darwin and Windows inventories differed according
to their embedded target build graphs. Every archive's filtered license index
was reconciled against its binary; missing, extra, changed, replaced, or
unlicensed embedded modules fail verification.

The verifier also reconstructed each entire archive from extracted allowlisted
regular files and required byte equality. This checks canonical ordering,
timestamp, mode, tar owner fields, compression, links/devices, duplicate paths,
and traversal in addition to root checksums.

## Isolated Linux container smoke

The already-present local image was addressed only by immutable image ID:

```text
sha256:2607caa9805847fac4de202017bb1b830deb09f4c07dc9964a0157abbc604577
```

The script verified that exact local ID, refused pull behavior, and started the
container with:

- `--network none`;
- a read-only root filesystem;
- no Linux capabilities;
- `no-new-privileges`;
- UID/GID 65534;
- an ephemeral bounded tmpfs;
- the candidate archive bind-mounted read-only; and
- Docker logging disabled.

The Linux amd64 archive completed the same offline smoke path. `--rm` removed the
test container; no matching stopped container remained. The local image existed
before this qualification and was not pulled, built, tagged, or removed here.
This test records an image content ID, not independent provenance or
authentication of that image.

## Checks that passed

- Go unit tests for release metadata, canonical SemVer, target settings, SPDX
  determinism, target license coverage, archive round trips, traversal/link
  rejection, and distribution comparison.
- Targeted CLI tests after release-stamp integration.
- `go vet` for the new maintainer packages.
- ShellCheck for all release scripts.
- actionlint for both GitHub workflow files.
- All six external SPDX documents independently parsed and validated as SPDX
  2.3 with the official SPDX tools-python `spdx-tools` 0.8.5 CLI. The tool was
  installed only in the designated external validation area, not the repository
  or product dependency graph.
- Two complete six-target builds with exact byte-for-byte comparison.
- Deep verification of exact file sets, checksums, archive recipe, build stamp,
  Go build graph, module replacements, license hashes, and regenerated SPDX.
- Native Linux amd64 offline command smoke.
- Windows amd64 offline command compatibility smoke under Wine 9.0 after fixing
  drive-letter SQLite file-URI handling. This is not native Windows
  qualification; see `2026-08-21-release-authentication.md`.
- One-byte material-file tamper rejection.
- Network-disabled/read-only-root Linux amd64 container smoke by immutable local
  image ID.

## Remaining release blockers outside this sub-gate

- Run the checked-in CI and manual candidate workflow from a published private
  revision; neither workflow has executed on GitHub yet.
- Run native archive/install/offline smoke on macOS and Windows, plus arm64
  hardware or trusted native hosted runners. Cross-compilation is not runtime
  qualification.
- Configure and exercise the checked-in protected GitHub build-provenance flow
  from the eventual tag. It has passed local static policy validation but has
  not minted or verified a real attestation. Current embedded metadata correctly
  records `authenticated: false`; authenticity is external to the bytes.
- Repeat independent SPDX validation on the eventual tagged artifacts using the
  release-pinned validator environment; the local synthetic pass is not evidence
  about future bytes.
- Build from the eventual real signed/reviewed project tag, download the hosted
  bytes on clean supported hosts, authenticate them, and compare their checksums
  to the locally reproduced candidate.
- Complete the product-level feasibility, live GitHub.com, scale, fuzz,
  cross-platform, and final semantic consistency gates tracked elsewhere. This
  packaging result cannot turn a product-contract **NO-GO** or unknown into a
  release **GO**.
