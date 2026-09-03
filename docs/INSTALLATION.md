# Installation lanes

Status: v0.2 evaluation-lane contract prepared on 2026-09-03. No v0.2 tag,
release, or Homebrew formula has been published; every v0.2 command below is
the intended shape, validated only through a local file-based module proxy.
The published product remains the immutable
[v0.1.1 release](https://github.com/torjan0/cirewind/releases/tag/v0.1.1).

CIRewind has two kinds of installation lane:

- **Evaluation lanes** get a working `cirewind` quickly so a new user can run
  the offline demo. They rely on the Go module ecosystem or a package manager
  for integrity and do not replace release attestation.
- **The high-assurance lane** downloads the reproducible release archives and
  authenticates provenance, checksums, and SPDX documents before extraction, as
  described in [`RELEASE_PROCESS.md`](RELEASE_PROCESS.md). Forensic use should
  prefer it.

## Versioned `go install` (evaluation lane)

The intended command for a published v0.2 tag is:

```sh
go install github.com/torjan0/cirewind/cmd/cirewind@v0.2.0
cirewind demo --out cirewind-demo
cirewind verify cirewind-demo
```

`@v0.2.0` does not exist yet. Do not run this shape against the public module
proxy expecting it to succeed until the release is published and the
post-publication distribution gate has rechecked it.

### Prerequisites

- A Go toolchain that can satisfy the `go` directive in
  [`go.mod`](../go.mod). A newer installed Go, or an older one with the
  default `GOTOOLCHAIN=auto`, downloads the exact pinned toolchain
  automatically; that download is part of the evaluation-lane time budget and
  is not an integrity claim.
- One of the six supported targets: Linux, macOS, or Windows on amd64 or
  arm64. Builds are CGO-disabled and use the pure-Go SQLite implementation, so
  no C toolchain is needed.
- Network access to the Go module proxy and checksum database configured for
  your environment. By default the `go` command contacts `proxy.golang.org`
  and `sum.golang.org`; CIRewind itself never does.
- `GOBIN` (or `$(go env GOPATH)/bin`) on `PATH` so the installed executable is
  found.

### What the installed binary reports

A module build has no linker-injected release metadata, so `cirewind version`
reports the Go module version and honest unknowns:

```text
cirewind 0.2.0 (commit unknown, built unknown)
```

The commit is unknown because a module zip embeds no VCS revision; the binary
does not invent one. Release archives from the high-assurance lane report the
exact version, source revision, and build time instead. A checkout build
reports its embedded revision and marks a modified worktree with `+dirty`.

### Uninstall

The lane installs one executable and populates the Go module and build caches:

```sh
rm "$(go env GOBIN)/cirewind" 2>/dev/null || rm "$(go env GOPATH)/bin/cirewind"
go clean -modcache   # optional; removes every cached module, not only CIRewind
```

CIRewind writes nothing else on installation. Case directories created by
`demo`, `investigate`, or `replay` are ordinary directories you chose.

## Homebrew (evaluation lane, planned)

The plan reserves a maintainer-owned tap that installs the exact upstream
release archives with per-platform SHA-256 values and no bottles. The tap does
not exist yet, so no `brew install` command is available or advertised.

## High-assurance lane

Download the complete release asset set into a clean directory, verify
build-provenance attestations, `SHA256SUMS`, and the per-target SPDX documents,
and only then extract the archive for your platform. The full procedure,
including the checked-in verifier, is in
[`RELEASE_PROCESS.md`](RELEASE_PROCESS.md). Release binaries are stamped with
authoritative version, source revision, and build time.

## Local qualification of the `go install` lane

Two Make targets exercise the lane offline without a public tag:

- `make go-install-check` serves the current tree as `v0.2.0-synthetic` from a
  file-based module proxy, installs it from a directory outside the checkout
  with dependencies taken from the local module download cache, and requires
  the installed binary to report that version with an unknown commit, to carry
  no VCS build setting, and to produce and verify the offline demo.
- `make go-install-qualify` repeats the install twice inside an already-present
  minimal Linux container image named by
  `CIREWIND_GO_INSTALL_IMAGE_ID=sha256:...`: cold with empty caches and warm
  with the caches left by the first install. The container has no network, a
  read-only root filesystem, no capabilities, an unprivileged user, and only
  read-only mounts for the pinned toolchain and the two file proxies. It
  never pulls an image and never accepts a mutable tag.

Both prove the install shape and version reporting. Neither proves that a
public tag exists, that the public proxy serves it, or that an arbitrary host
meets the north-star time budget; those are separate post-publication and
reference-host gates.

## Post-publication qualification of the public lane

After a release tag exists, `make go-install-public-qualify
GO_INSTALL_TAG=v0.2.0 GO_INSTALL_OUT=/path/to/record` runs the anonymous
public-lane check that `DIST-010` requires: a fresh, empty GOPATH, module
cache, build cache, and HOME outside any checkout; Go's default module proxy
and checksum database; the default `GOTOOLCHAIN=auto`, so a cold timing
includes any automatic toolchain download; a cold and a warm install; the
exact `cirewind <version> (commit unknown, built unknown)` version output; the
module hash and toolchain embedded in the binary; the binary SHA-256; and the
offline demo plus verification with an empty environment. The record it writes
binds those values with the host and timings and is signed by nothing; it is
input for the human-run reference-host measurements, not a substitute for
them. `make go-install-public-check` runs the same script as a file-proxy dry
run against a synthetic version, which proves the script and proves nothing
about the public module.
