# Versioned `go install` lane local prequalification

Date: 2026-09-03

Branch: `dist/v0.2-version-reporting`

Status: local engineering prequalification of the versioned `go install`
evaluation lane (`DIST-001`, `DIST-002`). No v0.2 tag exists, nothing was
published, and no public module proxy served CIRewind. Every install below
used a synthetic version served from a file-based proxy built from the local
tree. This record makes no claim about the public `@v0.2.0` command, about a
reference host, or about Homebrew.

## What was exercised

- `make go-install-check` on the host: the tree was served as
  `v0.2.0-synthetic` from a file proxy, installed from a directory outside the
  checkout under `env -i` with fresh `GOMODCACHE`, `GOCACHE`, `GOPATH`, and
  `HOME`, dependencies taken only from the host's existing module download
  cache through a second file proxy, then installed again warm. The installed
  binary had to report `cirewind 0.2.0-synthetic (commit unknown, built
  unknown)`, carry no `vcs.*` build setting, and produce and verify the
  offline demo.
- `make go-install-qualify` in a clean container: the same proxy, installed
  twice (cold, then warm) inside an already-present minimal Linux image
  addressed only by immutable ID, with `--network none`, a read-only root
  filesystem, all capabilities dropped, `no-new-privileges`, UID 65534, an
  ephemeral `tmpfs` work area, and read-only mounts for the pinned Go
  toolchain and the two file proxies. The script never pulls an image and
  rejects a mutable tag.

Container image: `debian:bookworm-slim`, pulled once by the operator on
2026-09-03 and then addressed as image ID
`sha256:160466e67bb85a4099d9d9c2356b4a6a64747b281a22c142efbd4539db1b8525`
(registry digest
`sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171`).
Toolchain inside the container: `go1.25.13 linux/amd64`, mounted read-only
from the host's toolchain cache. Host: Linux x86_64.

## Results

| Trial | Result |
| --- | --- |
| Host cold install, version line, no VCS setting, demo, verify | PASS |
| Host warm install, version line | PASS |
| Container cold install | PASS, 23,788 ms |
| Container warm install | PASS, 631 ms |
| Container `cirewind demo --out` | PASS, 188 ms, `manifest: verified` |
| Container `cirewind verify` | PASS, 24 ms |
| Container version line | `cirewind 0.2.0-synthetic (commit unknown, built unknown)` |

The cold time is dominated by compiling the pure-Go SQLite dependency from
source with empty caches on the audit host. It is recorded for context only:
this host is not a launch-blocking reference system, and the north-star
`T_total` measurement on Ubuntu 24.04 amd64 with 2 vCPU/4 GiB and on macOS 15
arm64 remains `ADO-031`.

Supporting checks on the same bytes:

```text
shellcheck scripts/go-install-proxy.sh scripts/test-go-install-version.sh scripts/qualify-go-install.sh
go test ./internal/buildinfo ./internal/cli -count=1
go test ./... -count=1
go vet ./...
go test -race ./... -count=1
go mod tidy -diff
```

Hosted CI run
[`33707851485`](https://github.com/torjan0/cirewind/actions/runs/33707851485)
passed all ten jobs on the `DIST-001` commit
`b95c13c5c9b08b1cd854d68f8e153cbd6bc14443`.

## What this does and does not establish

Established: the installing environment needs no source clone or current
`go.mod`; version output is honest for a module build; the installed binary
creates and verifies the exact offline demo with no network; prerequisites,
supported targets, and uninstall guidance are documented in
[`INSTALLATION.md`](../INSTALLATION.md); the module build embeds no VCS data
and the binary reports `unknown` rather than inventing a commit.

Not established: that a public `v0.2.0` tag exists or that `proxy.golang.org`
serves it; the public post-publication recheck (`DIST-008`); reference-host
timing (`ADO-031`); Homebrew (`DIST-003`); any non-Linux container trial. The
container trial runs the host's linux/amd64 toolchain and therefore covers one
target only; the other five targets are covered by the hosted CI test matrix,
not by an install trial.

Temporary data lived under the operator's designated Docker work root and was
removed. No AWS resource was used; cost `$0.00`.
