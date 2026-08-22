# Dependency and license inventory

This inventory records the Go module graph selected by `go.mod` and the modules
linked into CIRewind command binaries as reviewed on 2026-08-21. It is intended
to support release review; it is not legal advice, a software-bill-of-materials
attestation, or a vulnerability assessment.

## Method

The linked set was determined with `go list -deps` for amd64 and arm64 on
Linux, macOS, and Windows, then checked against `go version -m` on locally
built binaries. License classifications and the checked-in copies below come
from the exact module-cache files selected by `go.sum` and the Go 1.25.13
toolchain, not from package-directory badges or search results.

A release review should repeat these checks from a clean, committed release
revision for every supported target:

```sh
go list -m all
GOOS=linux GOARCH=amd64 go list -deps -f '{{if not .Standard}}{{.Module.Path}} {{.Module.Version}}{{end}}' ./cmd/cirewind
GOOS=linux GOARCH=arm64 go list -deps -f '{{if not .Standard}}{{.Module.Path}} {{.Module.Version}}{{end}}' ./cmd/cirewind
GOOS=darwin GOARCH=amd64 go list -deps -f '{{if not .Standard}}{{.Module.Path}} {{.Module.Version}}{{end}}' ./cmd/cirewind
GOOS=darwin GOARCH=arm64 go list -deps -f '{{if not .Standard}}{{.Module.Path}} {{.Module.Version}}{{end}}' ./cmd/cirewind
GOOS=windows GOARCH=amd64 go list -deps -f '{{if not .Standard}}{{.Module.Path}} {{.Module.Version}}{{end}}' ./cmd/cirewind
GOOS=windows GOARCH=arm64 go list -deps -f '{{if not .Standard}}{{.Module.Path}} {{.Module.Version}}{{end}}' ./cmd/cirewind
go version -m PATH_TO_RELEASE_BINARY
go test ./third_party/licenses
make vuln
```

## Modules linked into at least one reviewed target

“Direct” and “indirect” describe the declarations in `go.mod`; indirect modules
can still be linked into the final static executable. Platform entries describe
the reviewed target set, not a promise about every Go target.

| Module and version | `go.mod` status | Reviewed linked targets | License evidence in the selected module | Release notes |
| --- | --- | --- | --- | --- |
| [Go runtime and standard library 1.25.13](https://go.googlesource.com/go/+/refs/tags/go1.25.13) | Toolchain declared by `go 1.25.13` | Linux, macOS, Windows | Go BSD-3-Clause text in `$GOROOT/LICENSE`; patent grant in `$GOROOT/PATENTS` | Static binaries contain Go runtime and standard-library code. Preserve both files from the exact release toolchain. |
| [`gopkg.in/yaml.v3` v3.0.1](https://github.com/go-yaml/yaml/tree/v3.0.1) | Direct | Linux, macOS, Windows | Mixed MIT and Apache-2.0 in `LICENSE`; Canonical notice in `NOTICE` | Reproduce both license terms and the upstream notice. |
| [`modernc.org/sqlite` v1.57.0](https://gitlab.com/cznic/sqlite/-/tree/v1.57.0) | Direct | Linux, macOS, Windows | BSD-3-Clause in `LICENSE`; bundled SQLite dedication in `LICENSE-SQLITE` | `modernc.org/sqlite/vec` is not imported by CIRewind; its module-level MIT `LICENSE-SQLITE_VEC` should nevertheless be reevaluated if the imported package set changes. |
| [`github.com/dustin/go-humanize` v1.0.1](https://github.com/dustin/go-humanize/tree/v1.0.1) | Indirect | Linux, macOS, Windows | MIT in `LICENSE` | Preserve the Dustin Sallings copyright and permission notice. |
| [`github.com/google/uuid` v1.6.0](https://github.com/google/uuid/tree/v1.6.0) | Indirect | Linux, macOS | BSD-3-Clause in `LICENSE` | Preserve the Google copyright, conditions, and disclaimer. |
| [`github.com/mattn/go-isatty` v0.0.24](https://github.com/mattn/go-isatty/tree/v0.0.24) | Indirect | macOS, Windows | MIT in `LICENSE` | Preserve the Yasuhiro Matsumoto copyright and permission notice. |
| [`github.com/ncruces/go-strftime` v1.0.0](https://github.com/ncruces/go-strftime/tree/v1.0.0) | Indirect | macOS, Windows | MIT in `LICENSE` | Preserve the Nuno Cruces copyright and permission notice. |
| [`github.com/remyoudompheng/bigfft` pseudo-version ending `24d4a6f8daec`](https://github.com/remyoudompheng/bigfft/tree/24d4a6f8daece64d3c9a7660d4ee0974c4e31021) | Indirect | Linux, macOS, Windows | Go BSD-3-Clause text in `LICENSE` | Preserve the Go Authors copyright, conditions, and disclaimer. |
| [`golang.org/x/sys` v0.47.0](https://go.googlesource.com/sys/+/refs/tags/v0.47.0) | Indirect | Linux, macOS, Windows | Go BSD-3-Clause text in `LICENSE`; patent grant in `PATENTS` | Preserve both files from the selected module. |
| [`modernc.org/libc` v1.74.4](https://gitlab.com/cznic/libc/-/tree/v1.74.4) | Indirect | Linux, macOS, Windows | BSD-3-Clause in `LICENSE`; Go, musl, go-netdb, NixOS/nixpkgs, and other notices in `LICENSE-3RD-PARTY.md` | Ship the complete upstream third-party notice file, not only the top-level BSD license. |
| [`modernc.org/mathutil` v1.7.1](https://gitlab.com/cznic/mathutil/-/tree/v1.7.1) | Indirect | Linux, macOS, Windows | BSD-3-Clause in `LICENSE` | The separately licensed `mersenne` subpackage was not in the reviewed import graph. Recheck package imports for each release. |
| [`modernc.org/memory` v1.11.0](https://gitlab.com/cznic/memory/-/tree/v1.11.0) | Indirect | Linux, macOS, Windows | BSD-3-Clause in `LICENSE`, `LICENSE-GO`, and `LICENSE-MMAP-GO` | Preserve the ModernC, Go Authors, and Evan Shaw notices. CIRewind does not distribute the upstream logo referenced by `LICENSE-LOGO`. |

The reviewed linked licenses are permissive (MIT, BSD-3-Clause, Apache-2.0,
and SQLite public-domain dedication). No reciprocal or copyleft license was
identified in this linked set. Based on the bundled license files, these terms
appear compatible with distributing CIRewind under Apache-2.0 provided all
copyright, license, disclaimer, and `NOTICE` obligations are met. This is a
release-engineering assessment, not a legal conclusion.

## Selected module graph not linked into the CLI

`go list -m all` also selects modules used by dependency tests or generators.
They do not appear in `go list -deps ./cmd/cirewind` for the reviewed targets
and do not appear in the reviewed binaries' `go version -m` output:

- `github.com/santhosh-tekuri/jsonschema/v6` v6.0.3 is imported only by the
  generated-case contract test to validate every evidence-ledger record against
  Draft 2020-12 with all schema resources registered locally. Its license is
  Apache-2.0. Its test-only dependency path also selects
  `github.com/dlclark/regexp2` v1.11.0 (MIT) and `golang.org/x/text` v0.14.0
  (BSD-3-Clause). None is linked into `cirewind` command binaries;
- `github.com/google/pprof`, `golang.org/x/mod`, `golang.org/x/sync`,
  `golang.org/x/tools`, and `gopkg.in/check.v1`;
- `github.com/hashicorp/golang-lru/v2`; and
- `modernc.org/cc/v4`, `modernc.org/ccgo/v4`, `modernc.org/fileutil`,
  `modernc.org/gc/v2`, `modernc.org/gc/v3`, `modernc.org/goabi0`,
  `modernc.org/opt`, `modernc.org/sortutil`, `modernc.org/strutil`, and
  `modernc.org/token`.

Most of this graph-only set is Apache-2.0 or BSD-3-Clause. The selected
`github.com/hashicorp/golang-lru/v2` v2.0.7 module is MPL-2.0; `go mod why -m`
reaches it only through `modernc.org/libc` dependency tests, and it is not linked
into the CIRewind CLI. If a future source, test binary, tool, vendored tree, or
release artifact distributes graph-only code, its license obligations must be
reviewed for that artifact rather than inferred from the current CLI set.

## Release controls

- Complete copies of the reviewed terms are stored in
  [`third_party/licenses/`](../third_party/licenses/). Its deterministic
  [`index.json`](../third_party/licenses/index.json) records source paths,
  targets, and SHA-256 digests; `go test ./third_party/licenses` rejects missing,
  changed, unindexed, or version-stale files without accessing the network.
- Binary release archives must include CIRewind's `LICENSE`,
  `THIRD_PARTY_NOTICES.md`, and complete copies of every applicable upstream
  license and notice file for that target. The notice index alone is not a
  substitute for the complete upstream terms.
- Generate a target-specific SBOM or equivalent module inventory from the exact
  tagged build. Do not infer the shipped set solely from `go.mod`.
- Compare the module list embedded by `go version -m` with the bundled notices
  before publication.
- Recheck transitive license files whenever `go.mod`, `go.sum`, imported build
  tags, Go version, or supported target set changes.
- Dependency-license review does not establish that a dependency is free from
  vulnerabilities. Security review and update policy are separate controls.
- `make vuln` runs `govulncheck` v1.7.0 with the exact Go toolchain declared in
  `go.mod`; it requires the public Go vulnerability database. The command is
  Linux-only so its wrapper can isolate the Go user configuration and disable
  telemetry without changing an operator's normal profile. It fails before
  invoking Go on other operating systems. The check is intentionally separate
  from the offline default test suite; cross-platform build, test, and vet
  coverage remains in CI.
