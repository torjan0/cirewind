# Third-party notices

CIRewind command binaries include third-party software. This notice index must
accompany binary distributions together with CIRewind's Apache-2.0 `LICENSE`
and the applicable complete upstream terms checked into
[`third_party/licenses/`](third_party/licenses/). The machine-readable
[`index.json`](third_party/licenses/index.json) maps every copied source file to
its module version, linked targets, local path, and SHA-256 digest. This notice
index does not replace those complete terms.

The versions below are the modules linked into at least one of the Linux,
macOS, or Windows amd64 or arm64 command binaries reviewed on 2026-08-21.
Target-specific release packaging must derive the final set from `go version
-m` on the exact release binary.

| Software | License and required attribution source |
| --- | --- |
| Go runtime and standard library 1.25.13 | BSD-3-Clause © 2009 The Go Authors, with an additional patent grant. Include [`LICENSE`](https://go.googlesource.com/go/+/refs/tags/go1.25.13/LICENSE) and [`PATENTS`](https://go.googlesource.com/go/+/refs/tags/go1.25.13/PATENTS) from the exact release toolchain. |
| `gopkg.in/yaml.v3` v3.0.1 | MIT portions © 2006–2011 Kirill Simonov; Apache-2.0 portions © 2011–2019 Canonical Ltd. Include the upstream [`LICENSE`](https://github.com/go-yaml/yaml/blob/v3.0.1/LICENSE) and [`NOTICE`](https://github.com/go-yaml/yaml/blob/v3.0.1/NOTICE). |
| `modernc.org/sqlite` v1.57.0 | BSD-3-Clause © 2017 The Sqlite Authors; bundled SQLite code is dedicated to the public domain. Include upstream [`LICENSE`](https://gitlab.com/cznic/sqlite/-/blob/v1.57.0/LICENSE) and [`LICENSE-SQLITE`](https://gitlab.com/cznic/sqlite/-/blob/v1.57.0/LICENSE-SQLITE). |
| `github.com/dustin/go-humanize` v1.0.1 | MIT © 2005–2008 Dustin Sallings. Include upstream [`LICENSE`](https://github.com/dustin/go-humanize/blob/v1.0.1/LICENSE). |
| `github.com/google/uuid` v1.6.0 | BSD-3-Clause © 2009, 2014 Google Inc. Include upstream [`LICENSE`](https://github.com/google/uuid/blob/v1.6.0/LICENSE). |
| `github.com/mattn/go-isatty` v0.0.24 | MIT © Yasuhiro Matsumoto. Include upstream [`LICENSE`](https://github.com/mattn/go-isatty/blob/v0.0.24/LICENSE). |
| `github.com/ncruces/go-strftime` v1.0.0 | MIT © 2022 Nuno Cruces. Include upstream [`LICENSE`](https://github.com/ncruces/go-strftime/blob/v1.0.0/LICENSE). |
| `github.com/remyoudompheng/bigfft` pseudo-version ending `24d4a6f8daec` | BSD-3-Clause © 2012 The Go Authors. Include upstream [`LICENSE`](https://github.com/remyoudompheng/bigfft/blob/24d4a6f8daece64d3c9a7660d4ee0974c4e31021/LICENSE). |
| `golang.org/x/sys` v0.47.0 | BSD-3-Clause © 2009 The Go Authors, with an additional patent grant. Include upstream [`LICENSE`](https://go.googlesource.com/sys/+/refs/tags/v0.47.0/LICENSE) and [`PATENTS`](https://go.googlesource.com/sys/+/refs/tags/v0.47.0/PATENTS). |
| `modernc.org/libc` v1.74.4 | BSD-3-Clause © 2017 The Libc Authors, with additional Go, musl, go-netdb, NixOS/nixpkgs, and source-specific attributions. Include upstream [`LICENSE`](https://gitlab.com/cznic/libc/-/blob/v1.74.4/LICENSE) and the complete [`LICENSE-3RD-PARTY.md`](https://gitlab.com/cznic/libc/-/blob/v1.74.4/LICENSE-3RD-PARTY.md). |
| `modernc.org/mathutil` v1.7.1 | BSD-3-Clause © 2014 The mathutil Authors. Include upstream [`LICENSE`](https://gitlab.com/cznic/mathutil/-/blob/v1.7.1/LICENSE). |
| `modernc.org/memory` v1.11.0 | BSD-3-Clause © 2017 The Memory Authors, plus © 2009 The Go Authors and © 2011 Evan Shaw. Include upstream [`LICENSE`](https://gitlab.com/cznic/memory/-/blob/v1.11.0/LICENSE), [`LICENSE-GO`](https://gitlab.com/cznic/memory/-/blob/v1.11.0/LICENSE-GO), and [`LICENSE-MMAP-GO`](https://gitlab.com/cznic/memory/-/blob/v1.11.0/LICENSE-MMAP-GO). |

The module versions, target linkage, graph-only modules, and review method are
documented in [`docs/DEPENDENCIES.md`](docs/DEPENDENCIES.md).

Verify the checked-in bundle without network access:

```sh
go test ./third_party/licenses
```
