# Batch 1 corrective automated qualification — 2026-08-26

Status: **PASS for the recorded local automated scope**

This record qualifies the uncommitted Batch 1 corrective working tree described
below. It is not a frozen release candidate, a native multi-platform runtime
qualification, a security certification, an accessibility review, or an
external review. `ADO-015`, `ADO-025`, and `ADO-026` remain open.

## Candidate boundary

| Field | Value |
| --- | --- |
| Branch | `v0.2-adoption` |
| Base and remote branch tip | `79b15ebf145654bb8526e0ab770d26f8e5eff60c` |
| Candidate state | Modified and untracked working-tree files; not committed or pushed |
| Go toolchain | `go1.25.13 linux/amd64` |
| Qualified Linux binary SHA-256 | `b314cc1d80b70cfdb3f98fe278236d739e7abdc29162779d76790926be0fcc9a` |
| Qualified Linux binary size | 22,883,256 bytes |

Because this candidate is a working-tree diff, the base commit alone cannot
reproduce it. A later commit-bound or release-candidate qualification must run
again; this record must not be cited as qualification of later bytes.

The run used only synthetic CIRewind data. It used no GitHub credential, cloud
credential, real secret value, raw production log, or private repository data.
No repository setting, remote ref, pull request, tag, release, or external
service was changed.

## Corrective semantic coverage

The tested candidate includes regression coverage for these corrective rules:

- exact Action identity is bound to the matching incident component and
  indicator; ambiguous repository/subpath bindings fail closed;
- report findings and the `GraphV2` finding index retain the same state,
  provenance, occurrence identity, indicator, evidence-gap reason, and exact
  identity context;
- the affected-runs CSV preserves its original 11-column prefix, appends a
  closed row context plus indicator and finding-revision identities, and
  sanitizes every field; same-run propositions therefore remain distinguishable;
- absent runner-group metadata remains absent, while a present numeric group ID
  of zero remains present and distinct;
- environment-secret eligibility requires a started job plus one retained gate
  state from `approved`, `bypassed`, `crossed`, or `not-required`; approval is
  never inferred from bypass or absence of a required gate;
- each retained gate state maps to a distinct closed derivation rule;
  `not-required` additionally requires a known event time, and both Go and the
  public schema reject empty, surrounding-whitespace, and every case variant of
  the placeholder `unknown`;
- `ENVIRONMENT_SECRET_ELIGIBLE` requires same-finding and same-environment
  `TARGETED_ENVIRONMENT` and `ENVIRONMENT_GATE_SATISFIED` relationships;
- the v0.2-only `ENVIRONMENT_GATE_SATISFIED` relationship is rejected by the
  frozen v0.1 graph validator;
- historical-at-run, current-snapshot, and runtime-attempt definition bases are
  closed typed derivation markers rather than label or finding-state guesses;
- relationship wording varies by evidence class and does not combine an
  observed verb with an inferred classification;
- hostile evidence-gap text remains bounded machine evidence and is sanitized
  at every report and SVG presentation sink; and
- the downloaded/prepared lifecycle still cannot independently support
  `CONFIRMED_EXECUTED`.

No canonical finding state, provenance identifier, mandatory invariant,
attempt/job identity, credential semantic, or v0.1 generated graph byte contract
was weakened.

## Host and resource envelope

The local host was Ubuntu 24.04.4 LTS on x86-64, Linux
`6.8.0-100-generic`, Python 3.12.3, and Chromium 147.0.7727.116. The physical
host exposed 8 logical CPUs and approximately 16 GiB RAM.

The final five-trial demo harness ran in a transient user service with:

```text
systemd AllowedCPUs: 0,1
systemd CPUQuota: 200%
systemd MemoryMax: 4 GiB
```

The harness's in-process platform report still describes the physical host.
This is therefore a constrained-local Ubuntu qualification, not proof from
native two-vCPU hardware. The service reported 1.5 MiB peak memory for its
short-lived supervising process; that number is not a whole-case RSS claim.

## Automated gates

The following commands passed on the candidate:

```sh
go test -count=1 ./...
go test -race -count=1 ./...
go vet ./...
go mod tidy -diff
go mod verify
go test ./third_party/licenses
actionlint .github/workflows/*.yml
shellcheck scripts/*.sh
GO_TOOLCHAIN=go1.25.13 sh scripts/vulncheck.sh
gitleaks dir --no-banner --redact --no-color --timeout 120 .
gitleaks git --no-banner --redact --no-color --timeout 120 .
```

The default suite passed in 36.52 seconds, the race suite passed in 171.28
seconds without a race report, and vet passed in 1.45 seconds. The configured
Go formatter reported no files. `git diff --check` passed. The vulnerability
scan reported no known reachable Go vulnerability. The directory and 12-commit
history secret scans reported no leak. No unresolved unfinished-work marker was
found in product, schema, script, or documentation files.

Fuzz seed corpora ran as part of the default package suite. No timed fuzzing
campaign is claimed by this record.

## Cross-build results

All builds used `CGO_ENABLED=0`, `-trimpath`, `-buildvcs=false`, `GOAMD64=v1`
for amd64, and `GOARM64=v8.0` for arm64.

| Target | Binary SHA-256 |
| --- | --- |
| `linux/amd64` | `b314cc1d80b70cfdb3f98fe278236d739e7abdc29162779d76790926be0fcc9a` |
| `linux/arm64` | `2e842432accd69843de31f0e43c707e60828b90670eed7d588809345b522f8ca` |
| `darwin/amd64` | `ba7676c8f61009f7c1bdcaf4a6a55ddcbd04b5a9fc46229ac556adc75b797e98` |
| `darwin/arm64` | `882b5909857a15438b8e3466ea7f4421757ddc77a14c68adb8a325e6075a0497` |
| `windows/amd64` | `433985f3f9130dc8f2d70a9120dc69861fdea83b9c603aa2140c5bcb74eb4a98` |
| `windows/arm64` | `d6cd901109cef3c1f423f6d60f1120b410b25dac62c6e9d69b05c120ebe61e61` |

Only the Linux amd64 binary was executed here. Cross-compilation is not a
native runtime qualification for the other five targets.

## Demo oracle, timing, and determinism

Five clean trials used distinct output, home, cache, and temporary directories;
an unusable `PATH`; unset GitHub credential variables; poisoned proxy values;
and independent post-generation manifest verification. The timer covered
installed binary invocation through the demo command's successful built-in
manifest verification.

```text
T_demo seconds: 0.786722, 0.803171, 0.767758, 0.831016, 0.798543
p50:           0.798543 seconds
maximum:       0.831016 seconds
```

This passes the accepted Ubuntu `T_demo` thresholds of p50 at most 15 seconds
and no run over 30 seconds under the recorded constraints. It does not measure
`T_total` and does not satisfy the native macOS 15 arm64 launch lane.

Every complete case was byte-identical. The oracle contained 11 findings and
partial coverage:

| Finding state | Count |
| --- | ---: |
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

The downloaded-only scenario has no execution edge. The known-good rerun is
comparison context and not an affected run. Missing logs remain an evidence gap.

The thin `make demo` wrapper invoked the same application command, produced a
verified case, and produced the same `graph.svg` bytes as the direct command.

## Case hashes

The manifest covers every material case file except itself. The table also
records the SHA-256 of the manifest file as an external qualification datum.

| File | SHA-256 |
| --- | --- |
| `affected-runs.csv` | `d8aa28ddd7c3b5f3e90abe6a9b205859d5c7ddf0d32d08bae4e83ae062f54b8b` |
| `case.db` | `dff507d3a2442058ad9973ac63faf30db8a263e7615425f7f6e8ac2547eaf4e8` |
| `collection-metadata.json` | `c292b89ca9c61a1582bff5c2986b18b7ff097aaa9b343fc971291a8a94ed0db6` |
| `evidence.jsonl` | `2ff35fedd1e015994c15b57f1095283c859fb77d0b593bead76e561a6768d29f` |
| `findings.json` | `e179bd70210715e80fb48e925fc1dd0f5002f9ac53e4170da3e1005c7d263a50` |
| `graph.json` | `aedceebe418fddfccf9a8803e8411afde22b2e696733d8fa2c0cc211da1a4ce3` |
| `graph.svg` | `22c438174b3fd9f07b89d04731bde9454e6086725c99130b66fcddeb62504af1` |
| `manifest.sha256` | `4d5d8c5b72cb4efe3940c3bdb454fb186f4a1e6ab240c116765fe24b474b1b3c` |
| `report.html` | `dc26e91f40d1ea58f87e06351495de5919b08f83e77a7a7f6a7191781ed91445` |
| `summary.md` | `87a4bcb1318823de3bd1c0cf564531595a30321a97f34e8c6c8cbe665045634d` |

## Browser and hostile-output audit

The self-contained report passed Chromium loading at viewport widths 1440,
1024, 768, 390, and 320 pixels. The audit recorded:

- 11 visual lanes, 81 node rows, and 70 relationship-ledger rows;
- zero console errors and zero external requests;
- one request for the local document itself;
- verified CSP hashes;
- forced-colors mode active with `forced-color-adjust: none`, a white route
  underlay, and a distinct exact-observation foreground stroke;
- working keyboard focus and horizontal/vertical keyboard scrolling;
- 16 px effective text in the evidence-path region; and
- zero node, ledger, notice, lane-scope, or evidence-gap text overflows.

The standalone SVG had no external request or console error and matched the
report's deterministic path geometry. Hostile labels, XML markup, terminal
controls, bidi controls, long fields, and evidence-gap text are covered by the
automated package tests.

The fixed palette deliberately uses `forced-color-adjust: none` to preserve
distinct route foreground and underlay topology. The browser result does not
establish usability with a person's actual Windows High Contrast preferences.
The 3,000-pixel fixed-scale canvas also requires horizontal scrolling on narrow
viewports; the report supplies explicit scroll instructions and a responsive
text-equivalent skip target, but mobile discoverability remains part of the
open human review in `ADO-025`.

Snap Chromium could not place its profile under the retained Dockerstuff
directory because of its AppArmor confinement. The successful audit kept the
case in Dockerstuff and placed only the disposable browser profile under
`/tmp`. This was a browser-launch constraint, not a report failure.

## Offline process and network observation

Linux `strace` observed the following application paths:

```text
pack validate
archive --import-fixture synthetic
replay
verify
demo
```

Each path made no network syscall and launched no child process. The audit also
confirmed `network requests: 0` in the generated synthetic case.

## Performance probe

Five iterations of
`BenchmarkGraphV2ProjectionNoticeAggregation5000` completed at approximately
7.11 ms per operation on the local i7-7700 host, with about 1.52 MiB allocated
and 5,080 allocations per operation. This is a focused regression probe, not
organization-scale qualification.

## Remaining gates

- Run the demo and timing contract natively on macOS 15 arm64 with Homebrew;
  the documented AWS minimum remains above the approved USD 4 cost ceiling.
- Run the informational native Windows 11 amd64 smoke.
- Record human keyboard, screen-reader, zoom, contrast, and semantic review
  against the exact bytes under review.
- Repeat human review after the integrated release candidate, sample site, and
  README are frozen.
- Complete later real-incident-pack outside-human reviews and the public-lab
  independent reproduction. A model or automated audit cannot satisfy these
  human gates.
