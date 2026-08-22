# Offline safety and Chromium report qualification — 2026-08-21

Status: passing on the recorded Linux host; this is not a cross-platform browser
matrix.

## Environment

- Linux 6.8.0-100-generic, x86-64
- Go 1.25.13, `CGO_ENABLED=0` for the audited CLI build
- strace 6.8
- Chromium 147.0.7727.116
- ChromeDriver 147.0.7727.116

All generated cases, build caches, browser profiles, and traces were placed on a
dedicated scratch filesystem and removed by the harness after each run.

## Offline syscall boundary

Command:

```sh
CIREWIND_SAFETY_AUDIT_ROOT=/path/to/scratch make safety-audit
```

The harness built the CLI with the exact `go.mod` toolchain and `-trimpath`, then
ran these operations under `strace -f` with network and exec syscall filters:

- `pack validate` for the synthetic incident pack;
- synthetic compact archive import;
- replay into a complete case directory; and
- case-manifest verification.

Each command had exactly one `execve` (the audited CLI itself), no child exec,
and no network-system-call attempt. Replay produced the expected ten findings
and verification accepted the generated manifest. This demonstrates the local
Linux binary's offline boundary for these inputs; it is not a proof about every
kernel, binary, or future dependency.

## Browser report boundary

Command:

```sh
CIREWIND_BROWSER_AUDIT_ROOT=/path/to/scratch make browser-audit
```

The harness generated and verified a fresh synthetic case, loaded its
`report.html` through the W3C WebDriver protocol, and observed:

- document state `complete`;
- ten rendered findings;
- functional state filtering and reset behavior;
- exactly one inline script and one inline stylesheet;
- CSP hashes matching those exact inline bytes;
- one page request, for the local `file:` report itself;
- zero report-associated HTTP, HTTPS, WebSocket, or unexpected local-file
  requests; and
- zero severe browser-console errors.

The report CSP permits no default, image, connection, object, base, or form
source. Chromium correctly ignores `frame-ancestors` when delivered through a
`meta` element, so CIRewind does not claim that a standalone file can enforce
that directive. An operator serving a report over HTTP must add
`Content-Security-Policy: frame-ancestors 'none'` as a response header.

The browser observation establishes behavior in the recorded Chromium/Linux
combination. Native Firefox, macOS, Windows, accessibility, printing, and large
case usability remain separate qualification work.

A 1440×1200 Chromium screenshot of the same synthetic report was also inspected
manually. The partial-coverage warning appeared before conclusions, all eight
executive counters were legible, the long case/pack identifiers did not cause
horizontal overflow, and coverage gaps were visually distinct. This viewport
check is not an accessibility audit or a substitute for the interactive checks
above.
