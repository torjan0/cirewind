# Homebrew formula generator qualification (synthetic subjects)

Date: 2026-09-03
Scope: `DIST-003` local qualification of the Homebrew evaluation-lane formula
generator against synthetic release subjects. Nothing was published, no tap
was created remotely, and no subject hash is final.

## What ran

`make brew-formula-check BREW_WORK_ROOT=<scratch>` with
`CIREWIND_BREW` pointing at a portable Homebrew checkout (`Homebrew >=4.3.0`,
shallow clone, portable Ruby 4.0.6, Linux x86_64 host). The script:

1. built a synthetic six-target release distribution with
   `scripts/build-release.sh 0.0.1 <commit> 946684800` at source commit
   `d789e7abdf8e363c20a8ebc72ed05d6653f86bdf`;
2. rendered the upstream-shaped formula twice with `releasetool formula --dist`
   and required byte-identical output;
3. exposed the formula through a throwaway local tap
   (`cirewind-qualification/fixture`), ran `brew style` (one file inspected, no
   offenses) and `brew audit --strict` (no findings);
4. rendered the fixture formula with `--download-base` pointing at a loopback
   HTTP server that mirrors the upstream asset path shape and serves the
   synthetic archives, and required the fixture banner;
5. ran `brew install`, checked that the installed binary reports
   `cirewind 0.0.1 (commit d789e7ab…, built …)`, ran `brew test` (which
   invokes `cirewind version`, `cirewind demo`, and `cirewind verify` in a
   temporary directory), and `brew uninstall`;
6. removed the tap and workspace.

Unit tests (`internal/releaseartifact/formula_test.go`) cover the four
required Unix subjects, rejection of missing, duplicate, misnamed, foreign-
platform, uppercase-digest, version-drifted, and wrong-format subjects,
determinism, and the fixture download-base validation.

## Boundaries

- The Linux formula blocks were executed; the macOS blocks were rendered and
  audited but not installed. macOS 15 arm64 execution belongs to `DIST-005`.
- Homebrew's `homebrew/core` tap was cloned locally because installation from
  the API was disabled for the qualification; that clone is local scratch.
- Homebrew is an evaluation lane: the formula checks the archive SHA-256 but
  does not verify build-provenance attestations, and its caveats say so.
- The final formula for `v0.2.0` can be rendered only from the frozen release
  subjects of the release-candidate commit (`DIST-007`).
