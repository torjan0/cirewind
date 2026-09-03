# Exportable CIRewind public laboratory source package

This directory builds the proposed separate `torjan0/cirewind-lab` repository
without creating it, contacting GitHub, moving a tag, or running a workflow.
It is harmless synthetic source material governed by
[`docs/PUBLIC_LAB_SPEC.md`](../../docs/PUBLIC_LAB_SPEC.md).

Current status: local source package only. No public-lab repository, live run,
outside reproduction, or independent review is claimed by these files.

## Deterministic topology

The source overlays construct one linear history:

```text
G governance
└─ A harmless marker A                 <- annotated fixture-a; lightweight v1
   └─ B harmless affected marker B     <- annotated fixture-b
      └─ W restored marker A + wrapper
         └─ R reusable workflow pinned to W
            └─ I consumer workflows pinned to W/R <- main and bundle HEAD
```

Only the disposable lightweight `refs/tags/v1` is intended to move between the
exact A and B commits. Annotated tag-object IDs and their peeled commit IDs are
different identifiers and are recorded separately. SHA-1 values are Git object
identities, not integrity claims; SHA-256 covers the complete bundle bytes and
every imported file.

The builder uses fixed reviewed commit metadata and DCO trailers so identical
source produces identical object IDs and bundle bytes. It writes full Git
objects without deltas and never executes the Action/workflow content. Git
object IDs depend only on the source bytes; the bundle bytes and their SHA-256
additionally depend on the compressor of the Go toolchain pinned in `go.mod`,
so the checked artifact identity is a claim under that pinned toolchain.

Repository-qualified workflow bytes include the exact destination
owner/repository in every repository Action and reusable-workflow `uses:` field.
A normal GitHub fork therefore is not a qualified copy: its committed workflow
bytes would still target the original repository. Build a separate artifact for
the intended new, separately owned repository and import it into an empty
repository instead.

## Local validation

From the CIRewind repository root:

```text
make public-lab-check
```

The check regenerates the package, compares it with the checked-in artifact,
compiles and exercises the record schemas, imports the bundle into two empty
repositories, and runs `git bundle verify` plus `git fsck --strict --full`.
Default tests require no credentials or network access.

Hosted CI runs the package tests on all six release targets through the
ordinary `go test ./...` job, including a test that requires the checked-in
bundle and manifest to equal deterministic regeneration from source. The
shell-level `make public-lab-check` additionally runs `actionlint` on the
generated workflows, the artifact negative tests, and the marker source audit,
and `make public-lab-syscall-audit` requires Linux `strace`. Those remain
documented Linux-local gates rather than mandatory hosted checks: `actionlint`
and `strace` are not preinstalled on hosted runners, and the syscall audit
observes a fixed `printf` whose source bytes the Go tests already pin.

To inspect a generated copy without changing reviewed files:

```text
go run ./tools/publiclab build \
  --source lab/public/source \
  --repository NEW_OWNER/cirewind-lab \
  --out /new/empty/path
git clone -b main /new/empty/path/cirewind-lab.bundle /new/clone/path
```

The output path must not already exist. The checked-in artifact lives under
`artifacts/`; `object-manifest.json` binds its history, refs, Git objects,
imported files, byte lengths, and hashes.

The imported default branch must remain exactly the artifact's import commit I
through live qualification. Publish the sidecar manifest and later tag-move,
pack-input, generated-pack, run, and reproduction records only on protected,
append-only, non-default `refs/heads/observations`. Cite each record by a full
immutable commit URL and content hash; never advance `main` to publish evidence.
Use a separate observations clone: linked worktrees are outside the accepted
Git boundary. The tag-control clone must remain on `main` at I, but its worktree
content is deliberately not inspected and cleanliness is not a precondition;
commands operate on reviewed object IDs without invoking repository-controlled
clean filters. The isolated Git boundary discards credential helpers and
prompts, so SSH through the operator's normal agent or key is the practical
authenticated transport; an HTTPS push has no credential source and fails
closed before any ref changes.

## Safety boundary

- Marker A and B print only one fixed public string.
- Workflows use GitHub-hosted runners and `contents: read` only.
- No secret, environment, deployment, package, release, artifact, third-party
  Action, self-hosted runner, or `pull_request_target` behavior exists.
- Source generation, validation, and record validation are offline.
- The CIRewind product never moves the tag.

Schema validation, privacy attestations, scanners, and deterministic tests are
rejection controls, not proof that all sensitive or hostile material is absent.
The exact proposed public bytes still require human privacy and security review.

Creating an external repository, using the tag-move protocol, dispatching live
workflows, or publishing a record requires a later explicit maintainer action.
Local completion of this package grants none of those permissions.
