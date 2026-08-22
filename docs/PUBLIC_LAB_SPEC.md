# Public A-to-B-to-A laboratory specification

Status: accepted v0.2 laboratory and independent-reproduction contract as of
2026-08-22.

This specification describes a separate public repository. This planning pass
does not create that repository, mutate a tag, run a workflow, or claim an
independent reproduction.

## Purpose

The public laboratory makes CIRewind's central temporal claim independently
falsifiable:

1. a mutable `v1` Action tag initially identifies harmless commit A;
2. the tag moves to harmless marker commit B;
3. controlled workflows run while `v1` identifies B;
4. the tag returns to A;
5. new attempts run after `v1` again resolves to A;
6. CIRewind still distinguishes which exact run attempts downloaded or began
   executing B, which downloaded B without a step start, and which resolved A.

The laboratory demonstrates evidence reconstruction. It does not simulate
malware, exfiltration, persistence, cloud compromise, or victim impact.

## Repository boundary

Recommended repository: `torjan0/cirewind-lab`, created only after explicit
maintainer authorization.

The separate laboratory is Apache-2.0 licensed and uses Developer Certificate
of Origin sign-offs (`Signed-off-by`) rather than a custom CLA. The exact
`LICENSE`, contribution/DCO text, and governance files are included before the
Git bundle/object manifest is frozen; a builder may not invent or substitute
them afterward.

One standalone public repository contains the marker Action, stable wrapper,
reusable workflow, consumer workflows, protocol, expected-result schema, and
reproduction issue template. A reproducer may fork it or use a separately owned
copy. The basic protocol requires GitHub-hosted runners only; no self-hosted
runner, environment approval, cloud credential, package publication, or external
service is necessary.

The lab repository is not a subdirectory deployed as an active CIRewind test
target. CIRewind stores a reviewed exportable source package and expected hashes
locally before the maintainer creates the external repository.

The export is a hash-locked Git bundle plus a sidecar object manifest, not only a
working-tree archive. The bundle contains the complete reviewed history through
import commit I and the intended refs. The manifest records object-format
algorithm, every required commit/tree/blob/tag object ID, parent topology,
author/committer identities and timestamps, ref-to-object mappings, annotated-
tag objects and peeled commits, bundle SHA-256/length, and expected results of
`git bundle verify` and `git fsck`. Import tests clone the bundle into two empty
repositories and prove identical I, A, B, tag objects, peeled commits, trees,
and workflow bytes. The sidecar lives in CIRewind's reviewed lab source package,
so it can hash the bundle without creating a Git-object self-reference. The
external repository records I and the sidecar hash in a later provenance commit.

## Proposed layout

```text
.github/
  ISSUE_TEMPLATE/reproduction.yml
  workflows/
    direct.yml
    composite.yml
    reusable-caller.yml
    reusable.yml
    skipped.yml
    matrix.yml
    rerun.yml
actions/
  marker/action.yml
  wrapper/action.yml
protocol/
  README.md
  expected-findings.json
  run-record.schema.json
  reproduction-record.schema.json
  reset-checklist.md
SECURITY.md
README.md
LICENSE
```

All GitHub Actions in the lab use the minimum possible permissions, beginning
with a top-level permission map granting only `contents: read`. Checkout or setup Actions are
avoided where plain workflow metadata suffices; any introduced third-party
Action is source-verified and pinned to a full commit. No workflow uses
`pull_request_target`, untrusted pull-request code, writable `GITHUB_TOKEN`,
`id-token: write`, package/release/deployment permissions, or production
environment.

Repository tag protections cover immutable fixture and release tags. The only
documented mutation exception is the disposable lightweight `v1` ref, restricted
to the reviewed protocol and operator. No wildcard exception may permit moving
`fixture-a`, `fixture-b`, or a release tag.

## Harmless Actions A and B

A and B are complete immutable Git commits in the lab repository. Their only
intentional behavioral difference is a fixed public marker:

```text
A: cirewind-lab-marker=A
B: cirewind-lab-marker=B
```

The marker Action is a minimal composite Action with fixed shell output. It must
not:

- enumerate, interpolate, print, encode, hash, validate, or transmit environment
  variables or secret values;
- read process memory, credential stores, Git configuration, home directories,
  repository contents beyond its own fixed metadata, or runner metadata;
- make any network request;
- write outside the job's ordinary temporary workspace;
- upload/download artifacts, mutate GitHub, create releases/deployments, or
  invoke a package manager;
- execute dynamically downloaded content;
- deliberately fail except in the separate fixed rerun-control job;
- use obfuscation, encoding, anti-analysis behavior, or destructive commands.

Two immutable annotated fixture tags, such as `fixture-a` and `fixture-b`, bind
the reviewed A and B commits and are never moved. Each annotated tag has its own
tag-object ID and peels to the corresponding A or B commit ID; those identities
must never be conflated. The explicitly designated mutable `v1` is a lightweight
tag whose ref points directly to A or B. Neither A nor B is called malicious or
compromised; B is called the **affected synthetic marker** solely because the
synthetic pack uses B's full commit ID as the incident indicator.

## Stable support code

Wrapper/reusable support definitions are pinned by full reviewed commit wherever
GitHub syntax permits. Only the marker reference intentionally uses `v1` in the
central experiment. Moving `v1` must not accidentally change the caller
workflow, expected-result file, tag-control protocol, or unrelated support code.

The wrapper is a composite Action whose metadata invokes the marker Action. The
reusable workflow calls the stable wrapper. The resolver must therefore see:

```text
caller workflow -> reusable workflow -> composite wrapper -> marker@v1 -> A or B
```

Caller workflow SHA, called reusable-workflow SHA, wrapper Action definition SHA,
declared mutable ref, and runtime marker source SHA remain separate identifiers.

## Scenario matrix

| ID | Scenario | Controlled behavior | Required CIRewind conclusion |
|---|---|---|---|
| `PUBLIC-DIRECT` | Direct mutable Action | A normal step calls marker `@v1` while `v1` is B and begins. | Exact B lifecycle supports `CONFIRMED_EXECUTED`; declaration/window alone is insufficient. |
| `PUBLIC-COMPOSITE` | Composite calls affected Action | Workflow calls stable wrapper; wrapper calls marker `@v1` while B. | Transitive chain is retained. B is `CONFIRMED_EXECUTED` only when exact nested lifecycle start joins; otherwise no stronger than exact download plus `POTENTIAL_TRANSITIVE`, and the pre-publication gate fails until the expected oracle is deliberately fixed. |
| `PUBLIC-REUSABLE` | Reusable -> composite -> affected | Caller invokes reusable workflow; reusable calls stable wrapper; wrapper calls marker `@v1`. | Exact GitHub-recorded called-workflow identity is separate and may support `CONFIRMED_CALLED_WORKFLOW`; nested B follows the same lifecycle rule as composite. |
| `PUBLIC-SKIPPED` | Downloaded/prepared but skipped | Job preparation obtains marker B, but a fixed false condition prevents the marker step from beginning. | At most `CONFIRMED_DOWNLOADED`; never `CONFIRMED_EXECUTED`. If GitHub does not prepare it under the observed grammar, record the gap rather than manufacture a download. |
| `PUBLIC-MATRIX` | Matrix expansion | A fixed two-axis matrix produces distinct API job IDs with intentionally similar display names. | Each `run_id + run_attempt + job_id` stays distinct; no merge by display name. Exact B lifecycle is per job. |
| `PUBLIC-RERUN-FULL` | Full rerun after restoring A | Original attempt runs with B; after `v1` is restored, rerun all jobs. | Original and rerun attempts remain separate. Each reports the exact identity its retained logs/metadata show; present-day A never rewrites B. |
| `PUBLIC-RERUN-JOB` | Failed/single-job rerun | One fixed harmless control job fails after marker behavior; rerun failed or selected job after restoration. | Only rerun jobs appear in the new attempt. Called-workflow/action identity follows exact GitHub evidence, not a hardcoded rerun assumption. |

Before publication, the project runs the matrix once under controlled conditions
and freezes an exact expected-findings file containing only observations that the
public GitHub runner grammar can support. A semantic fallback in the table is a
planning safety rule, not permission to publish an ambiguous oracle. If direct B,
download-only separation, composite/reusable reconstruction, matrix identities,
or rerun attempt separation cannot be demonstrated, the public-lab gate is
NO-GO.

That pre-publication live qualification is itself an external repository/tag/
workflow action and requires Maksim's explicit authorization. It may use only an
authorized disposable staging repository created for this protocol. Local
fixture tests can proceed without that authority but cannot satisfy the live
qualification gate.

## Safe mutable-tag protocol

The tag-control tool or documented commands operate only against an explicitly
supplied exact lab repository. They are external laboratory operations; the
`cirewind` binary never mutates tags.

Preconditions:

1. Operator has write access only to a disposable lab/fork and authenticates
   through their normal Git/GitHub tooling; no token is written to the repository
   or command transcript.
2. Repository ID/owner/name and default branch commit equal the reviewed protocol
   record.
3. Local worktree is clean and remote URL equals the explicitly approved lab.
4. A/B full commit IDs, annotated fixture-tag object IDs, and their peeled
   commit IDs equal the reviewed object manifest and are reachable from the
   reviewed lab history.
5. Current remote lightweight `refs/tags/v1` points directly to the expected old
   A or B commit.
6. Operator enters a literal acknowledgement naming the repository, old object,
   and new object.

Each move uses a lease against the exact expected old lightweight-ref target
commit. A mismatch
fails closed; no generic `--force`, wildcard refspec, branch mutation, release
tag, organization target, or repository discovered from pack content is allowed.
After the move, read back `refs/tags/v1` and record its exact target commit and
observation time.

Protocol sequence:

1. Set/verify `v1 -> A`; dispatch baseline; record run/attempt/job IDs.
2. Move `v1: A -> B` with an exact-object lease; verify and record.
3. Dispatch direct, composite, reusable, skipped, matrix, and rerun-control
   workflows; record dispatch and run IDs.
4. Wait for terminal job states and retained logs. Do not restore early merely to
   shorten the protocol.
5. Restore `v1: B -> A` with an exact-object lease; verify and record.
6. Request full, failed-job, and single-job reruns through explicit GitHub UI/API
   operations against recorded run IDs; record new attempt/job IDs. GitHub's
   official [rerun documentation](https://docs.github.com/en/actions/how-tos/manage-workflow-runs/re-run-workflows-and-jobs)
   is the platform basis (retrieved 2026-08-22); the lab still measures the
   resulting attempt-specific behavior rather than assuming more than it states.
7. Wait for terminal states, collect with CIRewind, generate raw-disabled case,
   verify its manifest, and compare with the expected oracle.
8. Run the reset checklist and retain public run evidence.

If a failure occurs after B is installed, restoration to A is the first recovery
action. The protocol displays a prominent manual recovery command/check using
the exact recorded objects. Cleanup automation may attempt restoration but must
not claim success until the remote object is read back.

## Run record

A bounded machine-readable run record contains:

- lab repository immutable ID and public URL;
- protocol/source commit and manifest hash;
- A/B Git algorithms and full commit IDs;
- immutable annotated fixture-tag object IDs and their peeled A/B commit IDs;
- mutable lightweight-tag ref target commit before, during, and after;
- observation/dispatch times with event source and precision;
- workflow paths, workflow definition commits, event types, actors, and
  triggering actors;
- run IDs, every run attempt, job IDs, and conclusions;
- requested rerun kind and operator action time;
- CIRewind version/revision/binary digest;
- collection window, case manifest digest, and coverage summary;
- parser/API versions and all material gaps/errors;
- statement that no raw logs, token material, secret values, or private data are
  included.

The run record is evidence context, not a substitute for CIRewind evidence
objects. Approximate GitHub UI times remain approximate.

## Synthetic incident pack

The lab uses a pack containing only:

- the public lab repository/path;
- exact harmless B full commit ID;
- `v1` with the observed bounded synthetic window;
- A as known-good only after its immutable content is reviewed;
- source entries pointing to the lab protocol/tag observations;
- plain remediation text explaining that the exercise is synthetic.

The exposure window is derived from actual recorded remote tag observations and
states its precision/bounds. It is not copied from local wall-clock guesses. The
pack contains no URL that the product follows, script, command, HTML, external
request, real IOC, victim data, or secret.

## Expected findings and prohibited outcomes

The final oracle is keyed by run ID, attempt, job ID, step identity, indicator,
state, provenance ceiling, and evidence relationship—not display names alone.

It must prove:

- exact B execution for at least the direct, composite, reusable, and matrix
  positive lifecycles under the qualified grammar;
- B download/preparation without execution for the skipped scenario;
- exact reusable-workflow identity for the reusable caller when exposed by the
  run-attempt API;
- B and restored A retained separately across rerun attempts;
- historical B is unaffected by present-day `v1 -> A` and current workflow
  content;
- missing/denied evidence, if introduced, becomes `UNKNOWN_EVIDENCE_GAP` and
  never a no-match.

The oracle fails on any of these:

- downloaded-only scenario labeled `CONFIRMED_EXECUTED`;
- attempts or matrix jobs merged by display name;
- `head_sha` used as caller/callee/Action identity;
- a current A tag used to clear historical B;
- a reusable wrapper commit relabeled as the compromised B commit;
- a later rerun/action result causally attributed to an attacker;
- secret access, cloud-role assumption, runner persistence, or deployment
  causation language;
- a public run result asserted without stable evidence IDs and coverage.

## Reset procedure

Reset is successful only when all of the following are checked:

1. Remote `v1` resolves to exact A and not B.
2. Immutable annotated fixture tags retain their exact tag-object IDs and peel
   to their original exact A/B commit IDs.
3. No workflow run remains queued/in progress because of the exercise.
4. No repository/organization secret, variable, environment, deployment key,
   package credential, self-hosted runner, webhook, or GitHub App was created for
   the basic protocol. If an optional isolated extension created one, remove it
   explicitly and record removal without recording a value.
5. Default workflow permissions remain read-only.
6. Repository branch/ruleset protection and selected-Action policy remain as
   reviewed.
7. Public run pages and immutable records needed for reproduction remain
   available; reset does not delete evidence to make results appear clean.
8. The final CIRewind collection records any logs already expired or inaccessible
   as gaps.

Do not delete/rewrite run history, force-push branches, erase immutable fixture
tags, or rotate unrelated credentials as part of reset.

## Reproduction issue template

The lab repository provides a structured issue form with required fields:

- reproducer public identity and conflict disclosure;
- fork/lab repository and immutable source commit;
- exact A/B IDs and `v1` observations before/during/after;
- CIRewind exact qualified v0.2 release-candidate commit, binary SHA-256, and
  acquisition/provenance record; after publication, the released version and
  installation lane may be added as a post-release recheck;
- public run URLs plus run/attempt/job IDs;
- command with tokens/paths sanitized;
- stable anonymous URL for the complete raw-disabled case archive (or every
  manifested case file), archive SHA-256 and byte length, case-manifest
  SHA-256, and `cirewind verify` result reproduced after anonymous download;
- canonical finding-state/count table;
- confirmation that skipped B was not `CONFIRMED_EXECUTED`;
- confirmation that original/rerun attempts remain separate;
- `graph.svg` and report links; sanitized screenshots are optional illustration,
  never a substitute for the downloadable verifiable case;
- coverage, missing logs, parser/runner versions, and deviations from oracle;
- confirmation no real secrets, private repositories, production resources, or
  exfiltration behavior were used;
- permission to link the reproduction publicly.

The form warns not to paste tokens, cookies, signed URLs, raw logs, secret values,
private repository names, or unredacted local paths. Maintainers sanitize or
privately request removal if those appear; they do not quote the sensitive value
into a follow-up.

The downloadable case must contain the exact fixed raw-disabled case contract,
no `raw/`, and no unexpected file/link. Its hosting URL may not require a token,
cookie, expiring signature, or project membership. Privacy/secret-scan failure
rejects the submission; it does not justify accepting a screenshot-only record.

## Independent reproduction gate

A qualifying reproducer is a human who did not author the CIRewind
implementation, lab source, expected oracle, or candidate reproduction record.
Automation may run commands, but it cannot be the reproducer or approver.
The same reproducer may also perform the cold-reader and accessibility reviews,
because those external roles may overlap, provided they did not author the
material under either review and each gate has its own explicit evidence.

At least one outside human must independently reproduce the central direct,
skipped, composite/reusable, matrix, and rerun outcomes on the exact published
lab revision. Their record must include the items above and show a verified case
manifest after anonymous download. The project maintainer downloads and verifies
the full case independently, checks its evidence chains against public run
evidence, and records acceptance or a reason for rejection.

Because this reproduction gates v0.2 publication, the reproducer may use the
exact deeply qualified v0.2 release-candidate binary before a public tag exists.
The record binds its source commit, binary SHA-256, acquisition channel, and
local provenance. After publication, an anonymous released-binary recheck is a
separate post-publication distribution gate; lack of a prior release tag does
not create a dependency cycle or let an arbitrary development build qualify.
That identity/case recheck is tracked separately from the pre-publication human
reproduction and cannot make a failed reproduction pass retroactively.

The preferred acquisition path is an independent reproducible build from the
public immutable RC commit using the recorded Go/toolchain and release build
command. It uses the acquisition record's intended final `0.2.0` metadata rather
than deriving a version from the `v0.2.0-rc.N` source tag, and the resulting
binary must byte-match the project RC digest. If that is
not possible on the reproducer's platform, a retained immutable CI artifact may
be used only when the record includes workflow/run/attempt, artifact ID, the
locally audited artifact/binary hashes, exact source commit, access time, and
provenance verification. A mutable “latest” URL, ad-hoc maintainer attachment,
unrecorded development binary, or artifact that cannot be bound to the RC fails
the gate.

A failure or semantic discrepancy is valuable evidence and is retained. It
blocks the “independently reproduced” claim and coordinated v0.2 gate until
resolved and reproduced again. An internally run lab, bot-created issue,
generated approval, or maintainer repetition cannot satisfy this gate.

## Stable linking without changing the qualified CIRewind commit

Before the CIRewind RC freezes, the lab repository publishes a stable
`reproductions/` index path and CIRewind stages only that reviewed fixed URL.
After an outside submission is accepted, the complete sanitized record is added
to the separate lab repository as `reproductions/REPRODUCTION_ID.json`; its
exact lab-repository commit URL/hash is the immutable acceptance reference and
the index points to it. CIRewind's already frozen README/site need no source
change. `LAB-PUBLIC-010` and the final consistency gate verify the external
record/index read-only after RC freeze. Any desired CIRewind-source edit after
freeze creates a new RC binary/commit and requires the outside binary check to
be repeated.

## Security and privacy review

Before publication:

- scan full Git history and generated artifacts for credentials/private data;
- inspect every workflow permission, event, expression, shell step, and Action
  dependency;
- prove marker Actions perform no network I/O or environment enumeration;
- test tag tooling against wrong repo, wrong old object, missing acknowledgement,
  interrupted restore, and hostile remote output;
- pin all third-party Actions to source-verified full commits or remove them;
- ensure fork pull requests cannot obtain write permissions or secrets;
- run terminal/Markdown/YAML/path injection fixtures against record generators;
- ensure expected outputs contain only synthetic identities and public run IDs;
- publish a security contact and clear “harmless test only” scope.

GitHub documents that workflow-run logs for public resources can be downloaded
without authentication through the
[workflow-runs REST API](https://docs.github.com/en/rest/actions/workflow-runs?apiVersion=2026-03-10)
(retrieved 2026-08-22), even though browser log viewing may require sign-in.
The public lab therefore treats its logs as publicly retrievable: workflows emit
only fixed markers and ordinary GitHub metadata, and no secret is configured,
even a fake-valued one, for the basic path.

## Maintainer-only gates

Maksim must explicitly authorize or perform:

- creation/visibility of the public lab repository;
- import of the reviewed source package;
- repository/ruleset/workflow-permission settings;
- first mutable-tag movement and recovery drill;
- any workflow or helper capable of moving the tag;
- recruitment/coordination of an outside reproducer;
- acceptance of the external reproduction record;
- linking the lab and result from CIRewind's README/site.

No source package or local test completion grants this authority automatically.
