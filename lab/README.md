# CIRewind controlled forensic lab

This directory defines synthetic GitHub Actions scenarios for validating temporal
evidence semantics. It is not an exploit lab. Every Action emits only a fixed,
non-sensitive marker; no fixture sends data over the network, modifies repository
content, publishes packages, or accesses a real credential.

The names under the `cirewind-fixtures` owner are synthetic fixture identifiers,
not incident indicators. Provision them only in repositories you control. Secret
names beginning with `CIREWIND_LAB_` are placeholders. Never put a production
credential in a lab secret.

## Controlled repositories

The complete online lab uses three disposable private repositories:

1. `cirewind-fixtures/harmless` contains one of the source trees under
   `actions/mutable-marker/`. Commit the `commit-a` tree as safe commit A and the
   `commit-b` tree as harmless marker commit B. Move a `v1` tag only between those
   two commits.
2. `cirewind-fixtures/wrapper` contains `actions/wrapper/action.yml` at its root.
3. `cirewind-fixtures/workflows` contains the reusable workflow definitions from
   `workflows/reusable/` under `.github/workflows/`.

The consuming repository contains the remaining local Actions and scenario
workflows. Environment and self-hosted-runner scenarios require resources owned
by the lab operator. Do not aim these workflows at a repository, environment, or
runner that is not explicitly dedicated to CIRewind testing.

## Central temporal experiment

Record every commit and run-attempt identifier during this sequence:

1. Point `v1` at safe commit A and run the baseline workflow.
2. Move `v1` to harmless marker commit B and run scenarios A through M.
3. Rerun scenario E after restoring `v1` to A.
4. For scenario F, move the reusable-workflow `v1` tag after the first attempt,
   then rerun only the failed job. Preserve GitHub's referenced-workflow metadata
   for both attempts.
5. Restore all mutable tags to A before collecting present-day configuration.
6. Archive the attempts and logs before the configured retention period expires.

The success condition is not that every scenario is an execution. Scenario D must
remain downloaded-only, scenario I must remain blocked before job start, and
scenario N must remain an evidence gap.

## Scenario map

| ID | Definition | Required conclusion |
| --- | --- | --- |
| A | Direct mutable Action | B downloaded and executed |
| B | Composite wrapper | B is a transitive executed dependency |
| C | Reusable workflow to composite wrapper | Caller, callee, wrapper, and B remain distinct |
| D | False Action-step condition | B downloaded; execution not demonstrated |
| E | Full rerun after tag movement | Attempts remain separate; B then A |
| F | Failed/single-job rerun | Called-workflow identity remains attempt-specific |
| G | Named secret passed to one Action step | Only the explicit mapping is potentially reachable |
| H | `secrets: inherit` | Inheritance is one caller-to-callee hop |
| I | Protected environment is not approved | No environment-secret eligibility |
| J | `id-token: write` with no trust policy | OIDC minting capability only |
| K | Dedicated self-hosted runner | Runner classification is self-hosted |
| L | `pull_request_target` | Base-repository context is recorded without untrusted checkout |
| M | Matrix job | Every expanded job has its own execution identity |
| N | Deleted or expired logs | `UNKNOWN_EVIDENCE_GAP`, never a clean result |
| O | Historical workflow differs from current | Historical definition controls the conclusion |
| P | Static declaration and runtime SHA disagree | `CONTRADICTORY_EVIDENCE` |
| Q | Concurrent jobs | Time overlap alone does not establish causation |

`testdata/fixture-inventory.json` is the machine-readable source of expected
offline semantics. It uses fixed synthetic identifiers and contains no real-world
incident facts.
