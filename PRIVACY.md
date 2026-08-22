# Privacy model

CIRewind is a local, read-only incident-response CLI. It has no hosted control
plane, account requirement, advertising, upload path, or telemetry by default.
Network-backed investigation and archive contact GitHub.com only for the scope
selected by the operator; replay, pack validation, case verification, and the
offline demo require no network access.

## Data CIRewind processes

Depending on permissions and retained evidence, an investigation or archive may
process:

- repository and organization names;
- workflow, Action, run, attempt, job, and step metadata;
- actor identifiers and timestamps;
- exact Git object IDs and immutable package digests;
- relevant token-permission, secret-name, environment, runner, artifact, and
  deployment context; and
- bounded workflow log objects.

CIRewind never retrieves, validates, hashes, or stores secret values. A secret
name is retained only when it participates in an observed reference, step
mapping, reusable-workflow mapping or inheritance relationship, or supported
environment-eligibility conclusion. A repository or organization inventory is
not treated as exposure.

## Authentication

Networked commands resolve a token from the process environment in this order:
`CIREWIND_GITHUB_TOKEN`, `GITHUB_TOKEN`, then `GH_TOKEN`. Authentication material
must remain in process memory and must not appear in command output, URLs, errors,
SQLite databases, JSONL ledgers, reports, manifests, caches, or evidence IDs.

Use a dedicated read-only credential with the minimum repository and organization
visibility needed. Shell history, process inspection, environment inheritance,
debuggers, crash dumps, and host compromise are outside CIRewind's control;
protect the collection host accordingly.

## Local evidence storage

CIRewind writes to paths selected by the operator. Compact structured evidence is
the default. Raw logs are opt-in because GitHub masking is not a guarantee that
application output contains no credentials from other systems, personal data, or
proprietary information.

A raw-enabled archive is one logical set consisting of `archive.db` and its
content-addressed `archive.db.raw/` sidecar. Preserve, copy, and delete them
together. Raw objects enter a generated case only when the operator also requests
raw materialization; those files are covered by the case manifest.

Even without raw logs, cases can expose sensitive operational metadata:
repository topology, workflow history, actor names, secret names, permission
scopes, runner identifiers and labels, environment names, resource names, and
incident-response conclusions. Restrict access, prefer encrypted storage, and
sanitize a copy before sharing.

On Unix-like systems, CIRewind creates case and archive material with restrictive
permissions where supported and rejects unsafe parent symlinks. Windows ACLs,
network filesystems, backup systems, snapshots, indexers, and copied exports may
apply different access or retention rules.

## Network behavior

`investigate` and network-backed `archive` make read-only GitHub.com API and
validated temporary log-object requests selected by operator flags. Pack content
cannot choose an endpoint, redirect the client, or trigger any outbound request.
Downloaded workflow or Action content is parsed as hostile data and never run.

Default tests use local mock servers and sanitized fixtures. The controlled live
qualification used a process-only credential, disabled raw retention, and kept
its private GitHub identifiers and generated evidence outside the public tree.

## Retention and deletion

CIRewind operates no remote evidence service and cannot delete local cases on an
operator's behalf. Operators control case, archive, sidecar, cache, backup, and
export retention, subject to their incident-response and legal obligations.

Deleting a file does not guarantee erasure from snapshots, backups, flash media,
or remote synchronization. Use storage-appropriate secure deletion or
cryptographic erasure when policy requires it.

SHA-256 manifests support integrity verification. They do not provide encryption,
anonymity, publisher authentication, or legal chain-of-custody certification.
