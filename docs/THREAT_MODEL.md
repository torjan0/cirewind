# CIRewind threat model

Status: v0.1 security requirements
Planning date: 2026-08-20
Architecture trust boundaries: [ARCHITECTURE.md](ARCHITECTURE.md)
Security tests: [TEST_STRATEGY.md](TEST_STRATEGY.md)
GitHub source facts and primary citations: [GITHUB_DATA_SOURCES.md](GITHUB_DATA_SOURCES.md), retrieved 2026-08-20

## Security posture

CIRewind inspects repositories and CI output involved in a supply-chain incident. Therefore every fetched name, byte, archive entry, workflow, Action definition, error string, and incident pack is hostile even when delivered by an authenticated GitHub API.

The primary security goals are:

1. Do not expose the analyst's GitHub credential or any secret value.
2. Do not execute or import investigated code.
3. Do not allow hostile input to write outside the selected case/archive or to become active in a terminal/report.
4. Bound CPU, memory, disk, network, and parser work.
5. Preserve evidence integrity, provenance, and uncertainty.
6. Avoid causing mutations in GitHub or other systems.

This model assumes the local operating system, Go runtime, CIRewind binary, configured TLS roots, and analyst-selected output parent are initially trusted. It does not claim protection after root/administrator compromise.

## Protected assets

| Asset | Security property |
| --- | --- |
| GitHub access token/App token | Confidentiality; use only for intended read-only GitHub.com routes |
| GitHub organization/repositories | Integrity and availability; CIRewind must not mutate them |
| Secret values | Must never be intentionally requested, inspected, verified, hashed, stored, or reported |
| Analyst host and filesystem | No code execution, traversal, symlink overwrite, uncontrolled resource exhaustion, or active-content escape |
| Case/archive contents | Confidentiality, integrity, stable provenance, crash-safe writes |
| Evidence semantics | No false promotion, attempt merging, hidden gaps, or source/derivation substitution |
| Incident packs | Deterministic interpretation and provenance; no executable behavior |
| Terminal/log stream | No escape-sequence injection, log forging, or multiline spoofing |
| Offline HTML report | No stored XSS, remote dependency, automatic network request, or script/data-context escape |
| CIRewind distribution | Dependency/license integrity, reproducible provenance, signed releases where practical |

## Adversaries and misuse

- A compromised Action maintainer controls Action repository content, tags, metadata, bundled scripts, and sometimes release/package content.
- A compromised target repository contributor controls workflow YAML on relevant events, branch/ref text, job/step names, matrix values, artifact names, and application output.
- A malicious Action can print arbitrary bytes, fake runner-like log lines inside its step, generate enormous output, and influence downstream resource metadata.
- A malicious incident-pack author attempts parser exhaustion, semantic ambiguity, report injection, or pack-directed network access.
- A malicious archive/case provider supplies a corrupt or weaponized SQLite file or raw-evidence tree.
- A network attacker or untrusted local proxy attempts credential capture, redirect manipulation, truncation, or response modification. TLS is relied on; a user-installed interception root is part of the local trust base.
- A local unprivileged user attempts to read case files, race output paths, or replace components with symlinks.
- An honest operator supplies excessive scope, weak credentials, an output path with unsafe contents, or incorrect incident data.
- A future maintainer accidentally weakens semantics, introduces a write-capable endpoint, or lets a report/graph imply causation.

## Attacker-controlled inputs

- Workflow YAML, Action metadata YAML, and all scalar values/expressions within them.
- Traditional/immutable Action package setup logs and every application log line.
- ZIP central-directory metadata, paths, sizes, compression ratios, Unix mode bits, comments, extra fields, and duplicate names.
- Organization/repository/workflow/run/job/step/environment/runner/artifact/package/release/deployment/ref names.
- Matrix-generated display names and event payload-derived titles.
- API JSON, GraphQL responses, headers used only as data, error bodies, and status text.
- Signed-log redirect locations.
- Repository content bytes at exact SHAs.
- Incident-pack YAML, sources, URLs, remediation text, IOC literals, and time values.
- Imported SQLite/archive/case bytes and manifests.
- CLI/configuration paths and environment variable values.

GitHub masking reduces some accidental log disclosure but is not a security boundary. Raw logs can contain sensitive application output and remain opt-in.

## Trust boundaries

### Authentication boundary

The token enters the process from an environment variable, protected file descriptor, or a future OS credential adapter. A token command-line flag is prohibited because process listings and shell history can expose it. CIRewind never invokes `gh` or another process merely to obtain a token; an explicit future adapter requires a separate threat review.

Authorization is attached only to configured `https://api.github.com` requests. It is never forwarded to a log-storage redirect, report link, pack URL, GitHub web URL, or error reporter. Authentication headers are omitted from traces and evidence.

### GitHub API to parser boundary

TLS-authenticated API responses establish source provenance, not memory safety or semantic truth. All bodies are counted, hashed, bounded, and parsed with context cancellation. Hostile strings remain tainted through storage and reporting.

### Signed log redirect boundary

Log endpoints return a short-lived redirect. The transport follows only the narrowly validated log-download transition, strips authorization/cookies, requires HTTPS, limits redirect count to one, and applies a compiled host/IP policy. It stores no signed query string. A changed/unknown redirect pattern yields a coverage gap rather than a general-purpose fetch. The current policy is mock-tested; controlled validation against GitHub.com's live redirect behavior remains a release gate.

### Parser to evidence boundary

Parsers emit typed observations plus source spans, not findings. An observation is accepted only from an expected source class and structural context. For example, a runner download-announcement control line is valid only in the setup/top-level control entry, never merely because a user step printed the same text; even there, it proves neither preparation completion nor execution by itself.

### Evidence store to report boundary

Database values are still hostile. HTML/JavaScript/CSV/terminal encoders apply at each output sink. “Already escaped” strings are prohibited in the domain model.

### Imported archive boundary

An archive is untrusted even if its manifest verifies, because a bundled manifest is not an authenticity signature. The reader validates file type, size, schema allowlist, SQLite integrity/application ID, and evidence relationships before exposing a read-only snapshot to replay. A raw-enabled archive is one logical bundle consisting of the SQLite file and its sibling `<archive>.raw/` directory; single-file export/import is rejected for such archives. Missing or corrupt sidecar bytes become a raw-availability and literal-search gap while compact facts remain replayable; an explicit raw case-copy request fails closed. Raw copy/search operations recheck that each object is a regular file with the recorded length and SHA-256, and require no group/other mode bits on systems that expose Unix permissions, before consuming it.

## Security invariants

- The GitHub transport exposes only compiled, read-only endpoint descriptors; callers cannot supply an arbitrary URL or method.
- Incident-pack content never initiates network, process, plugin, template, or filesystem operations.
- Repository/Action content is never checked out, built, imported, sourced, loaded as a plugin, or executed.
- No secret-value endpoint or log-secret recovery routine exists.
- No repository/ref/job/step/evidence name is used directly as a filesystem path.
- All SQL statements are static or constructed from trusted schema identifiers; hostile values are bound parameters.
- Every stream has a byte/work limit and cancellation path.
- Raw evidence retention is false unless explicitly enabled and recorded.
- Reports contain no remote assets and make no automatic network requests.
- No telemetry is emitted by default; v0.1 defines no telemetry endpoint.

## Concrete safety budgets

These are conservative design defaults. Phase 0/9 tests may lower them. Raising a soft default remains bounded by a compiled hard ceiling and is recorded in collection metadata. Exceeding a limit creates a typed evidence gap; it never silently truncates into a no-match conclusion.

| Input/resource | Default | Hard ceiling / behavior |
| --- | --- | --- |
| Incident pack | 2 MiB | 2 MiB; reject before YAML graph construction |
| Workflow or Action metadata file | 4 MiB | 16 MiB; larger content is a `SIZE_LIMIT` gap |
| REST/GraphQL JSON response | 64 MiB | 256 MiB per response, streaming decode where practical |
| Attempt-log compressed body | 512 MiB | 2 GiB; stop stream and record gap |
| Attempt-log total uncompressed entries | 2 GiB | 8 GiB; counted while streaming |
| One log entry/job log | 256 MiB | 1 GiB |
| ZIP file count | 20,000 | 100,000 |
| ZIP compression ratio | 100:1 per entry and aggregate | 200:1; unknown size is streamed under byte budget |
| Nested archives | 0 | Never recursively unpack an entry as an archive |
| ZIP/YAML path length | 4,096 bytes | Reject metadata beyond limit; never materialize source path |
| Workflow/Action YAML nodes | 200,000 | 500,000; AST depth 64, alias references 100, cumulative alias expansion 4 MiB |
| Incident-pack YAML nodes | 20,000 | Anchors/aliases/merge keys forbidden; depth 32 |
| YAML scalar | 1 MiB for fetched definitions | Tighter field limits for packs; 4 MiB absolute |
| Expression text | 64 KiB | Do not evaluate beyond supported bounded grammar |
| Stored/display error | 4 KiB | Terminal controls/newlines escaped; original sensitive body not retained |
| Worker queues | 256 records each | Weighted global in-memory byte semaphore |
| Network concurrency | 8 metadata, 2 logs, 4 content | Operator may lower; hard max established by benchmark and secondary-limit tests |
| Case raw bytes | 10 GiB provisional | Explicit operator limit; stop retention before disk exhaustion and preserve compact facts/gap |

ZIP libraries can expose an entry before the full uncompressed total is known. The implementation must count bytes actually read and stop exactly at budget, not trust header sizes.

## Abuse cases and mitigations

### ZIP path traversal and filesystem overwrite

**Attack:** entries use `../`, absolute paths, Windows drive/UNC paths, backslashes, NUL, case collisions, alternate data streams, or symlink targets.

**Mitigations:** CIRewind does not extract source paths. It streams recognized regular entries by archive index and records a sanitized logical name. Opt-in raw retention writes each entire bounded source object under `<archive>.raw/<lowercase-source-sha256>.bin`, never under an archive-entry, evidence, repository, run, or job name. Investigation and replay copy a verified retained object to the case using the same content-addressed filename, and the case manifest covers that file. If future entry extraction is introduced, it requires canonical containment checks using OS-aware path semantics, exclusive creation, and a new threat review.

Duplicate/case-colliding logical entry names are all retained as metadata and make structure ambiguous; the parser does not choose last-wins.

### ZIP bombs and archive parser exhaustion

**Attack:** tiny compressed input expands enormously; many empty files; misleading sizes/CRC; nested archive; malicious extra fields.

**Mitigations:** compressed/uncompressed/file-count/per-entry/ratio budgets, streaming hashes and reads, cancellation, no recursive unpack, no entry preallocation from untrusted size, duplicate-name checks, and regression corpus. CRC failure or truncated stream yields partial evidence plus `MALFORMED_ARCHIVE`, not collected/no-match.

### Symlink and hard-link handling

ZIP Unix mode bits indicating symlink, device, socket, FIFO, or other non-regular types are rejected for parsing. No link target is followed. Hard-link-like metadata is treated as unsupported. Case paths are separately checked for symlink components before every create/finalize operation.

### YAML aliases, duplicate keys, and expansion

**Attack:** alias bombs, deep nesting, duplicate security keys, custom tags, implicit coercion, or enormous scalars.

**Mitigations:** location-preserving AST parser, byte/node/depth/scalar limits, duplicate-key detection, no custom tags/includes, explicit timestamp/string parsing, cancellation, and fuzzing. Incident packs reject aliases/anchors/merges completely. Workflow/Action YAML permits only bounded aliases because GitHub workflow syntax supports YAML anchors; expansion is lazy and counted. Ambiguous workflow YAML becomes a parse gap.

### Expression and resolver explosion

**Attack:** huge matrices, recursive reusable/composite references, dynamic `uses`, cyclic definitions, or expression nesting.

**Mitigations:** no arbitrary expression evaluator; only recognized reference/secret shapes; matrix expansion budget with symbolic fallback; documented workflow/composite depth caps; visited set keyed by repository/commit/path; edge/node total budget. Dynamic targets remain unresolved.

### Runner-control log forgery

**Attack:** a malicious step prints `Download action repository`, `GITHUB_TOKEN Permissions`, group markers, or `Starting:` to manufacture evidence.

**Mitigations:** source-context allowlists (setup/top-level control entry for preparation and permission facts), anchored versioned grammars, timestamp/entry structure, independent REST step metadata, step number/phase correlation, and no matching on names alone. A control-looking line in an application step is stored as hostile output or ignored by the control extractor. Conflicting structural signals emit `CONTRADICTORY_EVIDENCE` or a parser gap.

### Terminal escape and log forging

**Attack:** OSC hyperlinks/clipboard sequences, CSI cursor controls, bidi overrides, carriage returns, fake new log records, or enormous names.

**Mitigations:** operational logs are structured; every hostile value is length-bounded and JSON-escaped or terminal-sanitized at output. Strip/visualize C0/C1 controls, ESC/CSI/OSC/DCS sequences, carriage return, and bidi control characters. Newlines become visible escapes within one event. Raw bytes, if retained, are never printed automatically.

### HTML and JavaScript injection

**Attack:** repository/job/step/source/remediation strings close tags, break JSON/script context, create active URLs, or exploit graph labels.

**Mitigations:** context-aware Go HTML templates, no trusted-HTML domain type, JSON generated with a real encoder, escaping of `<`, `>`, `&`, U+2028/U+2029, data in a non-executable container, and fixed hashed scripts/styles. The self-contained report has a restrictive CSP equivalent to:

`default-src 'none'; img-src 'none'; style-src <fixed SHA-256 hash>; script-src <fixed SHA-256 hash>; connect-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'`

The exact CSP must be golden-tested in supported browsers before release. A
self-contained file cannot enforce `frame-ancestors`: browsers ignore that
directive in a `<meta>` policy. An operator who serves a report over HTTP must
set `Content-Security-Policy: frame-ancestors 'none'` as a response header in
addition to preserving the embedded policy. No remote font, image, script,
style, iframe, source map, fetch, WebSocket, or analytics reference is
permitted. Provenance URLs are either displayed as text or validated `https`
links that require an explicit user click; pack text cannot set arbitrary
schemes/attributes. The current offline tests do not qualify the full
supported-browser matrix.

### CSV and formula injection

**Attack:** cells begin with `=`, `+`, `-`, `@`, tab, CR, or Unicode forms interpreted by spreadsheet software.

**Mitigations:** RFC 4180 generation through the standard CSV writer plus a documented spreadsheet-safe text transform for every untrusted cell. Potential formula cells receive a leading apostrophe in CSV output only. JSON retains the exact normalized value. Tests cover delimiters, quotes, newlines, encodings, and formula prefixes.

### JSON/JSONL injection and log splitting

**Attack:** hostile bytes create invalid JSON or extra JSONL records.

**Mitigations:** standard JSON encoder only; no string concatenation; one encoded object plus one writer-owned newline per ledger record. Invalid UTF-8 is replaced or represented as encoded bytes with a redaction/normalization flag. Canonical hashing operates on typed normalized objects.

### SQL injection and hostile database content

**Attack:** values alter queries; imported database schema contains malicious views/triggers/extensions; giant values exhaust memory.

**Mitigations:** bound parameters, fixed trusted table/column identifiers, foreign keys and CHECK constraints, connection limits, statement cancellation, row/field size validation, no extension loading, no `ATTACH`, and no SQL sourced from evidence/packs. Imported DBs are size-bounded, opened read-only/query-only after an exact application ID/user version/schema allowlist and integrity check; `trusted_schema=OFF`/defensive mode are enabled where the selected driver exposes them. CIRewind does not execute imported views or triggers.

### Case-path traversal, races, and cross-platform semantics

**Attack:** malicious output/config path targets a broad directory, contains symlinks, reserved Windows names, case collisions, or is swapped during writes.

**Mitigations:** resolve an absolute canonical parent selected by the operator; reject root/home/workspace-wide ambiguous targets; create a new leaf with exclusive operations; traverse with no-follow/handle-relative APIs where supported; use fixed ASCII filenames for required outputs and lowercase SHA-256 filenames for raw objects. Repository names never become paths. Temporary names are random fixed-format siblings. Refuse an unexpected non-empty destination. Finalize with atomic rename on the same filesystem.

Unix directory/file modes are `0700`/`0600` regardless of umask. Owner-restricted Windows ACL behavior, prominent failure/warning policy when protection cannot be established, and cross-platform path qualification are release requirements; they are not established by the current Linux-only filesystem tests.

### HTTP SSRF, redirects, and credential forwarding

**Attack:** hostile pack/API content causes arbitrary fetch; signed redirect targets localhost/private networks; redirects receive the GitHub token.

**Mitigations:** typed compiled GitHub.com routes only, no general URL input, pack URLs inert, HTTPS, one stripped-auth log redirect, current-host allowlist/public-address validation proven in spike, DNS/IP checks per connection, bounded response, and no recursive redirects. If GitHub changes legitimate storage hosts, collection fails visibly until policy is updated; it does not relax to arbitrary hosts.

Environment-configured proxies are part of the local trust base and may see TLS destinations or content if they terminate trusted TLS. CIRewind records only that a proxy path was used, never proxy credentials, and supports a documented no-proxy mode.

### Rate-limit and availability abuse

**Attack:** enormous org/window or server throttling causes runaway requests/retries and prevents other tooling from using the token.

**Mitigations:** recursive partitions with work budgets, bounded concurrency, shared primary/secondary rate controller, `Retry-After` support, cancelable jittered backoff, per-source retry limits, resumable coverage watermarks, and optional request budget. No write endpoints are used. Exhaustion becomes a typed partial result.

### Incident-pack compromise

**Attack:** unsafe YAML, regex DoS, semantic conflict, malicious remediation, fake source links, or pack-directed I/O.

**Mitigations:** [INCIDENT_PACK_SPEC.md](INCIDENT_PACK_SPEC.md) closed schema, strict limits, no aliases/unknowns/regex/scripts/templates/HTML/network, plain guidance, per-indicator sources, typed digests, deterministic canonicalization, source-conflict review, two-maintainer real-pack review, and exact pack hashes in cases. Validation is structural, not an authenticity claim.

### Secret and token handling

**Attack:** tool logs token; persists authorization; downloads raw logs with leaked values; attempts to identify/verify secrets.

**Mitigations:** token never enters domain objects/evidence; custom HTTP tracing redacts all headers/cookies/query signatures; errors use allowlisted metadata; no request/response dump option in v0.1. Go strings may be copied, so token lifetime is minimized and no child process is spawned. The tool never calls secret-value APIs because GitHub does not expose Action secret values and CIRewind does not try to recover them from logs.

Secret metadata is limited to names, scope, visibility/selection, timestamps, and flow. CIRewind never compares leaked output to current secrets, never hashes possible values, and never runs the incident-specific secret recovery behavior in GitHub's audit tool.

### Privacy and raw evidence

**Risk:** even compact cases disclose private repository names, workflow structure, secret names, runner identities, permissions, environments, and incident scope. Raw logs can contain source, customer data, access tokens that masking missed, and application output.

**Mitigations:** owner-only local files, raw logs off by default, no telemetry/automatic upload, explicit collection scope, source-class redaction flags, compact structured control facts, and no raw content in normal terminal output. Reports label sensitivity and raw retention. Operators are advised to use encrypted storage and approved evidence-handling channels.

A future selective-disclosure/redacted export must create a separately hashed derived case, preserve derivation to the original, and never mutate the original bundle. Encryption-at-rest is not built into v0.1 and remains a residual local deployment responsibility.

### Downstream report consumers

JSON, CSV, SQLite, and HTML consumers may have their own vulnerabilities. CIRewind produces valid escaped formats and documents that hostile data remains hostile. Opening `case.db` in a full-featured external client, clicking provenance links, or disabling browser CSP leaves CIRewind's process boundary.

## Semantic abuse cases

| Abuse | Required prevention |
| --- | --- |
| Download announcement reported as completed preparation | Require a validated completion boundary or stronger lifecycle proof; otherwise preserve resolution and a gap |
| Prepared skipped Action reported as executed | Independent step-begin evidence and regression scenario D |
| Current safe tag used to clear historical run | Runtime SHA/digest and bitemporal ref observations; current state capped at `CURRENT_REFERENCE_ONLY` |
| Missing logs interpreted as no compromise | Required coverage unit forces `UNKNOWN_EVIDENCE_GAP` |
| Secret exists, therefore exposed | Separate metadata/reference/pass/eligibility/audit-provided states |
| `id-token: write`, therefore cloud compromise | Emit only `OIDC_MINTING_CAPABILITY`; no cloud identity edge without trust adapter evidence |
| Downstream deployment, therefore attacker caused it | `OBSERVED_AFTER`/direct-ID relation and conservative text |
| Same run ID attempts merged | Database uniqueness and finding subject includes attempt/job |
| Audit job name joined to wrong matrix job | Never join on name alone; ambiguity remains a gap |
| YAML order used as happens-before for concurrent steps | Retain step intervals and explicit synchronization; overlapping unsynchronized steps remain unordered |
| Pack `L4_CERTAIN` claim promotes weak runtime evidence | Finding provenance is capped by all material inputs; semantic state still follows evidence |

## CIRewind supply-chain security

- Keep dependency count small and record direct/transitive licenses.
- Pin Go module versions/checksums; review generated/transpiled SQLite dependency size and update cadence.
- Run vulnerability scanning, static analysis, tests, and fuzz regressions in release CI.
- Produce an SBOM and build provenance for CIRewind itself.
- Vendor report assets intentionally or embed version-pinned artifacts with their licenses and source hashes; no runtime CDN.
- Protect release tags, require review/DCO, use reproducible build settings where feasible, sign release artifacts/checksum file, and document verification.
- No post-install scripts, auto-update code, or plugin loading in v0.1.

## Security verification requirements

Required fuzz targets include:

- Attempt/job log ZIP central directory and streaming entries.
- Runner control-line grammars and group state machines.
- Workflow/Action YAML AST and reference/secret-expression extraction.
- Incident-pack YAML, canonicalization, and every indicator normalizer.
- Repository/ref/path/domain/IP normalization.
- Imported archive schema/evidence validation.
- HTML/JSON/CSV/terminal encoders.

Fuzz assertions include no panic, bounded allocation/time under harness budgets, cancellation response, no filesystem/network/process effects, deterministic output, and no semantic promotion without the required evidence predicate.

Security regression cases are specified in [TEST_STRATEGY.md](TEST_STRATEGY.md).

## Residual risks

- A vulnerability in the Go runtime, TLS stack, ZIP/YAML/SQLite parser, browser, or selected dependencies may still compromise the analyst.
- A locally trusted TLS interception proxy can observe credentials/content.
- GitHub runner log text is not a stable API; an unknown future grammar may cause gaps before a parser update.
- Without opt-in raw retention, another examiner cannot reparse the original log bytes and future arbitrary literal IOCs may be unavailable for replay.
- SHA-256 manifests detect modification only when the expected manifest/hash is obtained through an independent trusted channel. A bundle and manifest changed together are not authenticated.
- Owner-only permissions do not replace full-disk encryption, backups, secure deletion, or organizational evidence-handling controls.
- Go cannot guarantee all copies of an in-memory token are zeroed.
- Static secret flow proves eligibility/reachability, not read/use/exfiltration. Masking can hide or fail to hide output.
- Self-hosted runners may persist state outside GitHub evidence; CIRewind records context but cannot inspect endpoints in v0.1.
- Local `./` Action bytes may have been modified in the runner workspace; API Git content alone cannot prove exact executed bytes.
- GitHub may delete or withhold source evidence, and no architecture can reconstruct facts that were neither retained nor independently archived.

## Security-response behavior

On a safety-limit, integrity, or parser failure, CIRewind should:

1. Cancel or isolate the affected work unit.
2. Finalize the source hash/byte count if safely possible.
3. Record a sanitized typed error evidence object and coverage gap.
4. Continue unrelated repositories/attempts unless store/process integrity is at risk.
5. Prevent `NO_MATCH_CONFIRMED` for affected coverage.
6. Exit partial or fatal according to the operation-severity policy.

It must not retry with safety checks disabled, dump the input to the terminal, upload a sample, or execute a helper to “inspect” the content.
