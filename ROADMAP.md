# CIRewind roadmap

This roadmap records outcome gates, not calendar promises. v0.1 is an
experimental, bounded release under
[`ADR 0011`](docs/adr/0011-experimental-v0-1-qualification-envelope.md).
The ten finding states, five provenance identifiers, and eight mandatory
invariants are stable product semantics; compatibility coverage can expand
without weakening them.

## v0.1 baseline

The initial public release includes:

- GitHub.com organization and explicit-repository collection with attempt- and
  job-specific identity, partial-coverage continuation, and bounded transport;
- traditional repository-Action log parsing, preparation versus execution,
  effective token permissions, runner context, and immutable-package fixture
  grammar;
- non-executing historical remote Action, composite, reusable-workflow, and
  local-declaration reconstruction, including annotated reusable-workflow tag
  peeling and explicit local-workspace gaps;
- conservative named-secret, reusable-secret, environment, OIDC capability, and
  optional resource relationships;
- strict declarative incident packs;
- compact incremental archives, deterministic offline replay, SQLite cases,
  evidence JSONL, self-contained reports, focused graphs, and SHA-256 manifests;
- hostile-input defenses, offline safety and browser audits, reproducible release
  packaging, target SPDX documents, and a credential-free demo; and
- a controlled explicit-repository A→B→A lab that proves historical runtime
  evidence survives restoration of the current mutable tag.

The measured relational envelope is 1,000 repositories, 100,000 runs, and
300,000 attempt/job/fact executions on the reference host. Replay rejects more
than 1,000,000 facts or 256 MiB of materialized compact data. A 3,000,000-
execution reference profile exceeded the two-hour budget and is unsupported.

## 0.1.x hardening

Patch releases prioritize correctness and security inside the published v0.1
envelope:

- parser regressions discovered from safely sanitized runner-log variants;
- evidence traceability, coverage reconciliation, crash recovery, deterministic
  output, and migration defects;
- dependency and toolchain security updates;
- supported-platform packaging or runtime defects; and
- documentation corrections that prevent overclaiming.

Patch work must not broaden a finding predicate silently. A new accepted grammar
requires positive, download-only, ambiguous, truncated, and hostile-lookalike
regressions.

## Next compatibility milestones

### Organization-scale collection

- Live-qualify recursive partitioning near the 1,000-result ceiling and preserve
  `DENSITY_CEILING` at an unsplittable saturated second.
- Measure request, retry, rate-limit, checkpoint-overlap, and 65-day watched-parent
  cost on representative organizations.
- Add paged/streaming analysis and report generation before claiming support
  beyond the current snapshot guards.
- Exercise partial organization visibility without treating hidden repositories
  as absent.

### Authentication and retention matrix

- Exercise classic PAT, fine-grained PAT, and GitHub App installation tokens with
  representative public, private, owner, and optional-enrichment profiles.
- Record live `403`, hidden-resource `404`, log-retention, redirect renewal, and
  primary/secondary rate behavior without retaining credentials.
- Continue capability-by-capability degradation instead of adding an all-or-
  nothing permission requirement.

### Runner and historical-definition coverage

- Qualify live immutable Action package version/source/digest records.
- Add additional runner versions, platforms, pre/post phases, localization, and
  safe custom-step bindings only when structural oracles exist.
- Expand exact caller workflow identity across event/rerun forms where GitHub
  exposes an authoritative source object.
- Preserve local Action runtime bytes proactively in archives if a read-only,
  non-executing source can prove them; otherwise retain the gap.

### Exposure and resource context

- Expand exact affected-step secret-flow and environment-gate joins.
- Add evidence-backed attempt/job attribution for artifacts, packages, releases,
  deployments, repository writes, and pull-request changes.
- Keep temporal correlation separate from causation.
- Add optional static AWS, Azure, GCP, Vault, or infrastructure-as-code trust
  adapters only after a separate trust model. `id-token: write` alone remains
  only `OIDC_MINTING_CAPABILITY`.

### Distribution and community incident content

- Broaden native platform qualification where maintainable test hosts exist.
- Evaluate signed incident-pack distribution and key rotation separately from
  executable releases.
- Add real incident packs only after every indicator and window has primary-
  source provenance, deterministic fixtures, conflict review, and independent
  maintainer review. Synthetic data remains the fallback when facts are
  unavailable.
- Add sharing/redaction profiles without weakening local evidence integrity.

## Explicit non-goals

The following are not on the near-term roadmap: active exploitation, secret-value
retrieval or rotation, live cloud compromise validation, runner EDR/eBPF,
generic CI vulnerability scanning, full SBOM or malware analysis, mandatory
GitHub Apps, Neo4j, Kubernetes, a hosted control plane, telemetry, runtime LLMs,
or claims of exfiltration and malicious causation without direct evidence.

GHES and other CI providers require separate versioned compatibility programs;
a configurable base URL is not sufficient.
