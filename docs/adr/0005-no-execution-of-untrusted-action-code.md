# ADR 0005: Do not execute untrusted Action code

## Status

Accepted and a security invariant.

## Date

2026-08-20

## Context

CIRewind investigates suspected supply-chain compromises. Workflow YAML, Action metadata, source archives, JavaScript, Dockerfiles, composite steps, local Actions, log text, and incident packs are attacker-controlled inputs. Executing, importing, building, or checking out an affected Action would turn an evidence collector into an attack surface and could alter the analyst system or evidence.

Historical reconstruction needs declarations and metadata, not Action execution. GitHub content APIs and retained runtime observations can provide bytes and identities without invoking the downloaded code.

## Decision

- CIRewind is a parser and evidence-reconstruction system. It must not execute, source, import, compile, build, install, or run fetched workflow or Action content.
- Retrieve historical workflow files and `action.yml`/`action.yaml` at evidenced commits through configured GitHub APIs. Parse only bounded data formats and supported syntax.
- Do not perform a repository checkout merely to resolve content when API-based exact-SHA retrieval is sufficient. Do not invoke Docker, a shell, a JavaScript runtime, package managers, Action entrypoints, or Action-provided tools.
- Recognize that an Action or wrapper declares an internal tool download only as static reachability unless retained runtime evidence independently proves more. Never follow a URL or command found in workflow, Action, log, or pack content.
- Network requests are generated only by CIRewind's reviewed collectors against operator-configured GitHub.com sources and validated GitHub-returned download redirects. Incident-pack content cannot initiate outbound requests.
- Bound archive extraction, YAML parsing, recursion, aliases, sizes, file counts, paths, links, and concurrency; treat parser output as untrusted through reporting.

## Consequences

- Analysis does not reproduce attacker behavior or expose the analyst host to the investigated payload by design.
- Dynamic behavior, generated dependencies, arbitrary shell semantics, and tools downloaded internally may remain `POTENTIAL_TRANSITIVE` or `UNKNOWN_EVIDENCE_GAP` unless GitHub evidence resolves them.
- The resolver can be deterministic and fixture-tested offline, but cannot claim general behavioral equivalence with the Actions runner.
- Some convenience techniques used by build tools, such as local checkout and metadata execution, are unavailable.

## Revisit criteria

Do not relax this invariant inside CIRewind. Any future dynamic-analysis capability must be a separately named and separately threat-modeled system with an isolation contract, no shared authentication, and no ability to upgrade CIRewind findings without imported, hash-addressed evidence.
