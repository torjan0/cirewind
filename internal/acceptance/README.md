# Offline fixture acceptance harness

The tests in this package turn `testdata/fixture-inventory.json` into an
executable acceptance contract. They read every referenced log, workflow,
Action metadata file, and normalized metadata record, then exercise the real
log parser, workflow parser, historical resolver, archive fact validation,
incident analyzer, finding derivation, and exposure engine.

The adapter is deliberately narrow. The inventory supplies trusted structural
facts that do not safely come from hostile log filenames: repository ID,
run/attempt/job identity, entry role, expected Action declaration, API status,
and API conclusion. The adapter joins a lifecycle record to an exact setup
resolution only when both have the same execution identity and exact Action
declaration, and only when the setup identity is unambiguous. It never creates
a lifecycle record. Missing, skipped, malformed, or ambiguous input remains a
coverage gap or produces no runtime occurrence.

The following claims remain outside this offline harness:

- the hand-authored log grammar has not been validated against live retained
  GitHub logs for every runner release;
- the controlled tag move and rerun protocol has not been run live against
  GitHub.com;
- environment approvals, self-hosted runner details, and referenced-workflow
  metadata are normalized fixture records rather than live API observations;
- the affected leaf Action metadata is intentionally absent, so resolver tests
  retain `HISTORICAL_CONTENT_MISSING` while separately preserving exact runtime
  identity from the setup log;
- ZIP-entry-to-API-step correlation is covered by the live collector's focused
  mock tests, not duplicated by this fixture adapter.

Scenario I remains a non-started, gate-blocked job: it has no lifecycle or
download log and cannot produce `CONFIRMED_EXECUTED`,
`CONFIRMED_DOWNLOADED`, or `RUN_IN_WINDOW_MUTABLE_REF`.
