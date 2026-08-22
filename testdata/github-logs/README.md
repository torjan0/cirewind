# Synthetic workflow-log fixtures

These files are sanitized, hand-authored runner-log shapes for deterministic
offline tests. They are not asserted to be verbatim output from any particular
runner release. `testdata/fixture-inventory.json` supplies the trusted structural
role, execution identity, API status, expected Action declaration, and expected
observations for each entry. A test must never derive those facts from a ZIP entry
name or a hostile job/step display name.

There is deliberately no runtime log for scenario I because the environment gate
prevents the job from starting, and none for scenario N because the evidence is
modeled as expired. Their normalized states live in `normalized-metadata.json`.

All repositories, object IDs, run IDs, job IDs, names, and timestamps are
synthetic. Repeated hexadecimal characters are fixture sentinels, not real
incident indicators. Logs contain fixed markers and secret names only—never a
secret value.
