# Contributing

The laboratory is intentionally small and safety-sensitive. Changes must keep
the marker behavior fixed, public, harmless, and independently auditable.

Before proposing a change:

1. Do not add secrets, credentials, private data, production targets, external
   network requests, downloaded execution, environment enumeration, or
   destructive behavior.
2. Keep workflow permissions at `contents: read` and avoid third-party Actions.
3. Do not add `pull_request_target` or any trigger that executes untrusted fork
   content with elevated access.
4. Explain any change to the reviewed Git-object topology, fixture tags,
   expected findings, or reset protocol.
5. Run the repository's documented local validation without credentials or
   network access where applicable.

## Developer Certificate of Origin

This repository uses the [Developer Certificate of Origin 1.1](https://developercertificate.org/)
and does not require a contributor license agreement. Sign every commit with:

```text
Signed-off-by: Your Name <your-email@example.com>
```

Use `git commit -s` after configuring your own identity. The sign-off certifies
that you have the right to submit the contribution under the repository's
license. Do not use another person's identity.
