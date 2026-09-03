# Security policy

This repository contains a harmless synthetic laboratory, not malicious test
payloads. Please report security problems through GitHub's private vulnerability
reporting interface for this repository when it is available. If that interface
is unavailable, open a minimal issue asking for a private contact channel; do
not include exploit details, credentials, private repository names, raw logs, or
other sensitive material in the issue.

## Supported material

Security fixes apply to the current default branch and the most recently
published laboratory source package. Historical workflow runs and immutable
fixture objects remain evidence and are not silently rewritten.

## Laboratory constraints

Reports are especially useful when they identify a way the laboratory could:

- reveal or process a secret value;
- gain permissions beyond `contents: read`;
- execute untrusted or dynamically downloaded content;
- initiate an external network request from a workflow step;
- mutate a ref other than the explicitly designated disposable `v1` tag;
- confuse an annotated fixture-tag object with its peeled commit; or
- label a downloaded-only marker as executed.

Never include authentication tokens, cookies, signed URLs, private keys, secret
values, or private user data in a report.
