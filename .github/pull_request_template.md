## Purpose

Describe the narrowly scoped problem and the result of this change.

## Evidence semantics

Describe any finding state, provenance level, evidence chain, coverage result, or credential/resource conclusion affected. Explain the source evidence and the behavior when it is missing, denied, malformed, or contradictory.

## Validation

List the exact commands run and the harmless fixtures added or changed.

## Checklist

- [ ] The change stays within CIRewind's documented product boundaries.
- [ ] Downloaded Actions are not treated as executed without step-start or stronger evidence.
- [ ] Secret existence is not treated as step access.
- [ ] `id-token: write` is not treated as cloud-role assumption.
- [ ] Missing retained evidence does not produce a clean bill of health.
- [ ] Historical configuration is not replaced with present-day workflow state.
- [ ] Downstream temporal correlation is not described as attacker causation.
- [ ] New hostile-input boundaries have limits, malformed-input tests, and injection or fuzz coverage as appropriate.
- [ ] Tests are deterministic and require no credentials or network access by default.
- [ ] No token, secret value, private log, private repository content, or production case data is included.
- [ ] Real incident indicators and windows have primary-source citations; otherwise fixtures are explicitly synthetic.
- [ ] User-facing behavior and capability status are documented accurately.
- [ ] `go test ./...`, `go vet ./...`, and relevant race tests pass.
- [ ] Every commit includes a DCO sign-off (`git commit -s`).

## Live validation

State exactly what, if anything, was validated against controlled GitHub.com resources. Write `Not live-validated` when only mocks and fixtures were used.
