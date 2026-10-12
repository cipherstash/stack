# Risk model

Three separate axes. Do not collapse them into one number.

## Impact (per scenario, then overall)

What the consequence would be **if the scenario occurred**. Not how likely it is.

| Level | Meaning | Examples |
|---|---|---|
| low | Localised, readily recovered, no data or contract effect | A misleading log line; a CLI help typo; a dev-only script failing loudly |
| medium | Material degradation in a limited scope, recoverable | A CLI command fails for one configuration; a release job fails closed and needs a re-run; a type-level break that stops compilation for some consumers |
| high | Significant service, data, contract or security impact | Published package breaks consumers at runtime; migration fails or leaves a schema inconsistent; a release ships a broken binary; an authentication flow fails for all users of a path |
| critical | Systemic, irreversible, or severe integrity/security consequence | Plaintext reaches storage or a third party; data encrypted under the wrong key or context and not decryptable; cross-tenant access; ciphertext format change that old readers cannot read |

Overall `impact` = the worst **material** scenario. With no material scenario, `low`. Use `unknown` only when you could not understand the change well enough to say.

Impact is not raised by:
- a path matching a sensitive keyword (`auth`, `crypto`) without a mechanism;
- size alone;
- the number of scenarios.

## Verification confidence

How strongly the available evidence shows that the scenarios you found are prevented or caught.

| Level | Meaning |
|---|---|
| high | Tests exercise the changed behaviour including the failure path, and you saw them run (CI results supplied, or you ran them) |
| medium | Relevant tests exist and target the changed behaviour, but their results were not seen, or a failure path is untested |
| low | Little or no test targets the changed behaviour; or tests cover only the happy path of a risky change |
| unknown | You could not determine what is tested |

A test file existing or changing is not evidence it ran or passed.

## Release readiness

| Verdict | When |
|---|---|
| ready_for_review | No material scenario beyond normal review |
| focused_review_required | Material scenarios exist and are covered or low-impact, but a reviewer should look at named places |
| changes_or_verification_required | A material scenario (usually high or critical) lacks verification or mitigation |
| insufficient_evidence | Missing inputs or understanding prevent a defensible judgement |

A rough guide, not a formula:

- impact low → `ready_for_review`
- impact medium → `ready_for_review` or `focused_review_required`
- impact high/critical with confidence high → `focused_review_required`
- impact high/critical with confidence medium/low/unknown → `changes_or_verification_required`
- cannot tell → `insufficient_evidence`

Advisory only. Nothing here is a merge gate.
