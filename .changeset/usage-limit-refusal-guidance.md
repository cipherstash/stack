---
'@cipherstash/stack': minor
'stash': minor
---

Surface CipherStash token-service refusals as typed diagnostics.

`@cipherstash/stack` operation and initialization failures now carry
`authCode`, `help`, and `url` from stack-auth. The message remains stack-auth's
original diagnostic message; Stack does not copy or rewrite its instructions.
Callers can branch on `USAGE_LIMIT_EXCEEDED` or `ORG_NOT_PROVISIONED`, render
`help`, and link to `url`.

`LockContext.identify()` also recognizes those two codes on a genuine CTS
`402`, while declining malformed or unknown responses. Legacy valid JSON
responses without `cs_code` retain the historical usage-limit classification.

`stash auth login` and `stash env` now consume `@cipherstash/auth` 0.44.0's
typed failures. They print the upstream diagnostic guidance, preserve its URL,
avoid suggesting another login for terminal account refusals, and expose
terminal codes on the JSON stream. The JSON error envelope gains an optional
`hint` for the upstream guidance.
