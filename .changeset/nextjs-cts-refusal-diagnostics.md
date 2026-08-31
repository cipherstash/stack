---
'@cipherstash/nextjs': minor
---

Report what the CipherStash token service actually said when it refuses a token.

`getCtsToken()` reported a non-2xx response as `Failed to fetch CTS token: ` and
nothing else. It read `statusText`, which is the empty string over HTTP/2 — so
the message ended at the colon — and it discarded the response body, taking any
refusal code with it. A billing refusal was indistinguishable from a bad token,
and the accompanying log said "contact support", which is the wrong advice for
an organisation that needs to upgrade a plan.

The failure now names the status and quotes what the service returned, and the
refusal code is surfaced on a new optional `authCode` field of
`GetCtsTokenResponse` — `USAGE_LIMIT_EXCEEDED` for an organisation over its
allowance, `ORG_NOT_PROVISIONED` for one not registered with the usage system.
Both are terminal: retrying cannot clear either. Unknown `402` codes are
declined so a future payment-required response does not inherit the wrong
classification.

The body is read as text exactly once and then parsed defensively, never with
`response.json()`. The two shapes are not the same shape: a `402` is JSON, while
every other failure from this endpoint is `text/plain` (a `401` is the bare
string `Authorization failed: InvalidToken`), and `.json()` on one of those
throws a `SyntaxError` that replaces the real failure with a parse error. A
response that is not a recognisable CipherStash refusal — a gateway or WAF
answering in front of the service — still reports its status and body rather
than being reported as a billing problem it is not.

This package does not depend on `@cipherstash/stack`, so it carries the code
rather than a copy of that package's remedy text — look the remedy up from
`authCode` if you need to render one.
