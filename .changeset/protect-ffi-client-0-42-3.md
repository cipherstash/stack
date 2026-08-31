---
'@cipherstash/protect-ffi': patch
---

Move the CipherStash client crates to `0.42.3` — `cipherstash-client`,
`cts-common`, `stack-auth` and `stack-profile`, which release in lockstep.

This is the release that raises the usage-denial taxonomy. `stack-auth` gained
typed `UsageLimitExceeded` / `OrgNotProvisioned` errors with a `help` and a
`url` on each, a shared classifier for a `402` from any credential-issuance
path, and a 60-second sticky cache so a refused organisation stops re-issuing
the same doomed request at its own request rate. Together they are what makes
`authCode` on a failure report a billing refusal as one, rather than as a
generic server error a retry loop will hammer.

It also carries a ZeroKMS change requiring `org_id` on every token. The client
side decodes claims without requiring it, so this is transparent here.
