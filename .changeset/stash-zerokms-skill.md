---
'stash': minor
'@cipherstash/wizard': patch
---

Add a `stash-zerokms` agent skill and install it for every integration.

The keyset/client access model had no canonical home: several skills described
credentials and keysets in passing, and some of that wording contradicts how
ZeroKMS actually works. The new skill is the single source of truth for the
model, and other skills should point at it rather than restate it.

What it documents:

- The four-level key hierarchy (root key → per-keyset authority key →
  per-client client key → per-value data key) and why revoking one client is
  immediate and complete without re-encryption.
- The scoping rule: every encrypt, decrypt, and query is scoped to a keyset,
  and a client without a grant for that keyset fails **all three operations
  loudly** at the ZeroKMS round trip. In particular there is no failure mode
  where decrypt works but encrypted search silently returns nothing — search
  terms use a per-keyset index key that every granted client derives
  identically, so a zero-rows query with working decrypt is an index or
  predicate problem, never a key-identity problem.
- Clients and grants: creation binds a client to one keyset (the workspace
  default unless named), `grant`/`revoke` manage further access per
  (client, keyset) pair, and two different credentials interoperate fully as
  long as both reach the encrypting keyset — "identical credentials
  everywhere" was never the requirement.
- The workspace default keyset (`default`, reserved name, cannot be disabled
  or renamed) and multi-tenant isolation via `config.keyset` with one
  `Encryption()` client per tenant.
- The ZeroKMS API surface for automation (`/create-keyset`, `/grant-keyset`,
  `/revoke-keyset`, `/list-clients`, …) with required token scopes, the exact
  failure surfaces (404 no-grant, 403 disabled-keyset, 403 missing-scopes,
  per-value lock-context denials), and a diagnostic runbook that separates the
  client-level keyset gate from the value-level lock-context gate.

`stash-zerokms` joins the set every integration installs, alongside
`stash-encryption`, `stash-indexing`, `stash-deployment` and `stash-cli`.
