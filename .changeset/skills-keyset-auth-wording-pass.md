---
'stash': patch
---

Correct the keyset/credential model in five shipped skills to match the new
canonical sources.

`stash-edge`, `stash-cli`, `stash-postgres`, and `stash-supabase` all carried
a "credential-identity rule": EQL index terms deriving from the ZeroKMS
client key, so rows written under one credential would "decrypt correctly
but never match a query — silently". That model is wrong. Index terms come
from a per-**keyset** key, every client granted the keyset derives the same
terms, and a client that cannot reach the data's keyset fails loudly —
client construction, encrypt, decrypt, and query alike. The old diagnostic
("decrypt works but search misses → credential mismatch") could never fire
and misdirected agents away from the real causes of zero-row queries
(operand casts, predicate forms, missing indexes).

All five sites now state the keyset model and defer to `stash-zerokms`
(keysets/grants) and `stash-auth` (credentials/lock context) as canonical.
`stash-encryption` also drops its claim that identity-bound encryption on
the edge is "configured via `config.authStrategy`" (an auth strategy decides
who the client is; a lock context gates retrieval of a value's data key —
the edge entry simply lacks lock context, #797), and its auth, lock-context,
and keysets sections now point at the canonical skills.
