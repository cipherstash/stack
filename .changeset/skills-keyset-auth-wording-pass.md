---
'stash': patch
---

Correct the keyset/credential model in five shipped skills to match the new
canonical sources.

`stash-edge`, `stash-cli`, `stash-postgres`, and `stash-supabase` all carried
a "credential-identity rule": EQL index terms deriving from the ZeroKMS
client key, so rows written under one credential would "decrypt correctly
but never match a query — silently". That model is wrong. Index terms come
from a per-**keyset** key, so every client **bound** to the same keyset
derives the same terms — credential strings never matter. The keyset can
still miss silently, though: encrypt and query use the client's bound
keyset while decrypt follows each payload's keyset subject to grants, so a
reader granted the writer's keyset but bound to a different one decrypts
fine while its searches return zero rows. The old *credential* diagnostic
could never fire; the *keyset-binding* check replaces it, alongside the
other real causes of zero-row queries (operand casts, predicate forms,
missing indexes).

All five sites now state the keyset model and defer to `stash-zerokms`
(keysets/grants) and `stash-auth` (credentials/lock context) as canonical.
`stash-deployment`'s backfill-keyset guidance gets the same pass: bound
keyset (not a mere grant) is what routes the backfill's writes, the failure
table and troubleshooting rows distinguish the no-grant case (decrypt fails)
from the granted-but-differently-bound case (decrypt works, search silently
misses), and `stash-cli`'s backfill precondition now names the credential
*resolution* order — `CS_*` variables when present, else the local
`~/.cipherstash` profile via native auto auth.
`stash-encryption` also drops its claim that identity-bound encryption on
the edge is "configured via `config.authStrategy`" (an auth strategy decides
who the client is; a lock context gates retrieval of a value's data key —
the edge entry simply lacks lock context, #797), and its auth, lock-context,
and keysets sections now point at the canonical skills.
