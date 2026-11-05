# Domain risk prompts

Investigation prompts for domains where a correct-looking change can have outsized consequences. A match is a reason to look, not a reason to raise impact. Raise impact only when you can describe the mechanism.

## Encryption and key management
- **Ciphertext and serialization compatibility.** Does the change alter what is written (payload fields, encoding, versions, ordering of fields that are hashed or MAC'd)? Can data written before the change still be read after it, and data written after be read by the previous release still installed elsewhere?
- **Key identity and lifecycle.** Which key, keyset, or context encrypts each value? Can the change cause a value to be encrypted under a different key or context than the one used to decrypt it? Is key material cached, and keyed by the right identity?
- **Authorization enforcement.** Is the identity or context that must bind an operation still passed on every path, including bulk, batch, and error paths?
- **Security invariants.** What must always hold (e.g. every sensitive value is encrypted before it leaves the process; query terms match what storage-side encryption produces)? Does every changed path still uphold it?
- **Cross-version compatibility.** Are a client library and a storage-side component (SQL functions, a service) versioned together? What happens when only one side upgrades?
- **Accidental plaintext exposure.** Can plaintext reach logs, error messages, telemetry, query parameters, a third-party API, or an unencrypted column?

## Tenant isolation
- Tenant, workspace or account identity: where does it come from, and is it propagated through every call?
- Authorization scope: does a token, cache entry, or client instance get shared between principals or tenants?
- Cross-tenant data access: can a query, a key lookup, or a cache return another tenant's data?
- Cross-account storage permissions: buckets, registries, package scopes, container images.

## Distributed systems
- Multi-region consistency: reads after writes in another region; replicated caches.
- Retry semantics: what is repeated, what is skipped on retry, and is it safe to repeat?
- At-least-once delivery: duplicates must be harmless.
- Event ordering: what assumes order, and what guarantees it?
- Idempotency keys and "already exists" handling.
- Split-brain and partial failure: what state is left if the process dies midway?

## Persistence and migrations
- PostgreSQL schema compatibility: types, domains, constraints, extensions, functions other objects depend on.
- Old and new application versions running concurrently against one schema.
- Backfill and migration correctness on populated tables; locks and long-running statements.
- Rollback safety: can the schema change be reversed without losing data written in between?
- Transaction semantics: what is atomic, what is not, and what a partial run leaves behind.
- Generated SQL: what produces it, and what does other code assume about it?

## Event processing
- Producer/consumer compatibility and schema evolution.
- Missing, duplicated and delayed events.
- Delivery failure and replay semantics.

## Build, release and distribution
- Artefacts that must be released in lockstep (a library and the SQL or binary it pairs with).
- Native binaries per platform.
- Registry behaviour: publishes are effectively permanent.
- Release automation that publishes some artefacts and then fails.
- Content shipped to customers that is not code (templates, docs, agent instructions) and so is not type-checked.
