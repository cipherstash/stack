---
name: stash-zerokms
description: The ZeroKMS key model — keysets, clients, client keys, and the grant/revoke lifecycle. Covers the four-level key hierarchy, why every encrypt/decrypt/query is scoped to a keyset, the exact failure surface when a client lacks keyset access (all operations fail loudly — there is no silent partial failure), the workspace default keyset, multi-tenant isolation via `config.keyset`, and the ZeroKMS API for creating, granting, and revoking keyset access. Use when a decrypt or query fails with a ZeroKMS error, when planning multi-tenant key isolation, when deciding which credentials a backfill job or edge function should use, when rotating or revoking a compromised credential, or whenever another skill's guidance touches "credentials", "keysets", or "who can decrypt what" — this skill is the canonical source for that model.
---

# ZeroKMS: keysets, clients, and key management

ZeroKMS is the key service behind every CipherStash Stack operation. This
skill is the canonical description of its access model. Other skills
(`stash-edge`, `stash-deployment`, `stash-cli`, `stash-postgres`,
`stash-supabase`) touch credentials and keysets in passing; where their
wording and this skill disagree, **this skill wins**.

## The model in one paragraph

Every value is encrypted **under a keyset**. Encrypt, decrypt, and query are
all scoped to that keyset — there is no operation that bypasses it. A
**client** (an application credential with its own client key) is **granted
access** to one or more keysets. If the client performing an operation has no
grant for the keyset the data was encrypted under, **every operation fails:
encrypt, decrypt, and query alike** — loudly, at the ZeroKMS round trip, not
silently at the data layer.

Two corollaries that follow directly, and that agents get wrong most often:

1. **"Same credentials everywhere" is stronger than what's required.** Two
   different clients — each with its own client key — interoperate completely
   as long as both are granted the keyset. A backfill job and the deployed
   app may use different access keys; what must match is the *keyset* the
   operations run under, not the credential strings. Be precise about how
   that keyset is chosen: when an operation names one (`config.keyset`),
   it's that keyset; when it doesn't, ZeroKMS uses **that client's default
   keyset** — the keyset the client was bound to when it was created. So two
   clients that both omit `config.keyset` only interoperate if their
   *default keysets* are the same keyset.
2. **There is no failure mode where decrypt works but search silently
   misses.** Search terms are produced with a per-*keyset* index key that the
   client loads from ZeroKMS at initialization — a client without keyset
   access cannot even construct the cipher, and every client with access
   derives the *same* index key, so terms written by one client match terms
   written by another. If decrypt succeeds but an encrypted query returns
   zero rows, the problem is the index or the predicate, never key identity —
   go to `stash-indexing` (missing/unused index) or `stash-postgres` (wrong
   operand cast / predicate form).

## The key hierarchy

Four levels, each narrowing scope; no single component holds enough material
to derive a data key alone.

| Level | Key | Held by | Purpose |
|---|---|---|---|
| 1 | Root key | HSM / hardware root of trust | Protects all downstream key material. Never exported. |
| 2 | Authority key (per keyset) | ZeroKMS | Derives key seeds for a keyset. Materialized per client grant, so every granted client resolves the same keyspace. |
| 3 | Client key (per client / device) | Application runtime only | Never transmitted to ZeroKMS. Multiple clients can share a keyset, each with its own key. |
| 4 | Data key (per value) | Derived in-process, ephemeral | Derived from client key + key seed during encrypt/decrypt. Never stored or transmitted. |

ZeroKMS uses proxy symmetric re-encryption: it sends key *seeds*, never
usable keys, and the client combines a seed with its own client key to derive
each per-value data key. Because the data key requires both halves:

- **ZeroKMS never possesses a usable data key** (zero-knowledge).
- **Revoking one client is instant and complete.** ZeroKMS stops issuing
  seeds to that client; its client key cannot derive data keys from seeds
  issued to other clients. No re-encryption, no effect on other clients.

## Keysets

A keyset is the isolation unit: data encrypted under one keyset can never be
decrypted or queried with another keyset's keys. Every operation runs under
the data's own keyset, and only clients granted that keyset can perform it.
Keysets belong to a workspace.

- **Naming**: 1–64 characters, ASCII letters/digits plus `_`, `-`, `/`. The
  name `default` is reserved (case-insensitively) for the workspace default
  keyset. Descriptions are 1–256 characters.
- **The workspace default keyset**: every workspace has exactly one, named
  `default`, created automatically the first time it's needed. It cannot be
  renamed or disabled. A client created without naming a keyset is bound to
  it.
- **Every client also has its own default keyset**: the keyset it was bound
  to at creation (`default` unless another was named). An operation that
  doesn't specify a keyset resolves to **the client's default keyset** — not
  automatically the workspace's. The two coincide when the client was
  created without naming a keyset — as with the profile credentials in a
  dev environment — which is why single-tenant apps that never mention
  keysets still work. But a client created against `tenant-a` defaults to
  `tenant-a`, and a client with no default at all (possible via the API)
  gets `404 — "Client (…) has no default keyset"` on any keyset-less
  operation.
- **Disabled keysets**: a keyset (other than the default) can be disabled as
  a reversible kill-switch. While disabled, *every* operation under it fails
  for *every* client with `403 — "Keyset disabled: request could not be
  processed because the keyset has been disabled"`. Re-enabling restores
  access; no data is touched.

## Clients and grants

A **client** is a credential identity in ZeroKMS: it has an id, a client key
(generated at creation, returned once, held only by the application), and a
set of keyset grants.

- Creating a client binds it to one keyset immediately (the default keyset
  unless another is named at creation).
- **Grant** adds access to a further keyset. **Revoke** removes one grant.
  **Deleting a client** removes the client and all of its grants.
- Grants are per *(client, keyset)* pair. There is no wildcard and no
  transitive access.

Manage all of this in the
[dashboard](https://dashboard.cipherstash.com/workspaces/_/keysets) (the `_`
resolves to your selected workspace). The underlying ZeroKMS API, for
automation:

| Endpoint (POST) | Effect | Required scope |
|---|---|---|
| `/create-keyset` | Create a keyset (optionally with a client in one call) | `keyset:create` (+ `client:create` if bundling a client) |
| `/list-keysets` | List the workspace's keysets | `keyset:list` |
| `/modify-keyset`, `/enable-keyset`, `/disable-keyset` | Rename/describe, re-enable, kill-switch | `keyset:modify` / `keyset:enable` / `keyset:disable` |
| `/create-client` | Create a client bound to a keyset (default if unnamed) | `client:create` (+ `keyset:grant` when naming a keyset) |
| `/list-clients` | List clients and their keyset grants (filterable by keyset) | `client:list` |
| `/grant-keyset` | Grant an existing client access to a keyset (by name or UUID) | `keyset:grant` |
| `/revoke-keyset` | Remove one client's access to one keyset | `keyset:revoke` |
| `/delete-client` | Delete a client and all its grants | `client:delete` |

`/list-clients` is the check an agent can run to answer "does this client
have a grant for that keyset?" — it returns each client with the keyset ids
it can reach.

Scope strings in existing tokens may use the legacy `dataset:` prefix
(`dataset:create`, `dataset:grant`, …) — it is the same permission family as
`keyset:`; ZeroKMS accepts both spellings.

## Keysets in the Stack

```typescript
const client = await Encryption({
  schemas: [users],
  config: {
    keyset: { name: "tenant-a" }, // or { id: "<uuid>" }
  },
})
```

- Omit `config.keyset` → **the client's default keyset** (the keyset the
  ZeroKMS client behind your `CS_CLIENT_*` credentials was created against —
  the workspace `default` keyset if using the profile credentials in a dev
  environment).
- **Encrypt and query always use the bound keyset.** A client is bound to
  one keyset for its lifetime, and there is no per-operation keyset option
  in `@cipherstash/stack` — the underlying Rust SDK accepts a per-call
  keyset on decrypt, but the FFI does not expose it. Multi-tenant
  applications create one `Encryption()` client per tenant.
- **Decrypt is per-payload automatically.** Every encrypted payload embeds
  the id of the keyset it was encrypted under, and decryption routes key
  retrieval to that keyset — so one client can decrypt rows from several
  keysets, provided it holds a grant for each. No option needed; without
  the grant the decrypt fails as usual. (This is why cross-tenant *reads*
  can be centralized in one suitably-granted client while writes and
  queries still require the per-tenant client.)
- Keysets are orthogonal to `authStrategy` and lock context: a keyset
  isolates a whole keyspace (coarse, fixed per client); lock context binds an
  individual value to an identity claim (fine-grained, per operation). They
  compose.
- `stash login` binds your device to the workspace's default keyset, which is
  why CLI operations (`stash encrypt backfill`, dev-time tooling) work
  without any keyset configuration.

## Two gates, two very different failures

Keyset access and lock context are **independent gates**, and their failures
look different. Do not diagnose one as the other.

**Gate 1 — keyset access (client-level, wholesale).** Checked first, on
every request. No grant for the requested keyset means ZeroKMS cannot even
locate key material for the client:

| Cause | ZeroKMS response | What the application sees |
|---|---|---|
| Client has no grant for the keyset (or keyset name/id doesn't exist in this workspace) | `404 — "Not Found: no record found with id=…"` | `Encryption()` init fails (the per-keyset index key cannot be loaded); if a payload names an unreachable keyset, encrypt/decrypt return `{ failure }` (`EncryptionError` / `DecryptionError`) |
| Keyset disabled | `403 — "Keyset disabled: …"` | Same surface — init or operation failure, for every client of that keyset |
| Token missing scopes | `403 — "Not permitted"` | Operation failure; fix the credential's scopes, not the grants |

**Gate 2 — lock context / decryption policy (value-level, per identity).**
Only reached when gate 1 passes. A caller whose identity claims don't satisfy
a value's lock context is denied **that value** (`403`, surfaced as a
`{ failure }` on decrypt); encrypting and other values are unaffected, and
every denial is recorded in the access log. See the lock-context sections of
`stash-encryption` for usage.

The practical tell: gate-1 failures are *total* (the client can do nothing
under that keyset — encrypt, decrypt, and query all fail), gate-2 failures
are *selective* (specific values, specific callers).

## Diagnostic runbook

Encrypted operations failing with a ZeroKMS error? Check in this order —
each step's failure explains everything after it:

1. **Credentials present and pointing at the right workspace?** The four
   `CS_CLIENT_*` / `CS_WORKSPACE_CRN` variables (see `stash-edge` for the
   list). A keyset name resolves *within a workspace* — the same name in
   another workspace is a different keyset.
2. **Does the keyset exist there?** Dashboard, or `/list-keysets`. Typos in
   `config.keyset.name` surface as the 404 above, not as a helpful "no such
   keyset".
3. **Does this client have a grant?** `/list-clients` filtered by the
   keyset, or the dashboard's keyset page. If no keyset is being specified,
   check which keyset each client *defaults* to — a writer and a reader that
   both omit `config.keyset` can still be on different keysets if their
   clients were created against different ones.
4. **Is the keyset disabled?** The 403 message says so explicitly.
5. **Only decrypt of specific values failing, for specific callers?**
   That's lock context (gate 2), not keyset access — check that the decrypt
   call carries the same lock context the value was encrypted with.
6. **Decrypt fine but queries return zero rows?** Not a key problem at all.
   `stash-indexing` (is the extractor index there and used?) and
   `stash-postgres` (is the operand cast/predicate form right?).

## Operational rules of thumb

- **Environments should not share keysets.** Give production its own keyset
  (or workspace); a dev credential then can't decrypt production rows even
  if it leaks. `stash-deployment` covers where each environment's
  credentials come from.
- **Backfills and one-off jobs**: the job's client must reach the same
  keyset the deployed application uses. Same explicit `config.keyset` is the
  safe form; if both sides omit it, each resolves to *its own client's
  default keyset*, so verify the two clients were created against the same
  keyset — same workspace is necessary but not sufficient. The credential
  string itself may differ.
- **Suspected credential compromise**: revoke the client (or delete it).
  Revocation is immediate — ZeroKMS stops issuing seeds, and the revoked
  client key is useless against seeds issued to others. No re-encryption is
  needed and no other client is affected.
- **Retiring a keyset**: disable first (reversible, proves nothing still
  uses it), then deal with the data. There is no cross-keyset decrypt — data
  moves between keysets only by decrypting under the old and re-encrypting
  under the new.
