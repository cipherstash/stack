---
name: stash-auth
description: How a CipherStash client authenticates — the canonical skill for credentials, auth strategies, and lock context. Covers the service-token model (every request to a CipherStash service carries a CTS-minted token; strategies exist to obtain one), the three separable concerns people conflate (client credentials, end-user identity, key binding), the `@cipherstash/auth` strategies (`AutoStrategy`, `AccessKeyStrategy`, `OidcFederationStrategy`, `DeviceSessionStrategy`) and the Result-unwrap trap on `create()`, the four `CS_*` variables and `stash env`, credential discovery vs explicit config on the native and WASM entries, client lifetime with user-scoped strategies, `.withLockContext` and what is deprecated around it, and CTS failure codes. Use when an operation fails with 401/NOT_AUTHENTICATED/WORKSPACE_MISMATCH, when choosing between an access key and OIDC federation, when wiring per-user identity-bound encryption, when minting deployment credentials, or whenever another skill mentions "credentials" or `config.authStrategy` — this skill is the canonical source for that model.
---

# Authenticating to CipherStash

Every request a Stack client makes to a CipherStash service authenticates
with a **CipherStash service token**: a short-lived signed JWT minted by
**CTS** (the CipherStash token service). That is the only credential ZeroKMS
accepts. Access keys and identity-provider JWTs are never sent to ZeroKMS —
they are *exchanged* at CTS for a service token, and everything in this
skill is machinery for doing that exchange correctly and automatically.

This skill is canonical for authentication. Where other skills
(`stash-edge`, `stash-encryption`, `stash-cli`, `stash-deployment`) touch
credentials in passing and disagree with this one, this one wins. For what a
token *authorizes* — keysets, clients, grants — see `stash-zerokms`:
authentication and keyset access are separate gates, and a perfectly valid
token still fails operations on a keyset its client was never granted.

## The three concerns (do not merge them)

| Concern | What it decides | Where it's configured |
|---|---|---|
| **Client credentials** | Which workspace (`CS_WORKSPACE_CRN`) and — more granular than the workspace — which ZeroKMS *client* is acting (`CS_CLIENT_ID`, `CS_CLIENT_KEY`) and the access key that authenticates it (`CS_CLIENT_ACCESS_KEY`) | `CS_*` variables / dev profile / `config.accessKey` |
| **End-user identity** | Authenticating the client *as* a specific user | `config.authStrategy: OidcFederationStrategy` |
| **Key binding (lock context)** | Who can *retrieve a value's data key* — binds key access to a claim | `.withLockContext({ identityClaim })` per operation |

Note the granularity in the first row: only the CRN is about the
*workspace*. The other three variables identify a specific **client** within
it — its id, its key material, and its access key — so "the credentials"
always means a particular client's identity, not a workspace-wide secret
(see `stash-zerokms` for what a client is and what it can reach).

The classic conflation is between the last two: **an auth strategy decides
who the client is; a lock context decides who can get a value's data key
back.** They are orthogonal. Authenticating as a user via
`OidcFederationStrategy` does not by itself bind any value to that user —
without `.withLockContext()`, any client with the right keyset access can
retrieve the value's key. Lock context *requires* `OidcFederationStrategy`
on the Stack surface (there must be a user claim in the service token to
bind to), but not the other way around.

## The token exchange (CTS)

CTS's authorize endpoint exchanges exactly one of two credential kinds for a
service token:

- **A CipherStash access key** (`CSAK…`) — machine identity, for
  services/CI.
- **An OIDC JWT** from an identity provider configured for the workspace
  (Clerk, Supabase, Auth0, or Okta — or CipherStash's own login) — end-user
  identity. CTS verifies it against the provider's JWKS and checks workspace
  membership.

The minted token carries: the subject (`CS|<user-id>` or `CS|CSAK<key-id>`),
the workspace, scopes derived from the credential's role (member or admin —
see `stash-zerokms` for what the scopes gate), and a `services` claim with
the URL of the workspace's regional **ZeroKMS endpoint**. That last part is
the region story: the workspace CRN (`crn:<region>.<provider>:<workspace-id>`)
names the region, CTS resolves the endpoint for it, and the client reads it
from the token. Endpoints are never hand-configured — the `CS_*_HOST`
override variables are debug-only and must not appear in CI, examples, or
docs.

CipherStash runs in a variety of regions across the world, and the set is
**subject to change** — `stash auth regions` (add `--json` for
machine-readable output) lists the current ones; see `stash-cli`. As of this
writing:

| Region | Location |
|---|---|
| `us-east-1` | Virginia, USA |
| `us-east-2` | Ohio, USA |
| `us-west-1` | California, USA |
| `us-west-2` | Oregon, USA |
| `eu-west-1` | Dublin, Ireland |
| `eu-central-1` | Frankfurt, Germany |
| `ap-southeast-2` | Sydney, Australia |

A workspace lives in one region, chosen at creation (the `stash auth login`
region picker / `--region`); the CRN records it thereafter.

CTS failures are deliberate and descriptive: `401` with a reason ("Principal
X is not a member of workspace Y", "No OIDC provider found for issuer: …",
"Access key was malformed: …"), and `402` ("Insufficient balance…") when the
organisation is over its usage limit. A 402 is a billing problem, not a
credentials problem — don't rotate keys over it.

## The strategies

From `@cipherstash/auth`, re-exported by `@cipherstash/stack` so no separate
install is needed. Every strategy has one job — `getToken()` — and handles
caching and refresh internally; you never store or refresh a service token
yourself.

| Strategy | Use for | Credential source |
|---|---|---|
| `AutoStrategy` (the default when `config.authStrategy` is unset) | Most apps | `CS_CLIENT_ACCESS_KEY` **and** `CS_WORKSPACE_CRN` env vars, else the dev profile (`~/.cipherstash/auth.json`), else fails `NOT_AUTHENTICATED` |
| `AccessKeyStrategy` | Services, CI, backfill jobs | Explicit workspace CRN + access key |
| `OidcFederationStrategy` | Per-user (identity-bound) encryption | Your IdP's JWT, re-fetched via a callback on every federation |
| `DeviceSessionStrategy` | CLI-adjacent tooling | The device-code session `stash auth login` created |

`auto`'s access-key arm needs **both** variables, and the two
missing-variable cases behave differently: with `CS_CLIENT_ACCESS_KEY`
unset, detection falls back to the dev profile; with the access key set but
`CS_WORKSPACE_CRN` missing, it fails `MISSING_WORKSPACE_CRN` rather than
silently falling back — a half-configured environment errors instead of
quietly authenticating as whatever profile is on the machine.

```typescript
import { Encryption, AccessKeyStrategy } from "@cipherstash/stack"

// create() returns a Result — UNWRAP IT (see below).
const strategy = AccessKeyStrategy.create(workspaceCrn, accessKey)
if (strategy.failure) {
  throw new Error(`auth: ${strategy.failure.type}: ${strategy.failure.error.message}`)
}

const client = await Encryption({
  schemas: [users],
  config: { authStrategy: strategy.data },
})
```

For end users, `OidcFederationStrategy.create(workspaceCrn, getJwt)` — the
`getJwt` callback is invoked on *every* federation (initial and every
re-federation after the CTS token expires) and must return the **current**
IdP JWT, not a captured stale one. On the WASM/edge path,
`createWithStore(workspaceCrn, getJwt, loadToken, saveToken)` persists the
federated token (e.g. in an HTTP-only cookie) so it survives across
requests.

Federation only works if the JWT's **issuer is registered with the
workspace**. Add your OIDC provider — Clerk, Supabase, Auth0, or Okta — in
the [dashboard](https://dashboard.cipherstash.com) under the workspace's
OIDC providers; the registered issuer URL must match the JWT's `iss` claim
exactly. An unregistered issuer fails the exchange with `No OIDC provider
found for issuer: …`. A workspace can register multiple OIDC providers,
subject to billing conditions / plan level.

### The Result trap

As of `@cipherstash/auth` 0.41, **`create()` returns a
`Result<Strategy, AuthFailure>`** (`{ data }` or `{ failure }`), and so does
every `getToken()`. `config.authStrategy` expects the strategy itself — the
thing with `getToken()` on it. Passing the un-unwrapped `Result` is the
single most common auth mistake: it type-errors in TS, but plain-JS callers
find out only later, as an opaque failure when the client tries to call
`getToken` on an object that doesn't have one. Always: check `.failure`,
pass `.data`.

`AuthFailure` is discriminated on `type`. The ones worth recognising:

| `failure.type` | Meaning / fix |
|---|---|
| `NOT_AUTHENTICATED` | No credentials found — set the `CS_*` variables, or run `npx stash auth login` for a dev profile |
| `MISSING_WORKSPACE_CRN` | `CS_CLIENT_ACCESS_KEY` is set but `CS_WORKSPACE_CRN` isn't — the access-key path needs both |
| `WORKSPACE_MISMATCH` (`expected` / `actual`) | The access key belongs to a different workspace than the CRN — you've mixed environments' credentials |
| `INVALID_ACCESS_KEY` / `INVALID_CRN` | Malformed values — check for truncation/quoting in the secret store |
| `EXPIRED_TOKEN` / `INVALID_GRANT` | The underlying session/JWT expired — for `OidcFederationStrategy`, check that `getJwt` returns a *fresh* token |
| `ACCESS_DENIED` | CTS refused the exchange — membership, provider config, or (as an HTTP 402) billing |

Every failure also carries the live `error` and, when available, `help` and
`url` fields — surface them; don't swallow them into a generic message.

## Credentials: discovery vs explicit

**Native entry (`@cipherstash/stack`)**: the default `auto` strategy
discovers credentials — the `CS_*` environment variables first, then the
local dev profile created by `npx stash auth login`. During local
development you typically set nothing at all.

**WASM entry (`@cipherstash/stack/wasm-inline`)**: no environment
discovery, no profile, no device login — Workers and edge runtimes have
none of those. All four values are passed explicitly in config, or you
construct a strategy yourself and pass `config.authStrategy` plus
`clientId`/`clientKey`. On this entry, `config.authStrategy` and
`config.accessKey` are **mutually exclusive — the client throws** if both
are set. (On the native entry an explicit strategy simply takes precedence
over `config.accessKey`.) See `stash-edge` for the full edge story.

On both entries, `clientKey` is always required for encryption regardless of
strategy: the service token authenticates *requests*; the client key is
cryptographic *key material* (level 3 of the hierarchy — `stash-zerokms`)
and is never sent to any service. Auth strategies do not replace it.

### The four `CS_*` variables

| Variable | What it is | Secret? |
|---|---|---|
| `CS_WORKSPACE_CRN` | The workspace Cloud Resource Name — carries the region | No |
| `CS_CLIENT_ID` | The ZeroKMS client's identifier | No |
| `CS_CLIENT_KEY` | The client's key material (hex) — combined with key seeds to derive data keys | **Yes** |
| `CS_CLIENT_ACCESS_KEY` | The access key exchanged at CTS for service tokens | **Yes** |

Mint a deployment set with **`stash env --name <app-env>`**: it creates a
fresh ZeroKMS client and an access key from your logged-in session and
prints exactly this dotenv block on stdout (progress goes to stderr, so
`stash env --name x > prod.env` and pipes into secret stores are safe). The
access key is minted with the member role — the CLI never mints admin keys —
and is shown exactly once. Give each environment its own minted set; see
`stash-deployment` for where each environment's credentials live.

## Client lifetime (user-scoped strategies)

A strategy that authenticates *a user* makes the client user-scoped:
construct **one `Encryption()` client per request/user**, not a module-level
singleton. A shared client whose `OidcFederationStrategy` closed over one
request's user keeps authenticating — and, with lock context, encrypting —
as whoever arrived first. That is a cross-tenant data hazard, not a
performance nuance. `AccessKeyStrategy` and `auto` are service-scoped and
safe to share for the process lifetime.

## Lock context

Layered on top of `OidcFederationStrategy`, per operation:

```typescript
const result = await client
  .encrypt(email, { table: users, column: users.email })
  .withLockContext({ identityClaim: ["sub"] })
```

- The mechanism is **key-access binding**, and it lives in ZeroKMS, not in
  the ciphertext math: when the data key is generated or retrieved, the
  named claim (typically `sub`) is read from the caller's **service token**
  and bound to that key. Retrieving the key later — which is what decrypt
  does — requires presenting a service token carrying **exactly the same
  claim value**. Any other caller is refused the key by ZeroKMS; the value
  never decrypts. So if John encrypts with `identityClaim: ["sub"]`, only a
  caller whose token carries John's `sub` gets the key back.
- This is **orthogonal to keysets**: keyset access (`stash-zerokms`) decides
  which clients can operate on a keyspace at all; lock context adds a
  per-value, per-caller condition on key retrieval *within* it. Both gates
  must pass.
- `AccessKeyStrategy` is invalid for lock context on the Stack surface — a
  service token minted from an access key has no user `sub` to bind to. (The
  underlying mechanism binds verified token claims generally, not only user
  subjects, but `.withLockContext({ identityClaim })` is the user-claim
  path.)
- The WASM entry does not currently expose `.withLockContext()` (a known
  gap, stack#797) — values written there are not identity-bound, and it
  cannot read values the native entry wrote under a lock context.
- A lock-context denial is per-value and per-caller (the "gate 2" failure in
  `stash-zerokms`): ZeroKMS refused to release that key to that caller. It
  does not mean the credentials are wrong.

### Deprecated, and why

- `config.strategy` → renamed `config.authStrategy` (the old name still
  works with a runtime warning; `authStrategy` wins if both are set).
- `LockContext.identify(jwt)` and `getLockContext()` — the old ceremony
  fetched a per-operation CTS token. protect-ffi 0.25 removed per-operation
  tokens, so the token `identify()` fetches is no longer consumed by
  anything. The strategy handles token acquisition now; `.withLockContext()`
  accepts a plain `{ identityClaim }` (a `LockContext` instance still works).
  If you're reading example code that calls `identify()`, it predates this —
  don't copy it.

## Never read `~/.cipherstash`

The dev profile (`auth.json`, `secretkey.json`, device JWTs) is owned by the
CLI and the auth strategies. Agents and application code must **never read
those files directly** — not to "check whether the user is logged in", not
to extract a token, not to debug. Run `stash auth login` / `stash env` and
let the strategies do the reading. A skill about authentication is exactly
where you'd be tempted; don't.

## Proxy

Authentication through CipherStash Proxy is a different path entirely: the
application connects to the Proxy with ordinary PostgreSQL credentials, and
the Proxy holds the CipherStash credentials and performs the CTS exchange
server-side. A dedicated proxy skill covers it — nothing in this skill's
client-side strategy model applies to apps behind the Proxy.

## Quick diagnosis

1. **`NOT_AUTHENTICATED` locally** → `npx stash auth login` (dev profile),
   or export the four `CS_*` variables.
2. **Works locally, 401 in CI/production** → the deployed environment lacks
   the `CS_*` variables, or they're from the wrong workspace — mint with
   `stash env`, compare `CS_WORKSPACE_CRN`.
3. **`WORKSPACE_MISMATCH`** → the access key and the CRN name different
   workspaces; re-mint rather than mix-and-match.
4. **`No OIDC provider found for issuer`** → add your IdP at
   dashboard.cipherstash.com → workspace → OIDC providers, and check the
   issuer URL matches the JWT's `iss` exactly.
5. **HTTP 402** → billing/usage, not credentials.
6. **Token is fine but operations fail 404/403** → that's keyset access,
   not authentication — switch to the `stash-zerokms` runbook.
