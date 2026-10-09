# Changelog

## 1.0.0

### Minor Changes

- fd0ee91: `OidcFederationStrategy` now keeps one CTS token per distinct provider JWT
  instead of one token for everyone. `getJwt` is called on every `getToken()`
  and must return the JWT of the user the current request is for; a JWT is
  exchanged once and its CTS token reused while that token is valid _and_ the
  JWT's entry is still in the bounded least-recently-used cache (eviction before
  expiry, or `cacheCapacity: 0`, means another exchange; see below). Previously
  the strategy cached the first user's token and handed it to
  every caller until it expired, so on a server serving many users through one
  client a value one user encrypted under a lock context could be bound to
  another user's identity (cipherstash/stack#1045).

  `getToken()` now calls `getJwt` in the caller's own async context and hands the
  JWT to a new `getTokenForJwt(jwt)` method, on both the Node and `wasm-inline`
  entries. Previously the Node binding ran `getJwt` through a napi threadsafe
  function, in the async context of `create()`, so a callback that read the
  request from `AsyncLocalStorage` (Clerk's `auth()`, Next.js `headers()`) saw
  no request from a module-level strategy, or the creating request from one
  created inside a request. One long-lived strategy now serves every user from
  such a callback. `getTokenForJwt` is also public, for a caller that already
  holds the user's JWT; it shares the strategy's cache with `getToken()`.

  A token persisted through `createWithStore` (for example a cookie) is now
  served only to the JWT it was federated from, so a store shared across users,
  or a cookie left over from a previous sign-in, is a cache miss rather than
  another user's token. The store is still one slot, so a store shared by
  several users caches only the most recent of them; give each user their own
  (a per-browser cookie already is). The stored JSON carries a new
  `federated_from` field; tokens stored by earlier releases have none and are
  re-federated once.

  Because the cache is keyed on the whole JWT, an identity provider that rotates
  JWTs faster than the CTS token lifetime (about 15 minutes) re-federates on each
  rotation, where earlier releases reused the stored token.

  The cache holds 1024 JWTs unless told otherwise. `create` and `createWithStore`
  take an optional `cacheCapacity` after `baseUrl` (the `cacheCapacity` option on
  `@cipherstash/auth/wasm-inline`); when the cache is full the least recently
  used JWT's token is dropped, that user is exchanged again on their next call,
  and the eviction is logged at `debug`. `0` caches nothing. Existing calls are
  unchanged.

### Patch Changes

- fb75f40: Auth failures carry more help, and their messages never quote a credential or another library's text. A failure's `type` (`NOT_AUTHENTICATED`, `INVALID_CRN`, ...) is unchanged.

  - `REQUEST_ERROR`'s message no longer repeats the transport's own error, which can carry a URL with its query string. It gains `help` saying what to check.
  - `INVALID_TOKEN` for a token whose claims do not decode no longer quotes the decoder's message, which could carry a byte or a claim of the token.
  - A failed device binding reports ZeroKMS's status, not its response body.
  - `SERVER_ERROR` for a refused token exchange names the HTTP status and the auth server's `error_description`, not the response body, which from the edge in front of it is an HTML page and can echo the access key. A body that is not JSON is reported by where it broke, not by the parser's message.
  - A profile file that is not valid JSON is reported by error kind, line and column, not by the parser's message, which could quote the file.
  - `INVALID_GRANT`, `INVALID_WORKSPACE_ID` and `ALREADY_CONSUMED` gain `help`, and `NOT_AUTHENTICATED`'s help names `stash auth login`.
  - A `STORE_ERROR` carries the help of the profile failure underneath it, such as logging in again when the profile file is missing.
  - @cipherstash/auth-darwin-x64@1.0.0
  - @cipherstash/auth-darwin-arm64@1.0.0
  - @cipherstash/auth-win32-x64-msvc@1.0.0
  - @cipherstash/auth-linux-x64-gnu@1.0.0
  - @cipherstash/auth-linux-arm64-gnu@1.0.0
  - @cipherstash/auth-linux-x64-musl@1.0.0

## 0.44.1

### Patch Changes

- e766c9a: Internal addition to the underlying Rust crate: `AuthError` gains an
  `is_credential_rejection()` classifier used by FFI front-ends to decide
  whether refreshing the credential and retrying is sensible. No API or
  behaviour change for `@cipherstash/auth` consumers.
- e766c9a: Device-session refresh now reports failed profile saves so callers do not silently reuse a consumed refresh token.
- e766c9a: Internal restructuring of the underlying Rust crate: HTTP transport (reqwest
  and the bundled access-key, device-session, OIDC-federation and auto
  strategies) now sits behind an `http` cargo feature, on by default and always
  enabled in the npm builds — no API change for `@cipherstash/auth` consumers.
  The only observable difference is the wording of transport-failure error
  messages, which now read "Request to the auth server failed: …" instead of
  "HTTP request failed: …".
- e766c9a: Internal restructuring of the underlying Rust crate: every strategy now sends
  its requests through an `HttpTransport` trait, with the bundled reqwest client
  as the default implementation, so the same strategies can run over a host's own
  HTTP client (the Go binding's WASI guest). The npm builds always use the bundled
  client — no API or behaviour change for `@cipherstash/auth` consumers.
- ed14d04: The `linux-x64-musl` binary now links musl. In 0.44.0 it linked glibc, so
  `@cipherstash/auth` did not load on musl systems such as Alpine Linux.
- e766c9a: Internal test-only change to the underlying Rust crate: adds regression coverage for token expiry, credential rejection, device metadata, and browser-launch results. No API or behaviour change for `@cipherstash/auth` consumers; this entry exists because CI requires a changeset for changes under the crate.
- e766c9a: Internal addition to the underlying Rust crate: `stack_auth` now re-exports
  `Crn` (the workspace CRN every strategy is bound to) so a caller that builds
  a strategy by hand needs nothing else from `cts-common`. No API or behaviour
  change for `@cipherstash/auth` consumers.
- 32f6750: The native binding is now built from the `stack-auth` 0.43.0 crate, so its
  requests identify themselves as `stack-auth/0.43.0` in the user agent. No API
  or behaviour change for `@cipherstash/auth` consumers.
  - @cipherstash/auth-darwin-x64@0.44.1
  - @cipherstash/auth-darwin-arm64@0.44.1
  - @cipherstash/auth-win32-x64-msvc@0.44.1
  - @cipherstash/auth-linux-x64-gnu@0.44.1
  - @cipherstash/auth-linux-arm64-gnu@0.44.1
  - @cipherstash/auth-linux-x64-musl@0.44.1

## 0.44.0

### Minor Changes

- 2f75eca: Add `USAGE_LIMIT_EXCEEDED` and `ORG_NOT_PROVISIONED` to the `AuthFailure`
  union. Authentication and token refresh now report CTS usage denials as typed,
  non-retryable failures instead of misclassifying them as transient server,
  access-denied, or expired-token errors. The failure message is preserved and
  the `help` field identifies whether to upgrade the plan or contact support.

## 0.43.0

### Minor Changes

- 5d46b40: Add the `@cipherstash/auth/next` runtime adapter for federated CTS tokens in
  request/response server frameworks — built for the Next.js App Router, but
  framework-agnostic by construction (every function operates on WHATWG
  `Request`/`Headers` and returns plain data).

  `csFederate` / `csFederationMiddleware` federate-or-reuse a CTS service token in
  any writable, in-scope context (middleware, route handler, server action),
  persist it to a per-workspace HTTP-only cookie for the cross-request cache, and
  hand the freshly minted token to the same-request render via a request header.
  `csAuthHeader` reads that warmed token back into a no-federation `AuthStrategy`
  that can be driven from a detached callback (e.g. protect-ffi) for the life of
  the request — it replays the warmed token and does not refresh, so it is valid
  only until that token's TTL expires. `csSanitizeHeaders` strips a
  client-supplied warmed-token header on ingress; `csFederationMiddleware` applies
  it for you and returns the sanitised `requestHeaders` to forward.

  Built on the `Result`-returning strategy surface — `getToken()` resolves a
  `{ data }` / `{ failure }` `Result`.

## 0.42.0

### Minor Changes

- bc1d158: Add a `CUSTOM` member to the `AuthFailure` union (`type: "CUSTOM"`). This mirrors a new `AuthError::Custom` variant on the Rust side — the serde-style catch-all for an auth error outside the standard set, which a custom auth strategy can surface for its own failures and which an FFI adaptor reconstructs a failure into when its `type` code doesn't map to a specific typed variant. It serializes as `{ type: "CUSTOM", ... }`, so consumers switching on `failure.type` should handle it.

## 0.41.0

### Minor Changes

- 28fc5b1: **Errors are now returned, not thrown.** Every fallible operation returns a
  [`@byteslice/result`](https://www.npmjs.com/package/@byteslice/result)
  `Result` — `{ data }` on success, `{ failure }` on a domain error — instead of
  throwing. This applies to `getToken()`, the strategy factories
  (`AccessKeyStrategy.create`, `AutoStrategy.detect`,
  `DeviceSessionStrategy.fromProfile`, `OidcFederationStrategy.create` /
  `.createWithStore`), `beginDeviceCodeFlow`, `DeviceCodeResult.pollForToken` /
  `openInBrowser`, and `bindClientDevice`. The same applies to the
  `@cipherstash/auth/wasm-inline` entry.

  `failure` is a discriminated union (`AuthFailure`) tagged by `type` (the codes
  formerly on `err.code`), carrying the live `error: Error`, optional
  `help`/`url`, and per-variant payload (e.g. `WORKSPACE_MISMATCH`'s `expected`
  / `actual`). Only a genuine internal panic still throws.

  Migration:

  ```ts
  // before
  try {
    const { token } = await strategy.getToken();
  } catch (err) {
    if (err.code === "EXPIRED_TOKEN") {
      /* … */
    }
  }

  // after
  const result = await strategy.getToken();
  if (result.failure) {
    if (result.failure.type === "EXPIRED_TOKEN") {
      /* … */
    }
  } else {
    const { token } = result.data;
  }
  ```

  Two new failure `type`s surface caller/runtime states that previously threw
  as bare errors: `ALREADY_CONSUMED` (reusing a consumed `DeviceCodeResult`
  handle) and `INTERNAL_ERROR`.

  Adds a runtime dependency on `@byteslice/result` (zero-dependency, MIT).

  **`instanceof` on the strategy classes now returns `false`.** The exported
  `AutoStrategy` / `AccessKeyStrategy` / `DeviceSessionStrategy` are thin facades
  over the native classes, and the factories hand back the strategy inside
  `result.data`, so `result.data instanceof AccessKeyStrategy` is now `false` (it
  was `true` on `main`, when the factory returned the instance directly). Gate on
  `result.failure` and use `result.data` rather than `instanceof`.

## 0.40.0

### New Features

- **`OidcFederationStrategy` `baseUrl` override** — both `create` and
  `createWithStore` now accept an optional trailing `baseUrl` that pins a single
  strategy instance to a specific CTS host, taking precedence over the
  `CS_CTS_HOST` environment variable and region service discovery.

  ```ts
  OidcFederationStrategy.createWithStore(
    workspaceCrn,
    getJwt,
    loadToken,
    saveToken,
    "http://localhost:4000", // baseUrl — federate against a mock / self-hosted CTS
  );
  ```

  Unlike `CS_CTS_HOST`, the override is scoped to that strategy alone, so it
  doesn't redirect other CTS clients sharing the process (e.g. a `protect-ffi`
  encryption client). On `wasm-inline` it's the `baseUrl` field of the options
  object (`{ store?, baseUrl? }`); in the wasm runtime — which can't read
  `CS_CTS_HOST` from the environment — it's the only way to target a host other
  than the region-discovered one.

## 0.39.0

### New Features

- **`OidcFederationStrategy`** — federate a third-party OIDC JWT (Clerk,
  Supabase, …) into a CipherStash CTS service token via `/api/authorise`.
  Exposed on both the napi and `wasm-inline` entrypoints, with a `getJwt`
  callback that supplies the current third-party token.

  ```ts
  const strategy = OidcFederationStrategy.create(
    "crn:ap-southeast-2.aws:ZVATKW3VHMFG27DY",
    getJwt, // () => Promise<string> — your current third-party OIDC JWT
  );
  const { token } = await strategy.getToken();
  ```

  The first argument is a workspace CRN: region is derived from it for service
  discovery, and the workspace ID is used to verify every federated token —
  the same shape as `AccessKeyStrategy`.

  A store-backed variant persists the federated CTS token (e.g. in an HTTP-only
  cookie) so it survives across requests without re-federating:

  ```ts
  OidcFederationStrategy.createWithStore(
    workspaceCrn,
    getJwt,
    loadToken,
    saveToken,
  );
  ```

### Breaking Changes

- **`AccessKeyStrategy.create(workspaceCrn, accessKey)`** — the first argument
  is now a workspace CRN, not a region string. Region is derived from the CRN,
  so callers can no longer accidentally configure a strategy whose region
  disagrees with the workspace it was pointed at.

  ```ts
  // Before (0.38.x)
  const strategy = AccessKeyStrategy.create(
    "ap-southeast-2.aws",
    "CSAKid.secret",
  );

  // After (0.39.0)
  const strategy = AccessKeyStrategy.create(
    "crn:ap-southeast-2.aws:ZVATKW3VHMFG27DY",
    "CSAKid.secret",
  );
  ```

  The same change applies to the wasm-inline entry: `AccessKeyStrategy.create(workspaceCrn, accessKey, options?)`.

- **Per-call workspace verification.** Every issued token's `workspace` JWT
  claim is now checked against the CRN. If they differ (e.g. an access key
  with rights on multiple workspaces was bound to the wrong CRN), `getToken()`
  rejects with a new `WORKSPACE_MISMATCH` error code. Previously the
  strategy silently let the caller operate on a different workspace than the
  one they specified.

### Deprecations

- **`OAuthStrategy` is renamed to `DeviceSessionStrategy`** to make its purpose
  — _renewing an existing CTS device session_ via a refresh token — distinct
  from _federating a third-party JWT_ (`OidcFederationStrategy`). `OAuthStrategy`
  is still exported as a `@deprecated` alias of `DeviceSessionStrategy`, so
  existing code keeps working; it will be removed in a future major.

### New Error Codes

- `WORKSPACE_MISMATCH` — the JWT decoded cleanly but its `workspace` claim
  doesn't match the CRN the strategy was configured with. The accompanying
  message identifies both the expected and the token-supplied workspace IDs.
- `INVALID_WORKSPACE_ID` — a token's `workspace` claim could not be parsed
  while extracting or verifying it.

Both `AccessKeyStrategy` and `OidcFederationStrategy` take a workspace CRN, so a
malformed CRN argument is rejected with the existing `INVALID_CRN` code.

### Changed Error Codes

- **`OidcFederationStrategy` construction now reports `INVALID_CRN`.** Because it
  takes a single workspace CRN instead of separate `region` + `workspaceId`
  arguments, a malformed value is now surfaced as `INVALID_CRN` rather than the
  previous `INVALID_REGION` / `INVALID_WORKSPACE_ID` codes. Consumers matching on
  those codes from the strategy's factories should update accordingly.

## 0.35.0

### New Features

- **AutoStrategy** — auto-detect credentials from environment variables and the local profile store.
  Use `AutoStrategy.detect()` for zero-config auth, or pass explicit values:
  ```ts
  const strategy = AutoStrategy.detect({
    accessKey: "CSAK...",
    workspaceCrn: "crn:...",
  });
  const { token, issuer, services } = await strategy.getToken();
  ```
- **AccessKeyStrategy** — authenticate with a static access key (service-to-service, CI/CD):
  ```ts
  const strategy = AccessKeyStrategy.create(
    "ap-southeast-2.aws",
    "CSAKid.secret",
  );
  const { token } = await strategy.getToken();
  ```
- **OAuthStrategy** — authenticate using OAuth refresh tokens persisted to disk:
  ```ts
  const strategy = OAuthStrategy.fromProfile();
  const { token } = await strategy.getToken();
  ```
- **TokenResult** — `getToken()` returns `{ token, subject, workspaceId, issuer, services }` with
  the bearer credential and decoded JWT claims for identity and service discovery.
- New error codes: `NOT_AUTHENTICATED`, `MISSING_WORKSPACE_CRN`, `INVALID_ACCESS_KEY`, `INVALID_CRN`.

### Security

- `TokenResult` and `AutoStrategyOptions` use `OpaqueDebug` to prevent tokens and access keys
  from appearing in Rust debug/log output.

## 0.34.2

- Initial release with `beginDeviceCodeFlow()` and `bindClientDevice()`.
