# Changelog

## 0.40.0

### New Features

- **`OidcFederationStrategy` `baseUrl` override** — both `create` and
  `createWithStore` now accept an optional trailing `baseUrl` that pins a single
  strategy instance to a specific CTS host, taking precedence over the
  `CS_CTS_HOST` environment variable and region service discovery.

  ```ts
  OidcFederationStrategy.createWithStore(
    workspaceCrn, getJwt, loadToken, saveToken,
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
    workspaceCrn, getJwt, loadToken, saveToken,
  );
  ```

### Breaking Changes

- **`AccessKeyStrategy.create(workspaceCrn, accessKey)`** — the first argument
  is now a workspace CRN, not a region string. Region is derived from the CRN,
  so callers can no longer accidentally configure a strategy whose region
  disagrees with the workspace it was pointed at.

  ```ts
  // Before (0.38.x)
  const strategy = AccessKeyStrategy.create("ap-southeast-2.aws", "CSAKid.secret");

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
  — *renewing an existing CTS device session* via a refresh token — distinct
  from *federating a third-party JWT* (`OidcFederationStrategy`). `OAuthStrategy`
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
  const strategy = AutoStrategy.detect({ accessKey: "CSAK...", workspaceCrn: "crn:..." });
  const { token, issuer, services } = await strategy.getToken();
  ```
- **AccessKeyStrategy** — authenticate with a static access key (service-to-service, CI/CD):
  ```ts
  const strategy = AccessKeyStrategy.create("ap-southeast-2.aws", "CSAKid.secret");
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
