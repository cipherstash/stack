# Changelog

## 0.39.0

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

### New Error Codes

- `WORKSPACE_MISMATCH` — the JWT decoded cleanly but its `workspace` claim
  doesn't match the CRN the strategy was configured with. The accompanying
  message identifies both the expected and the token-supplied workspace IDs.

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
