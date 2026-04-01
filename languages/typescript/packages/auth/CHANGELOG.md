# Changelog

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
- **TokenResult** — `getToken()` returns `{ token, issuer, services }` with the bearer credential
  and decoded JWT claims for service discovery.
- New error codes: `NOT_AUTHENTICATED`, `MISSING_WORKSPACE_CRN`, `INVALID_ACCESS_KEY`, `INVALID_CRN`.

## 0.34.2

- Initial release with `beginDeviceCodeFlow()` and `bindClientDevice()`.
