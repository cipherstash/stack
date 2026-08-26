
## [0.42.3] - 2026-08-26


### Features

- classify usage denials as typed, non-retryable errors

### Fixes

- address usage-denial-taxonomy code review findings
- close out remaining PR #2120 review items
- register Notified before dropping the state lock (PR #2120 review)
- decode client-side claims without requiring org_id

### Refactoring

- remove duplication flagged by PR #2120 review

### Testing

- include org_id in JWT fixtures
- include org_id in JWT fixtures

## [0.42.2] - 2026-08-17


### Documentation

- 🩹 correct the fixture comment for the hand-rolled decode

### Fixes

- upgrade jsonwebtoken 9→10 (CVE-2026-25537)

## [0.42.1] - 2026-08-12


### Miscellaneous

- update Cargo.toml dependencies

## [0.42.0] - 2026-07-19


### Miscellaneous

- update Cargo.toml dependencies

## [0.41.1] - 2026-07-17


### Miscellaneous

- update Cargo.toml dependencies

## [0.41.0] - 2026-07-17


### Miscellaneous

- update Cargo.toml dependencies

## [0.40.0] - 2026-07-09


### Miscellaneous

- update Cargo.toml dependencies


### Features

- add AuthError::Custom + from_error_code reconstruction

### Fixes

- export CustomError; reconstruct WORKSPACE_MISMATCH from payload

### Style

- rustfmt reflow in workspace_mismatch_from_payload


### Documentation

- document the typed-error / diagnostic-help contract
- recommend passing the strategy to an SDK, not getToken
- fix cookies.d.ts example for the Result API
- fix wasm-inline.mjs JSDoc for the Result API
- note the instanceof break in the changelog

### Features

- add actionable miette help to AuthError variants
- serialize AuthError across the FFI boundary
- return a Result instead of throwing

### Fixes

- resolve doc + CRAP CI gates on error.rs
- wrap napi static factories via facade classes
- update index.d.ts guard for the Result-typed surface
- mirror help/url onto failure.error on the wasm seam
- always brand the JS error with __authFailure
- guard wasm-inline getToken against a synchronous throw
- harden failure envelope against parse + key collision

### Miscellaneous

- bump vite in /packages/stack-auth/node
- make changesets adoption review-ready (CIP-3278)
- release as 0.41.0, not 1.0.0
- bundle the LICENSE in the published package
- drive the 0.41.0 release via changesets

### Refactoring

- hand-written index.d.ts re-exporter, drop apply-dts script
- derive .d.ts drift set from AuthError::ERROR_CODES
- decompose AuthError into per-error structs
- adopt AuthError::ERROR_CODES for the AuthFailure drift guards
- define AuthError codes as named constants
- route DeviceClientError through AuthError; tidy payload

### Testing

- port re-lock-window cancellation regression test (CIP-3159)
- derive drift-test expected set from error_code() source
- cover all #[diagnostic(help)] variants, not just one
- behavioural guards for the index.d.ts split, not source-text checks
- close coverage gaps in the index.d.ts split guards
- migrate tests, examples and docs to Result; v1.0.0
- close FFI-envelope coverage gaps from PR review
- guard the __CS_FAIL__ sentinel; clean up temp dir
- cover From<DeviceClientError> for the CRAP gate
- cover WORKSPACE_MISMATCH payload end-to-end



### CI

- make the CRAP workflow blocking

### Documentation

- note OidcFederationStrategy INVALID_CRN error-code change
- drop Rustdoc intra-link from binding doc comments

### Features

- add baseUrl override to OidcFederationStrategy (CIP-3246)
- expose base_url override on all auth strategies

### Fixes

- format baseUrl bindings + cover baseUrl override in tests

### Refactoring

- take a workspace CRN in OidcFederationStrategy
- address code-review findings on the CRN change
- durable index.d.ts additions + shared base_url helper

### Testing

- deterministic expiry-crossing refresh test; clear CRAP findings
- cover is_*_at boundaries and failed-refresh expiry path
- assert backwards wall-clock is handled gracefully
- scaffold cargo-fuzz pilot for public string parsers
- assert base_url override beats CS_CTS_HOST
- cover the napi baseUrl seam + the dts normaliser
- close the lopsided baseUrl/normaliser test asymmetries


### CI

- add cargo-crap (CRAP metric) coverage report
- reuse crap:stack-auth mise task in CRAP workflow


### Documentation

- point authorize_dto refresher links at structs

### Features

- OidcFederationStrategy — federate a third-party OIDC JWT into a CTS service token
- verify federated token's workspace in OidcFederationStrategy
- napi + wasm bindings for OidcFederationStrategy

### Miscellaneous

- adopt biome for JS/TS formatting + CI

### Refactoring

- drop audience from OidcFederationStrategy; clarify provider docs
- rename OAuthStrategy to DeviceSessionStrategy


### Documentation

- note InvalidToken alongside WorkspaceMismatch
- add 0.39.0 changelog entry
- refresh AutoStrategy detection-order comment
- note CS_CTS_HOST override on AccessKeyStrategy::new
- align AccessKeyStrategy.create JSDoc

### Features

- AccessKeyStrategy takes workspaceCrn, verifies token

### Fixes

- clippy unnecessary clones + cipherstash-client test prelude
- address PR review + CI failures

### Miscellaneous

- bump @cipherstash/auth to 0.38.0
- sync lockfile + README to 0.38.0

### Refactoring

- relocate bounds to stack-auth, drop legacy ServiceToken

### Testing

- cover WORKSPACE_MISMATCH at FFI boundary
- verify workspace check runs on every get_token call
- reject stored token bound to wrong workspace
- cover AutoStrategy happy path with explicit CRN
- cover AccessKeyStrategy.create happy path
- pin CRN-with-service_name behaviour on AccessKeyStrategy

### Style

- apply rustfmt




### Documentation

- annotate None literal in TokenStore doctest
- document slick API + cookieStore + /cookies entry

### Features

- add TokenStore trait for pluggable token caching
- wire TokenStore into AutoRefresh + AccessKeyStrategy
- AccessKeyStrategy.createWithStore JS-callback bindings
- slick options-object API + cookieStore helper
- add CallbackAuthStrategy for foreign-callback strategies

### Fixes

- zeroize JSON-serialised tokens; add assertion messages
- drop private intra-doc link to crate::refresher
- log JsTokenStore callback rejections (CIP-3114)
- scope `web-sys` to the wasm32 target
- Zeroize JsTokenStore JSON + default cookieStore to Secure
- drop redundant self:: link targets in module docs
- address PR #1959 review feedback

### Miscellaneous

- migrate napi platform sub-packages to peerDependencies optional
- regenerate index.d.ts; preserve manual AuthError block

### Refactoring

- release state mutex during TokenStore load; tighten comments
- extract save_refreshed_token + install_refreshed_token helpers
- rename callback helpers to *Fn, split into auth/store modules




### Documentation

- document why TokenResultPayload uses String

### Features

- wasm-bindgen sibling crate for Supabase Edge (Layer 3.5)
- make runtime work in Supabase Edge

### Fixes

- address Copilot review feedback + patch Dockerfiles

### Refactoring

- wasm32 support — cfg-gate filesystem and Send bounds
- 🚨 address review feedback on Layer 3 PR
- dedupe error code mapping + tighten bindings
- scope down to AccessKeyStrategy



### Miscellaneous

- release v0.34.1-alpha.2


### Miscellaneous

- release
- use explicit versions for cipherstash-client and stack-auth


### Miscellaneous

- updated the following local packages: cts-common, cts-common, stack-profile, zerokms-protocol


### Documentation

- 📝 add TypeScript example for AutoStrategy usage
- 📝 add CHANGELOG.md for @cipherstash/auth
- 📝 add INVALID_CRN to changelog error codes
- 📝 demonstrate whoami (subject/workspace) in examples
- 📝 update CHANGELOG with whoami fields and security notes

### Features

- ✨ expose auth strategies in @cipherstash/auth Node bindings
- ✨ add subject() and workspace_id() to ServiceToken
- add multi-workspace profile support (CIP-2942)
- require workspace to exist before switching

### Fixes

- 🩹 add INVALID_CRN error code and deduplicate zerokms_url
- 🔒️ derive OpaqueDebug on TokenResult to prevent token leaks
- 🔒️ derive OpaqueDebug on AutoStrategyOptions
- update integration tests for workspace-scoped profiles
- hard-error on token persistence failure, strengthen test assertions
- use npm install instead of npm ci in integration test tasks

### Miscellaneous

- 🔖 bump @cipherstash/auth to 0.35.0
- 🔧 regenerate index.d.ts from napi build
- release

### Refactoring

- ♻️ restructure stack-auth-node tests to follow conventions
- simplify workspace store usage

### Testing

- ✅ add unit tests for exposed auth strategies

### Style

- 💄 fix cargo fmt formatting
- 🎨 remove redundant comments from examples


### Documentation

- 📝 add TypeScript example for AutoStrategy usage
- 📝 add CHANGELOG.md for @cipherstash/auth
- 📝 add INVALID_CRN to changelog error codes
- 📝 demonstrate whoami (subject/workspace) in examples
- 📝 update CHANGELOG with whoami fields and security notes

### Features

- ✨ expose auth strategies in @cipherstash/auth Node bindings
- ✨ add subject() and workspace_id() to ServiceToken

### Fixes

- 🩹 add INVALID_CRN error code and deduplicate zerokms_url
- 🔒️ derive OpaqueDebug on TokenResult to prevent token leaks
- 🔒️ derive OpaqueDebug on AutoStrategyOptions

### Miscellaneous

- 🔖 bump @cipherstash/auth to 0.35.0
- 🔧 regenerate index.d.ts from napi build

### Refactoring

- ♻️ restructure stack-auth-node tests to follow conventions

### Testing

- ✅ add unit tests for exposed auth strategies

### Style

- 💄 fix cargo fmt formatting
- 🎨 remove redundant comments from examples
# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

### Features

- add provisionDeviceClient Node.js binding and tests

### Fixes

- lock file
- add User-Agent header, rename to device_client, surface errors

### Miscellaneous

- clean up test imports and simplify mise task

### Refactoring

- extract device client provisioning from CLI into stack-auth
- rename provisionDeviceClient to bindClientDevice


### Documentation

- add README for stack-auth and include it as module docs
- add README for @cipherstash/auth npm package

### Fixes

- remove blank line to satisfy cargo fmt
- update vitaminc imports for 0.1.0-pre4.2 module restructure


### Documentation

- 📝 move token refresh docs and mermaid diagram to public AuthStrategy trait

### Fixes

- 🐛 fix race condition in get_token() when token expires during refresh

### Testing

- ✅ restructure auto_refresh tests into nested scenario modules


### Documentation

- 📝 fix AutoStrategy docs to reference CS_WORKSPACE_CRN not CS_REGION

### Features

- add AutoStrategyBuilder, Option<T> KeyProvider, and SecretKey::from_hex

### Fixes

- 🔥 remove unreleased AutoStrategy::new() deprecated method
- 🩹 remove unnecessary bytes.clone() and improve MissingWorkspaceCrn message
- 🩹 address PR review feedback

### Refactoring

- ♻️ replace with_region with with_workspace_crn and add
