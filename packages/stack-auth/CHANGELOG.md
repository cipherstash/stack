


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
