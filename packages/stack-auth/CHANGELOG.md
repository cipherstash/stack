

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
