

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
