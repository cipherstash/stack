---
"@cipherstash/auth": patch
---

The Rust `stack-auth` crate that `@cipherstash/auth` is built from gains `AutoStrategy::detect_workspace_crn()`. It returns the workspace CRN that `AutoStrategy` would use, without building a strategy: `CS_WORKSPACE_CRN` if it is set, otherwise the workspace of the session `stash auth login` saved for the CLI's current workspace. With neither, it fails with `NOT_AUTHENTICATED` rather than picking a default. A Rust caller building its own strategy, such as `OidcFederationStrategy`, no longer has to read the variable and the profile itself. The npm package's API does not change.
