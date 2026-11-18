---
"@cipherstash/auth": patch
---

No change to the npm package's API or behaviour. This release is built from a newer copy of the Rust crate behind the package. The newer crate adds a constructor for Rust callers, `OidcFederationStrategy::with_detected_workspace`. The constructor reads the workspace from `CS_WORKSPACE_CRN` or from the CLI's saved session.
