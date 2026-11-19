---
"@cipherstash/auth": patch
---

No change to the npm package's API or behaviour. This release is built from a newer copy of the Rust crate behind the package. The newer crate adds two constructors for Rust callers, `OidcFederationStrategy::with_detected_workspace` and `OidcFederationStrategy::builder_with_detected_workspace`. Both read the workspace from `CS_WORKSPACE_CRN` or from the CLI's saved session.
