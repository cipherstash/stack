---
"@cipherstash/auth": patch
---

No change to the npm package's API. This release is built from a newer copy of the Rust crate behind the package. In that crate, `OidcFederationStrategy::with_detected_workspace` no longer reports an `auth.json` it cannot read as "not logged in", and reports a saved session whose region it does not know as `AuthError::Region` instead of a server error. `Token::workspace_crn` reports the unknown region the same way. The new `profile_workspace_crn` function returns the workspace CRN of the CLI's saved session in a given profile directory.
