---
"@cipherstash/stack": minor
---

**Breaking (`@cipherstash/stack/wasm-inline`):** `WasmClientConfig` now takes a
`workspaceCrn` instead of `region`. The region is derived from the CRN and the
access-key token's workspace is asserted against it (`getToken()` fails with
`code === "WORKSPACE_MISMATCH"` on a mismatch), so the CRN is the single source
of truth for workspace identity — matching the Node entry.

Bumps `@cipherstash/auth` to 0.40.0 to pick up the
`AccessKeyStrategy.create(workspaceCrn, accessKey)` signature.

Migration: replace `config.region` (e.g. `"ap-southeast-2.aws"`) with
`config.workspaceCrn` (e.g. `"crn:ap-southeast-2.aws:<workspace-id>"`).
