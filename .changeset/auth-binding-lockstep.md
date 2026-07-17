---
'@cipherstash/stack': patch
'stash': patch
'@cipherstash/wizard': patch
---

Fix "Failed to load native binding" on project-local installs of the CLI/SDK
(npm). `@cipherstash/auth` was pinned at 0.41.0 while the six
`@cipherstash/auth-*` platform bindings declared in stack/stash/wizard's
optionalDependencies were pinned at 0.42.0. Because auth pins its bindings as
exact-version optional peer dependencies, the skew made npm nest per-consumer
binding copies that the hoisted `auth` package could not resolve — any command
or import touching auth then died at startup. All seven packages now move in
lockstep at 0.42.0, Dependabot is barred from bumping any of them
independently, and a supply-chain CI test fails on any future skew.
