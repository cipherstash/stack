---
'@cipherstash/protect-ffi': patch
---

Bump `cipherstash-client`, `cts-common`, `stack-auth`, and `stack-profile` to 0.42.2, which moves the transitive `jsonwebtoken` dependency from 9.3.1 to 10.4.0, resolving [CVE-2026-25537](https://github.com/advisories/GHSA-h395-gr6q-cpjc) (a JWT claim-validation type-confusion bug that could allow bypassing `nbf`/`exp` checks). No API changes.
