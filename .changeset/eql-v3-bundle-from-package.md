---
'@cipherstash/stack': patch
---

Source the EQL v3 install bundle from `@cipherstash/eql@3.0.0-alpha.3` instead of a hand-vendored 43k-line SQL fixture committed to the test tree. The package publishes its SQL and its TypeScript wire types from the same `eql-bindings` commit, so the bundle is now pinned to a released EQL version rather than tracked by convention.

Test-and-tooling only — `@cipherstash/eql` is a `devDependency` and no public API changes.

The staleness check in the v3 install helper now compares `eql_v3.version()` against the pinned release instead of probing for a hand-picked sentinel domain. The previous sentinel (`public.timestamp`) exists in both the old and new bundles, so it would have reported a stale install as current and left the suite silently running the wrong SQL.
