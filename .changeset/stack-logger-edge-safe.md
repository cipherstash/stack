---
'@cipherstash/stack': patch
---

`@cipherstash/stack/adapter-kit` is now importable in a runtime with no `process` global.

The shared logger read `process.env.STASH_STACK_LOG` unguarded while initialising at module scope, so importing adapter-kit — which re-exports that logger — threw `ReferenceError: process is not defined` before any user code ran. The environment read is now guarded.

This is not a single-adapter fix. `@cipherstash/stack-supabase`, `@cipherstash/stack-drizzle` and `@cipherstash/stack-prisma` all value-import `@cipherstash/stack/adapter-kit`, so edge users of all three hit the same import-time throw, and all three are fixed by this release.

**No behaviour change on Node.** `STASH_STACK_LOG`, its accepted values (`debug` / `info` / `error`), its `error` default, and the point at which the logger is configured are all unchanged.
