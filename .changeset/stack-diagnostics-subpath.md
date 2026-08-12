---
'@cipherstash/stack': minor
---

Add a `@cipherstash/stack/diagnostics` subpath, for tooling that needs to prove the protect-ffi native binding is installed.

It exports one function, `assertNativeBindingAvailable()`, re-exported from `@cipherstash/protect-ffi`. Calling it forces the platform binary to load and throws the loader's own `MODULE_NOT_FOUND` — unwrapped, naming the missing `@cipherstash/protect-ffi-<platform>-<arch>` package — if it is absent. Importing the subpath does not force anything, so the laziness that makes the native load cost nothing for callers that never encrypt is preserved.

The subpath exists because there is no way to do this from outside: the package's loader is not in its `exports` map, and reading an export never reaches the `@neon-rs/load` proxy. Importing `@cipherstash/stack` itself is not a substitute either — the root entry re-exports the auth strategies, so evaluating it resolves `@cipherstash/auth`'s binding instead. This entry reaches protect-ffi and nothing else.

Available as both `import` and `require`.
