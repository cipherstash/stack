---
'@cipherstash/protect-ffi': minor
---

The native binding now loads lazily. Importing the package no longer resolves the platform binary: the CJS entry pulls in `./load.cjs` with `import native = require(...)`, which emits a plain `require` and leaves the `@neon-rs/load` proxy untouched, where the previous `import * as native from` compiled to an `__importStar` that enumerated the module and forced resolution at module-evaluation time. `require('@cipherstash/protect-ffi')` therefore succeeds with no binding installed, and the same `MODULE_NOT_FOUND` — identical `code` and `message` — is raised on first use instead of at import.

Adds `assertNativeBindingAvailable()`: a diagnostic entry point that resolves the platform binary and throws the loader's error unwrapped if it is missing, without constructing a client, reading credentials or touching the network. It exists because laziness removed the implicit probe that importing the package used to be, and there is no consumer-side replacement — `lib/load.cjs` is not an exported path (`ERR_PACKAGE_PATH_NOT_EXPORTED`), reading one of this module's own exports never reaches the proxy, and forcing it through a real wrapper means picking one whose argument validation does not reject first.
