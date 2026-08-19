---
'stash': patch
---

`stash doctor` now detects a missing native binary. Both of its checks had stopped doing so, in different ways, and each reported a green row instead.

**The encryption engine check never loaded anything.** Since the protect-ffi native load became lazy, importing the package resolves no platform binary — `@neon-rs/load`'s proxy resolves on first use — so the probe passed with nothing installed and the failure surfaced later, at the first encrypt. It now calls `assertNativeBindingAvailable()` through the new `@cipherstash/stack/diagnostics` subpath, which forces the load.

**It was also reporting the wrong package.** Importing `@cipherstash/stack` reaches `@cipherstash/auth`, whose binding is eager, so the encryption row was really a second auth check: one signal rendered as two rows. The diagnostics subpath does not reach auth, so each row now means what it says.

**A missing `@cipherstash/auth` binary produced a bare `Fatal error`.** That package's napi loader swallows the resolver's `MODULE_NOT_FOUND` and throws a summary carrying no error `code`, which the CLI's native-binary classifier did not recognise — so every command, not only `doctor`, skipped the recovery guidance and printed a raw message. The classifier now recognises that shape, and prints the missing package with the reinstall steps.

`stash doctor` exits non-zero when either platform package is missing, and reports an install of `@cipherstash/stack` that predates the diagnostics subpath as unprobeable rather than failing on it. A run that could not complete a check now ends with "stash doctor could not run every check." instead of claiming they all passed — still exit 0, since an unrunnable check is not a diagnosis.

**A package that is installed but broken is no longer reported as "not installed".** The check for an absent package matched the package name anywhere in the failure message, and the probe's own import path contains it — so a partially installed or partially built `@cipherstash/stack` was reported as one you simply had not installed yet, in green, with nothing to suggest looking further. It now matches on the specifier Node failed to resolve.
