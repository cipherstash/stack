---
'stash': patch
---

`stash init` now pins the packages it installs (`@cipherstash/stack`, the
integration adapter, and `stash` itself) to the exact versions this CLI
release was built alongside, instead of installing bare package names that
resolve through npm dist-tags (#661). During a pre-release window dist-tags
lag or point at placeholders, so an unpinned `init` could silently deliver a
different release than the CLI driving the setup — stale `@cipherstash/stack`,
or an empty placeholder adapter — breaking `/v3` imports out of the box. The
versions are embedded at build time from the release train itself
(`src/release-train.ts`, the single source both the build and the runtime
check against), so they can never disagree with what was published together.

Init also now surfaces **version skew** on already-installed packages —
unconditionally, before any prompt or early exit, including when the install
is declined or partially fails. Interactively it offers to align the skewed
packages in the same confirm as the missing installs (keeping `stash` a dev
dependency); non-interactively it never mutates an existing install — it
warns and prints the exact align commands. A package whose manifest exists
but can't be read (an aborted install) is reported as skew, not treated as
matching. All other install guidance is pinned the same way: the
missing-package hints, `.cipherstash/context.json`'s `installCommand`, the
`install-eql` manual note, the native-module recovery hint (previously
`stash@latest`), and the `stash wizard` one-shot spawn (previously an
unpinned `npx @cipherstash/wizard`). The `stash-cli` skill documents the
behaviour, and the other bundled skills' manual install commands now carry a
verify-what-resolved note.
