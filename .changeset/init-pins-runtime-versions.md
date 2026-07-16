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
versions are embedded at build time from the release train itself, so they can
never disagree with what was published together.

Init also now **warns on version skew**: if a `@cipherstash/*` package is
already installed but its resolved `node_modules` version differs from the one
this release expects, init says so and prints the exact command to align it
(it never mutates existing installs). The install guidance printed by other
commands (missing-package hints, `.cipherstash/context.json`'s
`installCommand`) is pinned the same way, and the `stash-cli` skill documents
the pinning and skew-warning behaviour.
