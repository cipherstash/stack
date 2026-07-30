---
'stash': patch
---

The bundled skills pin `1.0.0`, not a release candidate (#791).

`skills/stash-edge` hardcoded `@cipherstash/stack@1.0.0-rc.4` in its Deno `npm:`
import and its `deno.json` import map, and `skills/stash-cli` pinned the
bare-project `npx --package=stash@…` one-shot the same way. Nothing in the build
rewrites those literals — `tsup.config.ts` copies `skills/` verbatim, and the
`__STASH_RUNTIME_VERSIONS__` embed only reaches compiled CLI code — so the
published skill would have told Deno and Supabase Edge Function users to pin a
release candidate in production, in their own repo, indefinitely.

The prerelease-semver paragraph that explained why `@^1.0.0` does not match
`1.0.0-rc.4` is gone with the rc pin; "pin exactly, Deno caches by specifier"
stands on its own. The `supabase-worker` example pins the same way.

A test now guards every `skills/*/SKILL.md`: an exact pin of a release-train
package must name a stable version on the current major, so a stale rc pin fails
on the version-bump PR instead of shipping.
