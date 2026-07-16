---
'stash': patch
---

Two guards for the release-train version embed (#661 follow-up):

**Direction-aware version skew.** `stash init` now distinguishes an installed
package that is *behind* this CLI release (offered alignment / the pinned
install command, as before) from one that is *newer* than the release expects.
A newer install no longer produces a downgrade command — init says the install
is likely fine and to update the stash CLI to the matching release instead.
Unreadable manifests still count as behind (a broken install should be offered
the reinstall fix).

**Version lockstep.** The release-train packages (`stash`,
`@cipherstash/stack`, `@cipherstash/stack-drizzle`,
`@cipherstash/stack-supabase`, `@cipherstash/wizard`) are now a Changesets
`fixed` group: a release of any of them republishes all of them at the same
version, so the CLI's embedded version map can never go stale against the
packages it pins (previously a stack-only release would have left the
published CLI embedding — and recommending — outdated versions).
`@cipherstash/prisma-next` stays on its own version line by design; the
direction-aware messaging above covers it.
