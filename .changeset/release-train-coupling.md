---
'stash': patch
---

Two guards for the release-train version embed (#661 follow-up):

**Direction-aware version skew.** `stash init` now distinguishes an installed
package that is *behind* this CLI release (offered alignment / the pinned
install command, as before) from one that is *newer* than the release expects.
A newer install no longer produces a downgrade command — init prints the exact
`stash` update command instead (release-train lockstep guarantees that version
exists), and when missing packages are about to be installed alongside newer
ones it says the pairing may not match and to update `stash` first. Unreadable
or malformed manifest versions always count as behind (a broken install should
be offered the reinstall fix, never "looks newer, leave it").

**Version lockstep.** The release-train packages (`stash`,
`@cipherstash/stack`, `@cipherstash/stack-drizzle`,
`@cipherstash/stack-supabase`, `@cipherstash/prisma-next`,
`@cipherstash/wizard`) are now a Changesets `fixed` group: a release of any of
them republishes all of them at the same version, so the CLI's embedded
version map can never go stale against the packages it pins (previously a
runtime-package-only release would have left the published CLI embedding —
and recommending — outdated versions). A test now asserts the fixed group
stays exactly equal to the release train.
