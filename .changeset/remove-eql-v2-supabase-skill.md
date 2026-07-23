---
'stash': patch
---

Update the bundled `stash-supabase` agent skill for the EQL v2 removal (#707):
`encryptedSupabase` is now the connect-time-introspecting EQL v3 factory (with
`encryptedSupabaseV3` kept as a `@deprecated` alias), and the legacy v2
`encryptedSupabase({ encryptionClient, supabaseClient })` authoring wrapper has
been removed. The skill's examples, exported-type list, and migration/cutover
guidance are corrected accordingly. Skills ship inside the `stash` tarball, so
the stale v2 guidance would otherwise land in a user's project.
