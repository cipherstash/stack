---
'stash': minor
'@cipherstash/stack': minor
'@cipherstash/stack-drizzle': minor
'@cipherstash/stack-supabase': minor
'@cipherstash/wizard': minor
---

**Reading this release.** These packages share one version line with
`@cipherstash/stack-prisma`, so all six move together:

- `stash`
- `@cipherstash/stack`
- `@cipherstash/stack-drizzle`
- `@cipherstash/stack-supabase`
- `@cipherstash/stack-prisma`
- `@cipherstash/wizard`

They are versioned together on purpose. `stash init` pins the versions of the
packages it installs and the CLI embeds that map at build time, so a package
shipping alone would leave the CLI recommending versions that no longer match
what is published, and warning about a skew it had itself created.

Two changes in this release can need action from some users. They are named
here so you do not have to read six changelogs to find them:

- **`@cipherstash/stack` — `clientKey` is hex-only.** A decoder fallback that
  also accepted standard padded base64 is gone, and such a key is now rejected
  at client construction with `invalid clientKey: expected a hex-encoded key`.
  Hex is the only encoding ever documented, and the only one `stash env` or any
  part of the JavaScript stack has ever produced — the base64 tolerance was an
  accident of the underlying Rust decoder, which accepts base64 solely to read
  its own profile store. A key pasted out of `~/.cipherstash/secretkey.json`
  (which stores base64) stops working; re-encode it, or drop the explicit key
  and let the client read the profile store directly, which is unaffected. The
  full entry is "Adopt protect-ffi 0.31.0" in the **`@cipherstash/stack`**
  changelog; it also narrows which `error.code` values DynamoDB operations
  report.
- **`stash` — `stash eql validate` lost `--exclude-operator-family`,** and two
  checks that used to exit 1 no longer do. A script passing that flag, or a CI
  gate relying on those exit codes, needs updating. The full entry is under
  `eql validate` in the **`stash`** changelog.

`@cipherstash/stack-prisma` also moves to Prisma Next 0.17 in this release,
which requires migration steps from its consumers — see its own changelog
entry.
