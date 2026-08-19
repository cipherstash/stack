---
'stash': major
'@cipherstash/stack': major
'@cipherstash/stack-drizzle': major
'@cipherstash/stack-supabase': major
'@cipherstash/wizard': major
---

**Why this package went to 2.0.0.** The major version number comes from
`@cipherstash/stack-prisma`, which moves to Prisma Next 0.17 — a breaking change
for its consumers, with the upgrade steps in its own Major Changes entry. These
six packages share one version line, so a major in any of them takes all six to
the same number:

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

**This does not mean every package in the release is drop-in.** The version
number is shared; the changes are not. Two entries below need action from some
users, and neither is filed under Major Changes — they are recorded at the level
their own authors judged correct, and appear here only so you do not have to
find them by reading the whole file:

- **`@cipherstash/stack` — `clientKey` is hex-only.** A decoder fallback that
  also accepted standard padded base64 is gone, and such a key is now rejected
  at client construction with `invalid clientKey: expected a hex-encoded key`.
  Hex is what `stash env` emits and what the docs have always specified, so most
  callers are unaffected; a key pasted out of `~/.cipherstash/secretkey.json`
  (which stores base64) is not. See "Adopt protect-ffi 0.31.0" under Patch
  Changes. That entry also narrows which `error.code` values DynamoDB
  operations report.
- **`stash` — `stash eql validate` lost `--exclude-operator-family`,** and two
  checks that used to exit 1 no longer do. A script passing that flag, or a CI
  gate relying on those exit codes, needs updating. See the `eql validate` entry
  under Minor Changes.

If you use neither `@cipherstash/stack-prisma` nor either of those, upgrading
1.x → 2.0.0 needs no code changes.
