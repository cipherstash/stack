# Changesets

This directory drives EQL's release versioning. `@cipherstash/eql`'s version is
the **single source of truth** for the whole EQL release identity `V`: the SQL
surface (`eql-V`), the Rust crate (`eql-bindings-vV`), and the npm package
(`@cipherstash/eql@V`) are all released at `V`, derived from the version
changesets computes here (see `scripts/sync-lockstep-versions.mjs`).

Because SQL, the crate, and npm are generated from one catalog at one commit,
**every releasable change needs a changeset** — including SQL-only or crate-only
changes — so that `V` moves for all three.

Add one with `pnpm changeset`, or hand-write a `.changeset/<name>.md`:

```md
---
'@cipherstash/eql': minor   # patch | minor | major
---

User-facing description of what changed and why.
```

Prereleases (alpha/beta/rc) use changesets pre-mode; see
`docs/development/releasing.md`. See
https://github.com/changesets/changesets for the tool docs.
