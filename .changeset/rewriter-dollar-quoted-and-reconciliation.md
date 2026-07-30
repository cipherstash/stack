---
'stash': patch
'@cipherstash/wizard': patch
---

Close three correctness follow-ups in the Drizzle EQL migration rewriter, all of
which previously exited 0 while leaving the user in a wrong state.

**Dollar-quoted DDL no longer bypasses the already-encrypted guard.** DDL inside
`DO $$ … END $$;` is executed SQL, but the corpus index skipped those bodies
whole, so an encrypted `ADD COLUMN` there never registered as encrypted. The
column fell through as "plaintext by residue" and the sweep staged an empty
`<column>_encrypted` twin beside the real ciphertext, reporting success. The
index now reads dollar-quoted bodies for the *encrypted* side, so these are
flagged for staged re-encryption instead. A plaintext declaration inside such a
block still does not count as declaring the column — the block may be
conditional — so those statements remain flagged rather than rewritten.
`target-exists` also now recognises a twin that exists only inside a
dollar-quoted body, which previously produced a duplicate `ADD COLUMN` that
failed at migrate time.

**A successful sweep now reports the artefact divergence it leaves behind.** The
rewrite repairs SQL only, so afterwards the database has both `email` (still
plaintext) and `email_encrypted`, while `schema.ts` and drizzle-kit's snapshot
both still declare `email` as the encrypted domain and know nothing about the
twin. `drizzle-kit generate` cannot surface this — it diffs the schema against
its snapshot and reads neither the `.sql` nor the database — so the divergence
was entirely silent: reads of the source column hand plaintext to a decrypt path
expecting an EQL envelope, and writes store an EQL envelope in a plaintext
column and succeed. `stash eql migration --drizzle` and the wizard now print the
divergence per column, naming the table, both columns, the domain and the
migration the twin was staged in, followed by the reconciliation: set the source
column back to its plaintext type, declare the twin under its own name, then run
`drizzle-kit generate` and delete the `ADD COLUMN` it regenerates for the twin.
That last step is load-bearing — the snapshot can only learn about the twin from
a `generate` that also emits SQL to create it, and the swept migration already
added that column, so leaving both fails with `column already exists`. The
`skills/stash-cli` and `skills/stash-drizzle` guides carry the same sequence.

Twins are reported only once the migration file they were written into has been
saved, so a sweep that fails mid-write no longer names a column that never
reached disk.

The new body scan is a single forward pass, so sweep time is unchanged on a real
drizzle output directory — which contains the ~2.6 MB EQL install migration, and
that file is itself thousands of `$$` PL/pgSQL bodies.

**The wizard's per-directory sweep reporting no longer breaks on a non-`Error`
throw.** It read its partial result off an unchecked cast, so a `throw null`
raised a `TypeError` inside the very `catch` meant to report the failure —
skipping the error result and abandoning the remaining directories. It now
narrows, matching the CLI.
