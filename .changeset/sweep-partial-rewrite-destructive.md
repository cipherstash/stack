---
'@cipherstash/wizard': patch
'stash': patch
---

Close the last fail-open path in the Drizzle ALTER COLUMN sweep: a sweep that
failed **after** it had already rewritten a file reported that directory as
merely *unverified* instead of *destructive*.

The sweep writes one migration file at a time. If the write of the second file
failed — ENOSPC, a read-only file, an editor or `drizzle-kit` holding a lock —
the whole call rejected and the list of files it had already rewritten was
discarded with the stack frame. The wizard then reported zero rewrites for that
directory and printed "the sweep could not check 1 directory (drizzle/)" over a
prompt that made no mention of data loss, while a live `DROP COLUMN` sat on
disk. The CLI's `stash eql migration --drizzle` had the milder form: it warned
about the directory but never named the files that had already become
data-destroying.

The work already done now travels with the failure. `rewriteEncryptedAlterColumns`
rejects with a `PartialRewriteError` carrying `rewritten` and `skipped` whenever
it fails part way through a directory it has already changed, and the wizard's
directory sweep reports those arrays alongside the error instead of zeros. A
directory in that state is reported as **both**: the rewritten files are listed
with the existing data-destroying warning, *and* the "sweep did not fully
complete — review the sibling migrations" warning still fires, because both are
true. The `Run the migration now?` prompt takes the destructive arm — defaulting
to No and saying the migration DESTROYS data on a populated table — since that
is the fact a user cannot afford to miss.

A sweep that fails before changing anything is unchanged: it rejects with the
original error, reports zeros, and keeps the softer "nothing is known about this
directory" wording, because claiming data destruction there would be a guess.
