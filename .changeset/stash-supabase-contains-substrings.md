---
"stash": patch
---

Correct the bundled `stash-supabase` agent skill: EQL v3 `contains()` matches
substrings. The skill previously carried the reverse — that `contains()` matched
only exact values because the query's bloom filter appended the whole search term
as an extra token. That was never true: `include_original` is inert in
protect-ffi (the match bloom is trigram-only either way), so any substring of at
least the tokenizer's `token_length` (3 characters) matches, and shorter terms are
rejected rather than silently matching every row. The skills directory ships
inside the `stash` tarball and is copied into the user's `.claude/skills/` /
`.codex/skills/` (or inlined into `AGENTS.md`) at handoff time, so the stale
sentence was shipping wrong guidance into customer repos.
