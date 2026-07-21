---
'stash': patch
'@cipherstash/wizard': patch
---

Fix the Codex handoff installing zero skills — and losing `AGENTS.md` and `.cipherstash/` with them — when `.codex/` is not writable.

Codex sandboxes deny writes under `.codex/`. `installSkills` created its destination with an unguarded `mkdirSync`, sitting directly above a per-skill copy loop that *was* guarded — so the failure threw past that fallback and past the caller, aborting the whole handoff step. Because the skills install runs first, nothing after it ran either: no `AGENTS.md`, no `.cipherstash/context.json`, no `.cipherstash/setup-prompt.md`. All five Codex runs of the rc.3 skilltester matrix landed here, and it was identified in that report as the primary driver of the Claude→Codex quality gap.

Two changes:

- **`installSkills` never throws.** Every filesystem step now degrades to a warning and a shorter return, so the caller decides what to do with an empty result instead of being skipped entirely.
- **The Codex handoff falls back to inlining.** When the skills cannot be written, their bodies are inlined into `AGENTS.md` — which lives at the project root and is writable — via the same `doctrine-plus-skills` path the editor-agent handoff already uses for Cursor / Windsurf / Cline. Codex still gets the API guidance, in one file instead of a directory, and the launch prompt points at wherever it actually ended up.

The fallback is only claimed when there is something to inline: a stripped CLI build that ships no skills at all stays `doctrine-only` and says nothing, rather than reporting a fallback that did not happen.

`@cipherstash/wizard` carries its own copy of `installSkills` with the same unguarded `mkdirSync` above the same guarded copy loop. It targets `.claude/skills` rather than `.codex/skills`, so the Codex sandbox case does not apply, but an unwritable destination crashed it identically — now guarded the same way.
