---
'stash': patch
'@cipherstash/wizard': patch
---

Fix the Codex handoff installing zero skills — and losing `AGENTS.md` and `.cipherstash/` with them — when `.codex/` is not writable.

Codex sandboxes deny writes under `.codex/`. `installSkills` created its destination with an unguarded `mkdirSync`, sitting directly above a per-skill copy loop that *was* guarded — so the failure threw past that fallback and past the caller, aborting the whole handoff step. Because the skills install runs first, nothing after it ran either: no `AGENTS.md`, no `.cipherstash/context.json`, no `.cipherstash/setup-prompt.md`. All five Codex runs of the rc.3 skilltester matrix landed here, and it was identified in that report as the primary driver of the Claude→Codex quality gap.

The fix, hardened by a follow-up review of the first cut:

- **`installSkills` never throws, and reports what happened.** It returns `{ copied, failed }` instead of a flat list, so callers can tell "unwritable destination" from "stripped build" from "partial copy" without re-deriving it — every filesystem failure degrades to a warning plus a `failed` entry.
- **The Codex handoff inlines exactly the skills that failed.** Whatever could not be copied into `.codex/skills/` — all of them under a sandbox, or a subset after a partial failure — has its body inlined into `AGENTS.md` via the same `doctrine-plus-skills` path the editor-agent handoff uses. The launch prompt points at wherever each skill actually ended up, including both locations after a partial copy. A stripped build that ships no skills stays `doctrine-only` and says nothing.
- **The doctrine now ships where the published CLI can find it.** The bundled AGENTS.md doctrine was copied to `dist/commands/init/doctrine`, but the compiled resolver probes ancestor directories of the chunk in `dist/bin/` — so every published build silently wrote the minimal `AGENTS.md` stub instead of the doctrine (and the inline fallback would have inlined nothing). It now lands at `dist/doctrine`, like the skills bundle. `buildAgentsMdBody` also honours `doctrine-plus-skills` even when the doctrine fragment is missing, so inlined skills are never dropped with it.
- **The generated artifacts describe the fallback honestly.** `context.json` gains an `inlinedSkills` field, and `setup-prompt.md` distinguishes installed / inlined / failed skills instead of mislabelling an unwritable destination as a "stripped build". The Claude handoff now warns when skills exist but could not be installed, and the AGENTS.md handoff records what it inlined.
- **The rest of the handoff is guarded too.** The `AGENTS.md` upsert (which refuses malformed sentinel pairs) and the bundled-file reads degrade to warnings instead of aborting the step before `.cipherstash/` is written.

`@cipherstash/wizard` carries its own copy of `installSkills` with the same unguarded `mkdirSync` above the same guarded copy loop. It targets `.claude/skills` rather than `.codex/skills`, so the Codex sandbox case does not apply, but an unwritable destination crashed it identically — now guarded the same way, with a confirmed-then-failed install recorded in the wizard changelog instead of vanishing with the terminal output.
