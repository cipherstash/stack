---
name: meta-issue-creation
description: How an agent files a GitHub issue on cipherstash repos — required structure (Background / Problem / Proposal), dumbed-down wording rules, and pre-filing checks. Use whenever drafting or filing an issue on this repo or a sibling CipherStash repo (encrypt-query-language, protectjs-ffi, …).
---

# Filing issues as an agent

These are **internal** skills for agents working on CipherStash repos. They are
deliberately outside `skills/` — everything in that directory ships to
customers inside the `stash` tarball; nothing in `.claude/skills/` does.

## Before filing anything

1. **Search for existing coverage** — open *and* closed, this repo *and* the
   sibling repo the problem might belong to:

   ```bash
   gh search issues --repo cipherstash/stack "<term>" --limit 30 --json number,title,state
   ```

   A closed issue that covers your problem is a finding, not a dead end — check
   *why* it closed (linked PR? shipped artifact? silent close?) before filing a
   duplicate. Reopening with a comment often beats a new issue.
2. **Verify every mechanical claim** against code or the installed package
   before asserting it. Cite `file:line`. Separate what you **verified** from
   what is **plausible** — say which is which in the issue.
3. **Pick the right repo.** A problem caused upstream (EQL SQL, prisma-next,
   protect-ffi) gets its issue upstream, with a consumer-impact issue here only
   if this repo needs its own mitigation. Cross-reference with the full
   `owner/repo#N` form so links work from both sides.

## Structure

Required sections, in this order:

- **Background** — orient a reader who is *new to CipherStash, stack, and EQL*.
  One short paragraph: what the relevant piece does and why it exists. Define
  every product term and acronym at first use ("EQL — the SQL library we
  install into the customer's database as the `eql_v3` schema").
- **Problem** — the mechanism (what actually happens, step by step), then the
  impact (who hits it, when, how often), then why nothing catches it today.
  A concrete failure narrative beats an abstraction: "queries slow from
  instant to scan-every-row, silently" — not "performance degradation may
  occur".
- **Proposal** — numbered, concrete steps. If the full fix is large, include a
  cheap interim step that could ship first. State the failure behaviour you
  want ("fail loudly listing the statements — a loud failure beats a silent
  deletion").

Optional sections, when they earn their place:

- **Affected versions** — when the problem is version-bounded.
- **Evidence / Verification** — commands run, output observed, `file:line`.
- **Relationship to other work** — links to sibling issues, and what each one
  does/doesn't cover. After filing, leave a short cross-link comment **on the
  related issues pointing back** — links must work in both directions or one
  side is never found.

## Wording

Dumbed down, always. Assume the reader joined yesterday:

- Short sentences. Plain verbs. No internal shorthand or codenames.
- Every acronym expanded at first use, even "obvious" ones (EQL, ZeroKMS, PSL).
- Say what breaks in the user's world, not just in the code's world.
- Titles are symptom-first and name the command or package:
  `` `stash eql upgrade` silently deletes search indexes — save and restore them ``
  beats "Improve EQL upgrade robustness".
- Write `#N` **only** for a real GitHub issue or PR reference — GitHub
  autolinks every `#N`, so "step #2 of the plan" mints a bogus link to issue 2.
  Write "step 2", "item 3" instead.
- **Never** reference internal Linear issues (`CIP-…` numbers) anywhere on
  GitHub — issues, PRs, comments, commit messages. GitHub is public; Linear is
  not. GitHub refs are fine.

## Mechanics

- `gh issue create --repo cipherstash/<repo> --title '…' --label <label> --body "…"`.
- Reuse existing labels (`enhancement`, `bug`, `SDK`, …) — check with
  `gh label list` rather than inventing new ones.
- Sibling skill: [meta-pr-creation](../meta-pr-creation/SKILL.md) for the PR
  that eventually closes the issue.
