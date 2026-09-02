# Issue tracker: GitHub

Issues and specs for this repo live as GitHub issues. Use the `gh` CLI for all
operations.

## Repository ownership

All work present in this monorepo is tracked in `cipherstash/stack`, including
the absorbed EQL source under `packages/eql` and protect-ffi under
`packages/protect-ffi`. Their former upstream repositories are historical
sources, not active issue trackers. Never create, move, or update an issue in
`cipherstash/encrypt-query-language` or `cipherstash/protectjs-ffi` for work in
this tree. Create it in `cipherstash/stack` and link historical upstream issues
only as provenance.

## Conventions

- **Create an issue**: `gh issue create --title "..." --body "..."`. Use a
  heredoc for multi-line bodies.
- **Read an issue**: `gh issue view <number> --comments`, filtering comments by
  `jq` and also fetching labels.
- **List issues**: `gh issue list --state open --json number,title,body,labels,comments --jq '[.[] | {number, title, body, labels: [.labels[].name], comments: [.comments[].body]}]'`
  with appropriate `--label` and `--state` filters.
- **Comment on an issue**: `gh issue comment <number> --body "..."`.
- **Apply/remove labels**: `gh issue edit <number> --add-label "..."` or
  `--remove-label "..."`.
- **Close**: `gh issue close <number> --comment "..."`.

Use `--repo cipherstash/stack` explicitly. Do not infer ownership from subtree
history, package names, old issue links, or additional git remotes.

## Pull requests as a triage surface

**PRs as a request surface: no.** Set this to `yes` if this repository starts
treating external pull requests as feature requests.

When enabled, use the corresponding `gh pr` commands. GitHub shares one number
space across issues and pull requests, so resolve an ambiguous `#42` with
`gh pr view 42` and fall back to `gh issue view 42`.

## Skill operations

- When a skill says **publish to the issue tracker**, create a GitHub issue.
- When a skill says **fetch the relevant ticket**, run
  `gh issue view <number> --comments`.

## Wayfinding operations

The map is one issue labelled `wayfinder:map`; its tickets are child issues.

- Create child tickets as GitHub sub-issues through `gh api`. If sub-issues are
  unavailable, use a task list in the map and add `Part of #<map>` to each
  child.
- Label children `wayfinder:<type>` where type is `research`, `prototype`,
  `grilling`, or `task`.
- Represent blocking with GitHub's native issue dependencies. Fall back to a
  `Blocked by: #<n>` line only when dependencies are unavailable.
- Claim work with `gh issue edit <n> --add-assignee @me`.
- Resolve work by commenting with the result, closing the child, and adding its
  context pointer to the map's Decisions-so-far section.
