---
'stash': patch
---

Correct the release-workflow section of the bundled `stash-supply-chain-security`
skill. It described the no-Actions-cache rule as a property of one file — "no
`cache:`, `package-manager-cache: false`, `pnpm/action-setup` with
`cache: false`" — which is no longer the whole rule.

The gate now follows any local composite action or reusable workflow the job
reaches, so the constraint is on the whole call tree rather than the workflow
file. And every published `uses:` must appear in the script's `AUDITED_ACTIONS`
allowlist: the check cannot open a published action to prove it does not cache,
and caching actions are not reliably named — a `setup-<tool>` action that caches
by default has no `cache:` input and nothing in its name to match. The list is
therefore what is permitted, not what is forbidden, and adding a step to
`release.yml` or `tests-supply-chain.yml` means auditing the action and adding
it there in the same PR.
