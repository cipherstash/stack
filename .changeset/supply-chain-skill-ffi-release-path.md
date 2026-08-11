---
'stash': patch
---

Document the native-binding publish path in the bundled
`stash-supply-chain-security` skill, and correct what it claims about
frozen-lockfile coverage.

`@cipherstash/protect-ffi` and its six platform packages ship compiled binaries,
which `changeset publish` cannot produce — it packs from the workspace, where
`index.node` is a build output. The skill now describes the pipeline that does:
a registry-state gate, a target-explicit build matrix in a reusable workflow,
and a publish step that ships the six platform packages before the wrapper and
tags all seven itself, because changesets tags only what it published. It also
records two npm requirements that fail late and quietly — `repository.url` must
match the publishing repository exactly (and `repository.directory` resolves
from that repository's root), and trusted-publisher configurations created after
2026-05-20 need an explicit "Allowed actions" selection.

The frozen-lockfile section said the rule was enforced in `tests.yml`, which was
true and misleading: that is where it was *checked*, and `release.yml` ran a
bare `pnpm install` from the day it was written — so the single install permitted
to resolve outside the lockfile was the one whose output goes to the registry.
The install is fixed and the check now scans every workflow and every local
composite action.
