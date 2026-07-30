---
'stash': patch
---

Update the `stash-supply-chain-security` skill: npm OIDC trusted publishing and provenance are live in `release.yml`, not deferred. Documents the constraints that keep them working (`id-token: write`, GitHub-hosted runner, no `NPM_TOKEN`, npm >= 11.5.1, no Actions cache) and adds a runbook for claiming a package name on npm for the first time — a trusted publisher can only be attached to a package that already exists, so a new name needs a manual placeholder publish before the release workflow can publish it.
