---
'stash': patch
---

Document the Dependabot major-version policy in `skills/stash-supply-chain-security`: no entry configures a `semver-major-days` cooldown, because every entry ignores `version-update:semver-major` and cooldown applies to version updates only. The supply-chain e2e suite now pins both halves of that relationship.
