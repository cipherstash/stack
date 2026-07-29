---
'stash': major
'@cipherstash/migrate': major
---

Remove the remaining EQL v2 installation and rollout surface. CLI installs,
upgrades, backfills, and drops now mutate EQL v3 state only, while legacy v2
status diagnostics and migration-manifest compatibility remain read-only.
