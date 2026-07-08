---
'@cipherstash/stack': minor
---

Upgrade `@cipherstash/protect-ffi` to 0.27.0 and update EQL v3 concrete Postgres domain names to match the SQL fixture (`integer*`, `smallint*`, `bool`, `real*`, and `double*`). The public factories remain semantic (`Integer`, `Smallint`, `Boolean`, `Real`, `Double`) while their concrete domains change, so this is a minor release.
