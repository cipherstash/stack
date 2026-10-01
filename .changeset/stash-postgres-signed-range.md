---
'stash': patch
---

Document how to express an absolute-value bucket over an EQL v3 ordered
column by decomposing it into positive and negative signed ranges. The
`stash-postgres` recipe encrypts all four bounds, shows the reversed negative
inequalities, and states the required bound validation.
