---
'stash': patch
---

The `stash-dynamodb` skill no longer tells you to re-encrypt items written by `@cipherstash/protect-dynamodb` when moving to Stack. Those items decrypt and stay queryable as stored, so re-encrypting is optional. The skill now lists the three differences to plan for: boolean equality lookups, `downcase` filters, and legacy `dataType('json')` attributes.
