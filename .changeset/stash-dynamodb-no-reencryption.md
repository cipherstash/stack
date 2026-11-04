---
'stash': patch
---

The `stash-dynamodb` skill no longer tells you to re-encrypt items written by `@cipherstash/protect-dynamodb` when moving to Stack. Those items decrypt and stay queryable as stored, so re-encrypting is optional. The skill now lists the differences to plan for: boolean equality lookups, removing a stale `__hmac` on in-place updates, `downcase` filters (normalize on write as well as on query), and legacy `dataType('json')` attributes. It also says when `{ storedEqlVersion: 2 }` is needed: for a grouped v2 field declared by its bare leaf name, not for top-level scalar items.
