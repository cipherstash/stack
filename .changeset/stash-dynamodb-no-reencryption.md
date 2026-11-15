---
'stash': patch
---

The `stash-dynamodb` skill now scopes the no-re-encryption upgrade to the tested top-level scalar equality columns and unindexed text written by `@cipherstash/protect-dynamodb@6.0.1`. It explains boolean lookup changes and the privacy cost of a plaintext replacement, stale `__hmac` removal, `downcase` normalization, and the required legacy JSON backfill with its rollback limit. It also clarifies legacy v2 reads and queries using current v3 schemas.
