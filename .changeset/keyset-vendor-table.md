---
'@cipherstash/auth': patch
---

Internal change to `keysetCreate` and `keysetRewrap`. One table now holds each key vendor backend: its short name, its vendor and how to build its client from the environment. There is no change to what they do.
