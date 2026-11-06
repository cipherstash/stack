---
'@cipherstash/auth': patch
---

Internal change to the key vendor crates that `keysetCreate` and `keysetRewrap` compile in. The key router can now hold no key vendor backend. There is no change to what `keysetCreate` and `keysetRewrap` do.
