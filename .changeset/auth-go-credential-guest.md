---
"@cipherstash/auth": patch
---

Device-session refresh now reports failed profile saves so callers do not silently reuse a consumed refresh token.
