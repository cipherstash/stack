---
'stash': patch
---

Document in the bundled `stash-auth` skill that `CS_CLIENT_KEY` must be
hex-encoded. Hex is what `stash env` emits and what the skill's variable table
already stated, but older client versions also accepted the base64 spelling
stored in `~/.cipherstash/secretkey.json`, so a key copied out of that file
used to work. It is now rejected at client construction, with a message that
deliberately withholds detail — so the skill names the symptom and the fix.
