---
'@cipherstash/eql': patch
---

Point `repository`, `repository.directory`, and `bugs.url` at `cipherstash/stack` instead of the archived `cipherstash/encrypt-query-language`. Purely metadata — no behaviour change — but required before npm's trusted publishing (already repointed at `cipherstash/stack`) can accept a release: npm rejects a publish whose manifest `repository.url` doesn't match the publishing repository.
