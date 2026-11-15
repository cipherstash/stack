---
"@cipherstash/auth": patch
---

Sign-in and token refresh no longer trust an unbounded `expires_in` from the
auth server. A token lifetime longer than 30 days is treated as 30 days, and a
device code is polled for at most one hour, so an oversized value can no
longer panic the process or wrap to an already-expired token. The buffers that
carry saved tokens and keys to and from `~/.cipherstash`, and an access key
read from `CS_CLIENT_ACCESS_KEY`, are now wiped from memory once used.
A device code's lifetime now runs from when it was issued, and polling stops
at that deadline rather than at the next poll after it.
