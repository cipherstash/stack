---
"@cipherstash/auth": patch
---

Sign-in and token refresh no longer trust an unbounded `expires_in` from the
auth server. A token lifetime longer than 30 days is treated as 30 days, and a
device code is polled for at most one hour, so an oversized value can no
longer panic the process or wrap to an already-expired token. The buffers that
carry saved tokens and keys to and from `~/.cipherstash`, and an access key
read from `CS_CLIENT_ACCESS_KEY`, are now wiped from memory once used. A
saved profile file that is not valid UTF-8 is now reported as malformed JSON,
like any other unreadable profile, rather than as an I/O error.
