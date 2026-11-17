---
'@cipherstash/stack': patch
'@cipherstash/stack-supabase': patch
'@cipherstash/stack-prisma': patch
'stash': patch
---

Two validation errors no longer quote the caller's search term: a free-text search term that is too short, and a `like`/`ilike` pattern with wildcards the encrypted search cannot honour. Each now reports the term's length instead.

The Supabase and DynamoDB adapters' error logs now record a failure's kind instead of its full message, which could quote a plaintext value. The kind is the error class plus any known encryption error type, FFI error code or auth code it carries; anything else is left out. The DynamoDB `options.logger` hook now receives a copy of the error whose message is that description, with the same `code`. The full message is still returned to the caller and passed to `errorHandler`. `@cipherstash/stack/adapter-kit` exports the shared `describeFailure` and `likeWildcardError` helpers that produce these messages.
