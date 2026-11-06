---
'@cipherstash/stack': patch
'@cipherstash/stack-supabase': patch
'@cipherstash/stack-prisma': patch
---

Search terms no longer appear in error messages or logs. A free-text search term that is too short, or a `like`/`ilike` pattern with wildcards the encrypted search cannot honour, is now reported by its length instead of being quoted.

The Supabase and DynamoDB adapters' error logs now record a failure's kind instead of its full message, which could quote a plaintext value: the error class, plus any `type`, `code` and `authCode` identifiers it carries (for example a PostgREST error code or an FFI error code). The full message is still returned to the caller on the error. `@cipherstash/stack/adapter-kit` exports the shared `describeFailure` helper that produces this description.
