---
'@cipherstash/stack': patch
'@cipherstash/stack-supabase': patch
'@cipherstash/stack-prisma': patch
---

Search terms no longer appear in error messages or logs. A free-text search term that is too short, or a `like`/`ilike` pattern with wildcards the encrypted search cannot honour, is now reported by its length instead of being quoted. The Supabase adapter's error log for a failed query now records the failure's kind (the error class and, for encryption failures, its `type` and `code`) instead of the full message, which could quote a plaintext value. The full message is still returned to the caller in `error.message`.
