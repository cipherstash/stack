---
'@cipherstash/stack': minor
---

Adopt protect-ffi 0.31.0.

**`clientKey` must now be hex-encoded.** This is the change to check before
upgrading. The client key used to be decoded by a function that accepted both
hex and standard padded base64 — the encoding `~/.cipherstash/secretkey.json`
stores on disk — so a base64 value in `config.clientKey` or `CS_CLIENT_KEY`
worked even though the documented encoding is hex. It is now rejected at client
construction with `invalid clientKey: expected a hex-encoded key`.

The message deliberately says nothing more, because the underlying decode error
names the offending character and its offset and would put part of a live key
into your logs. So if every operation starts failing at construction after this
upgrade, check the encoding of your key first. Re-encode it as hex, or drop the
explicit key and let the client read it from the profile store.

Reading the key from `~/.cipherstash/secretkey.json` is unaffected — that path
still uses base64, and only an explicitly supplied key is now hex-only.

**DynamoDB errors no longer report foreign error codes as encryption codes.**
`handleError` accepted any string-valued `code` on a caught error and passed it
through as a `ProtectErrorCode`, so a Node or AWS SDK failure — `ECONNRESET`,
say — surfaced as though it were an encryption error code. Codes are now checked
against the set the encryption layer actually emits, and anything else becomes
`DYNAMODB_ENCRYPTION_ERROR`. If you branch on `error.code` for DynamoDB
operations, a branch that was matching transport errors will stop.

Also in this release, with no action needed: the WASM entry passes credentials
under the option shape 0.31 expects and no longer pre-normalises `cast_as`
(the native layer does it on both bindings now), and bulk operations no longer
forward their internal correlation id across the FFI boundary, which 0.31
rejects rather than ignores.
