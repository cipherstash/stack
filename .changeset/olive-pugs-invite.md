---
'@cipherstash/stack': patch
---

Adopt protect-ffi 0.31.0.

**`clientKey` is hex, and a decoder tolerance that accepted other spellings is
gone.** Hex has always been the documented and only supported encoding for
`config.clientKey` / `CS_CLIENT_KEY` — it is what `stash env` emits and what
the docs and skills have always shown. The decoder underneath happened to fall
back to standard padded base64, which is the encoding the Rust
`stash-profile` crate uses for `~/.cipherstash/secretkey.json` on disk; that
fallback was never part of this package's contract, and nothing in the
JavaScript stack ever produced or accepted a base64 key. It is now rejected at
client construction with `invalid clientKey: expected a hex-encoded key`.

The message deliberately says nothing more, because the underlying decode error
names the offending character and its offset and would put part of a live key
into your logs. So if construction starts failing after this upgrade, the key
you supplied is not hex — re-encode it, or drop the explicit key and let the
native client read it from the profile store.

Reading the key from `~/.cipherstash/secretkey.json` is unaffected — that path
still uses base64, and only an explicitly supplied key is hex-only.

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
