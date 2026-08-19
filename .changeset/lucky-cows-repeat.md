---
'stash': patch
---

Document in the bundled `stash-auth` skill that `CS_CLIENT_KEY` must be
hex-encoded. Hex is what `stash env` emits and what the skill's variable table
already stated, but the decoder underneath used to fall back to standard padded
base64 — the encoding the Rust `stash-profile` crate uses for
`~/.cipherstash/secretkey.json` on disk — so a key copied out of that file
happened to work despite never being a supported input. That fallback is gone
and such a key is now rejected at client construction, with a message that
deliberately withholds detail — so the skill names the symptom and the fix.

The recovery advice is split by entry point: falling back to the profile store
works on the native entry, but not on `@cipherstash/stack/wasm-inline`, where
`clientId` and `clientKey` are required config and the target runtimes have no
profile store to read. Re-encoding as hex is the fix that works on both.
