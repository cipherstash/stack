# Client key validation

This page defines how the SDKs check a ZeroKMS client key before they use it.
This page is for maintainers of the Go SDK, the TypeScript SDK, and the crates they share.

A client key must decode to a keyset with four valid permutations.
`p1`, `p2_from`, and `p2_to` must each list the numbers 0 to 15 once.
`p3` must list the numbers 0 to 32 once, so it has exactly 33 entries.
The SDK refuses any other key before it derives a key from it and before it sends a request to ZeroKMS.
No error message includes a value from the key.

## Why the check exists

A key that breaks these rules cannot work. Such a key can also fail badly.

zerokms-keyset re-encrypts key material by following each permutation's cycles.
With a repeated entry, that loop can run forever at full CPU and ignore the context's deadline.
With an entry out of range, it panics.
One changed character in `CS_CLIENT_KEY` was enough to cause the loop (#1850).
Before the check, the key was read without error, and the failure started only after the first request to ZeroKMS.

## What a client key contains

A client key is the CBOR (Concise Binary Object Representation) encoding of a v1 keyset, written as hex or as padded base64.
The SDKs accept hex in upper or lower case, or standard base64 with its padding.
The client ID is not part of the key. The caller gives it separately.

The keyset is a map with four fields.
Each field is a map with one field, `permutation`. That field is a list of small numbers.

| Field | What it permutes | Entries |
|---|---|---|
| `p1` | the 16 bytes of one block | 16, each of 0 to 15 once |
| `p2_from` | the 16 bytes of one block | 16, each of 0 to 15 once |
| `p2_to` | the 16 bytes of one block | 16, each of 0 to 15 once |
| `p3` | the blocks of key material | 33, each of 0 to 32 once |

The entries are secret key material.

## The rules

The check refuses a key when any of these is true:

1. The key is not hex or padded base64.
2. The decoded bytes are not CBOR with the fields of a v1 keyset.
3. `p1`, `p2_from`, or `p2_to` does not have exactly 16 entries.
4. `p3` does not have exactly 33 entries.
5. A permutation has an entry that is not below its length.
6. A permutation lists any entry more than once.

Rule 4 has its own reason.
zerokms-keyset generates every `p3` with 33 entries, and the key material ZeroKMS returns has 33 blocks of 16 bytes.
A `p3` of another length cannot be used, even when it is a valid permutation.
Without rule 4, such a key failed only after the load-keyset round trip to ZeroKMS.
The Go SDK reported `invalid input length: expected 512 bytes but received 528` for a `p3` of 32 entries.
In the TypeScript SDK, recipher panicked on first use.

The check does not branch on any one entry, because the entries are secret.
Only its result depends on them.

## When the check runs

The check runs when the key is read, before any key is derived and before any request to ZeroKMS.

### Go SDK

The Go SDK applies the check through the `stack-kms` crate.

1. `NewClient` checks rule 1 on the host, before it loads the crypto guest.
   A key from `CS_CLIENT_KEY` or `AccessKeyCredentials` is checked when it is read.
2. The guest's `se_cipher_init` parses the config. The parser reads the key with `ClientKey::from_encoded_v1`.
   That runs rules 2 to 6 in `stack-kms`.
3. Only after that parse does the guest connect to ZeroKMS.

The same rules apply to every other caller of `ClientKey::from_bytes`, `ClientKey::from_hex_v1`, `ClientKey::from_encoded_v1`, `V1KeySet::from_bytes`, or the `V1KeySet` deserializer.
`ClientKey::new_v1` does not check the keyset it is given.

### TypeScript SDK

The TypeScript SDK will apply the same rules through `protect-ffi`, in pull request #1947.
That pull request is not merged yet, so the TypeScript SDK does not check the key today.

In #1947, `newClient` checks a key passed as `clientOpts.clientKey` when it reads the options.
A key read from the profile store (`secretkey.json`) is checked as it is loaded, on the native build only.
Bytes that are not a keyset at all are left to cipherstash-client. cipherstash-client refuses them without deriving a key.

## What the caller sees

### Go

`NewClient` returns an error that matches `encrypt.ErrConfig` and `encrypt.ErrEncoding`.
The error does not match `auth.ErrConfig`.
The error carries a `Diagnostic` with:

- the code `stack_encrypt::client_key`
- a message that says what is wrong, such as `the client key does not decode to a valid keyset` or `CS_CLIENT_KEY is not hex or padded base64`
- a Help that names `CS_CLIENT_KEY` and says the key must be exactly as it was issued

### TypeScript, after #1947

`newClient` rejects with an error that starts `invalid clientKey (CS_CLIENT_KEY)` and says the key's permutations are not valid.
For a key from the profile store, the error names the profile store instead.

### Both SDKs

Every message is fixed text.
No message includes a value read from the key, such as an entry, a character, or its position.
`stack-kms` also replaces serde's own parse error, because that error can print a value it read.

## Changing the rules

The lengths 16 and 33 are constants in the code.
If ZeroKMS ever issues keys of another shape, both SDKs need a code change, or they will refuse those keys:

- Go: `BLOCK_LEN` and `BLOCK_COUNT` in `packages/stack-kms/src/key.rs`
- TypeScript: `BLOCK_LEN` and `BLOCK_COUNT` in `languages/typescript/packages/protect-ffi/crates/protect-ffi/src/keyset_check.rs`, from #1947

Keep the two checks the same.
`protect-ffi` repeats the check because the `stack-kms` function is private, and the two crates build against different versions of cipherstash-client and recipher.
