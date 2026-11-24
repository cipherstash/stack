---
name: vitaminc
description: Using the vitaminc Rust crates for secrets and cryptography. Use when Rust code holds keys, passwords, tokens or other secrets; generates random values or passwords; encrypts or decrypts values or structs; wraps keys; derives keyed hashes or searchable index terms; or compares secrets.
---

# vitaminc

Internal skill. It lives in `.claude/skills/` on purpose: `skills/` ships to customers inside the `stash` tarball, and this skill must not.

This skill is a copy. The source is `.claude/skills/vitaminc/` in [cipherstash/vitaminc](https://github.com/cipherstash/vitaminc), at commit `5dbbafaa1` on `main` (24 November 2026). `RECIPES.md` is unchanged. `SKILL.md` differs in this note only. To update the copy, copy the two files again, then restore this note. Propose a change to a rule or a recipe in vitaminc, not here, so the two copies stay the same.

vitaminc is a suite of Rust crates that replace common cryptography footguns with types. When Rust code touches a secret, use the vitaminc type for the job instead of a raw value or a hand-rolled routine.

The compiler then checks the code under three assumptions. There is no `unsafe`. Every `risky_*` call is one the project has listed and reviewed. No `#[allow]` disables the lints that enforce this. Outside those assumptions the reviewer is checking again, not the compiler.

For the reasoning behind these types, and for designing APIs of your own, see the `misuse-resistance` skill.

## Install

Use the facade crate with a feature per capability, and import through it (`vitaminc::protected::Protected`):

```sh
cargo add vitaminc --features protected,random,encrypt,context
```

Or add individual crates (`cargo add vitaminc-protected`). All crates release together under one version. Deriving `Encrypt`/`Decrypt` also needs a direct `vitaminc-aead` dependency, because the generated code names that crate.

## Task map

| Task | Use | In place of |
|---|---|---|
| Hold a key, token, password or other secret | `Protected<T>` (`protected`) | `String`, `Vec<u8>`, `[u8; N]`, `Zeroizing<T>` |
| Hold a key for the whole process | `Locked<T>` (`protected`) | a `static` or lazily initialised byte array |
| Compare secrets or tags | `Equatable<Protected<T>>`, `TimingSafeEq` (`protected`) | `==` |
| Hash secret input | `ProtectedDigest` (`protected`) | a digest fed raw secret bytes |
| Require a non-empty label or context | `NonEmpty<T>`, `nonempty!` (`protected`) | `&str` |
| Generate random bytes, keys or structs | `SafeRand` + `Generatable` (`random`) | `rand::thread_rng`, `rand::random` |
| Pick a random index | `SafeRand::next_below` (`random`) | `rng.gen::<u32>() % n` |
| Generate a password | `Password`, `AlphaNumericPassword`, `AlphaPassword` + `into_protected_string` (`password`) | `rand`'s `Alphanumeric` sampler, or characters drawn by hand |
| Encrypt a value or struct | `encrypt` / `decrypt`, `Aes256Cipher`, `#[derive(Encrypt, Decrypt)]` (`encrypt`) | an AEAD crate with nonces managed by hand |
| Name what a ciphertext or index term belongs to | a type of your own implementing `IntoContext` (`context`) | a `format!` string built at each call site |
| Wrap a data key under a key-encryption key | `Key::wrap` / `Key::from_wrapped` (`encrypt`) | encrypting key bytes as ordinary data |
| Keyed hash, blind index, equality term | `HmacSha256Prf` + `PrfValue::prf_with_context` (`hmac`, `prf`) | an unkeyed hash, or HMAC with no context |
| HMAC with the key held in AWS KMS | `AwsKmsHmac` (`aws-kms`) | fetching the key into process memory |
| Order-revealing or normalised index terms | `vitaminc-ore`, `vitaminc-normalize` (`ore`, `normalize`) | encoding values for comparison by hand |

Working code for each common task is in [RECIPES.md](RECIPES.md). Read the recipe before writing the code, and copy it as written. For rows without a recipe, read the crate's docs on docs.rs.

## Rules

- **Wrap at the source.** A secret becomes `Protected` the moment it is read or generated (`Protected::generate_ok`, `Protected::random`) and stays wrapped until the last call that needs it. Transform it with `map`, `zip` and `flatten`, which keep the result wrapped. Their closures receive the bare value and own it: return it, or something that still holds it, rather than dropping it inside the closure, where nothing wipes it. To read a value without taking it, borrow with `risky_ref` while the wrapper keeps ownership, and the wrapper still wipes it on drop.
- **Unwrap only at a boundary.** `risky_unwrap` hands the plain value to code outside vitaminc, along with the duty to wipe it and keep it out of logs. Use it only at the call into an external API that must own the value. Prefer `risky_ref` there, kept inside that one call.
- **Errors carry no secret.** An error from the code that reads a secret may hold the value (`std::env::VarError::NotUnicode` holds the raw variable). Map it to an error of your own that says nothing about the value before it can reach a log.
- **Bind every ciphertext to its place.** Pass associated data naming what the ciphertext belongs to as the third argument to `encrypt` and `decrypt`, and spell it as a type: one newtype per kind of record, implementing `IntoContext`, that names the record and carries its id (see the encrypt recipe). The write and the read then cannot disagree, and a ciphertext moved to another record fails to open. `()` is for values that truly belong nowhere. The parameter also accepts a bare `&str`, so `""`, a typo, or a value copied from another record all compile. That is a gap in vitaminc, not a design choice: never pass a string.
- **Name every derivation.** Give `prf_with_context` a context naming the index and its version, checked non-empty at compile time with `nonempty!("users/email/exact/v1")`, and use the same input type and context for writes and for queries.
- **Keys come from a generator, an unwrap or the secret store**: generate a data key once with `Key::random(&mut SafeRand)`, store it wrapped, and load it with `Key::from_wrapped`. The root key-encryption key is the one key built from bytes: fetch its 32 bytes from the secret store at startup and pass them straight to `Key::from`, keeping no other copy. No vitaminc API fetches an AES key from a KMS (`AwsKmsHmac` computes HMACs only), so the secret store is the caller's code. A key written into the source, such as `Key::from([0u8; 32])`, is a test fixture. Rule 3 of `misuse-resistance` says key loading is the library's job, so the caller-written secret store and `Key::from` taking a plain array are both gaps in vitaminc, not design choices.
- **Rotate before the nonce budget runs out.** `Aes256Cipher` draws a random 96-bit nonce for every sealed leaf (each encrypted field and each sequence element), and nothing counts them. Keep the leaves sealed under one key, across every cipher instance and restart, well below 2³² (NIST SP 800-38D). Past that, the chance of a repeated nonce is no longer negligible, and a repeat under AES-GCM exposes plaintext and the authentication key. Give each tenant or table its own data key, version it (`dek/1`, `dek/2`), and wrap a new one before the count gets close.
- **Log the error kind, never the value.** Cipher failures are deliberately the opaque `Unspecified`: a wrong key, a wrong AAD and a tampered ciphertext look the same.

## Behaviour to know

- `#[aead(passthrough)]` stores a field in the clear by design: it is neither encrypted nor authenticated, so it can be read, edited or removed in storage while every encrypted field beside it still decrypts. Use it only for non-sensitive fields, treat what it returns as untrusted input, and never let it decide authorization, tenancy or which record to trust. A value that must be readable but tamper-evident belongs in the associated data.
- In an encrypted sequence, each element is bound to the sequence but not to its index, and the element count is not authenticated. If order or completeness matters, put it in the value or the associated data.
- `Aes256Cipher` is not `Sync` (its nonce generator is a `RefCell`). Build one per thread or per task rather than sharing one.
- `Protected` is never `Copy`. Duplicate it with an explicit `clone()`; each clone is wiped when dropped.
- `Locked` is best-effort by default: when the OS refuses to lock memory, the value still exists and `lock_error()` says why. Call `require_locked()`, or set `LockPolicy::Strict` at startup, when locking is mandatory.
- `vitaminc-password` types hold their characters in a `Protected` array and have no `Display`, equality or raw constructor. `into_protected_string` exports a `Protected<String>`, allocated once at full length so no unwiped copy is left behind. `into_unprotected_string` returns a plain `String` that nothing wipes: use it only where an external API must own one. The length is a const generic with a minimum (20, 22 or 23 by alphabet) that fails compilation below it.
