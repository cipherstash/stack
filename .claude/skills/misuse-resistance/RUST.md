# Misuse resistance in Rust

Techniques for reaching each rung of the ladder in [SKILL.md](SKILL.md). The snippets use only `std` so they show the pattern; in production, reach for a vetted crate for the secret type itself (`vitaminc-protected`, or `zeroize` plus `subtle`). Cryptographic internals are `todo!()`, so a copied snippet fails loudly instead of shipping a placeholder: do the same in your own examples.

## Rung 1: impossible to get wrong

Remove the parameter. If the library generates the nonce, no caller can reuse one. A random 96-bit nonce still bounds how much one key may seal: past about 2³² messages the chance of a repeat is no longer negligible (NIST SP 800-38D), so a long-lived key must be rotated, or the cipher must use a longer nonce (XChaCha20-Poly1305) or a nonce-misuse-resistant mode (AES-GCM-SIV). The caller still cannot get the nonce wrong; the library owns that limit too.

```rust
pub struct Ciphertext { nonce: [u8; 12], sealed: Vec<u8> }

pub struct Cipher { /* key, rng */ }

/// Opaque: says that sealing failed, not why.
pub struct EncryptError;

impl Cipher {
    // No `nonce` argument: the cipher draws a fresh one per call. Drawing it can
    // fail (the OS RNG is unavailable), so the call returns an error, not a panic.
    pub fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<Ciphertext, EncryptError> {
        let nonce = self.fresh_nonce()?;
        let sealed = self.seal(&nonce, plaintext, aad)?;
        Ok(Ciphertext { nonce, sealed })
    }

    fn fresh_nonce(&self) -> Result<[u8; 12], EncryptError> { todo!("draw from the CSPRNG") }
    fn seal(&self, _nonce: &[u8; 12], _plaintext: &[u8], _aad: &[u8]) -> Result<Vec<u8>, EncryptError> { todo!("AEAD seal") }
}
```

Make the valid value the only value. Private fields plus one constructor mean every instance passed the check. A blanket implementation over a sealed trait means no downstream type can supply its own, divergent, implementation.

```rust
mod sealed { pub trait Sealed {} }

/// Implemented only inside this crate.
pub trait Algorithm: sealed::Sealed { const NAME: &'static str; }

pub struct Aes256Gcm;
impl sealed::Sealed for Aes256Gcm {}
impl Algorithm for Aes256Gcm { const NAME: &'static str = "AES-256-GCM"; }
```

## Rung 2: won't compile

Put the invariant in the type. State the invariant first, in one sentence a reviewer can test; a type that says "verified" without saying under which key promises more than it delivers (rule 6).

- **Newtypes over raw bytes.** `Key([u8; 32])`, never `&[u8]`. A key, a nonce and a ciphertext should not be interchangeable.
- **Fixed-size arrays for fixed lengths.** A `[u8; 32]` argument makes the length check infallible and removes the error path; a const generic `[u8; N]` does the same for a family of sizes. Take runtime-length material through a separate, fallible `try_from_bytes` that rejects weak inputs.
- **Typestate.** Encode protocol steps as types, so the unsafe order does not type-check. Carry "by whom" in the type too: a message verified under the wrong key is then a type error, not a review question.

```rust
use std::marker::PhantomData;

/// The role a verifying key was loaded for. One marker per role, assigned where
/// the key is loaded from configuration, so a message verified under a key of
/// another role has another type.
pub trait Role {}
pub struct Issuer;
impl Role for Issuer {}

pub struct VerifyingKey<R: Role> { /* public key */ role: PhantomData<R> }

pub struct Unverified { message: Vec<u8>, signature: [u8; 64] }
pub struct Verified<R: Role> { message: Vec<u8>, role: PhantomData<R> }

pub struct BadSignature;

impl Unverified {
    /// Anyone may hold a message they received; only `verify` turns it into a `Verified`.
    pub fn new(message: Vec<u8>, signature: [u8; 64]) -> Self {
        Self { message, signature }
    }

    // The caller supplies a key, never the check: the library owns the
    // verification, so there is no predicate to stub out with `|_| true`.
    // The result carries the key's role, so "verified" always says by whom.
    pub fn verify<R: Role>(self, key: &VerifyingKey<R>) -> Result<Verified<R>, BadSignature> {
        key.check(&self.message, &self.signature)?;
        Ok(Verified { message: self.message, role: PhantomData })
    }
}

impl<R: Role> VerifyingKey<R> {
    fn check(&self, _message: &[u8], _signature: &[u8; 64]) -> Result<(), BadSignature> {
        todo!("signature verification")
    }
}

/// Only messages verified under the issuer's key can be processed. A message
/// verified under a key of another role has another type and does not compile
/// here. `Verified` has private fields, so the only way to obtain one is a
/// signature check the library performs.
pub fn process(message: Verified<Issuer>) -> usize { message.message.len() }
```

- **Consume one-shot values.** Take `self` by value for anything that must be used once (a nonce, a one-time key, a request token), so a second use is a move error.
- **Withhold dangerous traits.** A secret type implements no `Copy` (a copy has no owner to wipe it on drop), no `Default` (a default key is an all-zero key), no `Deref`, no derived `PartialEq` (it is not constant-time), no `Display`, and no `Serialize` unless through an explicitly named export type.
- **Post-monomorphisation checks.** A `const` assertion can reject a generic parameter at compile time. Use a named associated `const` item, not an inline `const { }` block: trybuild does not report inline-const failures.
- **Test the guarantee.** Every rung-2 claim gets a compile-fail test (trybuild) showing the misuse does not compile. Without one, a refactor can silently drop it to rung 6 or 7.

## Rung 3: fails the build

A check that blocks the merge is as strong as a type check: the mistake cannot reach `main`. A warning that nothing denies is read once, then tuned out, so it counts as rung 7.

- `#[must_use]` on results, tags, and anything whose silent drop is a bug, with `#![deny(unused_must_use)]` in the crate root.
- `#[deprecated(note = "use X instead: <reason>")]` names the replacement, with `#![deny(deprecated)]` once callers have migrated.
- Ship a `clippy.toml` snippet with `disallowed-methods` / `disallowed-types` for downstream users (for example, banning a non-cryptographic RNG in key-handling code). Run clippy with `-D warnings` in CI.
- Every escape hatch (`risky_*`, `hazmat`, `*_unchecked`) has an allowlist of call sites that CI checks. A new call site fails CI until a reviewer adds it, with a reason.

## Rung 4: the simplest use is correct

- The shortest constructor yields the secure configuration. Options exist only to make it stricter, or sit behind an explicitly named alternative.
- Prefer one function with no choices over a builder with secure defaults: a builder invites changing them.

## Rung 5: the name says how to use it

Name escape hatches so they are obvious and greppable: `risky_unwrap`, `risky_ref`, a `hazmat` module, an `insecure-*` feature, `*_unchecked`. Obvious, not easy: a caller who needs a legacy algorithm should find the door, and a reviewer should find every use with one search. A search is a human step, so the allowlist in rung 3 is what makes the count hold.

## Rung 6: fails loudly at runtime

- Return `Result` with an error that reveals nothing about the secret. Cipher failures are one opaque error: a wrong key, a wrong AAD and a tampered ciphertext are indistinguishable.
- Refuse weak input (short keys, empty contexts) at construction, once, then carry the proof in the type.
- Return errors rather than panicking on conditions that depend on a secret: a panic is an observable side channel.

## Secret types: the full checklist

A type holding a secret:

- wipes on drop (`Zeroize` + `ZeroizeOnDrop`, or a wrapper that does it);
- prints an opaque `Debug`, no `Display`;
- exposes its contents only through named, greppable methods, and offers `map`-style combinators so most code never unwraps;
- compares in constant time, if at all;
- serialises only through an explicit export type;
- for process-lifetime secrets, lives in memory that is both locked against swap and excluded from core dumps, since nothing drops a static or a killed process. These are two separate protections: `mlock` keeps pages out of swap but does not keep them out of a dump, which needs its own call (`madvise(MADV_DONTDUMP)` on Linux and Android). Check that both succeeded.

## Errors

- `Display` and `Debug` on error types never include plaintext, keys, or values derived from them. Report the path or position (`field "email"`), not the value. Redact messages that come from user-supplied types. Check what library errors carry before forwarding them: `std::env::VarError::NotUnicode` holds the variable's raw bytes.
- Mark error enums `#[non_exhaustive]` so variants can be added without a breaking change.

## Features

Optional functionality goes behind cargo features. Dangerous functionality goes behind a feature whose name says so, off by default.

## What the compiler does not check

"If it compiles, it is secure" holds only under assumptions. State them in the crate root and check them in CI:

- No `unsafe`: `#![forbid(unsafe_code)]` in every crate that does not need it, and `cargo geiger` (or an equivalent) on dependencies. Memory-safety bugs were the largest class in the C libraries Blessing et al. 2021 studied; Rust prevents them only where `unsafe` is absent. Where a crate needs `unsafe` (memory locking, FFI), confine it to one module, give each block a `// SAFETY:` comment, run the module under Miri, and count the blocks.
- No unbounded escape hatch: every `risky_*` call site is on the allowlist (rung 3).
- No `#[allow]` on the lints above without a reason on the same line.
- A change that adds any of these blocks review until a second person has read it. An agent writing the code does not change that.
