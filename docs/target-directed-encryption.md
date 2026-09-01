# Target-directed encryption

**Status:** design record, reconciled with the shipped API on 2026-08-28. The snippets below are the API as it ships in `stack-encrypt` (cipherstash-suite #2146, #2147); the async shape is specified by [RFC 0002](rfcs/0002-async-shape-for-target-directed-encryption.md).
**Date:** 2026-08-21
**Scope:** vitaminc (primitives), stack-encrypt (the new trait + batching), eql-bindings (one class of targets)

## Implementation notes

Everything this document decides shipped as designed: one trait on the output type, leaves handwritten, composites assembled from leaves, context threaded per value, ORE held rather than grown into vitaminc. Three things differ from the original sketches and are marked inline where they appear:

- **The derives are named after the traits they emit**, not `Encrypted`: `#[derive(EncryptFrom)]` / `#[derive(DecryptInto)]` in `stack-encrypt-derive`, under `#[stash(..)]` attributes. Hand-written impls remain the way to write a leaf (`packages/stack-encrypt/examples/encrypted_record.rs` shows one composite written out).
- **ORE/OPE use `cllw-ore`, not `ore-rs`,** and the per-field key is derived through the PRF *inside* the term — there is no `ProvidesOre` accessor and no key is ever handed back.
- **An empty context is rejected**, not permitted. `Aad::empty()` was proposed for non-EQL callers; the implementation refuses it (`Error::EmptyContext`).

## Problem

A stored encrypted value is rarely just a ciphertext. It is a *record*: the AEAD ciphertext of the plaintext, plus zero or more search terms derived from the same plaintext by different primitives, plus some metadata. EQL's `public.eql_v3_integer_ord_ore` is one instance —

```
{ v: schema version, i: identifier, c: ciphertext, ob: block-ORE term }
```

— but the shape is general. Any scheme that stores "the ciphertext and some derived terms alongside it" has it.

vitaminc today gives us the ciphertext (`Encrypt` / `Cipher`) and a PRF (`PrfValue` / `Prf`), each excellent at its own job and each producing *one* output. Nothing composes them into a record, decides which terms a given record needs, or lets one plaintext fan out to several primitives in a single batch.

We want the target type to answer all three questions, so that this compiles only when the pieces line up:

```rust
let x: IntegerOrdOre = 10.encrypt_into_with_context(&cipher, "users/age").await?;
```

**This must not be EQL-specific.** EQL payloads are one class of output. Nothing in the mechanism should know what a table or a column is.

## Prior art: the async-sync spike

`_spikes/async-sync/src/ore.rs` takes the **input-driven** route: a trait per index type, implemented per plaintext type.

```rust
pub trait OreEncrypt: Sized {
    fn encrypt_ore<C: OreCipher>(self, cipher: C) -> Composite<Self>;
}
pub struct Composite<T>(pub T, pub OreTerm);
```

`Composite` then implements `Encrypt` to lay out the map, and `EqlBuilder::with_ore(cipher)` stacks terms onto a value.

It works, and one idea in it is worth keeping (see [Analysis vs derivation](#analysis-vs-derivation)). Four things break at scale:

1. **No compile-time tie to a target shape.** `IntegerOrdOre` is `deny_unknown_fields` over exactly `v,i,c,ob`. A builder chain `.with_ore().with_eq()` produces `v,i,c,ob,hm`, which is not a domain. The shape is checked at Postgres, not by rustc.
2. **Combinatorics.** One trait per index × per plaintext type. `text_search` wants eq + ore + bloom: three traits, three calls, and the caller has to know which.
3. **Sync only.** `encrypt_ore` returns a value. ORE is local and sync; ZeroKMS-derived terms are async and batched. The spike has nowhere to join them.
4. **`Composite` writes the source back** (`self.value = val`), forcing the plaintext through the index path even when the index only needs to read it.

The root cause of 1 and 2 is direction: the *caller* assembles the record, so the type system never sees the record as a whole.

## Design

Invert it. One trait, on the output type, describing what that type is:

```rust
/// `Self` is an encrypted representation of `S`, producible by a cipher `C`,
/// under a context `Ctx`.
pub trait EncryptFrom<S, C: EncryptTarget, Ctx>: Sized {
    fn encrypt_from<'a>(source: &'a S, cipher: &'a C, context: Ctx) -> C::Output<'a, Self>
    where
        Self: 'a;
}

/// Implemented by ciphers: decides what an `EncryptFrom` implementation hands back.
pub trait EncryptTarget {
    type Error;
    type Output<'a, T> where Self: 'a, T: 'a;
}
```

Reads as a noun: *`EqualityTerm` is an encrypted form of `&str`*.

The output shape belongs to the **cipher**, not the trait — the same rule vitaminc follows for `Cipher::Ok` and `Prf::Ok<T>`. A cipher that does no I/O sets `Output<'a, T> = Result<T, Self::Error>`: no future, no `.await`. `StackCipher` sets `Output<'a, T> = Pending<'a, T, K>`, a request carrier: a local term resolves immediately, a ciphertext queues its data-key request, and merged pendings settle in one batched ZeroKMS call when awaited. The trait fixes neither a future nor an error type; RFC 0002 records why it must not.

The context is a parameter of the trait, not of the method, so that an implementation can say which contexts it accepts — see [Context](#context) below. The call-site sugar is `Into` over `From` — blanket, never implemented by hand — in two forms, the split of vitaminc's `encrypt` / `encrypt_with_aad`:

```rust
pub trait EncryptInto {
    /// Passes `()`: exists only for a `T` that needs no context from the caller.
    fn encrypt_into<'a, T, C>(&'a self, cipher: &'a C) -> C::Output<'a, T>
    where
        C: EncryptTarget,
        T: EncryptFrom<Self, C, ()> + 'a,
        Self: Sized;

    fn encrypt_into_with_context<'a, 'c, T, C, Ctx>(&'a self, cipher: &'a C, context: Ctx) -> C::Output<'a, T>
    where
        C: EncryptTarget,
        T: EncryptFrom<Self, C, Ctx> + 'a,
        Ctx: SuppliedContext<'c>,
        Self: Sized;
}
impl<S> EncryptInto for S { /* delegates to T::encrypt_from */ }
```

### Leaves are handwritten; composites are assembled

**Leaves** are the single-primitive types. Each names exactly one primitive, and that is the *only* place in the design where a primitive is named. As shipped in `stack-encrypt`:

```rust
// Every leaf, with `Ctx: EncryptContext<'c> + SuppliedContext<'c>` — a leaf refuses `()` by type.
impl<'c, S, K, Ctx>    EncryptFrom<S, StackCipher<K>, Ctx> for StackCipherText where S: Encrypt + Clone                     { ... }
impl<'c, S, K, Ctx>    EncryptFrom<S, StackCipher<K>, Ctx> for EqualityTerm    where S: PrfValue + Clone                    { ... }
impl<'c, S, K, O, Ctx> EncryptFrom<S, StackCipher<K>, Ctx> for MatchTerm<O>    where S: AsRef<str>, O: MatchConfig          { ... }
impl<'c, S, K, Ctx>    EncryptFrom<S, StackCipher<K>, Ctx> for OreTerm<S>      where S: CllwOreEncrypt + Clone + Send + 'static, S::Output: Send + 'static { ... }
```

EQL's wire newtypes (`Ciphertext`, `Hmac256`, `OreBlock256`) get the same treatment in `eql-bindings`, which owns them; encoding decisions (base85, block width) belong there, not in vitaminc or stack-encrypt.

> The leaf impls currently name `StackCipher<K>` rather than a capability bound. CIP-3897 tracks lifting each term into its own module with its own input trait and a capability-shaped cipher bound.

**Composites** fan out to each field's impl, merge the outputs, and assemble. Today that is written by hand — one impl, in the shape the derive will eventually generate:

```rust
impl<K, Ctx> EncryptFrom<u32, StackCipher<K>, Ctx> for EncryptedInt
where
    Ctx: Clone,                                              // fans out to every field
    StackCipherText: EncryptFrom<u32, StackCipher<K>, Ctx>,  // what each leaf demands,
    EqualityTerm: EncryptFrom<u32, StackCipher<K>, Ctx>,     //   inherited, not restated
    OreTerm<u32>: EncryptFrom<u32, StackCipher<K>, Ctx>,
{
    fn encrypt_from<'a>(source: &'a u32, cipher: &'a StackCipher<K>, context: Ctx) -> Pending<'a, Self, K>
    where Self: 'a,
    {
        StackCipherText::encrypt_from(source, cipher, context.clone())
            .zip(EqualityTerm::encrypt_from(source, cipher, context.clone()))
            .zip(OreTerm::<u32>::encrypt_from(source, cipher, context))
            .map(|((ciphertext, eq), ord)| Self { ciphertext, eq, ord })
    }
}
```

One context fans out to every field. `zip` concatenates the fields' requests, so the whole record is still one batched call when awaited. The where clauses are exactly the ones the derive writes — one `FieldTy: EncryptFrom<S, C, Ctx>` per field — so a record inherits its leaves' demand for a supplied context without naming it, and a hand-written composite that copies this shape rides along when the leaf bound tightens (vitaminc#291) instead of restating today's policy.

**The derive** writes exactly that impl from the struct:

```rust
#[derive(EncryptFrom)]
#[stash(plaintext = i16, plaintext = i32, plaintext = i64)]
struct IntegerOrdOre {
    #[stash(default = SchemaVersion::V3)] v: SchemaVersion,
                                          c: Ciphertext,
                                          ob: OreBlock256,
}
```

generating, per listed plaintext:

```rust
impl<K, Ctx> EncryptFrom<i64, StackCipher<K>, Ctx> for IntegerOrdOre
where
    Ciphertext:  EncryptFrom<i64, StackCipher<K>, Ctx>,
    OreBlock256: EncryptFrom<i64, StackCipher<K>, Ctx>,
    Ctx: Clone,
{ /* join both, assemble */ }
```

The capability bounds (`C: Cipher`, `C: ProvidesOre`) arrive **transitively from the field impls**. The macro emits one `where` clause per derived field and names no primitive, no capability, and nothing from EQL. Adding a scheme is a new field type plus its leaf impl; the derive is untouched.

### Which sources a target accepts

`EncryptFrom<S, C, Ctx>` is generic over `S`; only the derive's `plaintext` attribute pins it. Two modes:

- **Omit `plaintext`** — the derive emits a single impl generic over `S`. The accepted sources are then exactly the intersection of what the field types accept. Nothing to maintain.
- **List plaintexts** — one impl per listed type, restricting the target.

Use the list for EQL types. `eql_v3_integer_ord_ore` is a schema statement that the column holds an integer, and `OreBlock256` is width-agnostic on the wire, so the generic form would accept a `String` and hand Postgres a payload it rejects. That restriction is EQL's, declared by EQL. The mechanism stays open: non-EQL targets omit `plaintext`.

### Rows are the same mechanism

One level up, unchanged — same trait, now written by the derive:

```rust
#[derive(EncryptFrom)]
#[stash(row = User, context = "users")]
struct EncryptedUser {
    age:   IntegerOrdOre,   // from user.age,   under "users/age"
    email: TextEq,          // from user.email, under "users/email"
}

let row: EncryptedUser = user.encrypt_into(&cipher).await?;   // one batch, no context: the fields carry theirs
```

`row = User` infers each field's `from` (its own name) and the field half of
its context (`"<context>/<plaintext field>"`); the prefix is the required
container `context`, named explicitly — never inferred from the Rust type's
name, which two types can share and a refactor can change. `#[stash(from = ..)]`
and `#[stash(context = "..")]` on a field are the overrides, and
`#[stash(nested)]` marks a field whose type is itself a row carrying its own
contexts (it is handed `()`). The context is the AAD of every stored
ciphertext in the column, so renaming a plaintext *field* is still a data
migration: pin the old literal with `context = ".."` first.

Leaf, payload and row are the same trait, and a column of rows is `Vec<T>`'s structural impl over the same trait — `ages.encrypt_into_with_context(&cipher, ctx)` for a `Vec<u32>` is one batched call, and `users.encrypt_into(&cipher)` for a `Vec<User>` likewise. Recursion does the rest. Earlier sketches of this design had a separate input-side derive for rows — that was a second mechanism the naming was hiding.

### Relationship to `Encrypt`

`Encrypt` is not bypassed or superseded. It **is** the source-ciphertext field. The `Ciphertext` leaf impl is a bridge:

```rust
impl<'c, S, K, Ctx> EncryptFrom<S, StackCipher<K>, Ctx> for StackCipherText
where S: Encrypt + Clone, Ctx: EncryptContext<'c> + SuppliedContext<'c>,
{
    fn encrypt_from<'a>(source: &'a S, cipher: &'a StackCipher<K>, context: Ctx) -> Pending<'a, Self, K>
    where Self: 'a,
    {
        let aad = match supplied_aad(context) {   // validates and encodes; Error::EmptyContext on a degenerate one
            Ok(aad) => aad,
            Err(error) => return Pending::failed(cipher, error),
        };
        match source.clone().encrypt_with_aad(cipher, aad) {   // vitaminc Encrypt, untouched
            Ok(tree) => seal_pending(cipher, tree),              // one data-key request per leaf
            Err(_) => Pending::ready(cipher, Err(Error::Aead)),
        }
    }
}
```

(`Clone` because a composite hands the same borrowed source to several fields — open decision 1, resolved as the simple option.)

Every existing impl — `String`, `u32`, `Vec<T>`, `HashMap<K, V>`, `Protected<T>`, `Option<T>`, `Element<T>` — is therefore a valid source for free, and `#[derive(Encrypt)]` (PR #287) is what makes a nested struct usable as one.

Two layers, cleanly split:

| | drives | produces |
|---|---|---|
| `Encrypt` / `Cipher` | the cipher | one ciphertext |
| `EncryptFrom` | the target type | a record of derived outputs, ciphertext being one field |

## Capabilities

A cipher advertises what it can do by implementing traits. `StackCipher` implements vitaminc's `Cipher` directly. It does **not** implement `Prf`: it *holds* a `vitaminc_hmac::HmacSha256Prf`, keyed by the keyset's index key at construction, and exposes it through `prf()`. Term impls read the accessor.

**ORE is different, and vitaminc should not grow an ORE trait.** The scheme lives in its own crate and the cipher *holds* what it needs rather than implementing the scheme.

The original proposal was `ore-rs` behind a `ProvidesOre` accessor on the cipher. What shipped is `cllw-ore`, and the key never surfaces at all: `OreTerm<T>` / `OpeTerm<T>` derive the per-field CLLW key through the PRF (from the field context, never the plaintext) *inside* the term's PRF visitor, encrypt there, and hand back only the ciphertext. Under the 2-party PRF backend that means per-field key derivation is an auditable ZeroKMS event and no key exists on either side to be leaked.

The principle stands: capability accessors, not one god trait. The PRF is already held this way (`prf()`); any future primitive whose trait is owned elsewhere is absorbed the same way.

## Context, not cipher scoping

An EQL payload carries an identifier (`i`: table, column). Identifiers are an EQL concern and must not become cipher state.

vitaminc already has the generic notion, twice — `Aad<'a>` (aead) and `PrfContext<'a>` (prf), both PAE-framed domain separators, neither aware of tables. EQL's `Identifier` is just a value that converts into both:

```rust
pub trait EncryptContext<'a>: IntoAad<'a> + IntoPrfContext<'a> + Clone {}
impl<'a, T> EncryptContext<'a> for T where T: IntoAad<'a> + IntoPrfContext<'a> + Clone {}
```

`Clone` because one context fans out to every field of a record.

Context is threaded **per value**, as an argument. It is not baked into the cipher.

Whether the *caller* owes one is decided by the target type, at compile time. `Ctx` is a parameter of `EncryptFrom` so that each impl can bound it: a leaf demands `SuppliedContext` — every context type vitaminc provides except `()` — because it has nothing else to authenticate under; a record passes the caller's context to its fields and inherits their demand through its where clause; a row whose fields all name their own context never uses the caller's and is implemented for `()` alone. `encrypt_into(&cipher)` passes `()` and therefore resolves only against the last kind; everything else takes `encrypt_into_with_context` — and against a row, only `encrypt_into` does, since a supplied context would go nowhere. This is vitaminc's `encrypt` / `encrypt_with_aad` split, with the choice made by the type rather than at every call site. Whether a supplied context is also *non-empty* remains a runtime check at the leaf (`Error::EmptyContext`) until vitaminc carries non-emptiness in the type ([vitaminc#291](https://github.com/cipherstash/vitaminc/issues/291)).

A scoped cipher (`cipher.for_column("users", "age")`) was considered and rejected: it makes encrypting one row — several columns, several identifiers — into several scoped ciphers, which fights batching for no gain. With context as an argument, a row is one shared `&cipher`, many contexts, one flush.

### Recommendation: bind the identifier into the AAD

EQL's `i` field is currently unauthenticated metadata. A ciphertext from `users.email` can be transplanted into `users.name` and still decrypts. Passing the identifier as context — which reaches both `Aad` and `PrfContext` — closes that class of attack.

This stays a caller decision at the call site, not cipher state: non-EQL callers pass whatever context describes the field. What they may **not** pass is an empty one. With an empty context, equal plaintexts in different fields produce identical terms, every field shares one ORE/OPE key, and ciphertexts transplant between fields — so every built-in impl rejects it during the synchronous build (`Error::EmptyContext`), before any I/O. "Empty" is structural over the encoding: `()`, `""`, `None`, `Some("")` and `("", "")` are all empty. (cipherstash/vitaminc#291 tracks carrying non-emptiness in the type instead.)

## Batching and async

Awaiting at the leaf is one round-trip per value *unless* `Pending` is a deferred handle on a shared batch that flushes on first await. That is the whole reason the cipher implements `Cipher` and `Prf` together: one object, one keyset, one batch covering both the source ciphertext and every ZeroKMS-derived term in the record.

The row-level derive above is the entry point that makes this pay: one `.await` for a whole row rather than one per field.

## Analysis vs derivation

Worth preserving from the spike: `ExactIndex::analyze() -> AnalyzedExactIndex`.

Splitting **analysis** (tokenise, normalise, extract n-grams — pure, sync, keyless) from **derivation** (keyed, possibly async) is right, and text-match indexes cannot skip it. Under this design, analysis is a private stage inside a leaf impl (`MatchTerm<O>` tokenises before it derives; the tokenizer, `k` and `m` are type-level via `MatchConfig`), exposed as a public trait only if a custom analyser is needed.

## Naming

- **`EncryptFrom`** for the trait (first shipped as `EncryptedFrom`, renamed in review). Spelling the direction keeps bounds unambiguous, and it pairs with `encrypt_into` exactly as `From` pairs with `Into`; `DecryptInto` / `decrypt_from` mirror it.
- **`encrypt_into` / `encrypt_into_with_context`** for the two forms of the sugar, after vitaminc's `encrypt` / `encrypt_with_aad`; `_with_context` rather than `_with_aad` because here the value feeds the PRF domain separation as well as the AAD.
- **`#[derive(EncryptFrom)]` / `#[derive(DecryptInto)]`** for the macros, each named after the trait it emits, the way `Serialize` matches `derive(Serialize)`. `#[derive(Encrypted)]` — a noun on the struct — was the sketch; it names neither trait, and one noun cannot cover both directions.
- **`#[stash(..)]`** for the attribute, after the crate rather than after either derive, since both derives read the same annotations.
- **Avoid `CipherText` / `EncryptedValue`.** `CipherText` collides with vitaminc's `AesCipherText` container and with eql-bindings' `Ciphertext` newtype — which is a *field inside* these types, not the type itself.

An earlier iteration had two traits, `EncryptInto<T, C>` on the source and `DeriveFrom<S, C>` on the field type. They are the same relation written in opposite directions; the split was the main source of confusion and is gone.

## Decisions, as resolved

**1. Ownership at the bridge.** `Encrypt::encrypt_with_aad(self, ...)` takes ownership; `encrypt_from(source: &S, ...)` borrows, because k fields share one source. The `Ciphertext` bridge above does not compile as written. Options:

1. `S: Encrypt + Clone` on the bridge. Simplest. Costs k copies of the plaintext.
2. Blanket `impl<T> Encrypt for &T where T: Encrypt`. vitaminc already has `impl Encrypt for &str`, so the shape exists but is not systematic.
3. Derive hands ownership to the ciphertext field and borrows to the term fields. Cheapest; puts field-ordering knowledge into the macro.

**Resolved:** (1). `S: Encrypt + Clone` on the bridge; (2) later if the copies show up in a profile.

**2. Fan-out and zeroize.** **Resolved, and narrower than proposed.** The source reaches k consumers, but only the ciphertext's copy lives in `Protected` — it is held inside the pending and wiped as it seals. Term clones are ordinary values consumed during the synchronous build and dropped before any I/O; they are not wrapped. So the custody widening is bounded to the build phase for terms and to the pending's lifetime for the ciphertext. Stated in the `stack_encrypt::target` rustdoc ("Plaintext fan-out"), as this section asked.

**3. Orphan rule.** `impl<C> EncryptFrom<i64, C> for IntegerOrdOre` in eql-bindings is legal — `Self` is local. The reverse-direction sugar (`EncryptInto::encrypt_into` on `i64`) is a blanket impl over a local trait, also fine. Worth a compile test pinning both, since the layout puts the trait, the source type and the target type in three different crates.

**4. Error unification.** **Dissolved.** There is no per-target error: `EncryptTarget::Error` belongs to the cipher, and `StackCipher`'s `Error` already covers AEAD, PRF, ORE and ZeroKMS failures.

**5. Decrypt.** **Implemented** as `DecryptInto<P, C: DecryptTarget, Ctx>` on the encrypted type (first shipped as `DecryptFrom` on the plaintext; flipped so the implementable trait has the record as `Self`), with `DecryptFrom::decrypt_from` / `decrypt_from_with_context` as the blanket sugar on the plaintext. Only the source-ciphertext field participates (terms are one-way). The context bound is `DecryptContext` — `IntoAad` only, since decryption derives nothing — plus `SuppliedContext` at the leaves, as on the encrypt side.

**6. Where `EncryptFrom` lives.** **Resolved:** stack-encrypt. Argued here as stack-encrypt's, since target-directed assembly is the thing stack-encrypt adds and vitaminc's `Encrypt` already covers cipher-directed encryption. If it turns out to be useful to vitaminc consumers who never touch stack-encrypt, it could move down — but not before there is a second consumer.

## Non-goals

- EQL knowledge anywhere in vitaminc or in the derive macro.
- Replacing `Encrypt` / `Cipher`. This layer sits on top of them.
- Runtime-configured index sets. protect.js takes the index set from a runtime schema; in Rust with sqlx the target type is known at compile time, and this design spends that fact rather than reproducing the dynamic model.
