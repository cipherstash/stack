# RFC 0002 — The async shape of target-directed encryption

| | |
| -- | -- |
| **Status** | Accepted — implemented on PR #2146 (sem visitors) and #2147 (target layer) |
| **Author** | Dan Draper |
| **Area** | `packages/stack-encrypt` (`target`, `sem`, `cipher`), `vitaminc` (`prf`) |
| **Supersedes** | The "Batching and async" section of `target-directed-encryption.md` |
| **Prompted by** | Review of PR #2147 |

> **Companion:** [`target-directed-encryption.md`](../../target-directed-encryption.md) —
> the original design. Everything it says about *what* the target type decides
> stands. This RFC replaces only *how the async is shaped*, which the
> implementation got wrong.

## 1. Summary

`EncryptFrom` as implemented in #2147 hardcodes a boxed future as its return
type. Three consequences:

1. Every cipher is forced to be async, including ones that do no I/O.
2. Nothing can be batched — not the fields of one record, not a column of
   rows. A five-row insert is five ZeroKMS round-trips where `Encrypt` alone
   would make one.
3. The single 0KMS operation that will derive data keys **and** PRF values
   together is not merely unused, it is unreachable: by the time a composite
   sees its fields, each is a sealed-shut future with no inspectable requests.

The fix is to apply the rule vitaminc already follows everywhere else —
**build synchronously, settle once** — and to let the *cipher* own the output
type, exactly as `Cipher::Ok` and `Prf::Ok<T>` already do.

Call sites do not get worse. They get shorter.

## 2. What is wrong today

### 2.1 The trait decides the async, not the cipher

```rust
// packages/stack-encrypt/src/target.rs
pub type PendingEncrypt<'a, T, E> = Pin<Box<dyn Future<Output = Result<T, E>> + Send + 'a>>;

fn encrypt_from<'a, 'c, Ctx>(source: &'a S, cipher: &'a C, context: Ctx)
    -> PendingEncrypt<'a, Self, Self::Error>;
```

`EncryptFrom` is the only trait in the stack that does this. Its two
neighbours both hand the choice to the implementation:

| trait | output | who decides |
| -- | -- | -- |
| `Cipher::Ok` | `PendingStackCipherText` for `StackCipher`; a finished ciphertext for a local cipher | the cipher |
| `Prf::Ok<T>` | `ReadyPrf<T, Infallible>` for `HmacSha256Prf`; a real future for a future 2-party backend | the backend |
| `EncryptFrom` | `Pin<Box<dyn Future>>`, always | **the trait** |

A cipher that does no I/O still returns a future the caller must `.await`.

### 2.2 Nothing batches

`StackCipherText::encrypt_from` calls `cipher.encrypt(value, aad)`, which is
`encrypt_with_aad` **plus** `pending.seal(..)` — it settles immediately. So the
pending tree that exists precisely so leaves can share one `generate_keys`
call is built and consumed inside a single leaf.

The cost, from `examples/encrypted_record.rs`:

```rust
for age in ages {                                            // 5 ages
    let record: EncryptedInt = age.encrypt_into(&cipher, CONTEXT).await?;
    table.push(record);
}
```

Five `generate_keys` round-trips. The same five values through `Encrypt`
alone — `cipher.encrypt(vec_of_ages, aad)` — are **one**, because
`encrypt_seq` builds one tree and `key_count()` sums its leaves into one
payload batch.

The read path in the same example has the identical defect: one
`retrieve_keys` per row, in a loop.

The root cause is not the loop. It is that there is no `Vec` implementation,
so a column *cannot* be expressed as a single operation the way `Encrypt`
expresses it.

### 2.3 `try_join!` does not do what its comment claims

```rust
/// For that batching to be possible across a record's fields, composite
/// implementations must poll their field pendings **concurrently**
/// (e.g. `tokio::try_join!`), never sequentially.
```

Concurrency is not coalescing. Three independently constructed futures polled
at once issue three requests. Coalescing needs a shared request collector, and
there is nowhere to put one — each future has already closed over its inputs
before `try_join!` sees it.

(Today only the ciphertext branch does I/O, so a record costs one round-trip,
not three. The comment is still wrong about why, and the shape it recommends
is what blocks §2.2.)

### 2.4 SEM shaping happens inside the async

vitaminc's PRF already has the right seam: the backend produces blocks, and a
`PrfVisitor` turns blocks into whatever shape the caller wants —
`prf_visit_with_context(prf, ctx, visitor) -> P::Ok<V::Value>`. Nothing about
Bloom positions or CLLW ciphertexts needs to be async.

`sem`'s `derive_match` uses that seam correctly (`BloomVisitor`). The other
three do not:

```rust
// derive_equality — BlockVisitor, then shape in async code
let block = value.prf_with_context(prf, context).await?;
Ok(EqualityTerm(block))

// derive_cllw_key + derive_ore — BlockVisitor, then shape in async code
let block = context_bytes.prf_with_context(prf, ..).await?;
let key = cllw_ore::Key::from(block);
value.encrypt(&key)
```

Worse, all four `derive_*` are `async fn`, which collapses `P::Ok<V::Value>`
into an `.await` **inside stack-encrypt** — throwing away the backend's choice
of output type before the cipher ever sees it. That is the same mistake as
§2.2, one layer down: a deferred handle destroyed by the code that should have
been passing it along.

Pure validation (`require_context`, `MatchOptions::validate`,
`EmptyTermText`) also runs inside the async body, so a malformed call fails
after a round-trip rather than before one.

## 3. The rule

> **Build synchronously. Settle once. The settle point belongs to the cipher.**

vitaminc obeys this: `Encrypt` drives a `Cipher` with no I/O and yields
`Cipher::Ok`; whoever holds the `Ok` decides when — and how many at a time —
to settle. `EncryptFrom` must obey it too.

## 4. Design

### 4.1 The cipher owns the output type

```rust
/// Implemented by ciphers. Decides what `encrypt_from` hands back.
pub trait EncryptTarget {
    type Error;
    type Output<'a, T: 'a>: 'a where Self: 'a;
}

pub trait EncryptFrom<S, C: EncryptTarget>: Sized {
    fn encrypt_from<'a, 'c, Ctx>(source: &'a S, cipher: &'a C, ctx: Ctx) -> C::Output<'a, Self>
    where
        Ctx: EncryptContext<'c>;
}
```

- A synchronous cipher sets `Output<'a, T> = Result<T, Self::Error>`. No
  future, no `.await`.
- `StackCipher<K>` sets `Output<'a, T> = PendingEncrypted<'a, T, K>` (§4.3),
  which implements `IntoFuture`.

```rust
let t: EqualityTerm = "alice".encrypt_into(&stack_cipher, "users/email").await?;  // async backend
let t: LocalTerm    = "alice".encrypt_into(&local_cipher, "users/email")?;        // sync backend
```

(The bounds above are the shape, not the final spelling — `K: 'a` and the
GAT's implied bounds will surface during implementation. What must not change
is *where* the type is chosen.)

### 4.2 Type inference: why this works and the earlier attempt did not

The implementation notes record that an associated `Pending` type was tried
and defeated `let term: EqualityTerm = v.encrypt_into(..).await?`. That is
correct **for an associated type on the target**: normalizing `T::Pending`
requires selecting the `EncryptFrom` impl, which requires knowing `T` — the
very thing being inferred.

`C::Output<'a, T>` has no such cycle. Normalizing it requires only `C`, and
`C` is concrete at every call site (`&StackCipher<K>`). `T` survives as a
syntactic parameter of a concrete struct, exactly as it does in today's
`Pin<Box<dyn Future<Output = Result<T, E>>>>`, so the `.await?` unifies `T`
with the annotated binding through `PendingEncrypted`'s `IntoFuture` impl.

This distinction is the load-bearing part of the design and should be pinned
by a compile test.

### 4.3 `PendingEncrypted` — a request carrier, not a future

```rust
pub struct PendingEncrypted<'a, T, K> {
    cipher: &'a StackCipher<K>,
    requests: Vec<Request>,                     // Request::DataKey | Request::Prf
    fulfil: FulfilBox<'a, T>,
}

// The Send split mirrors today's `PendingEncrypt` alias and MUST carry over:
// the ZeroKMS futures are not `Send` on wasm32.
#[cfg(not(target_arch = "wasm32"))]
type FulfilBox<'a, T> = Box<dyn FnOnce(Responses) -> Result<T, Error> + Send + 'a>;
#[cfg(target_arch = "wasm32")]
type FulfilBox<'a, T> = Box<dyn FnOnce(Responses) -> Result<T, Error> + 'a>;

impl<'a, T, K: DataKeySource> IntoFuture for PendingEncrypted<'a, T, K> {
    type Output = Result<T, Error>;
    // Boxed future, cfg-split on Send exactly as above.
    fn into_future(self) -> ... {
        Box::pin(async move {
            let responses = dispatch(self.cipher, self.requests).await?;   // ONE call
            (self.fulfil)(responses)
        })
    }
}
```

Carrying `K` is what lets the type name the cipher it settles against; the
`EncryptTarget` impl is per-`K`, so `Output<'a, T> = PendingEncrypted<'a, T, K>`
is well-formed. (The alternative — erasing `K` behind a boxed dispatch
closure captured at construction — keeps the type two-parameter at the cost
of a second allocation per pending. Either works; carrying `K` is the default
because it is simpler and the type rarely appears in signatures outside
`encrypt_from`.)

`into_future` is the **only** place I/O happens, and the only place that knows
how to talk to 0KMS. With an empty request list it short-circuits: a
term-only target does zero round-trips. Requests are heterogeneous
(`DataKey` now, `Prf` later); a `fulfil` that draws a response of the wrong
variant — or the wrong count — is a composition bug and settles as an error
(`Error::ResponseShape`), never a panic.

Its API is small and is **the public surface third-party targets build
against** (§4.7):

```rust
impl<'a, T, K> PendingEncrypted<'a, T, K> {
    pub fn ready(cipher: &'a StackCipher<K>, result: Result<T, Error>) -> Self;
    pub fn request(cipher: &'a StackCipher<K>, requests: Vec<Request>, fulfil: ...) -> Self;
    pub fn map<U>(self, f: impl FnOnce(T) -> U + ...) -> PendingEncrypted<'a, U, K>;
    pub fn zip<U>(self, other: PendingEncrypted<'a, U, K>) -> PendingEncrypted<'a, (T, U), K>;
    // zip3 / zipN as needed; `all` for Vec (§4.4)
    pub fn all(items: Vec<PendingEncrypted<'a, T, K>>) -> PendingEncrypted<'a, Vec<T>, K>;
}
```

`zip` concatenates request vectors and splits the response vector back by
recorded length, so no `fulfil` can over-draw its neighbours' responses.

`StackCipherText::encrypt_from` stops calling `cipher.encrypt` and instead
keeps the tree it was always meant to keep:

```rust
let tree = value.encrypt_with_aad(cipher, aad)?;          // PendingStackCipherText, no I/O
requests = (0..tree.key_count()).map(|_| Request::data_key()),
fulfil   = move |keys| tree.seal_with(&mut keys.into_iter())
```

`key_count()` + `seal_with`'s draw-in-traversal-order is already the exact
invariant `zip` needs. The design is the existing machinery applied one level
up.

### 4.4 Composition is where batching comes from

Composites combine pendings **without awaiting them**, so requests merge:

```rust
impl<K> EncryptFrom<u32, StackCipher<K>> for EncryptedInt {
    fn encrypt_from<'a, 'c, Ctx>(source: &'a u32, cipher: &'a StackCipher<K>, ctx: Ctx)
        -> PendingEncrypted<'a, Self, K>
    {
        StackCipherText::encrypt_from(source, cipher, ctx.clone())
            .zip(EqualityTerm::encrypt_from(source, cipher, ctx.clone()))
            .zip(OreTerm::<u32>::encrypt_from(source, cipher, ctx))
            .map(|((ciphertext, eq), ord)| Self { ciphertext, eq, ord })
    }
}
```

No `tokio::try_join!`, no `Box::pin(async move ..)`, no error-conversion
where-clauses. This is roughly half the size of the current impl and is
directly emittable by `#[derive(Encrypted)]`.

Then the missing piece from §2.2:

```rust
impl<S, T, K> EncryptFrom<Vec<S>, StackCipher<K>> for Vec<T> where T: EncryptFrom<S, StackCipher<K>>
impl<S, T, K> EncryptFrom<Option<S>, StackCipher<K>> for Option<T>
```

which makes the column one operation, one await, one round-trip:

```rust
let table: Vec<EncryptedInt> = ages.encrypt_into(&cipher, CONTEXT).await?;
```

Batching comes from the **source shape**, exactly as it does for `Encrypt`.
There is no `seal_all`, no flush handle, and no two-step call site.

Elements of a `Vec` share one context deliberately: a column is one context.
(`Encrypt` separately refines per-element AAD via `Aad::for_sequence_element`;
the PRF context is not refined, so equal values in a column derive equal
terms — which is the point of an index.)

A caller who awaits per element still pays per element. That is true of
`Encrypt` too, is visible at the call site, and is acceptable.

### 4.5 SEM terms become visitors

Delete the four `derive_*` functions. Each term's `encrypt_from` does its pure
work up front, then derives through `prf_visit_with_context` with a visitor
that shapes the block:

| term | visitor | shaping |
| -- | -- | -- |
| `EqualityTerm` | `EqualityVisitor` | block → term |
| `MatchTerm<O>` | `BloomVisitor { k, mask }` | already correct; keep |
| `OreTerm<S>` | `OreVisitor(value)` | block → CLLW key → encrypt → term, all inside the visitor; the key never leaves |
| `OpeTerm<S>` | `OpeVisitor(value)` | as above, under the OPE domain |

`require_context`, `MatchOptions::validate` and the empty-token check move
ahead of the request, where they fail without a round-trip. The visitor owns
the plaintext it needs, which removes the clone-into-async-fn each term does
today and narrows the plaintext fan-out the module docs warn about — only the
ciphertext branch still needs an owned copy held until seal.

Owning the plaintext is not incidental for ORE/OPE, and it has a cost. The
cost: a visitor is `'static`, so ORE/OPE sources are `Send + 'static` —
literals still work, borrowed text becomes a `String` (`cllw-ore` gained
`CllwOreEncrypt`/`CllwOpeEncrypt` for `String` and `Vec<u8>`, byte-identical
to the borrowed impls). The reason: under the two-party PRF no CLLW key exists
on either side, so a visitor that *returns* a key — which is what the first
implementation did (`CllwKeyVisitor`, encrypting after the visitor) — has
nothing to return. The visitor has to be the whole ORE operation: PRF input
in, ciphertext out. Callers then see the surface the two-party backend will
have, and the key is a private detail of the local backend's visitor.

**How the value comes out synchronously.** No `SyncPrf` marker trait is
needed, but the mechanism deserves stating, because it is concrete-type
knowledge, not trait knowledge: term impls bind `StackCipher<K>`, whose PRF is
concretely `HmacSha256Prf`, whose `Ok<T>` is `ReadyPrf<T, Infallible>` —
and `ReadyPrf::into_result()` extracts without an executor. So today a term's
`encrypt_from` is:

```rust
let term = tokens
    .prf_visit_with_context(cipher.prf().clone(), context, BloomVisitor { k, mask })
    .into_result()                                  // ReadyPrf: sync, infallible backend
    .map_err(TermError::from_prf);
PendingEncrypted::ready(cipher, term.map_err(Error::from))
```

**The migration path is the argument for the visitor seam.** When the 2-party
ZeroKMS PRF backend replaces the local HMAC inside `StackCipher`, a term's
`encrypt_from` changes in exactly one way: instead of invoking the visitor
inline over a `ReadyPrf`, it pushes `Request::Prf { input, context }` and
invokes the **same visitor** inside `fulfil`, over the blocks that came back
in the batch response. The shaping code — Bloom positions, equality blocks —
does not change, because the visitor never knew which side of the round-trip
it ran on. ORE/OPE are the one place the visitor *internals* change, and they
prove the seam rather than break it: CLLW under a two-party PRF has no key,
so `OreVisitor` moves from `visit_block` (block → key → encrypt) to
`visit_seq` over per-prefix PRF outputs (one per plaintext bit), while
`OreTerm`'s `encrypt_from` and every call site stay exactly as they are. That swap is also what fuses terms and data
keys into the single combined 0KMS call: both are then rows in one
`requests` vector settled by one `dispatch`.

### 4.6 Errors belong to the cipher

`C::Output<'a, T>` has no error slot, so the error is `C::Error`, and
`EncryptFrom::Error` is dropped. `TargetError` and the six-line
error-conversion where-clauses on every composite go with it. Term errors
reach the cipher's error through `Error::Term(#[from] TermError)`; third-party
terms get an `Error::Other(Box<dyn std::error::Error + Send + Sync>)` escape;
`Error::ResponseShape` covers a mis-drawn response (§4.3).

### 4.7 The third-party recipe, revised

The current module docs teach external term authors to return
`Box::pin(async move ..)`. The replacement is shorter and does no async at
all until a deferred PRF exists:

```rust
impl<S, K> EncryptFrom<S, StackCipher<K>> for MyTerm
where
    S: PrfValue + Clone,
{
    fn encrypt_from<'a, 'c, Ctx>(
        source: &'a S,
        cipher: &'a StackCipher<K>,
        context: Ctx,
    ) -> PendingEncrypted<'a, Self, K>
    where
        Ctx: EncryptContext<'c>,
    {
        let context = context.into_prf_context().into_owned();
        let context = PrfContext::pae(&[b"my-crate/my-term/v1".as_slice(), context.as_bytes()]);
        let term = source
            .clone()
            .prf_visit_with_context(cipher.prf().clone(), context, MyVisitor)
            .into_result()
            .map(MyTerm)
            .map_err(|e| Error::Other(Box::new(e)));
        PendingEncrypted::ready(cipher, term)
    }
}
```

This commits `PendingEncrypted::ready` / `::request` — and therefore
`Request` (and enough of `Responses` for a `fulfil` to draw from) — to the
public API. That is deliberate: an extension point that only first-party code
can use is not an extension point. See §7.3 for what stays private.

## 5. Invariant this imposes on future backends

**A deferred output type must be a mergeable request carrier, not a
self-driving future.**

This is why `Cipher::Ok` is `PendingStackCipherText` rather than a future, and
it must hold for the 2-party ZeroKMS PRF backend too: if its `Prf::Ok<T>` is
`Pin<Box<dyn Future>>`, terms and data keys can never share a round-trip, and
the combined keys-and-PRF 0KMS operation becomes unreachable — silently, from
an implementation that looks perfectly reasonable in isolation.

Honesty about enforcement: today this is **guidance, not mechanism**. Nothing
in the `Prf` trait lets a caller decompose a foreign `Ok<T>` into requests
plus a continuation; `StackCipher` will merge PRF work by *being the caller*
of its own backend (§4.5), not by prying open a generic `P::Ok`. Making the
invariant structural — an `into_parts()`-style decomposition on deferred
outputs — is a future `Prf` trait extension, and should be designed with the
2-party backend, not before it. Until then the rustdoc on `Prf::Ok` /
`Cipher::Ok` can only warn (§8).

## 6. Impact

| file | change |
| -- | -- |
| `src/target/{mod,pending,request}.rs` | `EncryptTarget` + GAT; `Pending` (with the wasm32 `Send` cfg-split carried over from `PendingEncrypt`); drop `PendingEncrypt` alias, `EncryptFrom::Error`, `TargetError`. Split in review so `Pending` and `Request`/`Responses` carry their own unit tests |
| `src/sem/mod.rs` | four visitors in, four `derive_*` out; validation moves ahead of the request; ORE/OPE encrypt inside the visitor (`Send + 'static` sources) |
| `packages/cllw-ore` | `CllwOreEncrypt`/`CllwOpeEncrypt` for `String` and `Vec<u8>`, delegating to the borrowed impls |
| `src/cipher.rs` | `StackCipher: EncryptTarget`; `dispatch`; `Error::Term`/`Error::Other`/`Error::ResponseShape` |
| `examples/`, `tests/` | column encrypted as a `Vec`, not a loop; `try_join!` gone; tokio dev-dep drops out of the record shape |

Wire format is untouched. `tests/term_bytes.rs` is the guard: the four pinned
derivations must produce identical bytes before and after.

## 7. Decisions — resolved

1. **Composite impls bind `StackCipher`** (decided): records carrying SEM
   terms need a PRF that vitaminc's ciphers do not have, and the derive emits
   concrete code either way. The `ready`/`map`/`zip`/`all` combinators live on
   `Pending`; they lift onto `EncryptTarget` if a second async cipher ever
   appears.
2. **Decrypt landed with this change** (decided): `DecryptTarget`,
   `DecryptFrom`, `DecryptExt` and `DecryptContext` mirror the encrypt side;
   the `Vec` implementation batches a column of rows into one
   `retrieve_keys`. The derive will emit both directions from day one.
3. **`Request` is public but opaque** (decided): constructors only
   (`Request::generate_data_key()`, `Request::retrieve_data_key(iv, tag)`,
   later a PRF request and a keyset override), internals private. `Responses`
   is a drawing handle (`next_generated_key()` / `next_retrieved_key()`),
   never inspectable, and each fulfilment is scoped to exactly the responses
   its own requests asked for — over-drawing is `Error::ResponseShape`, not a
   sibling's stolen key.
4. **Per-field keysets are achievable in this shape**
   ([CIP-3870](https://linear.app/cipherstash/issue/CIP-3870)), and the
   request-carrier design is specifically what makes them so: `Request` being
   opaque means a keyset override field is a non-breaking addition; `dispatch`
   then groups requests by keyset and issues one call per distinct keyset,
   re-zipping responses into draw order — no trait or `Pending` surface
   change. Per-keyset *terms* need per-keyset index keys, so "load the index
   key for keyset X" becomes a request itself, with the visitor running in the
   fulfilment. The genuine blocker is decrypt: `SealedValue` records no
   keyset, so per-leaf retrieve routing needs the wire change already parked
   in CIP-3870.

### Deviations from the proposal above

The implementation kept the design and changed three names/details:

- **`Pending<'a, T, K>`**, not `PendingEncrypted` — one carrier serves both
  directions (it is `DecryptTarget::Output` too), so the direction is not in
  its name.
- **`DecryptContext`** (`IntoAad + Clone`) joined `EncryptContext`: decryption
  derives nothing, so it must not demand a PRF conversion.
- **`dispatch` issues one call per request *kind*** (at most one
  `generate_keys` + one `retrieve_keys`, sequentially — a mixed batch is rare
  today). When ZeroKMS grows the combined keys-plus-PRF operation, `dispatch`
  is the one function that changes.

Review of #2146/#2147 then corrected three more:

- **`EncryptFrom` / `DecryptFrom`** — first shipped as `EncryptedFrom` /
  `DecryptedFrom`; renamed to the names this RFC uses.
- **`target.rs` became `target/{mod,pending,request}.rs`** so the request
  carrier and the response handle have unit tests of their own (call counts
  per batch, per-kind response scoping, over-draw, zero-I/O `ready`).
- **ORE/OPE first shipped as `CllwKeyVisitor`** — a visitor that returned the
  CLLW key, with encryption after it. Reverted to the §4.5 shape
  (`OreVisitor(value)` / `OpeVisitor(value)`); §4.5 records why a
  key-returning visitor cannot survive the two-party backend. Wire format
  unchanged (`tests/term_bytes.rs`).

The final review then held the implementation to two of this RFC's own
claims:

- **"`dispatch` is the one place that changes" was not yet true.** The
  cipher-directed `seal` and `decipher` carried their own copies of the
  ZeroKMS plumbing. They now build a `Pending` through the same
  `seal_pending` / `decipher_pending` builders the target impls use and
  settle it via a crate-private, unboxed `Pending::settle`; there is one
  walker, one wire convention, one dispatch, and a test that ciphertext from
  either API opens under the other.
- **"Rejected during the synchronous build, before any I/O" had gaps.**
  `Pending` now records a build-time failure and `zip`/`all` drop the
  assembly's requests when one side has failed, so a misconfigured field
  never mints keys for its siblings; the empty-context guard is structural
  over PAE (so `None` / `Some("")` / tuples of empties are caught) and runs
  on columns and optionals even when there is nothing to encrypt; and merging
  pendings from different ciphers is `Error::CipherMismatch` rather than a
  `debug_assert`.

## 8. Where findings get recorded

Three homes, by durability:

- **Trait invariants** (§5, and "the visitor shapes, the backend only
  produces blocks") → rustdoc on `Prf::Ok<T>` in `vitaminc/packages/prf/src/traits.rs`,
  and on `Cipher::Ok` in `vitaminc/packages/aead/src/cipher.rs`. A backend
  author reads the trait, not this repo's RFC directory. These are the two
  places where getting it wrong is invisible until it is expensive.
- **The reasoning** (§2–§4) → this RFC. It explains why the obvious
  implementation is wrong, which rustdoc is the wrong length for.
- **The work** → Linear under CIP-3764.

## 9. Non-goals

- Changing what the target type decides. `target-directed-encryption.md`
  stands.
- Wire format changes.
- A flush handle, an ambient batch registry, or timing-window coalescing.
  Batching is expressed by the source shape and is visible at the call site.
