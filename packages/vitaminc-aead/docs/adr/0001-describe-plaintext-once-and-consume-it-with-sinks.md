---
status: accepted
---

# Describe plaintext once and consume it with sinks

> **Implemented** in #416–#448. This document describes what landed. The
> source trait is called `Plaintext` here and in the code at the time of
> writing; it ships as `Encrypt` (#449), and `Plaintext` is its interim
> name. See [Names](#9-names).

When this was decided, Stack Encrypt was unreleased, so vitaminc's
encryption data model was still open to change. This decision replaced the
`Encrypt`/`Cipher` and `Decrypt`/`Decipher` trait pairs and the `Value`
enum with a serde-style split between a type that describes itself
(`Plaintext`) and the things that consume that description (`Sink`).
Encryption, index terms, transport frames, host-language builders and typed
decoding are all sinks over one walk. Ciphers shrink to sealing and opening
bytes, synchronously or asynchronously, and a remote key provider seals a
whole document in one round trip.

## Context

### Before this decision (vitaminc 0.5.1)

`vitaminc-aead` had four traits and two sub-protocols on each side:

```rust
// Encrypt side: the type drives the cipher.
pub trait Encrypt {
    fn encrypt_with_aad<'a, C, A>(self, cipher: C, aad: A) -> Result<C::Ok, C::Error>
    where
        C: Cipher,
        A: IntoAad<'a>;
}

pub trait Cipher: Sized {
    type Ok;
    type Error;
    type Passthrough;
    type SeqCipher: SeqCipher<Ok = Self::Ok, ...>;
    type MapCipher: MapCipher<Ok = Self::Ok, ...>;

    fn encrypt_bytes_vec<'a, A>(self, data: Protected<Vec<u8>>, aad: A) -> Result<Self::Ok, Self::Error>;
    fn encrypt_seq<'a, A>(self, size_hint: Option<usize>, aad: A) -> Self::SeqCipher;
    fn encrypt_map<'a, A>(self, aad: A) -> Self::MapCipher;
    fn encrypt_none<'a, A>(self, aad: A) -> Result<Self::Ok, Self::Error>;
    fn passthrough(self, value: Self::Passthrough) -> Result<Self::Ok, Self::Error>;
}

// Decrypt side: the cipher drives a visitor.
pub trait Decrypt<'c>: Sized + Send {
    fn decrypt_with_aad<'a, D, A>(decipher: D, aad: A) -> D::Ok<Self>
    where
        D: Decipher<'c>,
        A: IntoAad<'a>;
}

pub trait Decipher<'c>: Sized {
    type Ok<T> where T: Send + 'c;   // Result<T, Unspecified>, or BoxFuture<'c, Result<..>>
    type Passthrough: Send + 'c;

    fn map_ok<T, U, F>(ok: Self::Ok<T>, f: F) -> Self::Ok<U>;
    fn decrypt_bytes<'a, V, A>(self, visitor: V, aad: A) -> Self::Ok<V::Value>;
    fn decrypt_seq<'a, V, A>(self, visitor: V, aad: A) -> Self::Ok<V::Value>;
    fn decrypt_map<'a, V, A>(self, visitor: V, aad: A) -> Self::Ok<V::Value>;
    fn decrypt_any<'a, V, A>(self, visitor: V, aad: A) -> Self::Ok<V::Value>;
    fn decrypt_passthrough(self) -> Self::Ok<Self::Passthrough>;
    fn decrypt_option<'a, T, A>(self, aad: A) -> Self::Ok<Option<T>>;
}
```

`DecipherVisitor` (with `visit_bytes_vec`, `visit_seq`, `visit_map`,
`visit_none`, `visit_passthrough`), `SeqAccess` and `MapAccess` completed the
decrypt side. `vitaminc-aead-value` added `Value`, a twenty-three-variant enum
(twenty scalars, array, object and passthrough) that host languages convert
into and out of, with a frozen one-byte tag per scalar variant, a `ValueKind` inventory, a transport codec for the wasm
boundary, and a `canonical` feature that produces equality inputs from a
`Value`.

### What was wrong with it

**The scalar type is erased at the cipher.** `Encrypt` describes a value and
targets the cipher's bytes-only data model in the same step. Once a scalar
reaches `Cipher::encrypt_bytes_vec` it is a `Protected<Vec<u8>>`, so anything
that needs the type later has to see the value first. Equality terms are the
case in point: `canonical::equality_input` takes a `&Value`, so a caller that
wants ciphertext and terms either builds a `Value` or walks its data twice.

**`Value` is a parallel data model.** Every scalar kind is a `Value`
variant, a wire tag, a `ValueKind`, a transport encoder and decoder, a
canonical encoder and a conversion in each host binding. Adding `uuid`
touches all of them. Nothing in the type system relates a `Value::Date` to
the `i32` it is stored as; the relationship is written out by hand in the
tag table, the canonical encoder and the Node wrapper objects.

**Container rules live in every cipher.** Element and entry AAD derivation,
the authenticated empty markers, duplicate-key rejection and the rule that a
container must seal something are implemented inside `Aes256Cipher`'s
`SeqCipher`, `MapCipher` and `AesDecipher`. A second cipher, such as the
0KMS-backed one in Stack Encrypt, has to reimplement them and can diverge.

**Decryption is pull-style, so one consumer drives it.** `SeqAccess::next_element`
hands the visitor one decrypted value at a time. Two consumers cannot share
a walk, and decrypting into a host value goes through `Value` again.

**Async is expressed in the wrong place.** `Decipher::Ok<T>` is a generic
associated type so that a cipher can return a future instead of a result.
That is essential: Stack Encrypt seals and opens leaves through 0KMS, and
other cloud key providers are coming. But the GAT makes every `Decrypt`
implementation thread `map_ok` through its wrappers, and it is per leaf: a
document with forty scalars is forty awaits, not one request. On the
encrypt side `Cipher::Ok` is a plain associated type, so an async cipher has
to make its output a future and combine element futures inside its own
container methods.

## Decision

### 1. Two traits carry the data model

`Plaintext` is implemented by anything that can describe itself once. `Sink`
is implemented by anything that consumes a description.

```rust
pub trait Plaintext {
    fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error>;
}

pub trait Sink: Sized {
    type Ok;
    type Error: Error;
    type Seq: SeqSink<Ok = Self::Ok, Error = Self::Error>;
    type Map: MapSink<Ok = Self::Ok, Error = Self::Error>;

    /// One scalar: a physical value and the logical type it represents, if any.
    fn scalar(self, ty: Option<Logical>, value: Physical<'_>) -> Result<Self::Ok, Self::Error>;
    fn seq(self, len: Option<usize>) -> Result<Self::Seq, Self::Error>;
    fn map(self, len: Option<usize>) -> Result<Self::Map, Self::Error>;
    /// A subtree that travels in the clear. Walked like anything else.
    /// `Clone`, so a sink that is really several sinks can give it to each.
    fn passthrough<P: Plaintext + Clone>(self, value: P) -> Result<Self::Ok, Self::Error>;
}

pub trait SeqSink: Sized {
    type Ok;
    type Error: Error;
    type Element<'s>: Sink<Error = Self::Error> where Self: 's;

    /// A sink for the next element. It writes into `self`.
    fn element(&mut self) -> Result<Self::Element<'_>, Self::Error>;
    fn end(self) -> Result<Self::Ok, Self::Error>;
}

pub trait MapSink: Sized {
    type Ok;
    type Error: Error;
    type Entry<'s>: Sink<Error = Self::Error> where Self: 's;

    /// A sink for the value under `key`. Keys travel in the clear, as before.
    fn entry(&mut self, key: &str) -> Result<Self::Entry<'_>, Self::Error>;
    fn end(self) -> Result<Self::Ok, Self::Error>;
}

/// Every sink's error type can carry a failure from the source.
/// (`vitaminc_aead::plaintext::Error`; not re-exported at the crate root.)
pub trait Error: Sized {
    fn source(error: SourceError) -> Self;
}
```

Three properties of this shape do the work:

- **Containers are push-style.** `SeqSink::element` returns a sink for the
  next child instead of taking the child as a value, so the source drives
  the whole walk and any number of sinks can share it. `Tee(a, b)` is an
  ordinary sink that forwards each call to both sides, at any depth.
  Encrypt-plus-terms is `Tee(EncryptSink, Terms)` with no special wrapper.
- **Sources can fail.** A source stops the walk with `Error::source`, without
  knowing which sink it is feeding. That is what lets a native binding walk
  a live host object (a JavaScript getter can throw, a string can hold an
  unpaired surrogate) without snapshotting it first.
- **Lengths are optional,** for host iterables that do not know their size.

#### Push-style containers: what `SeqSink::element` does

Before, a container handed each child to the cipher as a value, and the
cipher walked it:

```rust
// Before. The cipher receives the element and drives its walk.
pub trait SeqCipher: Sized {
    fn encrypt_next<T: Encrypt>(self, value: T) -> Result<Self, Self::Error>;
    fn end(self) -> Result<Self::Ok, Self::Error>;
}

impl<T: Encrypt> Encrypt for Vec<T> {
    fn encrypt_with_aad<'a, C: Cipher, A: IntoAad<'a>>(self, cipher: C, aad: A) -> Result<C::Ok, C::Error> {
        let mut seq = cipher.encrypt_seq(Some(self.len()), aad);
        for item in self {
            seq = seq.encrypt_next(item)?;   // `item` is moved into the cipher, which walks it
        }
        seq.end()
    }
}
```

`encrypt_next` consumes the element, so exactly one cipher ever sees it.
Inside `encrypt_next` the cipher calls `item.encrypt_with_aad(inner, aad)`
with a sub-cipher of its own making. The walk of the child happens inside
the consumer.

In the new model the container asks the sink for somewhere to put the next
child, and then walks the child into it itself:

```rust
// After. The source keeps driving; the sink only says where the child goes.
impl<T: Plaintext> Plaintext for Vec<T> {
    fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
        let mut seq = sink.seq(Some(self.len()))?;
        for item in self {
            item.visit(seq.element()?)?;   // `element()` returns a Sink; the item walks itself into it
        }
        seq.end()
    }
}
```

`element(&mut self)` returns a fresh `Sink` that borrows the parent for as
long as it lives (`Element<'s>` is tied to `&'s mut self`). Whatever the
child is, a scalar or a nested container, its `visit` runs against that
element sink, and when the child's walk finishes the element sink writes
one finished child into the parent. The element sink's `Ok` is incidental
(usually `()`) because its result goes into the parent, not back to the
caller. The borrow means
only one element sink exists at a time, so children land in order, and the
parent's `end` runs only after the last child is done.

This is what the encrypting sink does with it. Its sequence sink is a
vector of finished child nodes plus the AAD every element is sealed under;
`element` hands out a sink whose output slot is that vector:

```rust
/// `E` is the cipher's error type; `O` is where the finished node goes.
pub struct EncryptSeq<E, O> {
    aad: Context<'static>,           // the container's own AAD, for the empty marker
    element_aad: Context<'static>,   // aad.for_sequence_element(), shared by every child
    items: Vec<Node<Pending>>,
    rules: SeqRules,                 // the shared shape rules, from `vitaminc_aead::shape`
    out: O,                          // a `Slot`: the root, or a parent's `Push` or `Entry`
    depth: usize,
    _error: PhantomData<E>,
}

impl<E, O: Slot> SeqSink for EncryptSeq<E, O> {
    type Ok = O::Ok;
    type Error = EncryptError<E>;
    type Element<'s> = EncryptSink<E, Push<'s>> where Self: 's;

    fn element(&mut self) -> Result<Self::Element<'_>, Self::Error> {
        Ok(EncryptSink {
            aad: self.element_aad.clone(),
            out: Push {
                settle: self.rules.element(&self.out)?,   // refuses nesting past MAX_DEPTH
                items: &mut self.items,
                parent: &self.out,
            },
            depth: self.depth + 1,
            _error: PhantomData,
        })
    }

    fn end(self) -> Result<O::Ok, Self::Error> {
        self.rules.end(&self.out)?;   // a `Refusal`: nothing sealed, or a child sink dropped
        let node = if self.items.is_empty() {
            CipherText::EmptySequence(marker(self.aad.for_empty_sequence()))
        } else {
            CipherText::Sequence(self.items)
        };
        Ok(self.out.put(node))
    }
}
```

`Push` is the output slot: when the element sink receives a scalar it plans
one `Pending` leaf and pushes `CipherText::Single(leaf)` onto `items`; when
it receives a nested sequence it returns another `EncryptSeq` whose slot is
the same vector, so the nested node is pushed when that inner `end` runs.
The map sink is the same with `(key, node)` pairs and `for_map_entry(key)`
as the child AAD.

The rules every container keeps (no repeated key, something sealed in a
container that has children, no child sink dropped without a value, no
nesting deeper than `MAX_DEPTH`) are not written into `EncryptSink`. They
live in the public `vitaminc_aead::shape` module (`SeqRules`, `MapRules`,
`Settle`, `Locate`), so another sink keeps the same rules through the same
code: `Terms` (section 7) refuses exactly the values `EncryptSink` refuses.
A broken rule is a `Refusal`, which gives its `reason()` (an
`Unencryptable`) and its `path()`. A `Path` is a list of `Step::Index(usize)`
and `Step::Key(String)` from the root. Each child sink links to its parent's place, so the path is built only
when a refusal is. A refusal's `Display` shows only the reason, and its
`Debug` masks every map key, because keys can be user data. That module is
the whole of the container logic that before this decision was spread
across `Aes256Cipher`'s `SeqCipher`, `MapCipher` and `AesDecipher`.

#### `Tee`: two sinks, one walk

Because the source drives the walk and the sink only answers "where does
the next child go", a sink can answer with two places at once. `Tee<A, B>`
is a pair of sinks that forwards every call to both and pairs the results:

```rust
pub struct Tee<A, B>(pub A, pub B);

impl<A: Sink, B: Sink<Error = A::Error>> Sink for Tee<A, B> {
    type Ok = (A::Ok, B::Ok);
    type Error = A::Error;
    type Seq = Tee<A::Seq, B::Seq>;
    type Map = Tee<A::Map, B::Map>;

    fn scalar(self, ty: Option<Logical>, v: Physical<'_>) -> Result<Self::Ok, Self::Error> {
        Ok((self.0.scalar(ty, v)?, self.1.scalar(ty, v)?))   // `v` is borrowed: no copy
    }
    fn seq(self, len: Option<usize>) -> Result<Self::Seq, Self::Error> {
        Ok(Tee(self.0.seq(len)?, self.1.seq(len)?))
    }
    fn map(self, len: Option<usize>) -> Result<Self::Map, Self::Error> {
        Ok(Tee(self.0.map(len)?, self.1.map(len)?))
    }
    fn passthrough<P: Plaintext + Clone>(self, value: P) -> Result<Self::Ok, Self::Error> {
        Ok((self.0.passthrough(value.clone())?, self.1.passthrough(value)?))
    }
}

impl<A: SeqSink, B: SeqSink<Error = A::Error>> SeqSink for Tee<A, B> {
    type Ok = (A::Ok, B::Ok);
    type Error = A::Error;
    type Element<'s> = Tee<A::Element<'s>, B::Element<'s>> where Self: 's;

    fn element(&mut self) -> Result<Self::Element<'_>, Self::Error> {
        Ok(Tee(self.0.element()?, self.1.element()?))   // one element sink that is itself a tee
    }
    fn end(self) -> Result<Self::Ok, Self::Error> {
        Ok((self.0.end()?, self.1.end()?))
    }
}
```

A tee of two sequence sinks returns, from `element`, a tee of two element
sinks. So the nesting composes by itself: at every depth the source sees one
sink, and both consumers receive the same calls in the same order. For
`vec![1u32, 2u32]` walked into `Tee(EncryptSink, Terms)`:

| Source call                        | `EncryptSink` receives                | `Terms` receives                     |
| ---------------------------------- | ------------------------------------- | ------------------------------------ |
| `sink.seq(Some(2))`                | `seq(Some(2))`: start a node list     | `seq(Some(2))`: start a container    |
| `seq.element()`                    | `element()`: sink into the list       | `element()`: sink at path `[0]`      |
| `1u32.visit(element)` → `scalar`   | plan leaf `UINT32 1` under element AAD | term `(int domain, encoded 1)` at `[0]` |
| `seq.element()`                    | `element()`                           | `element()`: path `[1]`              |
| `2u32.visit(element)` → `scalar`   | plan leaf `UINT32 2`                  | term at `[1]`                        |
| `seq.end()`                        | `end()`: `CipherText::Sequence`       | `end()`: close the container         |

(`u8` is deliberately not a source or a target, so that `Vec<u8>`, `[u8; N]`
and `&[u8]` can be byte leaves. A lone 8-bit integer comes from a host, or
from `Raw`.)

Nothing is copied: `Physical<'_>` borrows the scalar's text or bytes, and
both sides read the same borrow. The two sides must share an error type,
which is why `Error` is a trait the tee can bound on; a sink meant for
teeing, such as `Terms`, is generic over its error type and adopts its
partner's. Encrypting with terms is then one walk:

```rust
let mut terms = Vec::new();
let (pending, ()) = value.visit(Tee(EncryptSink::root(aad), Terms::new(&mut terms)))?;
let ct = seal_all(cipher, pending)?;   // terms are complete before this line
```

`vitaminc-normalize` packages this as `plan_with_terms` and
`encrypt_with_terms`. Those tee `EncryptSink` with a `Terms` that leaves the
shape rules to its partner, so the rules are kept and paid for once; a
caller who tees `Terms::new` by hand, as above, has both sides keep them.

The one call a tee cannot share is `passthrough`, which hands a whole
subtree to each sink to walk for itself. That is why the value is `Clone`:
the tee gives each side its own copy. Passthrough is cleartext by contract,
so the copy carries no secret. A borrowed `Frame` is `Copy`, and a Rust
value in a passthrough field has to be `Clone` (the derive passes a
reference). The Node binding never produces a passthrough from a live
object, so `JsRef` needs neither.

A struct's `Plaintext` is what `#[derive(Plaintext)]` generates:

```rust
struct User {
    email: String,
    age: u32,
    signed_up: NaiveDate,
}

impl Plaintext for User {
    fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
        let mut map = sink.map(Some(3))?;
        self.email.visit(map.entry("email")?)?;
        self.age.visit(map.entry("age")?)?;
        self.signed_up.visit(map.entry("signed_up")?)?;
        map.end()
    }
}
```

The leaf implementations are short: `u32` calls
`sink.scalar(None, Physical::Int(Int::U32(self)))`, and `NaiveDate` calls
`sink.scalar(Some(Logical::Date), Physical::Int(Int::I32(days)))`. `String`
first wraps itself in `Protected`, then walks as
`sink.scalar(None, Physical::Text(&s))`; `Vec<u8>` and `[u8; N]` do the same
as bytes.

Every source also implements `Plaintext for &T`, and `Protected<T>` walks
the borrowed form (`Protected<T>: Plaintext` requires
`for<'a> &'a T: Plaintext`), so the value is never moved out of its
wrapper. A hand-written type therefore implements both forms to sit inside
a `Protected`, and `#[derive(Plaintext)]` emits both. The example above is
the borrowed shape; the by-value impl also drops the fields it has not
visited when the walk fails.

`vitaminc-aead` implements `Plaintext` for `bool`, every integer except
`u8`, `f32`, `f64`, `String`, `Vec<T>`, `&[T]`, `Vec<u8>`, `[u8; N]` and
`&[u8]` (bytes), `Option<T>`, `Protected<T>`, and `HashMap<K, V>` and
`BTreeMap<K, V>` with `K: AsRef<str>`. Behind the `chrono`, `rust_decimal`
and `uuid` features of the same names it implements `NaiveDate`,
`DateTime<Utc>` (`Timestamp(Nanos)` over `Int::I128`), `Decimal` and `Uuid`.
For hand-written sources there are `Raw(Option<Logical>, Physical)`, which
sends one scalar as given, `Bytes(&[u8])`, and the `visit_seq` and
`visit_map` helpers.

How the pieces map onto what existed before:

| Before                                                | After                                         |
| ----------------------------------------------------- | --------------------------------------------- |
| `Encrypt::encrypt_with_aad(self, cipher, aad)`        | `Plaintext::visit(self, sink)`                |
| `Cipher` (bytes, seq, map, none, passthrough)         | `Sink` (scalar, seq, map, passthrough)        |
| `SeqCipher::encrypt_next(value)` takes a value        | `SeqSink::element()` returns a sink           |
| `MapCipher::encrypt_value(key, value)` takes a value  | `MapSink::entry(key)` returns a sink          |
| `Cipher::encrypt_none`                                | `Option::<T>::None` is `scalar(None, Null)`   |
| `Decrypt<'c>` with `D::Ok<Self>` and `map_ok`         | `Decrypt` names a `Sink` that builds `Self`   |
| `Decipher` + `DecipherVisitor` + `SeqAccess` + `MapAccess` | a synchronous walk of the opened tree into any `Sink` |
| `Value` + `ValueKind`                                 | removed; hosts implement `Plaintext` and `Sink` |

`Sink` is implemented inside vitaminc and its host bindings, the way most
serde users never implement `Serializer`. Application code implements
`Plaintext` and `Decrypt`, almost always by derive.

### 2. A scalar is a physical value plus an optional logical type

`Value` conflates two questions: how is a scalar stored, and what does it
mean? The split here is Arrow's and Parquet's. Physical kinds say how a
value is stored and are a closed set. Logical types say what the stored
value means and are open.

```rust
/// How a scalar is stored. Exhaustive: a new kind fails to compile in every sink.
pub enum Physical<'a> {
    Null,
    Bool(bool),
    Int(Int),
    Float(Float),
    Text(&'a str),
    Bytes(&'a [u8]),
}

/// An integer with the width it came from.
pub enum Int { I8(i8), I16(i16), I32(i32), I64(i64), I128(i128),
               U8(u8), U16(u16), U32(u32), U64(u64), U128(u128) }

pub enum Float { F32(f32), F64(f64) }

/// What a physical value means. Open: a sink outside vitaminc must say what
/// it does with a logical type it does not know.
#[non_exhaustive]
pub enum Logical {
    /// JavaScript `undefined`. Over null.
    Undefined,
    /// Days since 1970-01-01. Over int.
    Date,
    /// Count of `TimeUnit`s since the Unix epoch, UTC, no leap seconds. Over int.
    Timestamp(TimeUnit),
    /// `int × 10^-scale`, scale at most 28, `|int| < 2^96`. Over int.
    Decimal { scale: u8 },
    /// Sixteen bytes. Over bytes.
    Uuid,
    /// A logical type this build does not know. Carried through unchanged.
    Unknown(UnknownLogical),
}
```

A schema names a column's type without a value or a parameter. `Kind` is
the physical kind on its own (`Physical::kind()` gives a value's), and
`KnownLogical` is a logical type without its parameter. `UnknownLogicalId`
is an id from a newer build. A `KnownLogical` says the one `Kind` it is
stored as, so a mismatched pair cannot be built. The wire ids live in
`kinds::id` (`NONE` = 0, `UNDEFINED` = 1, `DATE` = 2, `TIMESTAMP` = 3,
`DECIMAL` = 4, `UUID` = 5). The validity bounds are public constants:
`MAX_DECIMAL_SCALE`, `MIN_DATE_DAYS`/`MAX_DATE_DAYS` and the timestamp
nanosecond bounds.

**Integers are one physical kind, not ten.** Before, `Int8` through
`UInt128` were ten `Value` variants, ten tags, ten `ValueKind`s and ten
cipher paths, and nothing said they were the same thing. Here they are one
kind whose width is a hint for host fidelity: Go's `int32` comes back as
`int32`, a JavaScript BigInt keeps the narrowest width that fits. Nothing
that interprets a value looks at the width. `Int`'s own `==` is structural
and includes the width (`Int::I8(34) != Int::U64(34)`), but equality terms
and typed targets compare values through `sign_and_word` and `to_i128`.
Every width shares one equality domain, so `Int::I8(34)` and `Int::U64(34)`
produce the same term. A typed target reads the value, not
the width: a `u32` accepts an `i8` leaf holding 34 and refuses one holding
-1.

**A logical type rides on a physical value and is validated against it.** A
date is an int (its day count), a timestamp is an int (a count of units), a
decimal is an int (its mantissa) with a one-byte parameter (its scale), a
uuid is sixteen bytes, and `undefined` is a null. The parameter is carried
per value, so two decimals in one document can have different scales.
`Logical::admits(&Physical)` says whether a value is valid for its type: a
day count outside chrono's range, a decimal mantissa beyond 96 bits or a
uuid of fifteen bytes is refused before anything is sealed. A timestamp is
therefore not a physical kind of its own, and a JavaScript `Date` is
`Timestamp(Millis)` over its own millisecond count, with no conversion.

Sinks treat the two levels differently, and that is the point of the
split:

- **Structural sinks pass logical types through.** Encryption, the
  transport frame, the ciphertext codec, `Tee` and the host builders carry
  the annotation and the parameter without interpreting them. A logical type
  this build does not know arrives as `Logical::Unknown(UnknownLogical)`, an
  opaque value built by `Logical::from_wire(id, param)` and read back with
  `.id()`, `.param()` and `to_wire`, and it leaves the same way.
- **Index sinks opt in.** The equality sink has a table of the logical types
  it understands, each with its domain label and normalization, and refuses
  any other logical type with `NoDomain`. The exception is `undefined`,
  which, like null and booleans, simply has no term. A date's day count never collides with the
  integer it equals, because the date is indexed under the date domain.

Adding a logical type is a variant, a wire id, a validity rule, a `Plaintext`
source and a `Decrypt` target. Adding a physical kind is deliberately a
compile error in every sink, because it changes what every consumer has to
handle.

Every `Value` variant has one call in the new model:

| `Value` (before)                   | `Sink` call                                                     |
| ---------------------------------- | --------------------------------------------------------------- |
| `Null`                             | `scalar(None, Null)`                                            |
| `Undefined`                        | `scalar(Some(Undefined), Null)`                                 |
| `Bool(b)`                          | `scalar(None, Bool(b))`                                         |
| `Int8(v)` … `UInt128(v)` (ten)     | `scalar(None, Int(Int::I8(v)))` … `scalar(None, Int(Int::U128(v)))` |
| `Float32(v)`, `Float64(v)`         | `scalar(None, Float(F32(v)))`, `scalar(None, Float(F64(v)))`    |
| `Date(d)`                          | `scalar(Some(Date), Int(I32(days since epoch)))`                |
| `Timestamp(t)`                     | `scalar(Some(Timestamp(Nanos)), Int(I128(nanoseconds)))`        |
| `Decimal(d)`                       | `scalar(Some(Decimal { scale }), Int(I128(mantissa)))`          |
| `String(s)`                        | `scalar(None, Text(&s))`                                        |
| `Bytes(b)`                         | `scalar(None, Bytes(&b))`                                       |
| `Array(items)`                     | `seq(Some(len))`, then `element()` per item                     |
| `Object(entries)`                  | `map(Some(len))`, then `entry(key)` per entry                   |
| `Passthrough(v)`                   | `passthrough(v)`                                                |
| (no variant)                       | `scalar(Some(Uuid), Bytes(&id))`                                |

### 3. Scalar tags keep their encodings; the envelope version and the none node change

The sealed leaf is `[tag] ++ payload` inside the AEAD envelope, and the
transport frame uses the same tags. Every existing scalar tag keeps its
encoding byte for byte. The ciphertext around those tags does change,
and 0.5 ciphertext is not interoperable by default:

- The envelope's version byte moves from 1 to 2, and `Aes256Cipher`
  refuses version 1 leaves unless the reader opts in (see "Tagged leaves
  are sealed under wire version 2" below).
- `CipherText::None` and the transport's `CT_NONE` node are removed,
  because `None` becomes a `NULL` leaf.
- `LeafTypeAad` moves to a new domain label, so bindings made under the old
  label do not open.

The existing tags are read as shorthand for a physical kind plus a logical
type:

| Tag                          | Reads as                                     |
| ---------------------------- | -------------------------------------------- |
| `NULL`                       | `Null`                                       |
| `UNDEFINED`                  | `Undefined` over `Null`                      |
| `BOOL_FALSE`, `BOOL_TRUE`    | `Bool`                                       |
| `INT8` … `UINT128`           | `Int`, with that width                       |
| `FLOAT32`, `FLOAT64`         | `Float`                                      |
| `STRING`                     | `Text`                                       |
| `BYTES`                      | `Bytes`                                      |
| `DATE`                       | `Date` over `Int::I32`                       |
| `TIMESTAMP`                  | `Timestamp(Nanos)` over `Int::I128`          |
| `DECIMAL`                    | `Decimal { scale }` over `Int::I128`         |

A logical type that has no tag of its own, such as `Uuid`, a timestamp in
milliseconds or a type from a newer build, travels in one generic envelope:
the byte `0xF3`, the one-byte logical id, the one-byte parameter, then the
plain physical scalar. A known id with a parameter it cannot take is refused
as malformed. A reader that does not know the id still reads the
physical value and keeps the annotation. A host builder that has no value
of its own to keep it in must refuse the leaf rather than hand back the
physical value with the annotation dropped; the Go binding carries it in
`Tagged`, and the Node binding refuses it until #446 gives it a carrier.
There is exactly one encoding per value: an envelope is refused where a
shorthand tag exists, so two ciphertexts of the same value are never
byte-different for a reason the AEAD cannot see.

The parameter is one byte and stays one byte. Nothing in view needs more:
a Postgres `timestamptz` is stored in UTC, so a timezone is not part of the
value, and a decimal's precision is a constraint on the column rather than
something needed to read the value. If a logical type ever needs a longer
parameter, it gets a second envelope byte, `0xF4`, with a length-prefixed
parameter. The length is fixed per envelope byte rather than per id, so a
reader that does not know an id can still skip its parameter. `0xF4` is
reserved now as `tags::LOGICAL_LONG`: never written, and refused on read.

**Tagged leaves are sealed under wire version 2.** The tags inside the
AEAD stay byte for byte, but the version byte in front of the envelope
moves from 1 to 2. `vitaminc-encrypt` 0.5's `Encrypt` path sealed raw,
untagged bytes under version 1, the same version the `Value` path used for
its tagged leaves, and nothing in a version 1 leaf tells the two apart.
Read as tagged, a raw leaf can decode to a different value with no error:
a string that starts with `\n` loses its first character. So
`Aes256Cipher`, and with it the typed `decrypt` and the hlist openers,
refuses every version 1 leaf, as `DecryptError::Cipher`. Tagged version 1
leaves from the `Value` path open only through the explicit
`Aes256Cipher::opening_version_1()` view. That view is an `OpensVersion1`,
a full `Cipher` that works with typed `decrypt` as well as `decrypt_into`,
and it still seals version 2. Its callers are the Go binding, through
`decrypt_to_frame`, and the legacy fixtures. The cost is that 0.5 `Encrypt` data has no in-place upgrade:
it must be decrypted with 0.5 and encrypted again. A reader of `Value`-path
data opts in to version 1 knowing where its leaves came from.

**`Option::None` is null.** Before, a static Rust `None` sealed an empty
marker under `for_none` as `CipherText::None`, while a host `null` sealed a
`NULL`-tagged leaf as `CipherText::Single`, so a JavaScript `null` could not
decrypt into a Rust `Option`. Here `None` is `scalar(None, Null)`: one
`NULL`-tagged leaf, the same as a host null. The tag is inside the AEAD, so
a `Some` leaf can no longer be re-labelled as an absence, and the separate
`for_none` derivation is not needed. `CipherText::None` and the transport's
`CT_NONE` are removed; the transport keeps the byte as `CT_NONE_RETIRED`
(`0x02`) and refuses it on read. An `Option<T>` target reads null and `undefined` as
`None` and defers anything else to `T`.

**Two values in the 0.5 corpus have no physical-plus-logical form.** A
timestamp at a leap second (chrono's representation, nanoseconds above
999,999,999) is a real instant with no count in any unit, and is refused:
by the chrono source on the way in (`EncryptError::Source`), and as a
malformed leaf on the way out (`DecryptError::Malformed`). A
decimal negative zero (`rust_decimal`'s sign bit set over a zero mantissa)
is equal to zero by `rust_decimal`'s own comparison, and is normalized to
zero with its scale kept: `-0.00` reads back as `0.00`. Refusing it would
surprise any caller that negates a value that happens to be zero.

**Binding an expected type into the AAD.** `LeafTypeAad` was, and is, an
opt-in for schema-aware callers: the expected type goes into the AAD at both
ends, so a wrong-type ciphertext fails authentication before any plaintext
is released. The self-describing path never binds it, and that stays the
same. What changes is what "type" means. The expectation a schema holds is
"this column is a date", not "this column is an int", so the binding is the
physical kind plus the logical id, as the PAE list `(domain, base, kind, id)`
with id 0 for no logical type. The domain label moves from
`vitaminc/aead-value/leaf-type/v1` to `vitaminc/aead/leaf-type/v2`, and the
type moves with it to `vitaminc_aead::LeafTypeAad`. The kind is bound as its
`Kind::to_wire` byte (`Null` 0, `Bool` 1, `Int` 2, `Float` 3, `Text` 4,
`Bytes` 5), which is a new cross-language commitment. There are three
constructors: `physical(base, Kind)`; `logical(base, KnownLogical)`, which
takes the kind from the logical type so a mismatched pair cannot be built;
and `unknown(base, Kind, UnknownLogicalId)` for an id from a newer build. It
is the kind,
not the leaf tag: a date leaf carries `DATE` and an `i64` leaf `INT64`, so
binding the tag would give one column several possible bindings and make
the int's width part of the commitment, when width is a hint. Neither the
width nor the parameter is bound: a decimal's scale varies from value to
value within one column, and binding it would refuse `1.50` next to `1.5`.
The parameter is still validated after opening by `Logical::admits`. The
binding is a declaration, not a check: nothing compares it with the value
being sealed, so what it authenticates is that writer and reader agree on
the type.

### 4. Encryption is a sink, and the cipher is bytes-only and may be async

`EncryptSink<E, O = Root>`, built with `EncryptSink::root(aad)`, turns each
scalar into tagged leaf plaintext and applies every container rule:
element AAD (`for_sequence_element`), entry AAD (`for_map_entry(key)`), the
authenticated empty markers (`for_empty_sequence` and `for_empty_map`), and
the shared shape rules from section 1. Those rules are: no duplicate keys;
at least one sealed child in every container that has children (an empty
container becomes a marker, and one holding only passthrough is refused);
no child sink dropped without a value; no nesting deeper than `MAX_DEPTH`;
every scalar valid for its logical type (`Logical::admits`) and writable as
a leaf; and every passthrough framable. Each refusal is an
`EncryptError::Shape(Refusal)` that names the rule and the `Path`. The sink
never calls a cipher. Its output is a tree
of pending leaves, each carrying its plaintext and the AAD its position
derives:

```rust
pub struct Pending {
    pub plaintext: Protected<Vec<u8>>,
    pub aad: Context<'static>,
}
```

Sealing is a separate step over that tree, through one of two traits:

```rust
/// Seal and open one leaf, synchronously. `Aes256Cipher` implements this.
pub trait Cipher {
    type Leaf;
    type Error;

    fn seal(&self, plaintext: Protected<Vec<u8>>, aad: &Context<'_>) -> Result<Self::Leaf, Self::Error>;
    fn open(&self, leaf: Self::Leaf, aad: &Context<'_>) -> Result<Protected<Vec<u8>>, Self::Error>;
}

/// Seal and open leaves through something that has to be awaited: a remote
/// key provider, a KMS, a cloud HSM.
pub trait AsyncCipher: Sync {
    type Leaf: Send;
    type Error: Send;

    fn seal(&self, plaintext: Protected<Vec<u8>>, aad: Context<'static>)
        -> impl Future<Output = Result<Self::Leaf, Self::Error>> + Send;
    fn open(&self, leaf: Self::Leaf, aad: Context<'static>)
        -> impl Future<Output = Result<Protected<Vec<u8>>, Self::Error>> + Send;

    /// Every leaf of one document, in walk order. The default seals each
    /// leaf concurrently, at most `seal::DEFAULT_CONCURRENCY` (32) at a
    /// time, with results in order; a provider with a batch API overrides
    /// it to make one round trip per document.
    fn seal_many(&self, leaves: Vec<Pending>)
        -> impl Future<Output = Result<Vec<Self::Leaf>, Self::Error>> + Send { /* bounded per-leaf calls */ }
    fn open_many(&self, leaves: Vec<(Self::Leaf, Context<'static>)>)
        -> impl Future<Output = Result<Vec<Protected<Vec<u8>>>, Self::Error>> + Send { /* bounded per-leaf calls */ }
}
```

A ciphertext tree is `CipherText<Leaf, P>`, generic over the leaf and the
passthrough payload. Every entry point uses the alias for a tree whose
passthrough is a frame:

```rust
pub type Node<L> = CipherText<L, PassthroughFrame>;
```

The entry points:

```rust
pub fn encrypt<'a, P, C, A>(value: P, cipher: &C, aad: A)
    -> Result<Node<C::Leaf>, EncryptError<C::Error>>
where P: Plaintext, C: Cipher, A: IntoAad<'a>;

/// Walks `value` before returning, so the future holds only the planned
/// leaves and is `Send` even when the source is not.
pub fn encrypt_async<'a, 'c, P, C, A>(value: P, cipher: &'c C, aad: A)
    -> impl Future<Output = Result<Node<C::Leaf>, EncryptError<C::Error>>> + Send + 'c
where P: Plaintext, C: AsyncCipher, A: IntoAad<'a>;

pub fn decrypt<'a, T, C, A>(cipher: &C, node: Node<C::Leaf>, aad: A)
    -> Result<T, DecryptError<DecodeError, C::Error>>
where T: Decrypt, C: Cipher, A: IntoAad<'a>;

pub async fn decrypt_async<'a, T, C, A>(cipher: &C, node: Node<C::Leaf>, aad: A)
    -> Result<T, DecryptError<DecodeError, C::Error>>
where T: Decrypt, C: AsyncCipher, A: IntoAad<'a>;

/// Decrypt into any sink: a host builder, a frame writer.
pub fn decrypt_into<'a, C, S, A>(cipher: &C, node: Node<C::Leaf>, aad: A, sink: S)
    -> Result<S::Ok, DecryptError<S::Error, C::Error>>
where C: Cipher, S: Sink, A: IntoAad<'a>;

/// The sink is held across the await, so this future is `Send` only if the
/// sink is.
pub async fn decrypt_into_async<'a, C, S, A>(cipher: &C, node: Node<C::Leaf>, aad: A, sink: S)
    -> Result<S::Ok, DecryptError<S::Error, C::Error>>
where C: AsyncCipher, S: Sink, A: IntoAad<'a>;
```

Because `aad` is a named generic, a typed decrypt is written
`decrypt::<T, _, _>(…)`.

`encrypt` is two public steps, `seal_all(cipher, plan(value, aad)?)`.
`plan` walks the plaintext into `EncryptSink` to get a `Node<Pending>`.
`seal::seal_all` (or `seal_all_async`) splits the tree into its shape and a
vector of leaves in walk order, calls `seal` per leaf or `seal_many` once,
and puts the sealed leaves back into the shape. A tree with no leaves, such
as a top-level passthrough, makes no cipher call. Decryption mirrors it:
`decrypt_into` is `walk(open_all(cipher, node, aad)?, sink)`.
`seal::open_all` (or `open_all_async`) checks the container rules on the
sealed tree (something sealed in every container, no repeated keys, every
passthrough a valid frame), so a malformed tree costs no cipher calls. It
then derives each leaf's AAD from its position, opens every leaf (one
`open_many` call for an async cipher) and puts the plaintexts back. `walk`
feeds the opened tree (`Node<Opened>`) to the sink and checks every rule
again, because it accepts opened trees from anywhere. The walk itself is
always synchronous, whichever cipher is in use. All of these steps are
public, so a caller can plan or open on its own. A host whose builder is not
`Send` awaits `open_all_async` and then calls `walk` itself.
`decrypt_to_frame(cipher, node, aad)` is `decrypt_into` with a `FrameWriter`
over a `Protected` buffer, so the frame is wiped on every error path.

The errors:

```rust
pub enum EncryptError<E> {
    Cipher(E),              // the cipher refused to seal a leaf
    Source(SourceError),    // the source, or a sink teed beside this one, stopped the walk
    Shape(Refusal),         // the value cannot be encrypted as given: why, and where
    Count(LeafCount),       // the cipher returned too few or too many leaves
}

pub enum DecryptError<E, C = Infallible> {
    Cipher(C),              // the cipher refused a leaf
    Auth,                   // an authenticated empty marker carried a payload
    Malformed,              // a bad tree, a bad leaf plaintext, or a wrong leaf count
    Sink(E),                // the sink refused what it was given
}
```

The public steps have their own, narrower errors. `seal_all` (and
`seal_all_async`) returns `SealError<E>` (`Cipher`, `Count`), and
`From<SealError<E>> for EncryptError<E>` lets `?` lift it inside `encrypt`.
`open_all` (and `open_all_async`) returns `OpenError<E>` (`Cipher`,
`Malformed`, `Count`). It has no `From` into `DecryptError`: `decrypt_into`
maps it itself, so a caller who calls `open_all` directly handles
`OpenError`.

A cipher that returns the wrong number of leaves is refused:
`EncryptError::Count` on the way in, and `DecryptError::Malformed` on the way
out. `Unencryptable`, the reason inside a `Refusal`, is `#[non_exhaustive]`:
`DuplicateKey`, `SequenceHasNothingSealed`, `MapHasNothingSealed`,
`InvalidValue`, `Unwritable`, `UnframablePassthrough`, `DroppedChild` and
`TooDeep`.

A cipher's failure is returned as `DecryptError::Cipher` with the cipher's
own error, as `EncryptError::Cipher` is on the way in. For an AEAD that
means a wrong key, a wrong AAD or tampering. For a remote provider it may
also be an outage, which a caller must be able to retry rather than treat
as tampering. `DecryptError::Auth` is left for the one failure the cipher
cannot see: an authenticated empty marker that carries a payload.

Why this shape:

- **The walk never awaits.** A native binding walks a live host value on
  the host's thread; that walk cannot suspend. Only the leaf calls are
  async, so a plain `async fn` trait expresses them and the `Ok<T>` GAT and
  `map_ok` are gone.
- **One round trip per document.** 0KMS seals every leaf of a document in
  one `seal_many` call. A provider without a batch API gets the default,
  which is one call per leaf, a bounded number in flight at a time, and
  still correct.
- **Terms are complete before the first await.** `Tee(EncryptSink, Terms)`
  runs during the walk, so a caller holds the equality terms before any
  network call is made.
- **A second cipher cannot diverge on container rules,** because it has
  none. The whole of a 0KMS cipher is `seal`, `open` and a batching
  `seal_many`.

What a key-provider cipher looks like:

```rust
impl AsyncCipher for ZeroKms {
    type Leaf = ZeroKmsCipherText;
    type Error = ZeroKmsError;

    async fn seal(&self, plaintext: Protected<Vec<u8>>, aad: Context<'static>) -> Result<Self::Leaf, Self::Error> {
        self.client.encrypt_one(plaintext, aad.as_bytes()).await
    }

    async fn open(&self, leaf: Self::Leaf, aad: Context<'static>) -> Result<Protected<Vec<u8>>, Self::Error> {
        self.client.decrypt_one(leaf, aad.as_bytes()).await
    }

    async fn seal_many(&self, leaves: Vec<Pending>) -> Result<Vec<Self::Leaf>, Self::Error> {
        self.client.encrypt_batch(leaves.into_iter().map(|p| (p.plaintext, p.aad))).await
    }
}
```

Compared with the old `Cipher`, which had eight methods and two sub-traits,
and `Decipher`, which had seven plus a visitor and two access traits, a
cipher is now two methods, or four with batching. `Aes256Cipher` keeps its
key and nonce generator and loses its container logic. Static Rust callers
get the same tagged leaves as hosts do, so there is one leaf format and
every ciphertext is self-describing.

One statically shaped API remains outside this model. Behind the opt-in
`hlist` feature, `Aes256Cipher` still implements `StaticCipher`
(`encrypt_bytes`, `encrypt_none`, `open_encrypted`, `verify_absent` and
their per-entry forms), and `StaticMapBuilder` derives `for_map_entry`
itself. It seals the same tagged leaves (`BYTES` for a value, a `NULL` leaf
for an absence) and derives entry AAD the same way. It does not go through
`EncryptSink`, though, so it has no empty-map marker and no nothing-sealed
rule.

### 5. Typed decryption names a sink

The old `Decrypt<'c>` supplied a `DecipherVisitor` and threaded the
cipher's `Ok<T>` through `map_ok`. The replacement is a type that names the
sink that builds it:

```rust
pub trait Decrypt: Sized {
    type Sink: Sink<Ok = Self, Error = DecodeError>;
    fn sink() -> Self::Sink;
}

/// A type that decodes from one scalar.
pub trait FromScalar: Sized {
    const EXPECTED: &'static str;
    fn from_scalar(ty: Option<Logical>, value: Physical<'_>) -> Option<Self>;

    /// Decode straight into `Protected`. The default decodes, then wraps;
    /// a type that would otherwise pass through a bare temporary
    /// (`[u8; N]`) overrides it to build in place.
    fn from_scalar_protected(ty: Option<Logical>, value: Physical<'_>) -> Option<Protected<Self>>
    where Self: Zeroize { /* from_scalar, then Protected::new */ }
}

/// A type that can be decoded straight into `Protected<Self>`.
pub trait DecryptProtected: Decrypt + Zeroize {
    type ProtectedSink: Sink<Ok = Protected<Self>, Error = DecodeError>;
    fn protected_sink() -> Self::ProtectedSink;
}

impl<T: DecryptProtected> Decrypt for Protected<T> { /* T::protected_sink() */ }
```

Every `FromScalar` type gets `Decrypt` through a shared `ScalarSink<T>`,
which refuses sequences, maps and passthrough. `NaiveDate` accepts
`(Some(Date), Int)` and nothing else; `u32` accepts `(None, Int)` whose
value fits; `Option<T>` reads null and `undefined` as `None` and otherwise
defers to `T`, so `Some(None)` reads back as `None`. `HashMap<String, T>`
and `BTreeMap<String, T>` read a map through each value's sink.

`Protected<T>` is a target for any `T: DecryptProtected`. That covers every
`FromScalar` type that is `Zeroize`, decoded through
`from_scalar_protected` (so a fixed-size array is filled inside the wrapper
and no bare copy sits on the stack), and `Vec<T>` and `Option<T>` of those,
nested to any depth. Each is built inside the wrapper, so a failure part
way through wipes what was already decoded. A struct opts in by hand,
implementing `DecryptProtected` with `typed::Wrap(Self::sink())`; the
derive does not emit it.

A struct's sink is what `#[derive(Decrypt)]` generates: a `MapSink` that
routes each entry to the field's own sink. It refuses unknown keys,
duplicate keys and missing fields, including a missing `Option<T>` field,
which is refused rather than read as `None`. It also refuses a passthrough
standing in for the struct. `#[aead(skip)]` fields are rebuilt with
`Default`, `#[aead(passthrough)]` fields decode through `typed::Clear`, and
`rename` and `take` are supported. A newtype is transparent
(`typed::Wrapped`). A fieldless enum is an integer discriminant: a `u32`
leaf on the `Plaintext` side, read back through a generated `FromScalar`.
Nothing in a `Decrypt` implementation knows whether the cipher was sync or
async, because the opened tree is walked after every await has completed.

### 6. Host bindings implement the two traits instead of converting to `Value`

The data model is the FFI boundary. Each binding supplies a `Plaintext`
for values coming in and a `Sink` for values going out, and nothing in
between.

**Go** already shipped values as transport frames across the wasm boundary.
`Frame<'a>` is a validated, borrowed frame that implements `Plaintext` by
walking its own bytes in place: no `Value` tree is built, and no scalar
leaves the buffer except to go straight to a sink. `FrameWriter` is a `Sink`
that writes frame bytes. Both live in `vitaminc-aead`, next to the leaf
codec they share, because the encrypt sink frames passthrough subtrees
itself. The guest's `encrypt` becomes
`encrypt(Frame::parse(bytes)?, &cipher, aad)`. Its `decrypt` becomes
`decrypt_to_frame(&cipher.opening_version_1(), codec::decode_ciphertext(ct)?, aad)`,
which is `decrypt_into` with a `FrameWriter` over a `Protected` buffer. The
version 1 view lets it read `Value`-path leaves written before the change.
The Go API keeps its shape, and only the section 3 format changes reach it:
`vcvalue` gains `UUID` and `Tagged` for the `0xF3` envelope, and timestamps
in seconds, milliseconds and microseconds decode to `time.Time`. The `vcffi`
codec reads and writes the envelope, refuses a leap second and normalizes a
decimal `-0`. The none node (`ctNone`, `LeafNone`, `SealedNone`) is
retired.

**Node** walks live JavaScript values. `JsRef<'e>`, built with
`JsRef::new(value)`, implements `Plaintext` on the JavaScript thread, and
`JsBuilder` implements `Sink` and builds JavaScript values. Any of the
following stops the walk through `Error::source` and comes back to
JavaScript as a `JsFault`: a getter that throws, a string with an unpaired
surrogate, a BigInt out of range, a `Date` outside chrono's range, a typed
array that is not bytes, nesting that is too deep, or a forbidden key. To
encrypt off the JavaScript thread, the binding snapshots with
`JsRef::new(v).to_frame()` on the JavaScript thread and encrypts the frame
on the worker. The mapping:

| JavaScript                          | `Sink` call                                       |
| ----------------------------------- | ------------------------------------------------- |
| `null`                              | `scalar(None, Null)`                              |
| `undefined`                         | `scalar(Some(Undefined), Null)`                   |
| `boolean`                           | `scalar(None, Bool)`                              |
| `number`                            | `scalar(None, Float(F64))`                        |
| `bigint`                            | `scalar(None, Int(narrowest fitting width))`      |
| `string`                            | `scalar(None, Text)`                              |
| `Buffer`, `Uint8Array`              | `scalar(None, Bytes)`; any other typed-array view is refused |
| `Date`                              | `scalar(Some(Timestamp(Millis)), Int(I64(ms)))`   |
| `VcDate`                            | `scalar(Some(Date), Int(I32(days)))`              |
| `VcTimestamp`                       | `scalar(Some(Timestamp(Nanos)), Int(I128(ns)))`   |
| `VcDecimal`                         | `scalar(Some(Decimal { scale }), Int(mantissa))`  |
| `VcUuid`                            | `scalar(Some(Uuid), Bytes(16 bytes))`             |
| `Array`                             | `seq`, then `element()` per index; sparse arrays are refused |
| plain object                        | `map`, then `entry(key)` per own enumerable string key; forbidden keys and non-plain objects are refused |

A JavaScript `Date` is a count of milliseconds, so it is stored as one,
rather than converted to seconds and nanoseconds and back. `Timestamp`
admits chrono's range (years -262143 to 262142), which is narrower than a
`Date`'s (about ±275,000 years). It stays the bound because the `TIMESTAMP`
decoder is chrono-bound: a wider timestamp could be sealed but not read
back there. The binding refuses a `Date` outside it.

JavaScript has no type of its own for a calendar date, a timestamp finer
than a millisecond, a decimal or a uuid. The binding represents each as an
instance of a wrapper class, `VcDate`, `VcTimestamp`, `VcDecimal` or
`VcUuid`, recognised with `instanceof` (#382). These classes replace the
reserved `{ date }` and `{ decimal }` objects of 0.5, so an object like
`{ date: "…" }` is now ordinary data. `JsBuilder` builds a timestamp as a
`Date` when it is whole milliseconds inside `Date`'s range, and as a
`VcTimestamp` otherwise. It refuses a `Logical::Unknown` leaf until #446
gives it a carrier.

**Passthrough** is a subtree that travels in the clear. On the way in it is
walked like anything else and the encrypt sink frames it; on the way out
the frame is parsed and handed to the sink's `passthrough`. The payload is
therefore a frame in every binding and in static Rust, which replaces the
`Cipher::Passthrough` associated type and the `Box<dyn Any + Send>`
downcast in the sink-based model. The opt-in `hlist` static shape keeps its
typed `Passthrough<T>`. The contract is unchanged: passthrough is unencrypted,
unauthenticated and for non-sensitive fields only.

### 7. Index terms are a sink, and normalization is its own crate

The equality encoders behind the old `canonical` feature become public and
move to `vitaminc-normalize`. `Terms` is a `Sink` that produces a `Term` for
each scalar that has an equality domain: where the scalar sits, its frozen
domain label and its normalized bytes. Null, booleans and `undefined`
produce no term and do not stop the walk. A logical type with no domain
stops it with a `TermError` (`NoDomain`) at its `Path`. Through
`vitaminc_aead::shape`, `Terms` also refuses every value `EncryptSink` would
refuse, at the same path, so an index never holds terms for a value that
cannot be stored.

```rust
pub struct Normalized {
    pub domain: &'static str,
    pub bytes: Protected<Vec<u8>>,
}

pub struct Term {
    pub path: Path,               // from the root; empty for a scalar at the root
    pub normalized: Normalized,
}

pub type WithTerms<L> = (Node<L>, Vec<Term>);

/// Terms on their own, with no cipher.
pub fn terms<P: Plaintext>(value: P) -> Result<Vec<Term>, TermsError>;

/// One walk into `Tee(EncryptSink, Terms)`, without sealing.
pub fn plan_with_terms<'a, P, E, A>(value: P, aad: A)
    -> Result<WithTerms<Pending>, EncryptError<E>>
where P: Plaintext, A: IntoAad<'a>;

pub fn encrypt_with_terms<'a, P, C, A>(value: P, cipher: &C, aad: A)
    -> Result<WithTerms<C::Leaf>, EncryptError<C::Error>>
where P: Plaintext, C: Cipher, A: IntoAad<'a>;
```

`encrypt_with_terms_async` is the `AsyncCipher` form. `normalize()` and
`domain_of()` expose the per-scalar encoders, and `NormalizeError` says why
a scalar has no term. `TermError` (with `path()` and `error()`) is a refused
scalar. `TermsError` wraps what `terms` refuses: `term()` recovers a
`TermError`, `refusal()` a shape `Refusal`, and `source_error()` the failure
as it arrived. Beside encryption, a term refusal arrives as
`EncryptError::Source`, and `downcast_ref::<TermError>()` recovers it. Each
`Debug` masks map keys, as a `Refusal` does. `Path` and `Step` are
re-exported from `vitaminc_aead::plaintext`.

`vitaminc-prf`, behind its opt-in `normalize` feature, implements
`PrfValue` for `Normalized`, and adds `EqualityTerm` for a caller with one
scalar in hand. `vitaminc-normalize` has no cryptography of its own and
never imports PAE, which stays in `vitaminc-context` beneath everything. It
builds on `vitaminc-aead` for the data model, and for sealing in
`encrypt_with_terms`.

The existing domain labels are kept. `Uuid` gets one of its own,
`vitaminc/prf/value/uuid/v1`, over its sixteen raw bytes. It is a separate
domain from bytes for the same reason a date's domain is separate from an
int's: a value's logical type is part of what it is, so a uuid written as
plain bytes by one client and as a uuid by another does not match, and that
is the rule rather than an accident.

### 8. Four crates

| Crate                  | Before (0.5.1)                                                                                                             | After                                                                                                                                                                                                  |
| ---------------------- | -------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `vitaminc-aead`        | `Encrypt`, `Cipher`, `SeqCipher`, `MapCipher`, `Decrypt`, `Decipher`, `DecipherVisitor`, `SeqAccess`, `MapAccess`, `CipherText`, `Context` | `Plaintext`, `Sink`, `SeqSink`, `MapSink`, `SourceError` and `plaintext::Error`, `Physical`, `Logical`, `Kind`, `KnownLogical`, `UnknownLogical`, `UnknownLogicalId`, `TimeUnit`, `Raw`, `Bytes`, `visit_seq`/`visit_map`, `Path`/`Step`; the leaf codec and tag table; the frame (`Frame`, `FrameWriter`, `PassthroughFrame`, `to_frame`); `Cipher`, `AsyncCipher`, `Pending`, `EncryptSink`; `CipherText<Leaf, P>`, `Node`, `Opened`; `plan`, `walk`, `encrypt`/`decrypt` and their async and `_into` forms, `decrypt_to_frame`; the `shape` module (`Refusal`, `Unencryptable`, `SeqRules`, `MapRules`, `Settle`, `Locate`); the `seal` module (`seal_all`, `open_all` and async forms, `SealError`, `OpenError`, `LeafCount`, `DEFAULT_CONCURRENCY`); `Decrypt`, `FromScalar`, `DecryptProtected`; `Tee`; `Context`, `ContextTag`, `LeafTypeAad`. chrono, `rust_decimal` and `uuid` sources behind features; `hlist` stays opt-in; a docs-hidden `test-support` feature for sibling crates' tests |
| `vitaminc-encrypt`     | `Aes256Cipher` with its `SeqCipher`, `MapCipher` and `AesDecipher`, `Key`, static cipher                                     | `impl Cipher for Aes256Cipher` (`seal` and `open`) and `Key`; the `opening_version_1()` view (`OpensVersion1`); `AesCipherText = Node<LocalCipherText>`; the `encrypt_with_key`/`decrypt_with_key` facade; re-exports of `encrypt`, `decrypt`, `decrypt_into`, `Plaintext`, `Decrypt` and others. Container logic moves up into `EncryptSink`. The `hlist` static cipher stays |
| `vitaminc-aead-frame`  | `vitaminc-aead-value`: `Value`, `ValueKind`, tags, transport codec for values and ciphertexts, `canonical` feature          | Renamed. The ciphertext codec (`encode_ciphertext`/`decode_ciphertext` over `Node<Leaf>`), plus re-exports of the frame and the tag table from `vitaminc-aead` so a binding has the whole transport. `Value` and `ValueKind` are deleted; `CT_NONE` is retired as `CT_NONE_RETIRED` |
| `vitaminc-normalize`   | the `canonical` feature of `vitaminc-aead-value`                                                                           | New crate. Public per-scalar encoders (`normalize`, `domain_of`, `NormalizeError`), frozen domain labels, the logical-type opt-in table, `Terms`, `Term { path, normalized }`, `terms`, `plan_with_terms`, `encrypt_with_terms` and its async form, `TermError`, `TermsError`, `Normalized { domain, bytes }`, `Path`/`Step` re-exported. No cryptography of its own, no PAE |

The transport crate's new name follows the `vitaminc-aead-*` family it
already belongs to with `vitaminc-aead-napi` and `vitaminc-aead-derive`,
and names what it holds.

Around them:
- `vitaminc-context` keeps PAE and `ContextPiece`, and loses
  `Context::for_none`.
- `vitaminc-prf` takes `Normalized` instead of `&Value`, behind its
  `normalize` feature.
- `vitaminc-aead-napi` replaces its `Value` conversions with `JsRef` and
  `JsBuilder`, and its wrapper objects with wrapper classes.
- The Go guest replaces `decode_value` and `encode_value` with `Frame` and
  `decrypt_to_frame`.
- `vitaminc-aead-derive` generates `Plaintext` and `Decrypt` instead of
  `Encrypt` and `Decrypt`, including for fieldless enums. Under #449 it
  becomes `#[derive(Encrypt)]`.

### 9. Names

The trait names stay close to the old ones, because the design is the same
design with the type information kept: a cipher is still a `Cipher`, an
async one is an `AsyncCipher`, a typed decryption target is still
`Decrypt`, and the functions are `encrypt`, `encrypt_async`, `decrypt` and
`decrypt_async`. `Sink` is new because the concept is. `Value`,
`ValueKind`, `Decipher`, `DecipherVisitor`, `SeqAccess` and `MapAccess` are
removed from `vitaminc-aead`. (`vitaminc-prf` has its own, unrelated
`SeqAccess`, `MapAccess` and `PrfVisitor`.)

As implemented in #416–#448, the source trait is `Plaintext`, named so
because the trait no longer encrypts anything. Before release it is renamed
`Encrypt` (#449), so the trait pair a user implements, almost always by
derive, is `Encrypt` and `Decrypt`. `Plaintext` in this document is the
interim name. #449 also moves refusals for derived types to compile time;
this section will be updated with its reasoning when it merges.

## Consequences

- Hosts need no intermediate value type. Go encrypts from its frame and
  decrypts into one; Node walks live objects and builds live objects. A
  host-side failure during the walk surfaces as that host's error.
- Adding a logical type is local: a variant, a wire id, a validity rule, a
  `Plaintext` source and a `Decrypt` target. Encryption, decryption, the
  frame, the codec and `Tee` need no change. The terms sink refuses the new
  type with `NoDomain`, which stops the walk, until normalize's opt-in table
  gives it a domain. Node's `JsBuilder` refuses it until the binding has a
  carrier for it (#446). Adding a physical kind is deliberately a compile
  error in every sink.
- Index sinks never index a logical value as its physical value. A logical
  type with no domain gets a `TermError` (`NoDomain`) at its path, which
  stops the walk, not a term. A null, a boolean or `undefined` is skipped.
- `EncryptSink` and `Terms` keep the same shape rules through
  `vitaminc_aead::shape`, so `terms()` accepts exactly the values
  `encrypt_with_terms` accepts. Every refusal says where it happened: an
  `EncryptError::Shape(Refusal)` or a `TermError` carries a `Path`, and
  `Debug` masks the map keys in it.
- A cipher is `seal` and `open`. A 0KMS cipher adds a batching `seal_many`
  and makes one round trip per document. Stack Encrypt's async `Decipher`
  implementation becomes an `AsyncCipher` implementation with no container
  logic.
- Every leaf's plaintext exists at once before sealing, inside `Protected`,
  instead of streaming leaf by leaf. Memory is of the order of the plaintext
  itself.
- A timestamp at a leap second is refused and a decimal negative zero reads
  back as zero. Both were in the conformance corpus, so this is a small
  format change; the corpus now pins the refusal and the normalization
  (#444).
- `Option::None` and a host null are the same leaf. `CipherText::None`,
  `CT_NONE` and `Context::for_none` (in `vitaminc-context`) go away, and a
  JavaScript `null` decrypts into a Rust `Option` as `None`.
- `LeafTypeAad` binds the physical kind and the logical id under the new
  domain label `vitaminc/aead/leaf-type/v2`. Ciphertexts bound under the old
  label do not open under it. The type moves from
  `vitaminc_aead_value::LeafTypeAad`, which shipped in 0.3.0 through 0.5.1,
  to `vitaminc_aead::LeafTypeAad`. That is a breaking change for users of
  `vitaminc-aead-value`.
- Under a logical type the int's width is not kept: `DATE` reads back as an
  `i32` day count however it was written. Width is a hint end to end;
  equality never sees it and typed decoding reads the value.
- Static Rust leaves gain one tag byte each, and every ciphertext is
  self-describing.
- Tagged leaves are sealed as wire version 2, so 0.5 `Encrypt` ciphertext
  is refused rather than misread, and has to be decrypted with 0.5 and
  encrypted again. `Value`-path version 1 leaves open only through
  `Aes256Cipher::opening_version_1()`.
- Passthrough payloads are frames, not `Box<dyn Any + Send>`. A Rust
  passthrough value must implement `Plaintext + Clone`, and the derive
  passes it a reference.
- Node's `{ date }` and `{ decimal }` objects are replaced by the
  `VcDate`, `VcTimestamp`, `VcDecimal` and `VcUuid` classes, so one-key
  objects are ordinary data again.
- `AsyncCipher: Sync`, because an async cipher is shared across tasks.
  `Aes256Cipher` is not `Sync` (its nonce generator is a `RefCell`) and is
  not made so: it is the synchronous `Cipher`. A local cipher that has to
  sit behind an async API goes behind a mutex or uses a `Sync` nonce
  generator of its own.
- The model is core and runtime-free. `AsyncCipher` needs no executor, and
  the batching defaults use `futures-util` only. The optional sources sit
  behind features, in line with the minimal and compatible goals.
- The visitor-based `Encrypt`, `Decrypt<'c>`, `Cipher`'s container methods,
  `Decipher`, `DecipherVisitor`, `SeqAccess`, `MapAccess`, `Value` and
  `ValueKind`, which shipped in the 0.3 to 0.5 crates, are removed in a
  breaking release. No CipherStash product that depends on them has
  shipped. The `Encrypt` name is reused for the new source trait (#449).
