---
status: proposed
---

# Describe plaintext once and consume it with sinks

Stack Encrypt is unreleased, so vitaminc's encryption data model is still
open to change. This decision replaces the `Encrypt`/`Cipher` and
`Decrypt`/`Decipher` trait pairs and the `Value` enum with a serde-style
split between a type that describes itself (`Plaintext`) and the things
that consume that description (`Sink`). Encryption, index terms, transport
frames, host-language builders and typed decoding are all sinks over one
walk. Ciphers shrink to sealing and opening bytes, synchronously or
asynchronously, and a remote key provider seals a whole document in one
round trip.

## Context

### What exists today

`vitaminc-aead` has four traits and two sub-protocols on each side:

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
`visit_none`, `visit_passthrough`), `SeqAccess` and `MapAccess` complete the
decrypt side. `vitaminc-aead-value` adds `Value`, a twenty-three-variant enum
(twenty scalars, array, object and passthrough) that host languages convert
into and out of, with a frozen one-byte tag per scalar variant, a `ValueKind` inventory, a transport codec for the wasm
boundary, and a `canonical` feature that produces equality inputs from a
`Value`.

### What is wrong with it

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
    fn passthrough<P: Plaintext>(self, value: P) -> Result<Self::Ok, Self::Error>;
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

    /// A sink for the value under `key`. Keys travel in the clear, as today.
    fn entry(&mut self, key: &str) -> Result<Self::Entry<'_>, Self::Error>;
    fn end(self) -> Result<Self::Ok, Self::Error>;
}

/// Every sink's error type can carry a failure from the source.
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

Today a container hands each child to the cipher as a value, and the cipher
walks it:

```rust
// Today. The cipher receives the element and drives its walk.
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
one finished child into the parent. The element sink's `Ok` is `()` because
its result goes into the parent, not back to the caller. The borrow means
only one element sink exists at a time, so children land in order, and the
parent's `end` runs only after the last child is done.

This is what the encrypting sink does with it. Its sequence sink is a
vector of finished child nodes plus the AAD every element is sealed under;
`element` hands out a sink whose output slot is that vector:

```rust
pub struct EncryptSeq<'p> {
    aad: Context<'static>,           // the container's own AAD, for the empty marker
    element_aad: Context<'static>,   // aad.for_sequence_element(), shared by every child
    items: Vec<CipherText<Pending>>,
    out: Slot<'p>,                   // where the finished sequence node goes
}

impl SeqSink for EncryptSeq<'_> {
    type Element<'s> = EncryptSink<Push<'s>> where Self: 's;

    fn element(&mut self) -> Result<Self::Element<'_>, Self::Error> {
        Ok(EncryptSink { aad: self.element_aad.clone(), out: Push(&mut self.items) })
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        let node = match self.items.len() {
            0 => CipherText::EmptySequence(marker(self.aad.for_empty_sequence())),
            _ if nothing_sealed(&self.items) => return Err(EncryptError::Shape("sequence has nothing sealed")),
            _ => CipherText::Sequence(self.items),
        };
        Ok(self.out.put(node))
    }
}
```

`Push(&mut items)` is the output slot: when the element sink receives a
scalar it plans one `Pending` leaf and pushes `CipherText::Single(leaf)`
onto `items`; when it receives a nested sequence it returns another
`EncryptSeq` whose slot is the same vector, so the nested node is pushed
when that inner `end` runs. The map sink is the same with `(key, node)`
pairs, `for_map_entry(key)` as the child AAD and a `HashSet` for duplicate
keys. These few lines are the whole of the container logic that today is
spread across `Aes256Cipher`'s `SeqCipher`, `MapCipher` and `AesDecipher`.

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
    fn passthrough<P: Plaintext>(self, value: P) -> Result<Self::Ok, Self::Error> { /* see below */ }
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
`vec![1u8, 2u8]` walked into `Tee(EncryptSink, Terms)`:

| Source call                        | `EncryptSink` receives                | `Terms` receives                     |
| ---------------------------------- | ------------------------------------- | ------------------------------------ |
| `sink.seq(Some(2))`                | `seq(Some(2))`: start a node list     | `seq(Some(2))`: push path index 0    |
| `seq.element()`                    | `element()`: sink into the list       | `element()`: sink at path `[0]`      |
| `1u8.visit(element)` → `scalar`    | plan leaf `INT8 1` under element AAD  | term `(int domain, encoded 1)` at `[0]` |
| `seq.element()`                    | `element()`                           | `element()`: path `[1]`              |
| `2u8.visit(element)` → `scalar`    | plan leaf `INT8 2`                    | term at `[1]`                        |
| `seq.end()`                        | `end()`: `CipherText::Sequence`       | `end()`: pop path                    |

Nothing is copied: `Physical<'_>` borrows the scalar's text or bytes, and
both sides read the same borrow. The two sides must share an error type,
which is why `Error` is a trait the tee can bound on; a sink meant for
teeing, such as `Terms`, is generic over its error type and adopts its
partner's. `encrypt_with_terms` is then one line:

```rust
let mut terms = Vec::new();
let (pending, ()) = value.visit(Tee(EncryptSink::root(aad), Terms::new(&mut terms)))?;
let ct = seal_all(cipher, pending)?;   // terms are complete before this line
```

The one call a tee cannot share is `passthrough`, which hands a whole
subtree to each sink to walk for itself. The tee frames the subtree once
and gives both sides the frame. Passthrough is cleartext by contract, so the
copy is harmless.

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

The leaf implementations are one line each: `String` calls
`sink.scalar(None, Physical::Text(&self))`, `u32` calls
`sink.scalar(None, Physical::Int(Int::U32(self)))`, and `NaiveDate` calls
`sink.scalar(Some(Logical::Date), Physical::Int(Int::I32(days)))`.
`Vec<T>`, slices, `Option<T>`, `Protected<T>` and the chrono, `rust_decimal`
and `uuid` types get implementations in `vitaminc-aead`, the last three
behind features.

How the pieces map onto what exists today:

| Today                                                 | After                                         |
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

**Integers are one physical kind, not ten.** Today `Int8` through `UInt128`
are ten `Value` variants, ten tags, ten `ValueKind`s and ten cipher paths,
and nothing says they are the same thing. Here they are one kind whose
width is a hint for host fidelity: Go's `int32` comes back as `int32`, a
JavaScript BigInt keeps the narrowest width that fits. Nothing else looks at
the width. Every width shares one equality domain, so `Int::I8(34)` and
`Int::U64(34)` produce the same term. A typed target reads the value, not
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
  this build does not know arrives as `Logical::Unknown(id, param)` and
  leaves the same way.
- **Index sinks opt in.** The equality sink has a table of the logical types
  it understands, each with its domain label and normalization, and refuses
  the rest with `NoDomain`. A date's day count never collides with the
  integer it equals, because the date is indexed under the date domain.

Adding a logical type is a variant, a wire id, a validity rule, a `Plaintext`
source and a `Decrypt` target. Adding a physical kind is deliberately a
compile error in every sink, because it changes what every consumer has to
handle.

Every `Value` variant has one call in the new model:

| `Value` today                      | `Sink` call                                                     |
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

### 3. The wire format does not change for anything that exists today

The sealed leaf is `[tag] ++ payload` inside the AEAD envelope, and the
transport frame uses the same tags. Both stay byte for byte. Today's tags
are read as shorthand for a physical kind plus a logical type:

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
the byte `0xF3`, the logical id, the one-byte parameter, then the plain
physical scalar. A reader that does not know the id still reads the
physical value and keeps the annotation. There is exactly one encoding per
value: an envelope is refused where a shorthand tag exists, so two
ciphertexts of the same value are never byte-different for a reason the
AEAD cannot see.

Two values in today's corpus have no physical-plus-logical form and are
refused: a timestamp at a leap second (chrono's representation, nanoseconds
above 999,999,999) and a decimal negative zero. Both are format changes and
are listed under consequences.

### 4. Encryption is a sink, and the cipher is bytes-only and may be async

`EncryptSink` turns each scalar into tagged leaf plaintext and owns every
container rule in one place: element AAD (`for_sequence_element`), entry AAD
(`for_map_entry(key)`), the authenticated empty markers (`for_empty_sequence`,
`for_empty_map`, `for_none`), duplicate keys, and the rule that a container
must seal at least one leaf. It never calls a cipher. Its output is a tree
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
    /// leaf concurrently; a provider with a batch API overrides it to make
    /// one round trip per document.
    fn seal_many(&self, leaves: Vec<Pending>)
        -> impl Future<Output = Result<Vec<Self::Leaf>, Self::Error>> + Send { /* try_join_all */ }
    fn open_many(&self, leaves: Vec<(Self::Leaf, Context<'static>)>)
        -> impl Future<Output = Result<Vec<Protected<Vec<u8>>>, Self::Error>> + Send { /* try_join_all */ }
}
```

The entry points:

```rust
pub fn encrypt<P, C>(value: P, cipher: &C, aad: impl IntoAad<'_>)
    -> Result<CipherText<C::Leaf>, EncryptError<C::Error>>
where P: Plaintext, C: Cipher;

pub async fn encrypt_async<P, C>(value: P, cipher: &C, aad: impl IntoAad<'_>)
    -> Result<CipherText<C::Leaf>, EncryptError<C::Error>>
where P: Plaintext, C: AsyncCipher;

pub fn decrypt<T, C>(cipher: &C, ct: CipherText<C::Leaf>, aad: impl IntoAad<'_>)
    -> Result<T, DecryptError<DecodeError>>
where T: Decrypt, C: Cipher;

pub async fn decrypt_async<T, C>(...) where T: Decrypt, C: AsyncCipher;

/// Decrypt into any sink: a host builder, a frame writer.
pub fn decrypt_into<S, C>(cipher: &C, ct: CipherText<C::Leaf>, aad: impl IntoAad<'_>, sink: S)
    -> Result<S::Ok, DecryptError<S::Error>>
where S: Sink, C: Cipher;

pub async fn decrypt_into_async<S, C>(...) where S: Sink, C: AsyncCipher;
```

`encrypt` is two steps: walk the plaintext into `EncryptSink` to get a
`CipherText<Pending>`, then seal. Sealing splits the tree into its shape and
a vector of leaves in walk order, calls `seal` per leaf or `seal_many` once,
and puts the sealed leaves back into the shape. A cipher that returns the
wrong number of leaves is refused. Decryption mirrors it: derive each
leaf's AAD from its position, open every leaf (one `open_many` call for an
async cipher), put the plaintexts back, then walk the opened tree into the
sink. The walk itself is always synchronous, whichever cipher is in use.

Why this shape:

- **The walk never awaits.** A native binding walks a live host value on
  the host's thread; that walk cannot suspend. Only the leaf calls are
  async, so a plain `async fn` trait expresses them and the `Ok<T>` GAT and
  `map_ok` are gone.
- **One round trip per document.** 0KMS seals every leaf of a document in
  one `seal_many` call. A provider without a batch API gets the default,
  which is one concurrent call per leaf and still correct.
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

Compared with today's `Cipher`, which has eight methods and two sub-traits,
and `Decipher`, which has seven plus a visitor and two access traits, a
cipher is now two methods, or four with batching. `Aes256Cipher` keeps its
key and nonce generator and loses its container logic. Static Rust callers
get the same tagged leaves as hosts do, so there is one leaf format and
every ciphertext is self-describing.

### 5. Typed decryption names a sink

Today's `Decrypt<'c>` supplies a `DecipherVisitor` and threads the cipher's
`Ok<T>` through `map_ok`. The replacement is a type that names the sink that
builds it:

```rust
pub trait Decrypt: Sized {
    type Sink: Sink<Ok = Self, Error = DecodeError>;
    fn sink() -> Self::Sink;
}

/// A type that decodes from one scalar.
pub trait FromScalar: Sized {
    const EXPECTED: &'static str;
    fn from_scalar(ty: Option<Logical>, value: Physical<'_>) -> Option<Self>;
}
```

Every `FromScalar` type gets `Decrypt` through a shared `ScalarSink<T>`,
which refuses sequences, maps and passthrough. `NaiveDate` accepts
`(Some(Date), Int)` and nothing else; `u32` accepts `(None, Int)` whose
value fits; `Option<T>` accepts null and otherwise defers to `T`. A struct's
sink is what `#[derive(Decrypt)]` generates: a `MapSink` that routes each
entry to the field's own sink and refuses unknown keys and missing fields.
Nothing in a `Decrypt` implementation knows whether the cipher was sync or
async, because the opened tree is walked after every await has completed.

### 6. Host bindings implement the two traits instead of converting to `Value`

The data model is the FFI boundary. Each binding supplies a `Plaintext`
for values coming in and a `Sink` for values going out, and nothing in
between.

**Go** already ships values as transport frames across the wasm boundary.
`Frame<'a>` is a validated, borrowed frame that implements `Plaintext` by
walking its own bytes in place: no `Value` tree is built, and no scalar
leaves the buffer except to go straight to a sink. `FrameWriter` is a `Sink`
that writes frame bytes. The guest's `encrypt` becomes
`encrypt(Frame::parse(bytes)?, &cipher, aad)` and its `decrypt` becomes
`decrypt_into(&cipher, ct, aad, FrameWriter::new(&mut out))`. The Go side,
`vcvalue` and `vcencrypt`, does not change: the bytes in and out are the
same, with the `0xF3` envelope appearing only when a value carries a
logical type that has no shorthand tag.

**Node** walks live JavaScript values. `JsRef<'e>(Unknown<'e>)` implements
`Plaintext` on the JavaScript thread, and `JsBuilder` implements `Sink` and
builds JavaScript values. A getter that throws or a string with an unpaired
surrogate stops the walk through `Error::source` and comes back to
JavaScript as that error. To encrypt off the JavaScript thread, the binding
snapshots with `to_frame(JsRef(v))` and encrypts the frame on the worker.
The mapping:

| JavaScript                          | `Sink` call                                       |
| ----------------------------------- | ------------------------------------------------- |
| `null`                              | `scalar(None, Null)`                              |
| `undefined`                         | `scalar(Some(Undefined), Null)`                   |
| `boolean`                           | `scalar(None, Bool)`                              |
| `number`                            | `scalar(None, Float(F64))`                        |
| `bigint`                            | `scalar(None, Int(narrowest fitting width))`      |
| `string`                            | `scalar(None, Text)`                              |
| `Buffer`, `Uint8Array`              | `scalar(None, Bytes)`                             |
| `Date`                              | `scalar(Some(Timestamp(Millis)), Int(I64(ms)))`   |
| `Array`                             | `seq`, then `element()` per index                 |
| plain object                        | `map`, then `entry(key)` per own property         |

A JavaScript `Date` is a count of milliseconds, so it is stored as one,
rather than converted to seconds and nanoseconds and back. How the binding
represents a calendar date or a decimal in JavaScript (today, the reserved
`{ date }` and `{ decimal }` wrapper objects) is the binding's decision and
is not changed by this document.

**Passthrough** is a subtree that travels in the clear. On the way in it is
walked like anything else and the encrypt sink frames it; on the way out
the frame is parsed and handed to the sink's `passthrough`. The payload is
therefore a frame in every binding and in static Rust, which replaces the
`Cipher::Passthrough` associated type and the `Box<dyn Any + Send>`
downcast. The contract is unchanged: passthrough is unencrypted,
unauthenticated and for non-sensitive fields only.

### 7. Index terms are a sink, and normalization is its own crate

The equality encoders behind today's `canonical` feature become public and
move to `vitaminc-normalize`. `Terms` is a `Sink` that produces one term per
scalar: a frozen domain label and the normalized bytes.

```rust
pub struct Normalized {
    pub domain: &'static str,
    pub bytes: Protected<Vec<u8>>,
}

pub fn encrypt_with_terms<P, C>(value: P, cipher: &C, aad: impl IntoAad<'_>)
    -> Result<(CipherText<C::Leaf>, Vec<Term>), EncryptError<C::Error>>
where P: Plaintext, C: Cipher;
```

`vitaminc-prf` consumes `Normalized`. `vitaminc-normalize` has no
cryptography in it and never imports PAE, which stays in `vitaminc-context`
beneath everything.

### 8. Four crates

| Crate                  | Today                                                                                                                      | After                                                                                                                                                                                                  |
| ---------------------- | -------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `vitaminc-aead`        | `Encrypt`, `Cipher`, `SeqCipher`, `MapCipher`, `Decrypt`, `Decipher`, `DecipherVisitor`, `SeqAccess`, `MapAccess`, `CipherText`, `Context` | `Plaintext`, `Sink`, `SeqSink`, `MapSink`, `Physical`, `Logical`, the leaf codec and tag table, `Cipher`, `AsyncCipher`, `Pending`, `EncryptSink`, `encrypt`/`decrypt` and their async and `_into` forms, `Decrypt`, `FromScalar`, `Tee`, `CipherText`, `Context`. chrono, `rust_decimal` and `uuid` sources behind features |
| `vitaminc-encrypt`     | `Aes256Cipher` with its `SeqCipher`, `MapCipher` and `AesDecipher`, `Key`, static cipher                                     | `impl Cipher for Aes256Cipher` (`seal` and `open`) and `Key`. Container logic moves up into `EncryptSink`                                                                                             |
| `vitaminc-aead-value`  | `Value`, `ValueKind`, tags, transport codec for values and ciphertexts, `canonical` feature                                 | Renamed. `Frame`, `FrameWriter`, the ciphertext codec and `PassthroughFrame` only. `Value`, `ValueKind` and the tag table leave (tags go to `vitaminc-aead` with the leaf codec)                        |
| `vitaminc-normalize`   | the `canonical` feature of `vitaminc-aead-value`                                                                           | New crate. Public per-scalar encoders, frozen domain labels, the logical-type opt-in table, `Terms`, `encrypt_with_terms`, `Normalized { domain, bytes }`. No cryptography, no PAE                       |

Around them: `vitaminc-context` is unchanged and keeps PAE and
`ContextPiece`; `vitaminc-prf` takes `Normalized` instead of `&Value`;
`vitaminc-aead-napi` replaces its `Value` conversions with `JsRef` and
`JsBuilder`; the Go guest replaces `decode_value` and `encode_value` with
`Frame` and `FrameWriter`; `vitaminc-aead-derive` generates `Plaintext`
and `Decrypt` instead of `Encrypt` and `Decrypt`.

### 9. Names

The trait names stay close to today's, because the design is the same
design with the type information kept: a cipher is still a `Cipher`, an
async one is an `AsyncCipher`, a typed decryption target is still
`Decrypt`, and the functions are `encrypt`, `encrypt_async`, `decrypt` and
`decrypt_async`. `Plaintext` replaces `Encrypt` because the trait no longer
encrypts anything, and `Sink` is new because the concept is. `Value`,
`ValueKind`, `Decipher`, `DecipherVisitor`, `SeqAccess` and `MapAccess` are
removed.

## Consequences

- Hosts need no intermediate value type. Go encrypts from its frame and
  decrypts into one; Node walks live objects and builds live objects. A
  host-side failure during the walk surfaces as that host's error.
- Adding a logical type is local: a variant, a wire id, a validity rule, a
  `Plaintext` source and a `Decrypt` target. Encryption, decryption, the
  frame, the codec, `Tee` and the terms sink need no change. Adding a
  physical kind is deliberately a compile error in every sink.
- Index sinks never index a logical value as its physical value, and a
  logical type with no domain gets `NoDomain`, not a term.
- A cipher is `seal` and `open`. A 0KMS cipher adds a batching `seal_many`
  and makes one round trip per document. Stack Encrypt's async `Decipher`
  implementation becomes an `AsyncCipher` implementation with no container
  logic.
- Every leaf's plaintext exists at once before sealing, inside `Protected`,
  instead of streaming leaf by leaf. Memory is of the order of the plaintext
  itself.
- A timestamp at a leap second and a decimal negative zero are refused. Both
  are in the conformance corpus today, so this is a small format change.
- Under a logical type the int's width is not kept: `DATE` reads back as an
  `i32` day count however it was written. Width is a hint end to end;
  equality never sees it and typed decoding reads the value.
- Static Rust leaves gain one tag byte each, and every ciphertext is
  self-describing.
- Passthrough payloads are frames, not `Box<dyn Any + Send>`. A Rust
  passthrough value must implement `Plaintext`.
- `Aes256Cipher` is not `Sync` today, because its nonce generator is a
  `RefCell`. `AsyncCipher: Sync` is required so a cipher can be shared across
  tasks; a local cipher used asynchronously needs a `Sync` nonce generator.
- The model is core and runtime-free. `AsyncCipher` needs no executor, and
  the batching defaults use `futures-util` only. The optional sources sit
  behind features, in line with the minimal and compatible goals.
- `Value`, `ValueKind`, `Encrypt`, `Decrypt` in its current form, `Cipher`'s
  container methods, `Decipher`, `DecipherVisitor`, `SeqAccess` and
  `MapAccess` are removed. Nothing that depends on them has shipped.

## Open questions

- Whether `Option::None` keeps a node of its own (`CipherText::None`) or
  reads as null, possibly as another logical type over null like
  `undefined`.
- Whether the leaf type bound into the AAD is the physical tag alone or the
  physical tag plus the logical id and parameter. PAE makes either
  unambiguous; it is a protocol choice.
- Whether uuid gets an equality domain, which would be the bytes encoding
  under its own label.
- Whether logical parameters ever need more than one byte (a timezone, a
  precision and scale pair).
- Whether to normalize decimal negative zero to zero or refuse it as leap
  seconds are refused.
- The transport crate's new name.
