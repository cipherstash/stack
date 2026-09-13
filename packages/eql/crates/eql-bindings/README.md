# eql-bindings

Canonical wire types for EQL payloads — **one Rust definition per payload
shape**, the single source of truth for every tool that produces or consumes
EQL payloads (`cipherstash-client`, `protect-ffi`, CipherStash Proxy).

TypeScript bindings are generated from these definitions via [`ts-rs`] into
[`bindings/`](bindings/), and JSON Schemas via [`schemars`] into
[`schema/`](schema/).

## Why

Type information is lost at every hop of `EQL → cipherstash-client →
protect-ffi → stack`. protect-ffi hand-writes its TypeScript types; they drift
from the Rust they describe; stack widens them further. The result is bugs
like the `protect-dynamodb` search-term check that validates a payload shape
EQL never actually defined. A generated, single-source crate removes the
hand-copying.

## Capability-encoded types

The [`src/v3/`](src/v3/) module has one type per **SQL domain** in the
`eql_v3` schema — `Integer` / `IntegerEq` / `IntegerOrd` / `IntegerOrdOre`, and likewise
for `smallint`, `bigint`, `date`, `timestamp`, `numeric`, and `text` (which adds
`TextMatch`) — each carrying its index terms as **required** fields. The
capability is the type identity; `Option` never appears. A payload missing
its term key fails to deserialize: the Rust analogue of the SQL domain's
CHECK constraint.

Shared wire fields are reusable newtypes in
[`src/v3/terms.rs`](src/v3/terms.rs):

| Newtype | Wire key | Inner | Backs |
|---------|----------|-------|-------|
| `Ciphertext` | `c` | `String` | every domain (envelope) |
| `Hmac256` | `hm` | `String` | `_eq` domains + the text ordering/search domains |
| `OpeCllw` | `op` | `String` | `_ord` / `_ord_ope` domains, `text_search` |
| `OreBlock256` | `ob` | `Vec<String>` | `_ord_ore` domains, `text_search_ore` |
| `BloomFilter` | `bf` | `Vec<i16>` (signed!) | `_match` domains |

Note "v3" names the SQL schema generation (`eql_v3.*`); the JSON envelope
version is `v: 3` — the generated domain CHECKs assert `VALUE->>'v' = '3'`, and
the wire field names are unchanged from v2 (the purpose-named rename in
`docs/plans/eql-payload-scheme-discipline-rfc.md` is deferred).

## Drift protection

`tests/catalog_parity.rs` asserts the domain inventory —
[`v3::all()`](src/v3/mod.rs), a `Vec<Box<dyn DomainType>>` of zero-sized
type-level handles — exactly covers `eql-domains::CATALOG` (the same catalog
that generates the `eql_v3` SQL surface): every domain, in order. Adding a
scalar to the catalog without adding its types here fails the build.
Wire-key strictness (required term keys, unknown-key rejection, envelope
version) is covered per-type in `tests/v3_conformance.rs` and pinned against
the catalog by the JSON Schema parity test in the stacked schemars change.

## Develop

```sh
mise run types:generate   # clean-regenerate bindings/ and schema/
mise run types:check      # regenerate + fail if checked-in outputs are stale
```

Both wrap `cargo test -p eql-bindings`, which runs the conformance tests and
regenerates `bindings/` (TypeScript, via ts-rs) and `schema/` (JSON Schema,
via `tests/export.rs`, with canonical `$id`s injected). Both directories are
checked in so reviewers can see the codegen output without running anything;
CI runs `types:check` to keep them fresh. The crate is also part of the lean
`mise run test:crates` set (fmt, clippy, test — no database).

Note that both exporters default to writing under the crate dir (ts-rs to
`./bindings`, `tests/export.rs` to `./schema`), so a plain
`cargo test -p eql-bindings` (and therefore `mise run test:crates`) regenerates
`bindings/` and `schema/` **in place** as a side effect — it can leave your
working tree dirty if the checked-in copies were stale. Only `types:generate`
isolates the writes (it exports into a temp dir and swaps them in after the
build succeeds).

Published `eql-bindings` crates also include `eql_bindings::sql`, which exposes
the exact self-contained SQL installer and uninstaller built for the same EQL
release identity as the Rust wire types.

## Future direction: self-describing payloads

On the wire, a v3 payload is discriminated only by *which key is present*
(`hm` vs `ob` vs `bf`) — the SQL domain name carries the rest. Once the JSON
leaves SQL (into protect-ffi, into TypeScript, into a log line) that
information is gone, and a consumer is back to sniffing keys: the untagged
failure mode that produced the original protect-dynamodb bug. An earlier
prototype here carried an `IntegerTagged` enum with a one-field capability tag
(`"x": "integer_eq"`), which generates a clean TypeScript discriminated union
and a JSON Schema `oneOf` with per-branch `const`s. It was removed because
the tag is not part of the v3 wire contract (the generated domain CHECKs
know no `x` key) — but it remains the recommended shape if a future payload
revision adds a discriminator. See
`docs/plans/eql-payload-scheme-discipline-rfc.md` for the wider payload
evolution plan.

[`ts-rs`]: https://github.com/Aleph-Alpha/ts-rs
[`schemars`]: https://graham.cool/schemars/

## Rust text equality with Stack Encrypt

The optional `stack-encrypt` feature enables `EncryptFrom<String>` for `TextEq`
and `TextEqQuery`, and `DecryptInto<String>` for `TextEq`. Other domains do not
yet expose these conversions. The derives are emitted by `eql-codegen`.

```rust,ignore
use eql_bindings::{Identifier, v3::text::{TextEq, TextEqQuery}};

let column = Identifier::for_column("users", "email")?;
let keyset = cipher.default_keyset();
let email = "alice@example.com".to_owned();
let stored: TextEq = keyset.encrypt_as(&email, column.clone()).await?;
let query: TextEqQuery = keyset.encrypt_as(&email, column.clone()).await?;
let opened: String = cipher.decrypt_as(stored, column.into()).await?;
```

Both identifier components must be nonempty. Encryption stores the identifier
in `i`; its table and column supply the ciphertext AAD, term context, and ZeroKMS
descriptor. The storage field names `c` and `hm` add no further context.
Decryption validates `i` before retrieving keys. Passing an expected identifier,
as above, also checks the destination. `Default::default()` uses the stored
identifier alone, so moving a complete payload with its original `i` still opens.

Ciphertext uses Vitamin C's native string encoding. Equality uses its exact
string PRF input, with no normalization or case folding: `café` and
`cafe\u{301}`, or `Alice` and `alice`, produce different terms. A query contains
only `v`, `i`, and `hm` and requests no data keys. Neither EQL type implements
the plaintext-side `Encrypt` or `Decrypt` traits.

This is a **new producer profile**, independent of existing cipherstash-client
ciphertext and terms. `c` is `stack-encrypt:1:` followed by padded standard base64 of Stack
Encrypt's native `SealedValue` bytes; `hm` is the native 32-byte equality term
encoded as hex. Serde handles the final EQL JSON envelope only. SQL consumes
these payloads through the existing `public.eql_v3_text_eq` and
`eql_v3.query_text_eq` domains and their equality extractor index. Writers and
query producers for these values must use this same profile.

### Developing against the unpublished crates

Stack Encrypt and its runtime prerequisites must be published before the normal
registry-based build, CI, and `eql-bindings` publication can succeed. Regenerate
`Cargo.lock` without local overrides once they are published, before merging.
During development, use a checkout containing
[cipherstash-suite#2215](https://github.com/cipherstash/cipherstash-suite/pull/2215)
(tested with commit `cbb3e000009b5974e90ec7da98d015b4b19a7270`):

```bash
# From packages/eql. Generates a temporary Cargo patch; no local paths are committed.
bash tasks/dev/with-stack-encrypt.sh /path/to/cipherstash-suite \
  test -p eql-encryption-tests
bash tasks/dev/with-stack-encrypt.sh /path/to/cipherstash-suite \
  test -p eql-bindings --features stack-encrypt

# Against a disposable PostgreSQL database, using fresh encryption and a fake KMS:
psql "$EQL_TEST_DATABASE_URL" -v ON_ERROR_STOP=1 \
  -f crates/eql-bindings/sql/cipherstash-encrypt.sql
bash tasks/dev/with-stack-encrypt.sh /path/to/cipherstash-suite \
  test -p eql-encryption-tests --test text_eq -- --ignored
```
