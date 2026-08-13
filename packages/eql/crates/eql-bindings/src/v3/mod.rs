//! # `eql_v3` domain payload types
//!
//! One Rust struct per **SQL domain** in the `eql_v3` schema — the
//! capability-encoded design from the original integer scalar prototype
//! (PR #236's first cut), formalized:
//! the SQL surface is generated from `eql-domains::CATALOG`, and these types
//! mirror it 1:1 — `all()` is generated from the same catalog (`inventory.rs`),
//! so it cannot drift; the published JSON Schema wire contract is pinned by
//! `tests/catalog_parity.rs` and the emitted `.ts` property order by
//! `tests/ts_property_order.rs`.
//!
//! **Versioning.** "v3" is the SQL schema generation (`eql_v3.*` domains),
//! and the v3 tier now carries the matching JSON envelope version `v: 3`
//! ([`crate::EQL_SCHEMA_VERSION`]) — every generated domain CHECK asserts
//! `VALUE->>'v' = '3'`. The wire field names are unchanged from v2
//! (`hm`/`ob`/`bf`, plus the new `op`; the purpose-named rename in the
//! payload-scheme-discipline RFC is deferred). The legacy `eql_v2` wire
//! (documented by `docs/reference/schema/eql-payload-v2.*.schema.json`)
//! stays `v: 2`.
//!
//! ## Shape of every flat scalar payload
//!
//! For the generated flat-scalar families, every payload has the shared envelope
//! keys (required by every scalar domain CHECK, mirroring `ENVELOPE_KEYS` in
//! `eql-domains`): `v`, `i`, `c`. Then the domain's required term keys — `hm`
//! for `_eq`, `ob` for `_ord`/`_ord_ore`, `op` for `_ord_ope`, `bf` for
//! `_match`, none for
//! storage-only. `Option` does not appear in the generated scalar structs: the
//! capability **is** the type identity. Hold a [`integer::IntegerEq`] and `hm` is
//! present, guaranteed by the Rust type and (SQL-side) by the domain CHECK. A
//! missing term key is a deserialization error — the Rust analogue of the CHECK
//! constraint.
//!
//! One exception to "`ob` for `_ord`": `text`'s ordered domains carry **both**
//! `hm` and the ordering term (`text_ord`/`text_ord_ore`/`text_search` carry
//! `hm` + `ob`; `text_ord_ope` carries `hm` + `op`), where the non-text
//! ordered domains carry the ordering term alone. Text routes `=`/`<>`
//! through `hm` rather than the ordering term because lexicographic ORE/OPE
//! over text is not equality-lossless, so equality needs the HMAC. The
//! generated struct doc surfaces this structurally — its required-keys line
//! lists `hm` `ob` (or `hm` `op`) rather than just the ordering key.
//!
//! The generated flat-scalar types are also **strict**: every scalar struct is
//! `#[serde(deny_unknown_fields)]`, so a payload carrying keys outside the
//! domain's set fails to deserialize rather than being silently stripped on the
//! next serialize (a pass-through consumer must not lose data it didn't know
//! about), and the `v` field is [`crate::SchemaVersion`], which rejects any
//! version other than `3`. The SteVec `json` family below is structurally
//! different: its document/root shape has no root `c`, its entries flatten a
//! term enum, and only the flatten-free structs can be strict.
//!
//! **The `k` form discriminator, and why the flat-scalar structs omit it.** The
//! canonical EQL payload envelope (`eql-payload-v2.3.schema.json`) carries a `k`
//! form discriminator: `"ct"` for the scalar-ciphertext form, `"sv"` for the
//! STE-vec form. It is **optional on the scalar (`ct`) form** — the canonical
//! `EncryptedPayload` requires only `v`/`c`/`i`, and both the schema and the SQL
//! CHECKs discriminate structurally (`c`-vs-`sv` presence), not on `k`. So the
//! flat-scalar structs are deliberately `{v,i,c,+terms}` with no `k` field —
//! matching the scalar CHECK exactly. (Note: `eql_v3` never *reads* `k` — the
//! typed domain is the discriminator. If a producer emitted `k:"ct"` on a scalar
//! payload, these strict structs would reject it; no test currently parses real
//! scalar ciphertext into the bindings, so that path is unverified.) The one
//! place `k` is modelled is the SteVec **document** — see the `json` note below.
//!
//! ## Why there is no discriminated enum
//!
//! Cross-token: impossible — an `integer_eq` and a `bigint_eq` payload are
//! byte-identical on the wire (`v`/`i`/`c`/`hm`); nothing discriminates them.
//! Per-token: for the FLAT SCALAR families it is deliberately omitted — an
//! untagged enum over a token's domains would discriminate by key-sniffing, and
//! `_ord` vs `_ord_ore` are identical shapes that no sniffing can separate.
//! Consumers read from a typed column and already know the domain.
//!
//! The generated [`DomainPayload`] enum (`payload.rs`) does NOT contradict
//! this rule: it spans every stored-payload domain but derives only
//! `Serialize` (untagged, so the wire form is exactly the inner struct's) and
//! is constructible solely from a KNOWN domain name
//! ([`payload::DomainPayload::parse`], [`crate::from_v2::from_v2_typed`]) —
//! there is still no `Deserialize`, because inference from bytes remains
//! unsound. The hand-written [`QueryPayload`] enum (`query_payload.rs`)
//! follows the same Serialize-only rule for QUERY payloads — see its module
//! doc for why it is hand-written rather than generated.
//!
//! The SteVec `json` family is the principled exception to flat scalar shapes:
//! a document mixes term-less value/structural entries with number/string path
//! entries carrying an optional `op`. Exact matching is selector presence;
//! `op` exists only for ordering.
//!
//! ## Per-family caller-facing notes
//!
//! These are not derivable from the catalog and are documented here because the
//! per-family modules are generated.
//!
//! **`double` / `real` special values.** `-0.0` canonicalizes to `+0.0`
//! (equal under `=`, IEEE-consistent) and `±Inf` order correctly
//! (`-Inf < finite < +Inf`). **NaN is unordered and unspecified in the
//! encoder**: it can be encrypted, stored, and pass the domain CHECK, but it
//! carries **no comparison guarantee** and does NOT follow IEEE semantics. The
//! domain CHECK validates only the envelope — it cannot inspect the ciphertext
//! — so a NaN payload is never rejected server-side. **Reject NaN client-side
//! before encryption** if your column must not contain it; otherwise a NaN row
//! sorts at an arbitrary (but deterministic) position in an encrypted range
//! scan. See the `float_special` regression suite for the locked behaviour.
//!
//! **`boolean` is storage-only by design.** It has no `_eq`/`_ord` domain and
//! carries no index term: a two-value column has so little cardinality that any
//! searchable index (even HMAC equality) would trivially leak the plaintext
//! distribution. The payload is `{v,i,c}` only and every operator is blocked.
//!
//! **`json` (SteVec) uses explicit optional fields.** `a` and `op` are absent
//! when they do not apply; `i`/`v`/`h` are present only on entries extracted by
//! SQL. Naming those fields explicitly lets `SteVecEntry` and
//! `SteVecQueryEntry` reject retired, misplaced, and unknown wire keys in the
//! same way as the SQL domain checks.
//!
//! **The document carries the `k:"sv"` form discriminator.** Unlike the scalar
//! form (where `k` is optional — see above), the canonical `SteVecPayload`
//! *requires* `k` (`required: [v,k,i,sv]`, `const "sv"`) and cipherstash-client
//! emits it on every real SteVec document. Because `SteVecDocument` is strict
//! (`deny_unknown_fields`), it MUST model `k` or it rejects the real wire — so it
//! carries a [`json::SteVecForm`] field pinned to `"sv"`, exactly as
//! `SchemaVersion` pins `v`. `SteVecQuery` needs no `k`: it is a locally-built
//! `{sv:[…]}` containment needle (`eql_v3.to_ste_vec_query`), not a stored
//! envelope. `eql_v3` itself never reads `k`; it is passthrough form metadata
//! that the document preserves on round-trip.

pub mod bigint;
pub mod boolean;
pub mod date;
pub mod domain_type;
pub mod double;
pub mod integer;
pub mod inventory;
pub mod json;
/// Generated bindings for the `json` family's bare scalar storage domain
/// (`public.eql_v3_json`, the `Json` struct). Kept separate from the
/// hand-written SteVec `json` module; `json` re-exports `Json` from here so
/// `super::json::Json` resolves for the generated inventory/payload.
pub mod json_storage;
pub mod numeric;
pub mod payload;
pub mod query_payload;
pub mod real;
pub mod smallint;
pub mod terms;
pub mod text;
pub mod timestamp;

pub use domain_type::{DomainType, SCHEMA_ID_BASE, SQL_SCHEMA};
pub use inventory::{all, all_query};
pub use payload::DomainPayload;
pub use query_payload::QueryPayload;
