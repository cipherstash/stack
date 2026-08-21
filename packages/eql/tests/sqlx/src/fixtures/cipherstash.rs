//! Direct `cipherstash-client` integration — the encryption oracle for the
//! SQLx fixture generator.
//!
//! Earlier revisions of the generator started a CipherStash Proxy container,
//! wrote `add_search_config` rows so Proxy knew which columns to encrypt,
//! restarted the container so it reloaded that config, then INSERTed
//! plaintexts through a Proxy-mediated Postgres connection. That whole loop
//! existed only because the Proxy was the encryption oracle.
//!
//! `cipherstash-client` exposes the same surface natively. This module owns
//! the bootstrap — `build_cipher()` builds a `ScopedCipher<AutoStrategy>` —
//! and the batched helper `encrypt_store()` that wraps `eql::encrypt_eql_v3`
//! and returns the resulting EQL payloads as `serde_json::Value`s ready to
//! bind into a `jsonb` column. The client (the value-selector
//! branch) emits the **v3** wire natively — scalar payloads `{v, i, c,
//! terms…}` with no `k`, and SteVec documents whose entries are `{s, c, a?,
//! op?}` plus the appended presence-only value entries — so the retired
//! `from_v2` conversion hop (the old `v3_convert` module) is gone: fixtures
//! carry exactly what the client's own v3 assembler produces. A
//! fixture-generator process makes exactly one `encrypt_store` call, so the
//! cipher is built once per process by construction — no static cache, no
//! cross-runtime hazard.
//!
//! `column_config_for` is the bridge between the fixture spec's string-typed
//! index names (`"unique"`, `"ore"`, …) and the typed `IndexType` enum
//! cipherstash-config uses. Unknown names raise immediately so a typo at
//! spec construction fails fast.

use std::borrow::Cow;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use cipherstash_client::encryption::{DecryptOptions, QueryOp, ScopedCipher};
use cipherstash_client::eql::{
    encrypt_eql_v3, EqlCiphertextV3, EqlEncryptOpts, EqlOperation, EqlOutputV3, Identifier,
    PreparedPlaintext,
};
use cipherstash_client::schema::column::{ArrayIndexMode, Index, IndexType, SteVecMode};
use cipherstash_client::schema::{ColumnConfig, ColumnType};
use cipherstash_client::zerokms::{EnvKeyProvider, RecordWithNonce, ZeroKMSBuilder};
use cipherstash_client::AutoStrategy;

use super::eql_plaintext::{Cast, EqlPlaintext};
use super::index_kind::IndexKind;

/// Build a fresh `ScopedCipher`. Performs `AutoStrategy::detect()`, the
/// ZeroKMS handshake, and the keyset load on every call — fine because
/// every fixture-generator process calls this exactly once via the
/// single batched `encrypt_store`.
async fn build_cipher() -> Result<Arc<ScopedCipher<AutoStrategy>>> {
    let zerokms = ZeroKMSBuilder::auto()?
        .with_key_provider(EnvKeyProvider)
        .build()
        .await?;

    let cipher = ScopedCipher::init_default(Arc::new(zerokms)).await?;

    Ok(Arc::new(cipher))
}

/// The single encrypted-payload column name. Single-sourced here so the
/// `ColumnConfig` built for encryption and the `INSERT` target column in the
/// driver cannot drift apart.
pub const PAYLOAD_COLUMN: &str = "payload";

/// The SteVec index domain-separation prefix used for the `v3_ste_vec`
/// document fixture. The value is not externally constrained: the v3 jsonb
/// harness re-derives its selector constants from the *generated* fixture and
/// forges its own ORE ladder, so the fixture only needs to be *internally
/// consistent* — a single fixed prefix applied to all rows yields stable
/// per-path selectors. Any well-formed prefix that produces extractor-
/// compatible `hm`/`op` leaves works.
pub const STE_VEC_PREFIX: &str = "v3_ste_vec";

/// Build a `ColumnConfig` from the fixture spec's index list + cast.
///
/// `IndexKind` is a typed enum — every value is a real EQL index by
/// construction, so the mapping is total and `column_config_for` cannot
/// fail on an unknown index name. Extending fixture coverage to a new
/// index is one variant on `IndexKind` plus one arm here, both compile-
/// time checked.
///
/// Private: [`encrypt_store`] builds the config itself from the caller's
/// index set, so the seam is structurally the only entry point — no
/// caller can hold a config that drifts from the conversion targets.
fn column_config_for(spec_indexes: &[IndexKind], cast: Cast) -> Result<ColumnConfig> {
    let column_type = cast_to_column_type(cast)?;
    let mut config = ColumnConfig::build(PAYLOAD_COLUMN).casts_as(column_type);

    for ix in spec_indexes {
        config = config.add_index(Index::new(index_type_for(*ix)));
    }

    Ok(config)
}

/// Map an `EqlPlaintext::Cast` onto cipherstash-config's `ColumnType`. The
/// `Cast` newtype's allowlist is structural, so the only failure mode is
/// "we extended `EqlPlaintext` with a new variant but forgot to extend
/// this mapping" — explicit error rather than a `_ => unreachable!()`
/// gives the maintainer a clear breadcrumb.
fn cast_to_column_type(cast: Cast) -> Result<ColumnType> {
    match cast.as_str() {
        "int" => Ok(ColumnType::Int),
        "small_int" => Ok(ColumnType::SmallInt),
        "big_int" => Ok(ColumnType::BigInt),
        "boolean" => Ok(ColumnType::Boolean),
        "date" => Ok(ColumnType::Date),
        "decimal" => Ok(ColumnType::Decimal),
        "float" | "real" | "double" => Ok(ColumnType::Float),
        "text" => Ok(ColumnType::Text),
        "jsonb" | "json" => Ok(ColumnType::Json),
        "timestamp" => Ok(ColumnType::Timestamp),
        other => Err(anyhow!(
            "no cipherstash-config ColumnType mapping for cast {other:?} — \
             extend cipherstash::cast_to_column_type when adding a new \
             EqlPlaintext variant"
        )),
    }
}

/// Map an `IndexKind` variant onto cipherstash-config's `IndexType`.
/// Reuses the canonical constructors on `Index` (`Index::new_unique`,
/// etc.) so the defaults stay in sync with whatever cipherstash-config
/// considers the canonical shape for each index. Total — every variant
/// has an arm; adding a new variant is a compile error here, which is
/// the point.
fn index_type_for(kind: IndexKind) -> IndexType {
    match kind {
        IndexKind::Unique => Index::new_unique().index_type,
        IndexKind::Ore => IndexType::Ore,
        IndexKind::Ope => Index::new_ope().index_type,
        IndexKind::Match => Index::new_match().index_type,
        // No `Index::new_ste_vec()` constructor exists — SteVec is a struct
        // variant. `mode: SteVecMode::Compat` yields CLLW-OPE ordering terms
        // — the ones the v3 `eql_v3.ord_term` extractor consumes (order-
        // preserving under native byte comparison). The client's v3 assembler
        // emits Compat-mode OPE bytes under the sv-level `op` key directly.
        // NOT `SteVecMode::Standard`: Standard emits CLLW-*ORE* terms, which
        // do not order under byte comparison and have no v3 representation.
        // `ArrayIndexMode::default()` (NONE) + no term filters keep the
        // document index minimal.
        IndexKind::SteVec => IndexType::SteVec {
            prefix: STE_VEC_PREFIX.to_string(),
            term_filters: vec![],
            array_index_mode: ArrayIndexMode::default(),
            mode: SteVecMode::Compat,
        },
    }
}

/// Encrypt a batch of plaintext values for storage and return one **v3**
/// EQL payload per input as a `serde_json::Value` ready to bind into a
/// `jsonb` column.
///
/// The `ColumnConfig` is built here from `indexes` + `T::CAST` (via
/// [`column_config_for`]), so the config driving encryption and the
/// conversion targets derived from the same index set cannot drift apart.
///
/// One `encrypt_eql` call regardless of `values.len()` — ZeroKMS does the
/// round trip once, not N times. The per-value field in each
/// `PreparedPlaintext` is `value.to_plaintext()`; the config, identifier,
/// and `EqlOperation::Store` are shared across the batch.
///
/// Uses `EqlOperation::Store`, which yields a full v3 storage payload
/// (`{"v": 3, "i": …, "c": …, terms…}` for scalars; `{v, k: "sv", i, sv}`
/// for SteVec documents) straight from the client's v3 assembler, so
/// callers only ever see payloads that satisfy the `v = '3'` domain
/// CHECKs. `EqlEncryptOpts::default()` uses the cipher's
/// default keyset, no lock context, no service token, no index filter —
/// the same defaults Proxy uses for column-config-driven inserts.
///
/// An empty `values` slice short-circuits before `build_cipher()` so a
/// caller with nothing to encrypt does not pay the ZeroKMS bootstrap
/// cost. The config is still built (and so validated) first: a
/// misconfigured fixture must fail even when its value list happens to
/// be empty, not be masked by the short-circuit.
pub async fn encrypt_store<T: EqlPlaintext>(
    table: &str,
    column: &str,
    values: &[T],
    indexes: &[IndexKind],
) -> Result<Vec<serde_json::Value>> {
    let config = &column_config_for(indexes, T::CAST)
        .context("building ColumnConfig from the fixture indexes")?;

    if values.is_empty() {
        return Ok(Vec::new());
    }

    let cipher = build_cipher().await?;

    // `Identifier::new` does two `String` allocations per call — cheap
    // enough that constructing per-iteration is preferred over assuming
    // the upstream type implements `Clone`.
    let prepared: Vec<PreparedPlaintext> = values
        .iter()
        .map(|value| {
            PreparedPlaintext::new(
                Cow::Borrowed(config),
                Identifier::new(table, column),
                value.to_plaintext(),
                EqlOperation::Store,
            )
        })
        .collect();

    let opts = EqlEncryptOpts::default();
    let outputs = encrypt_eql_v3(cipher, prepared, &opts)
        .await
        .with_context(|| {
            format!(
                "encrypting batch of {} values for {table}.{column}",
                values.len()
            )
        })?;

    if outputs.len() != values.len() {
        return Err(anyhow!(
            "encrypt_eql_v3 returned {} outputs for {} inputs",
            outputs.len(),
            values.len()
        ));
    }

    // The client's own v3 assembler is the source of truth for the envelope
    // the `eql_v3` domain CHECKs accept — no EQL-side conversion.
    outputs
        .into_iter()
        .map(|output| {
            let ciphertext: EqlCiphertextV3 = match output {
                EqlOutputV3::Store(ct) => ct,
                EqlOutputV3::Query(_) => {
                    // EqlOperation::Store always yields EqlOutputV3::Store;
                    // treating the other arm as unreachable would hide a
                    // future API drift.
                    return Err(anyhow!(
                        "encrypt_eql_v3 returned a Query output for an EqlOperation::Store input"
                    ));
                }
            };
            serde_json::to_value(&ciphertext).context("serialising EqlCiphertextV3 to JSON")
        })
        .collect::<Result<_>>()
}

/// Encrypt one value as a **SteVec query operand** — the query-side counterpart
/// to [`encrypt_store`], returning the raw v3 query payload.
///
/// `EqlOperation::Query(&IndexType, QueryOp)` carries the `IndexType`
/// explicitly, and the query path in `to_encryption_targets` DISCARDS the
/// `ColumnConfig` entirely — only the identifier, plaintext, index type, and op
/// reach `build_queryable`. So the config here exists solely to satisfy
/// `PreparedPlaintext::new`, and the scalar/Json cast mismatch (a SteVec column
/// casts as Json; an operand is a bare scalar) is not a real one.
///
/// Reusing `index_type_for(IndexKind::SteVec)` is what makes the operand
/// comparable to the `v3_ste_vec` fixture's stored leaves: the OPE key is
/// `MAC(index_key ++ prefix ++ "OPE")`, and `index_key` comes from the
/// ScopedCipher (the keyset), NOT from the identifier — so matching the `prefix`
/// and `SteVecMode::Compat` is necessary AND sufficient for the terms to
/// correspond. Drifting either would silently produce non-comparable terms.
async fn encrypt_ste_vec_query<T: EqlPlaintext>(
    table: &str,
    column: &str,
    value: &T,
    op: QueryOp,
) -> Result<serde_json::Value> {
    let config = column_config_for(&[IndexKind::SteVec], T::CAST)
        .context("building ColumnConfig for a SteVec query operand")?;
    let index_type = index_type_for(IndexKind::SteVec);
    let cipher = build_cipher().await?;

    let prepared = vec![PreparedPlaintext::new(
        Cow::Borrowed(&config),
        Identifier::new(table, column),
        value.to_plaintext(),
        EqlOperation::Query(&index_type, op),
    )];

    let opts = EqlEncryptOpts::default();
    let mut outputs = encrypt_eql_v3(cipher, prepared, &opts)
        .await
        .with_context(|| format!("encrypting a SteVec query operand for {table}.{column}"))?;

    match outputs.pop() {
        Some(EqlOutputV3::Query(payload)) => {
            serde_json::to_value(&payload).context("serialising EqlQueryPayloadV3 to JSON")
        }
        Some(EqlOutputV3::Store(_)) => Err(anyhow!(
            "encrypt_eql_v3 returned a Store output for an EqlOperation::Query input"
        )),
        None => Err(anyhow!("encrypt_eql_v3 returned no output for one input")),
    }
}

/// Pull a required string field out of a v3 SteVec query payload.
fn query_payload_str(payload: &serde_json::Value, key: &str) -> Result<String> {
    payload
        .get(key)
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| anyhow!("SteVec query payload has no string `{key}` field; got {payload}"))
}

/// The tokenized **selector** for a JSON path (`"$.hello"`), as the opaque hex
/// string the `->` extractor takes: `payload -> '<selector>'`.
///
/// Derived from the client (`QueryOp::SteVecSelector` → `Selector::parse` →
/// `generate_selector`, Blake3 over the index key + prefix), so a test never has
/// to pin a selector constant. Selectors are a deterministic function of the
/// path under the fixture's keyset — a hard-coded hex silently names a DIFFERENT
/// field if the keyset or the document shape changes, which is exactly how
/// `SEL_HELLO_OP` came to point at `$.number`.
pub async fn ste_vec_query_selector(table: &str, column: &str, path: &str) -> Result<String> {
    let payload =
        encrypt_ste_vec_query(table, column, &path.to_owned(), QueryOp::SteVecSelector).await?;
    // The v3 selector query payload is the bare tokenized-selector hex string.
    payload
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| anyhow!("v3 selector payload must be a bare string; got {payload}"))
}

/// The CLLW-OPE **term** for a scalar value, as the hex string a v3 query
/// operand carries under `op` (the fixture SteVec index is pinned to
/// `SteVecMode::Compat`, so the ordering primitive is CLLW-OPE and the v3
/// assembler emits it under `op` directly).
///
/// The term encodes the PLAINTEXT and the column, never the field: `op` terms
/// carry no selector. Field scoping is the caller's `->` extraction, not a
/// property of this term — so one term is comparable against whichever leaf
/// the caller extracts.
///
/// `QueryOp::SteVecTerm` accepts strings and numbers only; a bool/null/object
/// plaintext has no orderable term and errors here rather than silently
/// producing a non-comparable operand.
pub async fn ste_vec_query_term<T: EqlPlaintext>(
    table: &str,
    column: &str,
    value: &T,
) -> Result<String> {
    let payload = encrypt_ste_vec_query(table, column, value, QueryOp::SteVecTerm).await?;
    query_payload_str(&payload, "op")
}

/// A complete `query_json` containment needle for an exact value at a JSON path
/// (`"$.number"`, `2`): `{"sv":[{"s":"<value_selector>"}]}`.
///
/// Derived from the client (`QueryOp::SteVecValueSelector` →
/// `generate_value_selector`, a MAC over the index key + prefix + path +
/// canonical(value)), so a value-selector's PRESENCE in the stored document is an
/// exact, injective match — the equality mechanism that replaced the lossy `op`
/// comparison. This is what a client binds for encrypted-JSON field
/// equality: `col @> $1::eql_v3.query_json`. Numbers canonicalise (jsonb numeric
/// equality: `2` and `2.0` share a selector), so, unlike [`ste_vec_query_term`], a
/// numeric value need not be pre-cast to a float.
pub async fn ste_vec_query_value_selector(
    table: &str,
    column: &str,
    path: &str,
    value: &serde_json::Value,
) -> Result<serde_json::Value> {
    let input = serde_json::json!({ "path": path, "value": value });
    let payload =
        encrypt_ste_vec_query(table, column, &input, QueryOp::SteVecValueSelector).await?;
    // Unlike a path selector (a bare string), an exact-value selector is already
    // assembled by cipherstash-client into the complete term-less containment
    // needle expected by eql_v3.query_json.
    let entries = payload
        .get("sv")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| {
            anyhow!("v3 value-selector payload must contain an `sv` array; got {payload}")
        })?;
    anyhow::ensure!(
        entries.len() == 1
            && entries[0]
                .get("s")
                .and_then(serde_json::Value::as_str)
                .is_some()
            && entries[0].as_object().is_some_and(|entry| entry.len() == 1),
        "v3 value-selector payload must be one term-less `s` entry; got {payload}",
    );
    Ok(payload)
}

/// Reassemble and decrypt SQL-extracted v3 SteVec entries independently.
///
/// Each input must be the self-contained shape returned by the SQL `->`
/// extractor: `{v, i, h, s, c, a?, op?}`. The helper reconstructs the client's
/// typed v3 envelope solely to decode the opaque header/ciphertext fields, then
/// binds each ciphertext to its stored selector through
/// `KeyHeader::record_with_selector`. Per-entry authentication failures remain
/// per-item errors so tests can assert that a valid extraction decrypts while a
/// ciphertext graft fails in the same batch.
pub async fn decrypt_ste_vec_entries_fallible(
    entries: &[serde_json::Value],
) -> Result<Vec<std::result::Result<Vec<u8>, String>>> {
    fn record(entry: &serde_json::Value) -> Result<RecordWithNonce> {
        let obj = entry
            .as_object()
            .ok_or_else(|| anyhow!("extracted SteVec entry must be an object; got {entry}"))?;
        let required = |key: &str| {
            obj.get(key)
                .cloned()
                .ok_or_else(|| anyhow!("extracted SteVec entry has no `{key}`; got {entry}"))
        };

        let mut wire_entry = obj.clone();
        for key in ["v", "i", "h"] {
            wire_entry.remove(key);
        }
        let wire = serde_json::json!({
            "v": required("v")?,
            "k": "sv",
            "i": required("i")?,
            "h": required("h")?,
            "sv": [serde_json::Value::Object(wire_entry)],
        });
        let parsed: EqlCiphertextV3 = serde_json::from_value(wire)
            .context("parsing the SQL-extracted entry as a typed v3 SteVec envelope")?;
        let EqlCiphertextV3::SteVec(mut document) = parsed else {
            return Err(anyhow!(
                "reconstructed entry did not parse as a SteVec document"
            ));
        };
        let entry = document
            .ste_vec
            .pop()
            .ok_or_else(|| anyhow!("reconstructed SteVec document has no entry"))?;
        let selector: [u8; 16] = hex::decode(&entry.selector)
            .context("decoding the extracted entry selector")?
            .try_into()
            .map_err(|bytes: Vec<u8>| {
                anyhow!(
                    "extracted selector must decode to 16 bytes, got {}",
                    bytes.len()
                )
            })?;
        Ok(document
            .key_header
            .record_with_selector(entry.ciphertext, selector))
    }

    let records = entries.iter().map(record).collect::<Result<Vec<_>>>()?;
    let cipher = build_cipher().await?;
    let decrypted = cipher
        .decrypt_fallible(records, &DecryptOptions::default())
        .await
        .context("decrypting SQL-extracted SteVec entries")?;
    Ok(decrypted
        .into_iter()
        .map(|result| result.map_err(|error| error.to_string()))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn column_config_for_int_with_unique_and_ore_builds_a_two_index_config() {
        let indexes = [IndexKind::Unique, IndexKind::Ore];
        let config = column_config_for(&indexes, Cast::INT).unwrap();

        assert_eq!(config.name, "payload");
        assert!(matches!(config.cast_type, ColumnType::Int));
        assert_eq!(config.indexes.len(), 2);
        assert!(config.indexes.iter().any(|i| i.is_unique()));
        assert!(config.indexes.iter().any(|i| i.is_ore()));
    }

    // Note: the "unknown index name rejected at runtime" test is gone —
    // `IndexKind` is a closed enum, so a typo is a compile error.

    #[test]
    fn index_type_for_maps_every_variant_to_its_canonical_index_type() {
        // Each `IndexKind` variant round-trips into the `IndexType`
        // cipherstash-config considers canonical for that name. Compared
        // via the public `Index` surface (`is_unique`, `is_ore`,
        // `is_match`) so the assertion does not depend on the shape of
        // the non-exhaustive `IndexType` enum.
        let unique = Index::new(index_type_for(IndexKind::Unique));
        assert!(unique.is_unique(), "Unique must map to the unique index");

        let ore = Index::new(index_type_for(IndexKind::Ore));
        assert!(ore.is_ore(), "Ore must map to the ORE index");

        let ope = Index::new(index_type_for(IndexKind::Ope));
        assert!(ope.is_ope(), "Ope must map to the OPE (CLLW-OPE) index");

        let m = Index::new(index_type_for(IndexKind::Match));
        assert!(m.is_match(), "Match must map to the match (bloom) index");
    }

    #[tokio::test]
    async fn encrypt_store_with_empty_values_returns_an_empty_vec_without_building_cipher() {
        // Empty input short-circuits before `build_cipher()` so a caller
        // with nothing to encrypt does not pay the ZeroKMS bootstrap cost.
        // Running this test under `cargo test` (no `fixture-gen` feature,
        // no CS_* env vars) proves the short-circuit: if `build_cipher()`
        // were reached, the missing credentials would surface as an error.
        let out = encrypt_store::<i32>("t", "c", &[], &[IndexKind::Unique])
            .await
            .unwrap();
        assert!(out.is_empty(), "empty input must yield empty output");
    }

    #[test]
    fn cast_to_column_type_covers_every_eql_plaintext_cast_constant() {
        // Every Cast constant on EqlPlaintext must round-trip into a
        // ColumnType — otherwise a freshly-added EqlPlaintext variant
        // would crash the generator at run time instead of failing the
        // build. Listed explicitly so a new `pub const` on Cast forces an
        // update here.
        for cast in [
            Cast::TEXT,
            Cast::INT,
            Cast::SMALL_INT,
            Cast::BIG_INT,
            Cast::REAL,
            Cast::DOUBLE,
            Cast::BOOLEAN,
            Cast::DATE,
            Cast::JSONB,
            Cast::JSON,
            Cast::FLOAT,
            Cast::DECIMAL,
            Cast::TIMESTAMP,
        ] {
            cast_to_column_type(cast).unwrap_or_else(|e| {
                panic!("Cast::{} has no ColumnType mapping: {e}", cast.as_str())
            });
        }
    }
}

/// Live `encrypt_store` round-trips against a real ZeroKMS keyset. Gated
/// by `fixture-gen` so default `cargo test` runs do not require
/// `CS_CLIENT_ACCESS_KEY` / `CS_WORKSPACE_CRN`. Each test is
/// `#[ignore]` so it only runs under
/// `cargo test --features fixture-gen -- --ignored`, mirroring the
/// `generate` test in `eql_v3_integer.rs`.
///
/// These complement the structural fixture-tests in
/// the `__scalar_matrix_fixture_shape!` arm in `tests/sqlx/src/matrix.rs`: those assert over the
/// regenerated SQL file end-to-end; these isolate the
/// `encrypt_store` call so an SDK API drift surfaces here before the
/// whole fixture pipeline fails.
#[cfg(all(test, feature = "fixture-gen"))]
mod live_tests {
    use super::*;
    use serde_json::Value;

    /// The index set used by most live tests — `Unique` drives the `hm`
    /// term, `Ore` drives the `ob` term, so the returned payloads carry
    /// both.
    const INT_INDEXES: &[IndexKind] = &[IndexKind::Unique, IndexKind::Ore];

    /// The full ordered-integer index set including `Ope`, which drives the
    /// scalar CLLW-OPE `op` term (cipherstash-client 0.38.1+).
    const INT_INDEXES_WITH_OPE: &[IndexKind] = &[IndexKind::Unique, IndexKind::Ore, IndexKind::Ope];

    /// Assert the well-formed v3 Store shape: the payload is a JSON object
    /// with non-null `v`, `c`, `hm`, `ob`, and `i` fields, `v = 3`, and no
    /// `k` discriminator (the v3 assembler never emits one). Mirrors the
    /// per-key assertions in the generated `scalars::integer` matrix suite
    /// (emitted from the `scalar_types!` list in `scalar_types.rs`).
    ///
    /// The `op` (CLLW-OPE) key is pinned in BOTH directions against the
    /// index set that produced the payload: an `ope`-indexed
    /// column MUST carry a hex-string `op` term, and a column without the
    /// `ope` index MUST NOT — a stray `op` on a non-ope column means the
    /// client started emitting the term unconditionally and the fixture
    /// conversion targets need re-auditing.
    fn assert_store_shape(payload: &Value, indexes: &[IndexKind]) {
        let obj = payload.as_object().expect("payload must be a JSON object");
        for key in ["v", "c", "hm", "ob", "i"] {
            assert!(
                obj.get(key).is_some_and(|v| !v.is_null()),
                "payload must carry a non-null `{key}` field; got {payload}"
            );
        }
        // `v` is the EQL payload-format version. The client's v3 assembler
        // emits the v3 envelope directly: scalar payloads carry no `k` form
        // discriminator.
        assert_eq!(
            obj.get("v").and_then(Value::as_i64),
            Some(3),
            "payload must declare v = 3; got {payload}"
        );
        assert!(
            !obj.contains_key("k"),
            "a converted scalar payload must not carry `k`; got {payload}"
        );
        if indexes.contains(&IndexKind::Ope) {
            let op = obj.get("op").and_then(Value::as_str).unwrap_or_else(|| {
                panic!(
                    "an ope-indexed payload must carry a string `op` (CLLW-OPE) \
                     term; got {payload}"
                )
            });
            assert!(
                !op.is_empty()
                    && op.len().is_multiple_of(2)
                    && op.bytes().all(|b| b.is_ascii_hexdigit()),
                "`op` must be a non-empty even-length hex string; got {op:?}"
            );
        } else {
            assert!(
                !obj.contains_key("op"),
                "a payload without the ope index must NOT carry an `op` term — \
                 the client emits CLLW-OPE only for ope-indexed columns; \
                 got {payload}"
            );
        }
    }

    #[tokio::test]
    #[ignore = "live ZeroKMS — run via `cargo test --features fixture-gen -- --ignored`"]
    async fn encrypt_store_single_value_returns_one_eql_payload() {
        let out = encrypt_store("live_one", "payload", &[42_i32], INT_INDEXES)
            .await
            .expect("encrypt_store should succeed against live ZeroKMS");
        assert_eq!(out.len(), 1, "single input should produce single output");
        assert_store_shape(&out[0], INT_INDEXES);
    }

    #[tokio::test]
    #[ignore = "live ZeroKMS — run via `cargo test --features fixture-gen -- --ignored`"]
    async fn encrypt_store_with_ope_index_emits_the_op_term() {
        // The client emits the scalar CLLW-OPE term for
        // `ope`-indexed columns on the `_ord_ope`-capable v3 payload as a
        // single hex string (NOT an array like `ob`).
        let out = encrypt_store(
            "live_ope",
            "payload",
            &[-1_i32, 0, 42],
            INT_INDEXES_WITH_OPE,
        )
        .await
        .expect("encrypt_store should succeed against live ZeroKMS");
        assert_eq!(out.len(), 3);
        for payload in &out {
            assert_store_shape(payload, INT_INDEXES_WITH_OPE);
        }
    }

    #[tokio::test]
    #[ignore = "live ZeroKMS — run via `cargo test --features fixture-gen -- --ignored`"]
    async fn encrypt_store_ope_term_is_deterministic_for_equal_plaintexts() {
        // CLLW-OPE determinism is load-bearing: the integer
        // families route `=`/`<>` through `op`, so two independent
        // encryptions of one plaintext MUST yield byte-identical `op` hex
        // strings — a randomized term would make op-routed equality
        // silently return false negatives. Two separate encrypt_store
        // calls = two independent cipher bootstraps, so this pins
        // determinism across encryption sessions, not just within a batch.
        let first = encrypt_store("live_ope_det", "payload", &[42_i32], INT_INDEXES_WITH_OPE)
            .await
            .expect("first encryption should succeed against live ZeroKMS");
        let second = encrypt_store("live_ope_det", "payload", &[42_i32], INT_INDEXES_WITH_OPE)
            .await
            .expect("second encryption should succeed against live ZeroKMS");
        let op_of = |payloads: &[Value]| -> String {
            payloads[0]
                .get("op")
                .and_then(Value::as_str)
                .expect("ope-indexed payload must carry a string `op` term")
                .to_string()
        };
        let (a, b) = (op_of(&first), op_of(&second));
        assert_eq!(
            a, b,
            "CLLW-OPE must be deterministic: equal plaintexts must produce \
             byte-identical `op` terms (the integer families' `=`/`<>` route \
             through `op`); got {a:?} vs {b:?}"
        );
        // And a control: a different plaintext must NOT collide.
        let other = encrypt_store("live_ope_det", "payload", &[43_i32], INT_INDEXES_WITH_OPE)
            .await
            .expect("control encryption should succeed against live ZeroKMS");
        assert_ne!(
            a,
            op_of(&other),
            "distinct plaintexts must yield distinct `op` terms"
        );
    }

    #[tokio::test]
    #[ignore = "live ZeroKMS — run via `cargo test --features fixture-gen -- --ignored`"]
    async fn encrypt_store_batch_returns_one_payload_per_input_in_input_order() {
        let values = [-1_i32, 1, 42];
        let out = encrypt_store("live_batch", "payload", &values, INT_INDEXES)
            .await
            .expect("encrypt_store should succeed against live ZeroKMS");
        assert_eq!(
            out.len(),
            values.len(),
            "batch length must equal input length"
        );
        for (i, payload) in out.iter().enumerate() {
            assert_store_shape(payload, INT_INDEXES);
            // Each payload's `i.t` should match the table identifier we
            // supplied — that's the field consuming code uses to bind a
            // payload to its source column.
            let identifier_t = payload
                .get("i")
                .and_then(Value::as_object)
                .and_then(|o| o.get("t"))
                .and_then(Value::as_str);
            assert_eq!(
                identifier_t,
                Some("live_batch"),
                "payload[{i}].i.t must match the table argument; got {payload}"
            );
        }
    }

    #[tokio::test]
    #[ignore = "live ZeroKMS — run via `cargo test --features fixture-gen -- --ignored`"]
    async fn encrypt_store_batch_distinct_plaintexts_yield_distinct_hm() {
        // HMAC is the equality term — three distinct plaintexts must
        // yield three distinct `hm` strings. Mirrors
        // `hmac_equality_terms_are_distinct_for_distinct_values` in the
        // fixture-tests but at the unit-test layer.
        let out = encrypt_store("live_distinct", "payload", &[-1_i32, 1, 42], INT_INDEXES)
            .await
            .expect("encrypt_store should succeed against live ZeroKMS");

        let hms: Vec<&str> = out
            .iter()
            .map(|p| {
                p.get("hm")
                    .and_then(Value::as_str)
                    .expect("payload must carry a string `hm` term")
            })
            .collect();
        let unique: std::collections::HashSet<&&str> = hms.iter().collect();
        assert_eq!(
            unique.len(),
            hms.len(),
            "distinct plaintexts must yield distinct hm terms; got {hms:?}"
        );
    }
}
