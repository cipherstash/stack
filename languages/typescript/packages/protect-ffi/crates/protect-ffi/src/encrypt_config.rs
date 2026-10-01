//! Normalisation of the public `EncryptConfig` into the vocabulary
//! cipherstash-config's `CanonicalEncryptionConfig` accepts.
//!
//! # Why this is in Rust
//!
//! It used to live in `src/normalizeEncryptConfig.ts` and run inside the Neon
//! entry's JS wrapper. That was fine while the Neon entry was the only caller,
//! but the wasm binding has no JS wrapper — so it deserialized the canonical
//! shape directly and a wasm caller had to normalise by hand or be rejected by
//! the Rust with an opaque variant error. `@cipherstash/stack` ended up
//! reimplementing the `cast_as` half of this for its own wasm path, which is
//! the drift this crate has been removing everywhere else.
//!
//! Doing it at the deserialization boundary means both bindings accept exactly
//! the same config, there is one implementation, and the rule cannot be
//! forgotten by a new entry point.
//!
//! # What it does
//!
//! Two transformations, both of which exist because the public JS vocabulary
//! and the canonical one differ:
//!
//! 1. **`cast_as` remap.** `string` → `text`, `number` → `float`, `bigint` →
//!    `big_int`. The other members are already canonical and pass through.
//! 2. **`ste_vec` array index mode.** An `ste_vec` index with no explicit
//!    `array_index_mode` gets `"none"`. Without it the library default is
//!    `"all"`, which changes what a stored document indexes — a silent
//!    behaviour difference, so it is pinned here rather than inherited.
//!
//! 3. **Null-valued keys are dropped.** `{ cast_as: cfg.castAs }` with an
//!    undefined `castAs` is ordinary JavaScript, and on the Neon entry it has
//!    always worked: neon's `Json` extractor is `JSON.stringify`-based, which
//!    omits `undefined` properties outright. On wasm they are own enumerable
//!    properties, so `serde_wasm_bindgen` yields `Value::Null` and every
//!    non-`Option` field below rejects it (`invalid type: null, expected string
//!    or map`). Dropping them here is what makes one config work on both, and
//!    it is safe because every field that currently accepts null is an
//!    `Option`, for which missing and `None` are the same thing.
//!
//! Anything not recognised is left alone: this normalises vocabulary, it does
//! not validate. `CanonicalEncryptionConfig`'s own deserialization remains the
//! thing that rejects a malformed config, and it still produces the error.

use cipherstash_client::schema::CanonicalEncryptionConfig;
use serde::{Deserialize, Deserializer};
use serde_json::{Map, Value};

/// A [`CanonicalEncryptionConfig`] deserialized through the public vocabulary.
///
/// Deserializing through `serde_json::Value` first is what lets the remap
/// happen before the canonical type ever sees the input. It costs one
/// intermediate parse of a config that is read once at client construction,
/// which is not a path worth optimising.
///
/// This works identically under `serde_json` (Neon, via `Json` extraction) and
/// `serde_wasm_bindgen` (wasm) because both can produce a `serde_json::Value`.
pub(crate) struct EncryptConfigInput(pub(crate) CanonicalEncryptionConfig);

impl<'de> Deserialize<'de> for EncryptConfigInput {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let mut value = Value::deserialize(deserializer)?;
        normalize(&mut value);
        serde_json::from_value(value)
            .map(EncryptConfigInput)
            .map_err(serde::de::Error::custom)
    }
}

/// Rewrite a config in place. Tolerant by design — a shape this does not
/// recognise is left for `CanonicalEncryptionConfig` to reject with its own
/// message, which is more specific than anything this could invent.
fn normalize(config: &mut Value) {
    prune_nulls(config);
    let Some(tables) = config.get_mut("tables").and_then(Value::as_object_mut) else {
        return;
    };
    for (_, columns) in tables.iter_mut() {
        let Some(columns) = columns.as_object_mut() else {
            continue;
        };
        for (_, column) in columns.iter_mut() {
            let Some(column) = column.as_object_mut() else {
                continue;
            };
            normalize_cast_as(column);
            normalize_ste_vec(column);
        }
    }
}

/// Recursively drop null-valued object keys, so `{ cast_as: undefined }` from
/// JS reads as an absent field rather than an explicit null.
///
/// Whole-config rather than per-field: `#[serde(default)]` does not cover an
/// explicit null, so this applies to every non-`Option` field in the canonical
/// config — `indexes`, `match.m`, `ste_vec.mode` — not just the two this module
/// otherwise touches. Array elements are recursed into but never removed;
/// dropping one would shift the rest.
///
/// # The cost, stated plainly
///
/// A non-finite number reaches this function as `null` too: `serde_json::Value`
/// cannot represent NaN or ±Infinity, and `JSON.stringify(Infinity)` is
/// literally `null`, so both bindings lose the distinction before the config
/// gets here. `{match: {m: Infinity}}` therefore no longer errors — the key is
/// dropped and `m` takes its default.
///
/// That is a real regression for that input, and it is not fixable at this
/// layer: by the time the config is a `Value`, `undefined` and `Infinity` are
/// the same thing. It is accepted because the two cases are not comparable in
/// frequency — `{cast_as: cfg.castAs}` with an undefined `castAs` is ordinary
/// JavaScript that used to hard-error on wasm, while a non-finite bloom filter
/// parameter is a typo nobody has written. Rejecting non-finite numbers needs
/// to happen before the hop, on the JS side, if it is worth doing at all.
fn prune_nulls(value: &mut Value) {
    match value {
        Value::Object(map) => {
            map.retain(|_, v| !v.is_null());
            for (_, v) in map.iter_mut() {
                prune_nulls(v);
            }
        }
        Value::Array(items) => items.iter_mut().for_each(prune_nulls),
        _ => {}
    }
}

fn normalize_cast_as(column: &mut Map<String, Value>) {
    let Some(Value::String(cast_as)) = column.get("cast_as") else {
        return;
    };
    let canonical = match cast_as.as_str() {
        "string" => "text",
        "number" => "float",
        "bigint" => "big_int",
        // Already canonical, or unrecognised — either way, not ours to change.
        _ => return,
    };
    column.insert("cast_as".to_string(), Value::String(canonical.to_string()));
}

fn normalize_ste_vec(column: &mut Map<String, Value>) {
    let Some(ste_vec) = column
        .get_mut("indexes")
        .and_then(Value::as_object_mut)
        .and_then(|indexes| indexes.get_mut("ste_vec"))
        .and_then(Value::as_object_mut)
    else {
        return;
    };
    // Only when absent: an explicit mode, including an explicit `"all"`, is
    // the caller's decision.
    if !ste_vec.contains_key("array_index_mode") {
        ste_vec.insert(
            "array_index_mode".to_string(),
            Value::String("none".to_string()),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Normalise and hand back the JSON, so a case can assert on the rewrite
    /// without also requiring a config `CanonicalEncryptionConfig` accepts.
    ///
    /// Note there is deliberately no "does not mutate the input" case, unlike
    /// the JS `normalizeEncryptConfig` these were ported from. That function
    /// returned a new object; this one rewrites a `Value` the deserializer owns
    /// and is about to consume, so in-place is the point.
    fn norm(mut value: Value) -> Value {
        normalize(&mut value);
        value
    }

    fn column(value: &Value) -> &Value {
        &value["tables"]["t"]["c"]
    }

    #[test]
    fn remaps_the_js_only_cast_as_spellings() {
        for (input, expected) in [
            ("string", "text"),
            ("number", "float"),
            ("bigint", "big_int"),
        ] {
            let out = norm(json!({"tables": {"t": {"c": {"cast_as": input}}}}));
            assert_eq!(column(&out)["cast_as"], expected, "remapping {input}");
        }
    }

    #[test]
    fn leaves_canonical_cast_as_untouched() {
        for value in [
            "text",
            "float",
            "big_int",
            "boolean",
            "date",
            "decimal",
            "int",
            "json",
            "small_int",
            "timestamp",
        ] {
            let out = norm(json!({"tables": {"t": {"c": {"cast_as": value}}}}));
            assert_eq!(column(&out)["cast_as"], value, "preserving {value}");
        }
    }

    #[test]
    fn leaves_omitted_cast_as_omitted() {
        let out = norm(json!({"tables": {"t": {"c": {}}}}));
        assert!(column(&out).get("cast_as").is_none());
    }

    #[test]
    fn injects_array_index_mode_none_when_ste_vec_omits_it() {
        let out =
            norm(json!({"tables": {"t": {"c": {"indexes": {"ste_vec": {"prefix": "t/c"}}}}}}));
        assert_eq!(
            column(&out)["indexes"]["ste_vec"]["array_index_mode"],
            "none"
        );
    }

    #[test]
    fn preserves_an_explicit_array_index_mode() {
        // Including an explicit "all" — the point of the default is to change
        // what an OMITTED value means, not to override a stated one. Both the
        // preset spellings and the object form, since `ModeOrPreset` is
        // untagged and only these two shapes deserialize.
        for mode in [json!("all"), json!("none"), json!({"item": true})] {
            let out = norm(json!({"tables": {"t": {"c": {"indexes": {"ste_vec": {
                "prefix": "t/c",
                "array_index_mode": mode,
            }}}}}}));
            assert_eq!(column(&out)["indexes"]["ste_vec"]["array_index_mode"], mode);
        }
    }

    #[test]
    fn leaves_omitted_ste_vec_mode_omitted() {
        // The default this module injects is `array_index_mode`, and only that.
        // `mode` has a library default too; not inventing one here is what
        // keeps the two bindings' storage behaviour identical to the library's.
        let out =
            norm(json!({"tables": {"t": {"c": {"indexes": {"ste_vec": {"prefix": "t/c"}}}}}}));
        assert!(column(&out)["indexes"]["ste_vec"].get("mode").is_none());
    }

    #[test]
    fn leaves_an_explicit_ste_vec_mode_untouched() {
        let out = norm(json!({"tables": {"t": {"c": {"indexes": {"ste_vec": {
            "prefix": "t/c",
            "mode": "standard",
        }}}}}}));
        let ste_vec = &column(&out)["indexes"]["ste_vec"];
        assert_eq!(ste_vec["mode"], "standard");
        assert_eq!(ste_vec["array_index_mode"], "none");
    }

    #[test]
    fn preserves_sibling_indexes_when_injecting_ste_vec_defaults() {
        let out = norm(json!({"tables": {"t": {"c": {"indexes": {
            "ore": {},
            "unique": {"token_filters": [{"kind": "downcase"}]},
            "ste_vec": {"prefix": "t/c"},
        }}}}}));
        let indexes = &column(&out)["indexes"];
        assert_eq!(indexes["ore"], json!({}));
        assert_eq!(
            indexes["unique"],
            json!({"token_filters": [{"kind": "downcase"}]})
        );
        assert_eq!(indexes["ste_vec"]["array_index_mode"], "none");
    }

    #[test]
    fn handles_multiple_tables_and_columns() {
        let out = norm(json!({"tables": {
            "users": {"name": {"cast_as": "string"}, "age": {"cast_as": "number"}},
            "events": {"data": {"cast_as": "json"}},
        }}));
        assert_eq!(out["tables"]["users"]["name"]["cast_as"], "text");
        assert_eq!(out["tables"]["users"]["age"]["cast_as"], "float");
        assert_eq!(out["tables"]["events"]["data"]["cast_as"], "json");
    }

    #[test]
    fn tolerates_shapes_it_does_not_recognise() {
        // Normalisation is not validation: a config the canonical type will
        // reject must still reach it, so the error names the real problem.
        for input in [
            json!({}),
            json!({"tables": "not an object"}),
            json!({"tables": {"t": 42}}),
            json!({"tables": {"t": {"c": {"cast_as": 7}}}}),
            json!({"tables": {"t": {"c": {"indexes": {"ste_vec": "nope"}}}}}),
        ] {
            let expected = input.clone();
            assert_eq!(norm(input), expected);
        }
    }

    // --- null pruning -----------------------------------------------------
    // What `{ cast_as: cfg.castAs }` with an undefined `castAs` becomes on
    // wasm. Neon never sees these (its extractor is JSON.stringify-based);
    // without pruning, wasm rejects the same object the Neon entry accepts.

    #[test]
    fn drops_null_valued_keys_at_every_depth() {
        let out = norm(json!({"v": 1, "tables": {"t": {"c": {
            "cast_as": null,
            "indexes": {
                "match": {"tokenizer": {"kind": "standard"}, "m": null},
                "ste_vec": {"prefix": "t/c", "array_index_mode": null, "mode": null},
            },
        }}}}));
        let c = column(&out);
        assert!(c.get("cast_as").is_none());
        assert!(c["indexes"]["match"].get("m").is_none());
        assert_eq!(c["indexes"]["match"]["tokenizer"]["kind"], "standard");
        // Pruned first, so the injected default applies — an explicit
        // `undefined` from JS means "I did not set this", as it does elsewhere.
        assert_eq!(c["indexes"]["ste_vec"]["array_index_mode"], "none");
        assert!(c["indexes"]["ste_vec"].get("mode").is_none());
    }

    #[test]
    fn prunes_inside_arrays_without_dropping_elements() {
        let out = norm(json!({"tables": {"t": {"c": {"indexes": {"unique": {
            "token_filters": [{"kind": "downcase", "unused": null}, {"kind": "downcase"}],
        }}}}}}));
        let filters = &column(&out)["indexes"]["unique"]["token_filters"];
        assert_eq!(filters.as_array().map(Vec::len), Some(2));
        assert_eq!(filters[0], json!({"kind": "downcase"}));
    }

    // --- the deserializer itself ------------------------------------------
    // Everything above calls `normalize` directly. These go through
    // `EncryptConfigInput::deserialize`, so a break in the impl or in the
    // `Error::custom` mapping cannot leave the suite green.

    fn parse(value: Value) -> Result<EncryptConfigInput, serde_json::Error> {
        serde_json::from_value(value)
    }

    #[test]
    fn deserializes_a_config_written_in_the_public_vocabulary() {
        let parsed = parse(json!({"v": 1, "tables": {"users": {
            "email": {"cast_as": "string", "indexes": {"match": {}}},
            "profile": {"cast_as": "json", "indexes": {"ste_vec": {"prefix": "users/profile"}}},
        }}}));
        assert!(parsed.is_ok(), "{:?}", parsed.err());
    }

    #[test]
    fn deserializes_a_config_that_was_already_canonical() {
        // The Neon entry's callers pre-normalised for years, and #142's whole
        // premise is that nothing they send stops working.
        let parsed = parse(json!({"v": 1, "tables": {"users": {
            "email": {"cast_as": "text", "indexes": {"match": {}}},
            "profile": {"cast_as": "json", "indexes": {"ste_vec": {
                "prefix": "users/profile",
                "array_index_mode": "none",
            }}},
        }}}));
        assert!(parsed.is_ok(), "{:?}", parsed.err());
    }

    #[test]
    fn deserializes_undefined_valued_keys_as_absent() {
        let parsed = parse(json!({"v": 1, "tables": {"users": {
            "email": {"cast_as": "text", "indexes": {"match": {"m": null}}},
        }}}));
        assert!(parsed.is_ok(), "{:?}", parsed.err());
    }

    #[test]
    fn a_non_finite_number_is_indistinguishable_from_undefined() {
        // Pins the cost documented on `prune_nulls`, so it is a known trade
        // rather than a surprise. `{match: {m: Infinity}}` arrives here as
        // `{"m": null}` on BOTH bindings — `serde_json::Value` cannot hold a
        // non-finite float, and `JSON.stringify(Infinity)` is `null` — so the
        // key is dropped and `m` takes its default instead of erroring.
        //
        // If this ever needs to fail loudly, it has to be caught before the
        // `Value` hop; there is nothing left to distinguish at this layer.
        let mut config = json!({"v": 1, "tables": {"users": {
            "email": {"cast_as": "text", "indexes": {"match": {"m": null, "k": 6}}},
        }}});
        normalize(&mut config);
        let m = &config["tables"]["users"]["email"]["indexes"]["match"];
        assert!(
            m.get("m").is_none(),
            "the key is dropped, not defaulted here"
        );
        assert_eq!(m["k"], 6, "its siblings survive");
    }

    #[test]
    fn surfaces_the_canonical_types_own_error() {
        // The mapping through `Error::custom` must not swallow the message —
        // it is the only thing that says what is actually wrong.
        let Err(err) = parse(json!({"v": 1, "tables": {"users": {
            "email": {"cast_as": "text", "indexes": {"ste_vec": {}}},
        }}})) else {
            panic!("ste_vec without a prefix should be rejected");
        };
        assert!(
            err.to_string().contains("prefix"),
            "expected the canonical error to name the missing field, got: {err}"
        );
    }
}
