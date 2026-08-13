//! Permanent guard: the emitted TypeScript property order for every domain is
//! envelope (`v`, `i`, `c`) then one property per term in `Term::term_json_keys`
//! order. ts-rs carries struct-declaration order into the `.ts`, and that order
//! is the load-bearing wire contract consumers read. Nothing else pins it:
//! `v3_conformance` compares `serde_json::Value` (a `BTreeMap`, no
//! `preserve_order`) so it is order-INSENSITIVE; `catalog_parity` compares a
//! `BTreeSet`; and `types:check` is regenerate-then-diff, which keeps committed
//! `.ts` in step with the *current* generator but cannot catch a generator order
//! regression that is regenerated + committed self-consistently.

use eql_domains::{Term, CATALOG};

/// Property identifiers, in declared order, from a ts-rs `export type X = { … }`
/// file. Layout-independent: ts-rs emits the body on a single line when fields
/// carry no doc comments (the doc-less generated structs) and across multiple
/// lines when they do, so we scope to the `export type` declaration's brace
/// body and split it on `,` rather than scanning per line. Each property is a
/// `name: Type` segment; the leading `ident:` token is the property name.
fn ts_property_order(ts: &str) -> Vec<String> {
    let decl = ts
        .find("export type")
        .expect("ts-rs file has an `export type` declaration");
    let after = &ts[decl..];
    let open = after.find('{').expect("export type has a brace body");
    let close = after.rfind('}').expect("export type closes its brace body");
    let body = &after[open + 1..close];
    body.split(',')
        .filter_map(|seg| {
            let (head, _) = seg.split_once(':')?;
            let id = head.trim();
            if id.is_empty() || !id.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                return None;
            }
            Some(id.to_string())
        })
        .collect()
}

/// Base directory ts-rs exported the `.ts` files into. `mise run types:generate`
/// redirects generation to a throwaway tree via `TS_RS_EXPORT_DIR` (mirroring
/// ts-rs itself), so the guard must read the FRESHLY generated files there, not
/// the committed `bindings/`. Falls back to the committed `bindings/` dir (next
/// to the crate manifest) for a plain `cargo test`.
fn ts_export_base() -> String {
    match std::env::var("TS_RS_EXPORT_DIR") {
        Ok(dir) if !dir.is_empty() => dir,
        _ => format!("{}/bindings", env!("CARGO_MANIFEST_DIR")),
    }
}

#[test]
fn every_ts_export_has_envelope_then_term_property_order() {
    let base = ts_export_base();
    for family in CATALOG {
        for domain in family.domains {
            if !domain.is_scalar() {
                continue;
            }
            let stem = domain.struct_ident(family.name);
            let path = format!("{base}/v3/{stem}.ts");
            let ts = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));

            let mut expected = vec!["v".to_string(), "i".to_string(), "c".to_string()];
            expected.extend(
                Term::term_json_keys(domain.terms)
                    .iter()
                    .map(|s| s.to_string()),
            );

            assert_eq!(
                ts_property_order(&ts),
                expected,
                "TS property order mismatch for {stem} ({path})"
            );
        }
    }
}
