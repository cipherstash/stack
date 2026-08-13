//! Test helper functions for EQL tests
//!
//! Common utilities for working with encrypted data in tests.

/// Sentinel payload that satisfies every encrypted-domain CHECK in the
/// `eql_v3.<T>{,_eq,_match,_ord,_ord_ore,_ord_ope,_search,_search_ore}` family.
/// Carries the EQL envelope (`v`, `i`, `c`) plus *all four* term keys (`hm`,
/// `ob`, `bf`, `op`) so one bind value works for any variant's cast — including
/// the combined `text_search` domain, whose CHECK requires `hm` + `op` + `bf`,
/// its block-ORE sibling `text_search_ore` (`hm` + `ob` + `bf`), and the
/// `_ord_ope` domains, whose CHECK requires `op`.
///
/// Used by blocker / null-result tests where the payload is bound but
/// never decrypted — the blocker raises (or the STRICT wrapper
/// short-circuits) before the term values matter. **Not a representative
/// payload.** Real encrypted payloads come from the fixture
/// (Proxy-encrypted). `bf` is a `smallint[]` (bloom-filter bit positions); a
/// small integer array satisfies the key-presence CHECK.
pub const PLACEHOLDER_PAYLOAD: &str = r#"{"v":3,"i":{"t":"t","c":"c"},"c":"sample","hm":"sample","ob":["00"],"bf":[1,2,3],"op":"00"}"#;
