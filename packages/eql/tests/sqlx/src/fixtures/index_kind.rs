//! `IndexKind` — the typed EQL search-index identifier.
//!
//! Replaces the `&str` / `FixtureIdentifier`-validated string at the
//! spec/driver boundary. `FixtureIdentifier` proves the value matches
//! `^[a-z][a-z0-9_]*$`; it does NOT prove the name is a real index type.
//! `IndexKind` proves both, at compile time. A typo at spec construction
//! (`.with_index(IndexKind::Uniqu)`) is a compile error rather than a
//! runtime "unknown EQL index identifier" panic deep in the driver.

use std::fmt;

/// One of the EQL search-index identifiers cipherstash-config recognises.
/// Construction is through the variants — by construction every value is
/// in the allowlist. The wire-form `&str` (used in cipherstash-config and
/// the SQL renderers) is available via `as_str` / `Display`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IndexKind {
    /// `unique` — drives `=` / `<>` via HMAC.
    Unique,
    /// `ore` — drives `<` / `<=` / `>` / `>=` via ORE block terms.
    Ore,
    /// `ope` — drives ordering (and, for the integer families, `=` / `<>`)
    /// via the CLLW-OPE term (`op`): a single hex-encoded order-preserving
    /// ciphertext, natively bytea-sortable after hex-decode. Emitted by
    /// cipherstash-client 0.38.1+.
    Ope,
    /// `match` — drives `LIKE` / `ILIKE` via the bloom filter.
    Match,
    /// `ste_vec` — drives the encrypted-JSONB (SteVec) document surface:
    /// per-leaf HMAC (`hm`, equality) + CLLW-OPE (`op`, ordered) terms. Used
    /// by the `v3_ste_vec` document fixture, not the scalar matrix.
    SteVec,
}

impl IndexKind {
    pub fn as_str(self) -> &'static str {
        match self {
            IndexKind::Unique => "unique",
            IndexKind::Ore => "ore",
            IndexKind::Ope => "ope",
            IndexKind::Match => "match",
            IndexKind::SteVec => "ste_vec",
        }
    }
}

impl fmt::Display for IndexKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_as_the_eql_wire_form_string() {
        assert_eq!(IndexKind::Unique.as_str(), "unique");
        assert_eq!(IndexKind::Ore.as_str(), "ore");
        assert_eq!(IndexKind::Ope.as_str(), "ope");
        assert_eq!(IndexKind::Match.as_str(), "match");
        assert_eq!(IndexKind::SteVec.as_str(), "ste_vec");
    }

    #[test]
    fn display_matches_as_str() {
        assert_eq!(format!("{}", IndexKind::Unique), "unique");
        assert_eq!(format!("{}", IndexKind::Ore), "ore");
        assert_eq!(format!("{}", IndexKind::Ope), "ope");
        assert_eq!(format!("{}", IndexKind::Match), "match");
        assert_eq!(format!("{}", IndexKind::SteVec), "ste_vec");
    }
}
