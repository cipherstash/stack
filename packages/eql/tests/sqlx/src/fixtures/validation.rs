//! Pure SQL-token validators. Validated tokens are wrapped in newtypes
//! (`FixtureIdentifier`, `ColumnType`) so a renderer that accepts the newtype
//! receives type-level proof of validation — an unvalidated `&str` cannot
//! reach the renderer's format strings.

use std::fmt;

/// Maximum unquoted identifier length PostgreSQL preserves; longer identifiers
/// are silently truncated (`NAMEDATALEN - 1`).
const MAX_IDENTIFIER_LEN: usize = 63;

/// Lowercase snake-case identifier, must start with a letter and be at most
/// 63 bytes (PostgreSQL truncates beyond that): `^[a-z][a-z0-9_]{0,62}$`.
fn is_valid_identifier(s: &str) -> bool {
    // All accepted chars are single-byte ASCII, so byte length == char count.
    if s.len() > MAX_IDENTIFIER_LEN {
        return false;
    }
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_lowercase() => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

/// Allowlist of generated `payload` column types. `jsonb` for the scalar
/// fixtures; `public.eql_v3_json_search` for the v3 json (SteVec document) fixture, whose
/// generated `payload` column is the `public.eql_v3_json_search` DOMAIN so the domain CHECK
/// runs on load; and `public.eql_v3_json` for the storage-only / encryption-only json
/// fixture, whose `payload` column is that DOMAIN so its `{v,i,c}` CHECK runs on
/// load. Schema-qualified tokens are allowed — each is an exact, vetted entry here, never a
/// free-form `&str`.
pub const ALLOWED_COLUMN_TYPES: &[&str] =
    &["jsonb", "public.eql_v3_json", "public.eql_v3_json_search"];

fn is_valid_column_type(s: &str) -> bool {
    ALLOWED_COLUMN_TYPES.contains(&s)
}

/// A validated SQL identifier. Construction proves the string matches
/// `^[a-z][a-z0-9_]*$`. Renderers interpolate via `Display`, so the bare
/// `&str` cannot reach generated SQL once it has been validated into this type.
#[derive(Debug, Clone)]
pub struct FixtureIdentifier(String);

impl FixtureIdentifier {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<&str> for FixtureIdentifier {
    type Error = String;
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        if is_valid_identifier(s) {
            Ok(Self(s.to_string()))
        } else {
            Err(format!(
                "{s:?} is not a valid identifier (^[a-z][a-z0-9_]*$)"
            ))
        }
    }
}

impl fmt::Display for FixtureIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A validated generated-payload column type token. Construction proves the
/// string is in `ALLOWED_COLUMN_TYPES`.
#[derive(Debug, Clone)]
pub struct ColumnType(String);

impl ColumnType {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<&str> for ColumnType {
    type Error = String;
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        if is_valid_column_type(s) {
            Ok(Self(s.to_string()))
        } else {
            Err(format!(
                "{s:?} is not in the allowlist {ALLOWED_COLUMN_TYPES:?}"
            ))
        }
    }
}

impl fmt::Display for ColumnType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_valid_identifiers() {
        assert!(FixtureIdentifier::try_from("eql_v3_integer").is_ok());
        assert!(FixtureIdentifier::try_from("a").is_ok());
        assert!(FixtureIdentifier::try_from("x9_y").is_ok());
    }

    #[test]
    fn rejects_invalid_identifiers() {
        assert!(FixtureIdentifier::try_from("").is_err());
        assert!(FixtureIdentifier::try_from("9abc").is_err()); // leading digit
        assert!(FixtureIdentifier::try_from("_abc").is_err()); // leading underscore
        assert!(FixtureIdentifier::try_from("Abc").is_err()); // uppercase
        assert!(FixtureIdentifier::try_from("a-b").is_err()); // hyphen
        assert!(FixtureIdentifier::try_from("a b").is_err()); // space
        assert!(FixtureIdentifier::try_from("a;DROP").is_err()); // injection attempt
    }

    #[test]
    fn accepts_63_char_identifier() {
        // 63 bytes is the longest PostgreSQL preserves unquoted.
        let id = format!("a{}", "b".repeat(62));
        assert_eq!(id.len(), 63);
        assert!(FixtureIdentifier::try_from(id.as_str()).is_ok());
    }

    #[test]
    fn rejects_64_char_identifier() {
        // 64 bytes would be silently truncated by PostgreSQL.
        let id = format!("a{}", "b".repeat(63));
        assert_eq!(id.len(), 64);
        assert!(FixtureIdentifier::try_from(id.as_str()).is_err());
    }

    #[test]
    fn identifier_renders_via_display() {
        let id = FixtureIdentifier::try_from("eql_v3_integer").unwrap();
        assert_eq!(format!("{id}"), "eql_v3_integer");
    }

    #[test]
    fn column_type_accepts_allowlisted_tokens_only() {
        assert!(ColumnType::try_from("jsonb").is_ok());
        assert!(ColumnType::try_from("public.eql_v3_json_search").is_ok());
        assert!(ColumnType::try_from("text").is_err());
        assert!(ColumnType::try_from("eql_v3_integer").is_err());
        assert!(ColumnType::try_from("eql_v3.jsonb").is_err());
        assert!(ColumnType::try_from("jsonb; DROP TABLE x").is_err());
    }

    #[test]
    fn column_type_renders_via_display() {
        let ct = ColumnType::try_from("jsonb").unwrap();
        assert_eq!(format!("{ct}"), "jsonb");
    }
}
