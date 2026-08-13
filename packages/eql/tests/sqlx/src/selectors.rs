//! Selector constants for test fixtures
//!
//! These selectors correspond to encrypted test data and provide
//! self-documenting references instead of magic literals.
//!
//! Test data structure:
//! - Plaintext: {"hello": "world", "n": 10/20/30, "a": [1,2,3,4,5]}
//! - Three records with IDs 1, 2, 3 (n=10, n=20, n=30)
//! - One record with array data

/// Selector constants for test fixtures
pub struct Selectors;

impl Selectors {
    // Root selectors

    /// Selector for root object ($)
    /// Maps to: $
    pub const ROOT: &'static str = "bca213de9ccce676fa849ff9c4807963";

    /// Selector for $.hello path
    /// Maps to: $.hello
    pub const HELLO: &'static str = "a7cea93975ed8c01f861ccb6bd082784";

    /// Selector for $.n path
    /// Maps to: $.n (numeric value)
    pub const N: &'static str = "2517068c0d1f9d4d41d2c666211f785e";

    // Array selectors

    /// Selector for $.a path (array accessor)
    /// Maps to: $.a (returns array elements)
    pub const ARRAY_ELEMENTS: &'static str = "f510853730e1c3dbd31b86963f029dd5";

    /// Selector for array root
    /// Maps to: array itself as single element
    pub const ARRAY_ROOT: &'static str = "33743aed3ae636f6bf05cff11ac4b519";

    // Nested path selectors
    // NOTE: These are placeholders - current test data doesn't have nested objects
    // See tests/sqlx/src/fixtures/v3_ste_vec.rs (the `documents()` fn) for the
    // actual current SteVec document shape, or tests/sqlx/fixtures/FIXTURE_SCHEMA.md
    // for the generated fixture layout.

    /// Selector for $.nested path (hypothetical nested object)
    /// Maps to: $.nested (not present in current test data)
    pub const NESTED_OBJECT: &'static str = "placeholder_nested_object_selector";

    /// Selector for nested field within object (hypothetical)
    /// Maps to: $.nested.field (not present in current test data)
    pub const NESTED_FIELD: &'static str = "placeholder_nested_field_selector";

    /// Create eql_v2_encrypted selector JSON for use in queries
    ///
    /// # Example
    /// ```ignore
    /// let selector = Selectors::as_encrypted(Selectors::N);
    /// // Returns: {"s": "2517068c0d1f9d4d41d2c666211f785e"}
    /// ```
    pub fn as_encrypted(selector: &str) -> String {
        format!(r#"{{"s": "{}"}}"#, selector)
    }
}
