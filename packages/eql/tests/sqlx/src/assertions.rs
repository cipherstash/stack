//! Fluent assertion builder for database queries
//!
//! Provides chainable assertions for common test patterns:
//! - Query returns rows
//! - Query returns specific count
//! - Query returns specific value
//! - Query throws exception

use sqlx::{PgPool, Row};

/// Fluent assertion builder for SQL queries
pub struct QueryAssertion<'a> {
    pool: &'a PgPool,
    sql: String,
}

impl<'a> QueryAssertion<'a> {
    /// Create new query assertion
    ///
    /// # Example
    /// ```ignore
    /// QueryAssertion::new(&pool, "SELECT * FROM encrypted")
    ///     .returns_rows()
    ///     .await;
    /// ```
    pub fn new(pool: &'a PgPool, sql: impl Into<String>) -> Self {
        Self {
            pool,
            sql: sql.into(),
        }
    }

    /// Assert that query returns at least one row
    ///
    /// # Panics
    /// Panics if query returns no rows or fails to execute
    pub async fn returns_rows(self) -> Self {
        let rows = sqlx::query(&self.sql)
            .fetch_all(self.pool)
            .await
            .unwrap_or_else(|e| panic!("Query failed: {}\n  -- error: {}", self.sql, e));

        assert!(
            !rows.is_empty(),
            "Expected query to return rows but got none: {}",
            self.sql
        );

        self
    }

    /// Assert that query returns exactly N rows
    ///
    /// # Panics
    /// Panics if query returns different number of rows
    pub async fn count(self, expected: usize) -> Self {
        let rows = sqlx::query(&self.sql)
            .fetch_all(self.pool)
            .await
            .unwrap_or_else(|e| panic!("Query failed: {}\n  -- error: {}", self.sql, e));

        assert_eq!(
            rows.len(),
            expected,
            "Expected {} rows but got {}: {}",
            expected,
            rows.len(),
            self.sql
        );

        self
    }

    /// Assert that query returns a specific value in first row, first column
    ///
    /// # Panics
    /// Panics if value doesn't match or query fails
    pub async fn returns_value(self, expected: &str) -> Self {
        let row = sqlx::query(&self.sql)
            .fetch_one(self.pool)
            .await
            .unwrap_or_else(|_| panic!("Query failed: {}", self.sql));

        let value: String = row.try_get(0).expect("Failed to get column 0");

        assert_eq!(
            value, expected,
            "Expected '{}' but got '{}': {}",
            expected, value, self.sql
        );

        self
    }

    /// Assert that query returns a specific integer value in first row, first column
    ///
    /// # Panics
    /// Panics if value doesn't match or query fails
    pub async fn returns_int_value(self, expected: i32) -> Self {
        let row = sqlx::query(&self.sql)
            .fetch_one(self.pool)
            .await
            .unwrap_or_else(|_| panic!("Query failed: {}", self.sql));

        let value: i32 = row.try_get(0).expect("Failed to get column 0");

        assert_eq!(
            value, expected,
            "Expected {} but got {}: {}",
            expected, value, self.sql
        );

        self
    }

    /// Assert that query returns a specific boolean value in first row, first column
    ///
    /// # Panics
    /// Panics if value doesn't match or query fails
    pub async fn returns_bool_value(self, expected: bool) -> Self {
        let row = sqlx::query(&self.sql)
            .fetch_one(self.pool)
            .await
            .unwrap_or_else(|_| panic!("Query failed: {}", self.sql));

        let value: bool = row.try_get(0).expect("Failed to get column 0");

        assert_eq!(
            value, expected,
            "Expected {} but got {}: {}",
            expected, value, self.sql
        );

        self
    }

    /// Assert that query throws an exception
    ///
    /// # Panics
    /// Panics if query succeeds instead of failing
    pub async fn throws_exception(self) {
        let result = sqlx::query(&self.sql).fetch_all(self.pool).await;

        assert!(
            result.is_err(),
            "Expected query to throw exception but it succeeded: {}",
            self.sql
        );
    }
}

/// Assert a `sqlx::Error` is a database error with the given SQLSTATE,
/// optionally with the given constraint name. Includes the actual error
/// in the panic message so a failing test prints *why* it failed, not
/// just *that* it failed — `assert!(result.is_err(), "…")` swallows the
/// underlying error so a constraint engagement against the wrong
/// constraint or SQLSTATE passes silently.
///
/// # SQLSTATEs commonly seen on encrypted columns
/// - `23505` — unique_violation
/// - `23502` — not_null_violation
/// - `23514` — check_violation
/// - `23503` — foreign_key_violation
/// - `P0001` — raise_exception (PL/pgSQL `RAISE EXCEPTION`)
/// - `42704` — undefined_object (no operator class found, etc.)
///
/// # Example
/// ```ignore
/// let result = sqlx::query(...).execute(&pool).await.unwrap_err();
/// assert_db_error(&result, "23514", Some("encrypted_check_c_constrained"));
/// ```
pub fn assert_db_error(
    err: &sqlx::Error,
    expected_sqlstate: &str,
    expected_constraint: Option<&str>,
) {
    let db_err = err
        .as_database_error()
        .unwrap_or_else(|| panic!("expected database error, got: {err:?}"));

    let code = db_err.code();
    assert_eq!(
        code.as_deref(),
        Some(expected_sqlstate),
        "expected SQLSTATE {expected_sqlstate}, got {code:?} (message: {})",
        db_err.message(),
    );

    if let Some(expected) = expected_constraint {
        let constraint = db_err.constraint();
        assert_eq!(
            constraint,
            Some(expected),
            "expected constraint name {expected:?}, got {constraint:?} (message: {})",
            db_err.message(),
        );
    }
}
