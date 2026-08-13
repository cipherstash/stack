//! `FixtureSpec<T>` — the type-checked fixture plug-in contract.
//!
//! `T` is the Rust plaintext type, inferred from `.with_values()`. Everything
//! not derivable — the indexes, the generated `payload` column type, the
//! data — is explicit. The fixture name drives every path by convention:
//!   - table        `fixtures.<name>`
//!   - working table `public._fixture_<name>`
//!   - script        `tests/sqlx/fixtures/<name>.sql`
//!   - SQLx ref      `scripts("<name>")`
//!
//! Token-safety is enforced **at construction**: `new`, `.with_index`, and
//! `.with_column_type` each validate via the newtype `TryFrom` and **panic**
//! on a violation, so the builder stays a fluent chain (no `Result`, no
//! `?`). Because the spec stores validated newtypes (`FixtureIdentifier`,
//! `ColumnType`) and uses them via `Display` in the SQL renderers, an
//! unvalidated `&str` cannot reach a generated SQL string. `T::CAST` /
//! `T::PLAINTEXT_SQL_TYPE` are typed const newtypes (`Cast`,
//! `PlaintextSqlType`) — their allowlists are structural, so no runtime
//! check is needed. `check_complete()` covers only the completeness checks
//! (non-empty indexes/values) that the builder cannot make until the chain
//! is finished.

use super::eql_plaintext::EqlPlaintext;
use super::index_kind::IndexKind;
use super::validation::{ColumnType, FixtureIdentifier};

/// A fully specified fixture, ready to `.run()`.
pub struct FixtureSpec<'a, T> {
    name: FixtureIdentifier,
    indexes: Vec<IndexKind>,
    column_type: ColumnType,
    values: &'a [T],
    /// True for a **storage-only / encryption-only** fixture (e.g. `bool`): the
    /// value is encrypted with no search index, so the payload is `{v,i,c}` with
    /// no `hm`/`ob`/`bf` term. Flips the `check_complete` index requirement —
    /// such a fixture MUST declare zero indexes rather than at least one.
    storage_only: bool,
}

impl<'a, T> FixtureSpec<'a, T> {
    /// Start a spec. `name` must match `^[a-z][a-z0-9_]*$` — it becomes a SQL
    /// identifier and a filename. Other fields take defaults until set:
    /// `column_type` defaults to `"jsonb"`, `indexes`/`values` to empty.
    ///
    /// # Panics
    /// Panics if `name` is not a valid identifier.
    pub fn new(name: &str) -> Self {
        let name =
            FixtureIdentifier::try_from(name).unwrap_or_else(|e| panic!("fixture name: {e}"));
        let column_type = ColumnType::try_from("jsonb")
            .expect("default column type \"jsonb\" must be in the allowlist");
        Self {
            name,
            indexes: Vec::new(),
            column_type,
            values: &[],
            storage_only: false,
        }
    }

    /// Add a search index. `IndexKind` is a closed enum — a typo at the
    /// call site is a compile error rather than a runtime panic.
    pub fn with_index(mut self, kind: IndexKind) -> Self {
        self.indexes.push(kind);
        self
    }

    /// Mark this as a **storage-only / encryption-only** fixture: the value is
    /// encrypted with no search index (the payload is `{v,i,c}`, no term keys).
    /// Such a fixture MUST declare no indexes; `check_complete` enforces that
    /// (and skips the usual "at least one index" requirement). Used by `bool`.
    pub fn storage_only(mut self) -> Self {
        self.storage_only = true;
        self
    }

    /// Set the generated `payload` column SQL type. Defaults to `"jsonb"`.
    ///
    /// # Panics
    /// Panics if `column_type` is not in `validation::ALLOWED_COLUMN_TYPES`.
    pub fn with_column_type(mut self, column_type: &str) -> Self {
        self.column_type =
            ColumnType::try_from(column_type).unwrap_or_else(|e| panic!("column type: {e}"));
        self
    }

    /// Set the plaintext value list. `T` is inferred and bound here, so this
    /// is where `T::CAST` and `T::PLAINTEXT_SQL_TYPE` become known. Their
    /// allowlists are structural (typed-const newtypes), so no runtime
    /// validation is needed at this point.
    pub fn with_values(mut self, values: &'a [T]) -> Self
    where
        T: EqlPlaintext,
    {
        self.values = values;
        self
    }

    // ----- accessors used by SQL rendering / the driver -----

    pub fn name(&self) -> &str {
        self.name.as_str()
    }

    pub fn indexes(&self) -> &[IndexKind] {
        &self.indexes
    }

    pub fn column_type(&self) -> &ColumnType {
        &self.column_type
    }

    /// The plaintext value slice.
    pub fn values(&self) -> &[T] {
        self.values
    }

    /// `fixtures.<name>` — the generated fixture table.
    pub fn fixture_table(&self) -> String {
        format!("fixtures.{}", self.name)
    }

    /// `_fixture_<name>` — the transient working table (unqualified `public`).
    pub fn working_table(&self) -> String {
        format!("_fixture_{}", self.name)
    }

    /// `<name>.sql` — the generated script filename (relative to fixtures dir).
    pub fn script_filename(&self) -> String {
        format!("{}.sql", self.name)
    }

    /// SQL for the transient working table on the generation database.
    /// `id BIGINT PRIMARY KEY`, `plaintext` as the SQL type for `T`, and a
    /// plain `payload jsonb` staging column. The fixture driver encrypts in
    /// Rust via `cipherstash-client` and inserts the resulting JSONB directly
    /// — the working table is a values buffer that exists only so the render
    /// step can use Postgres `format('%L', …)` for SQL literal escaping. No
    /// `eql_v2_configuration` writes, no EQL types — the working table has
    /// no EQL dependency at all.
    ///
    /// The leading `DROP TABLE IF EXISTS` is belt-and-suspenders: a normal run
    /// drops the working table itself at the end of `run()`, so this only
    /// matters when a prior run crashed before its own teardown.
    pub fn working_schema_sql(&self) -> String
    where
        T: EqlPlaintext,
    {
        let working = self.working_table();
        format!(
            "DROP TABLE IF EXISTS public.{working};\n\
             CREATE TABLE public.{working} (\n    \
             id BIGINT PRIMARY KEY,\n    \
             plaintext {plaintext_type} NOT NULL,\n    \
             payload jsonb NOT NULL\n);\n",
            plaintext_type = T::PLAINTEXT_SQL_TYPE,
        )
    }

    /// The generated fixture script's header + schema + DDL, up to (not
    /// including) the rendered INSERT rows. The driver appends the INSERTs.
    /// `payload` uses the generated `column_type` (`jsonb` for #224), not
    /// `eql_v2_encrypted`; `plaintext` uses the SQL type for `T`.
    pub fn fixture_script_preamble(&self) -> String
    where
        T: EqlPlaintext,
    {
        format!(
            "-- AUTO-GENERATED by `mise run fixture:generate {name}`.\n\
             -- DO NOT EDIT BY HAND. Re-run the generator to refresh.\n\
             --\n\
             -- Encrypted via cipherstash-client, which emits the\n\
             -- v3 envelope natively (value-selector wire).\n\
             -- A SQLx fixture script: opt in with\n\
             --   #[sqlx::test(fixtures(path = \"../fixtures\", scripts(\"{name}\")))]\n\
             \n\
             CREATE SCHEMA IF NOT EXISTS fixtures;\n\
             DROP TABLE IF EXISTS {table};\n\
             CREATE TABLE {table} (\n    \
             id BIGINT PRIMARY KEY,\n    \
             plaintext {plaintext_type} NOT NULL,\n    \
             payload {column_type} NOT NULL\n);\n\n",
            name = self.name,
            table = self.fixture_table(),
            plaintext_type = T::PLAINTEXT_SQL_TYPE,
            column_type = self.column_type,
        )
    }

    /// SQL run on the *direct* connection to render each working-table row as
    /// a generated INSERT. `format('%L', ...)` does server-side literal
    /// escaping; row values never pass through Rust string interpolation.
    /// `payload::text` projects the already-encrypted JSONB straight through
    /// — the working table stores the cipherstash-client-encrypted payload as
    /// plain `jsonb`, so no composite unwrap is needed.
    pub fn render_rows_sql(&self) -> String {
        format!(
            "SELECT format(\n  \
             'INSERT INTO {table} (id, plaintext, payload) VALUES (%L, %L, %L::{column_type});',\n  \
             id, plaintext, payload::text\n) \
             FROM public.{working} ORDER BY id",
            table = self.fixture_table(),
            column_type = self.column_type,
            working = self.working_table(),
        )
    }

    /// Check the spec is *complete*: it has at least one index and at least
    /// one value. These cannot be checked at construction — the builder does
    /// not know when the chain is finished — so the driver calls this before
    /// generating any SQL. Token safety is already guaranteed by the
    /// `FixtureIdentifier`/`ColumnType` newtypes; this method covers only what
    /// construction cannot.
    pub fn check_complete(&self) -> anyhow::Result<()> {
        if self.storage_only {
            // A storage-only (encryption-only) fixture intentionally has no
            // search index; it MUST NOT declare one (that would put a term key
            // in the payload, contradicting the storage-only contract).
            if !self.indexes.is_empty() {
                anyhow::bail!(
                    "storage-only fixture {:?} must declare no indexes, got {:?}",
                    self.name.as_str(),
                    self.indexes,
                );
            }
        } else if self.indexes.is_empty() {
            anyhow::bail!("fixture {:?} declares no indexes", self.name.as_str());
        }
        if self.values.is_empty() {
            anyhow::bail!("fixture {:?} has no values", self.name.as_str());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn integer_spec() -> FixtureSpec<'static, i32> {
        const VALUES: &[i32] = &[-1, 1, 42];
        FixtureSpec::new("eql_v3_integer")
            .with_index(IndexKind::Unique)
            .with_index(IndexKind::Ore)
            .with_column_type("jsonb")
            .with_values(VALUES)
    }

    #[test]
    fn derives_paths_from_the_name() {
        let s = integer_spec();
        assert_eq!(s.fixture_table(), "fixtures.eql_v3_integer");
        assert_eq!(s.working_table(), "_fixture_eql_v3_integer");
        assert_eq!(s.script_filename(), "eql_v3_integer.sql");
    }

    #[test]
    fn records_indexes_in_order() {
        let s = integer_spec();
        assert_eq!(s.indexes(), &[IndexKind::Unique, IndexKind::Ore]);
    }

    #[test]
    fn column_type_defaults_to_jsonb() {
        const V: &[i32] = &[1];
        let s = FixtureSpec::new("x")
            .with_index(IndexKind::Unique)
            .with_values(V);
        assert_eq!(s.column_type().as_str(), "jsonb");
    }

    #[test]
    fn valid_spec_passes_completeness_check() {
        assert!(integer_spec().check_complete().is_ok());
    }

    #[test]
    #[should_panic(expected = "is not a valid identifier")]
    fn validation_rejects_a_bad_name() {
        // A bad name panics at construction, before the chain continues.
        let _ = FixtureSpec::<'static, i32>::new("Bad-Name");
    }

    #[test]
    #[should_panic(expected = "is not in the allowlist")]
    fn validation_rejects_a_non_allowlisted_column_type() {
        // A non-allowlisted column type panics in `.with_column_type()`.
        let _ = FixtureSpec::<'static, i32>::new("x").with_column_type("text");
    }

    // Note: `with_index` formerly panicked on a malformed identifier (a
    // `FixtureIdentifier::try_from` failure). The typed `IndexKind` enum
    // makes that case unrepresentable — a typo is now a compile error.

    #[test]
    fn completeness_rejects_a_spec_with_no_indexes() {
        const V: &[i32] = &[1];
        let s = FixtureSpec::new("x").with_values(V);
        assert!(s.check_complete().is_err());
    }

    #[test]
    fn completeness_rejects_a_spec_with_no_values() {
        const V: &[i32] = &[];
        let s = FixtureSpec::new("x")
            .with_index(IndexKind::Unique)
            .with_values(V);
        assert!(s.check_complete().is_err());
    }

    #[test]
    fn storage_only_spec_passes_with_no_indexes() {
        // A storage-only (encryption-only) fixture legitimately declares zero
        // indexes — the value is encrypted with no search term.
        const V: &[bool] = &[false, true];
        let s = FixtureSpec::new("eql_v3_boolean")
            .storage_only()
            .with_values(V);
        assert!(s.indexes().is_empty());
        assert!(s.check_complete().is_ok());
    }

    #[test]
    fn storage_only_spec_rejects_a_declared_index() {
        // A storage-only fixture must NOT declare an index (that would add a
        // term key to the payload, contradicting the storage-only contract).
        const V: &[bool] = &[false, true];
        let s = FixtureSpec::new("eql_v3_boolean")
            .storage_only()
            .with_index(IndexKind::Unique)
            .with_values(V);
        assert!(s.check_complete().is_err());
    }

    #[test]
    fn working_schema_sql_drops_and_creates_the_working_table() {
        let sql = integer_spec().working_schema_sql();
        assert!(sql.contains("DROP TABLE IF EXISTS public._fixture_eql_v3_integer;"));
        assert!(sql.contains("CREATE TABLE public._fixture_eql_v3_integer ("));
        assert!(sql.contains("id BIGINT PRIMARY KEY"));
        assert!(sql.contains("plaintext integer NOT NULL"));
        // The working table's payload is plain jsonb — encryption happens in
        // Rust via cipherstash-client, not via a Proxy round trip.
        assert!(sql.contains("payload jsonb"));
        assert!(
            !sql.contains("eql_v2_encrypted"),
            "working table should not depend on the eql_v2_encrypted type"
        );
    }

    #[test]
    fn working_schema_sql_does_not_touch_eql_configuration() {
        // The cipherstash-client path does NOT write to eql_v2_configuration:
        // ColumnConfig lives entirely in Rust, no add_search_config /
        // remove_search_config calls are emitted, and the working table has
        // no EQL dependency.
        let sql = integer_spec().working_schema_sql();
        assert!(!sql.contains("add_search_config"));
        assert!(!sql.contains("remove_search_config"));
        assert!(!sql.contains("eql_v2_configuration"));
    }

    #[test]
    fn fixture_script_preamble_renders_the_generated_table() {
        let preamble = integer_spec().fixture_script_preamble();
        // header
        assert!(preamble.contains("AUTO-GENERATED"));
        assert!(preamble.contains("DO NOT EDIT BY HAND"));
        assert!(preamble.contains("mise run fixture:generate eql_v3_integer"));
        // schema + table in the fixtures schema, jsonb payload
        assert!(preamble.contains("CREATE SCHEMA IF NOT EXISTS fixtures;"));
        assert!(preamble.contains("DROP TABLE IF EXISTS fixtures.eql_v3_integer;"));
        assert!(preamble.contains("CREATE TABLE fixtures.eql_v3_integer ("));
        assert!(preamble.contains("id BIGINT PRIMARY KEY"));
        assert!(preamble.contains("plaintext integer NOT NULL"));
        assert!(preamble.contains("payload jsonb NOT NULL"));
    }

    #[test]
    fn fixture_script_preamble_attributes_encryption_to_cipherstash_client() {
        // The preamble must record the encryption path so a reader of the
        // generated SQL can trace it back to the generator.
        let preamble = integer_spec().fixture_script_preamble();
        assert!(preamble.contains("cipherstash-client"));
        assert!(
            !preamble.contains("CipherStash Proxy"),
            "preamble must not credit the Proxy — encryption is direct now"
        );
    }

    #[test]
    fn fixture_script_preamble_records_the_v3_envelope_conversion() {
        // The client emits the v3 envelope natively; the preamble must record
        // the provenance so a reader of the generated SQL can trace the wire
        // format the payloads carry.
        let preamble = integer_spec().fixture_script_preamble();
        assert!(
            preamble.contains("emits the"),
            "preamble must record the native v3 wire: {preamble}"
        );
        assert!(
            preamble.contains("v3 envelope"),
            "preamble must name the v3 envelope: {preamble}"
        );
    }

    #[test]
    fn fixture_script_preamble_uses_the_generated_column_type() {
        // The generated table uses .with_column_type(), NOT eql_v2_encrypted.
        let preamble = integer_spec().fixture_script_preamble();
        assert!(!preamble.contains("eql_v2_encrypted"));
    }

    #[test]
    fn render_rows_sql_projects_format_l_over_the_working_table() {
        let sql = integer_spec().render_rows_sql();
        assert!(sql.contains("INSERT INTO fixtures.eql_v3_integer (id, plaintext, payload) VALUES"));
        assert!(sql.contains("%L, %L, %L::jsonb"));
        assert!(sql.contains("FROM public._fixture_eql_v3_integer"));
        // payload is already encrypted JSONB in the working table; no
        // composite to unwrap.
        assert!(sql.contains("payload::text"));
        assert!(
            !sql.contains("(payload).data"),
            "render must not unwrap a composite — payload is plain jsonb"
        );
        assert!(sql.contains("ORDER BY id"));
    }
}
