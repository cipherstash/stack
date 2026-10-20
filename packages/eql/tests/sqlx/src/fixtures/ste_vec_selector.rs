//! Read a SteVec selector out of a LOADED fixture instead of pinning it.
//!
//! A SteVec selector is a keyed MAC over (workspace keyset, prefix, JSON path),
//! so the same path has a different selector in every CipherStash workspace.
//! A hex constant in this crate is therefore a constant about whichever
//! workspace generated the fixture last, and breaks the moment CI's
//! `CS_WORKSPACE_CRN` changes. The helpers here ask the fixture the suite is
//! actually running against, and keep the shape check a pinned constant used to
//! give: each fixture states a rule that picks out exactly one selector, and a
//! fixture where zero or several selectors satisfy it fails with every candidate
//! listed.
//!
//! The deterministic computation of a selector (that a given keyset and path
//! still produce the same bytes) is a separate property. It is pinned in
//! `packages/eql/tests/encryption`, against a fake key source, not here.

use anyhow::{bail, Result};
use sqlx::{Executor, Postgres};

/// One `op`-carrying selector in a fixture, with the profile the selection
/// rules read.
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct OpSelectorCandidate {
    /// The selector (`s`) of the `op`-carrying `sv` entry.
    pub selector: String,
    /// Number of fixture rows carrying an `op` entry under this selector.
    pub rows: i64,
    /// Number of rows in the fixture table.
    pub total_rows: i64,
    /// Number of distinct `op` hex lengths under this selector.
    pub distinct_op_lengths: i64,
    /// Shortest `op` hex length under this selector.
    pub min_op_length: i64,
    /// Longest `op` hex length under this selector.
    pub max_op_length: i64,
    /// Number of fixture rows carrying an `op` of [`Self::max_op_length`]
    /// under this selector.
    pub rows_at_max_op_length: i64,
}

impl std::fmt::Display for OpSelectorCandidate {
    /// One candidate per line in `pick_one`'s listing: the selector, then its profile.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}  rows={}/{} distinct_op_lengths={} min={} max={} rows_at_max={}",
            self.selector,
            self.rows,
            self.total_rows,
            self.distinct_op_lengths,
            self.min_op_length,
            self.max_op_length,
            self.rows_at_max_op_length,
        )
    }
}

/// The selector an `op`-carrying entry with no `s` key is listed under, so it
/// stays visible among the candidates rather than dropping out of the join.
pub const MISSING_SELECTOR: &str = "(no s key)";

/// SQL listing every distinct `op`-carrying selector in `table`, one row per
/// selector, ordered by selector. The payload is cast to bare jsonb first so
/// `-> 'sv'` is the native array accessor, not the `eql_v3_json_search -> text`
/// selector-lookup operator.
pub fn op_selector_candidates_sql(table: &str) -> String {
    format!(
        "WITH entries AS ( \
           SELECT f.id, coalesce(e ->> 's', '{MISSING_SELECTOR}') AS selector, \
                  length(e ->> 'op') AS op_length \
           FROM {table} f, jsonb_array_elements(f.payload::jsonb -> 'sv') e \
           WHERE e ? 'op' \
         ), longest AS ( \
           SELECT selector, max(op_length) AS op_length FROM entries GROUP BY 1 \
         ) \
         SELECT en.selector, \
                count(DISTINCT en.id) AS rows, \
                (SELECT count(*) FROM {table}) AS total_rows, \
                count(DISTINCT en.op_length) AS distinct_op_lengths, \
                min(en.op_length)::bigint AS min_op_length, \
                max(en.op_length)::bigint AS max_op_length, \
                count(DISTINCT en.id) FILTER (WHERE en.op_length = l.op_length) \
                  AS rows_at_max_op_length \
         FROM entries en JOIN longest l USING (selector) \
         GROUP BY 1 ORDER BY 1"
    )
}

/// Every `op`-carrying selector in `table` with its profile.
pub async fn op_selector_candidates<'e, E>(
    executor: E,
    table: &str,
) -> Result<Vec<OpSelectorCandidate>>
where
    E: Executor<'e, Database = Postgres>,
{
    Ok(sqlx::query_as(&op_selector_candidates_sql(table))
        .fetch_all(executor)
        .await?)
}

/// The one candidate satisfying `rule`. Fails, naming every candidate and
/// whether it matched, when zero or more than one do. `fixture` and
/// `rule_description` only shape the error message.
pub fn pick_one(
    fixture: &str,
    rule_description: &str,
    candidates: &[OpSelectorCandidate],
    rule: impl Fn(&OpSelectorCandidate) -> bool,
) -> Result<String> {
    let matching: Vec<&OpSelectorCandidate> = candidates.iter().filter(|c| rule(c)).collect();
    if let [only] = matching.as_slice() {
        return Ok(only.selector.clone());
    }
    let listing = if candidates.is_empty() {
        "    (none: the fixture has no op-carrying sv entry; is it loaded?)".to_string()
    } else {
        candidates
            .iter()
            .map(|c| {
                let mark = if rule(c) { "match" } else { "     " };
                format!("    {mark}  {c}")
            })
            .collect::<Vec<_>>()
            .join("\n")
    };
    bail!(
        "{fixture}: expected exactly one op-carrying selector matching the rule \
         \"{rule_description}\", found {}.\n  candidates:\n{listing}\n\
         The fixture's shape no longer singles out the leaf the tests mean. Check \
         the fixture documents and the rule; do not pin a selector value.",
        matching.len(),
    )
}

/// An [`OpSelectorCandidate`] with every field given, for selection-rule unit
/// tests. The one place a test builds the struct, so a new field is added here
/// only.
#[cfg(test)]
pub(crate) fn test_candidate(
    selector: &str,
    rows: i64,
    total_rows: i64,
    distinct_op_lengths: i64,
    min_op_length: i64,
    max_op_length: i64,
    rows_at_max_op_length: i64,
) -> OpSelectorCandidate {
    OpSelectorCandidate {
        selector: selector.to_string(),
        rows,
        total_rows,
        distinct_op_lengths,
        min_op_length,
        max_op_length,
        rows_at_max_op_length,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A candidate in a 10-row fixture with one (132) or two (132/148) op lengths.
    fn candidate(selector: &str, rows: i64, lengths: i64) -> OpSelectorCandidate {
        let (max, rows_at_max) = if lengths > 1 { (148, 1) } else { (132, rows) };
        test_candidate(selector, rows, 10, lengths, 132, max, rows_at_max)
    }

    /// A sample selection rule for the `pick_one` tests.
    fn two_lengths_on_every_row(c: &OpSelectorCandidate) -> bool {
        c.rows == c.total_rows && c.distinct_op_lengths == 2
    }

    #[test]
    fn picks_the_single_matching_candidate() {
        let candidates = [
            candidate("sel-number", 10, 1),
            candidate("sel-hello", 10, 2),
            candidate("sel-accented", 10, 3),
        ];
        let got = pick_one("fx", "rule", &candidates, two_lengths_on_every_row).unwrap();
        assert_eq!(got, "sel-hello");
    }

    #[test]
    fn zero_matches_fails_naming_every_candidate() {
        let candidates = [candidate("sel-number", 10, 1), candidate("sel-other", 9, 2)];
        let err = pick_one("fx", "two lengths", &candidates, two_lengths_on_every_row)
            .unwrap_err()
            .to_string();
        assert!(err.contains("found 0"), "{err}");
        assert!(err.contains("sel-number"), "{err}");
        assert!(err.contains("sel-other"), "{err}");
        assert!(err.contains("rows=9/10"), "{err}");
    }

    #[test]
    fn several_matches_fail_naming_every_candidate() {
        let candidates = [candidate("sel-a", 10, 2), candidate("sel-b", 10, 2)];
        let err = pick_one("fx", "two lengths", &candidates, two_lengths_on_every_row)
            .unwrap_err()
            .to_string();
        assert!(err.contains("found 2"), "{err}");
        assert!(err.contains("match  sel-a"), "{err}");
        assert!(err.contains("match  sel-b"), "{err}");
    }

    #[test]
    fn an_empty_fixture_fails_saying_so() {
        let err = pick_one("fx", "any", &[], |_| true)
            .unwrap_err()
            .to_string();
        assert!(err.contains("found 0"), "{err}");
        assert!(err.contains("no op-carrying sv entry"), "{err}");
    }

    /// The candidate SQL reads the table it is given, as bare jsonb.
    #[test]
    fn candidate_sql_reads_the_named_table() {
        let sql = op_selector_candidates_sql("fixtures.v3_ste_vec");
        assert!(sql.contains("FROM fixtures.v3_ste_vec f,"));
        assert!(sql.contains("(SELECT count(*) FROM fixtures.v3_ste_vec)"));
        assert!(sql.contains("payload::jsonb -> 'sv'"));
    }

    /// An `op`-carrying entry with no `s` key stays in the candidate list, so a
    /// generator regression that drops selectors shows up in `pick_one`'s
    /// listing instead of vanishing from it.
    #[sqlx::test]
    async fn an_op_entry_without_a_selector_is_still_a_candidate(pool: sqlx::PgPool) -> Result<()> {
        sqlx::query("CREATE TABLE candidates_fx (id int PRIMARY KEY, payload jsonb)")
            .execute(&pool)
            .await?;
        sqlx::query(
            r#"INSERT INTO candidates_fx VALUES
                 (1, '{"sv":[{"s":"sel-a","op":"00"},{"op":"0000"}]}'),
                 (2, '{"sv":[{"s":"sel-a","op":"00"}]}')"#,
        )
        .execute(&pool)
        .await?;

        let candidates = op_selector_candidates(&pool, "candidates_fx").await?;
        let mut selectors: Vec<&str> = candidates.iter().map(|c| c.selector.as_str()).collect();
        selectors.sort_unstable();
        assert_eq!(selectors, [MISSING_SELECTOR, "sel-a"], "{candidates:?}");
        Ok(())
    }
}
