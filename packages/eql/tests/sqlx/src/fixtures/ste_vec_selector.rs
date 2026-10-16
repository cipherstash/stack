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

/// SQL listing every distinct `op`-carrying selector in `table`, one row per
/// selector, ordered by selector. The payload is cast to bare jsonb first so
/// `-> 'sv'` is the native array accessor, not the `eql_v3_json_search -> text`
/// selector-lookup operator.
pub fn op_selector_candidates_sql(table: &str) -> String {
    format!(
        "WITH entries AS ( \
           SELECT f.id, e ->> 's' AS selector, length(e ->> 'op') AS op_length \
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

#[cfg(test)]
mod tests {
    use super::*;

    fn candidate(selector: &str, rows: i64, lengths: i64) -> OpSelectorCandidate {
        OpSelectorCandidate {
            selector: selector.to_string(),
            rows,
            total_rows: 10,
            distinct_op_lengths: lengths,
            min_op_length: 132,
            max_op_length: if lengths > 1 { 148 } else { 132 },
            rows_at_max_op_length: if lengths > 1 { 1 } else { rows },
        }
    }

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

    #[test]
    fn candidate_sql_reads_the_named_table() {
        let sql = op_selector_candidates_sql("fixtures.v3_ste_vec");
        assert!(sql.contains("FROM fixtures.v3_ste_vec f,"));
        assert!(sql.contains("(SELECT count(*) FROM fixtures.v3_ste_vec)"));
        assert!(sql.contains("payload::jsonb -> 'sv'"));
    }
}
