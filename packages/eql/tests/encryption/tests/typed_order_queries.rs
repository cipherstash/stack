//! A field reference's order query on an ordered EQL v4 type finds the
//! rows the data path's query for the same value finds
//! (`stack_encrypt::dynamic::query_term`, which the Go SDK runs), and those
//! are the rows the plaintexts say.
//!
//! One column for each way a twin carries its terms: an order term alone
//! (`IntegerOrd` OPE, `IntegerOrdOre` block ORE), an equality term beside
//! it (`TextOrd`, `TextOrdOre`), and the answering index's term alone, for
//! a twin whose terms are optional (`TextSearch`, `TextSearchOre`).
//! tests/typed_queries.rs holds every ordered type's query to the data
//! path's, term by term. Here each query is compared against rows a record
//! stored: in Rust, by the comparison EQL v4 makes (an OPE term's bytes,
//! ore-rs's comparator for a block ORE term, an `hm`'s equality), and,
//! against an EQL v4 database, by the SQL operators themselves.

mod common;

use eql_bindings::encryption::EqlTargets;
use eql_bindings::v4::integer::{IntegerOrd, IntegerOrdOre, IntegerOrdOreQuery, IntegerOrdQuery};
use eql_bindings::v4::text::{
    TextOrd, TextOrdOre, TextOrdOreQuery, TextOrdQuery, TextSearch, TextSearchOre,
    TextSearchOreQuery, TextSearchQuery,
};
use eql_bindings::v4::DomainType;
use serde::Serialize;
use stack_encrypt::dynamic::{self, record, FieldPlan, Op, Operand, ValueFrame};
use stack_encrypt::{ContextPiece, EncryptInto, EncryptTarget, NonEmpty, StackCipher};
use std::cmp::Ordering;
use zeroize::Zeroize;

type Cipher = StackCipher<common::RecordingKeySource>;

/// The integers the rows hold, ascending, and the texts, ascending by
/// their fold.
const LEVELS: [i32; 5] = [-200, -1, 0, 7, 1_000_000];
const TEXTS: [&str; 5] = ["Alpha", "bravo", "Charlie", "delta", "Echo"];

/// The row whose values every query below asks for: the middle one, so
/// each ordering finds rows on both sides.
const ASKED: usize = 2;

/// One column: its field name, the EQL type it names, and its stored and
/// query domains.
struct Column {
    field: &'static str,
    name: &'static str,
    domain: &'static str,
    query_domain: &'static str,
}

/// Everything the tests below know of each column, written once per
/// column: the EQL type it names and that type's query twin, its field and
/// the field's reference, the plaintext and the values the rows hold, and
/// the operators it answers from a field reference. Each row becomes a
/// field of the plaintext record and of the encrypted one, a value of each
/// row, an entry of `columns()`, and an arm of `typed`, `asked_input` and
/// `stored_row`.
macro_rules! ranking_columns {
    ($(
        $name:ident ($query:path): $field:ident / $reference:ident, $plaintext:ty = $values:ident,
            [$($op:ident),+];
    )+) => {
        /// One row's plaintexts: a value for each ordered column.
        #[derive(Zeroize)]
        struct Ranking {
            $($field: $plaintext,)+
        }

        /// The table `rankings`, with a column of each shape of ordered twin.
        #[derive(EncryptTarget)]
        #[stash(struct = Ranking, scope = "rankings")]
        struct EncryptedRanking {
            $($field: $name,)+
        }

        /// The row at `at`: each column holds the `at`th value, so the rows
        /// ascend in every column.
        fn ranking(at: usize) -> Ranking {
            Ranking {
                $($field: <$plaintext>::from($values[at]),)+
            }
        }

        /// Every column, and the operators each answers from a field
        /// reference.
        fn columns() -> Vec<(Column, &'static [&'static str])> {
            vec![$((
                Column {
                    field: stringify!($field),
                    name: stringify!($name),
                    domain: $name::sql_domain_static(),
                    query_domain: <$query>::sql_domain_static(),
                },
                &[$(stringify!($op)),+],
            ),)+]
        }

        /// The field reference's query on `field` for `operator`, for the
        /// value of the [asked](ASKED) row.
        async fn typed(keyset: &Keyset<'_>, field: &str, operator: &str) -> serde_json::Value {
            match field {
                $(stringify!($field) => match operator {
                    $(stringify!($op) => json(
                        &EncryptedRanking::$reference
                            .$op(ranking(ASKED).$field)
                            .encrypt(keyset)
                            .await
                            .unwrap(),
                    ),)+
                    other => panic!("{field} answers no `{other}`"),
                },)+
                other => panic!("no column {other}"),
            }
        }

        /// The data path's input for the [asked](ASKED) row's value of
        /// `field`.
        fn asked_input(field: &str) -> ValueFrame {
            match field {
                $(stringify!($field) => ValueFrame::of($values[ASKED]).unwrap(),)+
                other => panic!("no column {other}"),
            }
        }

        /// A stored row, as JSON, by column.
        fn stored_row(stored: &EncryptedRanking) -> serde_json::Map<String, serde_json::Value> {
            let mut row = serde_json::Map::new();
            $(row.insert(
                stringify!($field).to_owned(),
                serde_json::to_value(&stored.$field).unwrap(),
            );)+
            row
        }
    };
}

ranking_columns! {
    IntegerOrd(IntegerOrdQuery): level / LEVEL, i32 = LEVELS, [lt, lte, gt, gte];
    IntegerOrdOre(IntegerOrdOreQuery): level_ore / LEVEL_ORE, i32 = LEVELS, [lt, lte, gt, gte];
    TextOrd(TextOrdQuery): title / TITLE, String = TEXTS, [eq, lt, lte, gt, gte];
    TextOrdOre(TextOrdOreQuery): title_ore / TITLE_ORE, String = TEXTS, [eq, lt, lte, gt, gte];
    TextSearch(TextSearchQuery): name / NAME, String = TEXTS, [eq, lt, lte, gt, gte];
    TextSearchOre(TextSearchOreQuery): name_ore / NAME_ORE, String = TEXTS,
        [eq, lt, lte, gt, gte];
}

/// The JSON a query binds.
fn json<Q: Serialize>(query: &Q) -> serde_json::Value {
    serde_json::to_value(query).unwrap()
}

type Keyset<'k> = stack_encrypt::KeysetCipher<'k, common::RecordingKeySource>;

/// The data path's query on `column` for `operator`, for the value of the
/// [asked](ASKED) row: a data plan with one field under
/// `rankings/<field>`, naming the column's type.
async fn data(cipher: &Cipher, column: &Column, operator: &str) -> serde_json::Value {
    let context = NonEmpty::new(ContextPiece::List(vec![
        ContextPiece::Text("rankings".into()),
        ContextPiece::Text(column.field.to_owned().into()),
    ]))
    .unwrap();
    let plan = record::Plan::new_with(
        vec![FieldPlan::with_target("value", context, column.name).unwrap()],
        &EqlTargets,
    )
    .unwrap();
    let input = asked_input(column.field);
    let term = dynamic::query_term(
        &cipher.default_keyset(),
        &plan,
        "value",
        Op::parse(operator).unwrap(),
        input,
        &EqlTargets,
    )
    .unwrap()
    .await
    .unwrap();
    assert_eq!(
        term.domain(),
        Some(column.query_domain),
        "{} {operator}: the data path binds the twin's domain",
        column.name
    );
    let Operand::One(bytes) = term.operand() else {
        panic!("{}: a one-value query has one operand", column.name);
    };
    serde_json::from_slice(bytes).unwrap()
}

/// The rows the plaintexts say `operator` finds against the asked row: the
/// rows ascend in every column, so it is their position against
/// [`ASKED`].
fn expected(operator: &str) -> Vec<usize> {
    (0..LEVELS.len())
        .filter(|at| match operator {
            "eq" => *at == ASKED,
            "lt" => *at < ASKED,
            "lte" => *at <= ASKED,
            "gt" => *at > ASKED,
            "gte" => *at >= ASKED,
            other => panic!("no operator {other}"),
        })
        .collect()
}

/// The rows of `stored` that `query` finds for `operator`, by the
/// comparison EQL v4 makes of their terms: `=` compares the `hm`, an
/// ordering compares the `op` as bytes (its hex is lowercase, so the
/// strings order as the bytes do) or the `ob` by ore-rs's comparator.
fn finds(
    name: &str,
    operator: &str,
    query: &serde_json::Value,
    stored: &[serde_json::Value],
) -> Vec<usize> {
    stored
        .iter()
        .enumerate()
        .filter(|(_, row)| {
            if operator == "eq" {
                return row["hm"] == query["hm"];
            }
            let order = match query.get("op") {
                Some(op) => row["op"].as_str().unwrap().cmp(op.as_str().unwrap()),
                None => common::ob_order(name, &row["ob"], &query["ob"]),
            };
            match operator {
                "lt" => order == Ordering::Less,
                "lte" => order != Ordering::Greater,
                "gt" => order == Ordering::Greater,
                "gte" => order != Ordering::Less,
                other => panic!("no operator {other}"),
            }
        })
        .map(|(at, _)| at)
        .collect()
}

/// The rows a record stored, as JSON, by column.
struct Scenario {
    cipher: Cipher,
    rows: Vec<serde_json::Map<String, serde_json::Value>>,
}

async fn scenario() -> Scenario {
    let (cipher, _) = common::cipher().await;
    let keyset = cipher.default_keyset();
    let mut rows = Vec::new();
    for at in 0..LEVELS.len() {
        let stored: EncryptedRanking = ranking(at).encrypt_into(&keyset).await.unwrap();
        let row = stored_row(&stored);
        rows.push(row);
    }
    Scenario { cipher, rows }
}

mod given_rows_a_record_stored {
    use super::*;

    /// For every column and operator, the field reference's query and the
    /// data path's each find exactly the rows the plaintexts say.
    #[tokio::test]
    async fn each_query_finds_the_rows_the_plaintexts_say() {
        let scenario = scenario().await;
        let keyset = scenario.cipher.default_keyset();
        for (column, operators) in columns() {
            let stored: Vec<serde_json::Value> = scenario
                .rows
                .iter()
                .map(|row| row[column.field].clone())
                .collect();
            for operator in operators {
                let typed = typed(&keyset, column.field, operator).await;
                let data = data(&scenario.cipher, &column, operator).await;
                assertions::finds_the_rows(
                    column.name,
                    operator,
                    "field reference",
                    &typed,
                    &stored,
                );
                assertions::finds_the_rows(column.name, operator, "data path", &data, &stored);
            }
        }
    }

    /// Needs an EQL v4 installation. The rows are inserted into their
    /// domains, and each SQL operator, given the field reference's query
    /// or the data path's, cast to the type's query domain, selects
    /// exactly the rows the plaintexts say.
    #[test]
    #[ignore = "requires EQL_TEST_DATABASE_URL pointing to an EQL v4 database"]
    fn postgres_selects_the_same_rows_for_each_query() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let (scenario, queries) = runtime.block_on(async {
            let scenario = scenario().await;
            let keyset = scenario.cipher.default_keyset();
            let mut queries = Vec::new();
            for (column, operators) in columns() {
                for operator in operators {
                    let typed = typed(&keyset, column.field, operator).await;
                    let data = data(&scenario.cipher, &column, operator).await;
                    queries.push((column.field, *operator, typed, data));
                }
            }
            (scenario, queries)
        });

        let mut db = postgres::Client::connect(
            &std::env::var("EQL_TEST_DATABASE_URL").expect("EQL_TEST_DATABASE_URL"),
            postgres::NoTls,
        )
        .unwrap();
        let declared: Vec<String> = columns()
            .iter()
            .map(|(column, _)| format!("{} {}", column.field, column.domain))
            .collect();
        db.batch_execute(&format!(
            "CREATE TEMP TABLE typed_rankings (id int PRIMARY KEY, {});",
            declared.join(", ")
        ))
        .unwrap();
        for (id, row) in scenario.rows.iter().enumerate() {
            let values: Vec<String> = columns()
                .iter()
                .map(|(column, _)| row[column.field].to_string())
                .collect();
            let casts: Vec<String> = columns()
                .iter()
                .enumerate()
                .map(|(at, (column, _))| format!("${}::text::jsonb::{}", at + 2, column.domain))
                .collect();
            let id = i32::try_from(id).unwrap();
            let mut params: Vec<&(dyn postgres::types::ToSql + Sync)> = vec![&id];
            params.extend(
                values
                    .iter()
                    .map(|v| v as &(dyn postgres::types::ToSql + Sync)),
            );
            db.execute(
                &format!(
                    "INSERT INTO typed_rankings VALUES ($1, {})",
                    casts.join(", ")
                ),
                &params,
            )
            .unwrap();
        }

        for (field, operator, typed, data) in queries {
            let column = columns()
                .into_iter()
                .find(|(column, _)| column.field == field)
                .unwrap()
                .0;
            let sql_operator = match operator {
                "eq" => "=",
                "lt" => "<",
                "lte" => "<=",
                "gt" => ">",
                "gte" => ">=",
                other => panic!("no operator {other}"),
            };
            let sql = format!(
                "SELECT id FROM typed_rankings WHERE {field} {sql_operator} \
                 $1::text::jsonb::{} ORDER BY id",
                column.query_domain
            );
            let select = |db: &mut postgres::Client, query: &serde_json::Value| -> Vec<usize> {
                db.query(&sql, &[&query.to_string()])
                    .unwrap_or_else(|error| panic!("{sql}: {error}"))
                    .iter()
                    .map(|row| usize::try_from(row.get::<_, i32>(0)).unwrap())
                    .collect()
            };
            let expected = expected(operator);
            assert_eq!(
                select(&mut db, &typed),
                expected,
                "{} {operator}: the field reference's query selects the plaintexts' rows",
                column.name
            );
            assert_eq!(
                select(&mut db, &data),
                expected,
                "{} {operator}: the data path's query selects the same rows",
                column.name
            );
        }
    }
}

mod assertions {
    use super::*;

    /// `query` finds exactly the rows the plaintexts say among `stored`,
    /// and finds some, or misses some, so the comparison is not vacuous.
    pub(super) fn finds_the_rows(
        name: &str,
        operator: &str,
        path: &str,
        query: &serde_json::Value,
        stored: &[serde_json::Value],
    ) {
        let expected = expected(operator);
        assert!(
            !expected.is_empty() && expected.len() < stored.len(),
            "{name} {operator}: the rows split"
        );
        assert_eq!(
            finds(name, operator, query, stored),
            expected,
            "{name} {operator}: the {path}'s query finds the rows the plaintexts say"
        );
    }
}
