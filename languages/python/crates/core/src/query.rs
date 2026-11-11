//! `query`: the engine's query term for one field, one operator, and one
//! value.
//!
//! The term is the EQL query value the engine derives through the field's
//! EQL type, as JSON text. The SQL casts it to the type's query domain, such
//! as `eql_v4.query_text_eq`, and EQL's operator compares it with the stored
//! values' term for that index. A term is derived from the index key in the
//! loaded keyset, so no ZeroKMS request is made once the shared client is
//! built.

pub use stack_encrypt::dynamic::OpSpec;
use stack_encrypt::dynamic::{self, Operand};
use stack_encrypt::kms::{DataKeySource, IndexKeySource};
use stack_encrypt::op::{Limit, Stats};
use stack_encrypt::KeysetCipher;

use crate::client;
use crate::encrypt::{engine_fault, ModelPlan};
use crate::plan;
use crate::refusal::Refusal;
use crate::targets;
use crate::values::{Kind, Typed, Value};

/// The query term for `op` and `value` on the sealed field `field` of
/// `plan`, as JSON text.
///
/// Checks first, with no I/O, that the field answers `op`. Then builds the
/// shared client on the first call in the process. The caller has released
/// the GIL, and has checked that `value` fits the field's kind.
///
/// # Errors
///
/// `query_unsupported` for a field that does not answer `op`, before any
/// request. Then the client's refusal, or the engine's for the query.
pub fn query(
    plan: &ModelPlan,
    field: &str,
    op: OpSpec,
    kind: Kind,
    value: Value<'_>,
) -> Result<String, Refusal> {
    answers(plan, field, op)?;
    client::run!(|cipher| query_with(&cipher.default_keyset(), plan, field, op, kind, value))
}

/// [`query`] under `keyset`.
///
/// # Errors
///
/// The engine's refusal for the query.
pub async fn query_with<K>(
    keyset: &KeysetCipher<'_, K>,
    plan: &ModelPlan,
    field: &str,
    op: OpSpec,
    kind: Kind,
    value: Value<'_>,
) -> Result<String, Refusal>
where
    K: DataKeySource + IndexKeySource + Sync + 'static,
{
    let term = dynamic::query_term(
        keyset,
        plan.plan(),
        field,
        op,
        Typed(Some(kind), value),
        &targets::resolver(),
    )
    .map_err(|error| plan::refusal(&error))?
    .await
    .map_err(|error| Refusal::of(&error))?;
    let Operand::One(json) = term.operand() else {
        return Err(engine_fault("the query term is not one operand"));
    };
    // A copy of the term's bytes, about a hundred: `QueryTerm` has no
    // accessor that gives up its operand.
    String::from_utf8(json.clone()).map_err(|_| engine_fault("the query term is not UTF-8"))
}

/// For each of `values`, a page of decrypted values of `field`, whether it
/// holds every token of the match text `text`, in order. Runs in the engine
/// with no key and no request. The rows reported `false` are the false
/// positives of a match search.
///
/// # Errors
///
/// `query_unsupported` for a field that does not answer `matches`, or the
/// engine's refusal.
pub fn verify(
    plan: &ModelPlan,
    field: &str,
    text: &str,
    values: &[&str],
) -> Result<Vec<bool>, Refusal> {
    answers(plan, field, OpSpec::Matches)?;
    dynamic::verify(
        plan.plan(),
        field,
        OpSpec::Matches,
        Typed(Some(Kind::String), Value::Text(text)),
        values
            .iter()
            .map(|value| Typed(Some(Kind::String), Value::Text(value))),
        &targets::resolver(),
    )
    .map_err(|error| plan::refusal(&error))
}

/// How many rows to fetch for the match term `term` on `field` so that,
/// at the confidence, `want` of them pass [`verify`]: `None` when the
/// engine cannot promise a finite number. `rows` is the rows the search
/// scans. `histogram` is the stored filters' set-bit counts, as `(bits,
/// rows)` pairs; without one, the limit is unbounded. `confidence` is
/// 0.99 when `None`. Uses no key and makes no request.
///
/// # Errors
///
/// `query_unsupported` for a field that does not answer `matches`, or the
/// engine's refusal of a term it would not derive.
pub fn target_limit(
    plan: &ModelPlan,
    field: &str,
    term: &str,
    want: u64,
    rows: u64,
    histogram: Option<&[(u32, u64)]>,
    confidence: Option<f64>,
) -> Result<Option<u64>, Refusal> {
    answers(plan, field, OpSpec::Matches)?;
    let mut stats = match histogram {
        Some(histogram) => Stats::measured(rows, histogram.iter().copied()),
        None => Stats::declared(rows),
    };
    if let Some(confidence) = confidence {
        stats = stats.with_confidence(confidence);
    }
    let limit = dynamic::target_limit(
        plan.plan(),
        field,
        OpSpec::Matches,
        term.as_bytes(),
        want,
        &stats,
        &targets::resolver(),
    )
    .map_err(|error| plan::refusal(&error))?;
    Ok(match limit {
        Limit::Rows(rows) => Some(rows),
        Limit::Unbounded => None,
    })
}

/// The operators `field` answers, by their engine names, from the plan
/// alone. A passthrough field answers none.
///
/// # Errors
///
/// The engine's refusal of the field.
pub fn operators(plan: &ModelPlan, field: &str) -> Result<Vec<&'static str>, Refusal> {
    let operators = dynamic::field_operators(plan.plan(), field, &targets::resolver())
        .map_err(|error| plan::refusal(&error))?;
    Ok(operators
        .iter()
        .map(|(operator, _)| operator.name())
        .collect())
}

/// Whether `field` answers `op`, from the plan alone: the engine answers an
/// operator through one of the field's indexes. `Cipher` checks the same
/// list first. This check is for a caller that did not.
///
/// # Errors
///
/// `query_unsupported`, or the engine's refusal of the field.
pub fn answers(plan: &ModelPlan, field: &str, op: OpSpec) -> Result<(), Refusal> {
    if operators(plan, field)?.contains(&op.name()) {
        return Ok(());
    }
    Err(Refusal {
        code: "query_unsupported".to_owned(),
        message: format!("field {field:?} has no index that answers {:?}.", op.name()),
        field: Some(field.to_owned()),
        reason: None,
    })
}

#[cfg(test)]
mod tests {
    use stack_encrypt::StackCipher;
    use stack_kms::FakeDataKeySource;

    use super::*;
    use crate::decrypt::tests::{cipher, run, stored, users};
    use crate::encrypt::{Column, Field};

    fn term(cipher: &StackCipher<FakeDataKeySource>, email: &str) -> serde_json::Value {
        let json = run(query_with(
            &cipher.default_keyset(),
            &users(),
            "email",
            OpSpec::Eq,
            Kind::String,
            Value::Text(email),
        ))
        .unwrap();
        serde_json::from_str(&json).unwrap()
    }

    #[test]
    fn the_term_is_the_stored_eq_term_with_no_ciphertext() {
        let cipher = cipher();
        let term = term(&cipher, "a@example.com");
        let Column::Eql(json) = &stored(&cipher, &users(), &["a@example.com"])[0][0] else {
            panic!("not EQL");
        };
        let stored: serde_json::Value = serde_json::from_str(json).unwrap();

        // `hm` is the equality term EQL's `=` compares. The query carries
        // no ciphertext: a term reveals nothing a stored row does not.
        assert_eq!(term["hm"], stored["hm"], "{term}");
        assert_eq!(term["i"], stored["i"], "{term}");
        assert!(term.get("c").is_none(), "{term}");
    }

    #[test]
    fn the_same_value_gives_the_same_term_and_another_value_another() {
        let cipher = cipher();

        assert_eq!(
            term(&cipher, "a@example.com"),
            term(&cipher, "a@example.com")
        );
        assert_ne!(
            term(&cipher, "a@example.com"),
            term(&cipher, "b@example.com")
        );
    }

    fn levels() -> ModelPlan {
        ModelPlan::new(
            "users",
            vec![Field {
                name: "level".to_owned(),
                eql: Some(("IntegerOrd".to_owned(), Kind::Int32)),
            }],
        )
        .unwrap()
    }

    const ORDER: [OpSpec; 4] = [OpSpec::Lt, OpSpec::Lte, OpSpec::Gt, OpSpec::Gte];

    #[test]
    fn an_order_field_answers_every_order_operator() {
        for op in ORDER {
            answers(&levels(), "level", op).unwrap();
        }
    }

    #[test]
    fn an_equality_field_answers_no_order_operator() {
        for op in ORDER {
            let refused = answers(&users(), "email", op).unwrap_err();
            assert_eq!(refused.code, "query_unsupported", "{op:?}");
            assert_eq!(refused.field.as_deref(), Some("email"));
            assert!(refused.message.contains(op.name()), "{}", refused.message);
        }
    }

    #[test]
    fn an_order_term_is_derived_for_the_operator_asked() {
        let cipher = cipher();
        for op in ORDER {
            let json = run(query_with(
                &cipher.default_keyset(),
                &levels(),
                "level",
                op,
                Kind::Int32,
                Value::Int(3),
            ))
            .unwrap();
            let term: serde_json::Value = serde_json::from_str(&json).unwrap();
            // `op` is the order term EQL's `<` and `>` compare. The query
            // carries no ciphertext.
            assert!(term.get("op").is_some(), "{op:?}: {term}");
            assert!(term.get("c").is_none(), "{op:?}: {term}");
        }
    }

    fn notes() -> ModelPlan {
        ModelPlan::new(
            "users",
            vec![Field {
                name: "notes".to_owned(),
                eql: Some(("TextMatch".to_owned(), Kind::String)),
            }],
        )
        .unwrap()
    }

    fn match_term(cipher: &StackCipher<FakeDataKeySource>, text: &str) -> String {
        run(query_with(
            &cipher.default_keyset(),
            &notes(),
            "notes",
            OpSpec::Matches,
            Kind::String,
            Value::Text(text),
        ))
        .unwrap()
    }

    #[test]
    fn a_match_term_is_a_filter_with_no_ciphertext() {
        let term: serde_json::Value = serde_json::from_str(&match_term(&cipher(), "ali")).unwrap();
        // `bf` is the Bloom filter EQL's `@@` compares.
        assert!(
            term["bf"].as_array().is_some_and(|bits| !bits.is_empty()),
            "{term}"
        );
        assert!(term.get("c").is_none(), "{term}");
    }

    #[test]
    fn verify_keeps_the_values_that_hold_every_token_of_the_text() {
        let verified = verify(
            &notes(),
            "notes",
            "ali",
            &["Alice Smith", "Bob Jones", "Natalie"],
        )
        .unwrap();
        assert_eq!(verified, [true, false, true]);
    }

    #[test]
    fn verify_on_a_field_with_no_match_index_is_unsupported() {
        let refused = verify(&users(), "email", "ali", &["alice"]).unwrap_err();
        assert_eq!(refused.code, "query_unsupported");
        assert_eq!(refused.field.as_deref(), Some("email"));
    }

    #[test]
    fn with_no_histogram_the_limit_is_unbounded() {
        let term = match_term(&cipher(), "ali");
        let limit = target_limit(&notes(), "notes", &term, 10, 10_000, None, None).unwrap();
        assert_eq!(limit, None);
    }

    #[test]
    fn with_empty_stored_filters_the_limit_is_the_rows_wanted() {
        // Every stored filter sets no bit, so no row passes by chance, and
        // the fetch needs no margin.
        let term = match_term(&cipher(), "ali");
        let limit = target_limit(
            &notes(),
            "notes",
            &term,
            10,
            10_000,
            Some(&[(0, 10_000)]),
            None,
        )
        .unwrap();
        assert_eq!(limit, Some(10));
    }

    #[test]
    fn fuller_stored_filters_need_a_larger_fetch() {
        let cipher = cipher();
        let term = match_term(&cipher, "ali");
        let sparse = target_limit(
            &notes(),
            "notes",
            &term,
            10,
            10_000,
            Some(&[(20, 10_000)]),
            None,
        )
        .unwrap()
        .unwrap();
        let full = target_limit(
            &notes(),
            "notes",
            &term,
            10,
            10_000,
            Some(&[(400, 10_000)]),
            None,
        )
        .unwrap()
        .unwrap();
        assert!(sparse >= 10, "{sparse}");
        assert!(full > sparse, "{full} <= {sparse}");
    }

    #[test]
    fn a_field_with_only_an_order_or_match_index_answers_no_equality() {
        for eql in ["IntegerOrd", "IntegerOrdOre", "TextMatch"] {
            let kind = if eql == "TextMatch" {
                Kind::String
            } else {
                Kind::Int32
            };
            let plan = ModelPlan::new(
                "users",
                vec![Field {
                    name: "rank".to_owned(),
                    eql: Some((eql.to_owned(), kind)),
                }],
            )
            .unwrap();

            let refused = answers(&plan, "rank", OpSpec::Eq).unwrap_err();

            assert_eq!(refused.code, "query_unsupported", "{eql}");
            assert_eq!(refused.field.as_deref(), Some("rank"));
        }
    }

    #[test]
    fn a_field_with_an_eq_index_answers_equality() {
        answers(&users(), "email", OpSpec::Eq).unwrap();
    }

    #[test]
    fn a_passthrough_field_answers_no_equality() {
        assert_eq!(
            answers(&users(), "age", OpSpec::Eq).unwrap_err().code,
            "query_unsupported"
        );
    }

    #[test]
    fn a_passthrough_field_is_refused_by_the_engine() {
        let cipher = cipher();

        let refused = run(query_with(
            &cipher.default_keyset(),
            &users(),
            "age",
            OpSpec::Eq,
            Kind::Int64,
            Value::Int(1),
        ))
        .unwrap_err();

        assert_eq!(refused.field.as_deref(), Some("age"), "{refused:?}");
    }
}
