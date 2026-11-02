//! `query`: the engine's equality query term for one field and one value.
//!
//! The term is the EQL query value the engine derives through the field's
//! EQL type, as JSON text. The SQL casts it to the type's query domain, such
//! as `eql_v4.query_text_eq`, and EQL's `=` compares it with the stored
//! values' `eq_term`. A term is derived from the index key in the loaded
//! keyset, so no ZeroKMS request is made once the shared client is built.

use stack_encrypt::dynamic::plaintext::Sink;
use stack_encrypt::dynamic::{self, OpSpec, Operand};
use stack_encrypt::kms::{DataKeySource, IndexKeySource};
use stack_encrypt::{Encrypt, KeysetCipher};

use crate::client;
use crate::encrypt::{engine_fault, ModelPlan};
use crate::plan;
use crate::refusal::Refusal;
use crate::targets;
use crate::values::{self, Kind, Value};

/// The equality query term for `value` on the sealed field `field` of
/// `plan`, as JSON text.
///
/// Builds the shared client on the first call in the process. The caller
/// has released the GIL, and has checked that `field` is a sealed field
/// whose type answers equality and that `value` fits its kind.
///
/// # Errors
///
/// The client's refusal, or the engine's for the query.
pub fn query(
    plan: &ModelPlan,
    field: &str,
    kind: Kind,
    value: Value<'_>,
) -> Result<String, Refusal> {
    let client = client::shared()?;
    client.block_on(query_with(&client.keyset(), plan, field, kind, value))
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
        OpSpec::Eq,
        Typed(kind, value),
        &targets::resolver(),
    )
    .map_err(|error| plan::refusal(&error))?
    .await
    .map_err(|error| Refusal::of(&error))?;
    let Operand::One(json) = term.operand() else {
        return Err(engine_fault("the equality term is not one operand"));
    };
    String::from_utf8(json.clone()).map_err(|_| engine_fault("the equality term is not UTF-8"))
}

/// A value written as the field's kind, as `encrypt` writes it.
struct Typed<'a>(Kind, Value<'a>);

impl Encrypt for Typed<'_> {
    fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
        values::write(sink, Some(self.0), self.1)
    }
}

#[cfg(test)]
mod tests {
    use stack_encrypt::StackCipher;
    use stack_kms::FakeDataKeySource;

    use super::*;
    use crate::decrypt::tests::{cipher, run, stored, users};
    use crate::encrypt::Column;

    fn term(cipher: &StackCipher<FakeDataKeySource>, email: &str) -> serde_json::Value {
        let json = run(query_with(
            &cipher.default_keyset(),
            &users(),
            "email",
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

    #[test]
    fn a_passthrough_field_is_refused_by_the_engine() {
        let cipher = cipher();

        let refused = run(query_with(
            &cipher.default_keyset(),
            &users(),
            "age",
            Kind::Int64,
            Value::Int(1),
        ))
        .unwrap_err();

        assert_eq!(refused.field.as_deref(), Some("age"), "{refused:?}");
    }
}
