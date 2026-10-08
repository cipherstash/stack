//! The EQL types this wheel holds, as the engine's `TargetResolver`.
//!
//! `eql-bindings` already provides a by-name dispatch over its catalog
//! (`eql_bindings::encryption::targets`), so this is a wrapper and not a
//! second copy of anything. `languages/golang/encrypt/guest/src/targets.rs`
//! is the same wrapper for the WASI guest, and `describe` and `convert`
//! below are its two functions unchanged — they are the mapping between
//! eql-bindings' catalog types and the engine's, and there is one right
//! answer. The difference is that this build is always the EQL build: a
//! native wheel has no second build to choose between, so there is no `eql`
//! feature and no `NoTargets` arm.
//!
//! **Selection by (kind, index) rather than by EQL name is deliberate.** It
//! keeps every EQL name out of Python: the declaration says the field holds
//! text and a query must compare it for equality, and the engine answers
//! `TextEq`. Principle G1 — the SDK declares, the engine decides.
//!
//! Today the catalog produces exactly one type, `TextEq`. The others are
//! present and `Unproducible`, so a declaration that reaches for one gets
//! the catalog's own reason rather than "unknown".

use pyo3::prelude::*;
use stack_encrypt::dynamic::{TargetDescriptor, TargetError, TargetResolver, ValueKind};

use crate::errors::PlanError;

/// `eql-bindings`' dispatch as the engine's resolver.
#[derive(Clone, Copy, Debug, Default)]
pub struct Resolver;

impl TargetResolver for Resolver {
    fn targets(&self) -> Vec<TargetDescriptor> {
        eql_bindings::encryption::targets::targets()
            .iter()
            .map(describe)
            .collect()
    }

    fn encrypt<'a, K: 'static>(
        &self,
        name: &str,
        keyset: &'a stack_encrypt::KeysetCipher<'_, K>,
        label: &stack_encrypt::Label,
        plaintext: stack_encrypt::dynamic::FfiValue,
    ) -> Result<stack_encrypt::Pending<'a, Vec<u8>, K>, TargetError> {
        eql_bindings::encryption::targets::encrypt(name, keyset, label, plaintext).map_err(convert)
    }

    fn decrypt<'a, K: 'static>(
        &self,
        name: &str,
        cipher: &'a stack_encrypt::StackCipher<K>,
        label: &stack_encrypt::Label,
        stored: &[u8],
    ) -> Result<stack_encrypt::Pending<'a, stack_encrypt::dynamic::FfiValue, K>, TargetError> {
        eql_bindings::encryption::targets::decrypt(name, cipher, label, stored).map_err(convert)
    }

    fn query<'a, K: 'static>(
        &self,
        name: &str,
        keyset: &'a stack_encrypt::KeysetCipher<'_, K>,
        label: &stack_encrypt::Label,
        plaintext: stack_encrypt::dynamic::FfiValue,
    ) -> Result<stack_encrypt::Pending<'a, Vec<u8>, K>, TargetError> {
        eql_bindings::encryption::targets::query(name, keyset, label, plaintext).map_err(convert)
    }
}

/// The producible type whose plaintext kind is `kind` and whose index set
/// contains `index`.
///
/// Exactly one must match. Zero is a declaration no EQL type serves; more
/// than one means the catalog cannot be addressed this way and the
/// declaration has to name a type, so the refusal lists the candidates.
pub fn select(kind: ValueKind, index: Option<&str>) -> PyResult<TargetDescriptor> {
    let mut matching: Vec<TargetDescriptor> = Resolver
        .targets()
        .into_iter()
        .filter(|target| target.producible)
        .filter(|target| target.plaintext == Some(kind))
        .filter(|target| match index {
            None => target.indexes.is_empty(),
            Some(key) => target.indexes.iter().any(|carried| carried == key),
        })
        .collect();

    match matching.len() {
        1 => Ok(matching.remove(0)),
        0 => Err(PlanError::new_err(format!(
            "no EQL type the engine produces holds {} with index {}. \
             Producible today: {}",
            kind.name(),
            index.unwrap_or("none"),
            producible().join(", "),
        ))),
        _ => Err(PlanError::new_err(format!(
            "{} EQL types hold {} with index {}: name one with \
             EQL(name=...) — {}",
            matching.len(),
            kind.name(),
            index.unwrap_or("none"),
            names(&matching).join(", "),
        ))),
    }
}

/// A named type's descriptor, for an explicit `EQL(name=...)`.
///
/// `TargetResolver::resolve` carries the catalog's own refusals: unknown,
/// or present but not produced, with the reason it records.
pub fn named(name: &str) -> PyResult<TargetDescriptor> {
    Resolver
        .resolve(name)
        .map_err(|error| PlanError::new_err(format!("{error}")))
}

/// Every EQL type the engine produces today, for a refusal's message. A
/// declaration that reaches for one it does not is the common mistake, and
/// the list is short.
fn producible() -> Vec<String> {
    names(
        &Resolver
            .targets()
            .into_iter()
            .filter(|target| target.producible)
            .collect::<Vec<_>>(),
    )
}

fn names(targets: &[TargetDescriptor]) -> Vec<String> {
    targets
        .iter()
        .map(|target| target.name.clone())
        .collect::<Vec<_>>()
}

fn describe(target: &eql_bindings::encryption::targets::Target) -> TargetDescriptor {
    TargetDescriptor::new(
        target.name,
        target.family,
        target.suffix,
        target.plaintext_kind(),
        target.sql_domain,
        target.indexes.iter().map(|key| (*key).to_owned()).collect(),
        target.query.map(str::to_owned),
        target.query_sql_domain.map(str::to_owned),
        target.producible,
        target.reason.map(str::to_owned),
    )
}

/// An `eql-bindings` refusal as the engine's. The field name is left empty:
/// the lowering fills it in, since the resolver never sees it.
fn convert(error: eql_bindings::encryption::targets::TargetError) -> TargetError {
    use eql_bindings::encryption::targets::TargetError as Eql;
    match error {
        Eql::Unknown { name } => TargetError::Unknown { name },
        Eql::Unproducible { name, reason } => TargetError::Unproducible {
            name: name.to_owned(),
            reason: reason.to_owned(),
        },
        Eql::NoQuery { name } => TargetError::NoQuery {
            name: name.to_owned(),
        },
        Eql::Context { label } => TargetError::Column {
            name: String::new(),
            label,
            reason: "an EQL column is a two-segment label, table and column".to_owned(),
        },
        Eql::Plaintext {
            target,
            expected,
            found,
        } => TargetError::Plaintext {
            name: String::new(),
            target: target.to_owned(),
            expected: Some(expected),
            found,
        },
        // The parser's kind and position, never its message: serde_json
        // quotes the input it refused, and the input is stored ciphertext.
        Eql::Stored { target, source } => TargetError::Stored {
            name: String::new(),
            target: target.to_owned(),
            reason: stack_encrypt::diagnostic::describe_json_error(&source),
        },
        other => TargetError::Other(Box::new(other)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The catalog is what this wheel can produce, and the tracer's whole
    /// path rests on `TextEq` being in it.
    #[test]
    fn the_catalog_produces_text_eq_and_the_selector_finds_it() {
        let found = select(ValueKind::String, Some("eq")).expect("TextEq");
        assert_eq!(found.name, "TextEq");
        assert_eq!(found.sql_domain, "public.eql_v3_text_eq");
        assert_eq!(
            found.query_sql_domain.as_deref(),
            Some("eql_v3.query_text_eq")
        );
    }

    /// A pair no producible type serves. `TextOrdOre` is in the catalog and
    /// is not produced, so the selector must not offer it.
    #[test]
    fn a_pair_no_producible_type_serves_is_refused() {
        assert!(select(ValueKind::String, Some("ore")).is_err());
        assert!(select(ValueKind::Int64, Some("eq")).is_err());
    }

    #[test]
    fn an_unknown_name_is_refused_and_an_unproducible_one_says_why() {
        assert!(named("Nope").is_err());
        assert!(named("TextOrdOre").is_err());
        assert_eq!(named("TextEq").expect("TextEq").name, "TextEq");
    }
}
