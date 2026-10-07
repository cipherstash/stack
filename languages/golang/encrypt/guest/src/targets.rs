//! The EQL types this build holds: the `TargetResolver`
//! (`stack_encrypt::dynamic::TargetResolver`) the record operations run
//! target fields through. The two names below are cfg-dependent, so they
//! are code spans, not links: a doc build of either feature set resolves.
//!
//! Two builds of this crate, one resolver each (ADR-0007, amended
//! 2026-10-06). With the `eql` feature, [`Resolver`] is `EqlTargets`,
//! which installs `eql-bindings`' by-name dispatch
//! (`eql_bindings::encryption::targets`): `se_targets` lists every EQL type
//! the catalog has, and a plan field naming a producible one (`TextEq`) is
//! run through that type's own `EncryptFrom` / `DecryptInto`, in the same
//! ZeroKMS request as the rest of the record. Without it, [`Resolver`] is
//! the engine's `NoTargets` (`stack_encrypt::dynamic::NoTargets`):
//! `se_targets` lists nothing, and a plan that
//! names a target is refused when it is parsed — at `se_plan_check`, before
//! any value crosses.
//!
//! The Go module embeds both: `encrypt` the build without EQL types,
//! `encrypt/eql` the build with them, registered on import, so a program
//! that names an EQL type links the build that has it.

#[cfg(not(feature = "eql"))]
use stack_encrypt::dynamic::NoTargets;
#[cfg(feature = "eql")]
use stack_encrypt::dynamic::{TargetDescriptor, TargetError, TargetResolver};

/// The resolver this build installs.
#[cfg(feature = "eql")]
pub type Resolver = EqlTargets;
/// The resolver this build installs.
#[cfg(not(feature = "eql"))]
pub type Resolver = NoTargets;

/// This build's resolver, for the record operations.
pub fn resolver() -> Resolver {
    Resolver::default()
}

/// Whether this build holds the EQL types.
pub const HOLDS_EQL: bool = cfg!(feature = "eql");

/// `eql-bindings`' by-name dispatch as the engine's resolver. The resolver
/// sees a type name and a field's label; the field's name is the
/// lowering's to add to a refusal.
#[cfg(feature = "eql")]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EqlTargets;

#[cfg(feature = "eql")]
impl TargetResolver for EqlTargets {
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
        plaintext: vitaminc_aead_value::FfiValue,
    ) -> Result<stack_encrypt::Pending<'a, Vec<u8>, K>, TargetError> {
        eql_bindings::encryption::targets::encrypt(name, keyset, label, plaintext).map_err(convert)
    }

    fn decrypt<'a, K: 'static>(
        &self,
        name: &str,
        cipher: &'a stack_encrypt::StackCipher<K>,
        label: &stack_encrypt::Label,
        stored: &[u8],
    ) -> Result<stack_encrypt::Pending<'a, vitaminc_aead_value::FfiValue, K>, TargetError> {
        eql_bindings::encryption::targets::decrypt(name, cipher, label, stored).map_err(convert)
    }

    fn query<'a, K: 'static>(
        &self,
        name: &str,
        keyset: &'a stack_encrypt::KeysetCipher<'_, K>,
        label: &stack_encrypt::Label,
        plaintext: vitaminc_aead_value::FfiValue,
    ) -> Result<stack_encrypt::Pending<'a, Vec<u8>, K>, TargetError> {
        eql_bindings::encryption::targets::query(name, keyset, label, plaintext).map_err(convert)
    }
}

/// An `eql-bindings` table row as the engine's descriptor. The two spell
/// one wire format; `eql-bindings` tests its serde form against this
/// crate's `to_value`.
#[cfg(feature = "eql")]
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
#[cfg(feature = "eql")]
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
        Eql::Stored { target, source } => TargetError::Stored {
            name: String::new(),
            target: target.to_owned(),
            reason: source.to_string(),
        },
        other => TargetError::Other(Box::new(other)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(not(feature = "eql"))]
    #[test]
    fn the_build_without_eql_holds_no_target() {
        use stack_encrypt::dynamic::TargetResolver as _;
        assert!(resolver().targets().is_empty());
        assert!(matches!(
            resolver().resolve("TextEq"),
            Err(stack_encrypt::dynamic::TargetError::NoTargets { .. })
        ));
    }

    #[cfg(feature = "eql")]
    #[test]
    fn the_eql_build_lists_the_catalog_and_resolves_text_eq() {
        let targets = resolver().targets();
        assert!(!targets.is_empty(), "the catalog has types");
        let text_eq = targets.iter().find(|t| t.name == "TextEq").expect("TextEq");
        assert!(text_eq.producible);
        assert_eq!(
            text_eq.plaintext,
            Some(vitaminc_aead_value::ValueKind::String)
        );
        assert_eq!(text_eq.indexes, ["eq"]);
        assert_eq!(text_eq.query.as_deref(), Some("TextEqQuery"));
        assert_eq!(resolver().resolve("TextEq").unwrap().name, "TextEq");
        let producible: Vec<&str> = targets
            .iter()
            .filter(|t| t.producible)
            .map(|t| t.name.as_str())
            .collect();
        assert_eq!(producible, ["TextEq"], "the engine produces TextEq only");
        assert!(matches!(
            resolver().resolve("TextOrdOre"),
            Err(TargetError::Unproducible { .. })
        ));
        assert!(matches!(
            resolver().resolve("Nope"),
            Err(TargetError::Unknown { .. })
        ));
    }

    #[cfg(feature = "eql")]
    #[test]
    fn eql_refusals_convert_to_the_engines_with_the_field_left_to_the_lowering() {
        use eql_bindings::encryption::targets::TargetError as Eql;
        assert!(matches!(
            convert(Eql::Context {
                label: "tenant/users/email".into()
            }),
            TargetError::Column { name, label, .. } if name.is_empty() && label == "tenant/users/email"
        ));
        assert!(matches!(
            convert(Eql::Plaintext {
                target: "TextEq",
                expected: vitaminc_aead_value::ValueKind::String,
                found: Some(vitaminc_aead_value::ValueKind::UInt64),
            }),
            TargetError::Plaintext { target, expected: Some(vitaminc_aead_value::ValueKind::String), .. } if target == "TextEq"
        ));
    }
}
