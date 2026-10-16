//! Binding an expected leaf type into the AAD.
//!
//! [`LeafTypeAad`] is for a **schema-aware** caller, one that already knows
//! what type a field must hold. It binds that expectation into the AAD at
//! both ends, so a ciphertext of the wrong type fails authentication before
//! any plaintext is released. A type confusion becomes an ordinary AEAD
//! failure.
//!
//! Binding is opt-in, and stays so. If every leaf's type were bound by
//! default, a reader would need the type to open the data: a JavaScript or
//! Go reader with no schema, which decodes whatever the leaf's tag says,
//! could no longer open rows a Rust writer sealed. Self-describing data
//! that any binding can read is the default; a caller that holds a schema
//! on both sides adds this binding on top.
//!
//! The self-describing path never binds it. A sealed leaf carries its own
//! tag inside the AEAD, which is knowable only *after* decryption; AAD must
//! be known *before*, so it can only carry an expectation the caller
//! already holds. The two are complementary: the inner tag makes a value
//! self-describing, and this binding lets a schema enforce a type up front.
//!
//! The expectation a schema holds is "this column is a date", not "this
//! column is an int", so what is bound is the physical kind **and** the
//! logical id. An int's width is not part of it: width is a hint end to
//! end, and a column of `i32`s and a column of `i64`s are both int columns.
//! The logical type's parameter is not bound either: a decimal's scale
//! varies from value to value within one column, and binding it would
//! refuse `1.50` next to `1.5`. The parameter is still validated after
//! opening, by [`Logical::admits`].
//!
//! A known logical type is stored as exactly one kind, so
//! [`LeafTypeAad::logical`] derives the kind from it rather than taking
//! one: a pair that disagrees, such as text bound as a date, cannot be
//! written, and a column with a logical type has one binding, not one per
//! kind a caller might pick. Only for a logical id this build does not know
//! ([`LeafTypeAad::unknown`]) does the caller name the kind, since nothing
//! here can know it.
//!
//! The binding is a declaration, not a check. Nothing compares it with the
//! value being sealed, so a writer that binds a date and seals text has
//! made a ciphertext that opens, as text, under the date binding and under
//! nothing else. What the binding authenticates is that writer and reader
//! agree on the type; what the value is, the leaf's own tag says.

use std::borrow::Cow;

use crate::plaintext::kinds::id;
use crate::{ContextPiece, IntoContext, Kind, KnownLogical, UnknownLogicalId};

/// Domain-separation label for the leaf-type binding. Leading the list
/// keeps the context disjoint from a caller binding `(base, kind, id)` as a
/// list of its own. Replaces `vitaminc/aead-value/leaf-type/v1`, which
/// bound the leaf tag alone; a ciphertext bound under that label does not
/// open under this one.
const LEAF_TYPE_DOMAIN: &[u8] = b"vitaminc/aead/leaf-type/v2";

/// A context that binds an expected leaf type onto a base context.
///
/// Built on a base context (anything implementing [`IntoContext`],
/// typically the caller's schema context) by one of three constructors,
/// one per shape of column:
///
/// - [`physical`](Self::physical): a [`Kind`] with no logical type;
/// - [`logical`](Self::logical): a [`KnownLogical`], over the one kind it is
///   stored as;
/// - [`unknown`](Self::unknown): an [`UnknownLogicalId`] from a newer build,
///   over a kind the caller names.
///
/// None takes a logical type's parameter, which is never bound, and none
/// can pair a known logical type with a kind it is not stored as, so there
/// is nothing to check and nothing to fail.
///
/// As a context it is the four-part list `(domain, base, kind, id)`, with
/// the base's own parts intact, the kind's wire byte as a `u8` leaf and
/// the id as a `u8` leaf, `0` for no logical type. The same binding must
/// be supplied on decrypt or authentication fails.
///
/// ```
/// use vitaminc_aead::{Kind, KnownLogical, LeafTypeAad, UnknownLogicalId};
///
/// // A column of plain integers, of any width.
/// let age = LeafTypeAad::physical(("users", "age"), Kind::Int);
/// // A column of dates, bound over int, the kind a date is stored as.
/// let signed_up = LeafTypeAad::logical(("users", "signed_up"), KnownLogical::Date);
/// // A column of decimals, of any scale.
/// let price = LeafTypeAad::logical(("orders", "price"), KnownLogical::Decimal);
/// // A column whose logical type is newer than this build.
/// let id = UnknownLogicalId::new(200).expect("above the last known id");
/// let future = LeafTypeAad::unknown(("orders", "eta"), Kind::Int, id);
/// ```
///
/// A schema that stores each column's kind and logical id, as a
/// cross-language one does, picks the constructor from the id:
///
/// ```
/// use vitaminc_aead::{Kind, KnownLogical, LeafTypeAad, UnknownLogicalId};
///
/// fn column(name: &str, kind: Kind, logical_id: u8) -> LeafTypeAad<'_> {
///     if let Some(known) = KnownLogical::from_id(logical_id) {
///         // A known logical type brings its own kind.
///         LeafTypeAad::logical(name, known)
///     } else if let Some(unknown) = UnknownLogicalId::new(logical_id) {
///         LeafTypeAad::unknown(name, kind, unknown)
///     } else {
///         LeafTypeAad::physical(name, kind)
///     }
/// }
/// # let _ = column("price", Kind::Int, 4);
/// ```
///
/// The binding is associated data, not a secret, so it is `Debug` and
/// `Clone`: a caller can keep one per column and clone it for each row.
#[derive(Clone, Debug)]
pub struct LeafTypeAad<'a> {
    base: ContextPiece<'a>,
    kind: Kind,
    id: u8,
}

impl<'a> LeafTypeAad<'a> {
    /// Bind `kind`, with no logical type, as the expected leaf type onto
    /// `base`: a column of plain values of that kind.
    pub fn physical(base: impl IntoContext<'a>, kind: Kind) -> Self {
        Self::bind(base, kind, id::NONE)
    }

    /// Bind `logical`, over the kind it is stored as
    /// ([`KnownLogical::kind`]), as the expected leaf type onto `base`: a
    /// column of that logical type, whatever each value's parameter, such
    /// as a decimal's scale or a timestamp's unit.
    pub fn logical(base: impl IntoContext<'a>, logical: KnownLogical) -> Self {
        Self::bind(base, logical.kind(), logical.id())
    }

    /// Bind the logical id `logical`, from a build newer than this one,
    /// over `kind` as the expected leaf type onto `base`. This build cannot
    /// know what kind that logical type is stored as, so the caller names
    /// it; it must be the kind the newer build derives, or the two do not
    /// agree on the binding.
    pub fn unknown(base: impl IntoContext<'a>, kind: Kind, logical: UnknownLogicalId) -> Self {
        Self::bind(base, kind, logical.get())
    }

    fn bind(base: impl IntoContext<'a>, kind: Kind, id: u8) -> Self {
        Self {
            base: base.into_context(),
            kind,
            id,
        }
    }
}

impl<'a> IntoContext<'a> for LeafTypeAad<'a> {
    fn into_context(self) -> ContextPiece<'a> {
        ContextPiece::List(vec![
            ContextPiece::Bytes(Cow::Borrowed(LEAF_TYPE_DOMAIN)),
            self.base,
            ContextPiece::U8(self.kind.to_wire()),
            ContextPiece::U8(self.id),
        ])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plaintext::record::{record, Event, Owned, Record};
    use crate::plaintext::{Int, Logical, Physical, Raw};
    use crate::seal::mock::{Leaf, Mock, Refused};
    use crate::{decrypt, decrypt_into, encrypt, Context, DecryptError, IntoAad, Node};

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// The exact bytes are the type-binding commitment: the list
    /// `(domain, base, kind, id)` of typed parts. Changing them breaks
    /// decryption of every schema-bound ciphertext.
    #[test]
    fn pins_the_context_bytes_with_no_logical_type() {
        let bound = LeafTypeAad::physical("ctx", Kind::Int).into_aad();
        let expected = Context::pae(&[
            LEAF_TYPE_DOMAIN.into_aad().as_bytes(),
            "ctx".into_aad().as_bytes(),
            Kind::Int.to_wire().into_aad().as_bytes(),
            0u8.into_aad().as_bytes(),
        ]);
        assert_eq!(bound, expected);
        // Four parts, each a typed leaf of the context encoding.
        assert_eq!(
            hex(bound.as_bytes()),
            concat!(
                "0400000000000000",
                // The domain label, as bytes.
                "6c00000000000000",
                "0300000000000000",
                "1900000000000000766974616d696e632f636f6e746578742f76616c75652f7631",
                "1900000000000000766974616d696e632f636f6e746578742f62797465732f7631",
                "1a00000000000000766974616d696e632f616561642f6c6561662d747970652f7632",
                // The base, "ctx", as text.
                "5400000000000000",
                "0300000000000000",
                "1900000000000000766974616d696e632f636f6e746578742f76616c75652f7631",
                "1800000000000000766974616d696e632f636f6e746578742f757466382f7631",
                "0300000000000000637478",
                // The kind, int, as a u8.
                "5300000000000000",
                "0300000000000000",
                "1900000000000000766974616d696e632f636f6e746578742f76616c75652f7631",
                "1900000000000000766974616d696e632f636f6e746578742f75382d6c652f7631",
                "010000000000000002",
                // No logical type, as a u8.
                "5300000000000000",
                "0300000000000000",
                "1900000000000000766974616d696e632f636f6e746578742f76616c75652f7631",
                "1900000000000000766974616d696e632f636f6e746578742f75382d6c652f7631",
                "010000000000000000",
            )
        );
    }

    #[test]
    fn pins_the_context_bytes_with_a_logical_type() {
        let bound = LeafTypeAad::logical("ctx", KnownLogical::Date).into_aad();
        let expected = Context::pae(&[
            LEAF_TYPE_DOMAIN.into_aad().as_bytes(),
            "ctx".into_aad().as_bytes(),
            Kind::Int.to_wire().into_aad().as_bytes(),
            id::DATE.into_aad().as_bytes(),
        ]);
        assert_eq!(bound, expected);
        // The same four parts, with the date's id.
        assert_eq!(
            hex(bound.as_bytes()),
            concat!(
                "0400000000000000",
                "6c00000000000000",
                "0300000000000000",
                "1900000000000000766974616d696e632f636f6e746578742f76616c75652f7631",
                "1900000000000000766974616d696e632f636f6e746578742f62797465732f7631",
                "1a00000000000000766974616d696e632f616561642f6c6561662d747970652f7632",
                "5400000000000000",
                "0300000000000000",
                "1900000000000000766974616d696e632f636f6e746578742f76616c75652f7631",
                "1800000000000000766974616d696e632f636f6e746578742f757466382f7631",
                "0300000000000000637478",
                "5300000000000000",
                "0300000000000000",
                "1900000000000000766974616d696e632f636f6e746578742f76616c75652f7631",
                "1900000000000000766974616d696e632f636f6e746578742f75382d6c652f7631",
                "010000000000000002",
                "5300000000000000",
                "0300000000000000",
                "1900000000000000766974616d696e632f636f6e746578742f76616c75652f7631",
                "1900000000000000766974616d696e632f636f6e746578742f75382d6c652f7631",
                "010000000000000002",
            )
        );
    }

    #[test]
    fn keeps_the_base_parts_intact() {
        let parts = LeafTypeAad::physical(("schema", 7u64), Kind::Text).into_context();
        assert_eq!(
            parts.to_string(),
            "(0x766974616d696e632f616561642f6c6561662d747970652f7632, (\"schema\", 7u64), 4u8, 0u8)"
        );
        assert_eq!(parts.leaves().count(), 5);
    }

    #[test]
    fn differs_from_a_map_entry_and_from_a_bare_list() {
        // The domain label keeps the binding disjoint from the map-entry
        // derivation and from a caller binding `(base, kind, id)` as a list
        // of their own.
        let leaf = LeafTypeAad::physical("ctx", Kind::Int).into_aad();
        assert_ne!(leaf, "ctx".into_aad().for_map_entry("\x02"));
        let bare = ContextPiece::List(vec![
            "ctx".into_context(),
            ContextPiece::U8(Kind::Int.to_wire()),
            ContextPiece::U8(0),
        ]);
        assert_ne!(leaf, bare.into_aad());
    }

    /// The four parts the binding is, built by hand.
    fn parts(kind: Kind, id: u8) -> Context<'static> {
        Context::pae(&[
            LEAF_TYPE_DOMAIN.into_aad().as_bytes(),
            "ctx".into_aad().as_bytes(),
            kind.to_wire().into_aad().as_bytes(),
            id.into_aad().as_bytes(),
        ])
    }

    const ALL_KINDS: [Kind; 6] = [
        Kind::Null,
        Kind::Bool,
        Kind::Int,
        Kind::Float,
        Kind::Text,
        Kind::Bytes,
    ];

    /// Every binding a constructor can build is the list
    /// `(domain, base, kind, id)`, byte for byte: each kind with id 0, each
    /// known logical type over its kind and id, and every unknown id over
    /// every kind.
    #[test]
    fn every_kind_and_logical_id_binds_its_four_parts() {
        for kind in ALL_KINDS {
            assert_eq!(
                LeafTypeAad::physical("ctx", kind).into_aad(),
                parts(kind, id::NONE),
                "{kind:?}"
            );
        }
        let known = [
            (KnownLogical::Undefined, Kind::Null, id::UNDEFINED),
            (KnownLogical::Date, Kind::Int, id::DATE),
            (KnownLogical::Timestamp, Kind::Int, id::TIMESTAMP),
            (KnownLogical::Decimal, Kind::Int, id::DECIMAL),
            (KnownLogical::Uuid, Kind::Bytes, id::UUID),
        ];
        // Every id this build knows is here.
        assert_eq!(
            known.map(|(_, _, id)| id),
            core::array::from_fn(|i| i as u8 + 1)
        );
        assert_eq!(usize::from(id::LAST_KNOWN), known.len());
        for (logical, kind, id) in known {
            assert_eq!(
                LeafTypeAad::logical("ctx", logical).into_aad(),
                parts(kind, id),
                "{logical:?}"
            );
        }
        for id in id::LAST_KNOWN + 1..=u8::MAX {
            let unknown = UnknownLogicalId::new(id).expect("unknown");
            for kind in ALL_KINDS {
                assert_eq!(
                    LeafTypeAad::unknown("ctx", kind, unknown).into_aad(),
                    parts(kind, id),
                    "{kind:?} with id {id}"
                );
            }
        }
    }

    #[test]
    fn is_sensitive_to_the_kind_and_the_id() {
        let int = LeafTypeAad::physical("ctx", Kind::Int).into_aad();
        assert_ne!(int, LeafTypeAad::physical("ctx", Kind::Text).into_aad());
        assert_ne!(
            int,
            LeafTypeAad::logical("ctx", KnownLogical::Date).into_aad()
        );
        assert_ne!(
            LeafTypeAad::logical("ctx", KnownLogical::Date).into_aad(),
            LeafTypeAad::logical("ctx", KnownLogical::Decimal).into_aad()
        );
        let unknown = |id| UnknownLogicalId::new(id).expect("unknown");
        assert_ne!(
            int,
            LeafTypeAad::unknown("ctx", Kind::Int, unknown(200)).into_aad()
        );
        assert_ne!(
            LeafTypeAad::unknown("ctx", Kind::Int, unknown(200)).into_aad(),
            LeafTypeAad::unknown("ctx", Kind::Int, unknown(201)).into_aad()
        );
        assert_ne!(
            LeafTypeAad::unknown("ctx", Kind::Int, unknown(200)).into_aad(),
            LeafTypeAad::unknown("ctx", Kind::Text, unknown(200)).into_aad()
        );
    }

    /// Every physical kind has a wire byte of its own, and a boolean column
    /// binds like any other.
    #[test]
    fn every_kind_binds_differently() {
        for (i, a) in ALL_KINDS.iter().enumerate() {
            for b in &ALL_KINDS[i + 1..] {
                assert_ne!(
                    LeafTypeAad::physical("ctx", *a).into_aad(),
                    LeafTypeAad::physical("ctx", *b).into_aad(),
                    "{a:?} and {b:?} bind the same"
                );
            }
        }
        // One binding per column, cloned for each use.
        let flag = LeafTypeAad::physical("flags", Kind::Bool);
        let sealed = encrypt(true, &Mock, flag.clone()).expect("seals");
        assert!(decrypt::<bool, _, _>(&Mock, sealed, flag).expect("opens"));
    }

    /// A known logical type binds over the one kind it is stored as, the
    /// same binding as that kind with its id, so a column with a logical
    /// type has a single binding.
    #[test]
    fn a_logical_type_binds_over_its_own_kind() {
        assert_eq!(KnownLogical::Uuid.kind(), Kind::Bytes);
        assert_eq!(
            LeafTypeAad::logical("ctx", KnownLogical::Uuid).into_aad(),
            parts(Kind::Bytes, id::UUID)
        );
        assert_ne!(
            LeafTypeAad::logical("ctx", KnownLogical::Uuid).into_aad(),
            parts(Kind::Text, id::UUID)
        );
    }

    /// The binding is associated data, so its `Debug` shows the parts.
    #[test]
    fn debug_shows_the_binding() {
        let bound = LeafTypeAad::logical("ctx", KnownLogical::Date);
        let shown = format!("{bound:?}");
        assert!(shown.contains("Int") && shown.contains("id: 2"), "{shown}");
    }

    fn date() -> LeafTypeAad<'static> {
        LeafTypeAad::logical("schema", KnownLogical::Date)
    }

    fn int() -> LeafTypeAad<'static> {
        LeafTypeAad::physical("schema", Kind::Int)
    }

    fn opens<T: crate::typed::Decrypt>(
        sealed: Node<Leaf>,
        aad: LeafTypeAad<'_>,
    ) -> Result<T, DecryptError<crate::DecodeError, Refused>> {
        decrypt(&Mock, sealed, aad)
    }

    /// The binding is what the mock authenticates, so a value sealed under
    /// one expected type cannot be opened under another, either way round,
    /// and opens under its own.
    #[test]
    fn a_date_does_not_open_as_an_int_nor_an_int_as_a_date() {
        let days = || Raw(Some(Logical::Date), Physical::Int(Int::I32(19_000)));
        let sealed = encrypt(days(), &Mock, date()).expect("seals");
        assert!(
            matches!(
                opens::<i32>(sealed, int()),
                Err(DecryptError::Cipher(Refused))
            ),
            "a date opened under the int binding"
        );

        let sealed = encrypt(19_000i32, &Mock, int()).expect("seals");
        assert!(
            matches!(
                opens::<i32>(sealed, date()),
                Err(DecryptError::Cipher(Refused))
            ),
            "an int opened under the date binding"
        );

        let sealed = encrypt(19_000i32, &Mock, int()).expect("seals");
        assert_eq!(opens::<i32>(sealed, int()).expect("opens"), 19_000);
        let sealed = encrypt(days(), &Mock, date()).expect("seals");
        let mut log = Vec::new();
        decrypt_into(&Mock, sealed, date(), Record(&mut log)).expect("opens");
        assert_eq!(log, record(days()).expect("records"));
    }

    /// The int's width is not bound: an `i64` column and an `i32` column
    /// are both int columns.
    #[test]
    fn the_width_is_not_bound() {
        let sealed = encrypt(19_000i64, &Mock, int()).expect("seals");
        assert_eq!(opens::<i32>(sealed, int()).expect("opens"), 19_000);
    }

    /// The scale is not bound, so one column holds decimals of any scale,
    /// and each opens with the scale it was sealed with.
    #[test]
    fn decimals_of_different_scales_open_under_one_binding() {
        let column = || LeafTypeAad::logical("price", KnownLogical::Decimal);
        for (scale, mantissa) in [(2u8, 150i128), (1, 15), (0, 2)] {
            let value = || {
                Raw(
                    Some(Logical::Decimal { scale }),
                    Physical::Int(Int::I128(mantissa)),
                )
            };
            let sealed = encrypt(value(), &Mock, column()).expect("seals");
            let mut log = Vec::new();
            decrypt_into(&Mock, sealed, column(), Record(&mut log)).expect("opens");
            assert_eq!(
                log,
                [Event::Scalar(
                    Some(Logical::Decimal { scale }),
                    Owned::Int(Int::I128(mantissa))
                )],
                "scale {scale} did not round-trip"
            );
        }
    }

    /// The parameter is validated after opening, not by the binding: a leaf
    /// whose scale is out of range is refused when it is read, whichever
    /// binding it was sealed under.
    #[test]
    fn the_parameter_is_still_validated_after_opening() {
        let column = || LeafTypeAad::logical("price", KnownLogical::Decimal);
        // A leaf plaintext hand-built with a scale of 29, which the sink
        // would never write.
        let mut plaintext = vec![crate::tags::DECIMAL];
        plaintext.extend_from_slice(&(29u32 << 16).to_le_bytes());
        plaintext.extend_from_slice(&[1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        let leaf = crate::seal::Cipher::seal(
            &Mock,
            vitaminc_protected::Protected::new(plaintext),
            &column().into_aad(),
        )
        .expect("seals");
        let mut log = Vec::new();
        assert!(
            matches!(
                decrypt_into(&Mock, Node::Single(leaf), column(), Record(&mut log)),
                Err(DecryptError::Malformed)
            ),
            "an out-of-range scale was read"
        );
    }

    /// The old binding, `(old domain, base, tag)`, is a different context,
    /// so nothing sealed under it opens under the new one.
    #[test]
    fn a_ciphertext_bound_under_the_old_label_does_not_open() {
        let old = || {
            ContextPiece::List(vec![
                ContextPiece::Bytes(Cow::Borrowed(b"vitaminc/aead-value/leaf-type/v1")),
                "schema".into_context(),
                ContextPiece::U8(crate::tags::INT32),
            ])
        };
        let sealed = encrypt(19_000i32, &Mock, old()).expect("seals");
        assert!(
            matches!(
                opens::<i32>(sealed, int()),
                Err(DecryptError::Cipher(Refused))
            ),
            "a v1-bound ciphertext opened under v2"
        );
    }
}
