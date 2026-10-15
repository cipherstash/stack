//! Classification of the derive input into the wire shape it maps onto.

use std::collections::HashMap;

use proc_macro2::Span;
use syn::{Data, DeriveInput, Fields, Ident, Member, Result, Type};

use crate::attrs::FieldAttrs;

/// One field of a struct.
#[cfg_attr(test, derive(Debug))]
pub(crate) struct FieldInfo {
    /// Map key this field is stored under — the field name, the decimal index
    /// for a tuple struct, or the `#[aead(rename = "...")]` override.
    pub(crate) key: String,
    /// How the field is reached on `self` (`self.name` or `self.0`).
    pub(crate) member: Member,
    /// A local binding name, unique per field, for use in generated bodies.
    /// Derived from the position so tuple fields get a legal identifier.
    pub(crate) local: Ident,
    pub(crate) ty: Type,
    /// `#[aead(passthrough)]`: stored in the clear, never encrypted and never
    /// authenticated.
    pub(crate) passthrough: bool,
    /// `#[aead(skip)]`: not in the ciphertext at all; `Default` on decrypt.
    pub(crate) skip: bool,
    /// `#[aead(take)]`: taken with `core::mem::take` rather than moved.
    pub(crate) take: bool,
    /// Whether [`key`](FieldInfo::key) came from `#[aead(rename = "...")]`
    /// rather than the field's own name. Only the newtype guard needs this —
    /// everywhere else the rename has already been folded into `key`.
    pub(crate) renamed: bool,
}

impl FieldInfo {
    /// Whether the field has an entry in the map at all.
    pub(crate) fn stored(&self) -> bool {
        !self.skip
    }

    /// Whether the field's entry is sealed.
    pub(crate) fn sealed(&self) -> bool {
        self.stored() && !self.passthrough
    }
}

/// One variant of a fieldless enum.
#[cfg_attr(test, derive(Debug))]
pub(crate) struct VariantInfo {
    pub(crate) ident: Ident,
    /// The discriminant the variant is stored as: its explicit `= n`, or
    /// one more than the previous variant's, as Rust assigns them.
    pub(crate) discriminant: u32,
}

/// The wire shape a type maps onto — see the crate docs.
#[cfg_attr(test, derive(Debug))]
pub(crate) enum Shape {
    /// Exactly one unnamed field: transparent, delegating to the inner type.
    /// Boxed to keep the variant from dominating the enum's size.
    Newtype(Box<FieldInfo>),
    /// One or more fields, encoded as a map keyed by [`FieldInfo::key`].
    Map(Vec<FieldInfo>),
    /// No fields at all: the authenticated empty-map marker.
    Empty,
    /// A fieldless enum: one fixed-width int leaf holding the variant's
    /// discriminant. Only the sink dialect accepts it.
    Enum(Vec<VariantInfo>),
}

impl Shape {
    pub(crate) fn parse(input: &DeriveInput) -> Result<Self> {
        let data = match &input.data {
            Data::Struct(data) => data,
            Data::Enum(data) => return parse_enum(data, input),
            Data::Union(_) => {
                return Err(syn::Error::new_spanned(
                    &input.ident,
                    "cannot be derived for unions",
                ))
            }
        };

        let named = matches!(data.fields, Fields::Named(_));
        let fields = collect(&data.fields)?;
        reject_conflicting_attrs(&fields, input)?;

        // A newtype is transparent; a *named* one-field struct is not, since
        // its field name is a meaningful part of the wire contract.
        if !named && fields.len() == 1 {
            let mut fields = fields;
            let field = fields.remove(0);
            reject_newtype_field_attrs(&field, input)?;
            return Ok(Shape::Newtype(Box::new(field)));
        }

        if fields.is_empty() {
            return Ok(Shape::Empty);
        }

        reject_duplicate_keys(&fields, input)?;
        reject_nothing_sealed(&fields, input)?;
        Ok(Shape::Map(fields))
    }
}

fn collect(fields: &Fields) -> Result<Vec<FieldInfo>> {
    fields
        .iter()
        .enumerate()
        .map(|(index, field)| {
            let attrs = FieldAttrs::parse(&field.attrs)?;
            let renamed = attrs.rename.is_some();
            let (key, member) = match &field.ident {
                Some(ident) => (ident.to_string(), Member::Named(ident.clone())),
                None => (index.to_string(), Member::Unnamed(syn::Index::from(index))),
            };
            Ok(FieldInfo {
                key: attrs.rename.unwrap_or(key),
                member,
                local: Ident::new(&format!("__field_{index}"), Span::call_site()),
                ty: field.ty.clone(),
                passthrough: attrs.passthrough,
                skip: attrs.skip,
                take: attrs.take,
                renamed,
            })
        })
        .collect()
}

/// A fieldless enum is one fixed-width int leaf holding the variant's
/// discriminant, so every variant seals to a leaf of the same length and
/// the ciphertext gives nothing away. The discriminants are the ones Rust
/// assigns: an explicit `= n`, or one more than the previous variant's. A
/// variant with fields has no such encoding: its payload would need a
/// layout and a per-variant AAD of its own.
fn parse_enum(data: &syn::DataEnum, input: &DeriveInput) -> Result<Shape> {
    if data.variants.is_empty() {
        return Err(syn::Error::new_spanned(
            &input.ident,
            "cannot be derived for an enum with no variants: there is no value to seal",
        ));
    }
    let mut next = Some(0u32);
    let mut variants = Vec::with_capacity(data.variants.len());
    for variant in &data.variants {
        if !matches!(variant.fields, Fields::Unit) {
            return Err(syn::Error::new_spanned(
                &variant.ident,
                "only fieldless enums can be derived: a variant with fields has no \
                 agreed layout for its payload. Model it as a struct with an enum \
                 discriminant and `Option` fields instead.",
            ));
        }
        // A variant is stored as its discriminant, so there is nothing for
        // an attribute to rename or skip.
        if let Some(attr) = variant.attrs.iter().find(|a| a.path().is_ident("aead")) {
            return Err(syn::Error::new_spanned(
                attr,
                "variants take no `#[aead(...)]` attributes: a variant is stored as its \
                 discriminant, so give it an explicit `= n` to pin the value instead",
            ));
        }
        let discriminant = variant_discriminant(variant, next)?;
        next = discriminant.checked_add(1);
        variants.push(VariantInfo {
            ident: variant.ident.clone(),
            discriminant,
        });
    }
    let mut seen: HashMap<u32, ()> = HashMap::with_capacity(variants.len());
    for variant in &variants {
        if seen.insert(variant.discriminant, ()).is_some() {
            return Err(syn::Error::new_spanned(
                &variant.ident,
                format!(
                    "duplicate discriminant `{}`: two variants would be stored as the same value",
                    variant.discriminant
                ),
            ));
        }
    }
    Ok(Shape::Enum(variants))
}

/// A variant's discriminant: its explicit `= n`, or else the one after the
/// previous variant's. `next` is `None` once the previous variant was
/// `u32::MAX`, which is refused only if a variant actually needs the value
/// after it, so a last variant of `= 4294967295` is fine.
fn variant_discriminant(variant: &syn::Variant, next: Option<u32>) -> Result<u32> {
    match &variant.discriminant {
        Some((_, expr)) => explicit_discriminant(expr),
        None => next.ok_or_else(|| {
            syn::Error::new_spanned(
                &variant.ident,
                "this variant's implicit discriminant does not fit in 32 bits",
            )
        }),
    }
}

/// The wire holds a `u32`, so an explicit discriminant has to be an
/// unsigned integer literal that fits one.
fn explicit_discriminant(expr: &syn::Expr) -> Result<u32> {
    if let syn::Expr::Lit(syn::ExprLit {
        lit: syn::Lit::Int(int),
        ..
    }) = expr
    {
        if let Ok(value) = int.base10_parse::<u32>() {
            return Ok(value);
        }
    }
    Err(syn::Error::new_spanned(
        expr,
        "an explicit discriminant must be an unsigned integer literal that fits in 32 bits, \
         since that is the width the variant is sealed at",
    ))
}

/// `skip` and `take` mean nothing to the `Encrypt`/`Decrypt` derives, and
/// silently ignoring either would leave the author believing a field was
/// left out, or a `Drop` type handled, when it was not.
/// A skipped field has no entry to pass through, and a passthrough entry
/// is never taken out of `self`, so these combinations describe nothing.
fn reject_conflicting_attrs(fields: &[FieldInfo], input: &DeriveInput) -> Result<()> {
    for field in fields {
        if field.skip && (field.passthrough || field.take) {
            return Err(syn::Error::new_spanned(
                &input.ident,
                format!(
                    "field `{}` is `#[aead(skip)]`, so it has no entry to pass through or \
                     take: remove the other attribute",
                    field.key
                ),
            ));
        }
    }
    Ok(())
}

/// Two fields sharing a map key would silently overwrite one another on
/// encrypt (and the decipher rejects duplicate keys anyway), so catch it here
/// where the error can point at the offending `rename`.
fn reject_duplicate_keys(fields: &[FieldInfo], input: &DeriveInput) -> Result<()> {
    let mut seen: HashMap<&str, ()> = HashMap::with_capacity(fields.len());
    for field in fields.iter().filter(|field| field.stored()) {
        if seen.insert(field.key.as_str(), ()).is_some() {
            return Err(syn::Error::new_spanned(
                &input.ident,
                format!(
                    "duplicate map key `{}`: two fields would be encrypted under the same key",
                    field.key
                ),
            ));
        }
    }
    Ok(())
}

/// A newtype is transparent: it encrypts exactly as its inner type, opening no
/// map and producing no entry. Every field attribute that describes a map
/// entry has nothing to describe on one.
///
/// They are rejected rather than ignored, because ignoring them is silent and
/// the author's intent was the opposite of what they would get. `rename` names
/// a map key that is never written, so a value the author believes is
/// key-bound has no key binding at all. `passthrough` asks for a cleartext
/// entry that does not exist; honouring it instead would mean the whole value
/// travels unencrypted, leaving a container with no tag — the same thing the
/// map sink refuses to seal. `skip` would leave nothing at all. `take` is
/// about how the value leaves `self`, not about an entry, so it is allowed.
fn reject_newtype_field_attrs(field: &FieldInfo, input: &DeriveInput) -> Result<()> {
    if field.renamed {
        return Err(syn::Error::new_spanned(
            &input.ident,
            "`#[aead(rename = \"...\")]` has no effect on a newtype struct: a newtype is \
             transparent, so its value is not stored under a map key at all and there is no \
             key to rename. Give the struct a named field instead.",
        ));
    }
    if field.passthrough {
        return Err(syn::Error::new_spanned(
            &input.ident,
            "`#[aead(passthrough)]` is meaningless on a newtype struct: a newtype is \
             transparent, so there is no map entry to store in the clear and nothing \
             would be encrypted at all. Give the struct a named field instead.",
        ));
    }
    if field.skip {
        return Err(syn::Error::new_spanned(
            &input.ident,
            "`#[aead(skip)]` is meaningless on a newtype struct: a newtype is transparent, \
             so skipping its only field would leave nothing to encrypt. Give the struct a \
             named field instead.",
        ));
    }
    Ok(())
}

/// A map with no sealed entries carries no tag at all — nothing
/// authenticates the map's AAD, and nothing binds the entry keys — so the
/// map sink rejects one at seal time. Catch it here, where the error names
/// the struct instead of surfacing as a runtime encrypt failure.
fn reject_nothing_sealed(fields: &[FieldInfo], input: &DeriveInput) -> Result<()> {
    if !fields.iter().any(FieldInfo::sealed) {
        return Err(syn::Error::new_spanned(
            &input.ident,
            "no field would be encrypted: every field is `#[aead(passthrough)]` or \
             `#[aead(skip)]`, so the ciphertext would carry no tag — neither the associated \
             data nor the entry keys would be authenticated. Encrypt at least one field, or \
             do not derive for this struct at all.",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use syn::parse_quote;

    fn sink(input: &DeriveInput) -> Result<Shape> {
        Shape::parse(input)
    }

    /// A fieldless enum is one int leaf, so the sink derives accept it,
    /// with the discriminants Rust would assign.
    #[test]
    fn fieldless_enums_are_accepted_by_the_sink_derives() {
        let input: DeriveInput = parse_quote! {
            enum Status {
                Active,
                Suspended = 5,
                Closed,
                Last = 4294967295,
            }
        };
        match sink(&input).expect("fieldless enum") {
            Shape::Enum(variants) => {
                assert_eq!(variants[0].discriminant, 0);
                assert_eq!(variants[1].discriminant, 5);
                assert_eq!(variants[2].discriminant, 6);
                // `u32::MAX` fits; only a variant after it would not.
                assert_eq!(variants[3].discriminant, u32::MAX);
            }
            other => panic!("expected an enum shape, got {other:?}"),
        }
    }

    /// The wire holds a `u32`, so a discriminant outside that, or one that
    /// is not a literal, is refused with a message that says why.
    #[test]
    fn a_discriminant_the_wire_cannot_hold_is_rejected() {
        for input in [
            parse_quote! {
                enum Wide {
                    A = 4294967296,
                }
            },
            parse_quote! {
                enum Negative {
                    A = -1,
                }
            },
            parse_quote! {
                enum Computed {
                    A = 1 + 1,
                }
            },
        ] {
            let input: DeriveInput = input;
            let err = sink(&input).expect_err("should be rejected");
            assert!(err.to_string().contains("unsigned integer literal"));
        }
        let input: DeriveInput = parse_quote! {
            enum Overflow {
                A = 4294967295,
                B,
            }
        };
        assert!(sink(&input)
            .expect_err("overflow")
            .to_string()
            .contains("does not fit"));
    }

    #[test]
    fn variants_take_no_attributes() {
        let input: DeriveInput = parse_quote! {
            enum Status {
                #[aead(rename = "on")]
                Active,
            }
        };
        let err = sink(&input).expect_err("attribute should be rejected");
        assert!(err.to_string().contains("variants take no"));
    }

    /// A variant with fields has no agreed payload layout, so the error
    /// has to say that the enum itself is not the problem.
    #[test]
    fn enums_with_data_are_rejected_by_the_sink_derives() {
        let input: DeriveInput = parse_quote! {
            enum Choice {
                A(String),
                B,
            }
        };
        let err = sink(&input).expect_err("data enum should be rejected");
        assert!(err.to_string().contains("only fieldless enums"));
    }

    #[test]
    fn empty_enums_and_duplicate_discriminants_are_rejected() {
        let input: DeriveInput = parse_quote! {
            enum Never {}
        };
        assert!(sink(&input)
            .expect_err("empty enum")
            .to_string()
            .contains("no variants"));
        let input: DeriveInput = parse_quote! {
            enum Clash {
                A = 1,
                B = 0,
                C,
            }
        };
        assert!(sink(&input)
            .expect_err("duplicate discriminant")
            .to_string()
            .contains("duplicate discriminant `1`"));
    }

    #[test]
    fn unions_are_rejected() {
        let input: DeriveInput = parse_quote! {
            union Raw {
                a: u32,
                b: u32,
            }
        };
        assert!(sink(&input).is_err());
        assert!(sink(&input).is_err());
    }

    /// Two fields renamed onto one key would overwrite each other on encrypt
    /// and be rejected as duplicates on decrypt; catch it at compile time.
    #[test]
    fn duplicate_keys_are_rejected() {
        let input: DeriveInput = parse_quote! {
            struct Clash {
                a: String,
                #[aead(rename = "a")]
                b: String,
            }
        };
        let err = sink(&input).expect_err("duplicate key should be rejected");
        assert!(err.to_string().contains("duplicate map key `a`"));
    }

    /// A skipped field has no key, so it cannot clash with one that does.
    #[test]
    fn a_skipped_field_does_not_clash_on_its_key() {
        let input: DeriveInput = parse_quote! {
            struct Row {
                a: String,
                #[aead(skip)]
                #[aead(rename = "a")]
                b: String,
            }
        };
        assert!(matches!(sink(&input), Ok(Shape::Map(_))));
    }

    /// A map with no sealed entries carries no tag at all, and the map sink
    /// rejects one at seal time — so catch it at compile time.
    #[test]
    fn a_struct_with_nothing_sealed_is_rejected() {
        let input: DeriveInput = parse_quote! {
            struct Row {
                #[aead(passthrough)]
                id: i64,
                #[aead(passthrough)]
                tenant: String,
            }
        };
        let err = sink(&input).expect_err("all-passthrough struct should be rejected");
        assert!(err.to_string().contains("no field would be encrypted"));
        let input: DeriveInput = parse_quote! {
            struct Row {
                #[aead(passthrough)]
                id: i64,
                #[aead(skip)]
                tenant: String,
            }
        };
        let err = sink(&input).expect_err("nothing-sealed struct should be rejected");
        assert!(err.to_string().contains("no field would be encrypted"));
    }

    #[test]
    fn skip_cannot_be_combined_with_passthrough_or_take() {
        for other in ["passthrough", "take"] {
            let other: syn::Meta = syn::parse_str(other).expect("meta");
            let input: DeriveInput = parse_quote! {
                struct Row {
                    #[aead(skip, #other)]
                    a: String,
                    b: String,
                }
            };
            let err = sink(&input).expect_err("conflict should be rejected");
            assert!(err
                .to_string()
                .contains("has no entry to pass through or take"));
        }
    }

    /// A newtype's value is not stored under a map key, so a `rename` names a
    /// key that is never written. Ignoring it would leave the author believing
    /// the value is key-bound when nothing binds it at all.
    #[test]
    fn rename_on_a_newtype_is_rejected() {
        let input: DeriveInput = parse_quote!(
            struct Token(#[aead(rename = "token")] String);
        );
        let err = sink(&input).expect_err("renamed newtype should be rejected");
        assert!(err.to_string().contains("no effect on a newtype"));
    }

    /// A newtype is transparent, so there is no map entry for a passthrough to
    /// occupy. Silently ignoring the attribute would leave the author believing
    /// a field is stored in the clear when the whole value is encrypted.
    #[test]
    fn passthrough_on_a_newtype_is_rejected() {
        let input: DeriveInput = parse_quote!(
            struct Wrapper(#[aead(passthrough)] String);
        );
        let err = sink(&input).expect_err("passthrough newtype should be rejected");
        assert!(err.to_string().contains("meaningless on a newtype"));
    }

    #[test]
    fn skip_on_a_newtype_is_rejected_but_take_is_not() {
        let input: DeriveInput = parse_quote!(
            struct Wrapper(#[aead(skip)] String);
        );
        let err = sink(&input).expect_err("skipped newtype should be rejected");
        assert!(err.to_string().contains("meaningless on a newtype"));
        let input: DeriveInput = parse_quote!(
            struct Wrapper(#[aead(take)] String);
        );
        match sink(&input).expect("taken newtype") {
            Shape::Newtype(field) => assert!(field.take),
            other => panic!("expected a newtype, got {other:?}"),
        }
    }

    /// A mixed struct is the shape the attribute exists for: some columns in
    /// the clear, at least one encrypted.
    #[test]
    fn a_mixed_struct_records_which_fields_are_passthrough() {
        let input: DeriveInput = parse_quote! {
            struct Row {
                #[aead(passthrough)]
                id: i64,
                ssn: String,
            }
        };
        match sink(&input) {
            Ok(Shape::Map(fields)) => {
                assert!(fields[0].passthrough);
                assert!(!fields[1].passthrough);
            }
            _ => panic!("expected a map shape"),
        }
    }

    #[test]
    fn single_unnamed_field_is_a_transparent_newtype() {
        let input: DeriveInput = parse_quote!(
            struct Wrapper(String);
        );
        assert!(matches!(sink(&input), Ok(Shape::Newtype(_))));
    }

    /// A *named* single-field struct is not transparent: its field name is
    /// part of the wire contract.
    #[test]
    fn single_named_field_is_a_map() {
        let input: DeriveInput = parse_quote! {
            struct Wrapper {
                inner: String,
            }
        };
        match sink(&input) {
            Ok(Shape::Map(fields)) => assert_eq!(fields[0].key, "inner"),
            _ => panic!("expected a map shape"),
        }
    }

    #[test]
    fn tuple_fields_are_keyed_by_index() {
        let input: DeriveInput = parse_quote!(
            struct Pair(String, u32);
        );
        match sink(&input) {
            Ok(Shape::Map(fields)) => {
                assert_eq!(fields[0].key, "0");
                assert_eq!(fields[1].key, "1");
            }
            _ => panic!("expected a map shape"),
        }
    }

    #[test]
    fn field_less_structs_are_empty() {
        let inputs: [DeriveInput; 3] = [
            parse_quote!(
                struct Unit;
            ),
            parse_quote!(
                struct Braced {}
            ),
            parse_quote!(
                struct Parens();
            ),
        ];
        for input in inputs {
            assert!(matches!(sink(&input), Ok(Shape::Empty)));
            assert!(matches!(sink(&input), Ok(Shape::Empty)));
        }
    }
}
