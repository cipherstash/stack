//! Classification of the derive input into the record it describes.

use proc_macro2::Span;
use syn::{Data, DeriveInput, Expr, Fields, Ident, LitStr, Member, Path, Result, Type};

use crate::attrs::{ContainerAttrs, FieldAttrs};

/// One field of a record.
#[cfg_attr(test, derive(Debug))]
pub(crate) struct Field {
    /// How the field is reached (`name` or `0`); usable in a struct literal
    /// either way (`Self { 0: value }` is legal Rust).
    pub(crate) member: Member,
    /// A local binding name, unique per field, for the generated bodies.
    pub(crate) local: Ident,
    pub(crate) ty: Type,
    pub(crate) kind: Kind,
    /// `#[stack_encrypt(decrypt)]`: decryption opens this field.
    pub(crate) decrypt: bool,
}

/// How a field gets its value when the record is encrypted.
#[cfg_attr(test, derive(Debug))]
pub(crate) enum Kind {
    /// Derived from the source through the field type's own `EncryptFrom`.
    Derived {
        /// `#[stack_encrypt(context = "...")]`: this field's context, overriding
        /// the record's.
        context: Option<LitStr>,
        /// `#[stack_encrypt(from = field)]`: derived from one field of the
        /// plaintext rather than the whole plaintext.
        from: Option<Ident>,
    },
    /// Not derived: `Default::default()` or the given expression.
    Default(Option<Expr>),
}

impl Field {
    pub(crate) fn is_derived(&self) -> bool {
        matches!(self.kind, Kind::Derived { .. })
    }

    /// The `from` field, if this is a derived field with one.
    pub(crate) fn from(&self) -> Option<&Ident> {
        match &self.kind {
            Kind::Derived { from, .. } => from.as_ref(),
            Kind::Default(_) => None,
        }
    }

    /// The literal context, if this is a derived field with one.
    pub(crate) fn context(&self) -> Option<&LitStr> {
        match &self.kind {
            Kind::Derived { context, .. } => context.as_ref(),
            Kind::Default(_) => None,
        }
    }
}

/// The record a derive input describes.
#[cfg_attr(test, derive(Debug))]
pub(crate) struct Record {
    pub(crate) krate: Path,
    /// The plaintext types, one impl each; empty means one impl generic over
    /// the plaintext.
    pub(crate) plaintexts: Vec<Type>,
    pub(crate) fields: Vec<Field>,
}

impl Record {
    pub(crate) fn parse(input: &DeriveInput) -> Result<Self> {
        let attrs = ContainerAttrs::parse(&input.attrs)?;

        let data = match &input.data {
            Data::Struct(data) => data,
            Data::Enum(_) => return Err(syn::Error::new_spanned(
                &input.ident,
                "EncryptFrom/DecryptInto cannot be derived for enums: a record is a fixed set of \
                     fields derived from one source, and a variant choice has no field to be \
                     derived into. Model the choice explicitly instead, e.g. as a struct of \
                     `Option` fields.",
            )),
            Data::Union(_) => {
                return Err(syn::Error::new_spanned(
                    &input.ident,
                    "EncryptFrom/DecryptInto cannot be derived for unions",
                ))
            }
        };

        let fields = collect(&data.fields)?;

        if !fields.iter().any(Field::is_derived) {
            return Err(syn::Error::new_spanned(
                &input.ident,
                "nothing to derive: a record needs at least one field that is not `default`",
            ));
        }

        if attrs.plaintexts.is_empty() {
            if let Some(field) = fields.iter().find(|f| f.from().is_some()) {
                return Err(syn::Error::new(
                    field.from().map_or_else(Span::call_site, Ident::span),
                    "`from = ..` reaches into a field of the plaintext, so the plaintext type must \
                     be named: add `#[stack_encrypt(plaintext = ..)]` to the struct",
                ));
            }
        }

        Ok(Self {
            krate: attrs.krate,
            plaintexts: attrs.plaintexts,
            fields,
        })
    }
}

fn collect(fields: &Fields) -> Result<Vec<Field>> {
    fields
        .iter()
        .enumerate()
        .map(|(index, field)| {
            let attrs = FieldAttrs::parse(&field.attrs)?;
            let member = match &field.ident {
                Some(ident) => Member::Named(ident.clone()),
                None => Member::Unnamed(syn::Index::from(index)),
            };
            let kind = match attrs.default {
                Some(default) => {
                    if attrs.context.is_some() || attrs.from.is_some() || attrs.decrypt {
                        return Err(syn::Error::new_spanned(
                            &field.ty,
                            "a `default` field is not derived from the source, so `context`, \
                             `from` and `decrypt` do not apply to it",
                        ));
                    }
                    Kind::Default(default)
                }
                None => Kind::Derived {
                    context: attrs.context,
                    from: attrs.from,
                },
            };
            Ok(Field {
                member,
                local: Ident::new(&format!("__field_{index}"), Span::call_site()),
                ty: field.ty.clone(),
                kind,
                decrypt: attrs.decrypt,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use syn::parse_quote;

    fn parse(input: DeriveInput) -> Result<Record> {
        Record::parse(&input)
    }

    #[test]
    fn enums_are_rejected() {
        let err = parse(parse_quote! {
            enum Choice { A(String), B(u32) }
        })
        .unwrap_err();
        assert!(err.to_string().contains("cannot be derived for enums"));
    }

    #[test]
    fn all_default_is_rejected() {
        let err = parse(parse_quote! {
            struct Empty {
                #[stack_encrypt(default)]
                v: u8,
            }
        })
        .unwrap_err();
        assert!(err.to_string().contains("nothing to derive"));
    }

    #[test]
    fn from_needs_a_named_plaintext() {
        let err = parse(parse_quote! {
            struct Row {
                #[stack_encrypt(from = age)]
                age: EncryptedAge,
            }
        })
        .unwrap_err();
        assert!(err.to_string().contains("plaintext type must be named"));
    }

    #[test]
    fn default_excludes_the_derived_attributes() {
        let err = parse(parse_quote! {
            struct Rec {
                c: StackCipherText,
                #[stack_encrypt(default, context = "x")]
                v: u8,
            }
        })
        .unwrap_err();
        assert!(err.to_string().contains("`default` field is not derived"));
    }

    #[test]
    fn unknown_attributes_are_rejected() {
        let err = parse(parse_quote! {
            struct Rec {
                #[stack_encrypt(rename = "x")]
                c: StackCipherText,
            }
        })
        .unwrap_err();
        assert!(err.to_string().contains("unsupported field attribute"));

        let err = parse(parse_quote! {
            #[stack_encrypt(source = i32)]
            struct Rec {
                c: StackCipherText,
            }
        })
        .unwrap_err();
        assert!(err.to_string().contains("unsupported container attribute"));
    }

    #[test]
    fn fields_classify() {
        let record = parse(parse_quote! {
            #[stack_encrypt(plaintext = User, plaintext = Admin)]
            struct Row {
                #[stack_encrypt(from = age, context = "users/age", decrypt)]
                age: EncryptedAge,
                whole: RowTerm,
                #[stack_encrypt(default = SchemaVersion::V3)]
                v: SchemaVersion,
            }
        })
        .unwrap();
        assert_eq!(record.plaintexts.len(), 2);
        assert_eq!(record.fields.len(), 3);
        assert_eq!(record.fields[0].from().unwrap(), "age");
        assert_eq!(record.fields[0].context().unwrap().value(), "users/age");
        assert!(record.fields[0].decrypt);
        assert!(record.fields[1].is_derived());
        assert!(record.fields[1].from().is_none());
        assert!(!record.fields[2].is_derived());
    }
}
