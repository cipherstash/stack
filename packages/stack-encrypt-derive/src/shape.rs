//! Classification of the derive input into the record it describes.

use proc_macro2::{Span, TokenStream};
use quote::quote;
use syn::spanned::Spanned;
use syn::{
    parse_quote, Data, DeriveInput, Expr, Fields, Generics, Ident, LitStr, Member, Path, Result,
    Type,
};

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
    /// `#[stash(decrypt)]`: decryption opens this field.
    pub(crate) decrypt: bool,
}

/// How a field gets its value when the record is encrypted.
#[cfg_attr(test, derive(Debug))]
pub(crate) enum Kind {
    /// Derived from the source through the field type's own `EncryptFrom`.
    Derived {
        /// `#[stash(context = "...")]`: this field's context, overriding
        /// the record's.
        context: Option<LitStr>,
        /// `#[stash(from = field)]` / `from = 0`: derived from one
        /// field of the plaintext rather than the whole plaintext.
        from: Option<Member>,
    },
    /// Not derived: `Default::default()` or the given expression.
    Default(Option<Expr>),
}

impl Field {
    pub(crate) fn is_derived(&self) -> bool {
        matches!(self.kind, Kind::Derived { .. })
    }

    /// The `from` member, if this is a derived field with one.
    pub(crate) fn from(&self) -> Option<&Member> {
        match &self.kind {
            Kind::Derived { from, .. } => from.as_ref(),
            Kind::Default(_) => None,
        }
    }

    /// How this derived field gets its context — the one classification both
    /// derives project their where clauses and bodies from.
    ///
    /// A `from` field with no literal is [`FieldContext::Unit`], never the
    /// caller's: it reaches into one field of the plaintext, and its type
    /// says what that field needs — a leaf refuses `()` (the derive cannot
    /// name the plaintext field's type in a where clause, so the obligation
    /// is checked in the body and reported at the field type), and a nested
    /// row carrying its own contexts accepts nothing else. Handing such a
    /// field the caller's context instead would encrypt every column of the
    /// row under one context, which is the cross-column transplant the
    /// per-field contexts exist to prevent.
    ///
    /// Only called for derived fields: a `default` field is not derived from
    /// the source and is never handed a context at all.
    pub(crate) fn field_context(&self) -> FieldContext<'_> {
        match &self.kind {
            Kind::Derived {
                context: Some(literal),
                ..
            } => FieldContext::Literal(literal),
            Kind::Derived {
                context: None,
                from: Some(_),
            } => FieldContext::Unit,
            Kind::Derived {
                context: None,
                from: None,
            } => FieldContext::Caller,
            Kind::Default(_) => unreachable!("a `default` field has no context"),
        }
    }

    /// Is this field derived under the context the caller passes for the
    /// record? Only a field derived from the whole plaintext with no literal
    /// of its own is; see [`push_context_generics`].
    pub(crate) fn takes_callers_context(&self) -> bool {
        self.is_derived() && matches!(self.field_context(), FieldContext::Caller)
    }
}

/// Where a derived field's context comes from: a literal of its own, `()`
/// for a `from` field with no literal, or the caller's. See
/// [`Field::field_context`] for why a `from` field never gets the caller's.
#[cfg_attr(test, derive(Debug))]
pub(crate) enum FieldContext<'a> {
    /// `#[stash(context = "...")]`.
    Literal(&'a LitStr),
    /// A `from` field with no literal: handed `()`, and its type decides
    /// whether that will do.
    Unit,
    /// The context the caller passes for the record, as the impl's `__Ctx`.
    Caller,
}

impl FieldContext<'_> {
    /// The context type as it appears in a where clause: the literal's,
    /// `()`, or the impl's `__Ctx`.
    pub(crate) fn ty(&self) -> Type {
        match self {
            FieldContext::Literal(_) => parse_quote!(&'static str),
            FieldContext::Unit => parse_quote!(()),
            FieldContext::Caller => parse_quote!(__Ctx),
        }
    }

    /// The context expression the field is handed when it is not the
    /// caller's; `None` for a field that takes the caller's, whose
    /// expression is the call site's to choose (move, clone, or clone
    /// through a reference).
    pub(crate) fn own_expr(&self) -> Option<TokenStream> {
        match self {
            FieldContext::Literal(literal) => Some(quote!(#literal)),
            FieldContext::Unit => Some(quote!(())),
            FieldContext::Caller => None,
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
    /// The fields that are derived from the plaintext, in declaration order.
    pub(crate) fn derived(&self) -> Vec<&Field> {
        self.fields.iter().filter(|f| f.is_derived()).collect()
    }

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
                    field.from().map_or_else(Span::call_site, Spanned::span),
                    "`from = ..` reaches into a field of the plaintext, so the plaintext type must \
                     be named: add `#[stash(plaintext = ..)]` to the struct",
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

/// The demand a derive places on the impl's context parameter, beyond what
/// the field bounds already say.
pub(crate) enum CallerContext<'a> {
    /// Encrypt: `Clone` is all the generated body itself needs (the context
    /// fans out to every field); everything else — supplied, convertible —
    /// is inherited through the field bounds, because every encrypt leaf
    /// states its own demand.
    Encrypt,
    /// Decrypt: `DecryptContext` — convertible to the AAD the value was
    /// encrypted under. A term field's `DecryptField` accepts *any* context
    /// (it opens nothing), so field bounds alone would let a record whose
    /// ciphertext field carries a literal accept — and silently discard —
    /// any `Clone` value as its decrypt context.
    Decrypt(&'a Path),
}

/// Adds the impl's context parameter, if `fields` give it a use, and returns
/// the type the impl is for.
///
/// A field with a context of its own ([`FieldContext::own_expr`]) never sees
/// the caller's. A record whose fields all have one — every row does — is
/// therefore encrypted with no context at all, and its impl is for `()`
/// exactly: `row.encrypt_into(&cipher)` compiles and
/// `encrypt_into_with_context` does not, since the context would go nowhere.
/// Otherwise the impl is generic over `__Ctx`, cloned to each field that
/// takes it, bounded by what `bound` says the direction demands.
pub(crate) fn push_context_generics(
    generics: &mut Generics,
    bound: CallerContext<'_>,
    fields: &[&Field],
) -> Type {
    if !fields.iter().any(|f| f.takes_callers_context()) {
        return parse_quote!(());
    }
    generics.params.push(parse_quote!(__Ctx));
    let predicates = &mut generics.make_where_clause().predicates;
    match bound {
        CallerContext::Encrypt => {
            predicates.push(parse_quote!(__Ctx: ::core::clone::Clone));
        }
        CallerContext::Decrypt(krate) => {
            predicates.push(parse_quote!(__Ctx: #krate::target::DecryptContext<'__ctx>));
            // A lifetime parameter must precede the type parameters.
            generics.params.insert(0, parse_quote!('__ctx));
        }
    }
    parse_quote!(__Ctx)
}

/// `impl #trait_path for Record` around `content` — the scaffolding both
/// derives share. Splits the record's own generics (for the type position)
/// and the augmented `generics` (for the impl and its where clause) here, so
/// each derive hands over one `Generics` instead of three projections of it.
pub(crate) fn trait_impl(
    input: &DeriveInput,
    generics: &Generics,
    trait_path: TokenStream,
    content: TokenStream,
) -> TokenStream {
    let name = &input.ident;
    let (_, ty_generics, _) = input.generics.split_for_impl();
    let (impl_generics, _, where_clause) = generics.split_for_impl();
    quote! {
        #[automatically_derived]
        impl #impl_generics #trait_path for #name #ty_generics #where_clause {
            #content
        }
    }
}

/// The pendings of `fields`, zipped into one and mapped into `build` (a
/// struct literal over the fields' locals). Nothing is awaited, so the record
/// settles as one batched call.
///
/// `call(field, context)` renders one field's pending under `context`. The
/// record's context (`__context`) goes to every field without a context of
/// its own; the last such field takes it by move, the rest clone it.
pub(crate) fn zip_fields(
    fields: &[&Field],
    mut call: impl FnMut(&Field, TokenStream) -> TokenStream,
    build: TokenStream,
) -> TokenStream {
    let mut remaining = fields.iter().filter(|f| f.takes_callers_context()).count();

    let mut chain = TokenStream::new();
    let mut pattern = TokenStream::new();
    for (index, field) in fields.iter().enumerate() {
        let context = match field.field_context().own_expr() {
            Some(own) => own,
            None => {
                remaining -= 1;
                if remaining == 0 {
                    quote!(__context)
                } else {
                    quote!(::core::clone::Clone::clone(&__context))
                }
            }
        };
        let call = call(field, context);
        let local = &field.local;
        if index == 0 {
            chain = call;
            pattern = quote!(#local);
        } else {
            chain = quote!(#chain.zip(#call));
            pattern = quote!((#pattern, #local));
        }
    }

    quote!(#chain.map(|#pattern| #build))
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
                #[stash(default)]
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
                #[stash(from = age)]
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
                #[stash(default, context = "x")]
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
                #[stash(rename = "x")]
                c: StackCipherText,
            }
        })
        .unwrap_err();
        assert!(err.to_string().contains("unsupported field attribute"));

        let err = parse(parse_quote! {
            #[stash(source = i32)]
            struct Rec {
                c: StackCipherText,
            }
        })
        .unwrap_err();
        assert!(err.to_string().contains("unsupported container attribute"));
    }

    #[test]
    fn repeated_singleton_attributes_are_rejected() {
        // A silently-winning second `from` would encrypt the wrong (same-
        // typed) plaintext field — the crossed-field failure the derive
        // exists to prevent — so every singular attribute rejects a repeat.
        let err = parse(parse_quote! {
            #[stash(plaintext = User)]
            struct Rec {
                #[stash(from = expected, from = other)]
                c: StackCipherText,
            }
        })
        .unwrap_err();
        assert!(err.to_string().contains("`from` is given twice"));

        let err = parse(parse_quote! {
            struct Rec {
                #[stash(context = "users/email", context = "users/name")]
                c: StackCipherText,
            }
        })
        .unwrap_err();
        assert!(err.to_string().contains("`context` is given twice"));

        // Also across two `#[stash(..)]` attributes on the same field.
        let err = parse(parse_quote! {
            struct Rec {
                #[stash(context = "users/email")]
                #[stash(context = "users/name")]
                c: StackCipherText,
            }
        })
        .unwrap_err();
        assert!(err.to_string().contains("`context` is given twice"));

        let err = parse(parse_quote! {
            struct Rec {
                c: StackCipherText,
                #[stash(default, default = 3)]
                v: u8,
            }
        })
        .unwrap_err();
        assert!(err.to_string().contains("`default` is given twice"));

        let err = parse(parse_quote! {
            struct Rec {
                #[stash(decrypt, decrypt)]
                c: StackCipherText,
            }
        })
        .unwrap_err();
        assert!(err.to_string().contains("`decrypt` is given twice"));

        let err = parse(parse_quote! {
            #[stash(crate = "stack_encrypt", crate = "stack_encrypt")]
            struct Rec {
                c: StackCipherText,
            }
        })
        .unwrap_err();
        assert!(err.to_string().contains("`crate` is given twice"));
    }

    #[test]
    fn a_literal_empty_context_is_rejected() {
        let err = parse(parse_quote! {
            struct Rec {
                #[stash(context = "")]
                c: StackCipherText,
            }
        })
        .unwrap_err();
        assert!(err.to_string().contains("empty `context`"));
        assert!(err.to_string().contains("drop the attribute"));
    }

    #[test]
    fn an_empty_context_on_a_from_field_gets_from_specific_advice() {
        // "Drop the attribute" is a dead end for a `from` field — it is
        // never handed the record's context — so the advice must not offer
        // it, whichever order the attributes were written in.
        for input in [
            parse_quote! {
                #[stash(plaintext = User)]
                struct Row {
                    #[stash(from = email, context = "")]
                    email: StackCipherText,
                }
            },
            parse_quote! {
                #[stash(plaintext = User)]
                struct Row {
                    #[stash(context = "", from = email)]
                    email: StackCipherText,
                }
            },
        ] {
            let err = parse(input).unwrap_err();
            let message = err.to_string();
            assert!(message.contains("empty `context`"), "{message}");
            assert!(
                message.contains("never handed the record's context"),
                "{message}"
            );
            assert!(!message.contains("drop the attribute"), "{message}");
        }
    }

    #[test]
    fn a_reference_plaintext_is_rejected() {
        let err = parse(parse_quote! {
            #[stash(plaintext = &str)]
            struct Rec {
                c: StackCipherText,
            }
        })
        .unwrap_err();
        assert!(err.to_string().contains("must be an owned type"));
    }

    #[test]
    fn a_repeated_plaintext_is_rejected() {
        let err = parse(parse_quote! {
            #[stash(plaintext = u32, plaintext = u32)]
            struct Rec {
                c: StackCipherText,
            }
        })
        .unwrap_err();
        assert!(err.to_string().contains("listed twice"));
    }

    #[test]
    fn from_addresses_tuple_plaintexts_by_index() {
        let record = parse(parse_quote! {
            #[stash(plaintext = Pair)]
            struct Rec {
                #[stash(from = 0, context = "pair/0")]
                a: StackCipherText,
                #[stash(from = 1, context = "pair/1")]
                b: StackCipherText,
            }
        })
        .unwrap();
        assert!(matches!(record.fields[0].from(), Some(Member::Unnamed(i)) if i.index == 0));
        assert!(matches!(record.fields[1].from(), Some(Member::Unnamed(i)) if i.index == 1));
    }

    #[test]
    fn fields_classify() {
        let record = parse(parse_quote! {
            #[stash(plaintext = User, plaintext = Admin)]
            struct Row {
                #[stash(from = age, context = "users/age", decrypt)]
                age: EncryptedAge,
                whole: RowTerm,
                #[stash(default = SchemaVersion::V3)]
                v: SchemaVersion,
            }
        })
        .unwrap();
        assert_eq!(record.plaintexts.len(), 2);
        assert_eq!(record.fields.len(), 3);
        assert!(matches!(record.fields[0].from(), Some(Member::Named(name)) if name == "age"));
        assert!(matches!(
            record.fields[0].field_context(),
            FieldContext::Literal(literal) if literal.value() == "users/age"
        ));
        assert!(record.fields[0].decrypt);
        assert!(record.fields[1].is_derived());
        assert!(record.fields[1].from().is_none());
        assert!(!record.fields[2].is_derived());
    }
}
