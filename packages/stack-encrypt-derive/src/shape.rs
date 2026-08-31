//! Classification of the derive input into the record it describes.

use proc_macro2::{Span, TokenStream};
use quote::quote;
use syn::spanned::Spanned;
use syn::{
    parse_quote, parse_quote_spanned, Data, DeriveInput, Expr, Fields, Generics, Ident, LitStr,
    Member, Path, Result, Type,
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

        // `ContainerAttrs::parse` has established that `context` is present
        // exactly when `row` is.
        let fields = collect(&data.fields, attrs.context.as_ref())?;
        let plaintexts = match attrs.row {
            Some(row) => vec![row],
            None => attrs.plaintexts,
        };

        if !fields.iter().any(Field::is_derived) {
            return Err(syn::Error::new_spanned(
                &input.ident,
                "nothing to derive: a record needs at least one field that is not `default`",
            ));
        }

        if plaintexts.is_empty() {
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
            plaintexts,
            fields,
        })
    }
}

/// The demand a derive places on the impl's context parameter, beyond what
/// the field bounds already say.
pub(crate) enum CallerContext<'a> {
    /// Encrypt: `EncryptContext` — convertible to AAD and to a PRF context.
    /// The leaves in this crate state that demand through the field bounds
    /// already, but a third-party leaf generic over its context would not,
    /// and without this bound such a leaf lets `EncryptFrom::encrypt_from`
    /// accept — and silently discard — any `Clone` value as its context.
    Encrypt(&'a Path),
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
        CallerContext::Encrypt(krate) => {
            predicates.push(parse_quote!(__Ctx: #krate::target::EncryptContext<'__ctx>));
        }
        CallerContext::Decrypt(krate) => {
            predicates.push(parse_quote!(__Ctx: #krate::target::DecryptContext<'__ctx>));
        }
    }
    // A lifetime parameter must precede the type parameters.
    generics.params.insert(0, parse_quote!('__ctx));
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

/// Which trait a field bound names; the bound is otherwise identical between
/// the two derives, and built in one place so the where-clause logic that
/// carries the per-field contexts cannot diverge between them.
pub(crate) enum FieldBound {
    /// `EncryptFrom<Source, ..>` — for encrypt, on fields derived from the
    /// whole source (the caller filters; a `from` field's obligation is
    /// checked in the body instead, where the source field's type is known).
    Encrypt,
    /// `DecryptField<Plaintext, ..>` — for decrypt, on every candidate field.
    DecryptField,
}

/// `FieldTy: Trait<Target, StackCipher<__K>, Ctx>` for each of `fields`,
/// under the context it is derived or opened under — its literal's, `()`,
/// or the caller's `__Ctx`, which is how a record inherits its leaves'
/// demand for a supplied context.
pub(crate) fn push_field_bounds(
    generics: &mut Generics,
    krate: &Path,
    fields: &[&Field],
    target: &Type,
    bound: FieldBound,
) {
    let trait_name: Ident = match bound {
        FieldBound::Encrypt => parse_quote!(EncryptFrom),
        FieldBound::DecryptField => parse_quote!(DecryptField),
    };
    let predicates = &mut generics.make_where_clause().predicates;
    for field in fields {
        let ty = &field.ty;
        let context = field.field_context().ty();
        // Spanned at the field type, so a type that cannot be a field of the
        // record is reported there, not at the derive.
        predicates.push(parse_quote_spanned! {ty.span()=>
            #ty: #krate::target::#trait_name<#target, #krate::StackCipher<__K>, #context>
        });
    }
}

/// The source (or plaintext) types a derive emits one impl each for: the
/// listed ones, or — when none are listed — the given generic parameter,
/// with `true` saying it must be pushed onto the impl's generics.
pub(crate) fn impl_sources(record: &Record, generic: Ident) -> (Vec<Type>, bool) {
    if record.plaintexts.is_empty() {
        (vec![parse_quote!(#generic)], true)
    } else {
        (record.plaintexts.clone(), false)
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

/// The fields, with what a row (`row_context` is the container's `context`
/// prefix) fills in: `from` is the field's own name and `context` is
/// `"<row_context>/<from>"`, each unless the field gives its own.
/// `#[stash(nested)]` opts a field out of the inferred context — it is handed
/// `()`, which a nested row (a type carrying its own contexts) accepts and a
/// leaf refuses.
fn collect(fields: &Fields, row_context: Option<&LitStr>) -> Result<Vec<Field>> {
    fields
        .iter()
        .enumerate()
        .map(|(index, field)| {
            let attrs = FieldAttrs::parse(&field.attrs)?;
            let member = match &field.ident {
                Some(ident) => Member::Named(ident.clone()),
                None => Member::Unnamed(syn::Index::from(index)),
            };
            if attrs.nested && row_context.is_none() {
                return Err(syn::Error::new_spanned(
                    &field.ty,
                    "`nested` opts a row field out of its inferred context, so it applies only \
                     with `row = ..` on the struct; a `plaintext` record's `from` field with no \
                     `context` is already handed `()`",
                ));
            }
            let kind = match attrs.default {
                Some(default) => {
                    if attrs.context.is_some()
                        || attrs.from.is_some()
                        || attrs.decrypt
                        || attrs.nested
                    {
                        return Err(syn::Error::new_spanned(
                            &field.ty,
                            "a `default` field is not derived from the source, so `context`, \
                             `from`, `decrypt` and `nested` do not apply to it",
                        ));
                    }
                    Kind::Default(default)
                }
                None => match row_context {
                    Some(row_context) => {
                        let from = attrs.from.unwrap_or_else(|| member.clone());
                        let context = if attrs.nested {
                            // The field's type carries its own contexts; it
                            // is handed `()` (`FieldContext::Unit`).
                            None
                        } else {
                            Some(attrs.context.unwrap_or_else(|| {
                                let column = match &from {
                                    Member::Named(ident) => ident.to_string(),
                                    Member::Unnamed(index) => index.index.to_string(),
                                };
                                let prefix = row_context.value();
                                LitStr::new(&format!("{prefix}/{column}"), member.span())
                            }))
                        };
                        Kind::Derived {
                            context,
                            from: Some(from),
                        }
                    }
                    None => Kind::Derived {
                        context: attrs.context,
                        from: attrs.from,
                    },
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

    /// The field's literal context, for assertions.
    fn literal(field: &Field) -> String {
        match field.field_context() {
            FieldContext::Literal(lit) => lit.value(),
            other => panic!("expected a literal context, got {other:?}"),
        }
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
    fn a_row_fills_in_from_and_context() {
        let record = parse(parse_quote! {
            #[stash(row = crate::model::UserProfile<T>, context = "user_profiles")]
            struct EncryptedUser {
                age: EncryptedAge,
                #[stash(from = email_address)]
                email: StackCipherText,
                #[stash(context = "legacy/name")]
                name: StackCipherText,
                #[stash(nested)]
                address: EncryptedAddress,
                #[stash(default)]
                version: u8,
            }
        })
        .unwrap();
        assert_eq!(record.plaintexts.len(), 1);
        let (age, email, name, address, version) = (
            &record.fields[0],
            &record.fields[1],
            &record.fields[2],
            &record.fields[3],
            &record.fields[4],
        );
        // Own name under the container's prefix.
        assert!(matches!(age.from(), Some(Member::Named(m)) if m == "age"));
        assert_eq!(literal(age), "user_profiles/age");
        // `from` overrides the field; the context follows the plaintext field.
        assert!(matches!(email.from(), Some(Member::Named(m)) if m == "email_address"));
        assert_eq!(literal(email), "user_profiles/email_address");
        // `context` is taken verbatim.
        assert!(matches!(name.from(), Some(Member::Named(m)) if m == "name"));
        assert_eq!(literal(name), "legacy/name");
        // `nested`: no inferred context — the field is handed `()`.
        assert!(matches!(address.from(), Some(Member::Named(m)) if m == "address"));
        assert!(matches!(address.field_context(), FieldContext::Unit));
        assert!(!version.is_derived());
    }

    #[test]
    fn a_tuple_row_is_reached_and_named_by_index() {
        let record = parse(parse_quote! {
            #[stash(row = Reading, context = "readings")]
            struct EncryptedReading(EncryptedAge, StackCipherText);
        })
        .unwrap();
        assert!(matches!(record.fields[1].from(), Some(Member::Unnamed(i)) if i.index == 1));
        assert_eq!(literal(&record.fields[0]), "readings/0");
        assert_eq!(literal(&record.fields[1]), "readings/1");
    }

    #[test]
    fn a_row_requires_a_container_context() {
        // The prefix is part of the stored data's identity, so it is never
        // inferred from the Rust type's name: two types named `Account` in
        // different modules would otherwise silently share every column
        // context.
        let err = parse(parse_quote! {
            #[stash(row = User)]
            struct EncryptedUser {
                age: EncryptedAge,
            }
        })
        .unwrap_err();
        let message = err.to_string();
        assert!(message.contains("needs a `context = \"..\"`"), "{message}");
        assert!(message.contains("naming the table"), "{message}");
    }

    #[test]
    fn a_container_context_requires_a_row() {
        let err = parse(parse_quote! {
            #[stash(plaintext = User, context = "users")]
            struct Rec {
                c: StackCipherText,
            }
        })
        .unwrap_err();
        assert!(err.to_string().contains("applies only with `row = ..`"));

        let err = parse(parse_quote! {
            #[stash(context = "users")]
            struct Rec {
                c: StackCipherText,
            }
        })
        .unwrap_err();
        assert!(err.to_string().contains("applies only with `row = ..`"));
    }

    #[test]
    fn an_empty_container_context_is_rejected() {
        let err = parse(parse_quote! {
            #[stash(row = User, context = "")]
            struct EncryptedUser {
                age: EncryptedAge,
            }
        })
        .unwrap_err();
        assert!(err.to_string().contains("name the table"));
    }

    #[test]
    fn nested_applies_only_in_a_row_and_excludes_context() {
        // Outside a row it is at best redundant (`from` with no `context` is
        // already handed `()`), so it is rejected rather than ignored.
        let err = parse(parse_quote! {
            #[stash(plaintext = User)]
            struct Rec {
                #[stash(nested, from = user)]
                user: EncryptedUser,
            }
        })
        .unwrap_err();
        assert!(err.to_string().contains("applies only with `row = ..`"));

        let err = parse(parse_quote! {
            #[stash(row = Account, context = "accounts")]
            struct Rec {
                #[stash(nested, context = "accounts/user")]
                user: EncryptedUser,
            }
        })
        .unwrap_err();
        assert!(err.to_string().contains("`context` does not apply"));
    }

    #[test]
    fn row_and_plaintext_are_exclusive() {
        let err = parse(parse_quote! {
            #[stash(row = User, plaintext = User)]
            struct Rec {
                age: EncryptedAge,
            }
        })
        .unwrap_err();
        assert!(err.to_string().contains("give `row = ..` alone"));
    }

    #[test]
    fn a_row_must_name_a_struct_directly() {
        let err = parse(parse_quote! {
            #[stash(row = &User)]
            struct Rec {
                age: EncryptedAge,
            }
        })
        .unwrap_err();
        assert!(err.to_string().contains("must name a struct directly"));

        let err = parse(parse_quote! {
            #[stash(row = <T as Trait>::Row)]
            struct Rec {
                age: EncryptedAge,
            }
        })
        .unwrap_err();
        assert!(err.to_string().contains("must name a struct directly"));
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
