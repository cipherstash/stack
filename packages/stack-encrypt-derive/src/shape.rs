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
        /// This field's own context, if it has one: a `#[stash(context =
        /// "...")]` literal, or the `"<prefix>/<field>"` a `struct` derive
        /// infers. A context the caller passes extends it either way.
        context: Option<LitStr>,
        /// With `struct = ..`: the plaintext field this one is derived
        /// from — its own name, or the `#[stash(from = field)]` override.
        /// `None` for a `plaintext` record, whose fields are all derived
        /// from the whole value.
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
    /// A field with a context of its own — a literal, or the one a `struct`
    /// derive infers — is derived under it as it is when the caller passes
    /// `()`, and under it *extended* with the caller's (`("users/age", id)`)
    /// when the caller passes a `NonEmpty<_>`. A field with none is handed
    /// the caller's context as it is, and its type decides what that means:
    /// a nested `struct` derive composes it with its own contexts; a leaf
    /// accepts it only as a `NonEmpty<_>`, so under the record's `()` impl
    /// such a leaf is a compile error — at the field, since a `from` field's
    /// obligation is checked in the body against the plaintext field's type
    /// the derive cannot name — and the fix is a `context = ".."` on it.
    ///
    /// Only called for derived fields: a `default` field is not derived from
    /// the source and is never handed a context at all.
    pub(crate) fn field_context(&self) -> FieldContext<'_> {
        match &self.kind {
            Kind::Derived {
                context: Some(lit), ..
            } => FieldContext::Own(lit),
            Kind::Derived { context: None, .. } => FieldContext::Caller,
            Kind::Default(_) => unreachable!("a `default` field has no context"),
        }
    }

    /// Does this field use the context the caller passes, in the impl for
    /// `which`? A field with no context of its own always does; one with a
    /// context of its own extends the caller's, so only under `NonEmpty<_>`.
    /// See [`context_param`].
    pub(crate) fn uses_callers_context(&self, which: ContextImpl) -> bool {
        self.is_derived()
            && match self.field_context() {
                FieldContext::Caller => true,
                FieldContext::Own(_) => which == ContextImpl::NonEmpty,
            }
    }
}

/// Where a derived field's context comes from. See [`Field::field_context`].
#[cfg_attr(test, derive(Debug))]
pub(crate) enum FieldContext<'a> {
    /// A context of the field's own — `#[stash(context = "...")]`, or the
    /// `"<prefix>/<field>"` a `struct` derive infers: as it is under `()`,
    /// extended with the caller's context under `NonEmpty<_>`.
    Own(&'a LitStr),
    /// No context of its own: handed the caller's as it is — `()`, or the
    /// impl's `NonEmpty<__T>`.
    Caller,
}

/// Which of a derived record's two impls is being emitted: the context the
/// caller passes is `()` in one and `NonEmpty<__T>` in the other. Every
/// record gets both (see [`context_param`]), and every derived field uses
/// the caller's context under `NonEmpty<__T>`, so no record accepts a
/// context it then discards; a leaf field that has no context of its own
/// makes the `()` one unsatisfiable, which is the compile error
/// `encrypt_into` then reports.
#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(test, derive(Debug))]
pub(crate) enum ContextImpl {
    Unit,
    NonEmpty,
}

impl ContextImpl {
    pub(crate) const BOTH: [ContextImpl; 2] = [ContextImpl::Unit, ContextImpl::NonEmpty];
}

impl FieldContext<'_> {
    /// The context type as it appears in a where clause, in the impl for
    /// `which`.
    pub(crate) fn ty(&self, krate: &Path, which: ContextImpl) -> Type {
        match (self, which) {
            (FieldContext::Own(_), ContextImpl::Unit) => {
                parse_quote!(#krate::NonEmpty<&'static str>)
            }
            (FieldContext::Own(_), ContextImpl::NonEmpty) => {
                parse_quote!(#krate::NonEmpty<(&'static str, #krate::NonEmpty<__T>)>)
            }
            (FieldContext::Caller, ContextImpl::Unit) => parse_quote!(()),
            (FieldContext::Caller, ContextImpl::NonEmpty) => parse_quote!(#krate::NonEmpty<__T>),
        }
    }

    /// The context expression the field is handed in the impl for `which`;
    /// `caller` is the expression for the caller's context, which the call
    /// site chooses (move, clone, or clone through a reference) and which
    /// only a field that [uses it](Field::uses_callers_context) receives.
    pub(crate) fn expr(
        &self,
        krate: &Path,
        which: ContextImpl,
        caller: TokenStream,
    ) -> TokenStream {
        match (self, which) {
            (FieldContext::Own(lit), ContextImpl::Unit) => quote!(#krate::nonempty!(#lit)),
            (FieldContext::Own(lit), ContextImpl::NonEmpty) => {
                quote!(#krate::NonEmpty::with(#krate::nonempty!(#lit), #caller))
            }
            (FieldContext::Caller, _) => caller,
        }
    }
}

/// The record a derive input describes.
#[cfg_attr(test, derive(Debug))]
pub(crate) struct Record {
    pub(crate) krate: Path,
    /// The plaintext types, one impl each; empty means one impl generic over
    /// the plaintext. Exactly one for a `struct = ..` derive.
    pub(crate) plaintexts: Vec<Type>,
    /// `struct = ..`: the plaintext is encrypted field by field, every
    /// derived field from one field of it (`Field::from`).
    pub(crate) by_field: bool,
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
        // exactly when `struct` is.
        let fields = collect(&data.fields, attrs.context.as_ref())?;
        let by_field = attrs.by_field.is_some();
        let plaintexts = match attrs.by_field {
            Some(plaintext) => vec![plaintext],
            None => attrs.plaintexts,
        };

        if !fields.iter().any(Field::is_derived) {
            return Err(syn::Error::new_spanned(
                &input.ident,
                "nothing to derive: a record needs at least one field that is not `default`",
            ));
        }

        Ok(Self {
            krate: attrs.krate,
            plaintexts,
            by_field,
            fields,
        })
    }
}

/// The demand a derive places on the inner type of the caller's
/// `NonEmpty<__T>`, beyond what the field bounds already say — the vitaminc
/// context traits the direction needs, and `Clone` because one context
/// fans out to every field.
///
/// The leaves in this crate state that demand through the field bounds
/// already, but a `from` field's bound is checked in the body (the derive
/// cannot name the plaintext field's type), and a term field's
/// `DecryptField` accepts *any* context (it opens nothing), so without
/// this bound a record whose ciphertext field carries a literal would
/// accept — and silently discard — a value that is not a context at all.
pub(crate) enum CallerContext<'a> {
    /// Encrypt: convertible to AAD and to a PRF context.
    Encrypt(&'a Path),
    /// Decrypt: convertible to the AAD the value was encrypted under.
    Decrypt(&'a Path),
}

/// Adds the impl's context parameter for `which`, and returns the type the
/// impl is for.
///
/// Every derived record gets two impls: one for `()`, under which each
/// field is derived under the context it carries itself, and one for
/// `NonEmpty<__T>`, under which a row's inferred contexts are extended with
/// the caller's and a field with no context of its own is handed the
/// caller's as it is. The `()` impl of a record whose leaf takes the
/// caller's context is unsatisfiable — a leaf exists only under a
/// `NonEmpty<_>` — which is exactly the compile error `encrypt_into` reports
/// against it.
///
/// Under `NonEmpty<__T>` an extended context is `NonEmpty<(&'static str,
/// NonEmpty<__T>)>`, and the literal's `'static` fixes the lifetime the pair
/// implements the context traits for; a `struct` derive's `nested` field
/// hands the caller's context to a nested `struct` derive that extends it
/// likewise, and its obligation is checked in the body, where a free
/// lifetime could not meet it. So a record with any context of its own, and
/// every `struct` derive, is bounded for `'static`. Only a `plaintext`
/// record whose fields all take the caller's context as it is — every
/// bound in the where clause — is bounded for a free lifetime, and can pass
/// a borrowed context through.
pub(crate) fn context_param(
    generics: &mut Generics,
    bound: CallerContext<'_>,
    which: ContextImpl,
    by_field: bool,
    fields: &[&Field],
) -> Type {
    if which == ContextImpl::Unit {
        return parse_quote!(());
    }
    let krate = match bound {
        CallerContext::Encrypt(krate) | CallerContext::Decrypt(krate) => krate,
    };
    let needs_static = by_field
        || fields
            .iter()
            .any(|f| matches!(f.field_context(), FieldContext::Own(_)));
    let lifetime: syn::Lifetime = if needs_static {
        parse_quote!('static)
    } else {
        // A lifetime parameter must precede the type parameters.
        generics.params.insert(0, parse_quote!('__ctx));
        parse_quote!('__ctx)
    };
    generics.params.push(parse_quote!(__T));
    let predicates = &mut generics.make_where_clause().predicates;
    match bound {
        CallerContext::Encrypt(_) => predicates.push(parse_quote! {
            __T: #krate::IntoAad<#lifetime> + #krate::IntoPrfContext<#lifetime> + ::core::clone::Clone
        }),
        CallerContext::Decrypt(_) => predicates.push(parse_quote! {
            __T: #krate::IntoAad<#lifetime> + ::core::clone::Clone
        }),
    }
    parse_quote!(#krate::NonEmpty<__T>)
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
    /// `DecryptField<Plaintext, ..>` — for automatic decrypt, on every
    /// candidate field.
    DecryptField,
    /// `DecryptInto<Plaintext, ..>` — for explicit decrypt, on the one field
    /// opened as the whole plaintext.
    DecryptInto,
}

/// `FieldTy: Trait<Target, Cipher, Ctx>` for each of `fields`, under the
/// context it is derived or opened under in the impl for `which` — its
/// literal's, `()`, or the caller's `NonEmpty<__T>`, which is how a record
/// inherits its leaves' demand for a non-empty context. The cipher is the
/// one the trait binds to: encrypting binds to a keyset
/// (`KeysetCipher<'__k, __K>`), decrypting to the client (`StackCipher<__K>`;
/// the keyset-constrained form is a blanket over it).
pub(crate) fn push_field_bounds(
    generics: &mut Generics,
    krate: &Path,
    fields: &[&Field],
    target: &Type,
    bound: FieldBound,
    which: ContextImpl,
) {
    let trait_name: Ident = match bound {
        FieldBound::Encrypt => parse_quote!(EncryptFrom),
        FieldBound::DecryptField => parse_quote!(DecryptField),
        FieldBound::DecryptInto => parse_quote!(DecryptInto),
    };
    let cipher = cipher_type(krate, &bound);
    let predicates = &mut generics.make_where_clause().predicates;
    for field in fields {
        let ty = &field.ty;
        let context = field.field_context().ty(krate, which);
        // Spanned at the field type, so a type that cannot be a field of the
        // record is reported there, not at the derive.
        predicates.push(parse_quote_spanned! {ty.span()=>
            #ty: #krate::target::#trait_name<#target, #cipher, #context>
        });
    }
}

/// The cipher a derived impl binds to. Encrypting binds to a keyset, so the
/// encrypt impls are over `KeysetCipher<'__k, __K>` and carry the `'__k`
/// lifetime ([`push_keyset_lifetime`]); decrypting is client-scoped, so the
/// decrypt impls are over `StackCipher<__K>`.
pub(crate) fn cipher_type(krate: &Path, bound: &FieldBound) -> Type {
    match bound {
        FieldBound::Encrypt => parse_quote!(#krate::KeysetCipher<'__k, __K>),
        FieldBound::DecryptField | FieldBound::DecryptInto => {
            parse_quote!(#krate::StackCipher<__K>)
        }
    }
}

/// Add the `'__k` lifetime of the `KeysetCipher` an encrypt impl binds to.
/// Lifetimes precede type parameters in a generics list, so it goes first.
pub(crate) fn push_keyset_lifetime(generics: &mut Generics) {
    generics.params.insert(0, parse_quote!('__k));
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
/// `call(field, context)` renders one field's pending under `context`, the
/// expression [`FieldContext::expr`] gives the field in the impl for
/// `which`. The caller's context (`__context`) goes to every field that
/// uses it; the last such field takes it by move, the rest clone it.
pub(crate) fn zip_fields(
    krate: &Path,
    fields: &[&Field],
    which: ContextImpl,
    mut call: impl FnMut(&Field, TokenStream) -> TokenStream,
    build: TokenStream,
) -> TokenStream {
    let mut remaining = fields
        .iter()
        .filter(|f| f.uses_callers_context(which))
        .count();

    let mut chain = TokenStream::new();
    let mut pattern = TokenStream::new();
    for (index, field) in fields.iter().enumerate() {
        let caller = if field.uses_callers_context(which) {
            remaining -= 1;
            if remaining == 0 {
                quote!(__context)
            } else {
                quote!(::core::clone::Clone::clone(&__context))
            }
        } else {
            TokenStream::new()
        };
        let context = field.field_context().expr(krate, which, caller);
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

/// The fields, with what a `struct` derive (`prefix` is the container's
/// `context`) fills in: `from` is the field's own name and `context` is
/// `"<prefix>/<from>"`, each unless the field gives its own.
/// `#[stash(nested)]` opts a field out of the inferred context — it is handed
/// the caller's as it is, which a nested `struct` derive (a type carrying its
/// own contexts) composes with them and a leaf accepts only as a
/// `NonEmpty<_>`. `from` and `nested` reach into the plaintext, so they
/// exist only with `struct = ..`.
fn collect(fields: &Fields, prefix: Option<&LitStr>) -> Result<Vec<Field>> {
    fields
        .iter()
        .enumerate()
        .map(|(index, field)| {
            let attrs = FieldAttrs::parse(&field.attrs)?;
            let member = match &field.ident {
                Some(ident) => Member::Named(ident.clone()),
                None => Member::Unnamed(syn::Index::from(index)),
            };
            if prefix.is_none() {
                if let Some(from) = &attrs.from {
                    return Err(syn::Error::new(
                        from.span(),
                        "`from = ..` reaches into a field of the plaintext, which is what \
                         `#[stash(struct = ..)]` does: a `plaintext` record derives every field \
                         from the whole value",
                    ));
                }
                if attrs.nested {
                    return Err(syn::Error::new_spanned(
                        &field.ty,
                        "`nested` opts a field out of the context a `struct` derive infers, so \
                         it applies only with `struct = ..`; a `plaintext` record's field with no \
                         `context` is already handed the caller's",
                    ));
                }
            }
            // A literal context becomes a `nonempty!(..)`, which refuses an
            // empty one at compile time anyway; say so here, at the
            // attribute, with the alternative that applies.
            if let Some(context) = &attrs.context {
                if context.value().is_empty() {
                    let message = if prefix.is_some() {
                        "an empty `context` is rejected when a value is encrypted: name the \
                         field (e.g. \"users/email\"), or drop the attribute to use the inferred \
                         `\"<context>/<field>\"`"
                    } else {
                        "an empty `context` is rejected when a value is encrypted: name the \
                         field (e.g. \"users/email\"), or drop the attribute to hand the field \
                         the caller's context"
                    };
                    return Err(syn::Error::new(context.span(), message));
                }
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
                None => match prefix {
                    Some(prefix) => {
                        let from = attrs.from.unwrap_or_else(|| member.clone());
                        let context = if attrs.nested {
                            // The field's type carries its own contexts; it
                            // is handed the caller's (`FieldContext::Caller`).
                            None
                        } else if let Some(lit) = attrs.context {
                            Some(lit)
                        } else {
                            let column = match &from {
                                Member::Named(ident) => ident.to_string(),
                                Member::Unnamed(index) => index.index.to_string(),
                            };
                            let prefix = prefix.value();
                            Some(LitStr::new(&format!("{prefix}/{column}"), member.span()))
                        };
                        Kind::Derived {
                            context,
                            from: Some(from),
                        }
                    }
                    None => Kind::Derived {
                        context: attrs.context,
                        from: None,
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

    /// The field's own context, for assertions.
    fn own(field: &Field) -> String {
        match field.field_context() {
            FieldContext::Own(lit) => lit.value(),
            other => panic!("expected a context of the field's own, got {other:?}"),
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
    fn from_applies_only_with_struct() {
        // `from` reaches into the plaintext, which is what `struct = ..`
        // means; a `plaintext` record derives every field from the whole
        // value, named or not.
        for input in [
            parse_quote! {
                struct Row {
                    #[stash(from = age)]
                    age: EncryptedAge,
                }
            },
            parse_quote! {
                #[stash(plaintext = User)]
                struct Row {
                    #[stash(from = age, context = "users/age")]
                    age: EncryptedAge,
                }
            },
        ] {
            let err = parse(input).unwrap_err();
            assert!(
                err.to_string()
                    .contains("what `#[stash(struct = ..)]` does"),
                "{err}"
            );
        }
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
            #[stash(struct = User, context = "users")]
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

        let err = parse(parse_quote! {
            #[stash(struct = User, struct = User, context = "users")]
            struct Rec {
                c: StackCipherText,
            }
        })
        .unwrap_err();
        assert!(err.to_string().contains("`struct` is given twice"));
    }

    #[test]
    fn a_literal_empty_context_is_rejected_with_the_alternative_that_applies() {
        let err = parse(parse_quote! {
            struct Rec {
                #[stash(context = "")]
                c: StackCipherText,
            }
        })
        .unwrap_err();
        assert!(err.to_string().contains("empty `context`"));
        assert!(err
            .to_string()
            .contains("hand the field the caller's context"));

        let err = parse(parse_quote! {
            #[stash(struct = User, context = "users")]
            struct Rec {
                #[stash(context = "")]
                email: StackCipherText,
            }
        })
        .unwrap_err();
        assert!(err.to_string().contains("empty `context`"));
        assert!(err.to_string().contains("use the inferred"));
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
    fn a_struct_fills_in_from_and_context() {
        let record = parse(parse_quote! {
            #[stash(struct = crate::model::UserProfile<T>, context = "user_profiles")]
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
        assert!(record.by_field);
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
        assert_eq!(own(age), "user_profiles/age");
        // `from` overrides the field; the context follows the plaintext field.
        assert!(matches!(email.from(), Some(Member::Named(m)) if m == "email_address"));
        assert_eq!(own(email), "user_profiles/email_address");
        // `context` is taken verbatim; like the inferred ones, the caller's
        // context extends it.
        assert!(matches!(name.from(), Some(Member::Named(m)) if m == "name"));
        assert_eq!(own(name), "legacy/name");
        assert!(name.uses_callers_context(ContextImpl::NonEmpty));
        assert!(!name.uses_callers_context(ContextImpl::Unit));
        // `nested`: no inferred context — the field is handed the caller's.
        assert!(matches!(address.from(), Some(Member::Named(m)) if m == "address"));
        assert!(matches!(address.field_context(), FieldContext::Caller));
        assert!(address.uses_callers_context(ContextImpl::Unit));
        assert!(!version.is_derived());
    }

    #[test]
    fn a_tuple_struct_is_reached_and_named_by_index() {
        let record = parse(parse_quote! {
            #[stash(struct = Reading, context = "readings")]
            struct EncryptedReading(EncryptedAge, StackCipherText);
        })
        .unwrap();
        assert!(matches!(record.fields[1].from(), Some(Member::Unnamed(i)) if i.index == 1));
        assert_eq!(own(&record.fields[0]), "readings/0");
        assert_eq!(own(&record.fields[1]), "readings/1");
    }

    #[test]
    fn a_struct_requires_a_container_context() {
        // The prefix is part of the stored data's identity, so it is never
        // inferred from the Rust type's name: two types named `Account` in
        // different modules would otherwise silently share every field
        // context.
        let err = parse(parse_quote! {
            #[stash(struct = User)]
            struct EncryptedUser {
                age: EncryptedAge,
            }
        })
        .unwrap_err();
        let message = err.to_string();
        assert!(message.contains("needs a `context = \"..\"`"), "{message}");
        assert!(message.contains("naming the stored data"), "{message}");
    }

    #[test]
    fn a_container_context_requires_a_struct() {
        let err = parse(parse_quote! {
            #[stash(plaintext = User, context = "users")]
            struct Rec {
                c: StackCipherText,
            }
        })
        .unwrap_err();
        assert!(err.to_string().contains("applies only with `struct = ..`"));

        let err = parse(parse_quote! {
            #[stash(context = "users")]
            struct Rec {
                c: StackCipherText,
            }
        })
        .unwrap_err();
        assert!(err.to_string().contains("applies only with `struct = ..`"));
    }

    #[test]
    fn an_empty_container_context_is_rejected() {
        let err = parse(parse_quote! {
            #[stash(struct = User, context = "")]
            struct EncryptedUser {
                age: EncryptedAge,
            }
        })
        .unwrap_err();
        assert!(err.to_string().contains("name the stored data"));
    }

    #[test]
    fn nested_applies_only_with_struct_and_excludes_context() {
        let err = parse(parse_quote! {
            #[stash(plaintext = User)]
            struct Rec {
                #[stash(nested)]
                user: EncryptedUser,
            }
        })
        .unwrap_err();
        assert!(err.to_string().contains("applies only with `struct = ..`"));

        let err = parse(parse_quote! {
            #[stash(struct = Account, context = "accounts")]
            struct Rec {
                #[stash(nested, context = "accounts/user")]
                user: EncryptedUser,
            }
        })
        .unwrap_err();
        assert!(err.to_string().contains("`context` does not apply"));
    }

    #[test]
    fn struct_and_plaintext_are_exclusive() {
        let err = parse(parse_quote! {
            #[stash(struct = User, plaintext = User)]
            struct Rec {
                age: EncryptedAge,
            }
        })
        .unwrap_err();
        assert!(err.to_string().contains("give one of them"));
    }

    #[test]
    fn a_struct_must_name_a_struct_directly() {
        let err = parse(parse_quote! {
            #[stash(struct = &User)]
            struct Rec {
                age: EncryptedAge,
            }
        })
        .unwrap_err();
        assert!(err.to_string().contains("must name a struct directly"));

        let err = parse(parse_quote! {
            #[stash(struct = <T as Trait>::Row)]
            struct Rec {
                age: EncryptedAge,
            }
        })
        .unwrap_err();
        assert!(err.to_string().contains("must name a struct directly"));
    }

    #[test]
    fn plaintext_fields_classify() {
        let record = parse(parse_quote! {
            #[stash(plaintext = u32, plaintext = u64)]
            struct Rec {
                #[stash(context = "users/age", decrypt)]
                c: StackCipherText,
                hm: EqualityTerm,
                #[stash(default = SchemaVersion::V3)]
                v: SchemaVersion,
            }
        })
        .unwrap();
        assert!(!record.by_field);
        assert_eq!(record.plaintexts.len(), 2);
        assert_eq!(record.fields.len(), 3);
        // Nothing is derived from a field of the plaintext.
        assert!(record.fields.iter().all(|f| f.from().is_none()));
        assert_eq!(own(&record.fields[0]), "users/age");
        assert!(record.fields[0].decrypt);
        assert!(record.fields[1].is_derived());
        assert!(matches!(
            record.fields[1].field_context(),
            FieldContext::Caller
        ));
        assert!(!record.fields[2].is_derived());
    }
}
