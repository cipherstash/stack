//! Classification of the derive input into the record it describes.

use proc_macro2::{Group, Span, TokenStream, TokenTree};
use quote::{quote, quote_spanned, ToTokens};
use syn::spanned::Spanned;
use syn::{
    parse_quote, Data, DeriveInput, Expr, Fields, Generics, Ident, Lifetime, LitStr, Member, Path,
    Result, Type, WherePredicate,
};

use crate::attrs::{ContainerAttrs, FieldAttrs};

/// `tokens`, every one of them at `span`. An interpolated tree keeps the
/// spans it was built with, so a bound the derive states about a field is
/// reported at that field only if the *types* in it are spanned there too —
/// `quote_spanned!` alone re-spans nothing it interpolates.
fn respan(tokens: TokenStream, span: Span) -> TokenStream {
    tokens
        .into_iter()
        .map(|tree| match tree {
            TokenTree::Group(group) => {
                let mut group = Group::new(group.delimiter(), respan(group.stream(), span));
                group.set_span(span);
                TokenTree::Group(group)
            }
            mut leaf => {
                leaf.set_span(span);
                leaf
            }
        })
        .collect()
}

/// A generated lifetime must not shadow one the record declares. Append
/// underscores until the name is free, preserving the user's parameters.
pub(crate) fn fresh_lifetime(generics: &Generics, base: &str) -> Lifetime {
    let mut name = base.to_owned();
    while generics
        .lifetimes()
        .any(|declared| declared.lifetime.ident == name)
    {
        name.push('_');
    }
    Lifetime::new(&format!("'{name}"), Span::call_site())
}

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
        /// With `struct = ..`: the plaintext field this one is derived from
        /// and the context it is keyed under, which come together. `None`
        /// for every field of a `plaintext` record: it is derived from the
        /// whole value, under the caller's context.
        by_field: Option<ByField>,
    },
    /// Not derived: `Default::default()` or the given expression.
    Default(Option<Expr>),
    Context,
}

/// What a field of a `struct = ..` derive has and a field of a `plaintext`
/// record does not: a plaintext field to be derived from, and a context of
/// its own.
#[cfg_attr(test, derive(Debug))]
pub(crate) struct ByField {
    /// The plaintext field this one is derived from — its own name, or the
    /// `#[stash(from = field)]` override.
    pub(crate) from: Member,
    /// The `(prefix, segment)` pair it is derived under, extended by a
    /// context the caller passes.
    pub(crate) context: OwnContext,
}

impl Field {
    pub(crate) fn is_derived(&self) -> bool {
        matches!(self.kind, Kind::Derived { .. })
    }

    /// The `from` member, if this is a derived field with one.
    pub(crate) fn from(&self) -> Option<&Member> {
        match &self.kind {
            Kind::Derived { by_field } => by_field.as_ref().map(|by_field| &by_field.from),
            Kind::Default(_) | Kind::Context => None,
        }
    }

    /// How this derived field gets its context — the one classification both
    /// derives project their where clauses and bodies from.
    ///
    /// Every field of a `struct` derive has a context of its own, the one the
    /// derive infers: it is derived under it as it is when the caller passes
    /// `()`, and under it *extended* with the caller's (`(("users", "age"), id)`)
    /// when the caller passes a `NonEmpty<_>`. Every field of a `plaintext`
    /// record has none and is handed the caller's context as it is (a
    /// one-value plan has one context source), and its type decides what
    /// that means: a record field composes it with its own contexts; a leaf
    /// accepts it only as a `NonEmpty<_>`.
    ///
    /// Only called for derived fields: a `default` field is not derived from
    /// the source and is never handed a context at all.
    pub(crate) fn field_context(&self) -> FieldContext<'_> {
        match &self.kind {
            Kind::Derived {
                by_field: Some(by_field),
            } => FieldContext::Own(&by_field.context),
            Kind::Derived { by_field: None } => FieldContext::Caller,
            Kind::Default(_) | Kind::Context => unreachable!("a `default` field has no context"),
        }
    }
}

/// A derived field's own context, which only a `struct` derive's fields
/// have: the pair (container `context` prefix, segment), two parts, so it
/// renders `prefix/field` without the field name having to be joined into,
/// or kept out of, a string. The segment is the plaintext field's name or
/// the field's `identity`. The derive knows no tables (ADR-0003); a consumer
/// whose prefix is a table gets EQL's `(table, column)` shape from it.
#[cfg_attr(test, derive(Debug))]
pub(crate) struct OwnContext {
    pub(crate) prefix: LitStr,
    pub(crate) field: LitStr,
}
impl OwnContext {
    /// The `NonEmpty` the derive hands `under`.
    fn expr(&self, krate: &Path) -> TokenStream {
        let Self { prefix, field } = self;
        quote!(#krate::nonempty!(#prefix).with(#field))
    }
}

/// Where a derived field's context comes from. See [`Field::field_context`].
#[cfg_attr(test, derive(Debug))]
pub(crate) enum FieldContext<'a> {
    /// A context of the field's own, the `(prefix, field)` pair a `struct`
    /// derive infers: as it is under `()`, extended with the caller's
    /// context under `NonEmpty<_>`.
    Own(&'a OwnContext),
    /// No context of its own: handed the caller's as it is — `()`, or the
    /// record's associated context.
    Caller,
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
    /// `context_type = ..`: what the caller passes, in place of the
    /// `CallerContext` a record whose fields take the caller's context
    /// declares by default.
    pub(crate) context_type: Option<Type>,
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
        if fields
            .iter()
            .filter(|f| matches!(f.kind, Kind::Context))
            .count()
            > 1
        {
            return Err(syn::Error::new_spanned(
                &input.ident,
                "a record has exactly one `context_field`",
            ));
        }
        if fields.iter().any(|f| matches!(f.kind, Kind::Context)) && attrs.context.is_some() {
            return Err(syn::Error::new_spanned(
                &input.ident,
                "`context_field` supplies the complete context; a literal prefix does not apply",
            ));
        }
        let by_field = attrs.by_field.is_some();
        if by_field {
            one_output_per_plaintext_field(&fields)?;
        }
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

        let record = Self {
            krate: attrs.krate,
            plaintexts,
            by_field,
            context_type: attrs.context_type,
            fields,
        };
        // `ContainerAttrs::parse` has refused `context_type` beside `struct`;
        // the other shape that settles the context itself is checked here,
        // where the fields are known. (A `plaintext` record's derived fields
        // all take the caller's context, so no third shape remains.)
        if let Some(context_type) = &record.context_type {
            if record.context_field().is_some() {
                return Err(syn::Error::new_spanned(
                    context_type,
                    "`context_field` supplies the complete context, so the record's `Context` is \
                     `NonEmpty<T>` of that field's type; `context_type` does not apply",
                ));
            }
        }
        Ok(record)
    }
}

/// A `struct` derive's fields, as a plan's: each plaintext field has one
/// output, and each output one segment. A second output from one plaintext
/// field (a term beside its ciphertext) is one field of type
/// `Encrypted<Terms>` instead; two fields keyed under one segment would
/// share their data's identity.
fn one_output_per_plaintext_field(fields: &[Field]) -> Result<()> {
    let derived: Vec<&Field> = fields.iter().filter(|f| f.is_derived()).collect();
    for (at, field) in derived.iter().enumerate() {
        let name = |f: &Field| f.member.to_token_stream().to_string();
        for earlier in &derived[..at] {
            if let (Some(from), Some(earlier_from)) = (field.from(), earlier.from()) {
                if from == earlier_from {
                    return Err(syn::Error::new(
                        from.span(),
                        format!(
                            "`{}` and `{}` are both derived from the plaintext field `{}`: a \
                             plaintext field has one output. For a ciphertext with search terms \
                             beside it, make it one field of type `Encrypted<Terms>`, e.g. \
                             `{}: Encrypted<(EqualityTerm, MatchTerms)>`",
                            name(earlier),
                            name(field),
                            from.to_token_stream(),
                            name(earlier),
                        ),
                    ));
                }
            }
            if let (FieldContext::Own(own), FieldContext::Own(earlier_own)) =
                (field.field_context(), earlier.field_context())
            {
                let (segment, earlier_segment) = (&own.field, &earlier_own.field);
                if segment.value() == earlier_segment.value() {
                    return Err(syn::Error::new(
                        field.member.span(),
                        format!(
                            "`{}` and `{}` are both keyed under the segment `{}`, so their data \
                             would share one identity: give one of them another \
                             `identity = \"..\"`",
                            name(earlier),
                            name(field),
                            segment.value(),
                        ),
                    ));
                }
            }
        }
    }
    Ok(())
}

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

/// The fields, with what a `struct` derive (`prefix` is the container's
/// `context`) fills in: `from` is the field's own name and `context` is
/// the pair `("<prefix>", "<from>")`; `identity` replaces the second half.
/// `from` and `identity` reach into the plaintext, so they exist only with
/// `struct = ..`.
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
                if let Some(identity) = &attrs.identity {
                    return Err(syn::Error::new(
                        identity.span(),
                        "`identity` names the segment a field of a `struct = ..` derive is keyed \
                         under, after the record's `context`; a `plaintext` record's fields are \
                         all derived from the whole value and have no segment of their own",
                    ));
                }
            }
            // An identity is one label segment, as the plan builder's is:
            // non-empty, and plain so the descriptor names the field.
            if let Some(identity) = &attrs.identity {
                if !crate::attrs::is_plain_segment(&identity.value()) {
                    return Err(syn::Error::new(
                        identity.span(),
                        "an `identity` is the one label segment the field is keyed under, so it \
                         must be plain: not empty, no `/`, `(`, `)`, control or invisible \
                         character, and not beginning with `b64:`, a digit or `-` (e.g. \
                         `identity = \"email\"`)",
                    ));
                }
            }
            if attrs.context_field
                && (attrs.default.is_some()
                    || attrs.identity.is_some()
                    || attrs.from.is_some()
                    || attrs.decrypt)
            {
                return Err(syn::Error::new_spanned(
                    &field.ty,
                    "`context_field` is metadata and cannot also be derived or defaulted",
                ));
            }
            let kind = if attrs.context_field {
                Kind::Context
            } else {
                match attrs.default {
                    Some(default) => {
                        if attrs.identity.is_some() || attrs.from.is_some() || attrs.decrypt {
                            return Err(syn::Error::new_spanned(
                                &field.ty,
                                "a `default` field is not derived from the source, so `identity`, \
                                 `from` and `decrypt` do not apply to it",
                            ));
                        }
                        Kind::Default(default)
                    }
                    None => match prefix {
                        Some(prefix) => {
                            let from = attrs.from.unwrap_or_else(|| member.clone());
                            let context = if let Some(identity) = attrs.identity {
                                // Checked plain above.
                                OwnContext {
                                    prefix: prefix.clone(),
                                    field: identity,
                                }
                            } else {
                                // The inferred second segment must render
                                // verbatim, or the descriptor would not name
                                // the field. A named field is a Rust identifier
                                // and plain unless raw; a tuple index begins with
                                // a digit, which the descriptor reserves.
                                let field = match &from {
                                    Member::Named(ident) => ident.to_string(),
                                    Member::Unnamed(index) => {
                                        return Err(syn::Error::new(
                                            member.span(),
                                            format!(
                                                "a tuple field has no name to infer a context \
                                                 from: its index `{0}` begins with a digit, \
                                                 which a descriptor reserves, so `(\"{1}\", \
                                                 \"{0}\")` would render escaped; give the \
                                                 field `#[stash(identity = \"..\")]`",
                                                index.index,
                                                prefix.value()
                                            ),
                                        ));
                                    }
                                };
                                if !crate::attrs::is_plain_segment(&field) {
                                    return Err(syn::Error::new(
                                        member.span(),
                                        format!(
                                            "the field name `{field}` is not a plain descriptor \
                                             segment, so `(\"{}\", \"{field}\")` would render \
                                             escaped; give the field `#[stash(identity = \"..\")]`",
                                            prefix.value()
                                        ),
                                    ));
                                }
                                OwnContext {
                                    prefix: prefix.clone(),
                                    field: LitStr::new(&field, member.span()),
                                }
                            };
                            Kind::Derived {
                                by_field: Some(ByField { from, context }),
                            }
                        }
                        // Every output of a `plaintext` record takes the
                        // caller's context: a one-value plan has one source.
                        None => Kind::Derived { by_field: None },
                    },
                }
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

impl Record {
    pub(crate) fn context_field(&self) -> Option<&Field> {
        self.fields.iter().find(|f| matches!(f.kind, Kind::Context))
    }
    /// Whether the record takes `DeclaredContext`: exactly when it is a
    /// `struct` derive, whose fields all carry a context of their own. A
    /// `plaintext` record's fields have none.
    pub(crate) fn declared_contexts(&self) -> bool {
        self.by_field
    }
    pub(crate) fn context_type(&self, decrypt: bool) -> Type {
        let krate = &self.krate;
        if let Some(field) = self.context_field() {
            let ty = &field.ty;
            if decrypt {
                parse_quote!(#krate::target::ExpectedContext<#ty>)
            } else {
                parse_quote!(#krate::NonEmpty<#ty>)
            }
        } else if self.declared_contexts() {
            parse_quote!(#krate::target::DeclaredContext)
        } else if let Some(context_type) = &self.context_type {
            context_type.clone()
        } else {
            parse_quote!(#krate::target::CallerContext)
        }
    }
    /// The context a field is handed on the decrypt side: the caller's as it
    /// is, or — for a field with a context of its own, which only a `struct`
    /// derive has — the `CallerContext` that `context_expr` builds from the
    /// record's `DeclaredContext` with `under`.
    pub(crate) fn field_context_type(&self, field: &Field) -> Type {
        let krate = &self.krate;
        match field.field_context() {
            FieldContext::Own(_) => parse_quote!(#krate::target::CallerContext),
            FieldContext::Caller => self.context_type(false),
        }
    }
    /// The context type the record's declaration tree carries on the
    /// encrypt side (ADR-0004): a `DeclaredContext` when every field has a
    /// context of its own, so the caller's is optional; otherwise the
    /// caller's — the `context_type` named, or `CallerContext`. It is the
    /// record's own `Context` except for a record that stores its context,
    /// which declares the `NonEmpty<T>` it stores and converts it into this
    /// once, at the root.
    pub(crate) fn threaded_context(&self) -> Type {
        let krate = &self.krate;
        if self.context_field().is_some() {
            parse_quote!(#krate::target::CallerContext)
        } else {
            self.context_type(false)
        }
    }

    /// How the threaded context reaches this field's declaration, as the
    /// call appended to it on the encrypt side (ADR-0004).
    ///
    /// The context reaches operations by being threaded, so a field names
    /// itself once rather than computing a context to hand over. A field
    /// with a context of its own (a `struct` derive's) gives its subtree that
    /// context with `under`, which makes the caller's optional. A field with none
    /// is handed the threaded context as it is, converted into whatever its
    /// type declares it needs: the AEAD half for a ciphertext, unchanged for
    /// a term, composed with its own contexts by a record field, and — for
    /// a leaf reached through a record that may run under `()` — refused,
    /// at the field.
    ///
    /// Spanned at the field type: an interpolated token stream keeps the
    /// spans it was built with, so what the field's type refuses is
    /// reported there rather than at the derive.
    pub(crate) fn field_threading(&self, field: &Field) -> TokenStream {
        let krate = &self.krate;
        let span = field.ty.span();
        match field.field_context() {
            FieldContext::Own(own) => {
                let own = respan(own.expr(krate), span);
                quote_spanned!(span=> .under(#own))
            }
            FieldContext::Caller => {
                let threaded = respan(self.threaded_context().into_token_stream(), span);
                quote_spanned!(span=> .accepting::<#threaded>())
            }
        }
    }

    /// What [`field_threading`](Self::field_threading) asks of a field's
    /// type, as the impl's where-clause: that it is a target of `source`,
    /// and that the context handed down converts into the one it declares.
    /// Only for a field whose source the derive can name — a `from` field's
    /// obligation is checked in the body, against a plaintext field's type
    /// the derive cannot name.
    pub(crate) fn field_bounds(&self, field: &Field, source: &Type) -> [WherePredicate; 2] {
        let krate = &self.krate;
        let ty = &field.ty;
        let context = quote!(<#ty as #krate::target::EncryptFrom<#source>>::Context);
        let threading = match field.field_context() {
            FieldContext::Own(_) => parse_quote!(#context: From<#krate::target::CallerContext>),
            FieldContext::Caller => {
                let threaded = self.threaded_context();
                parse_quote!(#threaded: Into<#context>)
            }
        };
        [
            parse_quote!(#ty: #krate::target::EncryptFrom<#source>),
            threading,
        ]
    }

    /// The context a field is opened under, from the record's `__context`,
    /// on the decrypt side: the caller's as it is, or the field's own
    /// extended by it.
    pub(crate) fn context_expr(&self, field: &Field) -> TokenStream {
        let krate = &self.krate;
        match field.field_context() {
            FieldContext::Caller => quote!(::core::clone::Clone::clone(&__context)),
            FieldContext::Own(own) => {
                let own = own.expr(krate);
                quote!(::core::clone::Clone::clone(&__context).under(#own))
            }
        }
    }
    pub(crate) fn sources(&self, generic: Type) -> (Vec<Type>, bool) {
        if self.plaintexts.is_empty() {
            (vec![generic], true)
        } else {
            (self.plaintexts.clone(), false)
        }
    }
}
/// The chain zipping `operations` into one description, and the nested
/// tuple pattern that binds each operation's output to its local in the
/// closure that maps the chain's output.
pub(crate) fn zip_chain(operations: Vec<(TokenStream, Ident)>) -> (TokenStream, TokenStream) {
    let mut chain = TokenStream::new();
    let mut pattern = TokenStream::new();
    for (index, (operation, local)) in operations.into_iter().enumerate() {
        if index == 0 {
            chain = operation;
            pattern = quote!(#local);
        } else {
            chain = quote!(#chain.zip(#operation));
            pattern = quote!((#pattern, #local));
        }
    }
    (chain, pattern)
}

/// The zipped `operations`, mapped to `result`.
pub(crate) fn zip(operations: Vec<(TokenStream, Ident)>, result: TokenStream) -> TokenStream {
    let (chain, pattern) = zip_chain(operations);
    quote!(#chain.map(move |#pattern| #result))
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
            FieldContext::Own(OwnContext { prefix, field }) => {
                format!("({}, {})", prefix.value(), field.value())
            }
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
                    #[stash(from = age)]
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
                #[stash(default, decrypt)]
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
            #[stash(struct = User, context = "users")]
            struct Rec {
                #[stash(identity = "email", identity = "name")]
                c: StackCipherText,
            }
        })
        .unwrap_err();
        assert!(err.to_string().contains("`identity` is given twice"));

        // Also across two `#[stash(..)]` attributes on the same field.
        let err = parse(parse_quote! {
            #[stash(struct = User, context = "users")]
            struct Rec {
                #[stash(identity = "email")]
                #[stash(identity = "name")]
                c: StackCipherText,
            }
        })
        .unwrap_err();
        assert!(err.to_string().contains("`identity` is given twice"));

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
    fn a_field_context_is_refused_on_every_derive_form() {
        // A one-value plan has one context source, the caller's, and a
        // fields plan's fields all sit under the plan's: a field sealed under
        // a literal of its own has no plan form, whatever the literal, so the
        // attribute itself is the mistake. Even an empty or non-plain one.
        for context in ["nickname", "users/nickname", ""] {
            let inputs: [DeriveInput; 3] = [
                parse_quote! {
                    #[stash(struct = User, context = "users")]
                    struct Rec {
                        #[stash(context = #context)]
                        name: StackCipherText,
                    }
                },
                parse_quote! {
                    #[stash(plaintext = String)]
                    struct Rec {
                        c: StackCipherText,
                        #[stash(context = #context)]
                        shadow: StackCipherText,
                    }
                },
                parse_quote! {
                    struct Rec {
                        #[stash(decrypt, context = #context)]
                        c: StackCipherText,
                    }
                },
            ];
            for input in inputs {
                let message = parse(input).unwrap_err().to_string();
                assert!(
                    message.contains("field-level `context = \"..\"` is no longer accepted"),
                    "{message}"
                );
                assert!(
                    message.contains(
                        "All outputs of a `plaintext = T` record share the caller's context"
                    ),
                    "{message}"
                );
                // A 0.2.0 user is told the replacement moves their data.
                assert!(
                    message.contains("a different context from the old literal"),
                    "{message}"
                );
                assert!(message.contains("re-encrypt that data"), "{message}");
                assert!(message.contains("identity = \"..\""), "{message}");
                assert!(
                    message.contains("a fields plan that picks the same source twice"),
                    "{message}"
                );
            }
        }
    }

    #[test]
    fn an_identity_is_one_plain_segment_of_a_struct_field() {
        for identity in ["", "users/name", "0name", "b64:x"] {
            let err = parse(parse_quote! {
                #[stash(struct = User, context = "users")]
                struct Rec {
                    #[stash(identity = #identity)]
                    name: StackCipherText,
                }
            })
            .unwrap_err();
            assert!(
                err.to_string().contains("must be plain"),
                "{identity:?}: {err}"
            );
        }

        let err = parse(parse_quote! {
            #[stash(plaintext = String)]
            struct Rec {
                #[stash(identity = "name")]
                c: StackCipherText,
            }
        })
        .unwrap_err();
        assert!(err.to_string().contains("have no segment"), "{err}");

        let err = parse(parse_quote! {
            #[stash(struct = User, context = "users")]
            struct Rec {
                #[stash(identity = "a", identity = "b")]
                name: StackCipherText,
            }
        })
        .unwrap_err();
        assert!(
            err.to_string().contains("`identity` is given twice"),
            "{err}"
        );

        let err = parse(parse_quote! {
            #[stash(struct = User, context = "users")]
            struct Rec {
                name: StackCipherText,
                #[stash(default, identity = "v")]
                v: u8,
            }
        })
        .unwrap_err();
        assert!(
            err.to_string().contains("`default` field is not derived"),
            "{err}"
        );

        let err = parse(parse_quote! {
            #[stash(struct = User, context = "users")]
            struct Rec {
                #[stash(context_field, identity = "v")]
                tenant: String,
                c: StackCipherText,
            }
        })
        .unwrap_err();
        assert!(
            err.to_string().contains("`context_field` is metadata"),
            "{err}"
        );
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
                #[stash(identity = "full_name")]
                name: StackCipherText,
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
        assert_eq!(own(age), "(user_profiles, age)");
        // `from` overrides the field; the context follows the plaintext field.
        assert!(matches!(email.from(), Some(Member::Named(m)) if m == "email_address"));
        assert_eq!(own(email), "(user_profiles, email_address)");
        // `identity` replaces the segment, never the prefix above it.
        assert!(matches!(name.from(), Some(Member::Named(m)) if m == "name"));
        assert_eq!(own(name), "(user_profiles, full_name)");
        // A record-typed field is an ordinary field: the inferred pair.
        assert!(matches!(address.from(), Some(Member::Named(m)) if m == "address"));
        assert_eq!(own(address), "(user_profiles, address)");
        assert!(!version.is_derived());
    }

    #[test]
    fn a_tuple_struct_is_reached_by_index_and_must_name_its_contexts() {
        // An index is no name for a context: it begins with a digit, which a
        // descriptor reserves, so the bare form is refused…
        let err = parse(parse_quote! {
            #[stash(struct = Reading, context = "readings")]
            struct EncryptedReading(EncryptedAge, StackCipherText);
        })
        .unwrap_err();
        assert!(
            err.to_string().contains("index `0` begins with a digit"),
            "{err}"
        );
        // …and each field names its own, still reached by index.
        let record = parse(parse_quote! {
            #[stash(struct = Reading, context = "readings")]
            struct EncryptedReading(
                #[stash(identity = "value")] EncryptedAge,
                #[stash(identity = "unit")] StackCipherText,
            );
        })
        .unwrap();
        assert!(matches!(record.fields[1].from(), Some(Member::Unnamed(i)) if i.index == 1));
        assert_eq!(own(&record.fields[0]), "(readings, value)");
        assert_eq!(own(&record.fields[1]), "(readings, unit)");
    }

    #[test]
    fn a_plaintext_field_has_one_output() {
        for input in [
            // The field named `email` reaches `email`, and so does the term.
            parse_quote! {
                #[stash(struct = User, context = "users")]
                struct Rec {
                    email: StackCipherText,
                    #[stash(from = email)]
                    email_hm: EqualityTerm,
                }
            },
            parse_quote! {
                #[stash(struct = User, context = "users")]
                struct Rec {
                    #[stash(from = email, identity = "a")]
                    a: StackCipherText,
                    #[stash(from = email, identity = "b")]
                    b: EqualityTerm,
                }
            },
            parse_quote! {
                #[stash(struct = Reading, context = "readings")]
                struct Rec {
                    #[stash(from = 0, identity = "value")]
                    value: StackCipherText,
                    #[stash(from = 0, identity = "value_hm")]
                    value_hm: EqualityTerm,
                }
            },
        ] {
            let message = parse(input).unwrap_err().to_string();
            assert!(message.contains("has one output"), "{message}");
            assert!(message.contains("Encrypted<Terms>"), "{message}");
        }

        // One output per plaintext field, with `from` as a rename, is fine;
        // so is a `default` field beside it.
        let record = parse(parse_quote! {
            #[stash(struct = User, context = "users")]
            struct Rec {
                #[stash(from = email)]
                address: Encrypted<(EqualityTerm, MatchTerms)>,
                name: StackCipherText,
                #[stash(default)]
                version: u8,
            }
        })
        .unwrap();
        assert_eq!(own(&record.fields[0]), "(users, email)");
        assert_eq!(own(&record.fields[1]), "(users, name)");
    }

    #[test]
    fn two_fields_are_never_keyed_under_one_segment() {
        let err = parse(parse_quote! {
            #[stash(struct = User, context = "users")]
            struct Rec {
                email: StackCipherText,
                #[stash(identity = "email")]
                name: StackCipherText,
            }
        })
        .unwrap_err();
        let message = err.to_string();
        assert!(message.contains("`email` and `name`"), "{message}");
        assert!(message.contains("segment `email`"), "{message}");
    }

    #[test]
    fn a_container_prefix_that_is_not_plain_is_refused() {
        let err = parse(parse_quote! {
            #[stash(struct = User, context = "public/users")]
            struct Encrypted {
                email: StackCipherText,
            }
        })
        .unwrap_err();
        assert!(err.to_string().contains("must be plain"), "{err}");
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
    fn nested_is_refused_and_the_message_says_to_omit_it() {
        for input in [
            parse_quote! {
                #[stash(struct = Account, context = "accounts")]
                struct Rec {
                    #[stash(nested)]
                    user: EncryptedUser,
                }
            },
            parse_quote! {
                #[stash(plaintext = User)]
                struct Rec {
                    #[stash(nested)]
                    user: EncryptedUser,
                }
            },
        ] {
            let message = parse(input).unwrap_err().to_string();
            assert!(
                message.contains("`nested` is no longer accepted"),
                "{message}"
            );
            assert!(message.contains("Omit `nested`"), "{message}");
            assert!(
                message.contains("a different context from the one `nested` gave"),
                "{message}"
            );
            assert!(message.contains("re-encrypt that data"), "{message}");
        }
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
    fn context_type_replaces_the_default_caller_context() {
        let record = parse(parse_quote! {
            #[stash(plaintext = String, context_type = AeadContext)]
            struct Rec {
                c: StackCipherText,
                shadow: StackCipherText,
            }
        })
        .unwrap();
        let ty = |ty: &Type| quote!(#ty).to_string();
        assert_eq!(ty(&record.context_type(false)), "AeadContext");
        assert_eq!(ty(&record.context_type(true)), "AeadContext");
        // Both fields are handed the caller's type as it is.
        assert_eq!(
            ty(&record.field_context_type(&record.fields[0])),
            "AeadContext"
        );
        assert_eq!(
            ty(&record.field_context_type(&record.fields[1])),
            "AeadContext"
        );

        let record = parse(parse_quote! {
            struct Rec {
                c: StackCipherText,
            }
        })
        .unwrap();
        assert!(record.context_type.is_none());
        assert_eq!(
            ty(&record.context_type(false)),
            ":: stack_encrypt :: target :: CallerContext"
        );
    }

    #[test]
    fn context_type_applies_only_where_the_caller_settles_the_context() {
        let err = parse(parse_quote! {
            #[stash(struct = User, context = "users", context_type = AeadContext)]
            struct Rec {
                name: StackCipherText,
            }
        })
        .unwrap_err();
        assert!(
            err.to_string()
                .contains("a `struct` derive's fields carry their own"),
            "{err}"
        );

        let err = parse(parse_quote! {
            #[stash(context_type = AeadContext)]
            struct Rec {
                #[stash(context_field)]
                tenant: String,
                c: StackCipherText,
            }
        })
        .unwrap_err();
        assert!(
            err.to_string().contains("`context_type` does not apply"),
            "{err}"
        );

        let err = parse(parse_quote! {
            #[stash(context_type = AeadContext, context_type = AeadContext)]
            struct Rec {
                c: StackCipherText,
            }
        })
        .unwrap_err();
        assert!(
            err.to_string().contains("`context_type` is given twice"),
            "{err}"
        );
    }

    #[test]
    fn plaintext_fields_classify() {
        let record = parse(parse_quote! {
            #[stash(plaintext = u32, plaintext = u64)]
            struct Rec {
                #[stash(decrypt)]
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
        // Every derived field takes the caller's context: a one-value plan
        // has one source.
        assert!(record.fields[0].decrypt);
        assert!(record.fields[1].is_derived());
        for field in &record.fields[..2] {
            assert!(matches!(field.field_context(), FieldContext::Caller));
        }
        assert!(!record.fields[2].is_derived());
    }
}
