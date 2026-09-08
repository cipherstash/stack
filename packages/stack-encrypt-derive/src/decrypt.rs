//! Expansion of `#[derive(DecryptInto)]`.
//!
//! Which field decryption opens is, by default, not the derive's decision
//! but the type system's: every candidate field's type says through
//! `Decryptable` whether it is a ciphertext or a one-way term, a `const`
//! assertion requires exactly one ciphertext (per plaintext field, for a
//! row), and the body asks each field through `DecryptField`, taking the one
//! answer. `#[stash(decrypt)]` switches the record to the explicit mode, in
//! which only the marked fields are considered and the field types need not
//! be `Decryptable`.

use std::collections::HashSet;

use proc_macro2::{Span, TokenStream};
use quote::{quote, quote_spanned, ToTokens};
use syn::spanned::Spanned;
use syn::{
    parse_quote, DeriveInput, Generics, Ident, LitStr, Member, Path, PathArguments, Result, Type,
};

use crate::shape::{
    context_param, impl_sources, push_field_bounds, trait_impl, zip_fields, CallerContext,
    ContextImpl, Field, FieldBound, Record,
};

pub(crate) fn derive(input: DeriveInput) -> Result<TokenStream> {
    let record = Record::parse(&input)?;
    let krate = &record.krate;

    let field_impl = decrypt_field_impl(&input, krate);
    let impls = if record.fields.iter().any(|f| f.decrypt) {
        explicit(&input, &record)?
    } else {
        automatic(&input, &record)?
    };

    Ok(quote!(#impls #field_impl))
}

// =============================================================================
// Shared
// =============================================================================

/// `impl DecryptInto<Plaintext, StackCipher<__K>, Ctx> for Record` around
/// `body`; `ctx` is `()` or `NonEmpty<__T>` ([`context_param`]). The
/// context parameter is unnamed when no opened field uses it, so the
/// expansion warns of nothing.
fn impl_block(
    input: &DeriveInput,
    krate: &Path,
    generics: &Generics,
    plaintext: &Type,
    ctx: &Type,
    uses_context: bool,
    body: TokenStream,
) -> TokenStream {
    let context = if uses_context {
        quote!(__context)
    } else {
        quote!(_)
    };
    trait_impl(
        input,
        generics,
        quote!(#krate::target::DecryptInto<#plaintext, #krate::StackCipher<__K>, #ctx>),
        quote! {
            fn decrypt_into<'__a>(
                self,
                __cipher: &'__a #krate::StackCipher<__K>,
                #context: #ctx,
            ) -> #krate::target::Pending<'__a, #plaintext, __K>
            where
                Self: '__a,
                #plaintext: '__a,
            {
                #body
            }
        },
    )
}

/// `impl DecryptField<__P, __C, __Ctx> for Record`: a derived record is a
/// field of a larger one, opened through its own `DecryptInto`.
fn decrypt_field_impl(input: &DeriveInput, krate: &Path) -> TokenStream {
    let name = &input.ident;
    let (_, ty_generics, _) = input.generics.split_for_impl();
    let mut generics = input.generics.clone();
    generics.params.push(parse_quote!(__P));
    generics.params.push(parse_quote!(__C));
    generics.params.push(parse_quote!(__Ctx));
    generics.make_where_clause().predicates.push(parse_quote! {
        __C: #krate::target::DecryptTarget
    });
    generics.make_where_clause().predicates.push(parse_quote! {
        Self: #krate::target::DecryptInto<__P, __C, __Ctx>
    });
    let (impl_generics, _, where_clause) = generics.split_for_impl();
    quote! {
        #[automatically_derived]
        impl #impl_generics #krate::target::DecryptField<__P, __C, __Ctx> for #name #ty_generics
            #where_clause
        {
            fn decrypt_field<'__a>(
                self,
                __cipher: &'__a __C,
                __context: __Ctx,
            ) -> ::core::option::Option<<__C as #krate::target::DecryptTarget>::Output<'__a, __P>>
            where
                Self: '__a,
                __P: '__a,
            {
                ::core::option::Option::Some(
                    <Self as #krate::target::DecryptInto<__P, __C, __Ctx>>::decrypt_into(
                        self, __cipher, __context,
                    ),
                )
            }
        }
    }
}

/// The context one opened field is handed, by move, in the impl for
/// `which`: its own, the caller's, or its own extended with the caller's.
fn context_for(krate: &Path, field: &Field, which: ContextImpl) -> TokenStream {
    field.field_context().expr(krate, which, quote!(__context))
}

/// The plaintext type as a struct-literal path: `User<T>` becomes `User::<T>`.
fn struct_literal_path(plaintext: &Type) -> Result<Path> {
    let Type::Path(type_path) = plaintext else {
        return Err(syn::Error::new_spanned(
            plaintext,
            "field-by-field decryption rebuilds the plaintext as a struct literal, so \
             `plaintext` must name a struct",
        ));
    };
    if type_path.qself.is_some() {
        return Err(syn::Error::new_spanned(
            plaintext,
            "field-by-field decryption rebuilds the plaintext as a struct literal, so \
             `plaintext` must name a struct directly, not through a qualified path",
        ));
    }
    let mut path = type_path.path.clone();
    for segment in &mut path.segments {
        if let PathArguments::AngleBracketed(args) = &mut segment.arguments {
            args.colon2_token = Some(Default::default());
        }
    }
    Ok(path)
}

// =============================================================================
// Automatic mode: the type system picks the field
// =============================================================================

/// The shape of a record with no `decrypt` attribute, from its `from`s.
enum Auto<'a> {
    /// No derived field has a `from`: one of them is the whole plaintext's
    /// ciphertext.
    Whole(Vec<&'a Field>),
    /// Every derived field has a `from`: each plaintext field is recovered by
    /// one of the fields derived from it.
    ByField(Vec<Group<'a>>),
}

/// The fields derived from one field of the plaintext.
struct Group<'a> {
    from: &'a Member,
    fields: Vec<&'a Field>,
}

impl<'a> Auto<'a> {
    fn classify(record: &'a Record) -> Self {
        let candidates = record.derived();
        if !record.by_field {
            return Auto::Whole(candidates);
        }

        let mut groups: Vec<Group<'a>> = Vec::new();
        for field in candidates {
            let from = field
                .from()
                .unwrap_or_else(|| unreachable!("every field of a `struct` derive has a `from`"));
            match groups.iter_mut().find(|g| g.from == from) {
                Some(group) => group.fields.push(field),
                None => groups.push(Group {
                    from,
                    fields: vec![field],
                }),
            }
        }
        Auto::ByField(groups)
    }
}

fn automatic(input: &DeriveInput, record: &Record) -> Result<TokenStream> {
    let krate = &record.krate;
    let name = &input.ident;
    let auto = Auto::classify(record);

    // The one-ciphertext check: at the definition for a concrete record, at
    // the first use for a generic one (a `const _` cannot name the record's
    // parameters, and an inline `const` is evaluated per instantiation).
    let checks = match &auto {
        Auto::Whole(fields) => check(krate, name, None, fields),
        Auto::ByField(groups) => {
            let each = groups
                .iter()
                .map(|g| check(krate, name, Some(g.from), &g.fields));
            quote!(#(#each)*)
        }
    };
    let (definition_check, body_check) = if input.generics.params.is_empty() {
        (quote!(const _: () = { #checks };), TokenStream::new())
    } else {
        (TokenStream::new(), quote!(let () = const { #checks };))
    };

    // Every candidate field, moved out of `self` and asked in turn.
    let candidates: Vec<&Field> = match &auto {
        Auto::Whole(fields) => fields.clone(),
        Auto::ByField(groups) => groups
            .iter()
            .flat_map(|g| g.fields.iter().copied())
            .collect(),
    };
    let destructure = |uses_context: bool| {
        let bind = candidates.iter().map(|f| {
            let member = &f.member;
            let local = &f.local;
            quote!(#member: #local)
        });
        // The caller's context is cloned to every field that uses it, so
        // it is taken by reference once.
        let borrow = uses_context.then(|| quote!(let __context = &__context;));
        quote! {
            let Self { #(#bind,)* .. } = self;
            #borrow
        }
    };

    // One impl per listed plaintext, or one generic over it (whole mode
    // only: rebuilding field by field needs a struct literal, and
    // `Record::parse` has rejected `from` without a named plaintext) — and
    // each twice, for `()` and for `NonEmpty<__T>` (see `context_param`).
    // Each candidate field is bounded by `DecryptField` under the context
    // it is opened under, so a record's impl exists for exactly the
    // plaintexts its ciphertext field opens to — and only under a non-empty
    // context if that field needs one.
    let (plaintexts, generic) = impl_sources(record, parse_quote!(__P));
    let mut impls = Vec::with_capacity(plaintexts.len() * 2);
    for plaintext in &plaintexts {
        for which in ContextImpl::BOTH {
            let mut generics = input.generics.clone();
            if generic {
                generics.params.push(parse_quote!(__P));
            }
            generics.params.push(parse_quote!(__K));
            let open = match &auto {
                Auto::Whole(fields) => {
                    push_field_bounds(
                        &mut generics,
                        krate,
                        fields,
                        plaintext,
                        FieldBound::DecryptField,
                        which,
                    );
                    open_one(krate, fields, plaintext, which)
                }
                Auto::ByField(groups) => by_group_body(krate, groups, plaintext, which)?,
            };
            let ctx = context_param(
                &mut generics,
                CallerContext::Decrypt(krate),
                which,
                record.by_field,
                &candidates,
            );
            let uses_context = candidates.iter().any(|f| f.uses_callers_context(which));
            let destructure = destructure(uses_context);
            let body = quote!(#body_check #destructure #open);
            impls.push(impl_block(
                input,
                krate,
                &generics,
                plaintext,
                &ctx,
                uses_context,
                body,
            ));
        }
    }

    Ok(quote!(#(#impls)* #definition_check))
}

/// The `const` assertion that exactly one of `fields` is `Decryptable`;
/// `from` names the plaintext field they recover, for the message.
fn check(krate: &Path, name: &Ident, from: Option<&Member>, fields: &[&Field]) -> TokenStream {
    let terms = fields.iter().map(|field| {
        let ty = &field.ty;
        // Spanned at the field type: a type that is not `Decryptable` is
        // reported there, not at the derive.
        quote_spanned!(ty.span()=> + (<#ty as #krate::target::Decryptable>::DECRYPTABLE as usize))
    });
    let (none, several) = match from {
        None => (
            format!(
                "`{name}` has no decryptable field: every derived field is a one-way index \
                 term, so there is nothing for DecryptInto to open"
            ),
            format!(
                "`{name}` has several decryptable fields: mark the one decryption opens \
                 `#[stash(decrypt)]`"
            ),
        ),
        Some(from) => {
            let from = from.to_token_stream();
            (
                format!(
                    "no field of `{name}` can recover the plaintext field `{from}`: every field \
                     derived from it is a one-way index term"
                ),
                format!(
                    "several fields of `{name}` are derived from the plaintext field `{from}` and \
                     decryptable: mark the one decryption opens `#[stash(decrypt)]`"
                ),
            )
        }
    };
    let none = LitStr::new(&none, Span::call_site());
    let several = LitStr::new(&several, Span::call_site());
    // A `let`, not a nested `const` item: an item could not see the
    // record's generics from inside an inline `const`.
    quote! {
        {
            let __decryptable: usize = 0 #(#terms)*;
            ::core::assert!(__decryptable >= 1, #none);
            ::core::assert!(__decryptable <= 1, #several);
        }
    }
}

/// The one `Some` among the fields' `decrypt_field`s, as a pending of
/// `plaintext` (`_` when it is inferred from a struct literal), in the impl
/// for `which`.
fn open_one(krate: &Path, fields: &[&Field], plaintext: &Type, which: ContextImpl) -> TokenStream {
    let mut calls = fields.iter().map(|field| {
        let ty = &field.ty;
        let local = &field.local;
        let context = field.field_context().expr(
            krate,
            which,
            quote!(::core::clone::Clone::clone(__context)),
        );
        // The context type is named, not inferred, so a leaf that cannot
        // open under it is reported by the trait's `on_unimplemented`
        // rather than as an argument type mismatch inside the expansion.
        let context_ty = field.field_context().ty(krate, which);
        quote_spanned! {ty.span()=>
            <#ty as #krate::target::DecryptField<#plaintext, #krate::StackCipher<__K>, #context_ty>>::decrypt_field(
                #local, __cipher, #context,
            )
        }
    });
    let first = calls
        .next()
        .unwrap_or_else(|| unreachable!("a group has at least one field"));
    let chain = calls.fold(
        first,
        |chain, call| quote!(::core::option::Option::or_else(#chain, move || #call)),
    );
    // The const assertion has established that exactly one field's type is
    // `Decryptable`, but a third-party `DecryptField` can still break its
    // contract and return `None` for a type whose `DECRYPTABLE` is `true`.
    // That is `Error::NotOpened` — a failed pending that settles without
    // I/O — never a panic.
    quote! {
        ::core::option::Option::unwrap_or_else(#chain, || #krate::target::Pending::failed(
            __cipher,
            #krate::Error::NotOpened,
        ))
    }
}

/// Each group's opened pending, zipped into one and mapped into a struct
/// literal of the plaintext.
fn by_group_body(
    krate: &Path,
    groups: &[Group<'_>],
    plaintext: &Type,
    which: ContextImpl,
) -> Result<TokenStream> {
    let literal = struct_literal_path(plaintext)?;
    let inferred: Type = parse_quote!(_);

    let locals: Vec<Ident> = (0..groups.len())
        .map(|index| Ident::new(&format!("__group_{index}"), Span::call_site()))
        .collect();
    let opens = groups.iter().zip(&locals).map(|(group, local)| {
        let open = open_one(krate, &group.fields, &inferred, which);
        quote!(let #local = #open;)
    });

    let mut chain = TokenStream::new();
    let mut pattern = TokenStream::new();
    for (index, local) in locals.iter().enumerate() {
        if index == 0 {
            chain = quote!(#local);
            pattern = quote!(#local);
        } else {
            chain = quote!(#chain.zip(#local));
            pattern = quote!((#pattern, #local));
        }
    }
    let assign = groups.iter().zip(&locals).map(|(group, local)| {
        let from = group.from;
        quote!(#from: #local)
    });

    Ok(quote! {
        #(#opens)*
        #chain.map(|#pattern| #literal { #(#assign),* })
    })
}

// =============================================================================
// Explicit mode: `#[stash(decrypt)]` names the fields
// =============================================================================

fn explicit(input: &DeriveInput, record: &Record) -> Result<TokenStream> {
    let krate = &record.krate;
    let name = &input.ident;

    let opened: Vec<&Field> = record.fields.iter().filter(|f| f.decrypt).collect();
    let mode = Mode::classify(opened, name)?;

    // One impl per listed plaintext, or one generic over it — and each
    // twice, for `()` and for `NonEmpty<__T>`. Only the whole-plaintext mode
    // can be generic — rebuilding field by field needs a struct literal, and
    // therefore a name — and `Record::parse` has already rejected `from`
    // without one.
    let (plaintexts, generic) = impl_sources(record, parse_quote!(__P));
    let mut impls = Vec::with_capacity(plaintexts.len() * 2);
    for plaintext in &plaintexts {
        for which in ContextImpl::BOTH {
            let mut generics = input.generics.clone();
            if generic {
                generics.params.push(parse_quote!(__P));
            }
            generics.params.push(parse_quote!(__K));
            let (body, ctx, uses_context) = match &mode {
                Mode::Whole(field) => {
                    push_field_bounds(
                        &mut generics,
                        krate,
                        &[field],
                        plaintext,
                        FieldBound::DecryptInto,
                        which,
                    );
                    let ctx = context_param(
                        &mut generics,
                        CallerContext::Decrypt(krate),
                        which,
                        record.by_field,
                        &[field],
                    );
                    (
                        whole_body(krate, field, plaintext, which),
                        ctx,
                        field.uses_callers_context(which),
                    )
                }
                Mode::ByField(fields) => {
                    let ctx = context_param(
                        &mut generics,
                        CallerContext::Decrypt(krate),
                        which,
                        record.by_field,
                        fields,
                    );
                    (
                        by_field_body(krate, fields, plaintext, which)?,
                        ctx,
                        fields.iter().any(|f| f.uses_callers_context(which)),
                    )
                }
            };
            impls.push(impl_block(
                input,
                krate,
                &generics,
                plaintext,
                &ctx,
                uses_context,
                body,
            ));
        }
    }

    Ok(quote!(#(#impls)*))
}

enum Mode<'a> {
    /// One field is the whole plaintext's ciphertext: decrypting the record is
    /// decrypting that field.
    Whole(&'a Field),
    /// Each opened field recovers one field of the source, which is rebuilt
    /// by name.
    ByField(Vec<&'a Field>),
}

impl<'a> Mode<'a> {
    /// Which of the two shapes the `decrypt` fields describe; an error if
    /// they describe neither.
    fn classify(opened: Vec<&'a Field>, name: &Ident) -> Result<Self> {
        let by_field = opened.iter().filter(|f| f.from().is_some()).count();
        if by_field == 0 {
            if opened.len() == 1 {
                return Ok(Mode::Whole(opened[0]));
            }
            return Err(syn::Error::new_spanned(
                name,
                "several fields are marked `decrypt` but the record is one value: one plaintext \
                 cannot be recovered from two fields. Mark only the ciphertext field, or encrypt \
                 a struct field by field with `#[stash(struct = ..)]`.",
            ));
        }
        debug_assert_eq!(
            by_field,
            opened.len(),
            "every field of a `struct` derive has a `from`, and no other field does"
        );

        let mut seen: HashSet<&Member> = HashSet::with_capacity(opened.len());
        for field in &opened {
            let from = field
                .from()
                .unwrap_or_else(|| unreachable!("counted above"));
            if !seen.insert(from) {
                let name = quote!(#from);
                return Err(syn::Error::new(
                    from.span(),
                    format!("two `decrypt` fields would recover the same plaintext field `{name}`"),
                ));
            }
        }
        Ok(Mode::ByField(opened))
    }
}

fn whole_body(krate: &Path, field: &Field, plaintext: &Type, which: ContextImpl) -> TokenStream {
    let ty = &field.ty;
    let member = &field.member;
    let context = context_for(krate, field, which);
    let context_ty = field.field_context().ty(krate, which);
    quote! {
        <#ty as #krate::target::DecryptInto<#plaintext, #krate::StackCipher<__K>, #context_ty>>::decrypt_into(
            self.#member,
            __cipher,
            #context,
        )
    }
}

fn by_field_body(
    krate: &Path,
    fields: &[&Field],
    plaintext: &Type,
    which: ContextImpl,
) -> Result<TokenStream> {
    let literal = struct_literal_path(plaintext)?;

    let assign = fields.iter().map(|field| {
        let from = field.from();
        let local = &field.local;
        quote!(#from: #local)
    });

    Ok(zip_fields(
        krate,
        fields,
        which,
        |field, context| {
            let ty = &field.ty;
            let member = &field.member;
            // The plaintext field's type is not known here; it is inferred
            // from the struct literal, and the obligation checked against it
            // — spanned at the field type, so a leaf handed `()` (a `nested`
            // field) is reported at the field that needs a `context`, by the
            // trait's `on_unimplemented` since the context type is named.
            let context_ty = field.field_context().ty(krate, which);
            let call = quote_spanned! {ty.span()=>
                <#ty as #krate::target::DecryptInto<_, #krate::StackCipher<__K>, #context_ty>>::decrypt_into
            };
            quote!(#call(self.#member, __cipher, #context,))
        },
        quote!(#literal { #(#assign),* }),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{assert_contains, assert_lacks};

    fn expand(input: DeriveInput) -> Result<String> {
        derive(input).map(|tokens| tokens.to_string())
    }

    #[test]
    #[rustfmt::skip]
    fn unmarked_fields_are_chosen_by_their_types() {
        let expansion = expand(parse_quote! {
            #[stash(plaintext = u32)]
            struct Rec {
                c: StackCipherText,
                hm: EqualityTerm,
                #[stash(default)]
                v: u8,
            }
        })
        .unwrap();
        // Every derived field is a candidate, bounded and asked in turn; the
        // `default` field is neither. Once for `()` and once for
        // `NonEmpty<__T>`.
        assert_contains(&expansion, quote! {
            impl<__K> ::stack_encrypt::target::DecryptInto<u32, ::stack_encrypt::StackCipher<__K>, ()> for Rec
            where
                StackCipherText: ::stack_encrypt::target::DecryptField<u32, ::stack_encrypt::StackCipher<__K>, ()>,
                EqualityTerm: ::stack_encrypt::target::DecryptField<u32, ::stack_encrypt::StackCipher<__K>, ()>
        });
        assert_contains(&expansion, quote! {
            impl<'__ctx, __K, __T> ::stack_encrypt::target::DecryptInto<u32, ::stack_encrypt::StackCipher<__K>, ::stack_encrypt::NonEmpty<__T>> for Rec
            where
                StackCipherText: ::stack_encrypt::target::DecryptField<u32, ::stack_encrypt::StackCipher<__K>, ::stack_encrypt::NonEmpty<__T>>,
                EqualityTerm: ::stack_encrypt::target::DecryptField<u32, ::stack_encrypt::StackCipher<__K>, ::stack_encrypt::NonEmpty<__T>>,
                __T: ::stack_encrypt::IntoAad<'__ctx> + ::core::clone::Clone
        });
        assert_contains(&expansion, quote!(let Self { c: __field_0, hm: __field_1, .. } = self; let __context = &__context;));
        assert_contains(&expansion, quote! {
            ::core::option::Option::or_else(
                <StackCipherText as ::stack_encrypt::target::DecryptField<u32, ::stack_encrypt::StackCipher<__K>, ()>>::decrypt_field(
                    __field_0, __cipher, ::core::clone::Clone::clone(__context),
                ),
                move || <EqualityTerm as ::stack_encrypt::target::DecryptField<u32, ::stack_encrypt::StackCipher<__K>, ()>>::decrypt_field(
                    __field_1, __cipher, ::core::clone::Clone::clone(__context),
                )
            )
        });
        // Exactly one ciphertext, checked at the definition.
        assert_contains(&expansion, quote! {
            const _: () = {
                {
                    let __decryptable: usize = 0
                        + (<StackCipherText as ::stack_encrypt::target::Decryptable>::DECRYPTABLE as usize)
                        + (<EqualityTerm as ::stack_encrypt::target::Decryptable>::DECRYPTABLE as usize);
                    ::core::assert!(__decryptable >= 1, "`Rec` has no decryptable field: every derived field is a one-way index term, so there is nothing for DecryptInto to open");
                    ::core::assert!(__decryptable <= 1, "`Rec` has several decryptable fields: mark the one decryption opens `#[stash(decrypt)]`");
                }
            };
        });
        assert_lacks(&expansion, quote!(let () = const));
        assert_lacks(&expansion, quote!(<u8 as ::stack_encrypt::target::Decryptable>));
    }

    #[test]
    #[rustfmt::skip]
    fn a_caller_context_is_bounded_by_the_vitaminc_traits() {
        // The regression shape: the ciphertext field carries a literal and
        // a term's `DecryptField` accepts anything (it opens nothing). The
        // impl-level bound is what keeps `decrypt_into` from accepting a
        // value that is not a context at all — and the literal extends the
        // caller's context, so the ciphertext authenticates under it.
        let expansion = expand(parse_quote! {
            #[stash(plaintext = u32)]
            struct Rec {
                #[stash(context = "rec/c")]
                c: StackCipherText,
                hm: EqualityTerm,
            }
        })
        .unwrap();
        assert_contains(&expansion, quote! {
            impl<__K, __T> ::stack_encrypt::target::DecryptInto<u32, ::stack_encrypt::StackCipher<__K>, ::stack_encrypt::NonEmpty<__T>> for Rec
        });
        assert_contains(&expansion, quote! {
            __T: ::stack_encrypt::IntoAad<'static> + ::core::clone::Clone
        });
        // The literal is a compile-time `NonEmpty` under `()`, extended
        // under `NonEmpty<__T>`.
        assert_contains(&expansion, quote!(__field_0, __cipher, ::stack_encrypt::nonempty!("rec/c"),));
        assert_contains(&expansion, quote! {
            __field_0, __cipher,
            ::stack_encrypt::NonEmpty::with(::stack_encrypt::nonempty!("rec/c"), ::core::clone::Clone::clone(__context)),
        });
    }

    #[test]
    fn a_generic_record_is_checked_at_its_use() {
        let expansion = expand(parse_quote! {
            struct Tagged<T: CllwOreEncrypt> {
                c: StackCipherText,
                ob: OreTerm<T>,
            }
        })
        .unwrap();
        assert_contains(&expansion, quote!(let () = const));
        assert_lacks(&expansion, quote!(const _: ()));
    }

    #[test]
    #[rustfmt::skip]
    fn unmarked_from_fields_are_grouped_by_plaintext_field() {
        let expansion = expand(parse_quote! {
            #[stash(struct = User, context = "users")]
            struct Row {
                age: EncryptedAge,
                email: StackCipherText,
                #[stash(from = email)]
                email_eq: EqualityTerm,
            }
        })
        .unwrap();
        // One check and one opening per plaintext field; the two `email`
        // fields are asked in turn.
        assert_contains(&expansion, quote!("no field of `Row` can recover the plaintext field `age`: every field derived from it is a one-way index term"));
        assert_contains(&expansion, quote!("several fields of `Row` are derived from the plaintext field `email` and decryptable: mark the one decryption opens `#[stash(decrypt)]`"));
        assert_contains(&expansion, quote! {
            let __group_1 = ::core::option::Option::unwrap_or_else(
                ::core::option::Option::or_else(
                    <StackCipherText as ::stack_encrypt::target::DecryptField<_, ::stack_encrypt::StackCipher<__K>, ::stack_encrypt::NonEmpty<&'static str>>>::decrypt_field(
                        __field_1, __cipher, ::stack_encrypt::nonempty!("users/email"),
                    ),
                    move || <EqualityTerm as ::stack_encrypt::target::DecryptField<_, ::stack_encrypt::StackCipher<__K>, ::stack_encrypt::NonEmpty<&'static str>>>::decrypt_field(
                        __field_2, __cipher, ::stack_encrypt::nonempty!("users/email"),
                    )
                ),
                || ::stack_encrypt::target::Pending::failed(__cipher, ::stack_encrypt::Error::NotOpened,)
            );
        });
        assert_contains(&expansion, quote!(__group_0.zip(__group_1).map(|(__group_0, __group_1)| User { age: __group_0, email: __group_1 })));
        // Every field has its own context: the `()` impl uses none of the
        // caller's, so its parameter is unnamed and never borrowed; the
        // `NonEmpty<__T>` impl extends each with it.
        assert_contains(&expansion, quote! {
            impl<__K> ::stack_encrypt::target::DecryptInto<User, ::stack_encrypt::StackCipher<__K>, ()> for Row
        });
        assert_contains(&expansion, quote!(_: (),));
        assert_contains(&expansion, quote! {
            impl<__K, __T> ::stack_encrypt::target::DecryptInto<User, ::stack_encrypt::StackCipher<__K>, ::stack_encrypt::NonEmpty<__T>> for Row
        });
        assert_contains(&expansion, quote!(let __context = &__context;));
    }

    #[test]
    #[rustfmt::skip]
    fn a_struct_opens_its_fields_under_their_extended_contexts() {
        let expansion = expand(parse_quote! {
            #[stash(struct = User, context = "user")]
            struct EncryptedUser {
                age: EncryptedAge,
                email: StackCipherText,
            }
        })
        .unwrap();
        // Under `()`, the inferred literals as they are.
        assert_contains(&expansion, quote!(__field_0, __cipher, ::stack_encrypt::nonempty!("user/age"),));
        // Under `NonEmpty<__T>`, each extended with the caller's — cloned,
        // since every opened field is asked through a reference — and `__T`
        // bounded for `'static`.
        assert_contains(&expansion, quote! {
            impl<__K, __T> ::stack_encrypt::target::DecryptInto<User, ::stack_encrypt::StackCipher<__K>, ::stack_encrypt::NonEmpty<__T>> for EncryptedUser
            where
                __T: ::stack_encrypt::IntoAad<'static> + ::core::clone::Clone
        });
        assert_contains(&expansion, quote! {
            __field_0, __cipher,
            ::stack_encrypt::NonEmpty::with(::stack_encrypt::nonempty!("user/age"), ::core::clone::Clone::clone(__context)),
        });
        assert_contains(&expansion, quote! {
            __field_1, __cipher,
            ::stack_encrypt::NonEmpty::with(::stack_encrypt::nonempty!("user/email"), ::core::clone::Clone::clone(__context)),
        });
    }

    #[test]
    fn every_record_is_a_decrypt_field() {
        let expansion = expand(parse_quote! {
            #[stash(plaintext = u32)]
            struct Rec {
                #[stash(decrypt)]
                c: StackCipherText,
            }
        })
        .unwrap();
        assert_contains(
            &expansion,
            quote! {
                impl<__P, __C, __Ctx> ::stack_encrypt::target::DecryptField<__P, __C, __Ctx> for Rec
                where
                    __C: ::stack_encrypt::target::DecryptTarget,
                    Self: ::stack_encrypt::target::DecryptInto<__P, __C, __Ctx>
            },
        );
    }

    #[test]
    fn marking_a_field_turns_the_types_off() {
        let expansion = expand(parse_quote! {
            #[stash(plaintext = u32)]
            struct Rec {
                #[stash(decrypt)]
                c: StackCipherText,
                hm: EqualityTerm,
            }
        })
        .unwrap();
        assert_lacks(&expansion, quote!(Decryptable));
        assert_lacks(&expansion, quote!(DecryptField < u32));
    }

    #[test]
    fn two_whole_fields_are_ambiguous() {
        let err = expand(parse_quote! {
            #[stash(plaintext = u32)]
            struct Rec {
                #[stash(decrypt)]
                a: StackCipherText,
                #[stash(decrypt)]
                b: StackCipherText,
            }
        })
        .unwrap_err();
        assert!(err
            .to_string()
            .contains("cannot be recovered from two fields"));
    }

    #[test]
    fn duplicate_recovery_targets_are_rejected() {
        let err = expand(parse_quote! {
            #[stash(struct = User, context = "users")]
            struct Rec {
                #[stash(decrypt)]
                a: StackCipherText,
                #[stash(decrypt, from = a)]
                b: StackCipherText,
            }
        })
        .unwrap_err();
        assert!(err.to_string().contains("same plaintext field `a`"));
    }

    #[test]
    #[rustfmt::skip]
    fn a_generic_plaintext_opens_the_one_field() {
        let expansion = expand(parse_quote! {
            struct Wrapped {
                #[stash(decrypt)]
                c: StackCipherText,
                hm: EqualityTerm,
            }
        })
        .unwrap();
        assert_contains(&expansion, quote! {
            impl<__P, __K> ::stack_encrypt::target::DecryptInto<__P, ::stack_encrypt::StackCipher<__K>, ()> for Wrapped
            where
                StackCipherText: ::stack_encrypt::target::DecryptInto<__P, ::stack_encrypt::StackCipher<__K>, ()>
        });
        assert_contains(&expansion, quote! {
            impl<'__ctx, __P, __K, __T> ::stack_encrypt::target::DecryptInto<__P, ::stack_encrypt::StackCipher<__K>, ::stack_encrypt::NonEmpty<__T>> for Wrapped
            where
                StackCipherText: ::stack_encrypt::target::DecryptInto<__P, ::stack_encrypt::StackCipher<__K>, ::stack_encrypt::NonEmpty<__T>>,
                __T: ::stack_encrypt::IntoAad<'__ctx> + ::core::clone::Clone
        });
        assert_contains(&expansion, quote! {
            <StackCipherText as ::stack_encrypt::target::DecryptInto<__P, ::stack_encrypt::StackCipher<__K>, ()>>::decrypt_into(
                self.c, __cipher, __context,
            )
        });
        assert_lacks(&expansion, quote!(hm));
    }

    #[test]
    #[rustfmt::skip]
    fn whole_mode_opens_the_one_field() {
        let expansion = expand(parse_quote! {
            #[stash(plaintext = u32, plaintext = u64)]
            struct EncryptedAge {
                #[stash(decrypt)]
                c: StackCipherText,
                hm: EqualityTerm,
            }
        })
        .unwrap();
        assert_contains(&expansion, quote! {
            impl<'__ctx, __K, __T> ::stack_encrypt::target::DecryptInto<u32, ::stack_encrypt::StackCipher<__K>, ::stack_encrypt::NonEmpty<__T>> for EncryptedAge
            where
                StackCipherText: ::stack_encrypt::target::DecryptInto<u32, ::stack_encrypt::StackCipher<__K>, ::stack_encrypt::NonEmpty<__T>>
        });
        assert_contains(&expansion, quote! {
            <StackCipherText as ::stack_encrypt::target::DecryptInto<u64, ::stack_encrypt::StackCipher<__K>, ()>>::decrypt_into(
                self.c, __cipher, __context,
            )
        });
        assert_lacks(&expansion, quote!(hm));
        assert_lacks(&expansion, quote!(DecryptInto<__P, ::stack_encrypt::StackCipher));
    }

    #[test]
    #[rustfmt::skip]
    fn by_field_mode_rebuilds_the_plaintext() {
        let expansion = expand(parse_quote! {
            #[stash(struct = User<T>, context = "users")]
            struct EncryptedUser {
                #[stash(decrypt, context = "legacy/age")]
                age: EncryptedAge,
                #[stash(decrypt, nested)]
                email: EncryptedEmail,
                #[stash(from = email)]
                email_eq: EqualityTerm,
            }
        })
        .unwrap();
        assert_contains(&expansion, quote! {
            <EncryptedAge as ::stack_encrypt::target::DecryptInto<_, ::stack_encrypt::StackCipher<__K>, ::stack_encrypt::NonEmpty<&'static str>>>::decrypt_into(
                self.age, __cipher, ::stack_encrypt::nonempty!("legacy/age"),
            )
        });
        // `email` is `nested`: it is handed the caller's context as it is —
        // `()` in one impl, `NonEmpty<__T>` in the other — and its type
        // composes it with its own contexts. A `struct` derive is bounded
        // for `'static`.
        assert_contains(&expansion, quote!(self.email, __cipher, __context,));
        assert_contains(&expansion, quote! {
            impl<__K> ::stack_encrypt::target::DecryptInto<User<T>, ::stack_encrypt::StackCipher<__K>, ()> for EncryptedUser
        });
        assert_contains(&expansion, quote! {
            impl<__K, __T> ::stack_encrypt::target::DecryptInto<User<T>, ::stack_encrypt::StackCipher<__K>, ::stack_encrypt::NonEmpty<__T>> for EncryptedUser
            where
                __T: ::stack_encrypt::IntoAad<'static> + ::core::clone::Clone
        });
        assert_contains(&expansion, quote!(.map(|(__field_0, __field_1)| User::<T> { age: __field_0, email: __field_1 })));
        assert_lacks(&expansion, quote!(email_eq));
    }

    #[test]
    fn tuple_plaintexts_are_rebuilt_by_index() {
        let expansion = expand(parse_quote! {
            #[stash(struct = Pair, context = "pair")]
            struct EncryptedPair {
                #[stash(decrypt, from = 0)]
                a: StackCipherText,
                #[stash(decrypt, from = 1)]
                b: StackCipherText,
            }
        })
        .unwrap();
        assert_contains(
            &expansion,
            quote!(Pair {
                0: __field_0,
                1: __field_1
            }),
        );
    }

    #[test]
    fn duplicate_recovery_targets_by_index_are_rejected() {
        let err = expand(parse_quote! {
            #[stash(struct = Pair, context = "pair")]
            struct Rec {
                #[stash(decrypt, from = 0)]
                a: StackCipherText,
                #[stash(decrypt, from = 0)]
                b: StackCipherText,
            }
        })
        .unwrap_err();
        assert!(err.to_string().contains("same plaintext field `0`"));
    }
}
