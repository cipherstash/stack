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
    parse_quote, parse_quote_spanned, DeriveInput, Ident, LitStr, Member, Path, PathArguments,
    Result, Type,
};

use crate::shape::{zip_fields, Field, Record};

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

/// `impl DecryptInto<Plaintext, StackCipher<__K>> for Record` around `body`.
fn impl_block(
    krate: &Path,
    name: &Ident,
    ty_generics: &syn::TypeGenerics<'_>,
    impl_generics: &syn::ImplGenerics<'_>,
    where_clause: Option<&syn::WhereClause>,
    plaintext: &Type,
    body: TokenStream,
) -> TokenStream {
    quote! {
        #[automatically_derived]
        impl #impl_generics #krate::target::DecryptInto<#plaintext, #krate::StackCipher<__K>>
            for #name #ty_generics #where_clause
        {
            fn decrypt_into<'__a, '__c, __Ctx>(
                self,
                __cipher: &'__a #krate::StackCipher<__K>,
                __context: __Ctx,
            ) -> #krate::target::Pending<'__a, #plaintext, __K>
            where
                __Ctx: #krate::target::DecryptContext<'__c>,
                Self: '__a,
                #plaintext: '__a,
            {
                #body
            }
        }
    }
}

/// `impl DecryptField<__P, __C> for Record`: a derived record is a field of
/// a larger one, opened through its own `DecryptInto`.
fn decrypt_field_impl(input: &DeriveInput, krate: &Path) -> TokenStream {
    let name = &input.ident;
    let (_, ty_generics, _) = input.generics.split_for_impl();
    let mut generics = input.generics.clone();
    generics.params.push(parse_quote!(__P));
    generics.params.push(parse_quote!(__C));
    generics.make_where_clause().predicates.push(parse_quote! {
        __C: #krate::target::DecryptTarget
    });
    generics.make_where_clause().predicates.push(parse_quote! {
        Self: #krate::target::DecryptInto<__P, __C>
    });
    let (impl_generics, _, where_clause) = generics.split_for_impl();
    quote! {
        #[automatically_derived]
        impl #impl_generics #krate::target::DecryptField<__P, __C> for #name #ty_generics
            #where_clause
        {
            fn decrypt_field<'__a, '__c, __Ctx>(
                self,
                __cipher: &'__a __C,
                __context: __Ctx,
            ) -> ::core::option::Option<<__C as #krate::target::DecryptTarget>::Output<'__a, __P>>
            where
                __Ctx: #krate::target::DecryptContext<'__c>,
                Self: '__a,
                __P: '__a,
            {
                ::core::option::Option::Some(
                    <Self as #krate::target::DecryptInto<__P, __C>>::decrypt_into(
                        self, __cipher, __context,
                    ),
                )
            }
        }
    }
}

fn context_for(field: &Field) -> TokenStream {
    match field.context() {
        Some(literal) => quote!(#literal),
        None => quote!(__context),
    }
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
    fn classify(record: &'a Record, name: &Ident) -> Result<Self> {
        let candidates: Vec<&Field> = record.fields.iter().filter(|f| f.is_derived()).collect();
        let with_from = candidates.iter().filter(|f| f.from().is_some()).count();
        if with_from == 0 {
            return Ok(Auto::Whole(candidates));
        }
        if with_from != candidates.len() {
            return Err(syn::Error::new_spanned(
                name,
                "some derived fields name a plaintext field (`from = ..`) and some do not, so it \
                 is ambiguous whether decryption opens the record as a whole or rebuilds the \
                 plaintext field by field: mark the fields decryption opens `#[stash(decrypt)]`",
            ));
        }

        let mut groups: Vec<Group<'a>> = Vec::new();
        for field in candidates {
            let from = field
                .from()
                .unwrap_or_else(|| unreachable!("counted above"));
            match groups.iter_mut().find(|g| g.from == from) {
                Some(group) => group.fields.push(field),
                None => groups.push(Group {
                    from,
                    fields: vec![field],
                }),
            }
        }
        Ok(Auto::ByField(groups))
    }
}

fn automatic(input: &DeriveInput, record: &Record) -> Result<TokenStream> {
    let krate = &record.krate;
    let name = &input.ident;
    let (_, ty_generics, _) = input.generics.split_for_impl();
    let auto = Auto::classify(record, name)?;

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

    let destructure = {
        let candidates = match &auto {
            Auto::Whole(fields) => fields.clone(),
            Auto::ByField(groups) => groups
                .iter()
                .flat_map(|g| g.fields.iter().copied())
                .collect(),
        };
        let bind = candidates.iter().map(|f| {
            let member = &f.member;
            let local = &f.local;
            quote!(#member: #local)
        });
        quote! {
            let Self { #(#bind,)* .. } = self;
            let __context = &__context;
        }
    };

    if record.plaintexts.is_empty() {
        // One impl, generic over the plaintext: the record decrypts to
        // whatever its one ciphertext field decrypts to. `Record::parse` has
        // rejected `from` without a named plaintext, so this is whole mode.
        let Auto::Whole(fields) = &auto else {
            unreachable!("`from` without a named plaintext is rejected by `Record::parse`")
        };
        let plaintext: Type = parse_quote!(__P);
        let mut generics = input.generics.clone();
        generics.params.push(parse_quote!(__P));
        generics.params.push(parse_quote!(__K));
        push_field_bounds(&mut generics, krate, fields, &plaintext);
        let (impl_generics, _, where_clause) = generics.split_for_impl();
        let open = open_one(krate, name, None, fields, &plaintext);
        let body = quote!(#body_check #destructure #open);
        let block = impl_block(
            krate,
            name,
            &ty_generics,
            &impl_generics,
            where_clause,
            &plaintext,
            body,
        );
        return Ok(quote!(#block #definition_check));
    }

    let impls = record
        .plaintexts
        .iter()
        .map(|plaintext| {
            let mut generics = input.generics.clone();
            generics.params.push(parse_quote!(__K));
            let open = match &auto {
                Auto::Whole(fields) => {
                    push_field_bounds(&mut generics, krate, fields, plaintext);
                    open_one(krate, name, None, fields, plaintext)
                }
                Auto::ByField(groups) => by_group_body(krate, name, groups, plaintext)?,
            };
            let (impl_generics, _, where_clause) = generics.split_for_impl();
            let body = quote!(#body_check #destructure #open);
            Ok(impl_block(
                krate,
                name,
                &ty_generics,
                &impl_generics,
                where_clause,
                plaintext,
                body,
            ))
        })
        .collect::<Result<Vec<_>>>()?;

    Ok(quote!(#(#impls)* #definition_check))
}

/// `FieldTy: DecryptField<Plaintext, StackCipher<__K>>` for every candidate
/// field, so a record's impl exists for exactly the plaintexts its ciphertext
/// field opens to.
fn push_field_bounds(
    generics: &mut syn::Generics,
    krate: &Path,
    fields: &[&Field],
    plaintext: &Type,
) {
    let predicates = &mut generics.make_where_clause().predicates;
    for field in fields {
        let ty = &field.ty;
        // Spanned at the field type, so a type that cannot be a field of an
        // automatically decrypted record is reported there.
        predicates.push(parse_quote_spanned! {ty.span()=>
            #ty: #krate::target::DecryptField<#plaintext, #krate::StackCipher<__K>>
        });
    }
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
/// `plaintext` (`_` when it is inferred from a struct literal).
fn open_one(
    krate: &Path,
    name: &Ident,
    from: Option<&Member>,
    fields: &[&Field],
    plaintext: &Type,
) -> TokenStream {
    let mut calls = fields.iter().map(|field| {
        let ty = &field.ty;
        let local = &field.local;
        let context = match field.context() {
            Some(literal) => quote!(#literal),
            None => quote!(::core::clone::Clone::clone(__context)),
        };
        quote! {
            <#ty as #krate::target::DecryptField<#plaintext, #krate::StackCipher<__K>>>::decrypt_field(
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
    let what = match from {
        None => format!("`{name}`"),
        Some(from) => format!(
            "the plaintext field `{}` of `{name}`",
            from.to_token_stream()
        ),
    };
    let message = LitStr::new(
        &format!("exactly one field of {what} is decryptable, checked at compile time"),
        Span::call_site(),
    );
    quote!(::core::option::Option::expect(#chain, #message))
}

/// Each group's opened pending, zipped into one and mapped into a struct
/// literal of the plaintext.
fn by_group_body(
    krate: &Path,
    name: &Ident,
    groups: &[Group<'_>],
    plaintext: &Type,
) -> Result<TokenStream> {
    let literal = struct_literal_path(plaintext)?;
    let inferred: Type = parse_quote!(_);

    let locals: Vec<Ident> = (0..groups.len())
        .map(|index| Ident::new(&format!("__group_{index}"), Span::call_site()))
        .collect();
    let opens = groups.iter().zip(&locals).map(|(group, local)| {
        let open = open_one(krate, name, Some(group.from), &group.fields, &inferred);
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
    let (_, ty_generics, _) = input.generics.split_for_impl();

    let opened: Vec<&Field> = record.fields.iter().filter(|f| f.decrypt).collect();
    let mode = Mode::classify(opened, name)?;

    if record.plaintexts.is_empty() {
        // One impl, generic over the plaintext: the record decrypts to
        // whatever its opened field decrypts to. Only the whole-plaintext
        // mode can be generic — rebuilding field by field needs a struct
        // literal, and therefore a name — and `Record::parse` has already
        // rejected `from` without one.
        let Mode::Whole(field) = &mode else {
            unreachable!("`from` without a named plaintext is rejected by `Record::parse`")
        };
        let plaintext: Type = parse_quote!(__P);
        let ty = &field.ty;
        let mut generics = input.generics.clone();
        generics.params.push(parse_quote!(__P));
        generics.params.push(parse_quote!(__K));
        generics.make_where_clause().predicates.push(parse_quote! {
            #ty: #krate::target::DecryptInto<__P, #krate::StackCipher<__K>>
        });
        let (impl_generics, _, where_clause) = generics.split_for_impl();
        let body = whole_body(krate, field, &plaintext);
        return Ok(impl_block(
            krate,
            name,
            &ty_generics,
            &impl_generics,
            where_clause,
            &plaintext,
            body,
        ));
    }

    let impls = record
        .plaintexts
        .iter()
        .map(|plaintext| {
            let mut generics = input.generics.clone();
            generics.params.push(parse_quote!(__K));
            let body = match &mode {
                Mode::Whole(field) => {
                    let ty = &field.ty;
                    generics.make_where_clause().predicates.push(parse_quote! {
                        #ty: #krate::target::DecryptInto<#plaintext, #krate::StackCipher<__K>>
                    });
                    whole_body(krate, field, plaintext)
                }
                Mode::ByField(fields) => by_field_body(krate, fields, plaintext)?,
            };
            let (impl_generics, _, where_clause) = generics.split_for_impl();
            Ok(impl_block(
                krate,
                name,
                &ty_generics,
                &impl_generics,
                where_clause,
                plaintext,
                body,
            ))
        })
        .collect::<Result<Vec<_>>>()?;

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
                "several fields are marked `decrypt` but none names a plaintext field: one \
                 plaintext cannot be recovered from two fields. Either mark only the ciphertext \
                 field, or give each a `from = ..` so decryption rebuilds the plaintext field by \
                 field.",
            ));
        }
        if by_field != opened.len() {
            return Err(syn::Error::new_spanned(
                name,
                "`decrypt` fields must either all name a plaintext field (`from = ..`) or be a \
                 single field opened as the whole plaintext; this record mixes the two",
            ));
        }

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

fn whole_body(krate: &Path, field: &Field, plaintext: &Type) -> TokenStream {
    let ty = &field.ty;
    let member = &field.member;
    let context = context_for(field);
    quote! {
        <#ty as #krate::target::DecryptInto<#plaintext, #krate::StackCipher<__K>>>::decrypt_into(
            self.#member,
            __cipher,
            #context,
        )
    }
}

fn by_field_body(krate: &Path, fields: &[&Field], plaintext: &Type) -> Result<TokenStream> {
    let literal = struct_literal_path(plaintext)?;

    let assign = fields.iter().map(|field| {
        let from = field.from();
        let local = &field.local;
        quote!(#from: #local)
    });

    Ok(zip_fields(
        fields,
        |field, context| {
            let ty = &field.ty;
            let member = &field.member;
            // The plaintext field's type is not known here; it is inferred
            // from the struct literal, and the obligation checked against it.
            quote! {
                <#ty as #krate::target::DecryptInto<_, #krate::StackCipher<__K>>>::decrypt_into(
                    self.#member,
                    __cipher,
                    #context,
                )
            }
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
        // `default` field is neither.
        assert_contains(&expansion, quote! {
            where
                StackCipherText: ::stack_encrypt::target::DecryptField<u32, ::stack_encrypt::StackCipher<__K>>,
                EqualityTerm: ::stack_encrypt::target::DecryptField<u32, ::stack_encrypt::StackCipher<__K>>
        });
        assert_contains(&expansion, quote!(let Self { c: __field_0, hm: __field_1, .. } = self;));
        assert_contains(&expansion, quote! {
            ::core::option::Option::or_else(
                <StackCipherText as ::stack_encrypt::target::DecryptField<u32, ::stack_encrypt::StackCipher<__K>>>::decrypt_field(
                    __field_0, __cipher, ::core::clone::Clone::clone(__context),
                ),
                move || <EqualityTerm as ::stack_encrypt::target::DecryptField<u32, ::stack_encrypt::StackCipher<__K>>>::decrypt_field(
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
            #[stash(plaintext = User)]
            struct Row {
                #[stash(from = age, context = "users/age")]
                age: EncryptedAge,
                #[stash(from = email, context = "users/email")]
                email: StackCipherText,
                #[stash(from = email, context = "users/email")]
                email_eq: EqualityTerm,
            }
        })
        .unwrap();
        // One check and one opening per plaintext field; the two `email`
        // fields are asked in turn.
        assert_contains(&expansion, quote!("no field of `Row` can recover the plaintext field `age`: every field derived from it is a one-way index term"));
        assert_contains(&expansion, quote!("several fields of `Row` are derived from the plaintext field `email` and decryptable: mark the one decryption opens `#[stash(decrypt)]`"));
        assert_contains(&expansion, quote! {
            let __group_1 = ::core::option::Option::expect(
                ::core::option::Option::or_else(
                    <StackCipherText as ::stack_encrypt::target::DecryptField<_, ::stack_encrypt::StackCipher<__K>>>::decrypt_field(
                        __field_1, __cipher, "users/email",
                    ),
                    move || <EqualityTerm as ::stack_encrypt::target::DecryptField<_, ::stack_encrypt::StackCipher<__K>>>::decrypt_field(
                        __field_2, __cipher, "users/email",
                    )
                ),
                "exactly one field of the plaintext field `email` of `Row` is decryptable, checked at compile time"
            );
        });
        assert_contains(&expansion, quote!(__group_0.zip(__group_1).map(|(__group_0, __group_1)| User { age: __group_0, email: __group_1 })));
    }

    #[test]
    fn a_record_mixing_from_and_whole_fields_must_be_marked() {
        let err = expand(parse_quote! {
            #[stash(plaintext = User)]
            struct Row {
                #[stash(from = email)]
                email: StackCipherText,
                hm: EqualityTerm,
            }
        })
        .unwrap_err();
        assert!(err
            .to_string()
            .contains("ambiguous whether decryption opens"));
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
                impl<__P, __C> ::stack_encrypt::target::DecryptField<__P, __C> for Rec
                where
                    __C: ::stack_encrypt::target::DecryptTarget,
                    Self: ::stack_encrypt::target::DecryptInto<__P, __C>
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
    fn mixed_modes_are_rejected() {
        let err = expand(parse_quote! {
            #[stash(plaintext = User)]
            struct Rec {
                #[stash(decrypt, from = a)]
                a: StackCipherText,
                #[stash(decrypt)]
                b: StackCipherText,
            }
        })
        .unwrap_err();
        assert!(err.to_string().contains("mixes the two"));
    }

    #[test]
    fn duplicate_recovery_targets_are_rejected() {
        let err = expand(parse_quote! {
            #[stash(plaintext = User)]
            struct Rec {
                #[stash(decrypt, from = a)]
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
            impl<__P, __K> ::stack_encrypt::target::DecryptInto<__P, ::stack_encrypt::StackCipher<__K>> for Wrapped
            where
                StackCipherText: ::stack_encrypt::target::DecryptInto<__P, ::stack_encrypt::StackCipher<__K>>
        });
        assert_contains(&expansion, quote! {
            <StackCipherText as ::stack_encrypt::target::DecryptInto<__P, ::stack_encrypt::StackCipher<__K>>>::decrypt_into(
                self.c, __cipher, __context,
            )
        });
        assert_lacks(&expansion, quote!(hm));
    }

    #[test]
    fn a_generic_plaintext_cannot_be_rebuilt_field_by_field() {
        let err = expand(parse_quote! {
            struct Row {
                #[stash(decrypt, from = age)]
                age: EncryptedAge,
            }
        })
        .unwrap_err();
        // `Record::parse` catches `from` without a named plaintext first;
        // either message says what to add.
        assert!(err.to_string().contains("plaintext type must be named"));
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
            impl<__K> ::stack_encrypt::target::DecryptInto<u32, ::stack_encrypt::StackCipher<__K>> for EncryptedAge
            where
                StackCipherText: ::stack_encrypt::target::DecryptInto<u32, ::stack_encrypt::StackCipher<__K>>
        });
        assert_contains(&expansion, quote! {
            <StackCipherText as ::stack_encrypt::target::DecryptInto<u64, ::stack_encrypt::StackCipher<__K>>>::decrypt_into(
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
            #[stash(plaintext = User<T>)]
            struct EncryptedUser {
                #[stash(decrypt, from = age, context = "users/age")]
                age: EncryptedAge,
                #[stash(decrypt, from = email)]
                email: StackCipherText,
                #[stash(from = email, context = "users/email")]
                email_eq: EqualityTerm,
            }
        })
        .unwrap();
        assert_contains(&expansion, quote! {
            <EncryptedAge as ::stack_encrypt::target::DecryptInto<_, ::stack_encrypt::StackCipher<__K>>>::decrypt_into(
                self.age, __cipher, "users/age",
            )
        });
        assert_contains(&expansion, quote!(self.email, __cipher, __context,));
        assert_contains(&expansion, quote!(.map(|(__field_0, __field_1)| User::<T> { age: __field_0, email: __field_1 })));
        assert_lacks(&expansion, quote!(email_eq));
    }

    #[test]
    fn tuple_plaintexts_are_rebuilt_by_index() {
        let expansion = expand(parse_quote! {
            #[stash(plaintext = Pair)]
            struct EncryptedPair {
                #[stash(decrypt, from = 0, context = "pair/0")]
                a: StackCipherText,
                #[stash(decrypt, from = 1, context = "pair/1")]
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
            #[stash(plaintext = Pair)]
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
