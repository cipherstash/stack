//! Expansion of `#[derive(EncryptFrom)]`.

use proc_macro2::TokenStream;
use quote::{quote, quote_spanned};
use syn::spanned::Spanned;
use syn::{parse_quote, parse_quote_spanned, DeriveInput, Generics, Path, Result, Type};

use crate::shape::{
    push_context_generics, trait_impl, zip_fields, CallerContext, Field, Kind, Record,
};

pub(crate) fn derive(input: DeriveInput) -> Result<TokenStream> {
    let record = Record::parse(&input)?;
    let krate = &record.krate;
    let derived = record.derived();

    let decryptable = decryptable_impl(&input, &record, &derived);

    if record.plaintexts.is_empty() {
        // One impl, generic over the source: the record accepts exactly the
        // sources every derived field accepts, which the where clause spells
        // out so a mismatch is reported against the field type.
        let source: Type = parse_quote!(__S);
        let mut generics = input.generics.clone();
        generics.params.push(parse_quote!(__S));
        generics.params.push(parse_quote!(__K));
        push_field_bounds(&mut generics, krate, &derived, &source);
        let ctx = push_context_generics(&mut generics, CallerContext::Encrypt(krate), &derived);
        let body = body(krate, &record, &derived, &source);
        let block = impl_block(&input, krate, &generics, &source, &ctx, body);
        return Ok(quote!(#block #decryptable));
    }

    // One impl per listed source. Fields derived from the whole source get a
    // where clause as above; `from = ..` fields reach into the source, so
    // their obligations are checked in the body against the actual field.
    let impls = record.plaintexts.iter().map(|source| {
        let mut generics = input.generics.clone();
        generics.params.push(parse_quote!(__K));
        push_field_bounds(&mut generics, krate, &derived, source);
        let ctx = push_context_generics(&mut generics, CallerContext::Encrypt(krate), &derived);
        let body = body(krate, &record, &derived, source);
        impl_block(&input, krate, &generics, source, &ctx, body)
    });

    Ok(quote!(#(#impls)* #decryptable))
}

/// `impl EncryptFrom<Source, StackCipher<__K>, Ctx> for Record` around
/// `body`; `ctx` is `__Ctx` or `()` ([`push_context_generics`]).
fn impl_block(
    input: &DeriveInput,
    krate: &Path,
    generics: &Generics,
    source: &Type,
    ctx: &Type,
    body: TokenStream,
) -> TokenStream {
    trait_impl(
        input,
        generics,
        quote!(#krate::target::EncryptFrom<#source, #krate::StackCipher<__K>, #ctx>),
        quote! {
            fn encrypt_from<'__a>(
                __source: &'__a #source,
                __cipher: &'__a #krate::StackCipher<__K>,
                __context: #ctx,
            ) -> #krate::target::Pending<'__a, Self, __K>
            where
                Self: '__a,
            {
                #body
            }
        },
    )
}

/// `impl Decryptable for Record`: a record is decryptable if any derived
/// field is. This is what lets a record sit inside a row whose
/// `DecryptInto` derive finds its ciphertext fields on its own.
///
/// In the explicit mode — any field marked `#[stash(decrypt)]` — the record
/// is decryptable outright: the marker exists precisely so the other field
/// types need not be `Decryptable`, so probing them here would reintroduce
/// the bound the marker removes (and fail to compile for the documented
/// opaque-field shape).
fn decryptable_impl(input: &DeriveInput, record: &Record, derived: &[&Field]) -> TokenStream {
    let krate = &record.krate;
    let name = &input.ident;
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();
    let value = if record.fields.iter().any(|f| f.decrypt) {
        quote!(true)
    } else {
        let terms = derived.iter().map(|field| {
            let ty = &field.ty;
            // Spanned at the field type: a type that is not `Decryptable`
            // is reported there, not at the derive.
            quote_spanned!(ty.span()=> || <#ty as #krate::target::Decryptable>::DECRYPTABLE)
        });
        quote!(false #(#terms)*)
    };
    quote! {
        #[automatically_derived]
        impl #impl_generics #krate::target::Decryptable for #name #ty_generics #where_clause {
            const DECRYPTABLE: bool = #value;
        }
    }
}

/// `FieldTy: EncryptFrom<Source, StackCipher<__K>, Ctx>` for every field
/// derived from the whole source, under the context it is derived under —
/// its literal's, or the caller's `__Ctx`, which is how a record inherits
/// its leaves' demand for a supplied context.
fn push_field_bounds(generics: &mut Generics, krate: &Path, derived: &[&Field], source: &Type) {
    let predicates = &mut generics.make_where_clause().predicates;
    for field in derived.iter().filter(|f| f.from().is_none()) {
        let ty = &field.ty;
        let context = field.field_context().ty();
        // Spanned at the field type, so a type that is not an encrypted form
        // of the source is reported there, not at the derive.
        predicates.push(parse_quote_spanned! {ty.span()=>
            #ty: #krate::target::EncryptFrom<#source, #krate::StackCipher<__K>, #context>
        });
    }
}

/// The method body: every derived field's pending, zipped into one, mapped
/// into `Self`.
fn body(krate: &Path, record: &Record, derived: &[&Field], source: &Type) -> TokenStream {
    let assign = record.fields.iter().map(|field| {
        let member = &field.member;
        match &field.kind {
            Kind::Derived { .. } => {
                let local = &field.local;
                quote!(#member: #local)
            }
            Kind::Default(Some(expr)) => quote!(#member: #expr),
            Kind::Default(None) => quote!(#member: ::core::default::Default::default()),
        }
    });

    zip_fields(
        derived,
        |field, context| {
            let ty = &field.ty;
            // A `from` field's source type is not known here; it is inferred
            // from the field expression, and the obligation checked there —
            // spanned at the field type, so a leaf handed `()` (no literal)
            // is reported at the field that needs a `context`.
            let (source_expr, source_ty): (TokenStream, TokenStream) = match field.from() {
                Some(from) => (quote!(&__source.#from), quote!(_)),
                None => (quote!(__source), quote!(#source)),
            };
            let call = quote_spanned! {ty.span()=>
                <#ty as #krate::target::EncryptFrom<#source_ty, #krate::StackCipher<__K>, _>>::encrypt_from
            };
            quote!(#call(#source_expr, __cipher, #context,))
        },
        quote!(Self { #(#assign),* }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{assert_contains, assert_lacks};

    fn expand(input: DeriveInput) -> String {
        derive(input).unwrap().to_string()
    }

    #[test]
    #[rustfmt::skip]
    fn a_record_is_decryptable_if_any_derived_field_is() {
        let expansion = expand(parse_quote! {
            struct EncryptedAge {
                c: StackCipherText,
                hm: EqualityTerm,
                #[stash(default)]
                v: u8,
            }
        });
        assert_contains(&expansion, quote! {
            impl ::stack_encrypt::target::Decryptable for EncryptedAge {
                const DECRYPTABLE: bool = false
                    || <StackCipherText as ::stack_encrypt::target::Decryptable>::DECRYPTABLE
                    || <EqualityTerm as ::stack_encrypt::target::Decryptable>::DECRYPTABLE;
            }
        });
        assert_lacks(&expansion, quote!(<u8 as ::stack_encrypt::target::Decryptable>));
    }

    #[test]
    #[rustfmt::skip]
    fn an_explicit_decrypt_marker_makes_the_record_decryptable_outright() {
        // The documented explicit-mode shape: the marker frees the other
        // field types from `Decryptable`, so the emitted impl must not
        // probe them.
        let expansion = expand(parse_quote! {
            #[stash(plaintext = u32)]
            struct Rec {
                #[stash(decrypt)]
                c: StackCipherText,
                opaque: OpaqueTerm,
            }
        });
        assert_contains(&expansion, quote! {
            impl ::stack_encrypt::target::Decryptable for Rec {
                const DECRYPTABLE: bool = true;
            }
        });
        assert_lacks(&expansion, quote!(<OpaqueTerm as ::stack_encrypt::target::Decryptable>));
        assert_lacks(&expansion, quote!(<StackCipherText as ::stack_encrypt::target::Decryptable>));
    }

    #[test]
    #[rustfmt::skip]
    fn generic_source_bounds_every_whole_source_field() {
        let expansion = expand(parse_quote! {
            struct EncryptedAge {
                c: StackCipherText,
                hm: EqualityTerm,
            }
        });
        // Both fields take the caller's context: the impl is generic over
        // it, bounded `EncryptContext` so a third-party leaf that is generic
        // over its context cannot smuggle a non-context value through the
        // record ([`CallerContext::Encrypt`]).
        assert_contains(&expansion, quote! {
            impl<'__ctx, __S, __K, __Ctx> ::stack_encrypt::target::EncryptFrom<__S, ::stack_encrypt::StackCipher<__K>, __Ctx>
                for EncryptedAge
            where
                StackCipherText: ::stack_encrypt::target::EncryptFrom<__S, ::stack_encrypt::StackCipher<__K>, __Ctx>,
                EqualityTerm: ::stack_encrypt::target::EncryptFrom<__S, ::stack_encrypt::StackCipher<__K>, __Ctx>,
                __Ctx: ::stack_encrypt::target::EncryptContext<'__ctx>
        });
        // The first field clones the record context, the last takes it.
        assert_contains(&expansion, quote!(__source, __cipher, ::core::clone::Clone::clone(&__context),));
        assert_contains(&expansion, quote!(__source, __cipher, __context,));
        assert_contains(&expansion, quote!(.map(|(__field_0, __field_1)| Self { c: __field_0, hm: __field_1 })));
    }

    #[test]
    #[rustfmt::skip]
    fn a_caller_context_must_be_an_encrypt_context() {
        // The regression shape, mirroring the decrypt-side test: the
        // ciphertext field carries a literal, so only the term field sees
        // the caller's context — and a third-party leaf generic over its
        // context demands nothing of it. The impl-level bound is what keeps
        // `EncryptFrom::encrypt_from` from accepting, and silently
        // discarding, a value that is not a context at all.
        let expansion = expand(parse_quote! {
            #[stash(plaintext = u32)]
            struct Rec {
                #[stash(context = "rec/c")]
                c: StackCipherText,
                hm: EqualityTerm,
            }
        });
        assert_contains(&expansion, quote! {
            impl<'__ctx, __K, __Ctx> ::stack_encrypt::target::EncryptFrom<u32, ::stack_encrypt::StackCipher<__K>, __Ctx> for Rec
        });
        assert_contains(&expansion, quote! {
            __Ctx: ::stack_encrypt::target::EncryptContext<'__ctx>
        });
    }

    #[test]
    #[rustfmt::skip]
    fn listed_sources_get_one_impl_each() {
        let expansion = expand(parse_quote! {
            #[stash(plaintext = i32, plaintext = i64)]
            struct IntegerOrdOre {
                c: StackCipherText,
                #[stash(default = SchemaVersion::V3)]
                v: SchemaVersion,
            }
        });
        assert_contains(&expansion, quote! {
            impl<'__ctx, __K, __Ctx> ::stack_encrypt::target::EncryptFrom<i32, ::stack_encrypt::StackCipher<__K>, __Ctx> for IntegerOrdOre
        });
        assert_contains(&expansion, quote! {
            impl<'__ctx, __K, __Ctx> ::stack_encrypt::target::EncryptFrom<i64, ::stack_encrypt::StackCipher<__K>, __Ctx> for IntegerOrdOre
        });
        assert_contains(&expansion, quote!(Self { c: __field_0, v: SchemaVersion::V3 }));
        assert_lacks(&expansion, quote!(__S));
    }

    #[test]
    #[rustfmt::skip]
    fn row_fields_reach_into_the_source_under_their_own_context() {
        let expansion = expand(parse_quote! {
            #[stash(plaintext = User)]
            struct EncryptedUser {
                #[stash(from = age, context = "users/age")]
                age: EncryptedAge,
                #[stash(from = email, context = "users/email")]
                email: StackCipherText,
            }
        });
        assert_contains(&expansion, quote! {
            <EncryptedAge as ::stack_encrypt::target::EncryptFrom<_, ::stack_encrypt::StackCipher<__K>, _>>::encrypt_from(
                &__source.age, __cipher, "users/age",
            )
        });
        // No field takes the record's context, so the impl is for `()`
        // exactly: `encrypt_into(&cipher)` compiles, and only that.
        assert_lacks(&expansion, quote!(&__context));
        assert_contains(&expansion, quote! {
            impl<__K> ::stack_encrypt::target::EncryptFrom<User, ::stack_encrypt::StackCipher<__K>, ()> for EncryptedUser
        });
        assert_lacks(&expansion, quote!(__Ctx));
        // `from` fields carry no where clause: the source field's type is
        // unknown here, so the obligation is checked in the body instead.
        assert!(
            expansion.replace(' ', "").contains("forEncryptedUser{fnencrypt_from"),
            "unexpected where clause on the impl:\n{expansion}"
        );
    }

    #[test]
    #[rustfmt::skip]
    fn a_from_field_without_a_literal_is_handed_no_context() {
        let expansion = expand(parse_quote! {
            #[stash(plaintext = User)]
            struct EncryptedUser {
                #[stash(from = age)]
                age: EncryptedAge,
            }
        });
        // The caller's context never reaches a `from` field: the field gets
        // `()`, and its type decides (in the body, against the plaintext
        // field's type) whether that is acceptable. The row itself is then
        // for `()` too.
        assert_contains(&expansion, quote!(&__source.age, __cipher, (),));
        assert_contains(&expansion, quote! {
            impl<__K> ::stack_encrypt::target::EncryptFrom<User, ::stack_encrypt::StackCipher<__K>, ()> for EncryptedUser
        });
        assert_lacks(&expansion, quote!(SuppliedContext));
    }

    #[test]
    #[rustfmt::skip]
    fn a_whole_source_field_with_a_literal_is_bounded_under_it() {
        let expansion = expand(parse_quote! {
            #[stash(plaintext = u32)]
            struct Rec {
                #[stash(context = "rec/c")]
                c: StackCipherText,
            }
        });
        assert_contains(&expansion, quote! {
            where
                StackCipherText: ::stack_encrypt::target::EncryptFrom<u32, ::stack_encrypt::StackCipher<__K>, &'static str>
        });
        assert_lacks(&expansion, quote!(EncryptContext));
    }

    #[test]
    #[rustfmt::skip]
    fn a_row_needs_no_attributes_on_its_fields() {
        let expansion = expand(parse_quote! {
            #[stash(row = User)]
            struct EncryptedUser {
                age: EncryptedAge,
                email: StackCipherText,
            }
        });
        assert_contains(&expansion, quote! {
            <EncryptedAge as ::stack_encrypt::target::EncryptFrom<_, ::stack_encrypt::StackCipher<__K>, _>>::encrypt_from(
                &__source.age, __cipher, "user/age",
            )
        });
        assert_contains(&expansion, quote!(&__source.email, __cipher, "user/email",));
        assert_contains(&expansion, quote! {
            impl<__K> ::stack_encrypt::target::EncryptFrom<User, ::stack_encrypt::StackCipher<__K>, ()> for EncryptedUser
        });
    }

    #[test]
    fn tuple_plaintexts_are_reached_by_index() {
        let expansion = expand(parse_quote! {
            #[stash(plaintext = Pair)]
            struct EncryptedPair {
                #[stash(from = 1, context = "pair/1")]
                b: StackCipherText,
            }
        });
        assert_contains(&expansion, quote!(&__source.1, __cipher, "pair/1",));
    }

    #[test]
    fn a_single_derived_field_still_maps_into_self() {
        let expansion = expand(parse_quote! {
            struct Wrapped {
                c: StackCipherText,
            }
        });
        assert_contains(&expansion, quote!(.map(|__field_0| Self { c: __field_0 })));
        assert_lacks(&expansion, quote!(.zip));
    }

    #[test]
    fn tuple_structs_assign_by_index() {
        let expansion = expand(parse_quote! {
            struct Pair(StackCipherText, EqualityTerm);
        });
        assert_contains(
            &expansion,
            quote!(Self {
                0: __field_0,
                1: __field_1
            }),
        );
    }
}
