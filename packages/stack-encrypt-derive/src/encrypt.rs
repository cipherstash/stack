//! Expansion of `#[derive(EncryptFrom)]`.

use proc_macro2::TokenStream;
use quote::{quote, quote_spanned};
use syn::spanned::Spanned;
use syn::{parse_quote, DeriveInput, Generics, Path, Result, Type};

use crate::shape::{
    context_param, impl_sources, push_field_bounds, trait_impl, zip_fields, CallerContext,
    ContextImpl, Field, FieldBound, Kind, Record,
};

pub(crate) fn derive(input: DeriveInput) -> Result<TokenStream> {
    let record = Record::parse(&input)?;
    let krate = &record.krate;
    let derived = record.derived();
    // Fields derived from the whole source get a where clause; `from = ..`
    // fields reach into the source, so their obligations are checked in the
    // body against the actual field.
    let whole: Vec<&Field> = derived
        .iter()
        .filter(|f| f.from().is_none())
        .copied()
        .collect();

    let decryptable = decryptable_impl(&input, &record, &derived);

    // One impl per listed source, or one generic over it — and each of those
    // twice, for `()` and for `NonEmpty<__T>` (see `context_param`). The
    // record accepts exactly the sources every derived field accepts, which
    // the where clause spells out so a mismatch is reported against the
    // field type.
    let (sources, generic) = impl_sources(&record, parse_quote!(__S));
    let mut impls = Vec::with_capacity(sources.len() * 2);
    for source in &sources {
        for which in ContextImpl::BOTH {
            let mut generics = input.generics.clone();
            if generic {
                generics.params.push(parse_quote!(__S));
            }
            generics.params.push(parse_quote!(__K));
            push_field_bounds(
                &mut generics,
                krate,
                &whole,
                source,
                FieldBound::Encrypt,
                which,
            );
            let ctx = context_param(
                &mut generics,
                CallerContext::Encrypt(krate),
                which,
                record.by_field,
                &derived,
            );
            let uses_context = derived.iter().any(|f| f.uses_callers_context(which));
            let body = body(krate, &record, &derived, source, which);
            impls.push(impl_block(
                &input,
                krate,
                &generics,
                source,
                &ctx,
                uses_context,
                body,
            ));
        }
    }

    Ok(quote!(#(#impls)* #decryptable))
}

/// `impl EncryptFrom<Source, StackCipher<__K>, Ctx> for Record` around
/// `body`; `ctx` is `()` or `NonEmpty<__T>` ([`context_param`]). The
/// context parameter is unnamed when no field uses it — every field of the
/// `()` impl of a `struct` derive carries its own — so the expansion warns
/// of nothing.
fn impl_block(
    input: &DeriveInput,
    krate: &Path,
    generics: &Generics,
    source: &Type,
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
        quote!(#krate::target::EncryptFrom<#source, #krate::StackCipher<__K>, #ctx>),
        quote! {
            fn encrypt_from<'__a>(
                __source: &'__a #source,
                __cipher: &'__a #krate::StackCipher<__K>,
                #context: #ctx,
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

/// The method body: every derived field's pending, zipped into one, mapped
/// into `Self`.
fn body(
    krate: &Path,
    record: &Record,
    derived: &[&Field],
    source: &Type,
    which: ContextImpl,
) -> TokenStream {
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
        krate,
        derived,
        which,
        |field, context| {
            let ty = &field.ty;
            // A `from` field's source type is not known here; it is inferred
            // from the field expression, and the obligation checked there —
            // spanned at the field type, so a leaf handed `()` (a `nested`
            // field) is reported at the field that needs a `context`. The
            // context type is named, not inferred, so that report is the
            // trait's own (`EncryptFrom`'s `on_unimplemented`) rather than
            // an argument type mismatch inside the expansion.
            let (source_expr, source_ty): (TokenStream, TokenStream) = match field.from() {
                Some(from) => (quote!(&__source.#from), quote!(_)),
                None => (quote!(__source), quote!(#source)),
            };
            let context_ty = field.field_context().ty(krate, which);
            let call = quote_spanned! {ty.span()=>
                <#ty as #krate::target::EncryptFrom<#source_ty, #krate::StackCipher<__K>, #context_ty>>::encrypt_from
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
    fn a_record_gets_one_impl_for_unit_and_one_for_non_empty() {
        let expansion = expand(parse_quote! {
            struct EncryptedAge {
                c: StackCipherText,
                hm: EqualityTerm,
            }
        });
        // Both fields take the caller's context as it is. Under `()` the
        // field bounds are unsatisfiable for a leaf — which is the compile
        // error `encrypt_into` reports — and under `NonEmpty<__T>` the inner
        // type is bounded by the vitaminc context traits for a free
        // lifetime: nothing here extends a literal, so a borrowed context
        // passes through.
        assert_contains(&expansion, quote! {
            impl<__S, __K> ::stack_encrypt::target::EncryptFrom<__S, ::stack_encrypt::StackCipher<__K>, ()>
                for EncryptedAge
            where
                StackCipherText: ::stack_encrypt::target::EncryptFrom<__S, ::stack_encrypt::StackCipher<__K>, ()>,
                EqualityTerm: ::stack_encrypt::target::EncryptFrom<__S, ::stack_encrypt::StackCipher<__K>, ()>
        });
        assert_contains(&expansion, quote!(__context: (),));
        assert_contains(&expansion, quote! {
            impl<'__ctx, __S, __K, __T> ::stack_encrypt::target::EncryptFrom<__S, ::stack_encrypt::StackCipher<__K>, ::stack_encrypt::NonEmpty<__T>>
                for EncryptedAge
            where
                StackCipherText: ::stack_encrypt::target::EncryptFrom<__S, ::stack_encrypt::StackCipher<__K>, ::stack_encrypt::NonEmpty<__T>>,
                EqualityTerm: ::stack_encrypt::target::EncryptFrom<__S, ::stack_encrypt::StackCipher<__K>, ::stack_encrypt::NonEmpty<__T>>,
                __T: ::stack_encrypt::IntoAad<'__ctx> + ::stack_encrypt::IntoPrfContext<'__ctx> + ::core::clone::Clone
        });
        // The first field clones the caller's context, the last takes it.
        assert_contains(&expansion, quote!(__source, __cipher, ::core::clone::Clone::clone(&__context),));
        assert_contains(&expansion, quote!(__source, __cipher, __context,));
        assert_contains(&expansion, quote!(.map(|(__field_0, __field_1)| Self { c: __field_0, hm: __field_1 })));
    }

    #[test]
    #[rustfmt::skip]
    fn a_literal_context_is_extended_by_the_callers() {
        let expansion = expand(parse_quote! {
            #[stash(plaintext = u32)]
            struct Pinned {
                #[stash(context = "legacy/age")]
                c: StackCipherText,
            }
        });
        // Under `()`: the literal as it is, a compile-time `NonEmpty`, and
        // the (unit) context parameter unnamed.
        assert_contains(&expansion, quote! {
            impl<__K> ::stack_encrypt::target::EncryptFrom<u32, ::stack_encrypt::StackCipher<__K>, ()> for Pinned
            where
                StackCipherText: ::stack_encrypt::target::EncryptFrom<u32, ::stack_encrypt::StackCipher<__K>, ::stack_encrypt::NonEmpty<&'static str>>
        });
        assert_contains(&expansion, quote!(_: (),));
        assert_contains(&expansion, quote!(__source, __cipher, ::stack_encrypt::nonempty!("legacy/age"),));
        // Under `NonEmpty<__T>`: the literal extended with the caller's, so
        // no record accepts a context and then discards it; the literal
        // fixes the pair's lifetime, so `__T` is bounded for `'static`.
        assert_contains(&expansion, quote! {
            impl<__K, __T> ::stack_encrypt::target::EncryptFrom<u32, ::stack_encrypt::StackCipher<__K>, ::stack_encrypt::NonEmpty<__T>> for Pinned
            where
                StackCipherText: ::stack_encrypt::target::EncryptFrom<u32, ::stack_encrypt::StackCipher<__K>, ::stack_encrypt::NonEmpty<(&'static str, ::stack_encrypt::NonEmpty<__T>)>>,
                __T: ::stack_encrypt::IntoAad<'static> + ::stack_encrypt::IntoPrfContext<'static> + ::core::clone::Clone
        });
        assert_contains(&expansion, quote! {
            __source, __cipher,
            ::stack_encrypt::NonEmpty::with(::stack_encrypt::nonempty!("legacy/age"), __context),
        });
        assert_lacks(&expansion, quote!(_: ::stack_encrypt::NonEmpty<__T>));
    }

    #[test]
    #[rustfmt::skip]
    fn listed_sources_get_two_impls_each() {
        let expansion = expand(parse_quote! {
            #[stash(plaintext = i32, plaintext = i64)]
            struct IntegerOrdOre {
                c: StackCipherText,
                #[stash(default = SchemaVersion::V3)]
                v: SchemaVersion,
            }
        });
        for source in [quote!(i32), quote!(i64)] {
            assert_contains(&expansion, quote! {
                impl<__K> ::stack_encrypt::target::EncryptFrom<#source, ::stack_encrypt::StackCipher<__K>, ()> for IntegerOrdOre
            });
            assert_contains(&expansion, quote! {
                impl<'__ctx, __K, __T> ::stack_encrypt::target::EncryptFrom<#source, ::stack_encrypt::StackCipher<__K>, ::stack_encrypt::NonEmpty<__T>> for IntegerOrdOre
            });
        }
        assert_contains(&expansion, quote!(Self { c: __field_0, v: SchemaVersion::V3 }));
        assert_lacks(&expansion, quote!(__S));
    }

    #[test]
    #[rustfmt::skip]
    fn a_struct_extends_its_inferred_contexts_with_the_callers() {
        let expansion = expand(parse_quote! {
            #[stash(struct = User, context = "user")]
            struct EncryptedUser {
                age: EncryptedAge,
                email: StackCipherText,
            }
        });
        // Under `()`, the inferred contexts as they are; no field uses the
        // caller's, so the parameter is unnamed. `from` fields carry no
        // where clause: the plaintext field's type is unknown here, so the
        // obligation is checked in the body instead.
        assert_contains(&expansion, quote! {
            impl<__K> ::stack_encrypt::target::EncryptFrom<User, ::stack_encrypt::StackCipher<__K>, ()> for EncryptedUser
        });
        assert_contains(&expansion, quote!(_: (),));
        assert_contains(&expansion, quote! {
            <EncryptedAge as ::stack_encrypt::target::EncryptFrom<_, ::stack_encrypt::StackCipher<__K>, ::stack_encrypt::NonEmpty<&'static str>>>::encrypt_from(
                &__source.age, __cipher, ::stack_encrypt::nonempty!("user/age"),
            )
        });
        assert_contains(&expansion, quote!(&__source.email, __cipher, ::stack_encrypt::nonempty!("user/email"),));
        // Under `NonEmpty<__T>`, each extended with the caller's — cloned to
        // all but the last — and `__T` bounded for `'static`, the lifetime
        // the literal fixes.
        assert_contains(&expansion, quote! {
            impl<__K, __T> ::stack_encrypt::target::EncryptFrom<User, ::stack_encrypt::StackCipher<__K>, ::stack_encrypt::NonEmpty<__T>> for EncryptedUser
            where
                __T: ::stack_encrypt::IntoAad<'static> + ::stack_encrypt::IntoPrfContext<'static> + ::core::clone::Clone
        });
        assert_contains(&expansion, quote! {
            &__source.age, __cipher,
            ::stack_encrypt::NonEmpty::with(::stack_encrypt::nonempty!("user/age"), ::core::clone::Clone::clone(&__context)),
        });
        assert_contains(&expansion, quote! {
            &__source.email, __cipher,
            ::stack_encrypt::NonEmpty::with(::stack_encrypt::nonempty!("user/email"), __context),
        });
        assert_lacks(&expansion, quote!('__ctx));
    }

    #[test]
    #[rustfmt::skip]
    fn a_nested_field_is_handed_the_callers_context() {
        let expansion = expand(parse_quote! {
            #[stash(struct = Account, context = "accounts")]
            struct EncryptedAccount {
                #[stash(nested)]
                user: EncryptedUser,
                plan: StackCipherText,
            }
        });
        // `nested`: no inferred context; the caller's goes through as it
        // is, and the inner `struct` derive composes it with its own.
        assert_contains(&expansion, quote!(&__source.user, __cipher, ::core::clone::Clone::clone(&__context),));
        assert_contains(&expansion, quote! {
            &__source.plan, __cipher,
            ::stack_encrypt::NonEmpty::with(::stack_encrypt::nonempty!("accounts/plan"), __context),
        });
        // Under `()` the nested field is the only one using the (unit)
        // context, and takes it by move.
        assert_contains(&expansion, quote!(&__source.user, __cipher, __context,));
        assert_contains(&expansion, quote!(&__source.plan, __cipher, ::stack_encrypt::nonempty!("accounts/plan"),));
    }

    #[test]
    fn tuple_plaintexts_are_reached_by_index() {
        let expansion = expand(parse_quote! {
            #[stash(struct = Pair, context = "pair")]
            struct EncryptedPair {
                #[stash(from = 1)]
                b: StackCipherText,
            }
        });
        assert_contains(
            &expansion,
            quote!(&__source.1, __cipher, ::stack_encrypt::nonempty!("pair/1"),),
        );
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
