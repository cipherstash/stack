//! Expansion of `#[derive(EncryptFrom)]`.

use proc_macro2::{Span, TokenStream};
use quote::{quote, quote_spanned};
use syn::spanned::Spanned;
use syn::{parse_quote, DeriveInput, Ident, Path, Result, Type};

use crate::shape::{context_type, push_context_generics, zip_fields, Field, Kind, Record};

pub(crate) fn derive(input: DeriveInput) -> Result<TokenStream> {
    let record = Record::parse(&input)?;
    let krate = &record.krate;
    let name = &input.ident;
    let (_, ty_generics, _) = input.generics.split_for_impl();

    let decryptable = decryptable_impl(&input, &record);

    if record.plaintexts.is_empty() {
        // One impl, generic over the source: the record accepts exactly the
        // sources every derived field accepts, which the where clause spells
        // out so a mismatch is reported against the field type.
        let source: Type = parse_quote!(__S);
        let mut generics = input.generics.clone();
        generics.params.push(parse_quote!(__S));
        generics.params.push(parse_quote!(__K));
        push_field_bounds(&mut generics, krate, &record, &source);
        push_context_generics(&mut generics, krate, &derived(&record), &encrypt_context());
        let (impl_generics, _, where_clause) = generics.split_for_impl();
        let body = body(krate, &record, &source);
        let block = impl_block(
            krate,
            name,
            &ty_generics,
            &impl_generics,
            where_clause,
            &source,
            body,
        );
        return Ok(quote!(#block #decryptable));
    }

    // One impl per listed source. Fields derived from the whole source get a
    // where clause as above; `from = ..` fields reach into the source, so
    // their obligations are checked in the body against the actual field.
    let impls = record.plaintexts.iter().map(|source| {
        let mut generics = input.generics.clone();
        generics.params.push(parse_quote!(__K));
        push_field_bounds(&mut generics, krate, &record, source);
        push_context_generics(&mut generics, krate, &derived(&record), &encrypt_context());
        let (impl_generics, _, where_clause) = generics.split_for_impl();
        let body = body(krate, &record, source);
        impl_block(
            krate,
            name,
            &ty_generics,
            &impl_generics,
            where_clause,
            source,
            body,
        )
    });

    let decryptable = decryptable_impl(&input, &record);
    Ok(quote!(#(#impls)* #decryptable))
}

fn derived(record: &Record) -> Vec<&Field> {
    record.fields.iter().filter(|f| f.is_derived()).collect()
}

fn encrypt_context() -> Ident {
    Ident::new("EncryptContext", Span::call_site())
}

/// `impl EncryptFrom<Source, StackCipher<__K>, __Ctx> for Record` around
/// `body`.
fn impl_block(
    krate: &Path,
    name: &Ident,
    ty_generics: &syn::TypeGenerics<'_>,
    impl_generics: &syn::ImplGenerics<'_>,
    where_clause: Option<&syn::WhereClause>,
    source: &Type,
    body: TokenStream,
) -> TokenStream {
    quote! {
        #[automatically_derived]
        impl #impl_generics #krate::target::EncryptFrom<#source, #krate::StackCipher<__K>, __Ctx>
            for #name #ty_generics #where_clause
        {
            fn encrypt_from<'__a>(
                __source: &'__a #source,
                __cipher: &'__a #krate::StackCipher<__K>,
                __context: __Ctx,
            ) -> #krate::target::Pending<'__a, Self, __K>
            where
                Self: '__a,
            {
                #body
            }
        }
    }
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
fn decryptable_impl(input: &DeriveInput, record: &Record) -> TokenStream {
    let krate = &record.krate;
    let name = &input.ident;
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();
    let value = if record.fields.iter().any(|f| f.decrypt) {
        quote!(true)
    } else {
        let terms = record
            .fields
            .iter()
            .filter(|f| f.is_derived())
            .map(|field| {
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
fn push_field_bounds(generics: &mut syn::Generics, krate: &Path, record: &Record, source: &Type) {
    let predicates = &mut generics.make_where_clause().predicates;
    for field in record
        .fields
        .iter()
        .filter(|f| f.is_derived() && f.from().is_none())
    {
        let ty = &field.ty;
        let context = context_type(field);
        predicates.push(parse_quote! {
            #ty: #krate::target::EncryptFrom<#source, #krate::StackCipher<__K>, #context>
        });
    }
}

/// The method body: every derived field's pending, zipped into one, mapped
/// into `Self`.
fn body(krate: &Path, record: &Record, source: &Type) -> TokenStream {
    let derived: Vec<&Field> = record.fields.iter().filter(|f| f.is_derived()).collect();

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
        &derived,
        |field, context| {
            let ty = &field.ty;
            // A `from` field's source type is not known here; it is inferred
            // from the field expression, and the obligation checked there.
            let (source_expr, source_ty): (TokenStream, TokenStream) = match field.from() {
                Some(from) => (quote!(&__source.#from), quote!(_)),
                None => (quote!(__source), quote!(#source)),
            };
            quote! {
                <#ty as #krate::target::EncryptFrom<#source_ty, #krate::StackCipher<__K>, _>>::encrypt_from(
                    #source_expr,
                    __cipher,
                    #context,
                )
            }
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
        // Both fields take the caller's context, so the impl is bounded by
        // what they do with it — and inherits their demand for a supplied
        // one through the field bounds.
        assert_contains(&expansion, quote! {
            impl<'__c, __S, __K, __Ctx> ::stack_encrypt::target::EncryptFrom<__S, ::stack_encrypt::StackCipher<__K>, __Ctx>
                for EncryptedAge
            where
                StackCipherText: ::stack_encrypt::target::EncryptFrom<__S, ::stack_encrypt::StackCipher<__K>, __Ctx>,
                EqualityTerm: ::stack_encrypt::target::EncryptFrom<__S, ::stack_encrypt::StackCipher<__K>, __Ctx>,
                __Ctx: ::stack_encrypt::target::EncryptContext<'__c>
        });
        // The first field clones the record context, the last takes it.
        assert_contains(&expansion, quote!(__source, __cipher, ::core::clone::Clone::clone(&__context),));
        assert_contains(&expansion, quote!(__source, __cipher, __context,));
        assert_contains(&expansion, quote!(.map(|(__field_0, __field_1)| Self { c: __field_0, hm: __field_1 })));
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
            impl<'__c, __K, __Ctx> ::stack_encrypt::target::EncryptFrom<i32, ::stack_encrypt::StackCipher<__K>, __Ctx> for IntegerOrdOre
        });
        assert_contains(&expansion, quote! {
            impl<'__c, __K, __Ctx> ::stack_encrypt::target::EncryptFrom<i64, ::stack_encrypt::StackCipher<__K>, __Ctx> for IntegerOrdOre
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
        // No field takes the record's context, so `__Ctx` is unbounded: the
        // row accepts `()`, and `encrypt_into(&cipher)` compiles.
        assert_lacks(&expansion, quote!(&__context));
        assert_contains(&expansion, quote! {
            impl<__K, __Ctx> ::stack_encrypt::target::EncryptFrom<User, ::stack_encrypt::StackCipher<__K>, __Ctx> for EncryptedUser
        });
        assert_lacks(&expansion, quote!('__c));
        // `from` fields carry no where clause: the source field's type is
        // unknown here, so the obligation is checked in the body instead.
        assert!(
            expansion.replace(' ', "").contains("forEncryptedUser{fnencrypt_from"),
            "unexpected where clause on the impl:\n{expansion}"
        );
    }

    #[test]
    #[rustfmt::skip]
    fn a_from_field_taking_the_callers_context_demands_a_supplied_one() {
        let expansion = expand(parse_quote! {
            #[stash(plaintext = User)]
            struct EncryptedUser {
                #[stash(from = age)]
                age: EncryptedAge,
            }
        });
        // The obligation is checked in the body against a source field type
        // the derive cannot name, so the where clause states the demand.
        assert_contains(&expansion, quote! {
            where
                __Ctx: ::stack_encrypt::target::EncryptContext<'__c> + ::stack_encrypt::target::SuppliedContext<'__c>
        });
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
