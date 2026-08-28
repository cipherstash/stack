//! Expansion of `#[derive(EncryptFrom)]`.

use proc_macro2::TokenStream;
use quote::quote;
use syn::{parse_quote, DeriveInput, Ident, Path, Result, Type};

use crate::shape::{zip_fields, Field, Kind, Record};

pub(crate) fn derive(input: DeriveInput) -> Result<TokenStream> {
    let record = Record::parse(&input)?;
    let krate = &record.krate;
    let name = &input.ident;
    let (_, ty_generics, _) = input.generics.split_for_impl();

    if record.plaintexts.is_empty() {
        // One impl, generic over the source: the record accepts exactly the
        // sources every derived field accepts, which the where clause spells
        // out so a mismatch is reported against the field type.
        let source: Type = parse_quote!(__S);
        let mut generics = input.generics.clone();
        generics.params.push(parse_quote!(__S));
        generics.params.push(parse_quote!(__K));
        push_field_bounds(&mut generics, krate, &record, &source);
        let (impl_generics, _, where_clause) = generics.split_for_impl();
        let body = body(krate, &record, &source);
        return Ok(impl_block(
            krate,
            name,
            &ty_generics,
            &impl_generics,
            where_clause,
            &source,
            body,
        ));
    }

    // One impl per listed source. Fields derived from the whole source get a
    // where clause as above; `from = ..` fields reach into the source, so
    // their obligations are checked in the body against the actual field.
    let impls = record.plaintexts.iter().map(|source| {
        let mut generics = input.generics.clone();
        generics.params.push(parse_quote!(__K));
        push_field_bounds(&mut generics, krate, &record, source);
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

    Ok(quote!(#(#impls)*))
}

/// `impl EncryptFrom<Source, StackCipher<__K>> for Record` around `body`.
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
        impl #impl_generics #krate::target::EncryptFrom<#source, #krate::StackCipher<__K>>
            for #name #ty_generics #where_clause
        {
            fn encrypt_from<'__a, '__c, __Ctx>(
                __source: &'__a #source,
                __cipher: &'__a #krate::StackCipher<__K>,
                __context: __Ctx,
            ) -> #krate::target::Pending<'__a, Self, __K>
            where
                __Ctx: #krate::target::EncryptContext<'__c>,
                Self: '__a,
            {
                #body
            }
        }
    }
}

/// `FieldTy: EncryptFrom<Source, StackCipher<__K>>` for every field derived
/// from the whole source.
fn push_field_bounds(generics: &mut syn::Generics, krate: &Path, record: &Record, source: &Type) {
    let predicates = &mut generics.make_where_clause().predicates;
    for field in record
        .fields
        .iter()
        .filter(|f| f.is_derived() && f.from().is_none())
    {
        let ty = &field.ty;
        predicates.push(parse_quote! {
            #ty: #krate::target::EncryptFrom<#source, #krate::StackCipher<__K>>
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
                <#ty as #krate::target::EncryptFrom<#source_ty, #krate::StackCipher<__K>>>::encrypt_from(
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
    fn generic_source_bounds_every_whole_source_field() {
        let expansion = expand(parse_quote! {
            struct EncryptedAge {
                c: StackCipherText,
                hm: EqualityTerm,
            }
        });
        assert_contains(&expansion, quote! {
            impl<__S, __K> ::stack_encrypt::target::EncryptFrom<__S, ::stack_encrypt::StackCipher<__K>>
                for EncryptedAge
            where
                StackCipherText: ::stack_encrypt::target::EncryptFrom<__S, ::stack_encrypt::StackCipher<__K>>,
                EqualityTerm: ::stack_encrypt::target::EncryptFrom<__S, ::stack_encrypt::StackCipher<__K>>
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
            #[stack_encrypt(plaintext = i32, plaintext = i64)]
            struct IntegerOrdOre {
                c: StackCipherText,
                #[stack_encrypt(default = SchemaVersion::V3)]
                v: SchemaVersion,
            }
        });
        assert_contains(&expansion, quote! {
            impl<__K> ::stack_encrypt::target::EncryptFrom<i32, ::stack_encrypt::StackCipher<__K>> for IntegerOrdOre
        });
        assert_contains(&expansion, quote! {
            impl<__K> ::stack_encrypt::target::EncryptFrom<i64, ::stack_encrypt::StackCipher<__K>> for IntegerOrdOre
        });
        assert_contains(&expansion, quote!(Self { c: __field_0, v: SchemaVersion::V3 }));
        assert_lacks(&expansion, quote!(__S));
    }

    #[test]
    #[rustfmt::skip]
    fn row_fields_reach_into_the_source_under_their_own_context() {
        let expansion = expand(parse_quote! {
            #[stack_encrypt(plaintext = User)]
            struct EncryptedUser {
                #[stack_encrypt(from = age, context = "users/age")]
                age: EncryptedAge,
                #[stack_encrypt(from = email, context = "users/email")]
                email: StackCipherText,
            }
        });
        assert_contains(&expansion, quote! {
            <EncryptedAge as ::stack_encrypt::target::EncryptFrom<_, ::stack_encrypt::StackCipher<__K>>>::encrypt_from(
                &__source.age, __cipher, "users/age",
            )
        });
        // No field takes the record's context.
        assert_lacks(&expansion, quote!(&__context));
        // `from` fields carry no where clause: the source field's type is
        // unknown here, so the obligation is checked in the body instead.
        assert!(
            expansion.replace(' ', "").contains("forEncryptedUser{fnencrypt_from"),
            "unexpected where clause on the impl:\n{expansion}"
        );
    }

    #[test]
    fn tuple_plaintexts_are_reached_by_index() {
        let expansion = expand(parse_quote! {
            #[stack_encrypt(plaintext = Pair)]
            struct EncryptedPair {
                #[stack_encrypt(from = 1, context = "pair/1")]
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
