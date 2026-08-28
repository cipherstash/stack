//! Expansion of `#[derive(DecryptFrom)]`.

use std::collections::HashSet;

use proc_macro2::TokenStream;
use quote::quote;
use syn::{parse_quote, DeriveInput, Ident, Path, PathArguments, Result, Type};

use crate::shape::{Field, Record};

pub(crate) fn derive(input: DeriveInput) -> Result<TokenStream> {
    let record = Record::parse(&input)?;
    let krate = &record.krate;
    let name = &input.ident;
    let (_, ty_generics, _) = input.generics.split_for_impl();

    if record.sources.is_empty() {
        return Err(syn::Error::new_spanned(
            name,
            "DecryptFrom needs `#[encrypted(source = ..)]`: the plaintext type must be named. (An \
             impl for every type that can be decrypted from the ciphertext field would be a \
             blanket impl of a foreign trait, which the orphan rule forbids outside \
             stack-encrypt.)",
        ));
    }

    let opened: Vec<&Field> = record.fields.iter().filter(|f| f.decrypt).collect();
    if opened.is_empty() {
        return Err(syn::Error::new_spanned(
            name,
            "DecryptFrom needs to know which field decryption opens: mark it \
             `#[encrypted(decrypt)]` (index terms are one-way and cannot be)",
        ));
    }

    let by_field = opened.iter().filter(|f| f.from().is_some()).count();
    let mode =
        match by_field {
            0 if opened.len() == 1 => Mode::Whole(opened[0]),
            0 => return Err(syn::Error::new_spanned(
                name,
                "several fields are marked `decrypt` but none names a source field: one plaintext \
                 cannot be recovered from two fields. Either mark only the ciphertext field, or \
                 give each a `from = ..` so decryption rebuilds the source field by field.",
            )),
            n if n == opened.len() => {
                let mut seen: HashSet<&Ident> = HashSet::with_capacity(opened.len());
                for field in &opened {
                    let from = field
                        .from()
                        .unwrap_or_else(|| unreachable!("counted above"));
                    if !seen.insert(from) {
                        return Err(syn::Error::new(
                            from.span(),
                            format!(
                                "two `decrypt` fields would recover the same source field `{from}`"
                            ),
                        ));
                    }
                }
                Mode::ByField(opened)
            }
            _ => {
                return Err(syn::Error::new_spanned(
                    name,
                    "`decrypt` fields must either all name a source field (`from = ..`) or be a \
                 single field opened as the whole plaintext; this record mixes the two",
                ))
            }
        };

    let impls = record
        .sources
        .iter()
        .map(|source| {
            let mut generics = input.generics.clone();
            generics.params.push(parse_quote!(__K));
            let body = match &mode {
                Mode::Whole(field) => {
                    let ty = &field.ty;
                    generics.make_where_clause().predicates.push(parse_quote! {
                        #source: #krate::target::DecryptFrom<#ty, #krate::StackCipher<__K>>
                    });
                    whole_body(krate, field, source)
                }
                Mode::ByField(fields) => by_field_body(krate, fields, source)?,
            };
            let (impl_generics, _, where_clause) = generics.split_for_impl();

            Ok(quote! {
                #[automatically_derived]
                impl #impl_generics #krate::target::DecryptFrom<#name #ty_generics, #krate::StackCipher<__K>>
                    for #source #where_clause
                {
                    fn decrypt_from<'__a, '__c, __Ctx>(
                        __source: #name #ty_generics,
                        __cipher: &'__a #krate::StackCipher<__K>,
                        __context: __Ctx,
                    ) -> #krate::target::Pending<'__a, Self, __K>
                    where
                        __Ctx: #krate::target::DecryptContext<'__c>,
                        #name #ty_generics: '__a,
                        Self: '__a,
                    {
                        #body
                    }
                }
            })
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

fn context_for(field: &Field) -> TokenStream {
    match field.context() {
        Some(literal) => quote!(#literal),
        None => quote!(__context),
    }
}

fn whole_body(krate: &Path, field: &Field, source: &Type) -> TokenStream {
    let ty = &field.ty;
    let member = &field.member;
    let context = context_for(field);
    quote! {
        <#source as #krate::target::DecryptFrom<#ty, #krate::StackCipher<__K>>>::decrypt_from(
            __source.#member,
            __cipher,
            #context,
        )
    }
}

fn by_field_body(krate: &Path, fields: &[&Field], source: &Type) -> Result<TokenStream> {
    let literal = struct_literal_path(source)?;

    // The record's context goes to every opened field without its own; the
    // last such field takes it by move.
    let mut remaining = fields.iter().filter(|f| f.context().is_none()).count();
    let unused_context = (remaining == 0).then(|| quote!(let _ = __context;));

    let mut chain = TokenStream::new();
    let mut pattern = TokenStream::new();
    for (index, field) in fields.iter().enumerate() {
        let ty = &field.ty;
        let member = &field.member;
        let local = &field.local;
        let context = match field.context() {
            Some(literal) => quote!(#literal),
            None => {
                remaining -= 1;
                if remaining == 0 {
                    quote!(__context)
                } else {
                    quote!(::core::clone::Clone::clone(&__context))
                }
            }
        };
        // The plaintext field's type is not known here; it is inferred from
        // the struct literal below, and the obligation checked against it.
        let call = quote! {
            #krate::target::DecryptFrom::<#ty, #krate::StackCipher<__K>>::decrypt_from(
                __source.#member,
                __cipher,
                #context,
            )
        };
        if index == 0 {
            chain = call;
            pattern = quote!(#local);
        } else {
            chain = quote!(#chain.zip(#call));
            pattern = quote!((#pattern, #local));
        }
    }

    let assign = fields.iter().map(|field| {
        let from = field.from();
        let local = &field.local;
        quote!(#from: #local)
    });

    Ok(quote! {
        #unused_context
        #chain.map(|#pattern| #literal { #(#assign),* })
    })
}

/// The source type as a struct-literal path: `User<T>` becomes `User::<T>`.
fn struct_literal_path(source: &Type) -> Result<Path> {
    let Type::Path(type_path) = source else {
        return Err(syn::Error::new_spanned(
            source,
            "field-by-field decryption rebuilds the source as a struct literal, so `source` \
             must name a struct",
        ));
    };
    if type_path.qself.is_some() {
        return Err(syn::Error::new_spanned(
            source,
            "field-by-field decryption rebuilds the source as a struct literal, so `source` \
             must name a struct directly, not through a qualified path",
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{assert_contains, assert_lacks};

    fn expand(input: DeriveInput) -> Result<String> {
        derive(input).map(|tokens| tokens.to_string())
    }

    #[test]
    fn a_source_is_required() {
        let err = expand(parse_quote! {
            struct Rec {
                #[encrypted(decrypt)]
                c: StackCipherText,
            }
        })
        .unwrap_err();
        assert!(err.to_string().contains("plaintext type must be named"));
    }

    #[test]
    fn an_opened_field_is_required() {
        let err = expand(parse_quote! {
            #[encrypted(source = u32)]
            struct Rec {
                c: StackCipherText,
                hm: EqualityTerm,
            }
        })
        .unwrap_err();
        assert!(err.to_string().contains("which field decryption opens"));
    }

    #[test]
    fn two_whole_fields_are_ambiguous() {
        let err = expand(parse_quote! {
            #[encrypted(source = u32)]
            struct Rec {
                #[encrypted(decrypt)]
                a: StackCipherText,
                #[encrypted(decrypt)]
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
            #[encrypted(source = User)]
            struct Rec {
                #[encrypted(decrypt, from = a)]
                a: StackCipherText,
                #[encrypted(decrypt)]
                b: StackCipherText,
            }
        })
        .unwrap_err();
        assert!(err.to_string().contains("mixes the two"));
    }

    #[test]
    fn duplicate_recovery_targets_are_rejected() {
        let err = expand(parse_quote! {
            #[encrypted(source = User)]
            struct Rec {
                #[encrypted(decrypt, from = a)]
                a: StackCipherText,
                #[encrypted(decrypt, from = a)]
                b: StackCipherText,
            }
        })
        .unwrap_err();
        assert!(err.to_string().contains("same source field `a`"));
    }

    #[test]
    #[rustfmt::skip]
    fn whole_mode_opens_the_one_field() {
        let expansion = expand(parse_quote! {
            #[encrypted(source = u32, source = u64)]
            struct EncryptedAge {
                #[encrypted(decrypt)]
                c: StackCipherText,
                hm: EqualityTerm,
            }
        })
        .unwrap();
        assert_contains(&expansion, quote! {
            impl<__K> ::stack_encrypt::target::DecryptFrom<EncryptedAge, ::stack_encrypt::StackCipher<__K>> for u32
            where
                u32: ::stack_encrypt::target::DecryptFrom<StackCipherText, ::stack_encrypt::StackCipher<__K>>
        });
        assert_contains(&expansion, quote! {
            <u64 as ::stack_encrypt::target::DecryptFrom<StackCipherText, ::stack_encrypt::StackCipher<__K>>>::decrypt_from(
                __source.c, __cipher, __context,
            )
        });
        assert_lacks(&expansion, quote!(hm));
    }

    #[test]
    #[rustfmt::skip]
    fn by_field_mode_rebuilds_the_source() {
        let expansion = expand(parse_quote! {
            #[encrypted(source = User<T>)]
            struct EncryptedUser {
                #[encrypted(decrypt, from = age, context = "users/age")]
                age: EncryptedAge,
                #[encrypted(decrypt, from = email)]
                email: StackCipherText,
                #[encrypted(from = email, context = "users/email")]
                email_eq: EqualityTerm,
            }
        })
        .unwrap();
        assert_contains(&expansion, quote! {
            ::stack_encrypt::target::DecryptFrom::<EncryptedAge, ::stack_encrypt::StackCipher<__K>>::decrypt_from(
                __source.age, __cipher, "users/age",
            )
        });
        assert_contains(&expansion, quote!(__source.email, __cipher, __context,));
        assert_contains(&expansion, quote!(.map(|(__field_0, __field_1)| User::<T> { age: __field_0, email: __field_1 })));
        assert_lacks(&expansion, quote!(email_eq));
        assert_lacks(&expansion, quote!(let _ = __context;));
    }
}
