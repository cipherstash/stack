//! Expansion of `#[derive(DecryptInto)]`.

use std::collections::HashSet;

use proc_macro2::TokenStream;
use quote::quote;
use syn::spanned::Spanned;
use syn::{parse_quote, DeriveInput, Ident, Member, Path, PathArguments, Result, Type};

use crate::shape::{zip_fields, Field, Record};

pub(crate) fn derive(input: DeriveInput) -> Result<TokenStream> {
    let record = Record::parse(&input)?;
    let krate = &record.krate;
    let name = &input.ident;
    let (_, ty_generics, _) = input.generics.split_for_impl();

    let opened: Vec<&Field> = record.fields.iter().filter(|f| f.decrypt).collect();
    if opened.is_empty() {
        return Err(syn::Error::new_spanned(
            name,
            "DecryptInto needs to know which field decryption opens: mark it \
             `#[stack_encrypt(decrypt)]` (index terms are one-way and cannot be)",
        ));
    }

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

fn context_for(field: &Field) -> TokenStream {
    match field.context() {
        Some(literal) => quote!(#literal),
        None => quote!(__context),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{assert_contains, assert_lacks};

    fn expand(input: DeriveInput) -> Result<String> {
        derive(input).map(|tokens| tokens.to_string())
    }

    #[test]
    fn an_opened_field_is_required() {
        let err = expand(parse_quote! {
            #[stack_encrypt(plaintext = u32)]
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
            #[stack_encrypt(plaintext = u32)]
            struct Rec {
                #[stack_encrypt(decrypt)]
                a: StackCipherText,
                #[stack_encrypt(decrypt)]
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
            #[stack_encrypt(plaintext = User)]
            struct Rec {
                #[stack_encrypt(decrypt, from = a)]
                a: StackCipherText,
                #[stack_encrypt(decrypt)]
                b: StackCipherText,
            }
        })
        .unwrap_err();
        assert!(err.to_string().contains("mixes the two"));
    }

    #[test]
    fn duplicate_recovery_targets_are_rejected() {
        let err = expand(parse_quote! {
            #[stack_encrypt(plaintext = User)]
            struct Rec {
                #[stack_encrypt(decrypt, from = a)]
                a: StackCipherText,
                #[stack_encrypt(decrypt, from = a)]
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
                #[stack_encrypt(decrypt)]
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
                #[stack_encrypt(decrypt, from = age)]
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
            #[stack_encrypt(plaintext = u32, plaintext = u64)]
            struct EncryptedAge {
                #[stack_encrypt(decrypt)]
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
        assert_lacks(&expansion, quote!(__P));
    }

    #[test]
    #[rustfmt::skip]
    fn by_field_mode_rebuilds_the_plaintext() {
        let expansion = expand(parse_quote! {
            #[stack_encrypt(plaintext = User<T>)]
            struct EncryptedUser {
                #[stack_encrypt(decrypt, from = age, context = "users/age")]
                age: EncryptedAge,
                #[stack_encrypt(decrypt, from = email)]
                email: StackCipherText,
                #[stack_encrypt(from = email, context = "users/email")]
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
            #[stack_encrypt(plaintext = Pair)]
            struct EncryptedPair {
                #[stack_encrypt(decrypt, from = 0, context = "pair/0")]
                a: StackCipherText,
                #[stack_encrypt(decrypt, from = 1, context = "pair/1")]
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
            #[stack_encrypt(plaintext = Pair)]
            struct Rec {
                #[stack_encrypt(decrypt, from = 0)]
                a: StackCipherText,
                #[stack_encrypt(decrypt, from = 0)]
                b: StackCipherText,
            }
        })
        .unwrap_err();
        assert!(err.to_string().contains("same plaintext field `0`"));
    }
}
