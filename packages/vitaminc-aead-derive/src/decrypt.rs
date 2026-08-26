//! Expansion of `#[derive(Decrypt)]`.

use proc_macro2::TokenStream;
use quote::quote;
use syn::{parse_quote, DeriveInput, Result};

use crate::{
    attrs::ContainerAttrs,
    shape::{FieldInfo, Shape},
};

pub(crate) fn derive(input: DeriveInput) -> Result<TokenStream> {
    let attrs = ContainerAttrs::parse(&input.attrs)?;
    let krate = &attrs.krate;
    let shape = Shape::parse(&input)?;
    let name = &input.ident;

    // `'__c` is the decipher lifetime the trait is generic over. Every type
    // parameter must decrypt for it and outlive it; every lifetime parameter
    // must outlive it, since the visitor below is required to be `'__c`.
    let mut bounded = input.generics.clone();
    for param in bounded.type_params_mut() {
        param.bounds.push(parse_quote!(#krate::Decrypt<'__c>));
        param.bounds.push(parse_quote!('__c));
    }
    for lifetime in bounded.lifetimes_mut() {
        lifetime.bounds.push(parse_quote!('__c));
    }
    let mut with_c = bounded.clone();
    with_c.params.insert(0, parse_quote!('__c));

    // `ty_generics` must come from the *original* generics: the type is still
    // `Foo<T>`, not `Foo<'__c, T>`. The visitor declared inside the method body
    // redeclares those same parameters — it cannot mention `'__c`, which is
    // introduced by the impl, so its `Decrypt` bounds live on its impl block.
    let (visitor_decl_generics, ty_generics, visitor_where) = input.generics.split_for_impl();
    let (impl_generics, _, where_clause) = with_c.split_for_impl();
    let turbofish = ty_generics.as_turbofish();

    let body = match &shape {
        Shape::Newtype(field) => {
            let inner = &field.ty;
            quote! {
                // Transparent, mirroring the `Encrypt` side: decrypt the inner
                // type and rewrap. `map_ok` exists precisely because `Ok<T>`
                // is a GAT and cannot be mapped generically otherwise.
                <__D as #krate::Decipher<'__c>>::map_ok(
                    <#inner as #krate::Decrypt<'__c>>::decrypt_with_aad(__decipher, __aad),
                    #name,
                )
            }
        }
        Shape::Map(_) | Shape::Empty => {
            let visit_map = match &shape {
                Shape::Map(fields) => visit_map_body(krate, name, fields),
                _ => visit_empty_body(krate, name),
            };
            let phantom = phantom_data(name, &ty_generics);

            quote! {
                struct __Visitor #visitor_decl_generics (
                    ::core::marker::PhantomData<#phantom>
                ) #visitor_where;

                #[automatically_derived]
                impl #impl_generics #krate::DecipherVisitor<'__c>
                    for __Visitor #ty_generics #where_clause
                {
                    type Value = #name #ty_generics;

                    fn visit_map<__M>(
                        self,
                        mut __map: __M,
                    ) -> ::core::result::Result<Self::Value, #krate::Unspecified>
                    where
                        __M: #krate::MapAccess<'__c>,
                    {
                        #visit_map
                    }
                }

                #krate::Decipher::decrypt_map(
                    __decipher,
                    __Visitor #turbofish (::core::marker::PhantomData),
                    __aad,
                )
            }
        }
    };

    Ok(quote! {
        #[automatically_derived]
        impl #impl_generics #krate::Decrypt<'__c> for #name #ty_generics #where_clause {
            fn decrypt_with_aad<'__aead_a, __D, __A>(
                __decipher: __D,
                __aad: __A,
            ) -> __D::Ok<Self>
            where
                __D: #krate::Decipher<'__c>,
                __A: #krate::IntoAad<'__aead_a>,
            {
                #body
            }
        }
    })
}

/// Read keys first, then choose the type to decrypt each value into. Entry
/// order in a stored ciphertext is not authenticated, so a positional decode
/// would be wrong; matching on the key is also what makes heterogeneous field
/// types possible at all.
fn visit_map_body(krate: &syn::Path, name: &syn::Ident, fields: &[FieldInfo]) -> TokenStream {
    let slots = fields.iter().map(|field| {
        let local = &field.local;
        let ty = &field.ty;
        quote! {
            let mut #local: ::core::option::Option<#ty> = ::core::option::Option::None;
        }
    });

    let arms = fields.iter().map(|field| {
        let key = &field.key;
        let local = &field.local;
        let ty = &field.ty;
        // The duplicate guard is common to both arms: the decipher rejects
        // duplicate keys too, but this catches a decipher that does not,
        // rather than last-wins overwriting an already-verified field.
        let reject_duplicate = quote! {
            if #local.is_some() {
                return ::core::result::Result::Err(#krate::Unspecified);
            }
        };
        let read = if field.passthrough {
            // Nothing here is verified — no tag covers a passthrough entry and
            // nothing binds its key — so this value is untrusted input, exactly
            // as the column it came from is. The downcast is the only check:
            // it rejects a payload of the wrong type, not a tampered one.
            quote! {
                *<__M as #krate::MapAccess<'__c>>::next_passthrough(&mut __map)
                    .map_err(|_| #krate::Unspecified)?
                    .downcast::<#ty>()
                    .map_err(|_| #krate::Unspecified)?
            }
        } else {
            quote! {
                <__M as #krate::MapAccess<'__c>>::next_value::<#ty>(&mut __map)
                    .map_err(|_| #krate::Unspecified)?
            }
        };
        quote! {
            #key => {
                #reject_duplicate
                #local = ::core::option::Option::Some(#read);
            }
        }
    });

    let inits = fields.iter().map(|field| {
        let member = &field.member;
        let local = &field.local;
        quote! {
            // A missing field is a rejection, not a default: an absent entry
            // is an unauthenticated one.
            #member: #local.ok_or(#krate::Unspecified)?,
        }
    });

    quote! {
        #(#slots)*

        while let ::core::option::Option::Some(__key) =
            <__M as #krate::MapAccess<'__c>>::next_key(&mut __map)
                .map_err(|_| #krate::Unspecified)?
        {
            match __key.as_str() {
                #(#arms)*
                // Unknown keys are refused rather than skipped: a skipped
                // value is one whose AAD binding is never verified.
                _ => return ::core::result::Result::Err(#krate::Unspecified),
            }
        }

        ::core::result::Result::Ok(#name { #(#inits)* })
    }
}

fn visit_empty_body(krate: &syn::Path, name: &syn::Ident) -> TokenStream {
    quote! {
        if <__M as #krate::MapAccess<'__c>>::next_key(&mut __map)
            .map_err(|_| #krate::Unspecified)?
            .is_some()
        {
            return ::core::result::Result::Err(#krate::Unspecified);
        }
        ::core::result::Result::Ok(#name {})
    }
}

/// The visitor carries no data, but an inner item cannot inherit the outer
/// generics — it has to redeclare them, and every declared parameter must be
/// used. `PhantomData<fn() -> Self::Value>` uses all of them at once, whatever
/// kind they are.
///
/// Naming the parameters individually does not work: a const parameter can
/// only appear in a type as a generic argument, so the obvious `[u8; N]`
/// silently requires `N: usize` and makes `#[derive(Decrypt)]` fail on
/// `struct S<const N: u32>` with an error pointing at the macro. Referencing
/// them through the value type sidesteps the question — each parameter is
/// passed along exactly as declared.
///
/// A function pointer rather than the value itself, because the visitor owns
/// nothing: `fn() -> T` imposes no drop obligation on `T` and is `Send` and
/// `Sync` regardless of what `T` is, so the visitor stays usable for every
/// type the derive accepts.
fn phantom_data(name: &syn::Ident, ty_generics: &syn::TypeGenerics<'_>) -> TokenStream {
    quote!(fn() -> #name #ty_generics)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{assert_contains, assert_lacks};

    fn expand(input: DeriveInput) -> String {
        derive(input).expect("expansion should succeed").to_string()
    }

    /// Entry order is not authenticated, so the decode reads the key first and
    /// picks the field type from it — a positional decode would be wrong.
    #[test]
    fn fields_are_matched_by_key_not_position() {
        let out = expand(parse_quote! {
            struct User {
                name: String,
                age: u32,
            }
        });

        assert_contains(&out, quote!(::next_key(&mut __map)));
        assert_contains(&out, quote!("name" =>));
        assert_contains(&out, quote!("age" =>));
        assert_contains(&out, quote!(::next_value::<String>(&mut __map)));
        assert_contains(&out, quote!(::next_value::<u32>(&mut __map)));
    }

    /// An absent entry is an unauthenticated one, so a missing field is a
    /// rejection rather than a default.
    #[test]
    fn a_missing_field_is_rejected() {
        let out = expand(parse_quote! {
            struct User {
                name: String,
            }
        });

        assert_contains(
            &out,
            quote!(name: __field_0.ok_or(::vitaminc_aead::Unspecified)?),
        );
    }

    /// Belt and braces over the decipher's own duplicate rejection: last-wins
    /// would overwrite a field that has already been verified.
    #[test]
    fn a_duplicate_key_is_rejected() {
        let out = expand(parse_quote! {
            struct User {
                name: String,
            }
        });

        assert_contains(
            &out,
            quote!(if __field_0.is_some() {
                return ::core::result::Result::Err(::vitaminc_aead::Unspecified);
            }),
        );
    }

    /// Unknown keys are refused, not skipped: a skipped value is one whose AAD
    /// binding is never verified.
    #[test]
    fn an_unknown_key_is_rejected() {
        let out = expand(parse_quote! {
            struct User {
                name: String,
            }
        });

        assert_contains(
            &out,
            quote!(_ => return ::core::result::Result::Err(::vitaminc_aead::Unspecified),),
        );
    }

    /// A passthrough field is read through `next_passthrough` and downcast — no
    /// tag is checked, because none covers it. `next_value` must not appear for
    /// that key, or the read would demand a sealed node that is not there.
    #[test]
    fn a_passthrough_field_is_read_without_verification() {
        let out = expand(parse_quote! {
            struct Row {
                #[aead(passthrough)]
                tenant: String,
                ssn: String,
            }
        });

        assert_contains(&out, quote!(::next_passthrough(&mut __map)));
        assert_contains(&out, quote!(.downcast::<String>()));
        assert_contains(&out, quote!(::next_value::<String>(&mut __map)));
        // The duplicate guard applies to passthrough entries too: a repeated
        // key must not overwrite an already-read field.
        assert_contains(
            &out,
            quote!(if __field_0.is_some() {
                return ::core::result::Result::Err(::vitaminc_aead::Unspecified);
            }),
        );
    }

    /// Mirrors the `Encrypt` side: a newtype decrypts as its inner type and is
    /// rewrapped, so no visitor and no map are involved.
    #[test]
    fn newtype_is_transparent() {
        let out = expand(parse_quote!(
            struct Wrapper(String);
        ));

        assert_contains(
            &out,
            quote!(<__D as ::vitaminc_aead::Decipher<'__c>>::map_ok(
                <String as ::vitaminc_aead::Decrypt<'__c>>::decrypt_with_aad(__decipher, __aad),
                Wrapper,
            )),
        );
        assert_lacks(&out, quote!(struct __Visitor));
    }

    /// A field-less struct accepts only the empty map: any entry at all is a
    /// forgery attempt against a shape that has no fields to hold it.
    #[test]
    fn empty_struct_rejects_any_entry() {
        let out = expand(parse_quote!(
            struct Marker {}
        ));

        assert_contains(
            &out,
            quote!(
                if <__M as ::vitaminc_aead::MapAccess<'__c>>::next_key(&mut __map)
                    .map_err(|_| ::vitaminc_aead::Unspecified)?
                    .is_some()
                {
                    return ::core::result::Result::Err(::vitaminc_aead::Unspecified);
                }
            ),
        );
        assert_contains(&out, quote!(::core::result::Result::Ok(Marker {})));
    }

    /// The visitor is required to be `'__c`, so every type parameter must
    /// decrypt for that lifetime *and* outlive it, and every lifetime parameter
    /// must outlive it. The type itself stays `User<'a, T>` — `'__c` is
    /// introduced by the impl, not by the struct.
    #[test]
    fn generic_parameters_are_bound_to_the_decipher_lifetime() {
        let out = expand(parse_quote! {
            struct User<'a, T> {
                borrowed: &'a str,
                value: T,
            }
        });

        assert_contains(
            &out,
            quote!(impl<'__c, 'a: '__c, T: ::vitaminc_aead::Decrypt<'__c> + '__c>),
        );
        assert_contains(&out, quote!(::vitaminc_aead::Decrypt<'__c> for User<'a, T>));
        assert_contains(
            &out,
            quote!(
                type Value = User<'a, T>;
            ),
        );
        assert_contains(
            &out,
            quote!(__Visitor::<'a, T>(::core::marker::PhantomData)),
        );
    }

    /// The visitor cannot inherit the outer generics, so it redeclares them and
    /// must use every one. Routing them through the value type uses all of them
    /// at once, whatever kind they are — and a const parameter has nowhere else
    /// to appear in a type, so naming them individually would not work.
    #[test]
    fn the_visitor_uses_every_redeclared_parameter() {
        let out = expand(parse_quote! {
            struct User<'a, T, const N: usize> {
                borrowed: &'a str,
                value: T,
                bytes: [u8; N],
            }
        });

        assert_contains(&out, quote!(struct __Visitor<'a, T, const N: usize>));
        assert_contains(
            &out,
            quote!(::core::marker::PhantomData<fn() -> User<'a, T, N>),
        );
    }

    /// A const parameter that is not a `usize` must derive like any other. The
    /// previous encoding used each parameter as an array length, which silently
    /// required `usize` and failed here — with the error blamed on the macro.
    #[test]
    fn a_non_usize_const_parameter_is_supported() {
        let out = expand(parse_quote! {
            struct User<const N: u32> {
                value: String,
            }
        });

        assert_contains(&out, quote!(::core::marker::PhantomData<fn() -> User<N>));
        assert_lacks(&out, quote!([u8; N]));
    }

    #[test]
    fn crate_attribute_redirects_every_path() {
        let out = expand(parse_quote! {
            #[aead(crate = "::vitaminc::aead")]
            struct User {
                name: String,
            }
        });

        assert_contains(&out, quote!(::vitaminc::aead::Decrypt<'__c> for User));
        assert_contains(&out, quote!(::vitaminc::aead::DecipherVisitor<'__c>));
        assert!(
            !out.contains("vitaminc_aead"),
            "expansion still references the default crate path:\n{out}"
        );
    }

    #[test]
    fn unknown_container_attribute_is_rejected() {
        let err = derive(parse_quote! {
            #[aead(bogus = "x")]
            struct User {
                name: String,
            }
        })
        .expect_err("unknown container attribute should be rejected");

        assert!(err.to_string().contains("unsupported container attribute"));
    }
}
