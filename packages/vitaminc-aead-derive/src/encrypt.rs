//! Expansion of `#[derive(Encrypt)]`.

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

    // Bound every type parameter, serde-style: a field of type `Vec<T>` then
    // picks up `Vec<T>: Encrypt` from the blanket impl in `vitaminc_aead`.
    let mut generics = input.generics.clone();
    for param in generics.type_params_mut() {
        param.bounds.push(parse_quote!(#krate::Encrypt));
    }
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    let body = match &shape {
        Shape::Newtype(field) => newtype_body(krate, field),
        Shape::Map(fields) => map_body(krate, fields),
        Shape::Empty => empty_body(krate),
    };

    Ok(quote! {
        #[automatically_derived]
        impl #impl_generics #krate::Encrypt for #name #ty_generics #where_clause {
            fn encrypt_with_aad<'__aead_a, __C, __A>(
                self,
                __cipher: __C,
                __aad: __A,
            ) -> ::core::result::Result<__C::Ok, __C::Error>
            where
                __C: #krate::Cipher,
                __A: #krate::IntoAad<'__aead_a>,
            {
                #body
            }
        }
    })
}

/// A newtype adds nothing to the ciphertext — it encrypts exactly as its
/// inner value, so wrapping a type is not a wire-breaking change.
fn newtype_body(krate: &syn::Path, field: &FieldInfo) -> TokenStream {
    let member = &field.member;
    quote! {
        #krate::Encrypt::encrypt_with_aad(self.#member, __cipher, __aad)
    }
}

fn map_body(krate: &syn::Path, fields: &[FieldInfo]) -> TokenStream {
    let entries = fields.iter().map(|field| {
        let key = &field.key;
        let member = &field.member;
        quote! {
            let __map = #krate::MapCipher::encrypt_entry(__map, #key, self.#member)?;
        }
    });

    quote! {
        // The AAD is captured once by `encrypt_map`; `encrypt_entry` binds
        // each field's key into the AAD its value is sealed against, so a
        // stored field cannot be renamed or moved to another key undetected.
        let __map = #krate::Cipher::encrypt_map(__cipher, __aad);
        #(#entries)*
        #krate::MapCipher::end(__map)
    }
}

/// No fields: `MapCipher::end` emits the authenticated empty-map marker, so
/// even a field-less struct binds its AAD.
fn empty_body(krate: &syn::Path) -> TokenStream {
    quote! {
        #krate::MapCipher::end(#krate::Cipher::encrypt_map(__cipher, __aad))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{assert_contains, assert_lacks};

    fn expand(input: DeriveInput) -> String {
        derive(input).expect("expansion should succeed").to_string()
    }

    /// Every field is sealed through `encrypt_entry`, which binds the key into
    /// the AAD — that binding is what stops a stored field being renamed or
    /// swapped with another of the same type.
    #[test]
    fn each_field_is_sealed_against_its_own_key() {
        let out = expand(parse_quote! {
            struct User {
                name: String,
                age: u32,
            }
        });

        assert_contains(
            &out,
            quote!(::vitaminc_aead::Cipher::encrypt_map(__cipher, __aad)),
        );
        assert_contains(
            &out,
            quote!(::vitaminc_aead::MapCipher::encrypt_entry(
                __map, "name", self.name
            )),
        );
        assert_contains(
            &out,
            quote!(::vitaminc_aead::MapCipher::encrypt_entry(
                __map, "age", self.age
            )),
        );
        assert_contains(&out, quote!(::vitaminc_aead::MapCipher::end(__map)));
    }

    /// Field names are part of the wire contract, so `rename` has to reach the
    /// key the value is bound to — not just the source-level name.
    #[test]
    fn rename_replaces_the_map_key() {
        let out = expand(parse_quote! {
            struct User {
                #[aead(rename = "yrs")]
                age: u32,
            }
        });

        assert_contains(
            &out,
            quote!(::vitaminc_aead::MapCipher::encrypt_entry(
                __map, "yrs", self.age
            )),
        );
        assert_lacks(&out, quote!("age"));
    }

    /// A tuple struct of two or more fields keys on the decimal field index, so
    /// its fields get the same per-key binding a named struct's do.
    #[test]
    fn tuple_fields_are_keyed_by_index() {
        let out = expand(parse_quote!(
            struct Pair(String, u32);
        ));

        assert_contains(
            &out,
            quote!(::vitaminc_aead::MapCipher::encrypt_entry(
                __map, "0", self.0
            )),
        );
        assert_contains(
            &out,
            quote!(::vitaminc_aead::MapCipher::encrypt_entry(
                __map, "1", self.1
            )),
        );
    }

    /// A newtype adds nothing to the ciphertext: no map is opened, so wrapping
    /// an existing type does not break its stored values.
    #[test]
    fn newtype_delegates_to_its_inner_value() {
        let out = expand(parse_quote!(
            struct Wrapper(String);
        ));

        assert_contains(
            &out,
            quote!(::vitaminc_aead::Encrypt::encrypt_with_aad(
                self.0, __cipher, __aad
            )),
        );
        assert_lacks(&out, quote!(::vitaminc_aead::Cipher::encrypt_map));
    }

    /// A field-less struct still opens and ends a map: the empty-map marker is
    /// authenticated, so even this binds its AAD.
    #[test]
    fn empty_struct_still_binds_its_aad() {
        let out = expand(parse_quote!(
            struct Marker {}
        ));

        assert_contains(
            &out,
            quote!(::vitaminc_aead::MapCipher::end(
                ::vitaminc_aead::Cipher::encrypt_map(__cipher, __aad)
            )),
        );
        assert_lacks(&out, quote!(::vitaminc_aead::MapCipher::encrypt_entry));
    }

    /// Serde-style: bounding the parameter rather than each field's type lets a
    /// field of type `Vec<T>` pick up `Vec<T>: Encrypt` from the blanket impl.
    #[test]
    fn type_parameters_gain_an_encrypt_bound() {
        let out = expand(parse_quote! {
            struct Holder<T> {
                value: T,
            }
        });

        assert_contains(&out, quote!(impl<T: ::vitaminc_aead::Encrypt>));
        assert_contains(&out, quote!(for Holder<T>));
    }

    /// The `crate` attribute has to redirect *every* generated path, or the
    /// expansion half-references a crate the caller may not depend on.
    #[test]
    fn crate_attribute_redirects_every_path() {
        let out = expand(parse_quote! {
            #[aead(crate = "::vitaminc::aead")]
            struct User {
                name: String,
            }
        });

        assert_contains(&out, quote!(::vitaminc::aead::Encrypt for User));
        assert_contains(&out, quote!(::vitaminc::aead::MapCipher::encrypt_entry));
        assert!(
            !out.contains("vitaminc_aead"),
            "expansion still references the default crate path:\n{out}"
        );
    }

    /// Attribute typos are rejected rather than ignored: a silently dropped
    /// `#[aead(...)]` option is a setting the author believes is in effect.
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

    #[test]
    fn unknown_field_attribute_is_rejected() {
        let err = derive(parse_quote! {
            struct User {
                #[aead(bogus = "x")]
                name: String,
            }
        })
        .expect_err("unknown field attribute should be rejected");

        assert!(err.to_string().contains("unsupported field attribute"));
    }
}
