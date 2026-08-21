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
