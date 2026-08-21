//! Expansion of `#[derive(Decrypt)]`.

use proc_macro2::TokenStream;
use quote::quote;
use syn::{parse_quote, DeriveInput, GenericParam, Generics, Result};

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
            let phantom = phantom_data(&input.generics);

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
        quote! {
            #key => {
                // The decipher rejects duplicate keys too; this catches a
                // decipher that does not, rather than last-wins overwriting
                // an already-verified field.
                if #local.is_some() {
                    return ::core::result::Result::Err(#krate::Unspecified);
                }
                #local = ::core::option::Option::Some(
                    <__M as #krate::MapAccess<'__c>>::next_value::<#ty>(&mut __map)
                        .map_err(|_| #krate::Unspecified)?,
                );
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
/// used. `PhantomData` over a tuple of all of them does that without
/// affecting auto-trait inference: each component is `Send` whenever the
/// parameter it stands for is.
fn phantom_data(generics: &Generics) -> TokenStream {
    let parts = generics.params.iter().map(|param| match param {
        GenericParam::Lifetime(lt) => {
            let lifetime = &lt.lifetime;
            quote!(& #lifetime ())
        }
        GenericParam::Type(ty) => {
            let ident = &ty.ident;
            quote!(#ident)
        }
        GenericParam::Const(c) => {
            let ident = &c.ident;
            quote!([u8; #ident])
        }
    });
    quote!((#(#parts,)*))
}
