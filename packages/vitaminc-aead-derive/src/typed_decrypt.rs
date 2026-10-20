//! Expansion of the sink-based `#[derive(Decrypt)]`.
//!
//! A struct's target is a map sink with one slot per stored field. Its
//! `entry` looks the key up and hands back that field's own sink, so each
//! value is decoded by its own type; `end` refuses a missing field and
//! builds the struct. The field sinks have different types, so `entry`
//! returns them as a chain of `Either`s. The two generated types are
//! hidden items beside the struct, with its visibility, because an
//! associated type of a public impl cannot name a private one (E0446).
//! The same rule means a field's type has to be at least as visible as
//! the struct, since the entry sink names it; a type that should stay
//! unreachable can be `pub` inside a private module.

use proc_macro2::TokenStream;
use quote::{format_ident, quote, quote_spanned};
use syn::spanned::Spanned;
use syn::{parse_quote, DeriveInput, Result};

use crate::{
    attrs::ContainerAttrs,
    shape::{FieldInfo, Shape, VariantInfo},
};

pub(crate) fn derive(input: DeriveInput) -> Result<TokenStream> {
    let attrs = ContainerAttrs::parse(&input.attrs)?;
    let krate = &attrs.krate;
    let shape = Shape::parse(&input)?;
    let name = &input.ident;
    let vis = &input.vis;

    // Every type parameter must itself be a target, serde-style, so a field
    // of type `Vec<T>` picks up `Vec<T>: Decrypt` from the blanket impl.
    let mut generics = input.generics.clone();
    for param in generics.type_params_mut() {
        param.bounds.push(parse_quote!(#krate::typed::Decrypt));
    }
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();
    // The generated items are declared with the struct's own generics, and
    // the bounds live on their impls, as for any generic type.
    let (decl_generics, _, decl_where) = input.generics.split_for_impl();
    // Uses every generic parameter at once, whatever its kind, without
    // owning anything: `fn() -> T` is covariant and carries no drop check,
    // where `PhantomData<T>` would make the sink own a `T`.
    let marker = quote!(::core::marker::PhantomData<fn() -> #name #ty_generics>);

    let expanded = match &shape {
        Shape::Enum(variants) => enum_target(krate, &input, variants),
        Shape::Newtype(field) => {
            let inner = &field.ty;
            let wrap = format_ident!("__{name}DecryptWrap");
            quote! {
                #[doc(hidden)]
                #vis struct #wrap #decl_generics (#marker) #decl_where;

                #[automatically_derived]
                impl #impl_generics #krate::typed::Rewrap<#inner> for #wrap #ty_generics #where_clause {
                    type Output = #name #ty_generics;
                    fn rewrap(__value: #inner) -> ::core::result::Result<Self::Output, #krate::DecodeError> {
                        ::core::result::Result::Ok(#name(__value))
                    }
                }

                // Transparent, mirroring the `Encrypt` side: the inner
                // type's sink, with its result rewrapped.
                #[automatically_derived]
                impl #impl_generics #krate::typed::Decrypt for #name #ty_generics #where_clause {
                    type Sink = #krate::typed::Wrapped<
                        <#inner as #krate::typed::Decrypt>::Sink,
                        #wrap #ty_generics,
                    >;
                    fn reads_null(__ty: #krate::FixedType) -> bool {
                        <#inner as #krate::typed::Decrypt>::reads_null(__ty)
                    }
                    fn sink() -> Self::Sink {
                        #krate::typed::Wrapped::new(<#inner as #krate::typed::Decrypt>::sink())
                    }
                }
            }
        }
        Shape::Map(fields) => map_target(krate, &input, fields, &marker),
        Shape::Empty => map_target(krate, &input, &[], &marker),
    };

    Ok(expanded)
}

fn map_target(
    krate: &syn::Path,
    input: &DeriveInput,
    fields: &[FieldInfo],
    marker: &TokenStream,
) -> TokenStream {
    let name = &input.ident;
    let vis = &input.vis;
    let expected = name.to_string();
    let mut generics = input.generics.clone();
    for param in generics.type_params_mut() {
        param.bounds.push(parse_quote!(#krate::typed::Decrypt));
    }
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();
    let (decl_generics, _, decl_where) = input.generics.split_for_impl();
    let sink = format_ident!("__{name}DecryptSink");
    let map = format_ident!("__{name}DecryptMap");

    let stored: Vec<&FieldInfo> = fields.iter().filter(|field| field.stored()).collect();

    let slots = stored.iter().map(|field| {
        let local = &field.local;
        let ty = &field.ty;
        quote!(#local: ::core::option::Option<#ty>,)
    });
    let empty_slots = stored.iter().map(|field| {
        let local = &field.local;
        quote!(#local: ::core::option::Option::None,)
    });

    // One sink type per stored field, chained as `Either<S0, Either<S1, S2>>`
    // so `entry` has a single return type. The last field is the chain's
    // tail rather than a `Left` of its own.
    let field_sink = |field: &FieldInfo| {
        let ty = &field.ty;
        if field.passthrough {
            quote!(#krate::typed::Clear<#ty, #krate::typed::Slot<'__s, #ty>>)
        } else {
            quote!(#krate::typed::Forward<#ty, #krate::typed::Slot<'__s, #ty>>)
        }
    };
    let entry_ty = stored.iter().rev().fold(None, |tail, field| {
        let head = field_sink(field);
        Some(match tail {
            None => head,
            Some(tail) => quote!(#krate::typed::Either<#head, #tail>),
        })
    });
    // An empty struct hands out no entry sink at all; the type still has to
    // be named.
    let entry_ty = entry_ty.unwrap_or_else(|| quote!(#krate::typed::Nothing));

    let arms = stored.iter().enumerate().map(|(index, field)| {
        let key = &field.key;
        let local = &field.local;
        let ty = &field.ty;
        let build = if field.passthrough {
            // Nothing here is verified — no tag covers a passthrough entry
            // and nothing binds its key — so what comes back is untrusted
            // input, exactly as the column it came from is.
            quote!(#krate::typed::Clear::new(#krate::typed::Slot(&mut self.#local)))
        } else {
            // Spanned to the field's type, so "`Foo` does not implement
            // `Decrypt`" points at the field rather than at the derive.
            let sink = quote_spanned!(ty.span()=> <#ty as #krate::typed::Decrypt>::sink());
            quote!(#krate::typed::Forward(
                #sink,
                #krate::typed::Slot(&mut self.#local),
            ))
        };
        let last = index + 1 == stored.len();
        let wrapped = (0..index).fold(
            if last {
                build
            } else {
                quote!(#krate::typed::Either::Left(#build))
            },
            |inner, _| quote!(#krate::typed::Either::Right(#inner)),
        );
        // The walk refuses a repeated key before any leaf is opened; this
        // catches a source that does not, rather than let last-wins
        // overwrite a field that has already been decoded.
        quote! {
            #key => {
                if self.#local.is_some() {
                    return ::core::result::Result::Err(#krate::DecodeError::duplicate_key(__key));
                }
                ::core::result::Result::Ok(#wrapped)
            }
        }
    });

    let inits = fields.iter().map(|field| {
        let member = &field.member;
        let local = &field.local;
        let key = &field.key;
        if field.skip {
            quote!(#member: ::core::default::Default::default(),)
        } else {
            // A missing field is a refusal, not a default: an absent entry
            // is an unauthenticated one.
            quote!(#member: self.#local.ok_or(#krate::DecodeError::MissingField(#key))?,)
        }
    });

    quote! {
        #[doc(hidden)]
        #vis struct #sink #decl_generics (#marker) #decl_where;

        #[doc(hidden)]
        #vis struct #map #decl_generics #decl_where {
            #(#slots)*
            __marker: #marker,
        }

        #[automatically_derived]
        impl #impl_generics #krate::Sink for #sink #ty_generics #where_clause {
            type Ok = #name #ty_generics;
            type Error = #krate::DecodeError;
            type Seq = #krate::typed::Never<#name #ty_generics>;
            type Map = #map #ty_generics;

            fn scalar(
                self,
                _: ::core::option::Option<#krate::Logical>,
                _: #krate::Physical<'_>,
            ) -> ::core::result::Result<Self::Ok, Self::Error> {
                ::core::result::Result::Err(#krate::DecodeError::Expected(#expected))
            }

            fn typed_null(
                self,
                _: #krate::FixedType,
            ) -> ::core::result::Result<Self::Ok, Self::Error> {
                ::core::result::Result::Err(#krate::DecodeError::Expected(#expected))
            }

            fn seq(
                self,
                _: ::core::option::Option<usize>,
            ) -> ::core::result::Result<Self::Seq, Self::Error> {
                ::core::result::Result::Err(#krate::DecodeError::Expected(#expected))
            }

            fn map(
                self,
                _: ::core::option::Option<usize>,
            ) -> ::core::result::Result<Self::Map, Self::Error> {
                ::core::result::Result::Ok(#map {
                    #(#empty_slots)*
                    __marker: ::core::marker::PhantomData,
                })
            }

            // A passthrough is unauthenticated, so it must never stand in
            // for a sealed struct.
            fn passthrough<__P>(self, _: __P) -> ::core::result::Result<Self::Ok, Self::Error>
            where
                __P: #krate::Encrypt + ::core::clone::Clone,
            {
                ::core::result::Result::Err(#krate::DecodeError::Expected(#expected))
            }
        }

        #[automatically_derived]
        #[allow(clippy::type_complexity)]
        impl #impl_generics #krate::MapSink for #map #ty_generics #where_clause {
            type Ok = #name #ty_generics;
            type Error = #krate::DecodeError;
            type Entry<'__s>
                = #entry_ty
            where
                Self: '__s;

            // Keys are matched, not positions: entry order in a stored
            // ciphertext is not authenticated, and it is what lets fields
            // have different types at all.
            fn entry(
                &mut self,
                __key: &str,
            ) -> ::core::result::Result<Self::Entry<'_>, Self::Error> {
                match __key {
                    #(#arms)*
                    // Unknown keys are refused rather than skipped: a
                    // skipped value is one nobody checked.
                    _ => ::core::result::Result::Err(#krate::DecodeError::unknown_key(__key)),
                }
            }

            fn end(self) -> ::core::result::Result<Self::Ok, Self::Error> {
                ::core::result::Result::Ok(#name { #(#inits)* })
            }
        }

        #[automatically_derived]
        impl #impl_generics #krate::typed::Decrypt for #name #ty_generics #where_clause {
            type Sink = #sink #ty_generics;
            fn sink() -> Self::Sink {
                #sink(::core::marker::PhantomData)
            }
        }
    }
}

/// A fieldless enum reads one int leaf and matches its value against the
/// discriminants, whatever width the leaf was written at. Anything else,
/// a value that is no variant's included, is refused by the enum's name.
/// Going through `FromScalar` gives the enum its `Decrypt` through the
/// blanket impl.
fn enum_target(krate: &syn::Path, input: &DeriveInput, variants: &[VariantInfo]) -> TokenStream {
    let name = &input.ident;
    let expected = name.to_string();
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();
    let arms = variants.iter().map(|variant| {
        let ident = &variant.ident;
        let discriminant = u128::from(variant.discriminant);
        quote! {
            ::core::option::Option::Some(#discriminant) => ::core::option::Option::Some(#name::#ident),
        }
    });
    quote! {
        #[automatically_derived]
        impl #impl_generics #krate::FromScalar for #name #ty_generics #where_clause {
            const EXPECTED: &'static str = #expected;
            // Its own `None`, even with no variant at zero to read.
            const FIXED: ::core::option::Option<#krate::FixedType> =
                #krate::FixedType::plain(#krate::Width::U32);

            fn from_scalar(
                __ty: ::core::option::Option<#krate::Logical>,
                __value: #krate::Physical<'_>,
            ) -> ::core::option::Option<Self> {
                match (__ty, __value) {
                    (::core::option::Option::None, #krate::Physical::Int(__int)) => {
                        match #krate::Int::to_u128(__int) {
                            #(#arms)*
                            _ => ::core::option::Option::None,
                        }
                    }
                    _ => ::core::option::Option::None,
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{assert_contains, assert_lacks};

    fn expand(input: DeriveInput) -> String {
        derive(input).expect("expansion should succeed").to_string()
    }

    /// Entry order is not authenticated, so the decode matches the key and
    /// hands back that field's own sink — a positional decode would be wrong.
    #[test]
    fn each_key_routes_to_its_own_field_sink() {
        let out = expand(parse_quote! {
            struct User {
                name: String,
                age: u32,
            }
        });

        assert_contains(&out, quote!(struct __UserDecryptSink));
        assert_contains(&out, quote!(struct __UserDecryptMap));
        assert_contains(&out, quote!("name" =>));
        assert_contains(&out, quote!("age" =>));
        assert_contains(
            &out,
            quote!(::vitaminc_aead::typed::Either::Left(
                ::vitaminc_aead::typed::Forward(
                    <String as ::vitaminc_aead::typed::Decrypt>::sink(),
                    ::vitaminc_aead::typed::Slot(&mut self.__field_0),
                )
            )),
        );
        // The last field is the chain's tail.
        assert_contains(
            &out,
            quote!(::vitaminc_aead::typed::Either::Right(
                ::vitaminc_aead::typed::Forward(
                    <u32 as ::vitaminc_aead::typed::Decrypt>::sink(),
                    ::vitaminc_aead::typed::Slot(&mut self.__field_1),
                )
            )),
        );
        assert_contains(
            &out,
            quote!(type Entry<'__s> = ::vitaminc_aead::typed::Either<),
        );
        assert_contains(
            &out,
            quote!(::vitaminc_aead::typed::Forward<String, ::vitaminc_aead::typed::Slot<'__s, String>>,),
        );
    }

    /// An absent entry is an unauthenticated one, so a missing field is a
    /// refusal that names the key, rather than a default.
    #[test]
    fn a_missing_field_is_refused_by_name() {
        let out = expand(parse_quote! {
            struct User {
                name: String,
            }
        });

        assert_contains(
            &out,
            quote!(name: self
                .__field_0
                .ok_or(::vitaminc_aead::DecodeError::MissingField("name"))?),
        );
    }

    /// Belt and braces over the walk's own duplicate rejection: last-wins
    /// would overwrite a field that has already been decoded.
    #[test]
    fn a_duplicate_key_is_refused() {
        let out = expand(parse_quote! {
            struct User {
                name: String,
            }
        });

        assert_contains(&out, quote!(if self.__field_0.is_some()));
        assert_contains(
            &out,
            quote!(::vitaminc_aead::DecodeError::duplicate_key(__key)),
        );
    }

    /// Unknown keys are refused, not skipped: a skipped value is one nobody
    /// checked.
    #[test]
    fn an_unknown_key_is_refused() {
        let out = expand(parse_quote! {
            struct User {
                name: String,
            }
        });

        assert_contains(
            &out,
            quote!(::vitaminc_aead::DecodeError::unknown_key(__key)),
        );
    }

    /// A passthrough field is built through `Clear`, which only accepts a
    /// passthrough, and a sealed field through `Forward`, which refuses one.
    #[test]
    fn a_passthrough_field_is_read_through_clear() {
        let out = expand(parse_quote! {
            struct Row {
                #[aead(passthrough)]
                tenant: String,
                ssn: String,
            }
        });

        assert_contains(
            &out,
            quote!(::vitaminc_aead::typed::Clear::new(
                ::vitaminc_aead::typed::Slot(&mut self.__field_0)
            )),
        );
        assert_contains(
            &out,
            quote!(::vitaminc_aead::typed::Forward(
                <String as ::vitaminc_aead::typed::Decrypt>::sink(),
                ::vitaminc_aead::typed::Slot(&mut self.__field_1),
            )),
        );
    }

    /// A skipped field has no slot and no key: it is rebuilt with `Default`.
    #[test]
    fn a_skipped_field_is_rebuilt_with_default() {
        let out = expand(parse_quote! {
            struct Row {
                #[aead(skip)]
                id: u64,
                ssn: String,
            }
        });

        assert_lacks(&out, quote!("id" =>));
        assert_lacks(&out, quote!(__field_0: ::core::option::Option<u64>));
        assert_contains(&out, quote!(id: ::core::default::Default::default()));
    }

    /// Mirrors the `Encrypt` side: a newtype decodes as its inner type and
    /// is rewrapped, so no map sink is involved.
    #[test]
    fn newtype_is_transparent() {
        let out = expand(parse_quote!(
            struct Wrapper(String);
        ));

        assert_contains(&out, quote!(struct __WrapperDecryptWrap));
        assert_contains(
            &out,
            quote!(type Sink = ::vitaminc_aead::typed::Wrapped<
                <String as ::vitaminc_aead::typed::Decrypt>::Sink,
                __WrapperDecryptWrap,
            >),
        );
        assert_contains(&out, quote!(::core::result::Result::Ok(Wrapper(__value))));
        assert_lacks(&out, quote!(struct __WrapperDecryptMap));
    }

    /// A field-less struct accepts only the empty map: any entry at all is a
    /// forgery attempt against a shape that has no fields to hold it.
    #[test]
    fn empty_struct_refuses_any_entry() {
        let out = expand(parse_quote!(
            struct Marker {}
        ));

        assert_contains(
            &out,
            quote!(type Entry<'__s> = ::vitaminc_aead::typed::Nothing),
        );
        assert_contains(
            &out,
            quote!(::vitaminc_aead::DecodeError::unknown_key(__key)),
        );
        assert_contains(&out, quote!(::core::result::Result::Ok(Marker {})));
    }

    /// A fieldless enum is a scalar target: one int leaf, matched against
    /// the discriminants, and its `Decrypt` comes from the blanket impl.
    #[test]
    fn a_fieldless_enum_is_a_scalar_target() {
        let out = expand(parse_quote! {
            enum Status {
                Active,
                Suspended = 7,
            }
        });

        assert_contains(&out, quote!(::vitaminc_aead::FromScalar for Status));
        assert_contains(&out, quote!(const EXPECTED: &'static str = "Status"));
        assert_contains(&out, quote!(::vitaminc_aead::Int::to_u128(__int)));
        assert_contains(
            &out,
            quote!(::core::option::Option::Some(0u128) => ::core::option::Option::Some(Status::Active)),
        );
        assert_contains(
            &out,
            quote!(::core::option::Option::Some(7u128) => ::core::option::Option::Some(Status::Suspended)),
        );
        assert_lacks(&out, quote!(typed::Decrypt for Status));
    }

    /// Every type parameter must itself be a target, and the generated
    /// items must use every parameter the struct declares.
    #[test]
    fn generic_parameters_are_bound_and_carried() {
        let out = expand(parse_quote! {
            struct Holder<'a, T, const N: usize> {
                value: T,
                bytes: [u8; N],
                tag: &'a str,
            }
        });

        assert_contains(
            &out,
            quote!(impl<'a, T: ::vitaminc_aead::typed::Decrypt, const N: usize>),
        );
        assert_contains(&out, quote!(fn() -> Holder<'a, T, N>));
        assert_contains(
            &out,
            quote!(struct __HolderDecryptMap<'a, T, const N: usize>),
        );
    }

    /// The generated items take the struct's visibility, since the impl's
    /// associated type names them.
    #[test]
    fn generated_items_take_the_structs_visibility() {
        let out = expand(parse_quote! {
            pub(crate) struct User {
                name: String,
            }
        });

        assert_contains(&out, quote!(pub(crate) struct __UserDecryptSink));
        assert_contains(&out, quote!(pub(crate) struct __UserDecryptMap));
    }

    #[test]
    fn crate_attribute_redirects_every_path() {
        let out = expand(parse_quote! {
            #[aead(crate = "::vitaminc::aead")]
            struct User {
                name: String,
            }
        });

        assert_contains(&out, quote!(::vitaminc::aead::typed::Decrypt for User));
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
