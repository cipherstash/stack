//! Expansion of `#[derive(Plaintext)]`.
//!
//! The by-value `visit` moves each field out and walks it; when the sink or
//! a field refuses part way, the fields not yet reached are walked into a
//! discarding sink first, so every owned leaf among them wraps itself and is
//! wiped rather than dropped bare, as a bare `Vec<T>` does its leftover
//! elements. A struct inside a `Protected` takes the default
//! `visit_protected`, which unwraps and runs that same walk, so its
//! unvisited fields are wiped the same way.
//!
//! The derive does not override `visit_protected` to keep the struct
//! wrapped: that override's signature names `Protected<Self>`, which only
//! exists for a `Zeroize` type, and a derive cannot tell whether the struct
//! is one; for a struct that is not, the override is a compile error.

use proc_macro2::TokenStream;
use quote::quote;
use syn::{parse_quote, DeriveInput, Result};

use crate::{
    attrs::ContainerAttrs,
    shape::{Dialect, FieldInfo, Shape, VariantInfo},
};

pub(crate) fn derive(input: DeriveInput) -> Result<TokenStream> {
    let attrs = ContainerAttrs::parse(&input.attrs)?;
    let krate = &attrs.krate;
    let shape = Shape::parse(&input, Dialect::Sink)?;
    let name = &input.ident;

    // Bound every type parameter, serde-style: a field of type `Vec<T>` then
    // picks up `Vec<T>: Plaintext` from the blanket impl in `vitaminc_aead`.
    let mut generics = input.generics.clone();
    for param in generics.type_params_mut() {
        param.bounds.push(parse_quote!(#krate::Plaintext));
    }
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    // `take` writes an empty value back into `self`, so the receiver has to
    // be mutable; it is left alone otherwise so the expansion does not
    // trigger `unused_mut` in the deriving crate.
    let receiver = if shape_takes(&shape) {
        quote!(mut self)
    } else {
        quote!(self)
    };

    let body = match &shape {
        Shape::Newtype(field) => newtype_body(krate, field),
        Shape::Map(fields) => map_body(krate, fields),
        Shape::Empty => empty_body(krate),
        Shape::Enum(variants) => enum_body(krate, name, variants),
    };

    Ok(quote! {
        #[automatically_derived]
        impl #impl_generics #krate::Plaintext for #name #ty_generics #where_clause {
            fn visit<__S>(#receiver, __sink: __S) -> ::core::result::Result<__S::Ok, __S::Error>
            where
                __S: #krate::Sink,
            {
                #body
            }
        }
    })
}

fn shape_takes(shape: &Shape) -> bool {
    match shape {
        Shape::Newtype(field) => field.take,
        Shape::Map(fields) => fields.iter().any(|field| field.take),
        Shape::Empty | Shape::Enum(_) => false,
    }
}

/// How a field's value leaves `self`: moved out, or taken with `mem::take`
/// for a struct that implements `Drop` and so cannot be destructured.
fn value(field: &FieldInfo) -> TokenStream {
    let member = &field.member;
    if field.take {
        quote!(::core::mem::take(&mut self.#member))
    } else {
        quote!(self.#member)
    }
}

/// A newtype adds nothing to the ciphertext — it describes itself exactly
/// as its inner value, so wrapping a type is not a wire-breaking change.
fn newtype_body(krate: &syn::Path, field: &FieldInfo) -> TokenStream {
    let value = value(field);
    quote! {
        #krate::Plaintext::visit(#value, __sink)
    }
}

/// The by-value walk. Every stored field is moved out as its entry sink
/// arrives; if the sink refuses at any point, the fields not yet moved are
/// discarded through their own walk first, which wipes each owned leaf,
/// rather than dropped bare with `self`.
fn map_body(krate: &syn::Path, fields: &[FieldInfo]) -> TokenStream {
    let stored: Vec<&FieldInfo> = fields.iter().filter(|field| field.stored()).collect();
    let len = stored.len();
    // The fields from `from` on, discarded.
    let discard_from = |from: usize| {
        let rest = stored[from..].iter().map(|field| {
            let value = value(field);
            quote!(#krate::plaintext::__private::discard_one(#value);)
        });
        quote!(#(#rest)*)
    };

    let open = discard_from(0);
    let entries = stored.iter().enumerate().map(|(index, field)| {
        let key = &field.key;
        let value = value(field);
        let on_entry_failure = discard_from(index);
        let on_visit_failure = discard_from(index + 1);
        let visit = if field.passthrough {
            // Stored in the clear and bound to nothing — not the value, not
            // even its key. That is what lets the entry be an ordinary
            // database column other queries read and write independently of
            // the encrypted ones.
            quote!(#krate::Sink::passthrough(__entry, #value))
        } else {
            quote!(#krate::Plaintext::visit(#value, __entry))
        };
        quote! {
            let __entry = match #krate::MapSink::entry(&mut __map, #key) {
                ::core::result::Result::Ok(__entry) => __entry,
                ::core::result::Result::Err(__err) => {
                    #on_entry_failure
                    return ::core::result::Result::Err(__err);
                }
            };
            if let ::core::result::Result::Err(__err) = #visit {
                #on_visit_failure
                return ::core::result::Result::Err(__err);
            }
        }
    });

    quote! {
        // The encrypting sink binds each field's key into the AAD its value
        // is sealed against (`Context::for_map_entry`), so a stored field
        // cannot be renamed or moved to another key undetected.
        let mut __map = match #krate::Sink::map(__sink, ::core::option::Option::Some(#len)) {
            ::core::result::Result::Ok(__map) => __map,
            ::core::result::Result::Err(__err) => {
                #open
                return ::core::result::Result::Err(__err);
            }
        };
        #(#entries)*
        #krate::MapSink::end(__map)
    }
}

/// No fields: an empty map, which the encrypting sink seals as the
/// authenticated empty-map marker, so even a field-less struct binds its
/// AAD.
fn empty_body(krate: &syn::Path) -> TokenStream {
    quote! {
        #krate::MapSink::end(#krate::Sink::map(__sink, ::core::option::Option::Some(0))?)
    }
}

/// A fieldless enum is one int leaf: the variant's discriminant, as a
/// `u32`. Fixed width, so every variant seals to a leaf of the same length
/// and the ciphertext's size gives nothing away. It is sealed and
/// authenticated like any other leaf.
fn enum_body(krate: &syn::Path, name: &syn::Ident, variants: &[VariantInfo]) -> TokenStream {
    let arms = variants.iter().map(|variant| {
        let ident = &variant.ident;
        let discriminant = variant.discriminant;
        quote! {
            #name::#ident => #krate::Sink::scalar(
                __sink,
                ::core::option::Option::None,
                #krate::Physical::Int(#krate::Int::U32(#discriminant)),
            ),
        }
    });
    quote! {
        match self {
            #(#arms)*
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

    /// Every field is walked into its own entry sink, which is what binds
    /// the key into the AAD — that binding is what stops a stored field being
    /// renamed or swapped with another of the same type.
    #[test]
    fn each_field_is_walked_into_its_own_entry() {
        let out = expand(parse_quote! {
            struct User {
                name: String,
                age: u32,
            }
        });

        assert_contains(
            &out,
            quote!(::vitaminc_aead::Sink::map(
                __sink,
                ::core::option::Option::Some(2usize)
            )),
        );
        assert_contains(
            &out,
            quote!(::vitaminc_aead::MapSink::entry(&mut __map, "name")),
        );
        assert_contains(
            &out,
            quote!(::vitaminc_aead::Plaintext::visit(self.name, __entry)),
        );
        assert_contains(
            &out,
            quote!(::vitaminc_aead::MapSink::entry(&mut __map, "age")),
        );
        assert_contains(
            &out,
            quote!(::vitaminc_aead::Plaintext::visit(self.age, __entry)),
        );
        assert_contains(&out, quote!(::vitaminc_aead::MapSink::end(__map)));
    }

    /// When the sink refuses part way, the fields not yet walked are
    /// discarded through their own walk, which wipes them, before the error
    /// is returned. Opening the map discards everything; an entry failure
    /// discards from that field on; a visit failure from the next field on.
    #[test]
    fn fields_not_yet_walked_are_discarded_on_failure() {
        let out = expand(parse_quote! {
            struct User {
                name: String,
                age: u32,
            }
        });

        let discard = |field: TokenStream| quote!(::vitaminc_aead::plaintext::__private::discard_one(#field););
        let name = discard(quote!(self.name));
        let age = discard(quote!(self.age));
        // Map refused: both. Entry for `name` refused: both. `name` refused:
        // `age`. Entry for `age` refused: `age`. `age` refused: nothing.
        assert_eq!(out.matches(&name.to_string()).count(), 2, "{out}");
        assert_eq!(out.matches(&age.to_string()).count(), 4, "{out}");
        assert_contains(
            &out,
            quote!(if let ::core::result::Result::Err(__err) =
                ::vitaminc_aead::Plaintext::visit(self.age, __entry)
            {
                return ::core::result::Result::Err(__err);
            }),
        );
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
            quote!(::vitaminc_aead::MapSink::entry(&mut __map, "yrs")),
        );
        assert_lacks(&out, quote!("age"));
    }

    #[test]
    fn tuple_fields_are_keyed_by_index() {
        let out = expand(parse_quote!(
            struct Pair(String, u32);
        ));

        assert_contains(
            &out,
            quote!(::vitaminc_aead::MapSink::entry(&mut __map, "0")),
        );
        assert_contains(
            &out,
            quote!(::vitaminc_aead::MapSink::entry(&mut __map, "1")),
        );
    }

    /// A passthrough field goes to the entry sink's `passthrough`, never to
    /// `visit`, so it is walked in the clear.
    #[test]
    fn a_passthrough_field_is_stored_in_the_clear() {
        let out = expand(parse_quote! {
            struct Row {
                #[aead(passthrough)]
                tenant: String,
                ssn: String,
            }
        });

        assert_contains(
            &out,
            quote!(::vitaminc_aead::Sink::passthrough(__entry, self.tenant)),
        );
        assert_contains(
            &out,
            quote!(::vitaminc_aead::Plaintext::visit(self.ssn, __entry)),
        );
    }

    /// A skipped field contributes nothing: no entry, and it is not counted
    /// in the map's length hint. It is not discarded either; it was never
    /// part of the walk.
    #[test]
    fn a_skipped_field_has_no_entry() {
        let out = expand(parse_quote! {
            struct Row {
                #[aead(skip)]
                id: u64,
                ssn: String,
            }
        });

        assert_lacks(&out, quote!("id"));
        assert_lacks(&out, quote!(self.id));
        assert_contains(
            &out,
            quote!(::vitaminc_aead::Sink::map(
                __sink,
                ::core::option::Option::Some(1usize)
            )),
        );
    }

    /// `take` is for a struct with a `Drop` impl, which cannot be
    /// destructured: the value is swapped out for its default instead, in
    /// the walk and in the discard.
    #[test]
    fn a_taken_field_is_swapped_for_its_default() {
        let out = expand(parse_quote! {
            struct Secret {
                #[aead(take)]
                token: String,
            }
        });

        assert_contains(&out, quote!(mut self, __sink: __S));
        assert_contains(
            &out,
            quote!(::vitaminc_aead::Plaintext::visit(
                ::core::mem::take(&mut self.token),
                __entry
            )),
        );
        assert_contains(
            &out,
            quote!(::vitaminc_aead::plaintext::__private::discard_one(
                ::core::mem::take(&mut self.token)
            )),
        );
    }

    #[test]
    fn the_receiver_is_only_mutable_when_a_field_is_taken() {
        let out = expand(parse_quote! {
            struct User {
                name: String,
            }
        });
        assert_lacks(&out, quote!(mut self));
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
            quote!(::vitaminc_aead::Plaintext::visit(self.0, __sink)),
        );
        assert_lacks(&out, quote!(::vitaminc_aead::Sink::map));

        let out = expand(parse_quote!(
            struct Token(#[aead(take)] String);
        ));
        assert_contains(
            &out,
            quote!(::vitaminc_aead::Plaintext::visit(
                ::core::mem::take(&mut self.0),
                __sink
            )),
        );
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
            quote!(::vitaminc_aead::MapSink::end(::vitaminc_aead::Sink::map(
                __sink,
                ::core::option::Option::Some(0)
            )?)),
        );
        assert_lacks(&out, quote!(::vitaminc_aead::MapSink::entry));
    }

    /// A fieldless enum is one fixed-width int leaf holding the
    /// discriminant.
    #[test]
    fn a_fieldless_enum_is_a_fixed_width_int_leaf() {
        let out = expand(parse_quote! {
            enum Status {
                Active,
                Suspended = 7,
            }
        });

        assert_contains(
            &out,
            quote!(Status::Active => ::vitaminc_aead::Sink::scalar(
                __sink,
                ::core::option::Option::None,
                ::vitaminc_aead::Physical::Int(::vitaminc_aead::Int::U32(0u32)),
            )),
        );
        assert_contains(
            &out,
            quote!(::vitaminc_aead::Physical::Int(::vitaminc_aead::Int::U32(
                7u32
            ))),
        );
        assert_lacks(&out, quote!(::vitaminc_aead::Physical::Text));
    }

    /// Serde-style: bounding the parameter rather than each field's type lets a
    /// field of type `Vec<T>` pick up `Vec<T>: Plaintext` from the blanket impl.
    #[test]
    fn type_parameters_gain_a_plaintext_bound() {
        let out = expand(parse_quote! {
            struct Holder<T> {
                value: T,
            }
        });

        assert_contains(&out, quote!(impl<T: ::vitaminc_aead::Plaintext>));
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

        assert_contains(&out, quote!(::vitaminc::aead::Plaintext for User));
        assert_contains(&out, quote!(::vitaminc::aead::MapSink::entry));
        assert_contains(
            &out,
            quote!(::vitaminc::aead::plaintext::__private::discard_one),
        );
        assert!(
            !out.contains("vitaminc_aead"),
            "expansion still references the default crate path:\n{out}"
        );
    }

    #[test]
    fn unknown_attributes_are_rejected() {
        let err = derive(parse_quote! {
            #[aead(bogus = "x")]
            struct User {
                name: String,
            }
        })
        .expect_err("unknown container attribute should be rejected");
        assert!(err.to_string().contains("unsupported container attribute"));

        let err = derive(parse_quote! {
            struct User {
                #[aead(bogus = "x")]
                name: String,
            }
        })
        .expect_err("unknown field attribute should be rejected");
        assert!(err.to_string().contains("unsupported field attribute"));

        let err = derive(parse_quote! {
            enum Status {
                #[aead(skip)]
                Active,
            }
        })
        .expect_err("a variant attribute should be rejected");
        assert!(err.to_string().contains("variants take no"));
    }
}
