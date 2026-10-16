//! Expansion of `#[derive(Encrypt)]`.
//!
//! Two impls are generated. The by-value `visit` moves each field out and
//! walks it; when the sink or a field refuses part way, the fields not yet
//! reached are walked into a discarding sink first, so every owned leaf
//! among them wraps itself and is wiped rather than dropped bare, as a bare
//! `Vec<T>` does its leftover elements. The impl for `&Name` walks the
//! fields by reference and moves nothing; it is what a `Protected<Name>`
//! walks through, so the struct stays wrapped and is zeroized whole.

use proc_macro2::TokenStream;
use quote::quote;
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

    // Bound every type parameter, serde-style: a field of type `Vec<T>` then
    // picks up `Vec<T>: Encrypt` from the blanket impl in `vitaminc_aead`.
    let mut generics = input.generics.clone();
    for param in generics.type_params_mut() {
        param.bounds.push(parse_quote!(#krate::Encrypt));
    }
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    // The by-reference impl, for `&'__r Name<..>`: every type parameter is
    // bound by reference, and every lifetime outlives the borrow.
    let mut ref_generics = input.generics.clone();
    for lifetime in ref_generics.lifetimes_mut() {
        lifetime.bounds.push(parse_quote!('__r));
    }
    let ref_predicates: Vec<syn::WherePredicate> = input
        .generics
        .type_params()
        .map(|param| {
            let ident = &param.ident;
            parse_quote!(&'__r #ident: #krate::Encrypt)
        })
        .collect();
    ref_generics
        .make_where_clause()
        .predicates
        .extend(ref_predicates);
    ref_generics.params.insert(0, parse_quote!('__r));
    let (ref_impl_generics, _, ref_where_clause) = ref_generics.split_for_impl();

    // `take` writes an empty value back into `self`, so the receiver has to
    // be mutable; it is left alone otherwise so the expansion does not
    // trigger `unused_mut` in the deriving crate.
    let receiver = if shape_takes(&shape) {
        quote!(mut self)
    } else {
        quote!(self)
    };

    let (body, ref_body) = match &shape {
        Shape::Newtype(field) => (newtype_body(krate, field), newtype_ref_body(krate, field)),
        Shape::Map(fields) => (map_body(krate, fields), map_ref_body(krate, fields)),
        Shape::Empty => (empty_body(krate), empty_body(krate)),
        Shape::Enum(variants) => {
            let body = enum_body(krate, name, variants);
            (body.clone(), body)
        }
    };

    let Depth {
        owned: depth,
        by_ref: ref_depth,
        item_check,
        visit_check,
    } = depth(krate, &input, &shape, attrs.recursive);

    Ok(quote! {
        #[automatically_derived]
        impl #impl_generics #krate::Encrypt for #name #ty_generics #where_clause {
            #depth

            fn visit<__S>(#receiver, __sink: __S) -> ::core::result::Result<__S::Ok, __S::Error>
            where
                __S: #krate::Sink,
            {
                #visit_check
                #body
            }
        }

        #[automatically_derived]
        impl #ref_impl_generics #krate::Encrypt for &'__r #name #ty_generics #ref_where_clause {
            #ref_depth

            fn visit<__S>(self, __sink: __S) -> ::core::result::Result<__S::Ok, __S::Error>
            where
                __S: #krate::Sink,
            {
                #visit_check
                #ref_body
            }
        }

        #item_check
    })
}

/// The `DEPTH` constants for both impls, and the check that the type fits
/// within `MAX_DEPTH`.
struct Depth {
    owned: TokenStream,
    by_ref: TokenStream,
    /// A named `const` item, for a type with no generic parameters, so
    /// `cargo check` reports it. trybuild cannot see a post-monomorphization
    /// error, so this is also what the compile-fail tests exercise.
    item_check: TokenStream,
    /// An inline `const` block at the top of `visit`, for a generic type,
    /// whose depth is known only once its parameters are. It fires when the
    /// type is used at a concrete type, under `cargo build`.
    visit_check: TokenStream,
}

/// Work out the type's depth from its fields' depths, the way the encrypting
/// sink counts nesting. A recursive type has no fixed depth, and naming its
/// own `DEPTH` would be a cycle, so it keeps the default `None` and the
/// walk checks each value instead.
fn depth(krate: &syn::Path, input: &DeriveInput, shape: &Shape, recursive: bool) -> Depth {
    let name = &input.ident;
    let none = Depth {
        owned: TokenStream::new(),
        by_ref: TokenStream::new(),
        item_check: TokenStream::new(),
        visit_check: TokenStream::new(),
    };
    if recursive || names_itself(name, shape) {
        return none;
    }

    let depth = quote!(#krate::plaintext::depth);
    let expr = |by_ref: bool| -> TokenStream {
        let of = |ty: &syn::Type| {
            if by_ref {
                quote!(<&'__r #ty as #krate::Encrypt>::DEPTH)
            } else {
                quote!(<#ty as #krate::Encrypt>::DEPTH)
            }
        };
        match shape {
            Shape::Newtype(field) => of(&field.ty),
            Shape::Map(fields) => {
                let deepest = fields
                    .iter()
                    .filter(|field| field.stored())
                    .map(|field| {
                        let child = of(&field.ty);
                        if field.passthrough {
                            quote!(#depth::passthrough(#child))
                        } else {
                            child
                        }
                    })
                    .fold(
                        quote!(#depth::SCALAR),
                        |deepest, child| quote!(#depth::max(#deepest, #child)),
                    );
                quote!(#depth::container(#deepest))
            }
            Shape::Empty | Shape::Enum(_) => quote!(#depth::SCALAR),
        }
    };
    let owned = expr(false);
    let by_ref = expr(true);

    let message = format!(
        "`{name}` nests deeper than `MAX_DEPTH` levels, so the encrypting sink would refuse \
         its fully populated values"
    );
    let check = |ty: TokenStream| {
        quote!(::core::assert!(#depth::within_limit(<#ty as #krate::Encrypt>::DEPTH), #message))
    };
    // A type with no type or const parameters is checked where it is
    // defined, so `cargo check` sees the error. Each lifetime becomes
    // `'static`, which meets any bound a lifetime parameter can have.
    let lifetimes_only = input.generics.type_params().next().is_none()
        && input.generics.const_params().next().is_none();
    let (item_check, visit_check) = if lifetimes_only {
        let ty = if input.generics.params.is_empty() {
            quote!(#name)
        } else {
            let statics = input.generics.lifetimes().map(|_| quote!('static));
            quote!(#name<#(#statics),*>)
        };
        // The `&Name` impl works its depth out from each field's `&Field`
        // impl, which may differ from the owned one, so both are checked.
        let owned = check(ty.clone());
        let borrowed = check(quote!(&'static #ty));
        (
            quote!(const _: () = { #owned; #borrowed; };),
            TokenStream::new(),
        )
    } else {
        let assertion = check(quote!(Self));
        (TokenStream::new(), quote!(const { #assertion };))
    };

    Depth {
        owned: quote!(const DEPTH: ::core::option::Option<usize> = #owned;),
        by_ref: quote!(const DEPTH: ::core::option::Option<usize> = #by_ref;),
        item_check,
        visit_check,
    }
}

/// Whether a walked field's type names the type being derived, directly or
/// as `Self`: a recursive type, whose depth depends on the value. Mutual
/// recursion through another type cannot be seen from here; it needs
/// `#[aead(recursive)]`.
fn names_itself(name: &syn::Ident, shape: &Shape) -> bool {
    // The type's name counts only where it does not follow `::`, so a
    // field of another module's type with the same name (`db::User`) is not
    // taken for recursion. A self-reference through a full path, such as
    // `crate::models::Tree`, is then a cycle error, and the attribute docs
    // send the author to `#[aead(recursive)]`.
    fn mentions(tokens: TokenStream, name: &syn::Ident) -> bool {
        let mut after_path_sep = false;
        tokens.into_iter().any(|token| {
            let hit = match &token {
                proc_macro2::TokenTree::Ident(ident) => {
                    ident == "Self" || (!after_path_sep && ident == name)
                }
                proc_macro2::TokenTree::Group(group) => mentions(group.stream(), name),
                _ => false,
            };
            after_path_sep =
                matches!(&token, proc_macro2::TokenTree::Punct(p) if p.as_char() == ':');
            hit
        })
    }
    let walked: Vec<&FieldInfo> = match shape {
        Shape::Newtype(field) => vec![field],
        Shape::Map(fields) => fields.iter().filter(|field| field.stored()).collect(),
        Shape::Empty | Shape::Enum(_) => Vec::new(),
    };
    walked
        .iter()
        .any(|field| mentions(quote::ToTokens::to_token_stream(&field.ty), name))
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
        #krate::Encrypt::visit(#value, __sink)
    }
}

fn newtype_ref_body(krate: &syn::Path, field: &FieldInfo) -> TokenStream {
    let member = &field.member;
    quote! {
        #krate::Encrypt::visit(&self.#member, __sink)
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
            quote!(#krate::Encrypt::visit(#value, __entry))
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

/// The by-reference walk: nothing is moved, so nothing needs discarding.
fn map_ref_body(krate: &syn::Path, fields: &[FieldInfo]) -> TokenStream {
    let stored: Vec<&FieldInfo> = fields.iter().filter(|field| field.stored()).collect();
    let len = stored.len();
    let entries = stored.iter().map(|field| {
        let key = &field.key;
        let member = &field.member;
        if field.passthrough {
            quote! {
                #krate::Sink::passthrough(#krate::MapSink::entry(&mut __map, #key)?, &self.#member)?;
            }
        } else {
            quote! {
                #krate::Encrypt::visit(&self.#member, #krate::MapSink::entry(&mut __map, #key)?)?;
            }
        }
    });
    quote! {
        let mut __map = #krate::Sink::map(__sink, ::core::option::Option::Some(#len))?;
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
            quote!(::vitaminc_aead::Encrypt::visit(self.name, __entry)),
        );
        assert_contains(
            &out,
            quote!(::vitaminc_aead::MapSink::entry(&mut __map, "age")),
        );
        assert_contains(
            &out,
            quote!(::vitaminc_aead::Encrypt::visit(self.age, __entry)),
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
                ::vitaminc_aead::Encrypt::visit(self.age, __entry)
            {
                return ::core::result::Result::Err(__err);
            }),
        );
    }

    /// The by-reference impl walks the same entries without moving anything;
    /// it is what a `Protected<Name>` walks through.
    #[test]
    fn a_struct_also_walks_by_reference() {
        let out = expand(parse_quote! {
            struct Row {
                #[aead(passthrough)]
                tenant: String,
                name: String,
            }
        });

        assert_contains(
            &out,
            quote!(impl<'__r> ::vitaminc_aead::Encrypt for &'__r Row),
        );
        assert_contains(
            &out,
            quote!(::vitaminc_aead::Encrypt::visit(
                &self.name,
                ::vitaminc_aead::MapSink::entry(&mut __map, "name")?
            )),
        );
        assert_contains(
            &out,
            quote!(::vitaminc_aead::Sink::passthrough(
                ::vitaminc_aead::MapSink::entry(&mut __map, "tenant")?,
                &self.tenant
            )),
        );
        let out = expand(parse_quote!(
            struct Wrapper(String);
        ));
        assert_contains(
            &out,
            quote!(::vitaminc_aead::Encrypt::visit(&self.0, __sink)),
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
            quote!(::vitaminc_aead::Encrypt::visit(self.ssn, __entry)),
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
            quote!(::vitaminc_aead::Encrypt::visit(
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
            quote!(::vitaminc_aead::Encrypt::visit(self.0, __sink)),
        );
        assert_lacks(&out, quote!(::vitaminc_aead::Sink::map));

        let out = expand(parse_quote!(
            struct Token(#[aead(take)] String);
        ));
        assert_contains(
            &out,
            quote!(::vitaminc_aead::Encrypt::visit(
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
    /// field of type `Vec<T>` pick up `Vec<T>: Encrypt` from the blanket
    /// impl. The by-reference impl bounds the parameter by reference, and its
    /// lifetimes outlive the borrow.
    #[test]
    fn type_parameters_gain_a_plaintext_bound_by_value_and_by_reference() {
        let out = expand(parse_quote! {
            struct Holder<'a, T> {
                value: T,
                label: &'a str,
            }
        });

        assert_contains(&out, quote!(impl<'a, T: ::vitaminc_aead::Encrypt>));
        assert_contains(&out, quote!(for Holder<'a, T>));
        assert_contains(&out, quote!(impl<'__r, 'a: '__r, T>));
        assert_contains(&out, quote!(&'__r T: ::vitaminc_aead::Encrypt));
        assert_contains(&out, quote!(for &'__r Holder<'a, T>));
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

    /// A struct's depth is one more than its deepest walked field's, and a
    /// type with no generic parameters is checked by a named `const` item,
    /// which `cargo check` evaluates.
    #[test]
    fn a_struct_declares_its_depth_and_checks_it_at_compile_time() {
        let out = expand(parse_quote! {
            struct User {
                name: String,
                #[aead(passthrough)]
                tenant: Vec<u32>,
                #[aead(skip)]
                cached: Vec<Vec<u32>>,
            }
        });

        let depth = quote!(::vitaminc_aead::plaintext::depth);
        assert_contains(
            &out,
            quote!(const DEPTH: ::core::option::Option<usize> = #depth::container(
                #depth::max(
                    #depth::max(#depth::SCALAR, <String as ::vitaminc_aead::Encrypt>::DEPTH),
                    #depth::passthrough(<Vec<u32> as ::vitaminc_aead::Encrypt>::DEPTH)
                )
            );),
        );
        assert_contains(
            &out,
            quote!(<&'__r String as ::vitaminc_aead::Encrypt>::DEPTH),
        );
        assert_lacks(&out, quote!(Vec<Vec<u32>>));
        assert_contains(
            &out,
            quote!(#depth::within_limit(<User as ::vitaminc_aead::Encrypt>::DEPTH)),
        );
        assert_contains(
            &out,
            quote!(#depth::within_limit(<&'static User as ::vitaminc_aead::Encrypt>::DEPTH)),
        );
        assert!(
            out.contains("const _ : () = { :: core :: assert !"),
            "{out}"
        );
        assert!(!out.contains("const {"), "{out}");

        // A type with only lifetime parameters is checked where it is
        // defined too, at `'static`.
        let out = expand(parse_quote! {
            struct Row<'a, 'b: 'a> {
                name: &'a str,
                tags: Vec<&'b str>,
            }
        });
        assert_contains(
            &out,
            quote!(#depth::within_limit(<Row<'static, 'static> as ::vitaminc_aead::Encrypt>::DEPTH)),
        );
        assert_contains(
            &out,
            quote!(#depth::within_limit(<&'static Row<'static, 'static> as ::vitaminc_aead::Encrypt>::DEPTH)),
        );
        assert!(!out.contains("const {"), "{out}");
    }

    /// A generic type's depth is known only at a concrete type, so it is
    /// checked inside `visit`, where it is monomorphized.
    #[test]
    fn a_generic_type_is_checked_where_it_is_used() {
        let out = expand(parse_quote! {
            struct Holder<T> {
                value: T,
            }
        });

        assert!(out.contains("const {"), "{out}");
        assert_contains(
            &out,
            quote!(::vitaminc_aead::plaintext::depth::within_limit(
                <Self as ::vitaminc_aead::Encrypt>::DEPTH
            )),
        );
        assert_lacks(&out, quote!(const _: ()));
    }

    /// A type that names itself, directly or as `Self`, has no fixed depth,
    /// and naming its own `DEPTH` would be a cycle, so it declares none.
    /// `#[aead(recursive)]` says the same for mutual recursion.
    #[test]
    fn a_recursive_type_declares_no_depth() {
        for input in [
            parse_quote!(
                struct Tree {
                    children: Vec<Tree>,
                }
            ),
            parse_quote!(
                struct List {
                    tail: Option<Vec<Self>>,
                }
            ),
            parse_quote!(
                struct Wrapped(Vec<Wrapped>);
            ),
            // Named inside a tuple or an array, the type sits in a
            // delimited group of tokens, which is searched too.
            parse_quote!(
                struct Pair {
                    pair: (u32, Vec<Pair>),
                }
            ),
            parse_quote!(
                struct Fixed {
                    items: [Option<Box<Self>>; 2],
                }
            ),
            parse_quote!(
                #[aead(recursive)]
                struct Even {
                    next: Vec<Odd>,
                }
            ),
        ] {
            let out = expand(input);
            assert_lacks(&out, quote!(const DEPTH));
            assert_lacks(&out, quote!(within_limit));
        }

        // Another type with the same name, reached through a path, is not
        // recursion: its depth is fixed and checked as any other.
        let out = expand(parse_quote! {
            struct User {
                id: u32,
                inner: legacy::User,
            }
        });
        assert_contains(
            &out,
            quote!(<legacy::User as ::vitaminc_aead::Encrypt>::DEPTH),
        );
        assert_contains(&out, quote!(within_limit));

        // A skipped field is not walked, so naming the type there is no
        // recursion.
        let out = expand(parse_quote! {
            struct Cached {
                value: u32,
                #[aead(skip)]
                previous: Option<Box<Cached>>,
            }
        });
        assert_contains(&out, quote!(const DEPTH));
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
