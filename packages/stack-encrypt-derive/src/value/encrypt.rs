//! Expansion of `#[derive(Encrypt)]`.
//!
//! Two impls are generated. The by-value `visit` moves each field out and
//! walks it; when the sink or a field refuses part way, the fields not yet
//! reached are walked into a discarding sink first, so every owned leaf
//! among them wraps itself and is wiped rather than dropped bare, as a bare
//! `Vec<T>` does its leftover elements. The impl for `&Name` walks the
//! fields by reference and moves nothing; it is what a `Protected<Name>`
//! walks through, so the struct stays wrapped and is zeroized whole.
//!
//! A leaf is one sealed value. A newtype or a fieldless enum is one leaf.
//! So the derive also implements the `Scalar` marker for it, by value and
//! by reference, as every built-in leaf type has. A newtype is a `Scalar`
//! only when its inner type is one.

use proc_macro2::TokenStream;
use quote::quote;
use syn::{parse_quote, DeriveInput, Result};

use super::{
    attrs::ContainerAttrs,
    shape::{FieldInfo, Shape, VariantInfo},
};

pub(crate) fn derive(input: DeriveInput) -> Result<TokenStream> {
    let attrs = ContainerAttrs::parse(&input.attrs)?;
    let aead = &attrs.aead;
    let shape = Shape::parse(&input)?;
    let name = &input.ident;
    // A fieldless enum has no fields, so it cannot contain itself. It is one
    // `u32` leaf, with a fixed depth, even when it is marked `recursive`.
    let recursive = attrs.recursive && !matches!(shape, Shape::Enum(_));

    // Bound every type parameter, serde-style: a field of type `Vec<T>` then
    // picks up `Vec<T>: Encrypt` from the blanket impl in the AEAD crate.
    // A passthrough field is lent to the sink, never moved, so a parameter
    // it names is bounded on `EncryptRef`; one named only there is not
    // bounded on `Encrypt` at all.
    let mut generics = input.generics.clone();
    for param in generics.type_params_mut() {
        let usage = Usage::of(&param.ident, &shape);
        if usage.walked || !usage.lent {
            param.bounds.push(parse_quote!(#aead::Encrypt));
        }
        if usage.lent {
            param.bounds.push(parse_quote!(#aead::EncryptRef));
        }
    }
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    // The by-reference impl, for `&'__r Name<..>`: every type parameter can
    // be walked by reference (`EncryptRef`), which is what a field of `T`,
    // `Vec<T>` or `Option<T>` walked by reference needs. No lifetime is
    // bounded on `'__r`: `&'__r Name<'a>` being well formed already says
    // `'a: '__r`, and saying it again makes `for<'r> &'r Name<'a>: Encrypt`,
    // which a container of `Name<'a>` needs, demand `'a: 'static`.
    let mut ref_generics = input.generics.clone();
    let ref_predicates: Vec<syn::WherePredicate> = input
        .generics
        .type_params()
        .map(|param| {
            let ident = &param.ident;
            parse_quote!(#ident: #aead::EncryptRef)
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
        Shape::Newtype(field) => (newtype_body(aead, field), newtype_ref_body(aead, field)),
        Shape::Map(fields) => (map_body(aead, fields), map_ref_body(aead, fields)),
        Shape::Empty => (empty_body(aead), empty_body(aead)),
        Shape::Enum(variants) => {
            let body = enum_body(aead, name, variants);
            (body.clone(), body)
        }
    };

    let Depth {
        owned: depth,
        by_ref: ref_depth,
        item_check,
        visit_check,
    } = depth(aead, &input, &shape, recursive);
    let (fixed, ref_fixed) = fixed(aead, &input, &shape, recursive);
    let scalar = scalar(aead, &input, &shape, recursive, &generics, &ref_generics);

    Ok(quote! {
        #[automatically_derived]
        impl #impl_generics #aead::Encrypt for #name #ty_generics #where_clause {
            #depth
            #fixed

            fn visit<__S>(#receiver, __sink: __S) -> ::core::result::Result<__S::Ok, __S::Error>
            where
                __S: #aead::Sink,
            {
                #visit_check
                #body
            }
        }

        #[automatically_derived]
        impl #ref_impl_generics #aead::Encrypt for &'__r #name #ty_generics #ref_where_clause {
            #ref_depth
            #ref_fixed

            fn visit<__S>(self, __sink: __S) -> ::core::result::Result<__S::Ok, __S::Error>
            where
                __S: #aead::Sink,
            {
                #visit_check
                #ref_body
            }
        }

        #scalar

        #item_check
    })
}

/// The `Scalar` impls for a type that encrypts as one leaf. Two kinds of
/// type do: a newtype whose inner type is a `Scalar`, and a fieldless enum.
/// A fieldless enum is always one `u32` leaf. A struct with fields is a
/// map, so it gets no impl. A recursive newtype has no fixed depth, so it
/// gets none either.
///
/// Each impl for a newtype has a bound: the inner type is a `Scalar`. So a
/// newtype over a container, such as `Tags(Vec<String>)`, still derives
/// `Encrypt`. The newtype is not a `Scalar`.
///
/// The compiler checks a bound that names no generic parameter where the
/// impl is written. A false bound of that kind is an error. So the
/// borrowed impl's bound names the borrow's lifetime `'__r`. The owned
/// impl's bound is inside a `for<'__s>` binder. The compiler then checks
/// each bound only where code asks for the `Scalar` impl.
fn scalar(
    aead: &syn::Path,
    input: &DeriveInput,
    shape: &Shape,
    recursive: bool,
    generics: &syn::Generics,
    ref_generics: &syn::Generics,
) -> TokenStream {
    let name = &input.ident;
    let mut owned = generics.clone();
    let mut by_ref = ref_generics.clone();
    match shape {
        Shape::Newtype(_) if recursive || names_itself(name, shape) => return TokenStream::new(),
        Shape::Newtype(field) => {
            let ty = &field.ty;
            owned
                .make_where_clause()
                .predicates
                .push(parse_quote!(for<'__s> #ty: #aead::Scalar));
            by_ref
                .make_where_clause()
                .predicates
                .push(parse_quote!(&'__r #ty: #aead::Scalar));
        }
        Shape::Enum(_) => {}
        Shape::Map(_) | Shape::Empty => return TokenStream::new(),
    }
    let (impl_generics, ty_generics, where_clause) = owned.split_for_impl();
    let (ref_impl_generics, _, ref_where_clause) = by_ref.split_for_impl();
    quote! {
        #[automatically_derived]
        impl #impl_generics #aead::Scalar for #name #ty_generics #where_clause {}

        #[automatically_derived]
        impl #ref_impl_generics #aead::Scalar for &'__r #name #ty_generics #ref_where_clause {}
    }
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
fn depth(aead: &syn::Path, input: &DeriveInput, shape: &Shape, recursive: bool) -> Depth {
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

    let depth = quote!(#aead::depth);
    let expr = |by_ref: bool| -> TokenStream {
        let of = |ty: &syn::Type, by_ref: bool| {
            if by_ref {
                quote!(<#ty as #aead::EncryptRef>::REF_DEPTH)
            } else {
                quote!(<#ty as #aead::Encrypt>::DEPTH)
            }
        };
        match shape {
            Shape::Newtype(field) => of(&field.ty, by_ref),
            Shape::Map(fields) => {
                let deepest = fields
                    .iter()
                    .filter(|field| field.stored())
                    .map(|field| {
                        if field.passthrough {
                            // Lent in both impls, so walked by reference
                            // in both.
                            let child = of(&field.ty, true);
                            quote!(#depth::passthrough(#child))
                        } else {
                            of(&field.ty, by_ref)
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
        "`{name}` nests deeper than `stack_encrypt::plaintext::depth::MAX_DEPTH` levels. Stack \
         Encrypt refuses to encrypt a value nested that deeply, so it would refuse every full \
         value of this type"
    );
    let check = |ty: TokenStream| {
        quote!(::core::assert!(#depth::within_limit(<#ty as #aead::Encrypt>::DEPTH), #message))
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

/// The `FIXED` constants for both impls: what an absent value of the type
/// is sealed as. A newtype is transparent, so it has its inner type's (by
/// value and by reference, as `DEPTH` does). A fieldless enum is always a
/// `u32` leaf. A struct is a map, which has none, and a recursive newtype
/// keeps the default rather than name its own constant in a cycle.
fn fixed(
    aead: &syn::Path,
    input: &DeriveInput,
    shape: &Shape,
    recursive: bool,
) -> (TokenStream, TokenStream) {
    let decl = |value: TokenStream| quote!(const FIXED: ::core::option::Option<#aead::FixedType> = #value;);
    match shape {
        Shape::Newtype(_) if recursive || names_itself(&input.ident, shape) => {
            (TokenStream::new(), TokenStream::new())
        }
        Shape::Newtype(field) => {
            let ty = &field.ty;
            (
                decl(quote!(<#ty as #aead::Encrypt>::FIXED)),
                decl(quote!(<#ty as #aead::EncryptRef>::REF_FIXED)),
            )
        }
        Shape::Enum(_) => {
            let u32 = decl(quote!(#aead::FixedType::plain(#aead::Width::U32)));
            (u32.clone(), u32)
        }
        Shape::Map(_) | Shape::Empty => (TokenStream::new(), TokenStream::new()),
    }
}

/// Whether a walked field's type names the type being derived, directly or
/// as `Self`: a recursive type, whose depth depends on the value. Mutual
/// recursion through another type cannot be seen from here; it needs
/// `#[aead(recursive)]`.
fn names_itself(name: &syn::Ident, shape: &Shape) -> bool {
    stored_fields(shape)
        .iter()
        .any(|field| mentions(&field.ty, name, true))
}

/// The fields the walk reaches: a newtype's one, or a struct's stored ones.
fn stored_fields(shape: &Shape) -> Vec<&FieldInfo> {
    match shape {
        Shape::Newtype(field) => vec![field],
        Shape::Map(fields) => fields.iter().filter(|field| field.stored()).collect(),
        Shape::Empty | Shape::Enum(_) => Vec::new(),
    }
}

/// Whether `ty` names `name`, or `Self` too if `or_self`. A name counts only
/// where it does not follow `::`, so a field of another module's type with
/// the same name (`db::User`) is not taken for it. A self-reference through
/// a full path, such as `crate::models::Tree`, is then a cycle error, and
/// the attribute docs send the author to `#[aead(recursive)]`.
fn mentions(ty: &syn::Type, name: &syn::Ident, or_self: bool) -> bool {
    fn search(tokens: TokenStream, name: &syn::Ident, or_self: bool) -> bool {
        let mut after_path_sep = false;
        tokens.into_iter().any(|token| {
            let hit = match &token {
                proc_macro2::TokenTree::Ident(ident) => {
                    (or_self && ident == "Self") || (!after_path_sep && ident == name)
                }
                proc_macro2::TokenTree::Group(group) => search(group.stream(), name, or_self),
                _ => false,
            };
            after_path_sep =
                matches!(&token, proc_macro2::TokenTree::Punct(p) if p.as_char() == ':');
            hit
        })
    }
    search(quote::ToTokens::to_token_stream(ty), name, or_self)
}

/// How the by-value walk uses a type parameter: in a field it walks
/// (`walked`), or in a passthrough field it lends (`lent`). A parameter in
/// neither, such as one only a skipped field names, counts as neither.
struct Usage {
    walked: bool,
    lent: bool,
}

impl Usage {
    fn of(param: &syn::Ident, shape: &Shape) -> Self {
        let mut usage = Usage {
            walked: false,
            lent: false,
        };
        for field in stored_fields(shape) {
            if mentions(&field.ty, param, false) {
                if field.passthrough {
                    usage.lent = true;
                } else {
                    usage.walked = true;
                }
            }
        }
        usage
    }
}

/// Whether the by-value walk takes any field out of `self`. A passthrough
/// field is only lent, so it never does.
fn shape_takes(shape: &Shape) -> bool {
    match shape {
        Shape::Newtype(field) => field.take,
        Shape::Map(fields) => fields.iter().any(|field| field.take && !field.passthrough),
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
fn newtype_body(aead: &syn::Path, field: &FieldInfo) -> TokenStream {
    let value = value(field);
    quote! {
        #aead::Encrypt::visit(#value, __sink)
    }
}

fn newtype_ref_body(aead: &syn::Path, field: &FieldInfo) -> TokenStream {
    let member = &field.member;
    quote! {
        #aead::EncryptRef::visit_ref(&self.#member, __sink)
    }
}

/// The by-value walk. Every stored field is moved out as its entry sink
/// arrives; if the sink refuses at any point, the fields not yet moved are
/// discarded through their own walk first, which wipes each owned leaf,
/// rather than dropped bare with `self`.
fn map_body(aead: &syn::Path, fields: &[FieldInfo]) -> TokenStream {
    let stored: Vec<&FieldInfo> = fields.iter().filter(|field| field.stored()).collect();
    let len = stored.len();
    // The fields from `from` on, discarded. A passthrough field is
    // cleartext by contract and is only lent, never walked by value, so it
    // is left to drop with `self`.
    let discard_from = |from: usize| {
        let rest = stored[from..]
            .iter()
            .filter(|field| !field.passthrough)
            .map(|field| {
                let value = value(field);
                quote!(#aead::discard_one(#value);)
            });
        quote!(#(#rest)*)
    };

    let open = discard_from(0);
    let entries = stored.iter().enumerate().map(|(index, field)| {
        let key = &field.key;
        let on_entry_failure = discard_from(index);
        let on_visit_failure = discard_from(index + 1);
        let visit = if field.passthrough {
            // Stored in the clear and bound to nothing — not the value, not
            // even its key. That is what lets the entry be an ordinary
            // database column other queries read and write independently of
            // the encrypted ones. It is lent in place, so it needs neither a
            // move nor `take`, even on a type that implements `Drop`.
            let member = &field.member;
            quote!(#aead::Sink::passthrough(__entry, &self.#member))
        } else {
            let value = value(field);
            quote!(#aead::Encrypt::visit(#value, __entry))
        };
        quote! {
            let __entry = match #aead::MapSink::entry(&mut __map, #key) {
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
        let mut __map = match #aead::Sink::map(__sink, ::core::option::Option::Some(#len)) {
            ::core::result::Result::Ok(__map) => __map,
            ::core::result::Result::Err(__err) => {
                #open
                return ::core::result::Result::Err(__err);
            }
        };
        #(#entries)*
        #aead::MapSink::end(__map)
    }
}

/// The by-reference walk: nothing is moved, so nothing needs discarding.
fn map_ref_body(aead: &syn::Path, fields: &[FieldInfo]) -> TokenStream {
    let stored: Vec<&FieldInfo> = fields.iter().filter(|field| field.stored()).collect();
    let len = stored.len();
    let entries = stored.iter().map(|field| {
        let key = &field.key;
        let member = &field.member;
        if field.passthrough {
            quote! {
                #aead::Sink::passthrough(#aead::MapSink::entry(&mut __map, #key)?, &self.#member)?;
            }
        } else {
            quote! {
                #aead::EncryptRef::visit_ref(&self.#member, #aead::MapSink::entry(&mut __map, #key)?)?;
            }
        }
    });
    quote! {
        let mut __map = #aead::Sink::map(__sink, ::core::option::Option::Some(#len))?;
        #(#entries)*
        #aead::MapSink::end(__map)
    }
}

/// No fields: an empty map, which the encrypting sink seals as the
/// authenticated empty-map marker, so even a field-less struct binds its
/// AAD.
fn empty_body(aead: &syn::Path) -> TokenStream {
    quote! {
        #aead::MapSink::end(#aead::Sink::map(__sink, ::core::option::Option::Some(0))?)
    }
}

/// A fieldless enum is one int leaf: the variant's discriminant, as a
/// `u32`. Fixed width, so every variant seals to a leaf of the same length
/// and the ciphertext's size gives nothing away. It is sealed and
/// authenticated like any other leaf.
fn enum_body(aead: &syn::Path, name: &syn::Ident, variants: &[VariantInfo]) -> TokenStream {
    let arms = variants.iter().map(|variant| {
        let ident = &variant.ident;
        let discriminant = variant.discriminant;
        quote! {
            #name::#ident => #aead::Sink::scalar(
                __sink,
                ::core::option::Option::None,
                #aead::Physical::Int(#aead::Int::U32(#discriminant)),
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
    use crate::value::test_support::{assert_contains, assert_lacks};

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
            quote!(::stack_encrypt::__derive::Sink::map(
                __sink,
                ::core::option::Option::Some(2usize)
            )),
        );
        assert_contains(
            &out,
            quote!(::stack_encrypt::__derive::MapSink::entry(
                &mut __map, "name"
            )),
        );
        assert_contains(
            &out,
            quote!(::stack_encrypt::__derive::Encrypt::visit(
                self.name, __entry
            )),
        );
        assert_contains(
            &out,
            quote!(::stack_encrypt::__derive::MapSink::entry(&mut __map, "age")),
        );
        assert_contains(
            &out,
            quote!(::stack_encrypt::__derive::Encrypt::visit(self.age, __entry)),
        );
        assert_contains(&out, quote!(::stack_encrypt::__derive::MapSink::end(__map)));
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

        let discard = |field: TokenStream| quote!(::stack_encrypt::__derive::discard_one(#field););
        let name = discard(quote!(self.name));
        let age = discard(quote!(self.age));
        // Map refused: both. Entry for `name` refused: both. `name` refused:
        // `age`. Entry for `age` refused: `age`. `age` refused: nothing.
        assert_eq!(out.matches(&name.to_string()).count(), 2, "{out}");
        assert_eq!(out.matches(&age.to_string()).count(), 4, "{out}");
        assert_contains(
            &out,
            quote!(if let ::core::result::Result::Err(__err) =
                ::stack_encrypt::__derive::Encrypt::visit(self.age, __entry)
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
            quote!(impl<'__r> ::stack_encrypt::__derive::Encrypt for &'__r Row),
        );
        assert_contains(
            &out,
            quote!(::stack_encrypt::__derive::EncryptRef::visit_ref(
                &self.name,
                ::stack_encrypt::__derive::MapSink::entry(&mut __map, "name")?
            )),
        );
        assert_contains(
            &out,
            quote!(::stack_encrypt::__derive::Sink::passthrough(
                ::stack_encrypt::__derive::MapSink::entry(&mut __map, "tenant")?,
                &self.tenant
            )),
        );
        let out = expand(parse_quote!(
            struct Wrapper(String);
        ));
        assert_contains(
            &out,
            quote!(::stack_encrypt::__derive::EncryptRef::visit_ref(
                &self.0, __sink
            )),
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
            quote!(::stack_encrypt::__derive::MapSink::entry(&mut __map, "yrs")),
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
            quote!(::stack_encrypt::__derive::MapSink::entry(&mut __map, "0")),
        );
        assert_contains(
            &out,
            quote!(::stack_encrypt::__derive::MapSink::entry(&mut __map, "1")),
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
            quote!(::stack_encrypt::__derive::Sink::passthrough(
                __entry,
                &self.tenant
            )),
        );
        assert_contains(
            &out,
            quote!(::stack_encrypt::__derive::Encrypt::visit(self.ssn, __entry)),
        );
    }

    /// A passthrough field is lent in place in the by-value walk too, so a
    /// `Drop` type needs no `take` on it and the receiver stays immutable.
    #[test]
    fn a_passthrough_field_is_lent_without_taking_it() {
        let out = expand(parse_quote! {
            struct Row {
                #[aead(passthrough)]
                tenant: String,
                ssn: String,
            }
        });

        assert_contains(
            &out,
            quote!(::stack_encrypt::__derive::Sink::passthrough(
                __entry,
                &self.tenant
            )),
        );
        assert_lacks(&out, quote!(::core::mem::take));
        assert_lacks(&out, quote!(mut self));
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
            quote!(::stack_encrypt::__derive::Sink::map(
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
            quote!(::stack_encrypt::__derive::Encrypt::visit(
                ::core::mem::take(&mut self.token),
                __entry
            )),
        );
        assert_contains(
            &out,
            quote!(::stack_encrypt::__derive::discard_one(::core::mem::take(
                &mut self.token
            ))),
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
            quote!(::stack_encrypt::__derive::Encrypt::visit(self.0, __sink)),
        );
        assert_lacks(&out, quote!(::stack_encrypt::__derive::Sink::map));

        let out = expand(parse_quote!(
            struct Token(#[aead(take)] String);
        ));
        assert_contains(
            &out,
            quote!(::stack_encrypt::__derive::Encrypt::visit(
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
            quote!(::stack_encrypt::__derive::MapSink::end(
                ::stack_encrypt::__derive::Sink::map(__sink, ::core::option::Option::Some(0))?
            )),
        );
        assert_lacks(&out, quote!(::stack_encrypt::__derive::MapSink::entry));
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
            quote!(Status::Active => ::stack_encrypt::__derive::Sink::scalar(
                __sink,
                ::core::option::Option::None,
                ::stack_encrypt::__derive::Physical::Int(::stack_encrypt::__derive::Int::U32(0u32)),
            )),
        );
        assert_contains(
            &out,
            quote!(::stack_encrypt::__derive::Physical::Int(
                ::stack_encrypt::__derive::Int::U32(7u32)
            )),
        );
        assert_lacks(&out, quote!(::stack_encrypt::__derive::Physical::Text));
    }

    /// What an absent value of the type is sealed as: a newtype's inner
    /// type's, by value and by reference; a `u32` leaf for a fieldless
    /// enum; nothing for a struct, which is a map.
    #[test]
    fn fixed_follows_the_shape() {
        let aead = quote!(::stack_encrypt::__derive);
        let out = expand(parse_quote!(
            struct Age(u32);
        ));
        assert_contains(
            &out,
            quote!(
                const FIXED: ::core::option::Option<::stack_encrypt::__derive::FixedType> =
                    <u32 as ::stack_encrypt::__derive::Encrypt>::FIXED;
            ),
        );
        assert_contains(
            &out,
            quote!(
                const FIXED: ::core::option::Option<::stack_encrypt::__derive::FixedType> =
                    <u32 as ::stack_encrypt::__derive::EncryptRef>::REF_FIXED;
            ),
        );

        let out = expand(parse_quote! {
            enum Status {
                Active,
            }
        });
        assert_contains(
            &out,
            quote!(
                const FIXED: ::core::option::Option<#aead::FixedType> =
                    #aead::FixedType::plain(#aead::Width::U32);
            ),
        );

        let out = expand(parse_quote! {
            struct User {
                id: u32,
            }
        });
        assert_lacks(&out, quote!(const FIXED));
    }

    /// A recursive newtype keeps the default `FIXED` rather than name its
    /// own constant in a cycle, whether it names itself or says so with
    /// `#[aead(recursive)]`.
    #[test]
    fn a_recursive_newtype_declares_no_fixed() {
        for input in [
            parse_quote!(
                struct Wrapped(Option<Box<Wrapped>>);
            ),
            parse_quote!(
                #[aead(recursive)]
                struct Even(Option<Box<Odd>>);
            ),
        ] {
            assert_lacks(&expand(input), quote!(const FIXED));
        }
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

        assert_contains(
            &out,
            quote!(impl<'a, T: ::stack_encrypt::__derive::Encrypt>),
        );
        assert_contains(&out, quote!(for Holder<'a, T>));
        assert_contains(&out, quote!(impl<'__r, 'a, T>));
        assert_contains(&out, quote!(T: ::stack_encrypt::__derive::EncryptRef));
        assert_lacks(&out, quote!('a: '__r));
        assert_contains(&out, quote!(for &'__r Holder<'a, T>));
    }

    /// A passthrough field is lent, never walked by value: a parameter only
    /// it names is bounded on `EncryptRef` alone, one a walked field names
    /// too on both, and one only a skipped field names keeps `Encrypt`.
    #[test]
    fn a_parameter_a_passthrough_field_names_is_bounded_by_reference() {
        let out = expand(parse_quote! {
            struct Row<P, B, W, S> {
                #[aead(passthrough)]
                tag: Vec<P>,
                #[aead(passthrough)]
                both: B,
                value: Option<B>,
                walked: W,
                #[aead(skip)]
                skipped: S,
            }
        });

        assert_contains(
            &out,
            quote!(impl<
                P: ::stack_encrypt::__derive::EncryptRef,
                B: ::stack_encrypt::__derive::Encrypt + ::stack_encrypt::__derive::EncryptRef,
                W: ::stack_encrypt::__derive::Encrypt,
                S: ::stack_encrypt::__derive::Encrypt
            > ::stack_encrypt::__derive::Encrypt for Row<P, B, W, S>),
        );
    }

    /// A passthrough field is cleartext by contract and was only lent, so a
    /// failed walk leaves it to drop rather than discarding it by value.
    #[test]
    fn a_passthrough_field_is_not_discarded_on_failure() {
        let out = expand(parse_quote! {
            struct Row {
                #[aead(passthrough)]
                tenant: String,
                ssn: String,
            }
        });

        assert_lacks(
            &out,
            quote!(::stack_encrypt::__derive::discard_one(self.tenant)),
        );
        assert_contains(
            &out,
            quote!(::stack_encrypt::__derive::discard_one(self.ssn)),
        );
    }

    /// The `crate` attribute has to redirect *every* generated path, or the
    /// expansion half-references a crate the caller may not depend on.
    #[test]
    fn crate_attribute_redirects_every_path() {
        let out = expand(parse_quote! {
            #[aead(crate = "::app::encryption")]
            struct User {
                name: String,
            }
        });

        assert_contains(&out, quote!(::app::encryption::__derive::Encrypt for User));
        assert_contains(&out, quote!(::app::encryption::__derive::MapSink::entry));
        assert_contains(&out, quote!(::app::encryption::__derive::discard_one));
        assert!(
            !out.contains(":: stack_encrypt ::"),
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

        let depth = quote!(::stack_encrypt::__derive::depth);
        assert_contains(
            &out,
            quote!(const DEPTH: ::core::option::Option<usize> = #depth::container(
                #depth::max(
                    #depth::max(#depth::SCALAR, <String as ::stack_encrypt::__derive::Encrypt>::DEPTH),
                    #depth::passthrough(<Vec<u32> as ::stack_encrypt::__derive::EncryptRef>::REF_DEPTH)
                )
            );),
        );
        assert_contains(
            &out,
            quote!(<String as ::stack_encrypt::__derive::EncryptRef>::REF_DEPTH),
        );
        assert_lacks(&out, quote!(Vec<Vec<u32>>));
        assert_contains(
            &out,
            quote!(#depth::within_limit(<User as ::stack_encrypt::__derive::Encrypt>::DEPTH)),
        );
        assert_contains(
            &out,
            quote!(#depth::within_limit(<&'static User as ::stack_encrypt::__derive::Encrypt>::DEPTH)),
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
            quote!(#depth::within_limit(<Row<'static, 'static> as ::stack_encrypt::__derive::Encrypt>::DEPTH)),
        );
        assert_contains(
            &out,
            quote!(#depth::within_limit(<&'static Row<'static, 'static> as ::stack_encrypt::__derive::Encrypt>::DEPTH)),
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
            quote!(::stack_encrypt::__derive::depth::within_limit(
                <Self as ::stack_encrypt::__derive::Encrypt>::DEPTH
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
            quote!(<legacy::User as ::stack_encrypt::__derive::Encrypt>::DEPTH),
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

    /// A newtype is a `Scalar` when its inner type is one. The derive
    /// implements `Scalar` by value and by reference. Each impl has the
    /// inner type's `Scalar` as its bound.
    ///
    /// The owned bound is inside a
    /// binder, and the borrowed bound names the borrow's lifetime. So the
    /// compiler does not check either bound where the impl is written. A
    /// newtype over a container still derives.
    #[test]
    fn a_newtype_is_a_scalar_when_its_inner_type_is() {
        let out = expand(parse_quote!(
            struct Email(String);
        ));
        assert_contains(
            &out,
            quote!(impl ::stack_encrypt::__derive::Scalar for Email
                where for<'__s> String: ::stack_encrypt::__derive::Scalar {}),
        );
        assert_contains(
            &out,
            quote!(
                impl<'__r> ::stack_encrypt::__derive::Scalar for &'__r Email where
                    &'__r String: ::stack_encrypt::__derive::Scalar
                {
                }
            ),
        );

        let out = expand(parse_quote!(
            struct Tags(Vec<String>);
        ));
        assert_contains(
            &out,
            quote!(impl ::stack_encrypt::__derive::Scalar for Tags
                where for<'__s> Vec<String>: ::stack_encrypt::__derive::Scalar {}),
        );
        assert_contains(
            &out,
            quote!(
                impl<'__r> ::stack_encrypt::__derive::Scalar for &'__r Tags where
                    &'__r Vec<String>: ::stack_encrypt::__derive::Scalar
                {
                }
            ),
        );
    }

    /// A generic newtype's `Scalar` impls keep the bounds of its `Encrypt`
    /// impls. Each also has the inner type's `Scalar` as a bound.
    #[test]
    #[rustfmt::skip]
    fn a_generic_newtype_is_a_scalar_when_its_parameter_is() {
        let out = expand(parse_quote!(
            struct Wrapper<T>(T);
        ));
        assert_contains(
            &out,
            quote!(
                impl<T: ::stack_encrypt::__derive::Encrypt> ::stack_encrypt::__derive::Scalar for Wrapper<T> where
                    for<'__s> T: ::stack_encrypt::__derive::Scalar
                {
                }
            ),
        );
        assert_contains(
            &out,
            quote!(
                impl<'__r, T> ::stack_encrypt::__derive::Scalar for &'__r Wrapper<T>
                where
                    T: ::stack_encrypt::__derive::EncryptRef,
                    &'__r T: ::stack_encrypt::__derive::Scalar
                {
                }
            ),
        );
    }

    /// A fieldless enum is always one `u32` leaf. So its `Scalar` impls
    /// have no bound.
    #[test]
    fn a_fieldless_enum_is_a_scalar() {
        let out = expand(parse_quote! {
            enum Status {
                Active,
            }
        });
        assert_contains(
            &out,
            quote!(impl ::stack_encrypt::__derive::Scalar for Status {}),
        );
        assert_contains(
            &out,
            quote!(
                impl<'__r> ::stack_encrypt::__derive::Scalar for &'__r Status {}
            ),
        );
    }

    /// A fieldless enum cannot contain itself, so `recursive` changes
    /// nothing. The enum still declares a scalar depth and a `u32` fixed
    /// type, and it is still a `Scalar`.
    // rustfmt would add a trailing comma inside `plain(..)`, which changes
    // the tokens the fragment is compared as.
    #[rustfmt::skip]
    #[test]
    fn a_recursive_fieldless_enum_is_still_one_leaf() {
        let aead = quote!(::stack_encrypt::__derive);
        let out = expand(parse_quote! {
            #[aead(recursive)]
            enum Status {
                Active,
            }
        });
        assert_contains(
            &out,
            quote!(
                const DEPTH: ::core::option::Option<usize> =
                    ::stack_encrypt::__derive::depth::SCALAR;
            ),
        );
        assert_contains(
            &out,
            quote!(
                const FIXED: ::core::option::Option<#aead::FixedType> =
                    #aead::FixedType::plain(#aead::Width::U32);
            ),
        );
        assert_contains(
            &out,
            quote!(impl ::stack_encrypt::__derive::Scalar for Status {}),
        );
        assert_contains(
            &out,
            quote!(
                impl<'__r> ::stack_encrypt::__derive::Scalar for &'__r Status {}
            ),
        );
    }

    /// A struct with fields and a struct with none each encrypt as a map. A
    /// recursive newtype has no fixed depth. So none of them is a `Scalar`.
    #[test]
    fn a_map_or_a_recursive_type_is_not_a_scalar() {
        for input in [
            parse_quote! {
                struct User {
                    name: String,
                }
            },
            parse_quote!(
                struct Pair(String, u32);
            ),
            parse_quote!(
                struct Marker {}
            ),
            parse_quote!(
                struct Wrapped(Vec<Wrapped>);
            ),
            parse_quote!(
                #[aead(recursive)]
                struct Even(Option<Box<Odd>>);
            ),
        ] {
            assert_lacks(&expand(input), quote!(::stack_encrypt::__derive::Scalar));
        }
    }

    /// The `Scalar` path uses the crate named by the `crate` attribute, as
    /// every other path does.
    #[test]
    fn the_marker_follows_the_crate_attribute() {
        let out = expand(parse_quote! {
            #[aead(crate = "::app::encryption")]
            struct Email(String);
        });
        assert_contains(&out, quote!(::app::encryption::__derive::Scalar for Email));
        assert!(
            !out.contains(":: stack_encrypt ::"),
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
