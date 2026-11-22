//! The typed accessors of a document field's declared paths.
//!
//! A field's `#[stash(json(ordered = { "$.age": u32, .. }, paths = {
//! "$.name": String, .. }))]` names its declared paths and their types:
//! `ordered` ones, whose values carry an ordering term, and `paths` ones,
//! compared with equality alone. The derive generates, for the field
//! `profile` of the record `EncryptedCustomer`:
//!
//! - `EncryptedCustomerProfilePaths`, the type of the field's paths: the
//!   fifth type parameter of `EncryptedCustomer::PROFILE`, implementing
//!   `DocumentPaths`.
//! - `EncryptedCustomerProfileAt`, what `PROFILE.at()` returns: one method
//!   per path, returning a `DeclaredPath` of the path's type.
//! - `EncryptedCustomerProfileElements`, what `PROFILE.elements()` returns:
//!   one method per array whose elements have an ordered member.
//! - `EncryptedCustomerProfileElementsVisits`, for the array `$.visits[*]`:
//!   one method per ordered member, returning an `ElementMember` of the
//!   member's type. It implements `ElementArray`, so a predicate on the
//!   array reaches its members again through `and()`.
//!
//! # Names
//!
//! A JSON key gives a word: its ASCII letters in lower case, with `_`
//! before an upper-case letter that follows a lower-case letter or a digit
//! (`firstName` is `first_name`), and `-` read as `_`. A key with any other
//! character gives no word. `names = { "key": word }` gives a key its word
//! instead.
//!
//! An accessor's name is the words of its keys joined by `_`, with the
//! wildcards left out: `$.visits[*].at` is `visits_at` under `at()`, the
//! array `$.visits[*]` is `visits` under `elements()`, and its member
//! `at` is `at`. A path or an array with no keys is `root`. A name that is
//! a Rust keyword is written as a raw identifier (`r#type`). A key that
//! gives no word, a name that is not an identifier, and two paths, arrays
//! or members that give one name are compile errors at the path.

use proc_macro2::{Span, TokenStream};
use quote::{format_ident, quote, quote_spanned};
use stack_encrypt_jsonpath::{JsonPath, Segment};
use syn::spanned::Spanned;
use syn::{Ident, Path, Result, Visibility};

use crate::attrs::{JsonAttr, TypedPath};

/// The type of a field's declared paths, which the field reference's type
/// names: `<Record><Field>Paths`.
pub(crate) fn paths_type(record: &Ident, field: &Ident) -> Ident {
    format_ident!("{}{}Paths", record, pascal(&unraw(field)))
}

/// The accessors of one document field's declared paths, or nothing when
/// the field declares none.
pub(crate) fn accessors(
    krate: &Path,
    vis: &Visibility,
    record: &Ident,
    field: &Ident,
    json: &JsonAttr,
) -> Result<TokenStream> {
    if json.ordered.is_empty() && json.paths.is_empty() {
        return Ok(TokenStream::new());
    }
    let names = Names::new(json);
    let field_name = unraw(field);
    let prefix = format!("{}{}", record, pascal(&field_name));
    let paths = format_ident!("{}Paths", prefix);
    let at = format_ident!("{}At", prefix);
    let elements = format_ident!("{}Elements", prefix);
    let json_mod = quote!(#krate::field_reference::json);
    let reference = quote!(#krate::FieldReference<W, T, C, P, #paths>);
    let bounds = quote! {
        W: #krate::field_reference::Place,
        T: #krate::json::JsonQueries,
        C: #krate::field_reference::ScopeInput,
    };
    let constant = field_name.to_uppercase();

    // Each declared type is one a path can hold, checked at the type: an
    // ordered path's a type an ordering compares, and an unordered path's
    // a type equality compares.
    let types = json.ordered.iter().chain(&json.paths).map(|entry| {
        let ty = &entry.ty;
        if entry.ordered {
            quote_spanned! {ty.span()=> let _ = ordered::<#ty>; }
        } else {
            quote_spanned! {ty.span()=> let _ = unordered::<#ty>; }
        }
    });
    let checks = quote! {
        const _: () = {
            fn ordered<V: #json_mod::JsonPathType>() {}
            fn unordered<V: #json_mod::JsonScalarType>() {}
            #(#types)*
        };
    };

    // One method under `at()` per path, ordered or not.
    let mut at_methods = Vec::new();
    let mut at_names: Vec<(String, &TypedPath)> = Vec::new();
    for ordered in json.ordered.iter().chain(&json.paths) {
        let name = names.accessor(keys(ordered.path.segments()), ordered)?;
        if let Some((_, earlier)) = at_names.iter().find(|(seen, _)| *seen == name) {
            return Err(collision(ordered, earlier, &format!("at().{name}()")));
        }
        let method = method_ident(&name, ordered.text.span())?;
        let text = &ordered.text;
        let ty = &ordered.ty;
        let (order, compares) = if ordered.ordered {
            (
                quote!(#json_mod::OrderedPath),
                "Equality and the orderings compare it",
            )
        } else {
            (
                quote!(#json_mod::EqualityPath),
                "Equality compares it; it is not ordered",
            )
        };
        let doc = format!(
            "The value at `{}`, which holds a `{}`. {compares}.",
            text.value(),
            quote!(#ty)
        );
        let output = quote_spanned!(ty.span()=> #json_mod::DeclaredPath<W, T, C, P, #ty, #order>);
        at_methods.push(quote! {
            #[doc = #doc]
            pub fn #method(self) -> #output {
                #json_mod::DeclaredPath::new(self.0, #text)
            }
        });
        at_names.push((name, ordered));
    }

    // One method under `elements()` per array whose elements have an
    // ordered member, and one type per array holding its members.
    let mut arrays: Vec<Array<'_>> = Vec::new();
    for ordered in &json.ordered {
        let segments = ordered.path.segments();
        let Some(last) = segments
            .iter()
            .rposition(|segment| *segment == Segment::Wildcard)
        else {
            continue;
        };
        let (array, member) = segments.split_at(last + 1);
        if member.is_empty() {
            continue;
        }
        let array = JsonPath::from(array.to_vec());
        match arrays.iter_mut().find(|known| known.path == array) {
            Some(known) => known.members.push((member.to_vec(), ordered)),
            None => arrays.push(Array {
                path: array,
                first: ordered,
                members: vec![(member.to_vec(), ordered)],
            }),
        }
    }
    let mut element_methods = Vec::new();
    let mut array_items = Vec::new();
    let mut array_types = Vec::new();
    let mut array_names: Vec<(String, &TypedPath)> = Vec::new();
    for array in &arrays {
        let name = names.accessor(keys(array.path.segments()), array.first)?;
        if let Some((_, earlier)) = array_names.iter().find(|(seen, _)| *seen == name) {
            return Err(collision(
                array.first,
                earlier,
                &format!("elements().{name}()"),
            ));
        }
        let method = method_ident(&name, array.first.text.span())?;
        let members_type = format_ident!("{}Elements{}", prefix, pascal(&name));
        array_types.push(members_type.clone());
        let array_text = array.path.to_string();
        let doc = format!(
            "The array `{array_text}`: its ordered members are the methods of `{members_type}`."
        );
        element_methods.push(quote! {
            #[doc = #doc]
            pub fn #method(self) -> #members_type<#json_mod::ArrayElements<W, T, C, P, #members_type>> {
                #members_type(#json_mod::ArrayElements::new(self.0, #array_text))
            }
        });
        array_names.push((name, array.first));

        let mut member_methods = Vec::new();
        let mut member_names: Vec<(String, &TypedPath)> = Vec::new();
        for (member, ordered) in &array.members {
            let name = names.accessor(keys(member), ordered)?;
            if let Some((_, earlier)) = member_names.iter().find(|(seen, _)| *seen == name) {
                return Err(collision(
                    ordered,
                    earlier,
                    &format!(
                        "elements().{}().{name}()",
                        array_names.last().map_or("", |n| &n.0)
                    ),
                ));
            }
            let method = method_ident(&name, ordered.text.span())?;
            // A member's text is the path below the element, as the text
            // form of the query names it: `place`, or `["first name"]`.
            let rendered = JsonPath::from(member.clone()).to_string();
            let member_text = rendered
                .strip_prefix("$.")
                .or_else(|| rendered.strip_prefix('$'))
                .unwrap_or(&rendered)
                .to_owned();
            let ty = &ordered.ty;
            let doc = format!(
                "The member `{member_text}` of each element of `{array_text}`, which holds a `{}`. A condition on it holds of one element together with the predicate's other conditions.",
                quote!(#ty)
            );
            let output = quote_spanned!(ty.span()=> #json_mod::ElementMember<Q, #ty>);
            member_methods.push(quote! {
                #[doc = #doc]
                pub fn #method(self) -> #output {
                    #json_mod::ElementMember::new(self.0, #member_text)
                }
            });
            member_names.push((name, ordered));
        }
        let doc = format!(
            "The ordered members of each element of `{array_text}`, in the field `{field_name}`, one method each. Returned by `{record}::{constant}.elements().{}()`, and by `and()` after a condition on one of them.",
            array_names.last().map_or("", |n| &n.0),
        );
        array_items.push(quote! {
            #[doc = #doc]
            #[allow(dead_code)]
            pub struct #members_type<Q = ()>(Q);

            #[automatically_derived]
            #[allow(dead_code)]
            impl<Q> #members_type<Q> {
                #(#member_methods)*
            }

            #[automatically_derived]
            impl #json_mod::ElementArray for #members_type {
                type Members<Q> = #members_type<Q>;
                fn members<Q>(query: Q) -> Self::Members<Q> {
                    #members_type(query)
                }
            }
        });
    }

    let paths_doc = format!(
        "The paths the field `{field_name}` of `{record}` declares, as a type: the last type parameter of `{record}::{constant}`, through which it has `at()` and `elements()`."
    );
    let at_doc = format!(
        "The ordered paths of the field `{field_name}` of `{record}`, one method each: what `{record}::{constant}.at()` returns."
    );
    let elements_doc = format!(
        "The arrays of the field `{field_name}` of `{record}` whose elements have an ordered member, one method each: what `{record}::{constant}.elements()` returns."
    );
    // The types live in a module of their own, so that the field each
    // wraps is private to it and the compiler never suggests reaching
    // through it, and are re-exported beside the record.
    let module = format_ident!("__stash_json_paths_{}_{}", record, field_name);
    Ok(quote! {
        #checks

        #[doc(hidden)]
        #[allow(non_snake_case)]
        mod #module {
            #[allow(unused_imports)]
            use super::*;

        #[doc = #paths_doc]
        #[allow(dead_code)]
        pub enum #paths {}

        #[doc = #at_doc]
        #[allow(dead_code)]
        pub struct #at<W, T, C, P>(#reference);

        #[automatically_derived]
        #[allow(dead_code)]
        impl<W, T, C, P> #at<W, T, C, P>
        where
            #bounds
        {
            #(#at_methods)*
        }

        #[doc = #elements_doc]
        #[allow(dead_code)]
        pub struct #elements<W, T, C, P>(#reference);

        #[automatically_derived]
        #[allow(dead_code)]
        impl<W, T, C, P> #elements<W, T, C, P>
        where
            #bounds
        {
            #(#element_methods)*
        }

        #(#array_items)*

        #[automatically_derived]
        impl #json_mod::DocumentPaths for #paths {
            type At<W, T, C, P> = #at<W, T, C, P>;
            type Elements<W, T, C, P> = #elements<W, T, C, P>;
            fn at<W, T, C, P>(reference: #krate::FieldReference<W, T, C, P, Self>) -> Self::At<W, T, C, P> {
                #at(reference)
            }
            fn elements<W, T, C, P>(reference: #krate::FieldReference<W, T, C, P, Self>) -> Self::Elements<W, T, C, P> {
                #elements(reference)
            }
        }
        }

        #[allow(unused_imports)]
        #vis use #module::{#paths, #at, #elements #(, #array_types)*};
    })
}

/// One array a field declares through its ordered members.
struct Array<'a> {
    path: JsonPath,
    /// The first entry that names it, where an error about it is reported.
    first: &'a TypedPath,
    /// Each member's steps below the element, with its entry.
    members: Vec<(Vec<Segment>, &'a TypedPath)>,
}

/// The keys of `segments`, in order: the wildcards left out. Ordered paths
/// name no position, so every other step is a key.
fn keys(segments: &[Segment]) -> Vec<&str> {
    segments
        .iter()
        .filter_map(|segment| match segment {
            Segment::Key(key) => Some(key.as_str()),
            Segment::Index(_) | Segment::Wildcard => None,
        })
        .collect()
}

/// The words a field's `names = { .. }` gives keys.
struct Names<'a> {
    given: &'a [(syn::LitStr, Ident)],
}

impl<'a> Names<'a> {
    fn new(json: &'a JsonAttr) -> Self {
        Self { given: &json.names }
    }

    /// The word of one key: the one `names` gives it, or the naming rule's.
    fn word(&self, key: &str) -> Option<String> {
        if let Some((_, name)) = self.given.iter().find(|(given, _)| given.value() == key) {
            return Some(unraw(name));
        }
        word(key)
    }

    /// The accessor name of a path, an array or a member with these keys,
    /// reported at `ordered`'s literal when a key gives no word.
    fn accessor(&self, keys: Vec<&str>, ordered: &TypedPath) -> Result<String> {
        if keys.is_empty() {
            return Ok("root".to_owned());
        }
        let mut words = Vec::with_capacity(keys.len());
        for key in keys {
            let Some(word) = self.word(key) else {
                return Err(syn::Error::new(
                    ordered.text.span(),
                    format!(
                        "the key {key:?} gives no accessor name: a key gives one from ASCII \
                         letters, digits, `_` and `-`. Name it with `names = {{ {key:?}: word }}` \
                         in the field's `json(..)`"
                    ),
                ));
            };
            words.push(word);
        }
        Ok(words.join("_"))
    }
}

/// A key's word by the naming rule: ASCII letters in lower case, `_` before
/// an upper-case letter that follows a lower-case letter or a digit, and
/// `-` read as `_`. `None` for a key with any other character, or none.
pub(crate) fn word(key: &str) -> Option<String> {
    let mut out = String::with_capacity(key.len() + 4);
    let mut previous: Option<char> = None;
    for c in key.chars() {
        match c {
            'A'..='Z' => {
                if matches!(previous, Some('a'..='z' | '0'..='9')) {
                    out.push('_');
                }
                out.push(c.to_ascii_lowercase());
            }
            'a'..='z' | '0'..='9' | '_' => out.push(c),
            '-' => out.push('_'),
            _ => return None,
        }
        previous = Some(c);
    }
    (!out.is_empty()).then_some(out)
}

/// The method an accessor name is: the name itself, or a raw identifier
/// for a keyword. A name that is no identifier either way is refused at
/// `span`.
fn method_ident(name: &str, span: Span) -> Result<Ident> {
    if syn::parse_str::<Ident>(name).is_ok() {
        return Ok(Ident::new(name, span));
    }
    let starts_well = name.starts_with(|c: char| c.is_ascii_lowercase() || c == '_');
    let unrawable = matches!(name, "self" | "Self" | "super" | "crate" | "_");
    if starts_well && !unrawable {
        return Ok(Ident::new_raw(name, span));
    }
    Err(syn::Error::new(
        span,
        format!(
            "this path gives the accessor name `{name}`, which is not a Rust identifier. Name \
             the key that starts it with `names = {{ \"key\": word }}` in the field's `json(..)`"
        ),
    ))
}

/// Two entries that give one accessor name, reported at the later.
fn collision(later: &TypedPath, earlier: &TypedPath, accessor: &str) -> syn::Error {
    let mut error = syn::Error::new(
        later.text.span(),
        format!(
            "this path gives the accessor `{accessor}`, which `{}` gives too. Name a key with \
             `names = {{ \"key\": word }}` in the field's `json(..)`",
            earlier.text.value()
        ),
    );
    error.combine(syn::Error::new(
        earlier.text.span(),
        "the accessor's first path",
    ));
    error
}

/// An identifier's text without its `r#`.
fn unraw(ident: &Ident) -> String {
    let text = ident.to_string();
    text.strip_prefix("r#").map(str::to_owned).unwrap_or(text)
}

/// `snake_case` in `PascalCase`: `visits_at` is `VisitsAt`.
fn pascal(snake: &str) -> String {
    snake
        .split('_')
        .filter(|word| !word.is_empty())
        .map(|word| {
            let mut chars = word.chars();
            chars
                .next()
                .map(|first| first.to_ascii_uppercase().to_string() + chars.as_str())
                .unwrap_or_default()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_key_gives_its_word_by_the_rule() {
        for (key, expected) in [
            ("age", Some("age")),
            ("firstName", Some("first_name")),
            ("first-name", Some("first_name")),
            ("first_name", Some("first_name")),
            ("userID", Some("user_id")),
            ("URL", Some("url")),
            ("v2Count", Some("v2_count")),
            ("2fa", Some("2fa")),
            ("type", Some("type")),
            ("", None),
            ("first name", None),
            ("café", None),
            ("a.b", None),
        ] {
            assert_eq!(word(key).as_deref(), expected, "{key:?}");
        }
    }

    #[test]
    fn a_keyword_is_a_raw_identifier_and_a_digit_is_refused() {
        let span = Span::call_site();
        assert_eq!(method_ident("age", span).unwrap().to_string(), "age");
        assert_eq!(method_ident("type", span).unwrap().to_string(), "r#type");
        assert_eq!(method_ident("_", span).ok(), None);
        assert_eq!(method_ident("self", span).ok(), None);
        assert_eq!(method_ident("2fa", span).ok(), None);
    }

    #[test]
    fn a_name_is_pascal_cased_for_a_type() {
        assert_eq!(pascal("visits_at"), "VisitsAt");
        assert_eq!(pascal("profile"), "Profile");
        assert_eq!(pascal("a__b"), "AB");
    }
}
