//! Emit an owned `EncryptTarget` declaration. Also emit the structural
//! `EncryptFrom`. Then the record can be a field of a plan or of a structural
//! record, as well as an owned target.
//!
//! The derive composes the declarations of the fields:
//!
//! - A `struct = ..` record takes each field out of the plaintext and runs the
//!   field's own target under the field's context. The borrowed form uses
//!   `project`. The owned form uses a chain of `split` calls.
//! - A `plaintext = T` record runs every field's target over the whole value,
//!   under the one context the caller supplies.
//!
//! The field target's `ContextInput` decides which context the field can be
//! given. So a target that cannot take the record's context is a compile error
//! at that field.
use crate::shape::{fresh_lifetime, trait_impl, ByField, Field, Flavor, Kind, OwnContext, Record};
use proc_macro2::{Span, TokenStream};
use quote::{quote, quote_spanned};
use syn::spanned::Spanned;
use syn::{parse_quote, DeriveInput, Ident, Result, Type, WherePredicate};

pub(crate) fn derive(input: DeriveInput) -> Result<TokenStream> {
    let record = Record::parse_as(&input, Flavor::Owned)?;
    let derived = record.derived();
    let decryptable = crate::encrypt::decryptable_impl(&input, &record, &derived);
    let emitted = if record.by_field {
        struct_derive(&input, &record)
    } else {
        value_derive(&input, &record, &derived)
    };
    Ok(quote!(#emitted #decryptable))
}

/// The caller's input on the encrypt side. A record whose fields have their
/// own contexts takes an extension. A record that stores its context requires
/// the `NonEmpty<T>` it stores. Any other record requires the caller context,
/// or the type `context_type` names.
pub(crate) fn encrypt_input(record: &Record) -> Type {
    let krate = &record.krate;
    if let Some(field) = record.context_field() {
        let ty = &field.ty;
        parse_quote!(#krate::target::RequiredContext<#krate::NonEmpty<#ty>>)
    } else if record.by_field {
        parse_quote!(#krate::target::ContextExtension<#krate::target::DeclaredContext>)
    } else {
        let caller = caller_context(record);
        parse_quote!(#krate::target::RequiredContext<#caller>)
    }
}

/// The context that every field of a `plaintext` record runs under. This is
/// the context the record is given, or the `CallerContext` built from the
/// stored context.
pub(crate) fn threaded_input(record: &Record) -> Type {
    let krate = &record.krate;
    let caller = caller_context(record);
    parse_quote!(#krate::target::RequiredContext<#caller>)
}

/// The context type that the fields of a `plaintext` record take. This is the
/// type `context_type` names, or `CallerContext`.
fn caller_context(record: &Record) -> Type {
    let krate = &record.krate;
    record
        .context_type
        .clone()
        .unwrap_or_else(|| parse_quote!(#krate::target::CallerContext))
}

/// A where-predicate with the span of the field it is about. So an error about
/// what the field's type refuses is reported at that field.
pub(crate) fn spanned_predicate(span: Span, tokens: TokenStream) -> WherePredicate {
    let tokens = quote_spanned!(span=> #tokens);
    syn::parse2(tokens).unwrap_or_else(|error| {
        unreachable!("a predicate the derive wrote does not parse: {error}")
    })
}

/// The fields the encryption produces, in declaration order: the derived
/// fields and the passthrough fields. Each field gets a local variable for its
/// output.
fn participating(record: &Record) -> Vec<&Field> {
    record
        .fields
        .iter()
        .filter(|field| field.is_derived() || field.is_passthrough())
        .collect()
}

/// `a.zip(b).zip(c)` over the local variables, and the pattern that binds each
/// one back.
fn zip_chain(locals: &[&Ident]) -> (TokenStream, TokenStream) {
    let mut chain = TokenStream::new();
    let mut pattern = TokenStream::new();
    for (index, local) in locals.iter().enumerate() {
        if index == 0 {
            chain = quote!(#local);
            pattern = quote!(#local);
        } else {
            chain = quote!(#chain.zip(#local));
            pattern = quote!((#pattern, #local));
        }
    }
    (chain, pattern)
}

/// The struct literal that fills every field. A participating field takes its
/// local variable, and a `default` field takes its default.
fn literal(record: &Record, stored: Option<TokenStream>) -> TokenStream {
    let assignments = record.fields.iter().map(|field| {
        let member = &field.member;
        let local = &field.local;
        let value = match &field.kind {
            Kind::Derived { .. } | Kind::Passthrough { .. } => quote!(#local),
            Kind::Default(Some(expr)) => quote!(#expr),
            Kind::Default(None) => quote!(::core::default::Default::default()),
            Kind::Context => stored
                .clone()
                .unwrap_or_else(|| unreachable!("a context field has a stored value")),
        };
        quote!(#member: #value)
    });
    quote!(Self { #(#assignments),* })
}

/// `#[stash(struct = User, context = "users")]`. Each field is taken out of
/// the plaintext and run by its own target, under the field's context. A
/// passthrough field is passed through.
///
/// - The borrowed form projects each field.
/// - The owned form divides the struct between the fields with `split`. A
///   passthrough field is moved. Each sealed field is guarded by its own
///   target.
fn struct_derive(input: &DeriveInput, record: &Record) -> TokenStream {
    let krate = &record.krate;
    let source = &record.plaintexts[0];
    let fields = participating(record);
    let locals: Vec<&Ident> = fields.iter().map(|field| &field.local).collect();

    // The borrowed form: `project` a reference to the field.
    let borrowed: Vec<TokenStream> = fields
        .iter()
        .map(|field| {
            let ty = &field.ty;
            let local = &field.local;
            match &field.kind {
                Kind::Derived {
                    by_field: Some(ByField { from, context }),
                } => {
                    let own = own_expr(krate, context);
                    quote_spanned! {ty.span()=>
                        let #local = <#ty as #krate::target::EncryptTarget<_>>::encryption::<__K>()
                            .project(|__source: &#source| &__source.#from)
                            .under(#own);
                    }
                }
                Kind::Passthrough { from } => quote_spanned! {ty.span()=>
                    let #local = #krate::target::passthrough::<_, __K, #krate::target::Borrowed, #krate::target::DeclaredContext>()
                        .project(|__source: &#source| &__source.#from);
                },
                _ => unreachable!("only derived and passthrough fields participate"),
            }
        })
        .collect();
    let (zipped, zip_pattern) = zip_chain(&locals);
    let value = literal(record, None);
    let borrowed_body = quote! {
        #(#borrowed)*
        #zipped.map(move |#zip_pattern| #value).accepting()
    };

    // The owned form: each field's own owned description, with the struct
    // divided between them from right to left.
    let owned: Vec<TokenStream> = fields
        .iter()
        .map(|field| {
            let ty = &field.ty;
            let local = &field.local;
            match &field.kind {
                Kind::Derived {
                    by_field: Some(ByField { context, .. }),
                } => {
                    let own = own_expr(krate, context);
                    quote_spanned! {ty.span()=>
                        let #local = <#ty as #krate::target::EncryptTarget<_>>::owned_encryption::<__K>()
                            .under(#own);
                    }
                }
                Kind::Passthrough { .. } => quote_spanned! {ty.span()=>
                    let #local = #krate::target::passthrough::<_, __K, #krate::target::Owned, #krate::target::DeclaredContext>();
                },
                _ => unreachable!("only derived and passthrough fields participate"),
            }
        })
        .collect();
    // Destructure the plaintext into one local variable for each participating
    // field. The pattern has no `..`, so it must name every field.
    //
    // The owned form does not guard the whole value. So a plaintext field that the
    // record neither seals nor moves would be dropped without being wiped.
    // Such a field is a compile error at the `struct = ..` path ("pattern does
    // not mention field"). The decrypt side already refuses a plaintext that
    // it cannot rebuild.
    let bindings = fields.iter().map(|field| {
        let from = field.from().unwrap_or_else(|| unreachable!("a `from`"));
        let local = &field.local;
        quote!(#from: #local)
    });
    let nested = nested_tuple(&locals);
    let pattern = quote_spanned!(source.span()=> #source { #(#bindings),* });
    let divide = quote!(|__source: #source| {
        let #pattern = __source;
        #nested
    });
    let split = match locals.as_slice() {
        [single] => quote!(#single.project_owned(#divide)),
        [first, rest @ ..] => {
            // Build `rest` as one description over the nested tuple of its
            // parts, divided by identity. Then divide the struct into `first`
            // and that tuple. Each `split` is given the function that wipes
            // the parts still waiting for their descriptions, in case an
            // earlier field's description panics.
            let mut tail = {
                let last = rest[rest.len() - 1];
                quote!(#last)
            };
            for index in (1..locals.len() - 1).rev() {
                let local = locals[index];
                let wipe = wipe_waiting(krate, &fields[index + 1..]);
                tail = quote!(#local.split(#tail, |__parts| __parts, #wipe));
            }
            let wipe = wipe_waiting(krate, &fields[1..]);
            quote!(#first.split(#tail, #divide, #wipe))
        }
        [] => unreachable!("a record has a derived field"),
    };
    let owned_body = quote! {
        #(#owned)*
        #split.map(move |#nested| #value).accepting()
    };

    let lifetime = fresh_lifetime(&input.generics, "__source");
    let mut generics = input.generics.clone();
    generics
        .make_where_clause()
        .predicates
        .push(parse_quote!(Self: 'static));
    let encrypt_target = trait_impl(
        input,
        &generics,
        quote!(#krate::target::EncryptTarget<#source>),
        quote! {
            type ContextInput = #krate::target::ContextExtension<#krate::target::DeclaredContext>;
            fn encryption<#lifetime, __K: 'static>() -> #krate::target::Encryption<#lifetime, #source, Self, __K, Self::ContextInput> where #source: #lifetime {
                #borrowed_body
            }
            fn owned_encryption<#lifetime, __K: 'static>() -> #krate::target::Encryption<#lifetime, #source, Self, __K, Self::ContextInput, #krate::target::Owned> where #source: #lifetime {
                #owned_body
            }
        },
    );
    let bridge = bridge(
        input,
        record,
        source,
        parse_quote!(#krate::target::DeclaredContext),
        false,
    );
    quote!(#encrypt_target #bridge)
}

/// The `wipe` function that a `split` is given for the parts still waiting.
/// Those parts are the nested tuple `waiting`. The function wipes every sealed
/// field in the tuple, and leaves every passthrough field as it is.
///
/// The plaintext of a sealed field already implements `Zeroize`, as the source
/// of every `EncryptTarget` does, so this adds no bound. A passthrough field
/// is stored in the clear, so it needs no bound.
fn wipe_waiting(krate: &syn::Path, waiting: &[&Field]) -> TokenStream {
    let mut wipes = Vec::new();
    let mut base = quote!((*__parts));
    for (index, field) in waiting.iter().enumerate() {
        let last = index == waiting.len() - 1;
        let place = if last {
            base.clone()
        } else {
            let first = syn::Index::from(0);
            quote!(#base.#first)
        };
        if field.is_derived() {
            wipes.push(quote!(#krate::target::Zeroize::zeroize(&mut #place);));
        }
        if !last {
            let rest = syn::Index::from(1);
            base = quote!(#base.#rest);
        }
    }
    if wipes.is_empty() {
        quote!(|_| {})
    } else {
        quote!(|__parts| { #(#wipes)* })
    }
}

/// The nested tuple `(a, (b, (c, d)))` of the local variables. This is how
/// `split` divides a struct, one part at each step.
fn nested_tuple(locals: &[&Ident]) -> TokenStream {
    match locals {
        [] => quote!(()),
        [single] => quote!(#single),
        [first, rest @ ..] => {
            let rest = nested_tuple(rest);
            quote!((#first, #rest))
        }
    }
}

fn own_expr(krate: &syn::Path, context: &OwnContext) -> TokenStream {
    let OwnContext { prefix, field } = context;
    quote!(#krate::nonempty!(#prefix).with(#field))
}

/// `#[stash(plaintext = T)]`, or no record attribute. Every field's target
/// runs over the whole value, under the one required context, and the results
/// are zipped. A record with a `context_field` requires the `NonEmpty<T>` it
/// stores, and returns it beside the outputs.
fn value_derive(input: &DeriveInput, record: &Record, fields: &[&Field]) -> TokenStream {
    let krate = &record.krate;
    let input_type = encrypt_input(record);
    let threaded = threaded_input(record);
    let stored = record.context_field().map(|field| field.ty.clone());
    let (sources, generic) = record.sources(parse_quote!(__S));
    let lifetime = fresh_lifetime(&input.generics, "__source");
    let locals: Vec<&Ident> = fields.iter().map(|field| &field.local).collect();
    let (zipped, zip_pattern) = zip_chain(&locals);
    let mut impls = Vec::new();
    for source in sources {
        let mut generics = input.generics.clone();
        if generic {
            generics
                .params
                .push(parse_quote!(__S: #krate::target::Zeroize));
        }
        let predicates = &mut generics.make_where_clause().predicates;
        predicates.push(parse_quote!(Self: 'static));
        // Check each field, with the error at the field: a target that does
        // not accept the record's context is refused there. A generic impl
        // states the same check for each field in its where clause, and the
        // body is checked against it. A concrete impl lets the body report the
        // error at the field alone. That matters because a failure in a where
        // clause is reported at the derive.
        let descriptions: Vec<TokenStream> = fields
            .iter()
            .map(|field| {
                let ty = &field.ty;
                let local = &field.local;
                if generic {
                    predicates.push(spanned_predicate(
                        ty.span(),
                        quote!(#ty: #krate::target::EncryptTarget<#source>),
                    ));
                    predicates.push(spanned_predicate(
                        ty.span(),
                        quote!(#threaded: ::core::convert::Into<<#ty as #krate::target::EncryptTarget<#source>>::ContextInput>),
                    ));
                }
                quote_spanned! {ty.span()=>
                    let #local = <#ty as #krate::target::EncryptTarget<#source>>::encryption::<__K>()
                        .accepting::<#threaded>();
                }
            })
            .collect();
        let indexes = fields.iter().map(|field| {
            let ty = &field.ty;
            quote_spanned!(ty.span()=> __indexes.extend(<#ty as #krate::target::EncryptTarget<#source>>::indexes());)
        });
        let body = match &stored {
            None => {
                let value = literal(record, None);
                quote!(#zipped.map(move |#zip_pattern| #value).accepting::<Self::ContextInput>())
            }
            Some(_) => {
                let value = literal(
                    record,
                    Some(
                        quote!(#krate::target::RequiredContext::into_inner(__stored).into_inner()),
                    ),
                );
                quote! {
                    #zipped
                        .accepting::<Self::ContextInput>()
                        .map_with_context(move |#zip_pattern, __stored: Self::ContextInput| #value)
                }
            }
        };
        impls.push(trait_impl(
            input,
            &generics,
            quote!(#krate::target::EncryptTarget<#source>),
            quote! {
                type ContextInput = #input_type;
                fn encryption<#lifetime, __K: 'static>() -> #krate::target::Encryption<#lifetime, #source, Self, __K, Self::ContextInput> where #source: #lifetime {
                    #(#descriptions)*
                    #body
                }
                fn indexes() -> ::std::vec::Vec<#krate::target::IndexSpec> {
                    let mut __indexes = ::std::vec::Vec::new();
                    #(#indexes)*
                    __indexes
                }
            },
        ));
        let legacy = record.context_type(false);
        impls.push(bridge(input, record, &source, legacy, generic));
    }
    quote!(#(#impls)*)
}

/// The structural `EncryptFrom`. The record's structural context is converted
/// into its owned input at the root. This impl is emitted beside every owned
/// declaration. So an owned record can be a field of a plan or of a structural
/// record, with no second derive.
fn bridge(
    input: &DeriveInput,
    record: &Record,
    source: &Type,
    legacy: Type,
    generic: bool,
) -> TokenStream {
    let krate = &record.krate;
    let lifetime = fresh_lifetime(&input.generics, "__source");
    let mut generics = input.generics.clone();
    if generic {
        generics
            .params
            .push(parse_quote!(__S: #krate::target::Zeroize));
    }
    let predicates = &mut generics.make_where_clause().predicates;
    predicates.push(parse_quote!(Self: #krate::target::EncryptTarget<#source>));
    predicates.push(parse_quote!(
        #legacy: ::core::convert::Into<<Self as #krate::target::EncryptTarget<#source>>::ContextInput>
    ));
    trait_impl(
        input,
        &generics,
        quote!(#krate::target::EncryptFrom<#source>),
        quote! {
            type Context = #legacy;
            fn encryption<#lifetime, __K: 'static>() -> #krate::target::Encryption<#lifetime, #source, Self, __K, Self::Context> where #source: #lifetime {
                <Self as #krate::target::EncryptTarget<#source>>::encryption::<__K>().accepting::<Self::Context>()
            }
            fn indexes() -> ::std::vec::Vec<#krate::target::IndexSpec> {
                <Self as #krate::target::EncryptTarget<#source>>::indexes()
            }
        },
    )
}
