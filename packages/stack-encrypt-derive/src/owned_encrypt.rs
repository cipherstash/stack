//! Emit an owned `EncryptTarget` declaration, with the structural
//! `EncryptFrom` beside it as a bridge, so the record is a field of a plan
//! or of a structural record as well as an owned target.
//!
//! The derive composes the field declarations directly: a `struct = ..`
//! record picks each field out of the plaintext (`project`, borrowed; a
//! chain of `split`s, owned) and runs the field's own target under the pair
//! the record infers; a `plaintext = T` record runs every field's target
//! over the whole value under the one context the caller supplies. Which
//! context a field may be handed is the field target's `ContextInput`, so a
//! target that cannot take the record's context is refused at that field.
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

/// The caller's input on the encrypt side: an extension for a record whose
/// fields carry their own contexts, the required `NonEmpty<T>` a record
/// stores, otherwise the required caller context (or the `context_type`).
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

/// The context every field of a `plaintext` record is run under: what the
/// record is handed, or the `CallerContext` built from the stored one.
pub(crate) fn threaded_input(record: &Record) -> Type {
    let krate = &record.krate;
    let caller = caller_context(record);
    parse_quote!(#krate::target::RequiredContext<#caller>)
}

/// The bare context type a `plaintext` record's fields take: the
/// `context_type` named, or `CallerContext`.
fn caller_context(record: &Record) -> Type {
    let krate = &record.krate;
    record
        .context_type
        .clone()
        .unwrap_or_else(|| parse_quote!(#krate::target::CallerContext))
}

/// A where-predicate carrying the span of the field it is about, so what a
/// field's type refuses is reported at that field.
pub(crate) fn spanned_predicate(span: Span, tokens: TokenStream) -> WherePredicate {
    let tokens = quote_spanned!(span=> #tokens);
    syn::parse2(tokens).unwrap_or_else(|error| {
        unreachable!("a predicate the derive wrote does not parse: {error}")
    })
}

/// The fields the encryption produces, in declaration order: the derived
/// fields and the passthrough fields. Each gets an output local.
fn participating(record: &Record) -> Vec<&Field> {
    record
        .fields
        .iter()
        .filter(|field| field.is_derived() || field.is_passthrough())
        .collect()
}

/// `a.zip(b).zip(c)` over the locals, and the pattern binding each back.
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

/// The struct literal filling every field: participating fields from their
/// locals, `default` fields with their defaults.
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

/// `#[stash(struct = User, context = "users")]`: each field picked out of
/// the plaintext and run by its own target under the pair the record
/// infers; a passthrough field carried through. Borrowed, the fields are
/// projected; owned, the struct is divided between them with `split`, so a
/// passthrough field is moved and a sealed field is guarded by its target.
fn struct_derive(input: &DeriveInput, record: &Record) -> TokenStream {
    let krate = &record.krate;
    let source = &record.plaintexts[0];
    let fields = participating(record);
    let locals: Vec<&Ident> = fields.iter().map(|field| &field.local).collect();

    // Borrowed: `project` a reference to the field.
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

    // Owned: each field's own owned description, the struct divided
    // between them right to left.
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
    // The plaintext destructured into one local per participating field,
    // exhaustively: the owned form replaces the guard over the whole value,
    // so a plaintext field the record neither seals nor carries would be
    // dropped unwiped. Without `..`, such a field is refused at compile
    // time ("pattern does not mention field"), at the `struct = ..` path, as
    // the decrypt side already refuses a plaintext it cannot rebuild.
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
            // `rest` as one description over the nested tuple of its parts,
            // divided by identity; then the struct divided into `first` and
            // that tuple. Each `split` is told how to wipe the parts still
            // waiting for their descriptions, should an earlier field's
            // description panic.
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

/// The `wipe` a `split` is handed for the parts still waiting, the nested
/// tuple of `waiting`: every sealed field in it wiped, every passthrough
/// field left as it is. A sealed field's plaintext is `Zeroize` already, as
/// every `EncryptTarget` source is, so this adds no bound; a passthrough
/// field is stored in the clear and takes none.
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

/// The nested tuple `(a, (b, (c, d)))` of the locals: how `split` divides
/// a struct, one part per step.
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

/// `#[stash(plaintext = T)]` (or none): every field's target run over the
/// whole value under the one required context, zipped. A record with a
/// `context_field` requires the `NonEmpty<T>` it stores and carries it out
/// beside the outputs.
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
        // Per field, spanned at the field: a target that does not accept
        // the record's context is refused there. A generic impl states the
        // same per field in its where clause, which the body is checked
        // against; a concrete one lets the body report at the field alone,
        // since a where clause's failure is reported at the derive.
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

/// The structural `EncryptFrom` bridge: the record's legacy context,
/// converted into its owned input at the root. Emitted beside every owned
/// declaration so an owned record is a field of a plan or of a structural
/// record without a second derive.
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
