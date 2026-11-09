//! Emit an owned `DecryptSource` declaration. Also emit the structural
//! `DecryptInto` and `DecryptField`, so the record works where a structural
//! record is expected.
//!
//! Decryption follows the same layout as the owned encryption:
//!
//! - A `struct = ..` record opens each field through the field type's
//!   `DecryptField`. Each field opens under its context, extended by the
//!   caller's context if there is one. The passthrough fields are moved back
//!   into the plaintext.
//! - A `plaintext = T` record opens its one recoverable field under the
//!   context the caller supplies. A `context_field` record opens it under the
//!   context it stores, once that context has passed the caller's check.
use crate::decrypt::check;
use crate::owned_encrypt::{encrypt_input, spanned_predicate, threaded_input};
use crate::shape::{trait_impl, zip_wiping, Field, Flavor, Record};
use proc_macro2::{Span, TokenStream};
use quote::{quote, quote_spanned};
use syn::spanned::Spanned;
use syn::{parse_quote, DeriveInput, Ident, Member, Result, Type};

pub(crate) fn derive(input: DeriveInput) -> Result<TokenStream> {
    let record = Record::parse_as(&input, Flavor::Owned)?;
    let krate = &record.krate;
    let name = &input.ident;
    let explicit = record.fields.iter().any(|f| f.decrypt);
    // Each group recovers one plaintext, or one plaintext field. `None` means
    // the whole value.
    let groups: Vec<(Option<&Member>, Vec<&Field>)> = if explicit {
        let opened: Vec<&Field> = record.fields.iter().filter(|f| f.decrypt).collect();
        if record.by_field {
            opened.into_iter().map(|f| (f.from(), vec![f])).collect()
        } else {
            if opened.len() > 1 {
                return Err(syn::Error::new_spanned(
                    name,
                    "several fields are marked `decrypt` but the record is one value: one plaintext \
                     cannot be recovered from two fields. Mark only the ciphertext field, or encrypt \
                     a struct field by field with `#[stash(struct = ..)]`.",
                ));
            }
            vec![(None, opened)]
        }
    } else if record.by_field {
        record
            .derived()
            .into_iter()
            .map(|f| (f.from(), vec![f]))
            .collect()
    } else {
        vec![(None, record.derived())]
    };
    let checks = if explicit {
        TokenStream::new()
    } else {
        let checks = groups
            .iter()
            .map(|(from, fields)| check(krate, name, *from, fields));
        quote!(#(#checks)*)
    };
    let (definition_check, body_check) = if input.generics.params.is_empty() {
        (quote!(const _: () = { #checks };), TokenStream::new())
    } else {
        (TokenStream::new(), quote!(let () = const { #checks };))
    };

    let input_type = decrypt_input(&record);
    let (plaintexts, generic) = record.sources(parse_quote!(__P));
    let mut impls = Vec::new();
    for plaintext in plaintexts {
        let mut generics = input.generics.clone();
        if generic {
            generics.params.push(parse_quote!(__P));
        }
        let predicates = &mut generics.make_where_clause().predicates;
        predicates.push(parse_quote!(Self: 'static));
        if generic {
            predicates.push(parse_quote!(__P: #krate::target::Zeroize + 'static));
        }
        let body = if record.by_field {
            struct_body(&record, &plaintext, &groups, explicit)?
        } else {
            value_body(
                &record,
                &plaintext,
                &groups[0].1,
                explicit,
                generic,
                predicates,
            )
        };
        impls.push(trait_impl(
            &input,
            &generics,
            quote!(#krate::target::DecryptSource<#plaintext>),
            quote! {
                type ContextInput = #input_type;
                fn decryption<__K: 'static>(self, __context: Self::ContextInput) -> #krate::target::Decryption<#plaintext, __K> {
                    #body_check #body
                }
            },
        ));
        impls.push(bridge(&input, &record, &plaintext, generic));
        if !generic {
            impls.push(protected(&input, &record, &plaintext));
        }
    }

    // `DecryptField`, emitted the same way as the structural derive emits it.
    let mut generics = input.generics.clone();
    generics.params.push(parse_quote!(__P));
    generics.params.push(parse_quote!(__Ctx));
    let predicates = &mut generics.make_where_clause().predicates;
    predicates.push(parse_quote!(Self: #krate::target::DecryptInto<__P>));
    predicates.push(parse_quote!(__Ctx: Into<<Self as #krate::target::DecryptInto<__P>>::Context>));
    let field = trait_impl(
        &input,
        &generics,
        quote!(#krate::target::DecryptField<__P, __Ctx>),
        quote! {
            fn decryption_field<__K: 'static>(self, context: __Ctx) -> Option<#krate::target::Decryption<__P, __K>> {
                Some(<Self as #krate::target::DecryptInto<__P>>::decryption(self, context.into()))
            }
        },
    );
    Ok(quote!(#(#impls)* #field #definition_check))
}

/// The caller's input on the decrypt side. A `context_field` record takes a
/// check of the stored context. A `struct` record takes an extension. Any
/// other record takes the caller context the encrypt side required.
fn decrypt_input(record: &Record) -> Type {
    let krate = &record.krate;
    if let Some(field) = record.context_field() {
        let ty = &field.ty;
        parse_quote!(#krate::target::ExpectedContext<#ty>)
    } else {
        encrypt_input(record)
    }
}

/// A `struct = ..` record. Each field opens under its context, extended by the
/// caller's context. The fields are zipped so that a field recovered before a
/// later field fails is wiped. The plaintext is then rebuilt, with the
/// passthrough fields moved back.
fn struct_body(
    record: &Record,
    plaintext: &Type,
    groups: &[(Option<&Member>, Vec<&Field>)],
    explicit: bool,
) -> Result<TokenStream> {
    let krate = &record.krate;
    let literal = crate::decrypt::struct_literal_path(plaintext)?;
    let mut operations = Vec::new();
    for (index, (_, fields)) in groups.iter().enumerate() {
        let operation = if explicit {
            let field = fields[0];
            let ty = &field.ty;
            let member = &field.member;
            let own = record.context_expr(field);
            quote_spanned!(ty.span()=> <#ty as #krate::target::DecryptSource<_>>::decryption::<__K>(self.#member, ::core::convert::Into::into(#own)))
        } else {
            let field = fields[0];
            let ty = &field.ty;
            let member = &field.member;
            let own = record.context_expr(field);
            quote_spanned!(ty.span()=> <#ty as #krate::target::DecryptField<_, #krate::target::CallerContext>>::decryption_field::<__K>(self.#member, #own).unwrap_or_else(|| #krate::target::Decryption::failed(#krate::Error::NotOpened)))
        };
        operations.push((
            operation,
            Ident::new(&format!("__group_{index}"), Span::call_site()),
        ));
    }
    let opened = groups
        .iter()
        .zip(&operations)
        .map(|((from, _), (_, local))| quote!(#from: #local));
    let carried = record
        .fields
        .iter()
        .filter(|f| f.is_passthrough())
        .map(|field| {
            let from = field.from().unwrap_or_else(|| unreachable!("a `from`"));
            let member = &field.member;
            quote!(#from: self.#member)
        });
    let output = quote!(#literal { #(#opened,)* #(#carried),* });
    // A field opened before a later field is refused is wiped, not dropped as
    // it is.
    let zipped = zip_wiping(operations, output);
    Ok(quote! {
        let __context: #krate::target::DeclaredContext = ::core::convert::Into::into(__context);
        #zipped
    })
}

/// A `plaintext = T` record. Its one recoverable field opens under the
/// required context. A `context_field` record first builds that context from
/// the context it stores, and checks it against the caller's expectation.
fn value_body(
    record: &Record,
    plaintext: &Type,
    fields: &[&Field],
    explicit: bool,
    generic: bool,
    predicates: &mut syn::punctuated::Punctuated<syn::WherePredicate, syn::Token![,]>,
) -> TokenStream {
    let krate = &record.krate;
    let threaded = threaded_input(record);
    let stored = record.context_field().map(|field| {
        let member = &field.member;
        quote! {
            let __context = match __context.validate(self.#member) {
                ::core::result::Result::Ok(context) => <#threaded as #krate::target::AcceptsContext>::supplied(::core::convert::Into::into(context)),
                ::core::result::Result::Err(error) => return #krate::target::Decryption::failed(error),
            };
        }
    });
    // In a generic impl, the where clause states, for each field, what the
    // body is checked against. A concrete impl reports the error at the field
    // alone.
    for field in fields.iter().filter(|_| generic) {
        let ty = &field.ty;
        if explicit {
            predicates.push(spanned_predicate(
                ty.span(),
                quote!(#ty: #krate::target::DecryptSource<#plaintext>),
            ));
            predicates.push(spanned_predicate(
                ty.span(),
                quote!(#threaded: ::core::convert::Into<<#ty as #krate::target::DecryptSource<#plaintext>>::ContextInput>),
            ));
        } else {
            predicates.push(spanned_predicate(
                ty.span(),
                quote!(#ty: #krate::target::DecryptField<#plaintext, #threaded>),
            ));
        }
    }
    let operation = if explicit {
        let field = fields[0];
        let ty = &field.ty;
        let member = &field.member;
        quote_spanned!(ty.span()=> <#ty as #krate::target::DecryptSource<#plaintext>>::decryption::<__K>(self.#member, ::core::convert::Into::into(__context)))
    } else {
        let calls: Vec<_> = fields
            .iter()
            .map(|field| {
                let ty = &field.ty;
                let member = &field.member;
                quote_spanned!(ty.span()=> <#ty as #krate::target::DecryptField<#plaintext, #threaded>>::decryption_field::<__K>(self.#member, ::core::clone::Clone::clone(&__context)))
            })
            .collect();
        // Run every inspection before chaining them. A context error belongs
        // to the whole declaration, not to an `Option::or_else` closure.
        let locals: Vec<_> = (0..calls.len())
            .map(|n| Ident::new(&format!("__candidate_{n}"), Span::call_site()))
            .collect();
        let bindings = calls
            .iter()
            .zip(&locals)
            .map(|(call, local)| quote!(let #local = #call;));
        let first = &locals[0];
        let rest = &locals[1..];
        quote!({ #(#bindings)* #first #(.or(#rest))* .unwrap_or_else(|| #krate::target::Decryption::failed(#krate::Error::NotOpened)) })
    };
    quote!(#stored #operation)
}

/// The structural `DecryptInto`. The record's structural context is converted
/// into its owned input.
fn bridge(input: &DeriveInput, record: &Record, plaintext: &Type, generic: bool) -> TokenStream {
    let krate = &record.krate;
    let legacy = record.context_type(true);
    let mut generics = input.generics.clone();
    if generic {
        generics
            .params
            .push(parse_quote!(__P: #krate::target::Zeroize + 'static));
    }
    let predicates = &mut generics.make_where_clause().predicates;
    predicates.push(parse_quote!(Self: #krate::target::DecryptSource<#plaintext>));
    predicates.push(parse_quote!(
        #legacy: ::core::convert::Into<<Self as #krate::target::DecryptSource<#plaintext>>::ContextInput>
    ));
    trait_impl(
        input,
        &generics,
        quote!(#krate::target::DecryptInto<#plaintext>),
        quote! {
            type Context = #legacy;
            fn decryption<__K: 'static>(self, __context: Self::Context) -> #krate::target::Decryption<#plaintext, __K> {
                <Self as #krate::target::DecryptSource<#plaintext>>::decryption::<__K>(self, ::core::convert::Into::into(__context))
            }
        },
    )
}

/// `DecryptSource<Protected<P>>`, so a caller can decrypt straight into a
/// `Protected` that wipes the plaintext when it is dropped:
/// `Protected::<User>::decrypt_from(record, &cipher)`. It takes the same
/// context input as `DecryptSource<P>`. A record generic over its plaintext
/// gets none, because its generic impl could already cover `Protected<_>`.
fn protected(input: &DeriveInput, record: &Record, plaintext: &Type) -> TokenStream {
    let krate = &record.krate;
    let mut generics = input.generics.clone();
    generics
        .make_where_clause()
        .predicates
        .push(parse_quote!(Self: #krate::target::DecryptSource<#plaintext>));
    trait_impl(
        input,
        &generics,
        quote!(#krate::target::DecryptSource<#krate::Protected<#plaintext>>),
        quote! {
            type ContextInput = <Self as #krate::target::DecryptSource<#plaintext>>::ContextInput;
            fn decryption<__K: 'static>(self, __context: Self::ContextInput) -> #krate::target::Decryption<#krate::Protected<#plaintext>, __K> {
                <Self as #krate::target::DecryptSource<#plaintext>>::decryption::<__K>(self, __context)
                    .map(#krate::Protected::new)
            }
        },
    )
}
