//! Emit operation declarations; only core code receives plaintext and a cipher.
use crate::shape::{fresh_lifetime, trait_impl, zip_chain, Field, Kind, Record};
use proc_macro2::TokenStream;
use quote::{quote, quote_spanned};
use syn::spanned::Spanned;
use syn::{parse_quote, DeriveInput, Result};

pub(crate) fn derive(input: DeriveInput) -> Result<TokenStream> {
    let record = Record::parse(&input)?;
    let krate = &record.krate;
    let fields = record.derived();
    let context = record.context_type(false);
    let (sources, generic) = record.sources(parse_quote!(__S));
    let source_lifetime = fresh_lifetime(&input.generics, "__source");
    let mut impls = Vec::new();
    for source in sources {
        let mut generics = input.generics.clone();
        if generic {
            generics.params.push(parse_quote!(__S));
        }
        let predicates = &mut generics.make_where_clause().predicates;
        predicates.push(parse_quote!(Self: 'static));
        // ADR-0004: one context is threaded to every field, and `zip` will
        // not combine two subtrees that need different types — so every
        // field's declaration is brought to the type the record's tree
        // carries (`Record::threaded_context`) by `Record::field_threading`,
        // and the where-clause says what that asks of the field's type.
        //
        // The bounds name concrete types rather than adding a fresh impl
        // parameter, deliberately: a parameter constrained only by an
        // associated-type binding in a where-clause is E0207, and the user
        // is told "unconstrained type parameter" instead of their mistake.
        for field in fields.iter().filter(|f| f.from().is_none()) {
            predicates.extend(record.field_bounds(field, &source));
        }
        let operations = fields.iter().map(|field| {
            let ty = &field.ty;
            let threading = record.field_threading(field);
            // Spanned at the field type: what the field's type refuses is
            // reported there, not at the derive.
            let operation = if let Some(from) = field.from() {
                quote_spanned!(ty.span()=> <#ty as #krate::target::EncryptFrom<_>>::encryption::<__K>()
                    .project(|__source: &#source| &__source.#from) #threading)
            } else {
                quote_spanned!(ty.span()=> <#ty as #krate::target::EncryptFrom<#source>>::encryption::<__K>() #threading)
            };
            (operation, field.local.clone())
        }).collect();
        let assignments = record.fields.iter().map(|field| {
            let member = &field.member;
            let value = match &field.kind {
                Kind::Derived { .. } => {
                    let local = &field.local;
                    quote!(#local)
                }
                Kind::Default(Some(expr)) => quote!(#expr),
                Kind::Default(None) => quote!(::core::default::Default::default()),
                Kind::Context => quote!(__context.clone().into_inner()),
            };
            quote!(#member: #value)
        });
        let result = quote!(Self { #(#assignments),* });
        // The tree carries the threaded context; the record declares
        // `Self::Context`, converted into it once at the root — a record
        // storing its own context declares the `NonEmpty<T>` it stores while
        // its operations need a `CallerContext`. Such a record fills the
        // stored field here too: under threading the context arrives when
        // the description runs, not when it is built.
        let (chain, pattern) = zip_chain(operations);
        let chain = quote!(#chain.accepting::<Self::Context>());
        let body = if record.context_field().is_some() {
            quote!(#chain.map_with_context(move |#pattern, __context| #result))
        } else {
            quote!(#chain.map(move |#pattern| #result))
        };
        impls.push(trait_impl(&input, &generics, quote!(#krate::target::EncryptFrom<#source>), quote! {
            type Context = #context;
            fn encryption<#source_lifetime,__K: 'static>() -> #krate::target::Encryption<#source_lifetime,#source, Self, __K, Self::Context> where #source:#source_lifetime {
                #body
            }
        }));
    }
    let decryptable = decryptable_impl(&input, &record, &fields);
    Ok(quote!(#(#impls)* #decryptable))
}
fn decryptable_impl(input: &DeriveInput, record: &Record, derived: &[&Field]) -> TokenStream {
    let krate = &record.krate;
    let name = &input.ident;
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();
    let value = if record.fields.iter().any(|f| f.decrypt) {
        quote!(true)
    } else {
        let terms = derived.iter().map(|field| {
            let ty = &field.ty;
            // Spanned at the field type: a type that is not `Decryptable`
            // is reported there, not at the derive.
            quote_spanned!(ty.span()=> || <#ty as #krate::target::Decryptable>::DECRYPTABLE)
        });
        quote!(false #(#terms)*)
    };
    quote! {
        #[automatically_derived]
        impl #impl_generics #krate::target::Decryptable for #name #ty_generics #where_clause {
            const DECRYPTABLE: bool = #value;
        }
    }
}
