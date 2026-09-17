//! Emit operation declarations; only core code receives plaintext and a cipher.
use crate::shape::{fresh_lifetime, trait_impl, zip, Field, Kind, Record};
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
        generics
            .make_where_clause()
            .predicates
            .push(parse_quote!(Self: 'static));
        for field in fields.iter().filter(|f| f.from().is_none()) {
            let ty = &field.ty;
            let context = record.field_context_type(field);
            let where_ = &mut generics.make_where_clause().predicates;
            where_.push(parse_quote!(#ty: #krate::target::EncryptFrom<#source>));
            where_.push(parse_quote!(#context: Into<<#ty as #krate::target::EncryptFrom<#source>>::Context>));
        }
        let operations = fields.iter().map(|field| {
            let ty = &field.ty;
            let context = record.context_expr(field, false);
            let operation = if let Some(from) = field.from() {
                quote_spanned!(ty.span()=> <#ty as #krate::target::EncryptFrom<_>>::encryption::<__K>(#context.into())
                    .project(|__source: &#source| &__source.#from))
            } else {
                quote_spanned!(ty.span()=> <#ty as #krate::target::EncryptFrom<#source>>::encryption::<__K>(#context.into()))
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
                Kind::Context => quote!(__stored_context),
            };
            quote!(#member: #value)
        });
        let stored = record
            .context_field()
            .map(|_| quote!(let __stored_context = __context.clone().into_inner();));
        let body = zip(operations, quote!(Self { #(#assignments),* }));
        impls.push(trait_impl(&input, &generics, quote!(#krate::target::EncryptFrom<#source>), quote! {
            type Context = #context;
            fn encryption<#source_lifetime,__K: 'static>(__context: Self::Context) -> #krate::target::Encryption<#source_lifetime,#source, Self, __K> where #source:#source_lifetime {
                #stored
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
