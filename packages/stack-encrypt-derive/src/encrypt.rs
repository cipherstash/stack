//! Emit the record's plan, and an `EncryptFrom` that runs it. The derive
//! names plan verbs only; how fields are zipped, which context each is
//! handed and how the outputs are reassembled is the plan's business, so a
//! derived record and a hand-written plan cannot drift apart (ADR-0007).
use crate::shape::{fresh_lifetime, outputs, trait_impl, ByField, Field, Kind, OwnContext, Record};
use proc_macro2::TokenStream;
use quote::{quote, quote_spanned};
use syn::spanned::Spanned;
use syn::{parse_quote, DeriveInput, LitStr, Member, Result, Type};

pub(crate) fn derive(input: DeriveInput) -> Result<TokenStream> {
    let record = Record::parse(&input)?;
    let fields = record.derived();
    let decryptable = decryptable_impl(&input, &record, &fields);
    let emitted = if record.by_field {
        struct_derive(&input, &record, &fields)
    } else {
        value_derive(&input, &record, &fields)
    };
    Ok(quote!(#emitted #decryptable))
}

/// The struct's own fields, filled from what the plan produced: a derived
/// field from `value(field)`, a `default` field with its default, and a
/// context field from `stored`.
fn assignments<'a>(
    record: &'a Record,
    value: impl Fn(&Field) -> TokenStream + 'a,
    stored: TokenStream,
) -> impl Iterator<Item = TokenStream> + 'a {
    record.fields.iter().map(move |field| {
        let member = &field.member;
        let value = match &field.kind {
            Kind::Derived { .. } => value(field),
            Kind::Default(Some(expr)) => quote!(#expr),
            Kind::Default(None) => quote!(::core::default::Default::default()),
            Kind::Context => stored.clone(),
        };
        quote!(#member: #value)
    })
}

/// The plan field name of a `struct` derive's field: the plaintext field it
/// is derived from (`email`, or `0` for a tuple struct).
fn plan_name(from: &Member) -> LitStr {
    let name = match from {
        Member::Named(ident) => ident.to_string(),
        Member::Unnamed(index) => index.index.to_string(),
    };
    LitStr::new(&name, from.span())
}

/// `#[stash(struct = User, context = "users")]`: a fields plan under the
/// record's context, one typed field per derived field, each read by a
/// picker and laid out by its own type (`encrypt_into`).
fn struct_derive(input: &DeriveInput, record: &Record, fields: &[&Field]) -> TokenStream {
    let krate = &record.krate;
    let name = &input.ident;
    let source = &record.plaintexts[0];
    let mut prefix = None;
    let verbs: Vec<TokenStream> = fields
        .iter()
        .map(|field| {
            let ty = &field.ty;
            let Kind::Derived {
                by_field:
                    Some(ByField {
                        from,
                        context: OwnContext { prefix: own, field: segment },
                    }),
            } = &field.kind
            else {
                unreachable!("every field of a `struct` derive has a `from` and the context it infers")
            };
            prefix = Some(own.clone());
            let field_name = plan_name(from);
            // Pinned only where it differs from the name: the plan keys a
            // field under its name by default.
            let identity = (segment.value() != field_name.value())
                .then(|| quote_spanned!(ty.span()=> .identity(#segment)));
            // Spanned at the field type: what the field's type refuses is
            // reported there, not at the derive.
            quote_spanned! {ty.span()=>
                .encrypt_into::<#ty, _>(#krate::plan::pick(#field_name, |__source: &#source| &__source.#from))
                #identity
            }
        })
        .collect();
    let prefix = prefix.unwrap_or_else(|| unreachable!("a record has a derived field"));
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();
    let plan = quote! {
        #[automatically_derived]
        impl #impl_generics #name #ty_generics #where_clause {
            /// The plan this record's `EncryptFrom` runs: a fields plan
            /// under the record's context, each field laid out by its own
            /// type. Emitted by `#[derive(EncryptFrom)]`.
            ///
            /// # Errors
            ///
            /// The plan's own build errors, in `Error::Plan`. The derive
            /// refuses at compile time every input whose plan would not
            /// build, so this does not fail for derived output.
            pub fn plan<__K: 'static>() -> ::core::result::Result<#krate::Plan<#source, __K>, #krate::Error> {
                #krate::Plan::context(#prefix)
                    .fields::<#source, __K>()
                    #(#verbs)*
                    .build()
            }
        }
    };
    let values = assignments(
        record,
        |field| {
            let from = field.from().unwrap_or_else(|| unreachable!("a `from`"));
            let field_name = plan_name(from);
            quote!(__values.take(#field_name)?)
        },
        quote!(::core::unreachable!()),
    );
    let lifetime = fresh_lifetime(&input.generics, "__source");
    let mut generics = input.generics.clone();
    generics
        .make_where_clause()
        .predicates
        .push(parse_quote!(Self: 'static));
    let encrypt_from = trait_impl(
        input,
        &generics,
        quote!(#krate::target::EncryptFrom<#source>),
        quote! {
            type Context = #krate::target::DeclaredContext;
            fn encryption<#lifetime, __K: 'static>() -> #krate::target::Encryption<#lifetime, #source, Self, __K, Self::Context> where #source: #lifetime {
                match Self::plan::<__K>() {
                    ::core::result::Result::Ok(__plan) => __plan
                        .encryption(::core::option::Option::None)
                        .try_map(move |mut __values| ::core::result::Result::Ok(Self { #(#values),* })),
                    ::core::result::Result::Err(__error) => #krate::target::Encryption::failed(__error),
                }
            }
        },
    );
    quote!(#plan #encrypt_from)
}

/// `#[stash(plaintext = T)]` (or none): a one-value plan with no context
/// of its own, laid out by the tuple of the derived fields' types, run under
/// the context the caller hands over. A record with a `context_field`
/// carries that context out beside the tuple.
fn value_derive(input: &DeriveInput, record: &Record, fields: &[&Field]) -> TokenStream {
    let krate = &record.krate;
    let name = &input.ident;
    let (tuple, pattern, _) = outputs(fields, |_| TokenStream::new());
    let stored = record.context_field().map(|field| field.ty.clone());
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();
    let plan = match &stored {
        None => quote! {
            /// The plan this record's `EncryptFrom` runs: a one-value plan
            /// over `__S` with no context of its own, laid out by the tuple
            /// of the record's derived field types, so every output shares
            /// the caller's context. Emitted by `#[derive(EncryptFrom)]`.
            ///
            /// # Errors
            ///
            /// The plan's own build errors, in `Error::Plan`: two outputs
            /// that declare the same index.
            pub fn plan<__S>() -> ::core::result::Result<#krate::plan::ValuePlan<__S, #krate::plan::Typed<#tuple>>, #krate::Error>
            where
                #tuple: #krate::target::EncryptFrom<__S>,
                #krate::plan::Typed<#tuple>: #krate::plan::ValueShape<__S>,
            {
                #krate::Plan::value::<__S>().encrypt_into::<#tuple>().build()
            }
        },
        Some(stored) => quote! {
            /// The plan this record's `EncryptFrom` runs: a one-value plan
            /// over `__S` whose context is the caller's, carried out beside
            /// the outputs as the record's context field, and laid out by the
            /// tuple of the record's derived field types. Emitted by
            /// `#[derive(EncryptFrom)]`.
            ///
            /// # Errors
            ///
            /// The plan's own build errors, in `Error::Plan`: two outputs
            /// that declare the same index.
            pub fn plan<__S>() -> ::core::result::Result<#krate::plan::ValuePlan<__S, #krate::plan::Stored<#stored, #tuple>>, #krate::Error>
            where
                #tuple: #krate::target::EncryptFrom<__S>,
            {
                #krate::Plan::value::<__S>().context_field::<#stored>().encrypt_into::<#tuple>().build()
            }
        },
    };
    let plan = quote! {
        #[automatically_derived]
        impl #impl_generics #name #ty_generics #where_clause {
            #plan
        }
    };

    let context = record.context_type(false);
    let (sources, generic) = record.sources(parse_quote!(__S));
    let lifetime = fresh_lifetime(&input.generics, "__source");
    let values = assignments(
        record,
        |field| {
            let local = &field.local;
            quote!(#local)
        },
        quote!(__stored),
    )
    .collect::<Vec<_>>();
    let mut impls = Vec::new();
    for source in sources {
        let mut generics = input.generics.clone();
        if generic {
            generics.params.push(parse_quote!(__S));
        }
        let predicates = &mut generics.make_where_clause().predicates;
        predicates.push(parse_quote!(Self: 'static));
        // Per field first, spanned at the field: what a field's type refuses
        // is reported there. Then what the plan asks of the tuple.
        for field in fields {
            predicates.extend(record.field_bounds(field, &source));
        }
        let tuple_context: Type =
            parse_quote!(<#tuple as #krate::target::EncryptFrom<#source>>::Context);
        predicates.push(parse_quote!(#tuple: #krate::target::EncryptFrom<#source>));
        let body = match &stored {
            None => {
                predicates.push(
                    parse_quote!(#krate::plan::Typed<#tuple>: #krate::plan::ValueShape<#source>),
                );
                predicates.push(parse_quote!(#context: Into<#tuple_context>));
                quote! {
                    __plan
                        .encryption_with_context::<__K, Self::Context>()
                        .map(move |#pattern| Self { #(#values),* })
                }
            }
            Some(_) => {
                predicates.push(parse_quote!(#krate::target::CallerContext: Into<#tuple_context>));
                quote! {
                    __plan
                        .encryption_with_context::<__K>()
                        .map(move |(__stored, #pattern)| Self { #(#values),* })
                }
            }
        };
        impls.push(trait_impl(
            input,
            &generics,
            quote!(#krate::target::EncryptFrom<#source>),
            quote! {
                type Context = #context;
                fn encryption<#lifetime, __K: 'static>() -> #krate::target::Encryption<#lifetime, #source, Self, __K, Self::Context> where #source: #lifetime {
                    match Self::plan::<#source>() {
                        ::core::result::Result::Ok(__plan) => #body,
                        ::core::result::Result::Err(__error) => #krate::target::Encryption::failed(__error),
                    }
                }
                fn indexes() -> ::std::vec::Vec<#krate::target::IndexSpec> {
                    <#tuple as #krate::target::EncryptFrom<#source>>::indexes()
                }
            },
        ));
    }
    quote!(#plan #(#impls)*)
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
