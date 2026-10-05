//! Emit ciphertext inspection and core-owned opening descriptions.
use crate::shape::{trait_impl, zip, Field, Record};
use proc_macro2::{Span, TokenStream};
use quote::{quote, quote_spanned, ToTokens};
use syn::spanned::Spanned;
use syn::{parse_quote, DeriveInput, Ident, LitStr, Member, Path, PathArguments, Result, Type};

pub(crate) fn derive(input: DeriveInput) -> Result<TokenStream> {
    let record = Record::parse(&input)?;
    let krate = &record.krate;
    let name = &input.ident;
    let explicit = record.fields.iter().any(|f| f.decrypt);
    let groups = if explicit {
        match Mode::classify(record.fields.iter().filter(|f| f.decrypt).collect(), name)? {
            Mode::Whole(field) => vec![(None, vec![field])],
            Mode::ByField(fields) => fields.into_iter().map(|f| (f.from(), vec![f])).collect(),
        }
    } else {
        match Auto::classify(&record) {
            Auto::Whole(fields) => vec![(None, fields)],
            Auto::ByField(fields) => fields
                .into_iter()
                .map(|(from, field)| (Some(from), vec![field]))
                .collect(),
        }
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
    let context = record.context_type(true);
    let (plaintexts, generic) = record.sources(parse_quote!(__P));
    let mut impls = Vec::new();
    for plaintext in plaintexts {
        let mut generics = input.generics.clone();
        if generic {
            generics.params.push(parse_quote!(__P: 'static));
        }
        generics
            .make_where_clause()
            .predicates
            .push(parse_quote!(Self: 'static));
        let mut operations = Vec::new();
        for (index, (from, fields)) in groups.iter().enumerate() {
            let output = if from.is_some() {
                parse_quote!(_)
            } else {
                plaintext.clone()
            };
            if from.is_none() {
                for field in fields {
                    let ty = &field.ty;
                    let ctx = record.field_context_type(field);
                    let predicates = &mut generics.make_where_clause().predicates;
                    if explicit {
                        predicates.push(parse_quote!(#ty: #krate::target::DecryptInto<#output>));
                        predicates.push(parse_quote!(#ctx: Into<<#ty as #krate::target::DecryptInto<#output>>::Context>));
                    } else {
                        predicates
                            .push(parse_quote!(#ty: #krate::target::DecryptField<#output, #ctx>));
                    }
                }
            }
            let operation = if explicit {
                let field = fields[0];
                let ty = &field.ty;
                let member = &field.member;
                let ctx = record.context_expr(field);
                quote_spanned!(ty.span()=> <#ty as #krate::target::DecryptInto<#output>>::decryption::<__K>(self.#member, #ctx.into()))
            } else {
                let calls: Vec<_> = fields.iter().map(|field| {
                    let ty = &field.ty; let member = &field.member;
                    let ctx = record.context_expr(field);
                    let ctx_ty = record.field_context_type(field);
                    quote_spanned!(ty.span()=> <#ty as #krate::target::DecryptField<#output, #ctx_ty>>::decryption_field::<__K>(self.#member, #ctx))
                }).collect();
                // Evaluate every inspection before chaining: a context error belongs
                // to the whole declaration, not to an Option::or_else closure.
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
            operations.push((
                operation,
                Ident::new(&format!("__group_{index}"), Span::call_site()),
            ));
        }
        let body = if groups[0].0.is_none() {
            operations.remove(0).0
        } else {
            let literal = struct_literal_path(&plaintext)?;
            let assignments = groups
                .iter()
                .zip(&operations)
                .map(|((from, _), (_, local))| quote!(#from: #local));
            let output = quote!(#literal { #(#assignments),* });
            zip(operations, output)
        };
        let stored = record.context_field().map(|field| {
            let member = &field.member;
            quote!(let __context = match __context.validate(self.#member) {
                Ok(context) => context, Err(error) => return #krate::target::Decryption::failed(error),
            };)
        });
        impls.push(trait_impl(&input, &generics, quote!(#krate::target::DecryptInto<#plaintext>), quote! {
            type Context = #context;
            fn decryption<__K: 'static>(self, __context: Self::Context) -> #krate::target::Decryption<#plaintext, __K> {
                #body_check #stored #body
            }
        }));
    }
    let mut generics = input.generics.clone();
    generics.params.push(parse_quote!(__P));
    generics.params.push(parse_quote!(__Ctx));
    generics
        .make_where_clause()
        .predicates
        .push(parse_quote!(Self: #krate::target::DecryptInto<__P>));
    generics
        .make_where_clause()
        .predicates
        .push(parse_quote!(__Ctx: Into<<Self as #krate::target::DecryptInto<__P>>::Context>));
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
fn struct_literal_path(plaintext: &Type) -> Result<Path> {
    let Type::Path(type_path) = plaintext else {
        return Err(syn::Error::new_spanned(
            plaintext,
            "field-by-field decryption rebuilds the plaintext as a struct literal, so \
             `plaintext` must name a struct",
        ));
    };
    if type_path.qself.is_some() {
        return Err(syn::Error::new_spanned(
            plaintext,
            "field-by-field decryption rebuilds the plaintext as a struct literal, so \
             `plaintext` must name a struct directly, not through a qualified path",
        ));
    }
    let mut path = type_path.path.clone();
    for segment in &mut path.segments {
        if let PathArguments::AngleBracketed(args) = &mut segment.arguments {
            args.colon2_token = Some(Default::default());
        }
    }
    Ok(path)
}

// =============================================================================
// Automatic mode: the type system picks the field
// =============================================================================

/// The shape of a record with no `decrypt` attribute, from its `from`s.
enum Auto<'a> {
    /// No derived field has a `from`: one of them is the whole plaintext's
    /// ciphertext.
    Whole(Vec<&'a Field>),
    /// Every derived field has a `from`, and each plaintext field is
    /// recovered by the one field derived from it: `Record::parse` refuses a
    /// second (`one_output_per_plaintext_field`), so there is no choice to
    /// make and nothing to group.
    ByField(Vec<(&'a Member, &'a Field)>),
}

impl<'a> Auto<'a> {
    fn classify(record: &'a Record) -> Self {
        let candidates = record.derived();
        if !record.by_field {
            return Auto::Whole(candidates);
        }

        Auto::ByField(
            candidates
                .into_iter()
                .filter_map(|field| Some((field.from()?, field)))
                .collect(),
        )
    }
}

fn check(krate: &Path, name: &Ident, from: Option<&Member>, fields: &[&Field]) -> TokenStream {
    let terms = fields.iter().map(|field| {
        let ty = &field.ty;
        // Spanned at the field type: a type that is not `Decryptable` is
        // reported there, not at the derive.
        quote_spanned!(ty.span()=> + (<#ty as #krate::target::Decryptable>::DECRYPTABLE as usize))
    });
    // A plaintext field has one output in a `struct` derive, so only the
    // whole-value shape can hold several candidates.
    let several = match from {
        None => {
            let several = LitStr::new(
                &format!(
                    "`{name}` has several decryptable fields: mark the one decryption opens \
                     `#[stash(decrypt)]`"
                ),
                Span::call_site(),
            );
            quote!(::core::assert!(__decryptable <= 1, #several);)
        }
        Some(_) => TokenStream::new(),
    };
    let none = match from {
        None => format!(
            "`{name}` has no decryptable field: every derived field is a one-way index term, so \
             there is nothing for DecryptInto to open"
        ),
        Some(from) => format!(
            "no field of `{name}` can recover the plaintext field `{}`: the field derived from \
             it is a one-way index term. To store its ciphertext with the term, make it \
             `Encrypted<Terms>`",
            from.to_token_stream()
        ),
    };
    let none = LitStr::new(&none, Span::call_site());
    // A `let`, not a nested `const` item: an item could not see the
    // record's generics from inside an inline `const`.
    quote! {
        {
            let __decryptable: usize = 0 #(#terms)*;
            ::core::assert!(__decryptable >= 1, #none);
            #several
        }
    }
}

enum Mode<'a> {
    /// One field is the whole plaintext's ciphertext: decrypting the record is
    /// decrypting that field.
    Whole(&'a Field),
    /// Each opened field recovers one field of the source, which is rebuilt
    /// by name.
    ByField(Vec<&'a Field>),
}

impl<'a> Mode<'a> {
    /// Which of the two shapes the `decrypt` fields describe; an error if
    /// they describe neither.
    fn classify(opened: Vec<&'a Field>, name: &Ident) -> Result<Self> {
        let by_field = opened.iter().filter(|f| f.from().is_some()).count();
        if by_field == 0 {
            if opened.len() == 1 {
                return Ok(Mode::Whole(opened[0]));
            }
            return Err(syn::Error::new_spanned(
                name,
                "several fields are marked `decrypt` but the record is one value: one plaintext \
                 cannot be recovered from two fields. Mark only the ciphertext field, or encrypt \
                 a struct field by field with `#[stash(struct = ..)]`.",
            ));
        }
        debug_assert_eq!(
            by_field,
            opened.len(),
            "every field of a `struct` derive has a `from`, and no other field does"
        );
        // Two `decrypt` fields cannot recover one plaintext field: a
        // `struct` derive has one field per plaintext field
        // (`Record::parse`).
        Ok(Mode::ByField(opened))
    }
}
