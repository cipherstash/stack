//! `predicate!`: a SQL/JSON path predicate on a document field, checked
//! when the program compiles and sent as written when it runs.
//!
//! `stack_encrypt::predicate!` passes `$crate` and its own input here, so
//! the expansion names `stack-encrypt` however the caller reaches it.
//!
//! The text is read with the grammar the engine reads it with
//! (`stack_encrypt_jsonpath::predicate`), and refused here, at the literal,
//! when it does not parse or uses a construct the JSON index cannot answer
//! whatever the variables hold. The variables are matched with the `$name`s
//! the text uses. What is left needs the field's declaration, which a macro
//! cannot see: for each path the text compares, the expansion asks the
//! compiler for the derive's lookup of that path (see
//! `stack_encrypt::field_reference::json::predicate_checks`), so the
//! compiler refuses a path, an array or a member the field does not
//! declare, and a value of another type, at the literal or at the
//! variable's expression. That code is type-checked and never run.
//!
//! When the program runs, the expansion is
//! `reference.predicate(text).var(name, value)…`: the same text, through
//! the engine's own path, so the operand is the one `predicate(text)`
//! derives.

use proc_macro2::{Delimiter, Span, TokenStream, TokenTree};
use quote::{format_ident, quote, quote_spanned};
use stack_encrypt_jsonpath::predicate::{
    self, check_filter, single_equality, Comparison, Expression, LiteralKind, Operator,
    PredicateError, PredicateErrorKind, ValueAt, MAX_NESTING,
};
use stack_encrypt_jsonpath::{JsonPath, MAX_DEPTH};
use syn::parse::{Parse, ParseStream};
use syn::spanned::Spanned;
use syn::{Expr, Ident, LitStr, Token};

use crate::json_paths::key_type;

/// What `predicate!` was given, after the crate path.
struct Arguments {
    reference: Expr,
    text: LitStr,
    variables: Vec<Variable>,
}

/// One variable: `name = value`, `"any name" = value`, or `name` alone for
/// `name = name`.
struct Variable {
    name: String,
    /// Where the name is written.
    name_span: Span,
    value: Expr,
}

impl Parse for Arguments {
    fn parse(input: ParseStream<'_>) -> syn::Result<Self> {
        let reference: Expr = input.parse()?;
        input.parse::<Token![,]>()?;
        let text: LitStr = input.parse().map_err(|error| {
            syn::Error::new(
                error.span(),
                "`predicate!` takes a field reference, then the predicate as a string literal, \
                 then its variables: `predicate!(Record::FIELD, \"$.age >= $min\", min = 30)`",
            )
        })?;
        let mut variables = Vec::new();
        while !input.is_empty() {
            input.parse::<Token![,]>()?;
            if input.is_empty() {
                break;
            }
            variables.push(input.parse()?);
        }
        Ok(Self {
            reference,
            text,
            variables,
        })
    }
}

impl Parse for Variable {
    fn parse(input: ParseStream<'_>) -> syn::Result<Self> {
        if input.peek(LitStr) {
            let name: LitStr = input.parse()?;
            input.parse::<Token![=]>()?;
            return Ok(Self {
                name: name.value(),
                name_span: name.span(),
                value: input.parse()?,
            });
        }
        let ident: Ident = input.parse().map_err(|error| {
            syn::Error::new(
                error.span(),
                "a variable is `name = value`, `\"any name\" = value`, or a local variable's \
                 name alone",
            )
        })?;
        let name = ident.to_string();
        let name = name.strip_prefix("r#").unwrap_or(&name).to_owned();
        let value = if input.peek(Token![=]) {
            input.parse::<Token![=]>()?;
            input.parse()?
        } else {
            syn::parse_quote!(#ident)
        };
        Ok(Self {
            name,
            name_span: ident.span(),
            value,
        })
    }
}

/// Expand `$crate ; reference, "text", variables…`.
pub(crate) fn expand(input: TokenStream) -> syn::Result<TokenStream> {
    let mut tokens = input.into_iter();
    let mut krate = TokenStream::new();
    for token in tokens.by_ref() {
        match &token {
            TokenTree::Punct(punct) if punct.as_char() == ';' => break,
            // A `$crate` passed through a declarative macro can arrive
            // wrapped in an undelimited group.
            TokenTree::Group(group) if group.delimiter() == Delimiter::None => {
                krate.extend(group.stream());
            }
            _ => krate.extend([token]),
        }
    }
    let arguments: Arguments = syn::parse2(tokens.collect())?;
    let text = arguments.text.value();
    let expression = predicate::parse(&text)
        .map_err(|error| syn::Error::new(arguments.text.span(), refusal_message(error)))?;
    check_variables(&arguments, &expression)?;
    check_structure(&text, &expression)
        .map_err(|message| syn::Error::new(arguments.text.span(), message))?;
    // Where the predicate literal is written, for the names of the checks.
    let literal = arguments.text.span().unwrap();
    let location = (literal.line(), literal.column());
    Ok(Expansion::new(krate, &arguments, &text, location).expand(&expression))
}

/// The message for a refusal of the grammar's, at the predicate literal.
fn refusal_message(error: PredicateError) -> String {
    let PredicateError {
        kind,
        construct,
        at,
    } = error;
    match kind {
        PredicateErrorKind::Syntax => {
            format!("this predicate does not parse: {construct} at byte {at}")
        }
        PredicateErrorKind::TooDeep => format!(
            "this predicate nests too deep at byte {at}: the JSON index reads up to \
             {MAX_NESTING} levels of parentheses, `!` and `exists`, and paths of up to \
             {MAX_DEPTH} steps"
        ),
        PredicateErrorKind::Position => format!(
            "this predicate names an array position at byte {at}: the JSON index reads every \
             element of an array alike, so write `[*]`"
        ),
        PredicateErrorKind::NotEqualAtWildcard => format!(
            "the JSON index cannot answer `!=` at a path with a wildcard, at byte {at}: it \
             asks whether some element differs"
        ),
        PredicateErrorKind::FilterWithoutWildcard => format!(
            "the filter at byte {at} is on a path with no wildcard: a filter tests the \
             elements of an array, as `exists($.visits[*] ? (@.place == \"home\"))`"
        ),
        PredicateErrorKind::MemberWildcard => format!(
            "the filter condition at byte {at} names a path with a wildcard: a condition \
             names a member of one element"
        ),
        _ => {
            format!("the JSON index cannot answer this predicate: it uses {construct} at byte {at}")
        }
    }
}

/// Every variable the text uses is given, once, and every one given is
/// used.
fn check_variables(arguments: &Arguments, expression: &Expression) -> syn::Result<()> {
    let mut used: Vec<&str> = Vec::new();
    variables_of(expression, &mut used);
    let mut errors: Option<syn::Error> = None;
    let mut add = |error: syn::Error| match &mut errors {
        Some(errors) => errors.combine(error),
        None => errors = Some(error),
    };
    for (index, variable) in arguments.variables.iter().enumerate() {
        let name = &variable.name;
        if arguments.variables[..index]
            .iter()
            .any(|earlier| earlier.name == *name)
        {
            add(syn::Error::new(
                variable.name_span,
                format!("`{name}` is given twice: give each variable once"),
            ));
        } else if !used.contains(&name.as_str()) {
            add(syn::Error::new(
                variable.name_span,
                format!(
                    "`{name}` was given and the predicate does not use it: it names no `${name}`"
                ),
            ));
        }
    }
    let mut missing: Vec<&str> = Vec::new();
    for name in used {
        if !missing.contains(&name) && !arguments.variables.iter().any(|v| v.name == name) {
            missing.push(name);
        }
    }
    for name in missing {
        let give = if syn::parse_str::<Ident>(name).is_ok() {
            format!("{name} = value")
        } else {
            format!("{name:?} = value")
        };
        add(syn::Error::new(
            arguments.text.span(),
            format!("the predicate uses `${name}` and no `{name}` was given: add `{give}`"),
        ));
    }
    errors.map_or(Ok(()), Err)
}

/// The names of the variables `expression` uses, each once, in order.
fn variables_of<'e>(expression: &'e Expression, out: &mut Vec<&'e str>) {
    let mut add = |comparison: &'e Comparison| {
        if let Some(name) = comparison.value.variable() {
            if !out.contains(&name) {
                out.push(name);
            }
        }
    };
    match expression {
        Expression::And(terms) | Expression::Or(terms) => {
            for term in terms {
                variables_of(term, out);
            }
        }
        Expression::Not(term) => variables_of(term, out),
        Expression::Compare(comparison) => add(comparison),
        Expression::Exists { filter, .. } => {
            for condition in filter.iter().flatten() {
                add(condition);
            }
        }
    }
}

/// The refusals the engine makes when the query is encrypted that depend
/// on neither the variables' values nor the field's options, in the order
/// the engine makes them, so the first is the one it would report.
fn check_structure(text: &str, expression: &Expression) -> Result<(), String> {
    match expression {
        Expression::And(terms) | Expression::Or(terms) => terms
            .iter()
            .try_for_each(|term| check_structure(text, term)),
        Expression::Not(term) => check_structure(text, term),
        Expression::Compare(comparison) => {
            comparison
                .refuse_not_equal_at_wildcard()
                .map_err(refusal_message)?;
            match comparison.operator {
                Operator::Equal | Operator::NotEqual => literal(text, &comparison.value, false),
                _ => {
                    literal(text, &comparison.value, true)?;
                    comparison
                        .path
                        .element_member(comparison.at)
                        .map(drop)
                        .map_err(refusal_message)
                }
            }
        }
        Expression::Exists { filter: None, .. } => Ok(()),
        Expression::Exists {
            path,
            filter: Some(conditions),
        } => {
            check_filter(path, conditions).map_err(refusal_message)?;
            if let Some(only) = single_equality(conditions) {
                return literal(text, &only.value, false);
            }
            conditions.iter().try_for_each(|condition| {
                condition
                    .check_filter_condition()
                    .map_err(refusal_message)?;
                literal(text, &condition.value, true)
            })
        }
    }
}

/// A literal the engine reads, and one an ordering takes when `ordering`:
/// a number or a string.
fn literal(text: &str, value: &ValueAt, ordering: bool) -> Result<(), String> {
    let (Some(kind), Some(literal)) = (value.literal_kind(text), value.literal_text(text)) else {
        return Ok(());
    };
    let at = value.at();
    if kind == LiteralKind::Number && !number_is_read(literal) {
        return Err(format!(
            "the number `{literal}` at byte {at} is not one the JSON index reads: an integer \
             fits in 64 bits, and a number with a fraction or an exponent is a finite `f64`"
        ));
    }
    if ordering && matches!(kind, LiteralKind::Boolean | LiteralKind::Null) {
        return Err(format!(
            "an ordering compares a number or a string, and the literal at byte {at} is \
             `{literal}`: ask for it with `==`"
        ));
    }
    Ok(())
}

/// Whether the engine reads `token`, JSON number text, as a number: an
/// integer that fits a signed or unsigned 64-bit integer, or a number with
/// a fraction or an exponent whose nearest `f64` is finite.
pub(crate) fn number_is_read(token: &str) -> bool {
    if token.contains(['.', 'e', 'E']) {
        token.parse::<f64>().is_ok_and(f64::is_finite)
    } else if token.starts_with('-') {
        token.parse::<i64>().is_ok()
    } else {
        token.parse::<u64>().is_ok()
    }
}

/// The type a number literal is named by in `NumberFits`, from its text:
/// `Fraction` for a number with a fraction or an exponent, else `UpTo` or
/// `DownTo` the narrowest integer type that holds it. `None` for a number
/// the engine does not read, which is refused before this is asked.
pub(crate) fn number_class(token: &str) -> Option<(&'static str, Option<&'static str>)> {
    if token.contains(['.', 'e', 'E']) {
        return Some(("Fraction", None));
    }
    if let Ok(value) = token.parse::<u64>() {
        let narrowest = [
            ("i8", u64::from(i8::MAX.unsigned_abs())),
            ("u8", u64::from(u8::MAX)),
            ("i16", u64::from(i16::MAX.unsigned_abs())),
            ("u16", u64::from(u16::MAX)),
            ("i32", u64::from(i32::MAX.unsigned_abs())),
            ("u32", u64::from(u32::MAX)),
            ("i64", i64::MAX.unsigned_abs()),
        ]
        .into_iter()
        .find(|(_, max)| value <= *max)
        .map_or("u64", |(name, _)| name);
        return Some(("UpTo", Some(narrowest)));
    }
    let value = token.parse::<i64>().ok()?;
    if value >= 0 {
        // `-0`.
        return Some(("UpTo", Some("i8")));
    }
    let narrowest = [
        ("i8", i64::from(i8::MIN)),
        ("i16", i64::from(i16::MIN)),
        ("i32", i64::from(i32::MIN)),
    ]
    .into_iter()
    .find(|(_, min)| value >= *min)
    .map_or("i64", |(name, _)| name);
    Some(("DownTo", Some(narrowest)))
}

/// What a check site asks of a path's accessor.
#[derive(Clone, Copy)]
enum Ask {
    /// Its selector: `exists(path)`.
    Selector,
    /// A comparison: equality or an ordering.
    Compare(Operator),
}

/// The expansion: the run-time call, and the checks the compiler makes.
struct Expansion<'a> {
    support: TokenStream,
    arguments: &'a Arguments,
    text: &'a str,
    /// The field reference's type, in the checks.
    reference: Ident,
    /// Its paths type, in the checks.
    paths: Ident,
    /// Each variable's value, bound once, in the order given.
    values: Vec<Ident>,
    checks: Vec<TokenStream>,
    /// The predicate literal's line and column, and how many checks have
    /// been named: each check's trait has a name of its own in its file,
    /// so the compiler names it without its path. (Two predicates at the
    /// same line and column of two files of one crate share a name, and
    /// the compiler then prints the path of each. Each check is in a block
    /// of its own, so that changes a message and nothing else.)
    location: (usize, usize),
    named: std::cell::Cell<usize>,
}

impl<'a> Expansion<'a> {
    fn new(
        krate: TokenStream,
        arguments: &'a Arguments,
        text: &'a str,
        location: (usize, usize),
    ) -> Self {
        let local = |name: &str| Ident::new(name, Span::mixed_site());
        Self {
            support: quote!(#krate::field_reference::json::predicate_checks),
            arguments,
            text,
            reference: local("reference"),
            paths: local("paths"),
            values: (0..arguments.variables.len())
                .map(|index| format_ident!("value_{}", index, span = Span::mixed_site()))
                .collect(),
            checks: Vec::new(),
            location,
            named: std::cell::Cell::new(0),
        }
    }

    /// A name for a check's trait: `role`, the predicate's line and column,
    /// and a count.
    fn name(&self, role: &str) -> Ident {
        let (line, column) = self.location;
        let count = self.named.replace(self.named.get() + 1);
        format_ident!("{role}Line{line}Column{column}Check{count}")
    }

    fn expand(mut self, expression: &Expression) -> TokenStream {
        self.visit(expression);
        let Self {
            support,
            arguments,
            reference,
            paths,
            values,
            checks,
            ..
        } = self;
        let reference_expression = &arguments.reference;
        let text = &arguments.text;
        let bindings = arguments
            .variables
            .iter()
            .zip(&values)
            .map(|(variable, value)| {
                let expression = &variable.value;
                quote_spanned!(expression.span()=> let #value = #expression;)
            });
        let calls = arguments
            .variables
            .iter()
            .zip(&values)
            .map(|(variable, value)| {
                let name = &variable.name;
                quote_spanned!(variable.value.span()=> .var(#name, #value))
            });
        // The field reference's value, written at its expression, so a
        // refusal of the field points there.
        let field = Ident::new(
            "field",
            Span::mixed_site().located_at(reference_expression.span()),
        );
        let query = Ident::new("query", Span::mixed_site());
        // The field reference is evaluated first, then each variable's
        // value, once each. One call takes the field reference, so a field
        // that stores no document is refused once, at the reference.
        let document = quote_spanned! {reference_expression.span()=>
            #support::document(#field, #text)
        };
        quote! {{
            let #field = #reference_expression;
            #(#bindings)*
            let (#query, #paths, #reference) = #document;
            #[allow(unused, clippy::all, clippy::pedantic)]
            let _ = || {
                #[allow(unused_imports)]
                use #support::{
                    FoundArray as _, FoundMember as _, FoundPath as _, MissingArray as _,
                    MissingMember as _, MissingPath as _,
                };
                #(#checks)*
            };
            #query #(#calls)*
        }}
    }

    fn visit(&mut self, expression: &Expression) {
        match expression {
            Expression::And(terms) | Expression::Or(terms) => {
                for term in terms {
                    self.visit(term);
                }
            }
            Expression::Not(term) => self.visit(term),
            Expression::Compare(comparison) => {
                self.at_path(
                    &comparison.path.path,
                    Ask::Compare(comparison.operator),
                    Some(&comparison.value),
                );
            }
            Expression::Exists { path, filter: None } => {
                self.at_path(&path.path, Ask::Selector, None);
            }
            Expression::Exists {
                path,
                filter: Some(conditions),
            } => {
                // One equality is containment at the condition's full
                // path, as the engine compiles it: that path's accessor
                // answers it, ordered or not.
                if let Some(only) = single_equality(conditions) {
                    let mut full = path.path.segments().to_vec();
                    full.extend_from_slice(only.path.path.segments());
                    self.at_path(
                        &JsonPath::from(full),
                        Ask::Compare(Operator::Equal),
                        Some(&only.value),
                    );
                    return;
                }
                for condition in conditions {
                    self.member(&path.path, condition);
                }
            }
        }
    }

    /// The span of the predicate literal, resolving as the expansion's own
    /// names do.
    fn at_literal(&self) -> Span {
        Span::mixed_site().located_at(self.arguments.text.span())
    }

    /// Check a path under `at()`: that the field declares it, that its
    /// accessor answers `ask`, and that `value` fits its type.
    fn at_path(&mut self, path: &JsonPath, ask: Ask, value: Option<&ValueAt>) {
        let support = &self.support;
        let shown = path.to_string();
        let key = key_type(support, &shown);
        let declared = self.declared(
            |name| quote!(impl<D: #support::PathLookup<#key>> #name for D {}),
            format!("this field declares no path `{}`", escaped(&shown)),
            format!(
                "`{}` is not one of the field's declared paths",
                escaped(&shown)
            ),
            format!(
                "`predicate!` checks each path against the field's `#[stash(json(..))]`. \
                 Declare `{}` with its type under `ordered = {{..}}` to compare it, or under \
                 `paths = {{..}}` for equality alone, or build this query at run time with \
                 `predicate(text)`",
                escaped(&shown)
            ),
        );
        let reference = &self.reference;
        let paths = &self.paths;
        let call = self.ask(ask);
        let fits = value
            .map(|value| self.fits(&shown, value))
            .unwrap_or_default();
        self.checks.push(quote! {{
            #declared
            let find = #support::PathFind::<_, #key>::new(#paths);
            let accessor = (&find).accessor(#support::placeholder_of(#reference));
            let value = (&find).value();
            accessor #call;
            #fits
        }});
    }

    /// Check one condition of a filter on the array `base`: that the field
    /// declares the array with the member, that the member's accessor
    /// answers the comparison, and that the value fits its type.
    fn member(&mut self, base: &JsonPath, condition: &Comparison) {
        let support = &self.support;
        let array = base.to_string();
        let member = condition.path.path.to_string();
        let written = member.replacen('$', "@", 1);
        let mut full = base.segments().to_vec();
        full.extend_from_slice(condition.path.path.segments());
        let full = JsonPath::from(full).to_string();
        let array_key = key_type(support, &array);
        let member_key = key_type(support, &member);
        let declared = self.declared(
            |name| quote! {
                impl<D> #name for D
                where
                    D: #support::ArrayLookup<#array_key>,
                    <D as #support::ArrayLookup<#array_key>>::Array: #support::MemberLookup<#member_key>,
                {}
            },
            format!(
                "this field declares no array `{}` whose elements have the ordered member `{}`",
                escaped(&array),
                escaped(&written)
            ),
            format!(
                "`{}` is not one of the field's ordered paths",
                escaped(&full)
            ),
            format!(
                "a filter with more than one condition compares each member by its ordering \
                 term. Declare `{}` with its type under `ordered = {{..}}` in the field's \
                 `#[stash(json(..))]`, or build this query at run time with `predicate(text)`",
                escaped(&full)
            ),
        );
        let reference = &self.reference;
        let paths = &self.paths;
        let call = self.ask(Ask::Compare(condition.operator));
        let fits = self.fits(&full, &condition.value);
        self.checks.push(quote! {{
            #declared
            let array = #support::ArrayFind::<_, #array_key>::new(#paths);
            let members = (&array).members(#support::placeholder_of(#reference));
            let find = #support::MemberFind::<_, #member_key>::new((&array).array());
            let accessor = (&find).accessor(members);
            let value = (&find).value();
            accessor #call;
            #fits
        }});
    }

    /// The method call a check makes on an accessor, with a value of the
    /// path's own type.
    fn ask(&self, ask: Ask) -> TokenStream {
        let support = &self.support;
        let method = match ask {
            Ask::Selector => return quote!(.selector()),
            Ask::Compare(Operator::Equal | Operator::NotEqual) => "eq",
            Ask::Compare(Operator::Less) => "lt",
            Ask::Compare(Operator::LessOrEqual) => "lte",
            Ask::Compare(Operator::Greater) => "gt",
            Ask::Compare(Operator::GreaterOrEqual) => "gte",
        };
        // At the predicate, so a refused ordering of a path declared for
        // equality alone points there.
        let method = Ident::new(
            method,
            Span::call_site().located_at(self.arguments.text.span()),
        );
        quote!(.#method(#support::placeholder_of(value)))
    }

    /// The trait a check site requires of the paths type, refused with the
    /// message given, at the predicate literal.
    fn declared(
        &self,
        implementation: impl FnOnce(&Ident) -> TokenStream,
        message: String,
        label: String,
        note: String,
    ) -> TokenStream {
        let paths = Ident::new("paths", self.at_literal());
        let name = self.name("Declares");
        let implementation = implementation(&name);
        quote! {
            #[diagnostic::on_unimplemented(message = #message, label = #label, note = #note)]
            trait #name {}
            #[diagnostic::do_not_recommend]
            #implementation
            fn declared<D: #name>(_: ::core::marker::PhantomData<D>) {}
            declared(#paths);
        }
    }

    /// That `value` fits the type the path `shown` holds: a variable's
    /// expression, at the expression; a literal's kind, at the predicate.
    fn fits(&self, shown: &str, value: &ValueAt) -> TokenStream {
        let support = &self.support;
        let shown = escaped(shown);
        if let Some(name) = value.variable() {
            let Some(index) = self.arguments.variables.iter().position(|v| v.name == name) else {
                // Refused already: a variable that is not given.
                return TokenStream::new();
            };
            let expression = &self.arguments.variables[index].value;
            let local = Ident::new(
                &format!("value_{index}"),
                Span::mixed_site().located_at(expression.span()),
            );
            let message = format!("`{shown}` holds `{{V}}`, and `{{Self}}` is not one");
            let label = format!("the value of `${}`", escaped(name));
            let note = "a declared path takes the type its `ordered = {..}` or `paths = {..}` \
                        entry names; a `String` path takes a `&str` or a `&String` too"
                .replace('{', "{{")
                .replace('}', "}}");
            let name = self.name("Fits");
            // Written at the value's expression, so a refusal points there;
            // the names resolve as the check's own.
            let here = Span::call_site().located_at(expression.span());
            let (fits, value) = (Ident::new("fits", here), Ident::new("value", here));
            let check = quote_spanned!(expression.span()=> #fits(#value, &#local););
            return quote! {{
                #[diagnostic::on_unimplemented(message = #message, label = #label, note = #note)]
                trait #name<V> {}
                #[diagnostic::do_not_recommend]
                impl<V, X: #support::ValueFits<V>> #name<V> for X {}
                fn fits<V, X: #name<V>>(_: ::core::marker::PhantomData<V>, _: &X) {}
                #check
            }};
        }
        let (Some(kind), Some(literal)) =
            (value.literal_kind(self.text), value.literal_text(self.text))
        else {
            return TokenStream::new();
        };
        let (bound, what, note) = match kind {
            LiteralKind::Number => {
                let Some((class, narrowest)) = number_class(literal) else {
                    // Refused already: a number the engine does not read.
                    return TokenStream::new();
                };
                let class = Ident::new(class, Span::call_site());
                let narrowest = narrowest.map(|name| {
                    let name = Ident::new(name, Span::call_site());
                    quote!(<::core::primitive::#name>)
                });
                (
                    quote!(#support::NumberFits<#support::#class #narrowest>),
                    "a number it does not hold",
                    "an integer path holds the integers of its type, and an `f64` path any number",
                )
            }
            LiteralKind::String => (
                quote!(#support::StringFits),
                "a string",
                "a string literal fits a `String` path",
            ),
            LiteralKind::Boolean => (
                quote!(#support::BooleanFits),
                "a boolean",
                "`true` and `false` fit a `bool` path, which `paths = {{..}}` can declare",
            ),
            LiteralKind::Null => return TokenStream::new(),
        };
        let literal = escaped(literal);
        let message = format!("`{shown}` holds `{{Self}}`, and the literal `{literal}` is {what}");
        let label = format!("this predicate compares `{shown}` with `{literal}`");
        // The check's own `value`, written at the predicate so a refusal
        // points there.
        let value = Ident::new(
            "value",
            Span::call_site().located_at(self.arguments.text.span()),
        );
        let name = self.name("Fits");
        quote! {{
            #[diagnostic::on_unimplemented(message = #message, label = #label, note = #note)]
            trait #name {}
            #[diagnostic::do_not_recommend]
            impl<V: #bound> #name for V {}
            fn fits<V: #name>(_: ::core::marker::PhantomData<V>) {}
            fits(#value);
        }}
    }
}

/// Text for a `diagnostic::on_unimplemented` string, where `{` and `}`
/// name a type parameter unless doubled.
fn escaped(text: &str) -> String {
    text.replace('{', "{{").replace('}', "}}")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The engine's parser of JSON text, and this crate's reading of a
    /// number literal, agree on which numbers they read.
    #[test]
    fn reads_the_numbers_the_engine_reads() {
        for token in [
            "0",
            "-0",
            "1",
            "-1",
            "1.5",
            "-0.0",
            "1e3",
            "1E-2",
            "2e+2",
            "18446744073709551615",
            "18446744073709551616",
            "-9223372036854775808",
            "-9223372036854775809",
            "1e308",
            "1e309",
            "-1e999",
            "5e-324",
            "1e-400",
            "123456789012345678.5",
        ] {
            assert_eq!(
                number_is_read(token),
                stack_encrypt::json::parse_text(token.as_bytes()).is_ok(),
                "{token}"
            );
        }
    }

    /// A number literal is named by the narrowest type that holds it, at
    /// each type's limits.
    #[test]
    fn names_a_number_by_the_narrowest_type_that_holds_it() {
        for (token, class) in [
            ("0", ("UpTo", Some("i8"))),
            ("-0", ("UpTo", Some("i8"))),
            ("127", ("UpTo", Some("i8"))),
            ("128", ("UpTo", Some("u8"))),
            ("255", ("UpTo", Some("u8"))),
            ("256", ("UpTo", Some("i16"))),
            ("32767", ("UpTo", Some("i16"))),
            ("32768", ("UpTo", Some("u16"))),
            ("65535", ("UpTo", Some("u16"))),
            ("65536", ("UpTo", Some("i32"))),
            ("2147483647", ("UpTo", Some("i32"))),
            ("2147483648", ("UpTo", Some("u32"))),
            ("4294967295", ("UpTo", Some("u32"))),
            ("4294967296", ("UpTo", Some("i64"))),
            ("9223372036854775807", ("UpTo", Some("i64"))),
            ("9223372036854775808", ("UpTo", Some("u64"))),
            ("18446744073709551615", ("UpTo", Some("u64"))),
            ("-1", ("DownTo", Some("i8"))),
            ("-128", ("DownTo", Some("i8"))),
            ("-129", ("DownTo", Some("i16"))),
            ("-32768", ("DownTo", Some("i16"))),
            ("-32769", ("DownTo", Some("i32"))),
            ("-2147483648", ("DownTo", Some("i32"))),
            ("-2147483649", ("DownTo", Some("i64"))),
            ("-9223372036854775808", ("DownTo", Some("i64"))),
            ("1.5", ("Fraction", None)),
            ("-0.0", ("Fraction", None)),
            ("1e3", ("Fraction", None)),
            ("2E-2", ("Fraction", None)),
        ] {
            assert_eq!(number_class(token), Some(class), "{token}");
        }
        for token in ["18446744073709551616", "-9223372036854775809"] {
            assert_eq!(number_class(token), None, "{token}");
        }
    }
}
