//! Parsing of the `#[stash(...)]` container and field attributes.

use syn::{Attribute, Expr, Ident, LitStr, Member, Path, Result, Type};

/// Container-level options, from `#[stash(...)]` on the struct itself.
pub(crate) struct ContainerAttrs {
    /// Path to the `stack_encrypt` crate in the generated code. Defaults to
    /// `::stack_encrypt`; overridden by `#[stash(crate = "...")]` so the
    /// macros work through a re-export.
    pub(crate) krate: Path,
    /// The plaintext types this record is an encrypted form of, one impl
    /// each, from repeated `#[stash(plaintext = Type)]`. Empty means
    /// a single impl generic over the plaintext.
    pub(crate) plaintexts: Vec<Type>,
    /// `#[stash(struct = Type)]`: the record encrypts the struct `Type`
    /// field by field. Every derived field is derived from the plaintext
    /// field of its own name (`from`), under a context made of the
    /// container's `scope` and the plaintext field's name, unless the
    /// field says otherwise. Exclusive with `plaintext`; requires `scope`.
    pub(crate) by_field: Option<Type>,
    /// `#[stash(scope = "...")]` on the container: the record's name and the
    /// first scope of every field's context, the pair `("<scope>", "<field>")`.
    /// Names the stored data, not the Rust type: it is part of the stored
    /// data's identity, so it is given explicitly rather than inferred from a
    /// name a refactor can change. Only meaningful with `struct`.
    pub(crate) scope: Option<LitStr>,
    /// `#[stash(scope(tenant: u64))]`: a scope the caller supplies on every
    /// call, with its name and type. In the query context and the stored
    /// context.
    pub(crate) caller_scope: Option<(Ident, Type)>,
    /// `#[stash(scope(field = "tenant"))]`: a scope stored in the row, in
    /// the `passthrough` field derived from the named plaintext field.
    pub(crate) stored_scope: Option<LitStr>,
    /// `#[stash(bind(row: u128))]`: a binding the caller supplies on every
    /// call. In the stored context only.
    pub(crate) caller_bind: Option<(Ident, Type)>,
    /// `#[stash(bind(field = "id"))]`: a binding stored in the row.
    pub(crate) stored_bind: Option<LitStr>,
    /// `#[stash(context_type = Type)]`: the record's associated `Context`,
    /// when its fields take the caller's context. The default,
    /// `CallerContext`, derives ciphertext and terms alike and so needs both
    /// Vitamin C encodings; `AeadContext` needs only the AEAD one, and a
    /// record whose fields are all ciphertexts declares it to accept the
    /// same contexts the canonical `StackCipherText` path does. Excludes
    /// `context_field` and `struct`.
    pub(crate) context_type: Option<Type>,
}

const CONTAINER_KEYS: &str = "unsupported container attribute; expected `plaintext = Type`, \
     `struct = Type`, `scope = \"...\"` (with `struct`), `scope(name: Type)`, \
     `scope(field = \"...\")`, `bind(name: Type)`, `bind(field = \"...\")`, `context_type = Type` \
     or `crate = \"...\"`";

/// One `scope(..)` or `bind(..)` part: a caller part with its name and type,
/// or a stored part naming the plaintext field.
enum Part {
    Caller(Ident, Box<Type>),
    Stored(LitStr),
}

/// Parse the parentheses of `scope(..)` or `bind(..)`: `name: Type` or
/// `field = "name"`.
fn parse_part(input: syn::parse::ParseStream<'_>, kind: &str) -> Result<Part> {
    let content;
    syn::parenthesized!(content in input);
    let name: Ident = content.call(syn::ext::IdentExt::parse_any)?;
    if content.peek(syn::Token![=]) {
        if name != "field" {
            return Err(syn::Error::new(
                name.span(),
                format!(
                    "`{kind}(..)` takes `name: Type` for a part the caller supplies, or \
                     `field = \"..\"` for a part stored in the row"
                ),
            ));
        }
        let _: syn::Token![=] = content.parse()?;
        return Ok(Part::Stored(content.parse()?));
    }
    let _: syn::Token![:] = content.parse().map_err(|_| {
        syn::Error::new(
            name.span(),
            format!(
                "`{kind}(..)` takes `name: Type` for a part the caller supplies, or \
                 `field = \"..\"` for a part stored in the row"
            ),
        )
    })?;
    Ok(Part::Caller(name, Box::new(content.parse()?)))
}

impl ContainerAttrs {
    pub(crate) fn parse(attrs: &[Attribute]) -> Result<Self> {
        let mut krate: Option<Path> = None;
        let mut plaintexts: Vec<Type> = Vec::new();
        let mut by_field: Option<Type> = None;
        let mut scope: Option<LitStr> = None;
        let mut caller_scope: Option<(Ident, Type)> = None;
        let mut stored_scope: Option<LitStr> = None;
        let mut caller_bind: Option<(Ident, Type)> = None;
        let mut stored_bind: Option<LitStr> = None;
        let mut context_type: Option<Type> = None;

        for attr in attrs.iter().filter(|a| a.path().is_ident("stash")) {
            // `struct` and `crate` are keywords, but a nested-meta path is
            // parsed with `Ident::parse_any`, so `struct = User` reads as
            // written — no `r#struct`.
            attr.parse_nested_meta(|meta| {
                if meta.path.is_ident("crate") {
                    if krate.is_some() {
                        return Err(meta.error("`crate` is given twice"));
                    }
                    let lit: LitStr = meta.value()?.parse()?;
                    krate = Some(lit.parse()?);
                    return Ok(());
                }
                if meta.path.is_ident("scope") && meta.input.peek(syn::token::Paren) {
                    if caller_scope.is_some() || stored_scope.is_some() {
                        return Err(meta.error(
                            "`scope(..)` is given twice; a record lists one scope beside its name",
                        ));
                    }
                    match parse_part(meta.input, "scope")? {
                        Part::Caller(name, ty) => caller_scope = Some((name, *ty)),
                        Part::Stored(field) => stored_scope = Some(field),
                    }
                    return Ok(());
                }
                if meta.path.is_ident("bind") && meta.input.peek(syn::token::Paren) {
                    if caller_bind.is_some() || stored_bind.is_some() {
                        return Err(
                            meta.error("`bind(..)` is given twice; a record lists one binding")
                        );
                    }
                    match parse_part(meta.input, "bind")? {
                        Part::Caller(name, ty) => caller_bind = Some((name, *ty)),
                        Part::Stored(field) => stored_bind = Some(field),
                    }
                    return Ok(());
                }
                if meta.path.is_ident("scope") {
                    if scope.is_some() {
                        return Err(meta.error(
                            "`scope` is given twice; a record has one name, its first scope",
                        ));
                    }
                    scope = Some(meta.value()?.parse()?);
                    return Ok(());
                }
                // Renamed rather than unknown, so the message can say what to
                // write instead.
                if meta.path.is_ident("context") {
                    return Err(meta.error(
                        "the record's name is now `scope = \"..\"` (`context = \"..\"` before): \
                         it is the record's first scope, and each field's name is the next. \
                         The stored data does not change",
                    ));
                }
                if meta.path.is_ident("context_type") {
                    if context_type.is_some() {
                        return Err(meta.error(
                            "`context_type` is given twice; a record has one associated context",
                        ));
                    }
                    context_type = Some(meta.value()?.parse()?);
                    return Ok(());
                }
                if meta.path.is_ident("struct") {
                    if by_field.is_some() {
                        return Err(meta.error(
                            "`struct` is given twice; a record encrypts one plaintext struct",
                        ));
                    }
                    let ty: Type = meta.value()?.parse()?;
                    // The plaintext is reached by field name and rebuilt
                    // with a struct literal, so the type must be a struct
                    // named directly.
                    let named_struct = match &ty {
                        Type::Path(path) => path.qself.is_none(),
                        _ => false,
                    };
                    if !named_struct {
                        return Err(syn::Error::new_spanned(
                            &ty,
                            "`struct` must name a struct directly (`struct = User`): its fields \
                             are reached by name and the plaintext is rebuilt with a struct \
                             literal",
                        ));
                    }
                    by_field = Some(ty);
                    return Ok(());
                }
                if meta.path.is_ident("plaintext") {
                    let plaintext: Type = meta.value()?.parse()?;
                    // The type is spliced into the impl header as
                    // written, where a reference has no lifetime to
                    // name. The generic impl (no `plaintext` at all)
                    // already accepts `&str` and friends.
                    if let Type::Reference(_) = plaintext {
                        return Err(syn::Error::new_spanned(
                            &plaintext,
                            "`plaintext` must be an owned type: a reference plaintext has no \
                             lifetime the generated impl can name. Omit `plaintext` for an impl \
                             generic over the source, which accepts references too.",
                        ));
                    }
                    if plaintexts.contains(&plaintext) {
                        return Err(syn::Error::new_spanned(
                            &plaintext,
                            "this `plaintext` is listed twice; each listed type gets one impl",
                        ));
                    }
                    plaintexts.push(plaintext);
                    return Ok(());
                }
                Err(meta.error(CONTAINER_KEYS))
            })?;
        }

        if let (Some(by_field), Some(plaintext)) = (&by_field, plaintexts.first()) {
            let mut err = syn::Error::new_spanned(
                by_field,
                "`struct` and `plaintext` are two ways of naming the plaintext: `struct = ..` \
                 encrypts it field by field, `plaintext = ..` as one value, so give one of them",
            );
            err.combine(syn::Error::new_spanned(plaintext, "`plaintext` given here"));
            return Err(err);
        }

        // The prefix is part of the stored data's identity — the AAD of every
        // ciphertext derived from the struct and the domain of every term —
        // so it is never inferred from the Rust type's name: two types named
        // `Account` in different modules would silently share every field
        // context, making ciphertexts transplantable between them and index
        // terms comparable across them.
        match (&by_field, &scope) {
            (Some(by_field), None) => {
                return Err(syn::Error::new_spanned(
                    by_field,
                    "`struct = ..` needs a `scope = \"..\"` beside it naming the stored data \
                     (e.g. `#[stash(struct = User, scope = \"users\")]`): each field is derived \
                     under the pair `(\"<scope>\", \"<field>\")`, and the record's name is part of the stored data's \
                     identity, so it is given explicitly rather than inferred from the Rust \
                     type's name",
                ));
            }
            (None, Some(scope)) => {
                return Err(syn::Error::new(
                    scope.span(),
                    "a container `scope` is the record's name, the first scope of each field's \
                     context, and applies only with `struct = ..`; a `plaintext` record's fields \
                     take the caller's context",
                ));
            }
            _ => {}
        }
        if let Some(scope) = &scope {
            if scope.value().is_empty() {
                return Err(syn::Error::new(
                    scope.span(),
                    "an empty `scope` is rejected when a value is encrypted: name the stored \
                     data (e.g. \"users\")",
                ));
            }
            if !is_plain_segment(&scope.value()) {
                return Err(syn::Error::new(
                    scope.span(),
                    "a container `scope` is the first segment of every field's ZeroKMS \
                     descriptor, so it must be plain: no `/`, `(`, `)`, control or invisible \
                     character, and not beginning with `b64:`, a digit or `-`; otherwise it \
                     would render escaped and the log would not name the table. For the table \
                     `public.users` write `scope = \"users\"`",
                ));
            }
        }

        if let (Some(by_field), Some(context_type)) = (&by_field, &context_type) {
            let mut err = syn::Error::new_spanned(
                context_type,
                "`context_type` names what the caller passes to a record whose fields take the \
                 caller's context; a `struct` derive's fields carry their own contexts, so it does \
                 not apply",
            );
            err.combine(syn::Error::new_spanned(by_field, "`struct` given here"));
            return Err(err);
        }

        if by_field.is_none() {
            let part = caller_scope
                .as_ref()
                .map(|(name, _)| name.span())
                .or_else(|| stored_scope.as_ref().map(|field| field.span()))
                .or_else(|| caller_bind.as_ref().map(|(name, _)| name.span()))
                .or_else(|| stored_bind.as_ref().map(|field| field.span()));
            if let Some(span) = part {
                return Err(syn::Error::new(
                    span,
                    "`scope(..)` and `bind(..)` list the parts of a `struct = ..` record's \
                     context: a `plaintext` record takes the whole context from its caller",
                ));
            }
        }

        Ok(Self {
            krate: krate.unwrap_or_else(|| syn::parse_quote!(::stack_encrypt)),
            plaintexts,
            by_field,
            scope,
            caller_scope,
            stored_scope,
            caller_bind,
            stored_bind,
            context_type,
        })
    }
}

/// Field-level options, from `#[stash(...)]` on a field.
#[derive(Default)]
pub(crate) struct FieldAttrs {
    pub(crate) context_field: bool,
    /// `#[stash(identity = "...")]`: with `struct = ..`, the label segment
    /// this field is keyed under, in place of the plaintext field's name:
    /// the field is derived under `("<scope>", "<identity>")`. The plan
    /// builder's `.identity(segment)`.
    pub(crate) identity: Option<LitStr>,
    /// `#[stash(from = field)]` / `#[stash(from = 0)]`: with `struct = ..`,
    /// derive this field from a plaintext field whose name differs from its
    /// own.
    pub(crate) from: Option<Member>,
    /// `#[stash(default)]` / `#[stash(default = expr)]`: not derived;
    /// filled with `Default::default()` or the expression.
    pub(crate) default: Option<Option<Expr>>,
    /// `#[stash(decrypt)]`: decryption opens this field.
    pub(crate) decrypt: bool,
    /// `#[stash(passthrough)]`, on a field of a `struct = ..` record with the
    /// owned derives. The plaintext field is moved into the record in the
    /// clear, not encrypted, and moved back when the record is decrypted.
    pub(crate) passthrough: bool,
    /// `#[stash(query = String)]`: with `struct = ..`, the type a query of
    /// this field takes, so its marker's methods take that type alone. The
    /// derive checks it against the plaintext field, which is that type or
    /// an `Option` of it. On a field whose marker has no operator method
    /// (a record field, a ciphertext alone), only the check applies.
    pub(crate) query: Option<Type>,
}

impl FieldAttrs {
    pub(crate) fn parse(attrs: &[Attribute]) -> Result<Self> {
        let mut parsed = Self::default();

        for attr in attrs.iter().filter(|a| a.path().is_ident("stash")) {
            attr.parse_nested_meta(|meta| {
                if meta.path.is_ident("context_field") {
                    if parsed.context_field {
                        return Err(meta.error("`context_field` is given twice"));
                    }
                    parsed.context_field = true;
                    return Ok(());
                }
                // Removed rather than unknown, so the message can say what
                // to write instead. A plan has exactly one context source,
                // and every field sits under it: a field sealed under a
                // literal of its own has no plan form.
                if meta.path.is_ident("context") {
                    return Err(meta.error(
                        "a field-level `context = \"..\"` is no longer accepted (0.2.0 accepted \
                         it). All outputs of a `plaintext = T` record share the caller's context, \
                         so remove it there; every field of a `struct = ..` derive sits under the \
                         record's context, so key it under another segment with \
                         `identity = \"..\"`. Either replacement is a different context from the \
                         old literal: data written with the literal does not decrypt under it and \
                         its terms do not match, so re-encrypt that data. Writing one value under \
                         two contexts (a dual write) is a fields plan that picks the same source \
                         twice, not a derive",
                    ));
                }
                // Each of these is singular by meaning, so a repeat is a
                // mistake: rejected rather than silently overwritten. A
                // silently-winning second `from` would be the worst of them —
                // it crosses fields, which is exactly the failure the derive
                // exists to prevent.
                if meta.path.is_ident("identity") {
                    if parsed.identity.is_some() {
                        return Err(meta.error(
                            "`identity` is given twice; a field is keyed under one segment",
                        ));
                    }
                    parsed.identity = Some(meta.value()?.parse()?);
                    return Ok(());
                }
                if meta.path.is_ident("from") {
                    if parsed.from.is_some() {
                        return Err(meta.error(
                            "`from` is given twice; a field is derived from one plaintext field",
                        ));
                    }
                    parsed.from = Some(meta.value()?.parse()?);
                    return Ok(());
                }
                if meta.path.is_ident("default") {
                    if parsed.default.is_some() {
                        return Err(meta.error("`default` is given twice"));
                    }
                    parsed.default = Some(if meta.input.peek(syn::Token![=]) {
                        Some(meta.value()?.parse()?)
                    } else {
                        None
                    });
                    return Ok(());
                }
                if meta.path.is_ident("decrypt") {
                    if parsed.decrypt {
                        return Err(meta.error("`decrypt` is given twice"));
                    }
                    parsed.decrypt = true;
                    return Ok(());
                }
                if meta.path.is_ident("passthrough") {
                    if parsed.passthrough {
                        return Err(meta.error("`passthrough` is given twice"));
                    }
                    parsed.passthrough = true;
                    return Ok(());
                }
                if meta.path.is_ident("query") {
                    if parsed.query.is_some() {
                        return Err(
                            meta.error("`query` is given twice; a field's queries take one type")
                        );
                    }
                    parsed.query = Some(meta.value()?.parse()?);
                    return Ok(());
                }
                // Removed rather than unknown, so the message can say what
                // to write instead.
                if meta.path.is_ident("nested") {
                    return Err(meta.error(
                        "`nested` is no longer accepted (0.2.0 accepted it): a field whose type \
                         is a record is an ordinary field, derived under \
                         `(\"<scope>\", \"<field>\")` like any other, and its own fields sit \
                         under that. Omit `nested`. That is a different context from the one \
                         `nested` gave the inner fields: data written with `nested` does not \
                         decrypt without it and its terms do not match, so re-encrypt that data",
                    ));
                }
                Err(meta.error(
                    "unsupported field attribute; expected `context_field`, \
                     `identity = \"...\"`, `from = field`, `default`, `default = expr`, \
                     `decrypt`, `passthrough` or `query = Type`",
                ))
            })?;
        }

        Ok(parsed)
    }
}

/// Whether `text` renders verbatim in a ZeroKMS descriptor: the plain-segment
/// rule of `stack_encrypt::Label`, copied here because a proc-macro crate
/// cannot depend on the crate it serves. The test below reads the fixture the
/// Rust and Go suites share, so this copy cannot drift from them.
pub(crate) fn is_plain_segment(text: &str) -> bool {
    const INVISIBLE: &[char] = &[
        '\u{00AD}', '\u{061C}', '\u{180E}', '\u{200B}', '\u{200C}', '\u{200D}', '\u{200E}',
        '\u{200F}', '\u{202A}', '\u{202B}', '\u{202C}', '\u{202D}', '\u{202E}', '\u{2060}',
        '\u{2061}', '\u{2062}', '\u{2063}', '\u{2064}', '\u{2066}', '\u{2067}', '\u{2068}',
        '\u{2069}', '\u{FEFF}',
    ];
    !text.is_empty()
        && !text.starts_with("b64:")
        && !text.starts_with(|c: char| c.is_ascii_digit() || c == '-')
        && !text
            .chars()
            .any(|c| c.is_control() || INVISIBLE.contains(&c) || matches!(c, '/' | '(' | ')'))
}

#[cfg(test)]
mod plain_segment_tests {
    use super::is_plain_segment;

    /// The derive is the third reader of `label_segments.json`, beside the
    /// stack-encrypt and Go suites: one list of what is plain.
    #[test]
    fn the_copied_rule_matches_the_shared_fixture() {
        let json: serde_json::Value = serde_json::from_str(include_str!(
            "../../stack-encrypt/tests/fixtures/label_segments.json"
        ))
        .expect("a valid fixture");
        let list = |key: &str| {
            json[key]
                .as_array()
                .expect("an array")
                .iter()
                .map(|v| v.as_str().expect("a string").to_owned())
                .collect::<Vec<_>>()
        };
        let (plain, not_plain) = (list("plain"), list("not_plain"));
        assert!(!plain.is_empty() && !not_plain.is_empty());
        for text in &plain {
            assert!(is_plain_segment(text), "{text:?}");
        }
        for text in &not_plain {
            assert!(!is_plain_segment(text), "{text:?}");
        }
        // The names the derive infers are Rust identifiers, which are plain
        // unless raw; an index is not.
        assert!(is_plain_segment("email_address"));
        assert!(!is_plain_segment("0"));
    }
}
