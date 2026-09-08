//! Parsing of the `#[stash(...)]` container and field attributes.

use syn::{Attribute, Expr, LitStr, Member, Path, Result, Type};

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
    /// container's `context` and the plaintext field's name, unless the
    /// field says otherwise. Exclusive with `plaintext`; requires `context`.
    pub(crate) by_field: Option<Type>,
    /// `#[stash(context = "...")]` on the container: the first half of every
    /// field's inferred context — `"<context>/<field>"`. Names the stored
    /// data, not the Rust type: it is part of the stored data's identity, so
    /// it is given explicitly rather than inferred from a name a refactor
    /// can change. Only meaningful with `struct`.
    pub(crate) context: Option<LitStr>,
}

const CONTAINER_KEYS: &str = "unsupported container attribute; expected `plaintext = Type`, \
     `struct = Type`, `context = \"...\"` (with `struct`) or `crate = \"...\"`";

impl ContainerAttrs {
    pub(crate) fn parse(attrs: &[Attribute]) -> Result<Self> {
        let mut krate: Option<Path> = None;
        let mut plaintexts: Vec<Type> = Vec::new();
        let mut by_field: Option<Type> = None;
        let mut context: Option<LitStr> = None;

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
                if meta.path.is_ident("context") {
                    if context.is_some() {
                        return Err(meta.error("`context` is given twice; a struct has one prefix"));
                    }
                    context = Some(meta.value()?.parse()?);
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
        match (&by_field, &context) {
            (Some(by_field), None) => {
                return Err(syn::Error::new_spanned(
                    by_field,
                    "`struct = ..` needs a `context = \"..\"` beside it naming the stored data \
                     (e.g. `#[stash(struct = User, context = \"users\")]`): each field is derived \
                     under `\"<context>/<field>\"`, and the prefix is part of the stored data's \
                     identity, so it is given explicitly rather than inferred from the Rust \
                     type's name",
                ));
            }
            (None, Some(context)) => {
                return Err(syn::Error::new(
                    context.span(),
                    "a container `context` is the prefix of the per-field contexts and applies \
                     only with `struct = ..`; a `plaintext` record's fields take the caller's \
                     context, or a `context = \"..\"` of their own",
                ));
            }
            _ => {}
        }
        if let Some(context) = &context {
            if context.value().is_empty() {
                return Err(syn::Error::new(
                    context.span(),
                    "an empty `context` is rejected when a value is encrypted: name the stored \
                     data (e.g. \"users\")",
                ));
            }
        }

        Ok(Self {
            krate: krate.unwrap_or_else(|| syn::parse_quote!(::stack_encrypt)),
            plaintexts,
            by_field,
            context,
        })
    }
}

/// Field-level options, from `#[stash(...)]` on a field.
#[derive(Default)]
pub(crate) struct FieldAttrs {
    /// `#[stash(context = "...")]`: derive this field under exactly this
    /// context instead of the one a `struct` derive would infer, or the one
    /// the caller passes for the record. Extended by a caller's context like
    /// any other.
    pub(crate) context: Option<LitStr>,
    /// `#[stash(from = field)]` / `#[stash(from = 0)]`: with `struct = ..`,
    /// derive this field from a plaintext field whose name differs from its
    /// own.
    pub(crate) from: Option<Member>,
    /// `#[stash(default)]` / `#[stash(default = expr)]`: not derived;
    /// filled with `Default::default()` or the expression.
    pub(crate) default: Option<Option<Expr>>,
    /// `#[stash(decrypt)]`: decryption opens this field.
    pub(crate) decrypt: bool,
    /// `#[stash(nested)]`: with `struct = ..`, do not infer a context for
    /// this field — hand it the caller's as it is, because its type (a
    /// nested `struct` derive) carries its own contexts and composes them
    /// with it.
    pub(crate) nested: bool,
}

impl FieldAttrs {
    pub(crate) fn parse(attrs: &[Attribute]) -> Result<Self> {
        let mut parsed = Self::default();

        for attr in attrs.iter().filter(|a| a.path().is_ident("stash")) {
            attr.parse_nested_meta(|meta| {
                if meta.path.is_ident("context") {
                    // Each of these is singular by meaning, so a repeat is a
                    // mistake: rejected rather than silently overwritten. A
                    // silently-winning second `from` would be the worst of
                    // them — it crosses fields, which is exactly the failure
                    // the derive exists to prevent.
                    if parsed.context.is_some() {
                        return Err(meta.error("`context` is given twice; a field has one context"));
                    }
                    parsed.context = Some(meta.value()?.parse()?);
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
                if meta.path.is_ident("nested") {
                    if parsed.nested {
                        return Err(meta.error("`nested` is given twice"));
                    }
                    parsed.nested = true;
                    return Ok(());
                }
                Err(meta.error(
                    "unsupported field attribute; expected `context = \"...\"`, `from = field`, \
                     `default`, `default = expr`, `decrypt` or `nested`",
                ))
            })?;
        }

        if parsed.nested {
            if let Some(context) = &parsed.context {
                return Err(syn::Error::new(
                    context.span(),
                    "`nested` hands this field the caller's context because its type carries its \
                     own, so `context` does not apply: give one or the other",
                ));
            }
        }

        Ok(parsed)
    }
}
