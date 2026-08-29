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
    /// `#[stash(row = Type)]`: the record is a row of the struct `Type`.
    /// Every derived field is derived from the plaintext field of its own
    /// name (`from`), under a context made of both names, unless the field
    /// says otherwise. Exclusive with `plaintext`.
    pub(crate) row: Option<Type>,
}

impl ContainerAttrs {
    pub(crate) fn parse(attrs: &[Attribute]) -> Result<Self> {
        let mut krate: Option<Path> = None;
        let mut plaintexts: Vec<Type> = Vec::new();
        let mut row: Option<Type> = None;

        for attr in attrs.iter().filter(|a| a.path().is_ident("stash")) {
            attr.parse_nested_meta(|meta| {
                if meta.path.is_ident("crate") {
                    if krate.is_some() {
                        return Err(meta.error("`crate` is given twice"));
                    }
                    let lit: LitStr = meta.value()?.parse()?;
                    krate = Some(lit.parse()?);
                    return Ok(());
                }
                if meta.path.is_ident("row") {
                    let ty: Type = meta.value()?.parse()?;
                    // A row reaches into the plaintext by field name and
                    // rebuilds it with a struct literal, so the type must be
                    // a struct named directly; its last segment also names
                    // the fields' contexts.
                    let named_struct = match &ty {
                        Type::Path(path) => path.qself.is_none(),
                        _ => false,
                    };
                    if !named_struct {
                        return Err(syn::Error::new_spanned(
                            &ty,
                            "`row` must name a struct directly (`row = User`): its fields are \
                             reached by name and its name is part of every field's context",
                        ));
                    }
                    if row.is_some() {
                        return Err(syn::Error::new_spanned(
                            &ty,
                            "`row` is given twice; a row has one plaintext struct",
                        ));
                    }
                    row = Some(ty);
                    return Ok(());
                }
                if meta.path.is_ident("plaintext") {
                    let plaintext: Type = meta.value()?.parse()?;
                    // The type is spliced into the impl header as written,
                    // where a reference has no lifetime to name. The generic
                    // impl (no `plaintext` at all) already accepts `&str` and
                    // friends; a listed one is only needed for `from = ..`,
                    // which reaches into a struct.
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
                Err(meta.error(
                    "unsupported container attribute; expected `plaintext = Type`, `row = Type` \
                     or `crate = \"...\"`",
                ))
            })?;
        }

        if let (Some(row), Some(plaintext)) = (&row, plaintexts.first()) {
            let mut err = syn::Error::new_spanned(
                row,
                "`row` and `plaintext` are two ways of naming the plaintext: a row *is* a record \
                 of its struct's fields, so give `row = ..` alone",
            );
            err.combine(syn::Error::new_spanned(plaintext, "`plaintext` given here"));
            return Err(err);
        }

        Ok(Self {
            krate: krate.unwrap_or_else(|| syn::parse_quote!(::stack_encrypt)),
            plaintexts,
            row,
        })
    }
}

/// Field-level options, from `#[stash(...)]` on a field.
#[derive(Default)]
pub(crate) struct FieldAttrs {
    /// `#[stash(context = "...")]`: derive this field under exactly this
    /// context instead of the one the caller passed for the record.
    pub(crate) context: Option<LitStr>,
    /// `#[stash(from = field)]` / `#[stash(from = 0)]`: derive
    /// this field from one field of the plaintext rather than from the whole
    /// plaintext. In a row, the override for a field whose name differs
    /// from its plaintext field's.
    pub(crate) from: Option<Member>,
    /// `#[stash(default)]` / `#[stash(default = expr)]`: not derived;
    /// filled with `Default::default()` or the expression.
    pub(crate) default: Option<Option<Expr>>,
    /// `#[stash(decrypt)]`: decryption opens this field.
    pub(crate) decrypt: bool,
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
                Err(meta.error(
                    "unsupported field attribute; expected `context = \"...\"`, `from = field`, \
                     `default`, `default = expr` or `decrypt`",
                ))
            })?;
        }

        // The leaves reject an empty context at runtime; a literal one is
        // known here, so say so at the literal. Checked after the loop, once
        // `from` is known whatever order the attributes were written in: the
        // advice depends on it, because a `from` field is never handed the
        // record's context, so "drop the attribute" is a dead end there.
        if let Some(context) = &parsed.context {
            if context.value().is_empty() {
                let message = if parsed.from.is_some() {
                    "an empty `context` is rejected when a value is encrypted: name the column \
                     this field encrypts (e.g. \"users/email\"). A `from` field is never handed \
                     the record's context, so the literal is the only context this field can have."
                } else {
                    "an empty `context` is rejected when a value is encrypted: name the field \
                     (e.g. \"users/email\"), or drop the attribute to use the record's context"
                };
                return Err(syn::Error::new(context.span(), message));
            }
        }

        Ok(parsed)
    }
}
