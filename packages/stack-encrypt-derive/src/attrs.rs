//! Parsing of the `#[stack_encrypt(...)]` container and field attributes.

use syn::{Attribute, Expr, Ident, LitStr, Path, Result, Type};

/// Container-level options, from `#[stack_encrypt(...)]` on the struct itself.
pub(crate) struct ContainerAttrs {
    /// Path to the `stack_encrypt` crate in the generated code. Defaults to
    /// `::stack_encrypt`; overridden by `#[stack_encrypt(crate = "...")]` so the
    /// macros work through a re-export.
    pub(crate) krate: Path,
    /// The plaintext types this record is an encrypted form of, one impl
    /// each, from repeated `#[stack_encrypt(plaintext = Type)]`. Empty means
    /// a single impl generic over the plaintext.
    pub(crate) plaintexts: Vec<Type>,
}

impl ContainerAttrs {
    pub(crate) fn parse(attrs: &[Attribute]) -> Result<Self> {
        let mut krate: Option<Path> = None;
        let mut plaintexts = Vec::new();

        for attr in attrs.iter().filter(|a| a.path().is_ident("stack_encrypt")) {
            attr.parse_nested_meta(|meta| {
                if meta.path.is_ident("crate") {
                    let lit: LitStr = meta.value()?.parse()?;
                    krate = Some(lit.parse()?);
                    return Ok(());
                }
                if meta.path.is_ident("plaintext") {
                    plaintexts.push(meta.value()?.parse()?);
                    return Ok(());
                }
                Err(meta.error(
                    "unsupported container attribute; expected `plaintext = Type` or `crate = \"...\"`",
                ))
            })?;
        }

        Ok(Self {
            krate: krate.unwrap_or_else(|| syn::parse_quote!(::stack_encrypt)),
            plaintexts,
        })
    }
}

/// Field-level options, from `#[stack_encrypt(...)]` on a field.
#[derive(Default)]
pub(crate) struct FieldAttrs {
    /// `#[stack_encrypt(context = "...")]`: derive this field under exactly this
    /// context instead of the one the caller passed for the record.
    pub(crate) context: Option<LitStr>,
    /// `#[stack_encrypt(from = field)]`: derive this field from one field of
    /// the plaintext rather than from the whole plaintext.
    pub(crate) from: Option<Ident>,
    /// `#[stack_encrypt(default)]` / `#[stack_encrypt(default = expr)]`: not derived;
    /// filled with `Default::default()` or the expression.
    pub(crate) default: Option<Option<Expr>>,
    /// `#[stack_encrypt(decrypt)]`: decryption opens this field.
    pub(crate) decrypt: bool,
}

impl FieldAttrs {
    pub(crate) fn parse(attrs: &[Attribute]) -> Result<Self> {
        let mut parsed = Self::default();

        for attr in attrs.iter().filter(|a| a.path().is_ident("stack_encrypt")) {
            attr.parse_nested_meta(|meta| {
                if meta.path.is_ident("context") {
                    parsed.context = Some(meta.value()?.parse()?);
                    return Ok(());
                }
                if meta.path.is_ident("from") {
                    parsed.from = Some(meta.value()?.parse()?);
                    return Ok(());
                }
                if meta.path.is_ident("default") {
                    parsed.default = Some(if meta.input.peek(syn::Token![=]) {
                        Some(meta.value()?.parse()?)
                    } else {
                        None
                    });
                    return Ok(());
                }
                if meta.path.is_ident("decrypt") {
                    parsed.decrypt = true;
                    return Ok(());
                }
                Err(meta.error(
                    "unsupported field attribute; expected `context = \"...\"`, `from = field`, \
                     `default`, `default = expr` or `decrypt`",
                ))
            })?;
        }

        Ok(parsed)
    }
}
