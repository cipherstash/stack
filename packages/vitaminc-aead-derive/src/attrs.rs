//! Parsing of the `#[aead(...)]` container and field attributes.

use syn::{Attribute, Path, Result};

/// Container-level options, from `#[aead(...)]` on the struct itself.
pub(crate) struct ContainerAttrs {
    /// Path to the `vitaminc_aead` crate in the generated code. Defaults to
    /// `::vitaminc_aead`; overridden by `#[aead(crate = "...")]` so the macros
    /// work through a re-export such as `::vitaminc::aead`.
    pub(crate) krate: Path,
}

impl ContainerAttrs {
    pub(crate) fn parse(attrs: &[Attribute]) -> Result<Self> {
        let mut krate: Option<Path> = None;

        for attr in attrs.iter().filter(|a| a.path().is_ident("aead")) {
            attr.parse_nested_meta(|meta| {
                if meta.path.is_ident("crate") {
                    let lit: syn::LitStr = meta.value()?.parse()?;
                    krate = Some(lit.parse()?);
                    return Ok(());
                }
                Err(meta.error("unsupported container attribute; expected `crate = \"...\"`"))
            })?;
        }

        Ok(Self {
            krate: krate.unwrap_or_else(|| syn::parse_quote!(::vitaminc_aead)),
        })
    }
}

/// Field-level options, from `#[aead(...)]` on a field.
pub(crate) struct FieldAttrs {
    /// Map key to use for this field, from `#[aead(rename = "...")]`.
    pub(crate) rename: Option<String>,
    /// Store this field in the clear rather than encrypting it, from
    /// `#[aead(passthrough)]`. The value is neither encrypted nor
    /// authenticated — see the crate docs.
    pub(crate) passthrough: bool,
}

impl FieldAttrs {
    pub(crate) fn parse(attrs: &[Attribute]) -> Result<Self> {
        let mut rename: Option<String> = None;
        let mut passthrough = false;

        for attr in attrs.iter().filter(|a| a.path().is_ident("aead")) {
            attr.parse_nested_meta(|meta| {
                if meta.path.is_ident("rename") {
                    let lit: syn::LitStr = meta.value()?.parse()?;
                    rename = Some(lit.value());
                    return Ok(());
                }
                if meta.path.is_ident("passthrough") {
                    passthrough = true;
                    return Ok(());
                }
                Err(meta.error(
                    "unsupported field attribute; expected `rename = \"...\"` or `passthrough`",
                ))
            })?;
        }

        Ok(Self {
            rename,
            passthrough,
        })
    }
}
