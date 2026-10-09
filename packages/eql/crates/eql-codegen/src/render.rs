//! Renders the EQL SQL source as one EQL version.
//!
//! The SQL under `src/v3` names its schemas and its payload version by
//! placeholder, never literally, so one source can be written out under two
//! names (ADR-0002): `eql_v3` for cipherstash-client's terms and `eql_v4` for
//! Stack Encrypt's. Postgres then refuses to compare a query term of one with a
//! column of the other, at plan time.
//!
//! | placeholder       | `eql_v3` | `eql_v4` |
//! |-------------------|----------|----------|
//! | `{{prefix}}`      | `eql_v3` | `eql_v4` |
//! | `{{eql_version}}` | `3`      | `4`      |
//!
//! `{{prefix}}` is both the schema (`{{prefix}}.eq_term`) and the start of every
//! other name (`{{prefix}}_internal`, `public.{{prefix}}_text_eq`).
//!
//! Rendering is strict in both directions. An unknown or unterminated
//! placeholder is an error, and so is a literal `eql_v3` or `eql_v4` in the
//! source: a literal name would render the same in both outputs, so the `eql_v4`
//! bundle would quietly reach into `eql_v3`.

use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// The schema-and-name prefix placeholder.
pub const PREFIX: &str = "{{prefix}}";

/// The payload-version placeholder.
pub const EQL_VERSION: &str = "{{eql_version}}";

/// An EQL version the source can be rendered as.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EqlVersion {
    /// `eql_v3`: payloads and terms written by cipherstash-client.
    V3,
    /// `eql_v4`: payloads and terms written by Stack Encrypt.
    V4,
}

impl EqlVersion {
    /// Every version, in release order.
    pub const ALL: [EqlVersion; 2] = [EqlVersion::V3, EqlVersion::V4];

    /// The payload version, as the domain CHECKs compare it: `"3"` or `"4"`.
    pub fn number(self) -> &'static str {
        match self {
            EqlVersion::V3 => "3",
            EqlVersion::V4 => "4",
        }
    }

    /// The schema and name prefix: `eql_v3` or `eql_v4`.
    pub fn prefix(self) -> &'static str {
        match self {
            EqlVersion::V3 => "eql_v3",
            EqlVersion::V4 => "eql_v4",
        }
    }
}

impl std::str::FromStr for EqlVersion {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        EqlVersion::ALL
            .into_iter()
            .find(|v| v.number() == s)
            .ok_or_else(|| format!("unknown EQL version {s:?} (expected 3 or 4)"))
    }
}

/// Why a source could not be rendered. `line` is 1-based.
#[derive(Debug, PartialEq, Eq)]
pub enum RenderError {
    /// `{{name}}` where `name` is not a placeholder this renderer knows.
    UnknownPlaceholder { line: usize, name: String },
    /// `{{` with no closing `}}` on the same line.
    Unterminated { line: usize },
    /// A literal `eql_v3` or `eql_v4` where a placeholder belongs.
    LiteralName { line: usize, literal: &'static str },
}

impl fmt::Display for RenderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RenderError::UnknownPlaceholder { line, name } => write!(
                f,
                "line {line}: unknown placeholder {{{{{name}}}}} (expected {PREFIX} or {EQL_VERSION})"
            ),
            RenderError::Unterminated { line } => {
                write!(f, "line {line}: `{{{{` with no closing `}}}}`")
            }
            RenderError::LiteralName { line, literal } => write!(
                f,
                "line {line}: literal `{literal}`; write {PREFIX} so the name follows the EQL version"
            ),
        }
    }
}

impl std::error::Error for RenderError {}

/// Render one source text as `version`.
pub fn render_str(src: &str, version: EqlVersion) -> Result<String, RenderError> {
    let mut out = String::with_capacity(src.len());
    for (i, line) in src.split_inclusive('\n').enumerate() {
        let lineno = i + 1;
        for v in EqlVersion::ALL {
            if line.contains(v.prefix()) {
                return Err(RenderError::LiteralName {
                    line: lineno,
                    literal: v.prefix(),
                });
            }
        }
        let mut rest = line;
        while let Some(open) = rest.find("{{") {
            out.push_str(&rest[..open]);
            let after = &rest[open + 2..];
            let close = after
                .find("}}")
                .ok_or(RenderError::Unterminated { line: lineno })?;
            match &after[..close] {
                "prefix" => out.push_str(version.prefix()),
                "eql_version" => out.push_str(version.number()),
                other => {
                    return Err(RenderError::UnknownPlaceholder {
                        line: lineno,
                        name: other.to_string(),
                    })
                }
            }
            rest = &after[close + 2..];
        }
        out.push_str(rest);
    }
    Ok(out)
}

/// Why a file could not be rendered.
#[derive(Debug)]
pub enum RenderFileError {
    Io { path: PathBuf, source: io::Error },
    Render { path: PathBuf, source: RenderError },
}

impl fmt::Display for RenderFileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RenderFileError::Io { path, source } => write!(f, "{}: {source}", path.display()),
            RenderFileError::Render { path, source } => {
                write!(f, "{}: {source}", path.display())
            }
        }
    }
}

impl std::error::Error for RenderFileError {}

/// Render each of `files` (relative to `root`) as `version`, writing it to the
/// same relative path under `out`. Every file is rendered before any is
/// written, so a source error leaves `out` as it was.
pub fn render_files(
    root: &Path,
    files: &[PathBuf],
    out: &Path,
    version: EqlVersion,
) -> Result<(), RenderFileError> {
    let mut rendered = Vec::with_capacity(files.len());
    for rel in files {
        let path = root.join(rel);
        let src = fs::read_to_string(&path).map_err(|source| RenderFileError::Io {
            path: path.clone(),
            source,
        })?;
        let body = render_str(&src, version).map_err(|source| RenderFileError::Render {
            path: path.clone(),
            source,
        })?;
        rendered.push((out.join(rel), body));
    }
    for (dest, body) in rendered {
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent).map_err(|source| RenderFileError::Io {
                path: parent.to_path_buf(),
                source,
            })?;
        }
        fs::write(&dest, body).map_err(|source| RenderFileError::Io { path: dest, source })?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SRC: &str = "CREATE DOMAIN public.{{prefix}}_text_eq AS jsonb\n  \
                       CHECK (VALUE->>'v' = '{{eql_version}}');\n\
                       SELECT {{prefix}}_internal.f({{prefix}}.g());\n";

    #[test]
    fn renders_v3() {
        assert_eq!(
            render_str(SRC, EqlVersion::V3).unwrap(),
            "CREATE DOMAIN public.eql_v3_text_eq AS jsonb\n  \
             CHECK (VALUE->>'v' = '3');\n\
             SELECT eql_v3_internal.f(eql_v3.g());\n"
        );
    }

    #[test]
    fn renders_v4() {
        assert_eq!(
            render_str(SRC, EqlVersion::V4).unwrap(),
            "CREATE DOMAIN public.eql_v4_text_eq AS jsonb\n  \
             CHECK (VALUE->>'v' = '4');\n\
             SELECT eql_v4_internal.f(eql_v4.g());\n"
        );
    }

    #[test]
    fn text_without_placeholders_is_unchanged() {
        let src = "SELECT '{}'::jsonb, '{\"a\":1}', $$ { } $$;\n-- eql_v2 provenance\nno newline";
        assert_eq!(render_str(src, EqlVersion::V4).unwrap(), src);
    }

    #[test]
    fn rejects_literal_names() {
        for (src, literal) in [
            ("x\nSELECT eql_v3.f();\n", "eql_v3"),
            ("x\n-- eql_v4_internal\n", "eql_v4"),
        ] {
            assert_eq!(
                render_str(src, EqlVersion::V3),
                Err(RenderError::LiteralName { line: 2, literal })
            );
        }
    }

    #[test]
    fn rejects_unknown_placeholder() {
        assert_eq!(
            render_str("{{prefix}}\n{{ prefix }}\n", EqlVersion::V3),
            Err(RenderError::UnknownPlaceholder {
                line: 2,
                name: " prefix ".to_string()
            })
        );
    }

    #[test]
    fn rejects_unterminated_placeholder() {
        assert_eq!(
            render_str("ok\n{{prefix\n}}\n", EqlVersion::V3),
            Err(RenderError::Unterminated { line: 2 })
        );
    }

    #[test]
    fn parses_versions() {
        assert_eq!("3".parse(), Ok(EqlVersion::V3));
        assert_eq!("4".parse(), Ok(EqlVersion::V4));
        assert!("2".parse::<EqlVersion>().is_err());
    }

    #[test]
    fn render_files_writes_nothing_when_any_file_fails() {
        let dir = std::env::temp_dir().join(format!("eql-render-{}", std::process::id()));
        let root = dir.join("root");
        let out = dir.join("out");
        fs::create_dir_all(root.join("src/v3")).unwrap();
        fs::write(root.join("src/v3/a.sql"), "SELECT {{prefix}}.f();\n").unwrap();
        fs::write(root.join("src/v3/b.sql"), "SELECT eql_v3.f();\n").unwrap();

        let files = [PathBuf::from("src/v3/a.sql"), PathBuf::from("src/v3/b.sql")];
        let err = render_files(&root, &files, &out, EqlVersion::V4).unwrap_err();
        assert!(err.to_string().contains("b.sql"), "{err}");
        assert!(!out.exists());

        render_files(&root, &files[..1], &out, EqlVersion::V4).unwrap();
        assert_eq!(
            fs::read_to_string(out.join("src/v3/a.sql")).unwrap(),
            "SELECT eql_v4.f();\n"
        );
        fs::remove_dir_all(&dir).unwrap();
    }
}
