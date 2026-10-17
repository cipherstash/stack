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
//!
//! A file belongs to every version unless it says otherwise with one line,
//! [`ONLY_DIRECTIVE`] and a version number: `-- ONLY EQL VERSION: 4`. That is
//! how a surface EQL v4 has and EQL v3 must not (the range query domains and
//! `between`, ADR-0009 decision 7) shares the one source tree: the build
//! renders a file only for the version it belongs to ([`belongs_to`]), and
//! [`render_str`] refuses to render it as any other.

use std::fmt;
use std::fs;
use std::io;
use std::path::{Component, Path, PathBuf};

/// The schema-and-name prefix placeholder.
pub const PREFIX: &str = "{{prefix}}";

/// The payload-version placeholder.
pub const EQL_VERSION: &str = "{{eql_version}}";

/// The start of the line that confines a source file to one EQL version:
/// `-- ONLY EQL VERSION: 4`. At most one per file; a file without one belongs
/// to every version. The number is the payload version ([`EqlVersion::number`]),
/// not the schema name, because the source may not name a schema literally.
pub const ONLY_DIRECTIVE: &str = "-- ONLY EQL VERSION:";

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
    /// An [`ONLY_DIRECTIVE`] line that does not name a version.
    BadOnlyDirective { line: usize, value: String },
    /// A second [`ONLY_DIRECTIVE`] line.
    DuplicateOnlyDirective { line: usize },
    /// A file confined to another version, rendered as this one.
    OtherVersion {
        line: usize,
        only: EqlVersion,
        version: EqlVersion,
    },
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
                "line {line}: literal `{literal}`; write {PREFIX} in its place, in comments too, \
                 so the name follows the EQL version (`{literal}_internal` is \
                 `{PREFIX}_internal`)"
            ),
            RenderError::BadOnlyDirective { line, value } => write!(
                f,
                "line {line}: `{ONLY_DIRECTIVE}{value}` names no EQL version (expected \
                 `{ONLY_DIRECTIVE} 3` or `{ONLY_DIRECTIVE} 4`)"
            ),
            RenderError::DuplicateOnlyDirective { line } => {
                write!(f, "line {line}: a second `{ONLY_DIRECTIVE}` line")
            }
            RenderError::OtherVersion {
                line,
                only,
                version,
            } => write!(
                f,
                "line {line}: this file belongs to {} only and cannot be rendered as {}",
                only.prefix(),
                version.prefix()
            ),
        }
    }
}

impl std::error::Error for RenderError {}

/// The one version `src` is confined to by its [`ONLY_DIRECTIVE`] line, with
/// the line's number, or `None` when it belongs to every version.
fn only_version(src: &str) -> Result<Option<(usize, EqlVersion)>, RenderError> {
    let mut found = None;
    for (i, line) in src.lines().enumerate() {
        let Some(value) = line.strip_prefix(ONLY_DIRECTIVE) else {
            continue;
        };
        let lineno = i + 1;
        if found.is_some() {
            return Err(RenderError::DuplicateOnlyDirective { line: lineno });
        }
        let version = value
            .strip_prefix(' ')
            .and_then(|v| v.trim_end().parse::<EqlVersion>().ok())
            .ok_or_else(|| RenderError::BadOnlyDirective {
                line: lineno,
                value: value.to_string(),
            })?;
        found = Some((lineno, version));
    }
    Ok(found)
}

/// Whether `src` belongs to `version`: true unless an [`ONLY_DIRECTIVE`] line
/// confines it to another. The build asks this of every ordered file before
/// rendering a version's bundle, so a file confined to EQL v4 never reaches
/// the EQL v3 installer.
pub fn belongs_to(src: &str, version: EqlVersion) -> Result<bool, RenderError> {
    Ok(only_version(src)?.is_none_or(|(_, only)| only == version))
}

/// Render one source text as `version`. A source confined to another version
/// by its [`ONLY_DIRECTIVE`] line is refused ([`RenderError::OtherVersion`]).
pub fn render_str(src: &str, version: EqlVersion) -> Result<String, RenderError> {
    if let Some((line, only)) = only_version(src)? {
        if only != version {
            return Err(RenderError::OtherVersion {
                line,
                only,
                version,
            });
        }
    }
    let mut out = String::with_capacity(src.len());
    for (i, line) in src.split_inclusive('\n').enumerate() {
        let lineno = i + 1;
        for v in EqlVersion::ALL {
            if contains_name(line, v.prefix()) {
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

/// Whether `line` names `prefix` as a name, rather than as the start of a
/// longer version (`eql_v30`). Comments count: they are rendered into both
/// bundles and into the docs, so a literal there is wrong in one of them.
fn contains_name(line: &str, prefix: &str) -> bool {
    line.match_indices(prefix).any(|(at, _)| {
        !line[at + prefix.len()..]
            .bytes()
            .next()
            .is_some_and(|b| b.is_ascii_digit())
    })
}

/// Why a file could not be rendered.
#[derive(Debug)]
pub enum RenderFileError {
    Io {
        path: PathBuf,
        source: io::Error,
    },
    Render {
        path: PathBuf,
        source: RenderError,
    },
    /// A file path that is absolute or climbs out with `..`. `out.join` would
    /// put its output outside `out`, or over the source itself.
    NotRelative {
        path: PathBuf,
    },
}

impl fmt::Display for RenderFileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RenderFileError::Io { path, source } => write!(f, "{}: {source}", path.display()),
            RenderFileError::Render { path, source } => {
                write!(f, "{}: {source}", path.display())
            }
            RenderFileError::NotRelative { path } => write!(
                f,
                "{}: not a relative path inside the source root",
                path.display()
            ),
        }
    }
}

impl std::error::Error for RenderFileError {}

/// Render each of `files` (relative to `root`) as `version`, writing it to the
/// same relative path under `out`. Every file is rendered before any is
/// written, so a source error leaves `out` as it was. A path that is absolute
/// or contains `..` is refused, since its output would land outside `out`.
pub fn render_files(
    root: &Path,
    files: &[PathBuf],
    out: &Path,
    version: EqlVersion,
) -> Result<(), RenderFileError> {
    let mut rendered = Vec::with_capacity(files.len());
    for rel in files {
        if !rel
            .components()
            .all(|c| matches!(c, Component::Normal(_) | Component::CurDir))
        {
            return Err(RenderFileError::NotRelative { path: rel.clone() });
        }
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
    fn a_longer_version_is_not_a_literal_name() {
        let src = "SELECT eql_v30_foo, eql_v41;\n";
        assert_eq!(render_str(src, EqlVersion::V3).unwrap(), src);
        assert_eq!(
            render_str("eql_v30 eql_v3\n", EqlVersion::V3),
            Err(RenderError::LiteralName {
                line: 1,
                literal: "eql_v3"
            })
        );
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

    const V4_ONLY: &str = "-- AUTOMATICALLY GENERATED FILE.\n\
                           -- ONLY EQL VERSION: 4\n\
                           SELECT {{prefix}}.between();\n";

    #[test]
    fn a_file_without_the_directive_belongs_to_every_version() {
        for v in EqlVersion::ALL {
            assert_eq!(belongs_to(SRC, v), Ok(true));
        }
    }

    #[test]
    fn a_confined_file_belongs_to_its_version_alone_and_renders_only_as_it() {
        assert_eq!(belongs_to(V4_ONLY, EqlVersion::V4), Ok(true));
        assert_eq!(belongs_to(V4_ONLY, EqlVersion::V3), Ok(false));
        assert_eq!(
            render_str(V4_ONLY, EqlVersion::V4).unwrap(),
            "-- AUTOMATICALLY GENERATED FILE.\n\
             -- ONLY EQL VERSION: 4\n\
             SELECT eql_v4.between();\n"
        );
        let err = render_str(V4_ONLY, EqlVersion::V3).unwrap_err();
        assert_eq!(
            err,
            RenderError::OtherVersion {
                line: 2,
                only: EqlVersion::V4,
                version: EqlVersion::V3
            }
        );
        assert_eq!(
            err.to_string(),
            "line 2: this file belongs to eql_v4 only and cannot be rendered as eql_v3"
        );
        // Trailing whitespace is tolerated; the version is the number.
        assert_eq!(
            belongs_to("-- ONLY EQL VERSION: 3  \n", EqlVersion::V3),
            Ok(true)
        );
    }

    #[test]
    fn a_malformed_or_repeated_directive_is_refused() {
        for (src, value) in [
            ("x\n-- ONLY EQL VERSION: 2\n", " 2"),
            ("x\n-- ONLY EQL VERSION:4\n", "4"),
            ("x\n-- ONLY EQL VERSION: v4\n", " v4"),
            ("x\n-- ONLY EQL VERSION:\n", ""),
        ] {
            let err = belongs_to(src, EqlVersion::V4).unwrap_err();
            assert_eq!(
                err,
                RenderError::BadOnlyDirective {
                    line: 2,
                    value: value.to_string()
                }
            );
            assert!(err.to_string().starts_with("line 2: "), "{err}");
            assert_eq!(render_str(src, EqlVersion::V4), Err(err));
        }
        let twice = "-- ONLY EQL VERSION: 4\n-- ONLY EQL VERSION: 4\n";
        assert_eq!(
            belongs_to(twice, EqlVersion::V4),
            Err(RenderError::DuplicateOnlyDirective { line: 2 })
        );
        assert_eq!(
            RenderError::DuplicateOnlyDirective { line: 2 }.to_string(),
            "line 2: a second `-- ONLY EQL VERSION:` line"
        );
        // Prose that mentions the directive mid-line is not a directive.
        assert_eq!(
            belongs_to("--! see `-- ONLY EQL VERSION: 4`\n", EqlVersion::V3),
            Ok(true)
        );
    }

    #[test]
    fn parses_versions() {
        assert_eq!("3".parse(), Ok(EqlVersion::V3));
        assert_eq!("4".parse(), Ok(EqlVersion::V4));
        assert!("2".parse::<EqlVersion>().is_err());
    }

    /// A scratch directory removed on drop, so a failed assertion does not
    /// leave it behind for a later run with the same pid to find.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(name: &str) -> Self {
            let dir = std::env::temp_dir().join(format!("{name}-{}", std::process::id()));
            let _ = fs::remove_dir_all(&dir);
            Scratch(dir)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn render_files_writes_nothing_when_any_file_fails() {
        let scratch = Scratch::new("eql-render");
        let dir = &scratch.0;
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
    }

    #[test]
    fn render_files_refuses_a_file_confined_to_the_other_version() {
        let scratch = Scratch::new("eql-render-only");
        let dir = &scratch.0;
        let root = dir.join("root");
        let out = dir.join("out");
        fs::create_dir_all(root.join("src/v3")).unwrap();
        fs::write(root.join("src/v3/range.sql"), V4_ONLY).unwrap();
        let files = [PathBuf::from("src/v3/range.sql")];

        let err = render_files(&root, &files, &out, EqlVersion::V3).unwrap_err();
        assert!(err.to_string().contains("belongs to eql_v4 only"), "{err}");
        assert!(!out.exists());
        render_files(&root, &files, &out, EqlVersion::V4).unwrap();
        assert!(out.join("src/v3/range.sql").exists());
    }

    #[test]
    fn render_files_refuses_paths_outside_out() {
        let scratch = Scratch::new("eql-render-abs");
        let dir = &scratch.0;
        let root = dir.join("root");
        let out = dir.join("out");
        fs::create_dir_all(root.join("src")).unwrap();
        let src = root.join("src/a.sql");
        fs::write(&src, "SELECT {{prefix}}.f();\n").unwrap();

        for rel in [src.clone(), PathBuf::from("src/../src/a.sql")] {
            let err =
                render_files(&root, std::slice::from_ref(&rel), &out, EqlVersion::V4).unwrap_err();
            assert!(
                matches!(&err, RenderFileError::NotRelative { path } if *path == rel),
                "{err}"
            );
        }
        assert_eq!(
            fs::read_to_string(&src).unwrap(),
            "SELECT {{prefix}}.f();\n"
        );
        assert!(!out.exists());
    }
}
