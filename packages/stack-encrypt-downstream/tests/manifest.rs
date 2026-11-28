//! This crate proves that a crate which depends on `stack-encrypt` alone can
//! derive and implement `Encrypt` and `Decrypt`. The proof holds only while
//! the manifest keeps that shape, so these tests read it.
//!
//! Rust resolves a path such as `::vitaminc_aead` only when the crate being
//! compiled names that crate as a dependency of its own. So a manifest that
//! names no vitaminc crate means that nothing here, the derived code
//! included, can reach one except through `stack_encrypt`.
//!
//! Cargo reads dependencies from more than one table: `[dependencies]`,
//! `[build-dependencies]`, and `[dev-dependencies]`, each also under
//! `[target.<cfg>]`. A dependency can be a sub-table of its own, such as
//! `[dependencies.serde]`. The manifest is parsed as TOML, so every one of
//! those forms is read.

use toml::{Table, Value};

const MANIFEST: &str = include_str!("../Cargo.toml");

/// The only crate that a table other than a dev-dependency table can list.
const ONLY_DEPENDENCY: &str = "stack-encrypt";

/// The three kinds of dependency table that Cargo reads.
const KINDS: [&str; 3] = ["dependencies", "build-dependencies", "dev-dependencies"];

/// One entry of a dependency table.
struct Dependency {
    /// Where the entry is, such as `target.'cfg(unix)'.dependencies.serde`.
    place: String,
    /// The table's kind, one of [`KINDS`].
    kind: &'static str,
    /// The name the entry is listed under.
    name: String,
    /// The crate the entry resolves to: its `package` key, if it has one,
    /// or else its name.
    package: String,
}

/// Every entry of every dependency table in `manifest`: the top-level tables
/// and those under each `[target.<cfg>]`.
fn dependencies(manifest: &str) -> Vec<Dependency> {
    let manifest: Table = manifest.parse().expect("the manifest is not valid TOML");
    let mut found = Vec::new();
    collect(&manifest, "", &mut found);
    if let Some(Value::Table(targets)) = manifest.get("target") {
        for (cfg, target) in targets {
            if let Value::Table(target) = target {
                collect(target, &format!("target.'{cfg}'."), &mut found);
            }
        }
    }
    found
}

/// The entries of the dependency tables directly under `table`.
fn collect(table: &Table, prefix: &str, found: &mut Vec<Dependency>) {
    for kind in KINDS {
        let Some(Value::Table(entries)) = table.get(kind) else {
            continue;
        };
        for (name, entry) in entries {
            let package = match entry {
                Value::Table(entry) => entry.get("package").and_then(Value::as_str),
                _ => None,
            };
            found.push(Dependency {
                place: format!("{prefix}{kind}.{name}"),
                kind,
                name: name.clone(),
                package: package.unwrap_or(name).to_owned(),
            });
        }
    }
}

/// What makes `manifest` break the rule this crate depends on. Empty when
/// the manifest keeps the rule:
///
/// - `[dependencies]` lists `stack-encrypt`.
/// - No table but a dev-dependency table lists any other crate.
/// - No table, dev-dependency tables included, names a vitaminc crate.
fn problems(manifest: &str) -> Vec<String> {
    let dependencies = dependencies(manifest);
    let mut problems = Vec::new();
    let lists_stack_encrypt = dependencies.iter().any(|dependency| {
        dependency.place == format!("dependencies.{ONLY_DEPENDENCY}")
            && dependency.package == ONLY_DEPENDENCY
    });
    if !lists_stack_encrypt {
        problems.push(format!(
            "`[dependencies]` does not list `{ONLY_DEPENDENCY}`"
        ));
    }
    for dependency in &dependencies {
        let Dependency {
            place,
            kind,
            name,
            package,
        } = dependency;
        let only = name == ONLY_DEPENDENCY && package == ONLY_DEPENDENCY;
        if *kind != "dev-dependencies" && !only {
            problems.push(format!("`{place}` lists `{package}`"));
        }
        if name.contains("vitaminc") || package.contains("vitaminc") {
            problems.push(format!("`{place}` names a vitaminc crate, `{package}`"));
        }
    }
    problems
}

/// Every key and string value in `manifest` that names a vitaminc crate,
/// with where it is. The scan reads every table, not only the dependency
/// tables, such as a `[patch]` table or a feature list.
fn vitaminc_mentions(manifest: &str) -> Vec<String> {
    fn walk(value: &Value, place: &str, found: &mut Vec<String>) {
        match value {
            Value::String(text) if text.contains("vitaminc") => {
                found.push(format!("`{place}` = {text:?}"));
            }
            Value::Array(items) => {
                for item in items {
                    walk(item, place, found);
                }
            }
            Value::Table(table) => {
                for (key, value) in table {
                    let place = if place.is_empty() {
                        key.clone()
                    } else {
                        format!("{place}.{key}")
                    };
                    if key.contains("vitaminc") {
                        found.push(format!("`{place}`"));
                    }
                    walk(value, &place, found);
                }
            }
            _ => {}
        }
    }
    let manifest: Table = manifest.parse().expect("the manifest is not valid TOML");
    let mut found = Vec::new();
    walk(&Value::Table(manifest), "", &mut found);
    found
}

#[test]
fn the_only_dependency_is_stack_encrypt() {
    assert_eq!(
        problems(MANIFEST),
        Vec::<String>::new(),
        "this crate must depend on stack-encrypt and on nothing else, and reach vitaminc only \
         through stack-encrypt, or it no longer shows what a crate with that one dependency \
         can do"
    );
}

#[test]
fn no_table_names_a_vitaminc_crate() {
    let named = vitaminc_mentions(MANIFEST);
    assert!(
        named.is_empty(),
        "this crate must reach vitaminc only through stack-encrypt, but its manifest names \
         it: {named:?}"
    );
}

#[test]
fn the_crate_has_no_features() {
    // trybuild builds `tests/ui` with this crate's features. A feature that
    // turned on a stack-encrypt feature could add implementors to the lists
    // that rustc prints, and so change the errors recorded there.
    let manifest: Table = MANIFEST.parse().expect("the manifest is not valid TOML");
    assert!(
        !manifest.contains_key("features"),
        "this crate must have no features, or the errors recorded in `tests/ui` can depend on \
         which features are on"
    );
}

#[test]
fn the_reader_sees_every_dependency_table() {
    // A reader that missed a table would pass the test above on a manifest
    // it had not read.
    let kinds: Vec<&str> = dependencies(MANIFEST)
        .iter()
        .map(|dependency| dependency.kind)
        .collect();
    for kind in ["dependencies", "dev-dependencies"] {
        assert!(
            kinds.contains(&kind),
            "the manifest reader found no entry in a `[{kind}]` table; it found {kinds:?}"
        );
    }
}

/// The checks of `problems` and `vitaminc_mentions`, one manifest form at a
/// time.
mod problems {
    use super::{problems, vitaminc_mentions};

    /// The `[dependencies]` table that every manifest below starts with.
    const BASE: &str = "[dependencies]\nstack-encrypt = { path = \"../stack-encrypt\" }\n";

    #[track_caller]
    fn assert_refused(extra: &str, expected: &str) {
        let manifest = format!("{BASE}{extra}");
        assert_eq!(
            problems(&manifest),
            vec![expected.to_owned()],
            "the check did not refuse this manifest with exactly the expected problem:\n{manifest}"
        );
    }

    #[test]
    fn accepts_stack_encrypt_alone() {
        assert_eq!(
            problems(BASE),
            Vec::<String>::new(),
            "the check refused a manifest whose only dependency is stack-encrypt"
        );
    }

    #[test]
    fn accepts_dev_dependencies_that_are_not_vitaminc() {
        let manifest = format!(
            "{BASE}[dev-dependencies]\n\
             stack-encrypt = {{ path = \"../stack-encrypt\", features = [\"test-support\"] }}\n\
             tokio = {{ workspace = true, features = [\"rt\", \"macros\"] }}\n\
             trybuild = \"1\"\n"
        );
        assert_eq!(
            problems(&manifest),
            Vec::<String>::new(),
            "the check refused dev-dependencies that name no vitaminc crate"
        );
    }

    #[test]
    fn refuses_a_manifest_without_stack_encrypt() {
        assert_eq!(
            problems("[dependencies]\n"),
            vec!["`[dependencies]` does not list `stack-encrypt`".to_owned()],
            "the check accepted a manifest that does not depend on stack-encrypt"
        );
    }

    #[test]
    fn refuses_a_second_entry_in_dependencies() {
        assert_refused("serde = \"1\"\n", "`dependencies.serde` lists `serde`");
    }

    #[test]
    fn refuses_a_dependency_written_as_a_sub_table() {
        assert_refused(
            "[dependencies.serde]\nversion = \"1\"\n",
            "`dependencies.serde` lists `serde`",
        );
    }

    #[test]
    fn refuses_a_dependency_under_a_target() {
        assert_refused(
            "[target.'cfg(unix)'.dependencies]\nlibc = \"0.2\"\n",
            "`target.'cfg(unix)'.dependencies.libc` lists `libc`",
        );
    }

    #[test]
    fn refuses_a_dependency_written_as_a_dotted_key_under_a_target() {
        assert_refused(
            "[target.'cfg(unix)']\ndependencies.libc = \"0.2\"\n",
            "`target.'cfg(unix)'.dependencies.libc` lists `libc`",
        );
    }

    #[test]
    fn refuses_a_build_dependency() {
        assert_refused(
            "[build-dependencies]\ncc = \"1\"\n",
            "`build-dependencies.cc` lists `cc`",
        );
    }

    #[test]
    fn refuses_a_build_dependency_under_a_target() {
        assert_refused(
            "[target.'cfg(unix)'.build-dependencies]\ncc = \"1\"\n",
            "`target.'cfg(unix)'.build-dependencies.cc` lists `cc`",
        );
    }

    #[test]
    fn refuses_a_vitaminc_dev_dependency() {
        assert_refused(
            "[dev-dependencies]\nvitaminc-aead = \"0.10\"\n",
            "`dev-dependencies.vitaminc-aead` names a vitaminc crate, `vitaminc-aead`",
        );
    }

    #[test]
    fn refuses_a_vitaminc_dev_dependency_under_a_target() {
        assert_refused(
            "[target.'cfg(unix)'.dev-dependencies]\nvitaminc-aead = \"0.10\"\n",
            "`target.'cfg(unix)'.dev-dependencies.vitaminc-aead` names a vitaminc crate, \
             `vitaminc-aead`",
        );
    }

    #[test]
    fn refuses_a_vitaminc_crate_under_another_name() {
        assert_refused(
            "[dev-dependencies]\naead = { package = \"vitaminc-aead\", version = \"0.10\" }\n",
            "`dev-dependencies.aead` names a vitaminc crate, `vitaminc-aead`",
        );
    }

    #[test]
    fn finds_vitaminc_outside_the_dependency_tables() {
        let manifest = format!(
            "{BASE}[features]\nextra = [\"stack-encrypt/vitaminc-extra\"]\n\
             [patch.crates-io]\nvitaminc-aead = {{ path = \"../vitaminc-aead\" }}\n"
        );
        assert_eq!(
            vitaminc_mentions(&manifest),
            vec![
                "`features.extra` = \"stack-encrypt/vitaminc-extra\"".to_owned(),
                "`patch.crates-io.vitaminc-aead`".to_owned(),
                "`patch.crates-io.vitaminc-aead.path` = \"../vitaminc-aead\"".to_owned(),
            ],
            "the scan missed a vitaminc name outside the dependency tables"
        );
        assert_eq!(
            vitaminc_mentions(BASE),
            Vec::<String>::new(),
            "the scan found a vitaminc name in a manifest that has none"
        );
    }

    #[test]
    fn refuses_another_crate_listed_as_stack_encrypt() {
        let manifest =
            "[dependencies]\nstack-encrypt = { package = \"vitaminc-aead\", version = \"0.10\" }\n";
        assert_eq!(
            problems(manifest),
            vec![
                "`[dependencies]` does not list `stack-encrypt`".to_owned(),
                "`dependencies.stack-encrypt` lists `vitaminc-aead`".to_owned(),
                "`dependencies.stack-encrypt` names a vitaminc crate, `vitaminc-aead`".to_owned(),
            ],
            "the check accepted another crate renamed to stack-encrypt"
        );
    }
}
