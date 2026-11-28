//! This crate proves that a crate which depends on `stack-encrypt` alone can
//! derive and implement `Encrypt` and `Decrypt`. The proof holds only while
//! the manifest keeps that shape, so these tests read it.
//!
//! Rust resolves a path such as `::vitaminc_aead` only when the crate being
//! compiled names that crate as a dependency of its own. So a manifest that
//! names no vitaminc crate means that nothing here, the derived code
//! included, can reach one except through `stack_encrypt`.

const MANIFEST: &str = include_str!("../Cargo.toml");

/// Each `[table]` of the manifest with the lines in it, comments left out.
fn tables() -> Vec<(String, Vec<String>)> {
    let mut tables: Vec<(String, Vec<String>)> = vec![(String::new(), Vec::new())];
    for line in MANIFEST.lines() {
        let line = line.split('#').next().unwrap_or_default().trim();
        if line.is_empty() {
            continue;
        }
        if let Some(name) = line
            .strip_prefix('[')
            .and_then(|rest| rest.strip_suffix(']'))
        {
            tables.push((name.to_owned(), Vec::new()));
        } else if let Some((_, lines)) = tables.last_mut() {
            lines.push(line.to_owned());
        }
    }
    tables
}

/// The keys of a table: the dependency names, in a dependency table.
fn keys(lines: &[String]) -> Vec<String> {
    lines
        .iter()
        .filter_map(|line| line.split('=').next())
        .map(|key| key.trim().to_owned())
        .collect()
}

#[test]
fn the_only_dependency_is_stack_encrypt() {
    let tables = tables();
    let dependencies = tables
        .iter()
        .find(|(name, _)| name == "dependencies")
        .map(|(_, lines)| keys(lines));
    assert_eq!(
        dependencies,
        Some(vec!["stack-encrypt".to_owned()]),
        "this crate must depend on stack-encrypt and on nothing else, or it no longer \
         shows what a crate with that one dependency can do"
    );
}

#[test]
fn no_table_names_a_vitaminc_crate() {
    let named: Vec<String> = tables()
        .into_iter()
        .flat_map(|(name, lines)| std::iter::once(name).chain(lines))
        .filter(|line| line.contains("vitaminc"))
        .collect();
    assert!(
        named.is_empty(),
        "this crate must reach vitaminc only through stack-encrypt, but its manifest names \
         it: {named:?}"
    );
}

#[test]
fn the_reader_sees_every_dependency_table() {
    // A reader that missed a table would pass the tests above on a manifest
    // it had not read.
    let names: Vec<String> = tables().into_iter().map(|(name, _)| name).collect();
    for table in ["package", "dependencies", "dev-dependencies"] {
        assert!(
            names.iter().any(|name| name == table),
            "the manifest reader did not find the `[{table}]` table; it found {names:?}"
        );
    }
}
