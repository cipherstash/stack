//! Where a node sits in a value: the steps from the root to it.

use vitaminc_protected::OpaqueDebug;

/// One step from a container to one of its children.
///
/// A map key can be user data, so `Debug` masks it; an index is structure
/// and is shown. Read a key by matching on the step.
///
/// Steps compare by value, keys included. A key is not secret from the
/// ciphertext, which carries every map key in the clear; only logs are
/// kept free of it.
#[derive(Clone, PartialEq, Eq, OpaqueDebug)]
pub enum Step {
    /// The element at this index of a sequence.
    Index(#[non_sensitive] usize),
    /// The entry under this key of a map.
    Key(String),
}

/// The steps from the root of a value to one node in it, root first. A
/// node at the root has no steps.
///
/// Refusals carry one to say where the value was refused, and their
/// `Display` never shows it, because map keys can be user data. `Debug`
/// shows its shape, with every key masked (see [`Step`]). Read the steps
/// with [`steps`](Path::steps). Paths compare step by step.
#[derive(Clone, Default, PartialEq, Eq, OpaqueDebug)]
pub struct Path(#[non_sensitive] Vec<Step>);

impl Path {
    /// A path of these steps, root first.
    pub fn new(steps: Vec<Step>) -> Self {
        Self(steps)
    }

    /// The steps, root first.
    pub fn steps(&self) -> &[Step] {
        &self.0
    }
}

/// A path written out for a test's assertion: `.key` for an entry and
/// `[i]` for an element, so `.m[0].k` is the entry `k` of the first
/// element of the entry `m`.
#[cfg(test)]
pub(crate) fn render(path: &Path) -> String {
    path.steps()
        .iter()
        .map(|step| match step {
            Step::Index(i) => format!("[{i}]"),
            Step::Key(k) => format!(".{k}"),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_writes_keys_and_indexes() {
        let path = Path::new(vec![
            Step::Key("m".into()),
            Step::Index(0),
            Step::Key("k".into()),
        ]);
        assert_eq!(render(&path), ".m[0].k");
        assert_eq!(render(&Path::default()), "");
    }

    #[test]
    fn steps_are_kept_root_first() {
        let path = Path::new(vec![Step::Key("a".into()), Step::Index(2)]);
        assert_eq!(path.steps(), [Step::Key("a".into()), Step::Index(2)]);
        assert!(Path::default().steps().is_empty());
    }

    #[test]
    fn paths_compare_step_by_step() {
        let path = |steps: Vec<Step>| Path::new(steps);
        let a = path(vec![Step::Key("a".into()), Step::Index(2)]);
        assert_eq!(a, a.clone());
        assert_ne!(a, path(vec![Step::Key("b".into()), Step::Index(2)]));
        assert_ne!(a, path(vec![Step::Key("a".into()), Step::Index(3)]));
        assert_ne!(a, path(vec![Step::Key("a".into())]));
        assert_ne!(Step::Index(0), Step::Key("0".into()));
        assert_eq!(Path::default(), path(Vec::new()));
    }

    #[test]
    fn debug_shows_indexes_and_masks_keys() {
        let path = Path::new(vec![Step::Key("ada@example.com".into()), Step::Index(2)]);
        let shown = format!("{path:?}");
        assert!(!shown.contains("ada"), "{shown}");
        assert!(shown.contains("Key(\"***\")"), "{shown}");
        assert!(shown.contains("Index(2)"), "{shown}");
    }
}
