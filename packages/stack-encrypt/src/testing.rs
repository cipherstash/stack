//! Assertions over the contexts a declaration or a call uses. Behind the
//! `testing` feature.
//!
//! A wrong context loses data silently, so a test should pin it. The
//! [`assert_context!`](crate::assert_context) macro compares the context of
//! a declaration ([`Contexts`]) or of a prepared call ([`CallContexts`])
//! against the parts the test states, with their types. When they differ,
//! the failure names the first part that differs.
//!
//! ```
//! use stack_encrypt::sem::EqualityTerm;
//! use stack_encrypt::target::{DecryptSource, EncryptTarget};
//! use stack_encrypt::{assert_context, Encrypted, StackCipherText};
//! use zeroize::Zeroize;
//!
//! #[derive(Zeroize)]
//! struct User { email: String, notes: String }
//!
//! #[derive(EncryptTarget, DecryptSource)]
//! #[stash(struct = User, scope = "users")]
//! struct EncryptedUser {
//!     email: Encrypted<EqualityTerm>,
//!     notes: StackCipherText,
//! }
//!
//! assert_context!(
//!     EncryptedUser::contexts(),
//!     email = ["users", "email"],
//!     notes = ["users", "notes"],
//! );
//! ```
//!
//! A part the caller supplies is stated with [`required`], [`optional`], or
//! [`extension`]. A nested list is stated with a nested array:
//!
//! ```
//! # use stack_encrypt::plan::{Field, Fields};
//! # struct User { age: u32 }
//! # impl Fields for User { fn field_names(&self) -> Vec<&str> { vec!["age"] } }
//! # impl Field<u32> for User {
//! #     fn field(&self, name: &str) -> Option<&u32> { (name == "age").then_some(&self.age) }
//! # }
//! use stack_encrypt::kms::FakeDataKeySource;
//! use stack_encrypt::testing::extension;
//! use stack_encrypt::{assert_context, Ore, Plan};
//!
//! let plan: Plan<User, FakeDataKeySource> = Plan::context("users")
//!     .fields()
//!     .encrypt_index::<u32>("age", Ore)
//!     .build()?;
//! assert_context!(plan.contexts(), age = [["users", "age"], extension()]);
//! # Ok::<(), stack_encrypt::Error>(())
//! ```

use std::borrow::Cow;

use vitaminc_aead::ContextPiece;

use crate::contexts::{short_type_name, CallContexts, ContextTree, Contexts, Placeholder};

/// A required part of type `T` that the caller supplies: `{context: T}`.
pub fn required<T: ?Sized>() -> Placeholder {
    Placeholder::of::<T>()
}

/// An optional part of type `T` that the caller may supply:
/// `{context?: T}`.
pub fn optional<T: ?Sized>() -> Placeholder {
    Placeholder::optional("context", short_type_name::<T>())
}

/// The optional extension a plan accepts from the call that runs it:
/// `{extension?: CallerContext}`.
pub fn extension() -> Placeholder {
    Placeholder::optional("extension", "CallerContext")
}

/// A part of type `T` read from the field `name` of the plaintext:
/// `{name: T, from the plaintext}`.
pub fn from_plaintext<T: ?Sized>(name: &str) -> Placeholder {
    Placeholder::from_plaintext(name.to_owned(), short_type_name::<T>())
}

/// One part a test states, built from a literal, a placeholder, or a
/// nested array of parts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Expect(ContextTree);

impl Expect {
    /// The tree the parts state. One part is that part; several are a
    /// list of them.
    pub fn tree(parts: &[Expect]) -> ContextTree {
        match parts {
            [one] => one.0.clone(),
            many => ContextTree::List(many.iter().map(|part| part.0.clone()).collect()),
        }
    }
}

impl From<ContextTree> for Expect {
    fn from(tree: ContextTree) -> Self {
        Self(tree)
    }
}
impl From<Placeholder> for Expect {
    fn from(placeholder: Placeholder) -> Self {
        Self(ContextTree::Placeholder(placeholder))
    }
}
impl From<&str> for Expect {
    fn from(text: &str) -> Self {
        Self(ContextTree::Part(ContextPiece::Text(Cow::Owned(
            text.to_owned(),
        ))))
    }
}
impl From<String> for Expect {
    fn from(text: String) -> Self {
        Self(ContextTree::Part(ContextPiece::Text(Cow::Owned(text))))
    }
}
impl From<Vec<u8>> for Expect {
    fn from(bytes: Vec<u8>) -> Self {
        Self(ContextTree::Part(ContextPiece::Bytes(Cow::Owned(bytes))))
    }
}
impl From<()> for Expect {
    fn from((): ()) -> Self {
        Self(ContextTree::Part(ContextPiece::Unit))
    }
}
macro_rules! integer_expectations {
    ($($ty:ty => $variant:ident),* $(,)?) => {$(
        impl From<$ty> for Expect {
            fn from(value: $ty) -> Self {
                Self(ContextTree::Part(ContextPiece::$variant(value)))
            }
        }
    )*};
}
integer_expectations!(
    u8 => U8, u16 => U16, u32 => U32, u64 => U64, u128 => U128,
    i8 => I8, i16 => I16, i32 => I32, i64 => I64, i128 => I128,
);
impl<T: Into<Expect>, const N: usize> From<[T; N]> for Expect {
    fn from(parts: [T; N]) -> Self {
        let parts: Vec<Expect> = parts.into_iter().map(Into::into).collect();
        Self(Expect::tree(&parts))
    }
}

/// What `assert_context!` can check one context of: a declaration with one
/// unnamed context, a call, or a context itself.
pub trait ContextSubject {
    /// The one context, or why there is not exactly one.
    fn single_context(&self) -> Result<&ContextTree, String>;
}
impl ContextSubject for ContextTree {
    fn single_context(&self) -> Result<&ContextTree, String> {
        Ok(self)
    }
}
impl ContextSubject for Contexts {
    fn single_context(&self) -> Result<&ContextTree, String> {
        self.single().ok_or_else(|| match self.fields().len() {
            0 => "the declaration seals and indexes nothing, so it has no context".to_owned(),
            _ => format!(
                "the declaration names its fields; state each one as `name = [..]`:\n{self}"
            ),
        })
    }
}
impl ContextSubject for CallContexts {
    fn single_context(&self) -> Result<&ContextTree, String> {
        self.single().ok_or_else(|| match self.contexts().len() {
            0 => "the call seals and indexes nothing, so it has no context".to_owned(),
            _ => format!("the call uses several contexts:\n{self}"),
        })
    }
}

/// Check the one context of `subject` against `expected`.
///
/// # Errors
///
/// The message `assert_context!` panics with: why the subject has no single
/// context, or the first part that differs.
pub fn check_single(subject: &impl ContextSubject, expected: &[Expect]) -> Result<(), String> {
    let actual = subject.single_context()?;
    check_tree(actual, &Expect::tree(expected))
}

/// Check the context of the field `name` of `subject` against `expected`.
///
/// # Errors
///
/// The message `assert_context!` panics with: a field the declaration does
/// not name, or the first part that differs.
pub fn check_field(subject: &Contexts, name: &str, expected: &[Expect]) -> Result<(), String> {
    let actual = subject.get(name).ok_or_else(|| {
        let names: Vec<&str> = subject
            .fields()
            .iter()
            .filter_map(|field| field.name())
            .collect();
        format!("the declaration has no field `{name}`; its fields are {names:?}:\n{subject}")
    })?;
    check_tree(actual, &Expect::tree(expected))
        .map_err(|message| format!("field `{name}`: {message}"))
}

/// Compare two trees, naming the first part that differs.
fn check_tree(actual: &ContextTree, expected: &ContextTree) -> Result<(), String> {
    let mut path = Vec::new();
    match first_difference(actual, expected, &mut path) {
        None => Ok(()),
        Some((found, wanted)) => {
            let at = if path.is_empty() {
                "the whole context".to_owned()
            } else {
                format!(
                    "part {}",
                    path.iter()
                        .map(|index| (index + 1).to_string())
                        .collect::<Vec<_>>()
                        .join(".")
                )
            };
            Err(format!(
                "the context differs at {at}: expected `{wanted}`, found `{found}`\n  expected: {expected}\n  found:    {actual}"
            ))
        }
    }
}

/// The first leaf or list that differs, with the path of list indexes that
/// reaches it.
fn first_difference(
    actual: &ContextTree,
    expected: &ContextTree,
    path: &mut Vec<usize>,
) -> Option<(String, String)> {
    match (actual, expected) {
        (ContextTree::List(found), ContextTree::List(wanted)) => {
            for (index, (a, e)) in found.iter().zip(wanted).enumerate() {
                path.push(index);
                if let Some(difference) = first_difference(a, e, path) {
                    return Some(difference);
                }
                let _ = path.pop();
            }
            if found.len() != wanted.len() {
                let index = found.len().min(wanted.len());
                path.push(index);
                let found = found
                    .get(index)
                    .map_or("nothing".to_owned(), ToString::to_string);
                let wanted = wanted
                    .get(index)
                    .map_or("nothing".to_owned(), ToString::to_string);
                return Some((found, wanted));
            }
            None
        }
        (a, e) if a == e => None,
        (a, e) => Some((a.to_string(), e.to_string())),
    }
}

/// Pin the context of a declaration or a call.
///
/// Two forms:
///
/// - `assert_context!(subject, [parts..])` checks the one context of a
///   declaration of one value, a call, or a [`ContextTree`].
/// - `assert_context!(subject, field = [parts..], ..)` checks the named
///   fields of a declaration's [`Contexts`].
///
/// A part is a text literal, an integer with its type (`7u64`), a
/// [`Placeholder`] from [`required`], [`optional`], [`extension`], or
/// [`from_plaintext`], or a nested array of parts. The failure names the
/// first part that differs. See the [module docs](crate::testing).
///
/// A field is named by its identifier, or by a string for a name an
/// identifier cannot spell: a nested record's field, `"owner.email"`, or a
/// tuple field, `"0"`. The field form checks the fields the test states
/// and no others, so a new field does not fail an existing test. To pin
/// every field, compare `contexts().to_string()` with the whole text.
#[macro_export]
macro_rules! assert_context {
    ($subject:expr, [$($part:expr),* $(,)?] $(,)?) => {{
        let __expected: &[$crate::testing::Expect] = &[$($crate::testing::Expect::from($part)),*];
        if let ::core::result::Result::Err(__message) =
            $crate::testing::check_single(&$subject, __expected)
        {
            ::core::panic!("assert_context! failed: {}", __message);
        }
    }};
    ($subject:expr, $($field:ident = [$($part:expr),* $(,)?]),+ $(,)?) => {{
        let __subject = &$subject;
        $(
            let __expected: &[$crate::testing::Expect] = &[$($crate::testing::Expect::from($part)),*];
            if let ::core::result::Result::Err(__message) =
                $crate::testing::check_field(__subject, ::core::stringify!($field), __expected)
            {
                ::core::panic!("assert_context! failed: {}", __message);
            }
        )+
    }};
    ($subject:expr, $($field:literal = [$($part:expr),* $(,)?]),+ $(,)?) => {{
        let __subject = &$subject;
        $(
            let __expected: &[$crate::testing::Expect] = &[$($crate::testing::Expect::from($part)),*];
            if let ::core::result::Result::Err(__message) =
                $crate::testing::check_field(__subject, $field, __expected)
            {
                ::core::panic!("assert_context! failed: {}", __message);
            }
        )+
    }};
}

#[cfg(test)]
mod tests {
    use super::*;

    fn column() -> ContextTree {
        ContextTree::List(vec![Expect::from("users").0, Expect::from("email").0])
    }

    #[test]
    fn a_matching_context_passes() {
        check_single(&column(), &[Expect::from("users"), Expect::from("email")]).unwrap();
    }

    #[test]
    fn the_first_differing_part_is_named() {
        let message =
            check_single(&column(), &[Expect::from("users"), Expect::from("name")]).unwrap_err();
        assert!(
            message.starts_with("the context differs at part 2: expected `name`, found `email`"),
            "{message}"
        );
    }

    #[test]
    fn a_missing_part_is_named_as_nothing() {
        let message = check_single(&column(), &[Expect::from("users")]).unwrap_err();
        assert!(
            message.contains("expected `users`, found `users / email`"),
            "{message}"
        );
        let message = check_single(
            &column(),
            &[
                Expect::from("users"),
                Expect::from("email"),
                Expect::from(7u64),
            ],
        )
        .unwrap_err();
        assert!(
            message.contains("part 3: expected `7u64`, found `nothing`"),
            "{message}"
        );
    }

    #[test]
    fn a_nested_array_states_a_nested_list() {
        let tree = ContextTree::List(vec![column(), Expect::from(extension()).0]);
        check_single(
            &tree,
            &[Expect::from(["users", "email"]), Expect::from(extension())],
        )
        .unwrap();
        let message = check_single(
            &tree,
            &[Expect::from(["users", "email"]), Expect::from(7u64)],
        )
        .unwrap_err();
        assert!(
            message.contains("part 2: expected `7u64`, found `{extension?: CallerContext}`"),
            "{message}"
        );
    }

    #[test]
    fn every_literal_becomes_the_part_it_names() {
        use vitaminc_aead::IntoContext;
        fn part<'a>(value: impl IntoContext<'a>) -> ContextTree {
            ContextTree::from_piece(&value.into_context())
        }
        assert_eq!(Expect::from("users").0, part("users"));
        assert_eq!(Expect::from(String::from("users")).0, part("users"));
        assert_eq!(Expect::from(vec![7u8]).0, part(vec![7u8]));
        assert_eq!(Expect::from(()).0, part(()));
        assert_eq!(Expect::from(1u8).0, part(1u8));
        assert_eq!(Expect::from(2u16).0, part(2u16));
        assert_eq!(Expect::from(3u32).0, part(3u32));
        assert_eq!(Expect::from(4u64).0, part(4u64));
        assert_eq!(Expect::from(5u128).0, part(5u128));
        assert_eq!(Expect::from(-1i8).0, part(-1i8));
        assert_eq!(Expect::from(-2i16).0, part(-2i16));
        assert_eq!(Expect::from(-3i32).0, part(-3i32));
        assert_eq!(Expect::from(-4i64).0, part(-4i64));
        assert_eq!(Expect::from(-5i128).0, part(-5i128));
        assert_eq!(Expect::from(column()).0, column());
        // One part in an array is that part; several are a list.
        assert_eq!(Expect::from(["users"]).0, part("users"));
        assert_eq!(Expect::from(["users", "email"]).0, column());
    }

    #[test]
    fn the_placeholder_helpers_name_their_parts() {
        assert_eq!(required::<u64>(), Placeholder::of::<u64>());
        assert_eq!(optional::<u64>(), Placeholder::optional("context", "u64"));
        assert_eq!(
            extension(),
            Placeholder::optional("extension", "CallerContext")
        );
        assert_eq!(
            from_plaintext::<u64>("tenant"),
            Placeholder::from_plaintext("tenant", "u64")
        );
    }

    #[test]
    fn a_subject_without_one_context_says_why() {
        let none = CallContexts::from_pieces(&[], false);
        let message = check_single(&none, &[Expect::from("users")]).unwrap_err();
        // Exactly this: the call's own `Display` says "the call seals and
        // indexes nothing" too, so a looser check would pass with the
        // several-contexts message.
        assert_eq!(
            message,
            "the call seals and indexes nothing, so it has no context"
        );
        let several = CallContexts::from_pieces(
            &[Expect::from("a").0.piece(), Expect::from("b").0.piece()],
            false,
        );
        let message = check_single(&several, &[Expect::from("a")]).unwrap_err();
        assert!(
            message.starts_with("the call uses several contexts:"),
            "{message}"
        );

        let empty = crate::contexts::resolve(Vec::new(), None);
        let message = check_single(&empty, &[Expect::from("users")]).unwrap_err();
        assert!(
            message.contains("the declaration seals and indexes nothing"),
            "{message}"
        );
        let named = crate::contexts::resolve(
            crate::contexts::name(crate::contexts::caller_leaf(), "email"),
            None,
        );
        let message = check_single(&named, &[Expect::from("users")]).unwrap_err();
        assert!(
            message.starts_with("the declaration names its fields"),
            "{message}"
        );
        let message = check_field(&named, "name", &[Expect::from("users")]).unwrap_err();
        assert!(
            message.starts_with("the declaration has no field `name`; its fields are [\"email\"]"),
            "{message}"
        );
        let message = check_field(&named, "email", &[Expect::from("users")]).unwrap_err();
        assert!(
            message.starts_with("field `email`: the context differs at the whole context"),
            "{message}"
        );
    }

    #[test]
    fn a_typed_integer_differs_from_another_width() {
        let tree = Expect::from(7u64).0;
        check_single(&tree, &[Expect::from(7u64)]).unwrap();
        let message = check_single(&tree, &[Expect::from(7i64)]).unwrap_err();
        assert!(
            message.contains("expected `7i64`, found `7u64`"),
            "{message}"
        );
    }
}
