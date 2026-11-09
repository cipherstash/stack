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
//! A call that uses several contexts is pinned with
//! [`assert_contexts!`](crate::assert_contexts), one array per context, in
//! the order the call's leaves run.
//!
//! A part the caller supplies is stated with [`scope`], [`bind`],
//! [`required`], [`optional`], or [`caller_scope`]. A part read from the
//! plaintext is stated with [`stored_scope`] or [`stored_bind`]. A nested
//! list is stated with a nested array. A field with a binding has a query
//! context and a stored context, and the test states both:
//!
//! ```
//! use stack_encrypt::sem::EqualityTerm;
//! use stack_encrypt::target::{DecryptSource, EncryptTarget};
//! use stack_encrypt::testing::{bind, scope, Expect};
//! use stack_encrypt::{assert_context, Encrypted};
//! use zeroize::Zeroize;
//!
//! #[derive(Zeroize)]
//! struct User { email: String }
//!
//! #[derive(EncryptTarget, DecryptSource)]
//! #[stash(struct = User, scope = "users", scope(tenant: u64), bind(row: u128))]
//! struct EncryptedUser {
//!     email: Encrypted<EqualityTerm>,
//! }
//!
//! assert_context!(
//!     EncryptedUser::contexts(),
//!     email = {
//!         query = [["users", "email"], scope::<u64>("tenant")],
//!         stored = [
//!             [Expect::from(["users", "email"]), Expect::from(scope::<u64>("tenant"))],
//!             bind::<u128>("row"),
//!         ],
//!     },
//! );
//! ```

use std::borrow::Cow;

use vitaminc_aead::ContextPiece;

use crate::contexts::{
    short_type_name, CallContexts, ContextTree, Contexts, LeafContext, Placeholder,
};

/// A scope of type `T` that the caller supplies, named `name`: what a
/// record's `scope(name: T)` lists. `{name: T}`.
pub fn scope<T: ?Sized>(name: &str) -> Placeholder {
    Placeholder::scope::<T>().renamed(name.to_owned())
}

/// A binding of type `T` that the caller supplies, named `name`: what a
/// record's `bind(name: T)` lists. `{name: T}`.
pub fn bind<T: ?Sized>(name: &str) -> Placeholder {
    Placeholder::bind::<T>().renamed(name.to_owned())
}

/// A scope of type `T` read from the field `name` of the plaintext: what a
/// record's `scope(field = "name")` lists. `{name: T, from the plaintext}`.
pub fn stored_scope<T: ?Sized>(name: &str) -> Placeholder {
    Placeholder::from_plaintext(name.to_owned(), short_type_name::<T>())
}

/// A binding of type `T` read from the field `name` of the plaintext: what
/// a record's `bind(field = "name")` lists. `{name: T, from the plaintext}`.
pub fn stored_bind<T: ?Sized>(name: &str) -> Placeholder {
    stored_scope::<T>(name).as_bind()
}

/// A required context of type `T` that the caller supplies, for a target
/// that takes a whole context: `{context: T}`.
pub fn required<T: ?Sized>() -> Placeholder {
    Placeholder::of::<T>()
}

/// An optional context of type `T` that the caller may supply:
/// `{context?: T}`.
pub fn optional<T: ?Sized>() -> Placeholder {
    Placeholder::optional("context", short_type_name::<T>())
}

/// The optional scope a plan accepts from the call that runs it:
/// `{scope?: CallerContext}`.
pub fn caller_scope() -> Placeholder {
    Placeholder::optional("scope", "CallerContext")
}

/// A part of type `T` read from the field `name` of the plaintext:
/// `{name: T, from the plaintext}`. The same as [`stored_scope`].
pub fn from_plaintext<T: ?Sized>(name: &str) -> Placeholder {
    stored_scope::<T>(name)
}

/// One part a test states, built from a literal, a placeholder, or a
/// nested array of parts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Expect(ContextTree);

impl Expect {
    /// The tree the parts state. One part is that part; several are a
    /// list of them. So `["users"]` states the bare part `users`, as
    /// `nonempty!("users")` renders. A list of one part, as a one-segment
    /// label renders (`(email)`), is stated with [`list`].
    pub fn tree(parts: &[Expect]) -> ContextTree {
        match parts {
            [one] => one.0.clone(),
            many => ContextTree::List(many.iter().map(|part| part.0.clone()).collect()),
        }
    }
}

/// A list of exactly these parts, however many: `list(["email"])` states
/// the one-part list a one-segment label renders as, `(email)`, which an
/// array literal of one part would state as the bare part `email`.
///
/// ```
/// use stack_encrypt::testing::list;
/// use stack_encrypt::{assert_context, ContextTree, IntoContext as _};
///
/// // A list of one part, as a data plan's one-segment label is.
/// let one_part = ContextTree::List(vec![ContextTree::from_piece(&"email".into_context())]);
/// assert_eq!(one_part.to_string(), "(email)");
/// assert_context!(one_part, [list(["email"])]);
///
/// // Inside a longer context, the same list is one part of it.
/// let part = ContextTree::from_piece(&42u64.into_context());
/// let extended = ContextTree::List(vec![one_part, part]);
/// assert_context!(extended, [list(["email"]), 42u64]);
/// ```
pub fn list<T: Into<Expect>, const N: usize>(parts: [T; N]) -> Expect {
    Expect(ContextTree::List(
        parts.into_iter().map(|part| part.into().0).collect(),
    ))
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
    fn single_context(&self) -> Result<LeafContext, String>;
}
impl ContextSubject for ContextTree {
    fn single_context(&self) -> Result<LeafContext, String> {
        Ok(LeafContext::one(self.clone()))
    }
}
impl ContextSubject for LeafContext {
    fn single_context(&self) -> Result<LeafContext, String> {
        Ok(self.clone())
    }
}
impl ContextSubject for Contexts {
    fn single_context(&self) -> Result<LeafContext, String> {
        self.single()
            .cloned()
            .ok_or_else(|| match self.fields().len() {
                0 => "the declaration seals and indexes nothing, so it has no context".to_owned(),
                _ => format!(
                    "the declaration names its fields; state each one as `name = [..]`:\n{self}"
                ),
            })
    }
}
impl ContextSubject for CallContexts {
    fn single_context(&self) -> Result<LeafContext, String> {
        if self.has_failed() {
            return Err("the call has failed; await it for the error".to_owned());
        }
        self.single()
            .cloned()
            .ok_or_else(|| match self.contexts().len() {
                0 => "the call seals and indexes nothing, so it has no context".to_owned(),
                _ => format!("the call uses several contexts:\n{self}"),
            })
    }
}

/// What a test states about one field or call: one context, or a query
/// context and a stored context.
pub enum Stated<'a> {
    /// One context: the query context and the stored context are the
    /// same.
    One(&'a [Expect]),
    /// A query context and a stored context.
    Both {
        /// The scopes.
        query: &'a [Expect],
        /// The scopes, then the bindings.
        stored: &'a [Expect],
    },
}

/// Check the one context of `subject` against `stated`.
///
/// # Errors
///
/// The message `assert_context!` panics with: why the subject has no single
/// context, or the first part that differs.
pub fn check_single(subject: &impl ContextSubject, stated: Stated<'_>) -> Result<(), String> {
    let actual = subject.single_context()?;
    check_leaf(&actual, stated)
}

/// Check the context of the field `name` of `subject` against `stated`.
///
/// # Errors
///
/// The message `assert_context!` panics with: a field the declaration does
/// not name, or the first part that differs.
pub fn check_field(subject: &Contexts, name: &str, stated: Stated<'_>) -> Result<(), String> {
    let actual = subject.get(name).ok_or_else(|| {
        let names: Vec<&str> = subject
            .fields()
            .iter()
            .filter_map(|field| field.name())
            .collect();
        format!("the declaration has no field `{name}`; its fields are {names:?}:\n{subject}")
    })?;
    check_leaf(actual, stated).map_err(|message| format!("field `{name}`: {message}"))
}

fn check_leaf(actual: &LeafContext, stated: Stated<'_>) -> Result<(), String> {
    match stated {
        Stated::One(parts) => {
            if actual.has_binding() {
                return Err(format!(
                    "the context has a binding, so state it as `{{ query = [..], stored = [..] }}`:\n{actual}"
                ));
            }
            check_tree(actual.query(), &Expect::tree(parts))
        }
        Stated::Both { query, stored } => {
            check_tree(actual.query(), &Expect::tree(query))
                .map_err(|message| format!("query context: {message}"))?;
            check_tree(actual.stored(), &Expect::tree(stored))
                .map_err(|message| format!("stored context: {message}"))
        }
    }
}

/// Check the context at `index` of the call `subject` against `stated`:
/// what `assert_contexts!` asks for each context it states, in order.
///
/// # Errors
///
/// The message `assert_contexts!` panics with: more contexts stated than
/// the call uses, or the part of this context that differs.
pub fn check_nth(subject: &CallContexts, index: usize, stated: Stated<'_>) -> Result<(), String> {
    let contexts = subject.contexts();
    let Some(actual) = contexts.get(index) else {
        return Err(format!(
            "the call uses {} contexts, and context {} was stated:\n{subject}",
            contexts.len(),
            index + 1
        ));
    };
    check_leaf(actual, stated).map_err(|message| format!("context {}: {message}", index + 1))
}

/// Check that the call `subject` uses exactly `stated` contexts: what
/// `assert_contexts!` asks once every context it states has been checked.
///
/// # Errors
///
/// The message `assert_contexts!` panics with when the call uses more
/// contexts than were stated.
pub fn check_count(subject: &CallContexts, stated: usize) -> Result<(), String> {
    let used = subject.contexts().len();
    if used != stated {
        return Err(format!(
            "the call uses {used} contexts, and {stated} were stated:\n{subject}"
        ));
    }
    Ok(())
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
/// The forms:
///
/// - `assert_context!(subject, [parts..])` checks the one context of a
///   declaration of one value, a call, or a [`ContextTree`]. The subject
///   must have no binding.
/// - `assert_context!(subject, query = [parts..], stored = [parts..])`
///   checks both contexts of such a subject.
/// - `assert_context!(subject, field = [parts..], ..)` checks the named
///   fields of a declaration's [`Contexts`]. A field with a binding is
///   stated as `field = { query = [..], stored = [..] }`.
///
/// A part is a text literal, an integer with its type (`7u64`), a
/// [`Placeholder`] from [`scope`], [`bind`], [`stored_scope`],
/// [`stored_bind`], [`required`], [`optional`], or [`caller_scope`], or a
/// nested array of parts. The failure names the first part that differs.
/// See the [module docs](crate::testing).
///
/// A field is named by its identifier, or by a string for a name an
/// identifier cannot spell: a nested record's field, `"owner.email"`, or a
/// tuple field, `"0"`. The field form checks the fields the test states
/// and no others, so a new field does not fail an existing test. To pin
/// every field, compare `contexts().to_string()` with the whole text.
#[macro_export]
macro_rules! assert_context {
    ($subject:expr, [$($part:expr),* $(,)?] $(,)?) => {{
        let __stated: &[$crate::testing::Expect] = &[$($crate::testing::Expect::from($part)),*];
        if let ::core::result::Result::Err(__message) =
            $crate::testing::check_single(&$subject, $crate::testing::Stated::One(__stated))
        {
            ::core::panic!("assert_context! failed: {}", __message);
        }
    }};
    ($subject:expr, query = [$($query:expr),* $(,)?], stored = [$($stored:expr),* $(,)?] $(,)?) => {{
        let __query: &[$crate::testing::Expect] = &[$($crate::testing::Expect::from($query)),*];
        let __stored: &[$crate::testing::Expect] = &[$($crate::testing::Expect::from($stored)),*];
        if let ::core::result::Result::Err(__message) = $crate::testing::check_single(
            &$subject,
            $crate::testing::Stated::Both { query: __query, stored: __stored },
        ) {
            ::core::panic!("assert_context! failed: {}", __message);
        }
    }};
    ($subject:expr, $($fields:tt)+) => {{
        let __subject = &$subject;
        $crate::__assert_context_fields!(__subject; $($fields)+);
    }};
}

/// Pin each context a call uses, in order.
///
/// `assert_contexts!(call.context(), [[parts..], [parts..], ..])` states
/// one context per array, in the order the call's leaves run: the order
/// [`CallContexts::contexts`] lists them. A context of one part is stated
/// as that part. A context with a binding is stated as
/// `{ query = [parts..], stored = [parts..] }`, as a field of
/// [`assert_context!`] is. The failure names the first context that
/// differs and the part in it, or the count of contexts when it is not the
/// one stated.
///
/// ```
/// # tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
/// use stack_encrypt::kms::FakeDataKeySource;
/// use stack_encrypt::sem::EqualityTerm;
/// use stack_encrypt::target::{DecryptSource, EncryptTarget};
/// use stack_encrypt::{assert_contexts, EncryptInto, Encrypted, StackCipher, StackCipherText};
/// use zeroize::Zeroize;
///
/// #[derive(Zeroize)]
/// struct User { email: String, notes: String }
///
/// #[derive(EncryptTarget, DecryptSource)]
/// #[stash(struct = User, scope = "users")]
/// struct EncryptedUser {
///     email: Encrypted<EqualityTerm>,
///     notes: StackCipherText,
/// }
///
/// let cipher = StackCipher::builder().kms(FakeDataKeySource::new()).init().await?;
/// let keyset = cipher.default_keyset();
/// let user = User { email: "ada@example.com".into(), notes: "none".into() };
/// let call = user.encrypt_into::<EncryptedUser, _>(&keyset);
/// assert_contexts!(call.context(), [["users", "email"], ["users", "notes"]]);
/// let _stored = call.await?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// # }).unwrap();
/// ```
#[macro_export]
macro_rules! assert_contexts {
    ($subject:expr, [$($contexts:tt)*] $(,)?) => {{
        let __subject = &$subject;
        #[allow(unused_mut)]
        let mut __index: usize = 0;
        $crate::__assert_contexts_each!(__subject, __index; $($contexts)*);
        if let ::core::result::Result::Err(__message) =
            $crate::testing::check_count(__subject, __index)
        {
            ::core::panic!("assert_contexts! failed: {}", __message);
        }
    }};
}

/// The context forms of [`assert_contexts!`]. Not for direct use.
#[doc(hidden)]
#[macro_export]
macro_rules! __assert_contexts_each {
    ($subject:ident, $index:ident;) => {};
    ($subject:ident, $index:ident; { query = [$($query:expr),* $(,)?], stored = [$($stored:expr),* $(,)?] $(,)? } $(, $($rest:tt)*)?) => {
        let __query: &[$crate::testing::Expect] = &[$($crate::testing::Expect::from($query)),*];
        let __stored: &[$crate::testing::Expect] = &[$($crate::testing::Expect::from($stored)),*];
        if let ::core::result::Result::Err(__message) = $crate::testing::check_nth(
            $subject,
            $index,
            $crate::testing::Stated::Both { query: __query, stored: __stored },
        ) {
            ::core::panic!("assert_contexts! failed: {}", __message);
        }
        $index += 1;
        $crate::__assert_contexts_each!($subject, $index; $($($rest)*)?);
    };
    ($subject:ident, $index:ident; [$($part:expr),* $(,)?] $(, $($rest:tt)*)?) => {
        let __stated: &[$crate::testing::Expect] = &[$($crate::testing::Expect::from($part)),*];
        if let ::core::result::Result::Err(__message) = $crate::testing::check_nth(
            $subject,
            $index,
            $crate::testing::Stated::One(__stated),
        ) {
            ::core::panic!("assert_contexts! failed: {}", __message);
        }
        $index += 1;
        $crate::__assert_contexts_each!($subject, $index; $($($rest)*)?);
    };
    ($subject:ident, $index:ident; $part:expr $(, $($rest:tt)*)?) => {
        let __stated: &[$crate::testing::Expect] = &[$crate::testing::Expect::from($part)];
        if let ::core::result::Result::Err(__message) = $crate::testing::check_nth(
            $subject,
            $index,
            $crate::testing::Stated::One(__stated),
        ) {
            ::core::panic!("assert_contexts! failed: {}", __message);
        }
        $index += 1;
        $crate::__assert_contexts_each!($subject, $index; $($($rest)*)?);
    };
}

/// The field forms of [`assert_context!`]. Not for direct use.
#[doc(hidden)]
#[macro_export]
macro_rules! __assert_context_fields {
    ($subject:ident;) => {};
    ($subject:ident; $field:ident = { query = [$($query:expr),* $(,)?], stored = [$($stored:expr),* $(,)?] $(,)? } $(, $($rest:tt)*)?) => {
        $crate::__assert_context_fields!($subject; ::core::stringify!($field) => { query = [$($query),*], stored = [$($stored),*] } $(, $($rest)*)?);
    };
    ($subject:ident; $field:ident = [$($part:expr),* $(,)?] $(, $($rest:tt)*)?) => {
        $crate::__assert_context_fields!($subject; ::core::stringify!($field) => [$($part),*] $(, $($rest)*)?);
    };
    ($subject:ident; $field:literal = { query = [$($query:expr),* $(,)?], stored = [$($stored:expr),* $(,)?] $(,)? } $(, $($rest:tt)*)?) => {
        $crate::__assert_context_fields!($subject; $field => { query = [$($query),*], stored = [$($stored),*] } $(, $($rest)*)?);
    };
    ($subject:ident; $field:literal = [$($part:expr),* $(,)?] $(, $($rest:tt)*)?) => {
        $crate::__assert_context_fields!($subject; $field => [$($part),*] $(, $($rest)*)?);
    };
    ($subject:ident; $field:expr => { query = [$($query:expr),* $(,)?], stored = [$($stored:expr),* $(,)?] $(,)? } $(, $($rest:tt)*)?) => {
        let __query: &[$crate::testing::Expect] = &[$($crate::testing::Expect::from($query)),*];
        let __stored: &[$crate::testing::Expect] = &[$($crate::testing::Expect::from($stored)),*];
        if let ::core::result::Result::Err(__message) = $crate::testing::check_field(
            $subject,
            $field,
            $crate::testing::Stated::Both { query: __query, stored: __stored },
        ) {
            ::core::panic!("assert_context! failed: {}", __message);
        }
        $crate::__assert_context_fields!($subject; $($($rest)*)?);
    };
    ($subject:ident; $field:expr => [$($part:expr),* $(,)?] $(, $($rest:tt)*)?) => {
        let __stated: &[$crate::testing::Expect] = &[$($crate::testing::Expect::from($part)),*];
        if let ::core::result::Result::Err(__message) = $crate::testing::check_field(
            $subject,
            $field,
            $crate::testing::Stated::One(__stated),
        ) {
            ::core::panic!("assert_context! failed: {}", __message);
        }
        $crate::__assert_context_fields!($subject; $($($rest)*)?);
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    fn column() -> ContextTree {
        ContextTree::List(vec![Expect::from("users").0, Expect::from("email").0])
    }

    fn one(parts: &[Expect]) -> Stated<'_> {
        Stated::One(parts)
    }

    /// [`one`], where a local `one` is a tree.
    fn one_stated(parts: &[Expect]) -> Stated<'_> {
        Stated::One(parts)
    }

    #[test]
    fn a_matching_context_passes() {
        check_single(
            &column(),
            one(&[Expect::from("users"), Expect::from("email")]),
        )
        .unwrap();
    }

    /// A one-segment label is a list of one part, `(email)`. An array of
    /// one part states the bare part, so the list is stated with `list`.
    #[test]
    fn a_one_part_list_is_stated_with_list() {
        let one = ContextTree::List(vec![Expect::from("email").0]);
        check_single(&one, one_stated(&[list(["email"])])).unwrap();
        let message = check_single(&one, one_stated(&[Expect::from("email")])).unwrap_err();
        assert!(
            message.contains("expected `email`, found `(email)`"),
            "{message}"
        );
        let nested = ContextTree::List(vec![one.clone(), Expect::from(42u64).0]);
        check_single(&nested, one_stated(&[list(["email"]), Expect::from(42u64)])).unwrap();
        let bare = Expect::from("users").0;
        check_single(&bare, one_stated(&[Expect::from("users")])).unwrap();
        assert!(check_single(&bare, one_stated(&[list(["users"])])).is_err());
    }

    #[test]
    fn the_first_differing_part_is_named() {
        let message = check_single(
            &column(),
            one(&[Expect::from("users"), Expect::from("name")]),
        )
        .unwrap_err();
        assert!(
            message.starts_with("the context differs at part 2: expected `name`, found `email`"),
            "{message}"
        );
    }

    #[test]
    fn a_missing_part_is_named_as_nothing() {
        let message = check_single(&column(), one(&[Expect::from("users")])).unwrap_err();
        assert!(
            message.contains("expected `users`, found `users / email`"),
            "{message}"
        );
        let message = check_single(
            &column(),
            one(&[
                Expect::from("users"),
                Expect::from("email"),
                Expect::from(7u64),
            ]),
        )
        .unwrap_err();
        assert!(
            message.contains("part 3: expected `7u64`, found `nothing`"),
            "{message}"
        );
    }

    #[test]
    fn a_nested_array_states_a_nested_list() {
        let tree = ContextTree::List(vec![column(), Expect::from(caller_scope()).0]);
        check_single(
            &tree,
            one(&[
                Expect::from(["users", "email"]),
                Expect::from(caller_scope()),
            ]),
        )
        .unwrap();
        let message = check_single(
            &tree,
            one(&[Expect::from(["users", "email"]), Expect::from(7u64)]),
        )
        .unwrap_err();
        assert!(
            message.contains("part 2: expected `7u64`, found `{scope?: CallerContext}`"),
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
        assert_eq!(Expect::from(["users"]).0, part("users"));
        assert_eq!(Expect::from(["users", "email"]).0, column());
    }

    #[test]
    fn the_placeholder_helpers_name_their_parts() {
        assert_eq!(required::<u64>(), Placeholder::of::<u64>());
        assert_eq!(optional::<u64>(), Placeholder::optional("context", "u64"));
        assert_eq!(
            caller_scope(),
            Placeholder::optional("scope", "CallerContext")
        );
        assert_eq!(scope::<u64>("tenant").to_string(), "{tenant: u64}");
        assert_eq!(bind::<u128>("row").to_string(), "{row: u128}");
        assert_eq!(bind::<u128>("row").kind(), crate::contexts::Kind::Bind);
        assert_eq!(
            stored_scope::<u64>("tenant"),
            Placeholder::from_plaintext("tenant", "u64")
        );
        assert_eq!(
            stored_bind::<u128>("id").kind(),
            crate::contexts::Kind::Bind
        );
        assert_eq!(
            stored_bind::<u128>("id").to_string(),
            "{id: u128, from the plaintext}"
        );
        assert_eq!(
            from_plaintext::<u64>("tenant"),
            stored_scope::<u64>("tenant")
        );
    }

    #[test]
    fn a_subject_without_one_context_says_why() {
        let none = CallContexts::from_pieces(&[], false);
        let message = check_single(&none, one(&[Expect::from("users")])).unwrap_err();
        assert!(
            message.contains("the call seals and indexes nothing"),
            "{message}"
        );
        let failed = CallContexts::from_pieces(&[], true);
        let message = check_single(&failed, one(&[Expect::from("users")])).unwrap_err();
        assert!(message.contains("the call has failed"), "{message}");
        let a = Expect::from("a").0.piece();
        let b = Expect::from("b").0.piece();
        let several = CallContexts::from_pieces(&[(a.clone(), a), (b.clone(), b)], false);
        let message = check_single(&several, one(&[Expect::from("a")])).unwrap_err();
        assert!(
            message.starts_with("the call uses several contexts:"),
            "{message}"
        );

        let empty = crate::contexts::resolve(Vec::new(), crate::contexts::CallerShape::none());
        let message = check_single(&empty, one(&[Expect::from("users")])).unwrap_err();
        assert!(
            message.contains("the declaration seals and indexes nothing"),
            "{message}"
        );
        let named = crate::contexts::resolve(
            crate::contexts::name(crate::contexts::caller_leaf(), "email"),
            crate::contexts::CallerShape::none(),
        );
        let message = check_single(&named, one(&[Expect::from("users")])).unwrap_err();
        assert!(
            message.starts_with("the declaration names its fields"),
            "{message}"
        );
        let message = check_field(&named, "name", one(&[Expect::from("users")])).unwrap_err();
        assert!(
            message.starts_with("the declaration has no field `name`; its fields are [\"email\"]"),
            "{message}"
        );
        let message = check_field(&named, "email", one(&[Expect::from("users")])).unwrap_err();
        assert!(
            message.starts_with("field `email`: the context differs at the whole context"),
            "{message}"
        );
    }

    #[test]
    fn each_context_of_a_call_is_checked_in_order() {
        let column = ContextPiece::List(vec![
            Expect::from("users").0.piece(),
            Expect::from("email").0.piece(),
        ]);
        let bound = ContextPiece::List(vec![column.clone(), Expect::from(7u128).0.piece()]);
        let call = CallContexts::from_pieces(
            &[
                (column.clone(), bound),
                (
                    Expect::from("acme").0.piece(),
                    Expect::from("acme").0.piece(),
                ),
            ],
            false,
        );
        check_nth(
            &call,
            0,
            Stated::Both {
                query: &[Expect::from("users"), Expect::from("email")],
                stored: &[Expect::from(["users", "email"]), Expect::from(7u128)],
            },
        )
        .unwrap();
        check_nth(&call, 1, one(&[Expect::from("acme")])).unwrap();
        check_count(&call, 2).unwrap();

        let message = check_nth(
            &call,
            0,
            one(&[Expect::from("users"), Expect::from("email")]),
        )
        .unwrap_err();
        assert!(
            message.starts_with("context 1: the context has a binding"),
            "{message}"
        );
        let message = check_nth(&call, 1, one(&[Expect::from("globex")])).unwrap_err();
        assert!(
            message.starts_with(
                "context 2: the context differs at the whole context: expected `globex`, found `acme`"
            ),
            "{message}"
        );
        let message = check_nth(&call, 2, one(&[Expect::from(7u64)])).unwrap_err();
        assert!(
            message.starts_with("the call uses 2 contexts, and context 3 was stated:"),
            "{message}"
        );
        let message = check_count(&call, 1).unwrap_err();
        assert!(
            message.starts_with("the call uses 2 contexts, and 1 were stated:"),
            "{message}"
        );
    }

    #[test]
    fn a_binding_needs_both_contexts_stated() {
        let own = crate::nonempty!("users").with("email");
        let with_binding = crate::contexts::resolve(
            crate::contexts::substitute(
                crate::contexts::caller_leaf(),
                &crate::contexts::Shape::under(crate::contexts::piece_of(own).into_inner()),
            ),
            crate::contexts::CallerShape::bind(Placeholder::bind::<u128>()),
        );
        let leaf = with_binding.single().unwrap();
        let message = check_single(leaf, one(&[Expect::from("users")])).unwrap_err();
        assert!(
            message.starts_with("the context has a binding"),
            "{message}"
        );
        check_single(
            leaf,
            Stated::Both {
                query: &[Expect::from("users"), Expect::from("email")],
                stored: &[
                    Expect::from(["users", "email"]),
                    Expect::from(bind::<u128>("bind")),
                ],
            },
        )
        .unwrap();
        let message = check_single(
            leaf,
            Stated::Both {
                query: &[Expect::from("users"), Expect::from("email")],
                stored: &[Expect::from(["users", "email"]), Expect::from(7u64)],
            },
        )
        .unwrap_err();
        assert!(
            message.starts_with("stored context: the context differs at part 2"),
            "{message}"
        );
        let unbound = LeafContext::one(column());
        check_single(
            &unbound,
            one(&[Expect::from("users"), Expect::from("email")]),
        )
        .unwrap();
    }

    #[test]
    fn a_typed_integer_differs_from_another_width() {
        let tree = Expect::from(7u64).0;
        check_single(&tree, one(&[Expect::from(7u64)])).unwrap();
        let message = check_single(&tree, one(&[Expect::from(7i64)])).unwrap_err();
        assert!(
            message.contains("expected `7i64`, found `7u64`"),
            "{message}"
        );
    }
}
