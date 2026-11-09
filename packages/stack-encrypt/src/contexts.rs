//! The contexts a declaration or a call uses, shown before any key is
//! requested.
//!
//! Every value is sealed under a context, and every search term is derived
//! under one. A wrong context loses data silently: a query under the wrong
//! context matches nothing, and gives no error. So a developer must be able
//! to see the context a declaration will use, and a test must be able to
//! state it.
//!
//! Every part of a context is a scope or a binding. The **query context** is
//! the scopes, and the search terms derive under it. The **stored context**
//! is the query context followed by the bindings, and the key and the AAD
//! derive under it. A field with no binding has one context. See
//! [`CallerContext`].
//!
//! Two views exist:
//!
//! - [`Contexts`], from [`Encryption::contexts`](crate::target::Encryption::contexts).
//!   It lists the contexts of each field of a declaration. A part the caller
//!   supplies when the declaration runs appears as a typed
//!   [`Placeholder`]. The derives emit `contexts()` on every record, and a
//!   [`Plan`](crate::Plan) has it too.
//! - [`CallContexts`], from [`Pending::context`](crate::Pending::context).
//!   It lists the exact contexts a prepared call will use, with the caller's
//!   values filled in. No key has been requested yet.
//!
//! The declaration view is built beside the engine's closures, by the same
//! combinator calls: each combinator that changes a subtree's context
//! records the change, and substitutes a placeholder where the engine
//! substitutes the caller's context. The call view reads the contexts the
//! leaves validated. So neither view is written by hand, and each changes
//! only where the context does.
//!
//! The view shows each part with its type: `7u64`, `7i64`, the text `7`,
//! and the bytes `0x37` are four different contexts. The
//! [`Descriptor`] that ZeroKMS logs is coarser, and is
//! not changed by this module.
//!
//! The `testing` feature adds `assert_context!`,
//! which compares a view against the parts a test states and names the
//! first part that differs.
//!
//! # Rendering
//!
//! A context is a tree of parts. The rendering follows the structure of the
//! tree, as the descriptor does, with ` / ` between the parts of a list. At
//! the root, a list of two or more parts has no brackets. Any other list is
//! bracketed. So a column extended by a tenant renders as
//! `(users / email) / 7u64`.
//!
//! | Part | Rendering |
//! |---|---|
//! | plain text | as it is: `users` |
//! | other text | quoted and escaped: `"a/b"` |
//! | bytes | hex: `0x37` |
//! | an integer | its value and its type: `7u64`, `-3i32` |
//! | the unit context | `()` |
//! | a pre-encoded context | `encoded:0x…` |
//! | a scope the caller supplies | `{scope: u64}`, or `{tenant: u64}` when the declaration names it; `{scope?: u64}` when optional |
//! | a binding the caller supplies | `{bind: u128}`, or `{row: u128}` when the declaration names it |
//! | a part read from the plaintext | `{tenant: u64, from the plaintext}` |
//!
//! Plain text is text the descriptor renders as it is: no `/`, no brackets,
//! no control characters, and not starting with a digit, a `-`, or `b64:`.
//! Text that would read as another form, starting with `{` or `encoded:`,
//! is quoted too. Quoting escapes `"` and `\` with a backslash, and any
//! other control or non-printing character as `\u{..}`.
//!
//! A field whose query context and stored context are the same shows one
//! `context:` line. A field with a binding shows a `query context:` line
//! and a `stored context:` line.
//!
//! # What a placeholder stands for
//!
//! A placeholder is one node of the tree, but the part it stands for is
//! not always one part:
//!
//! - A placeholder of type `Label` stands for the label's segments, which
//!   splice into the list around it. `{tenant: Label, from the plaintext} / text`
//!   with the label `tenants/acme` is the flat list `tenants / acme / text`.
//! - An optional placeholder, such as the `{scope?: CallerContext}` of a
//!   plan, stands for no part, one part, or several parts applied in
//!   order, each nesting to the left of the one before.
//!
//! The text is the same once the values are known. The tree is not, so a
//! test that states such a context with `assert_context!`
//! states the placeholder, not the values.

use std::borrow::Cow;
use std::fmt;
use std::sync::Arc;

use vitaminc_aead::{ContextPiece, IntoAad};

use crate::target::{
    AeadContext, Bind, BindPart, CallerContext, DeclaredContext, DeclaredScopes, NoCallerContext,
    OptionalContext, Parts, RequiredContext, Scope, ScopePart,
};
use crate::{Descriptor, IntoContext as _, NonEmpty};

/// Where a placeholder's value comes from when the declaration runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Supplier {
    /// The caller passes the value, as an argument of the call.
    Caller,
    /// The value is read from a field of the plaintext.
    Plaintext,
}

/// The kind of a part: a scope is in the query context and the stored
/// context; a binding is in the stored context only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Kind {
    /// A part a query supplies too.
    Scope,
    /// A part that ties a ciphertext to one row.
    Bind,
}

/// A part of a context that is not known until the declaration runs.
///
/// A placeholder names the part and its type. The type matters, because
/// `7u64` and `7i64` are different contexts. An optional placeholder stands
/// for a part the caller may leave out, such as the scope a plan's run may
/// add.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Placeholder {
    name: Cow<'static, str>,
    ty: Cow<'static, str>,
    optional: bool,
    supplier: Supplier,
    kind: Kind,
}

impl Placeholder {
    /// A scope the caller must pass.
    pub fn required(name: impl Into<Cow<'static, str>>, ty: impl Into<Cow<'static, str>>) -> Self {
        Self {
            name: name.into(),
            ty: ty.into(),
            optional: false,
            supplier: Supplier::Caller,
            kind: Kind::Scope,
        }
    }

    /// A scope the caller may pass.
    pub fn optional(name: impl Into<Cow<'static, str>>, ty: impl Into<Cow<'static, str>>) -> Self {
        Self {
            optional: true,
            ..Self::required(name, ty)
        }
    }

    /// A scope read from a field of the plaintext.
    pub fn from_plaintext(
        name: impl Into<Cow<'static, str>>,
        ty: impl Into<Cow<'static, str>>,
    ) -> Self {
        Self {
            supplier: Supplier::Plaintext,
            ..Self::required(name, ty)
        }
    }

    /// A required scope of type `T`, named `context`. The type is shown
    /// without its module path.
    pub fn of<T: ?Sized>() -> Self {
        Self::required("context", short_type_name::<T>())
    }

    /// A caller scope of type `T`, named `scope`.
    pub fn scope<T: ?Sized>() -> Self {
        Self::required("scope", short_type_name::<T>())
    }

    /// A caller binding of type `T`, named `bind`.
    pub fn bind<T: ?Sized>() -> Self {
        Self::required("bind", short_type_name::<T>()).as_bind()
    }

    /// This placeholder as a binding.
    pub fn as_bind(self) -> Self {
        Self {
            kind: Kind::Bind,
            ..self
        }
    }

    /// This placeholder as a part the caller may leave out.
    pub fn as_optional(self) -> Self {
        Self {
            optional: true,
            ..self
        }
    }

    /// This placeholder with another name.
    pub fn renamed(self, name: impl Into<Cow<'static, str>>) -> Self {
        Self {
            name: name.into(),
            ..self
        }
    }

    /// The name of the part.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The type of the part, without its module path.
    pub fn type_name(&self) -> &str {
        &self.ty
    }

    /// Whether the caller may leave the part out.
    pub fn is_optional(&self) -> bool {
        self.optional
    }

    /// Where the part comes from.
    pub fn supplier(&self) -> Supplier {
        self.supplier
    }

    /// Whether the part is a scope or a binding.
    pub fn kind(&self) -> Kind {
        self.kind
    }
}

impl fmt::Display for Placeholder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{{{}", self.name)?;
        if self.optional {
            f.write_str("?")?;
        }
        write!(f, ": {}", self.ty)?;
        if self.supplier == Supplier::Plaintext {
            f.write_str(", from the plaintext")?;
        }
        f.write_str("}")
    }
}

/// One context, with its types, as a tree of parts.
///
/// A [`Part`](Self::Part) is a leaf of the context: text, bytes, an integer,
/// the unit context, or a pre-encoded context. A nested list of known parts
/// is a [`List`](Self::List), never a `Part`. A [`Placeholder`] stands for a
/// part that is supplied when the declaration runs.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ContextTree {
    /// A leaf known when the declaration is written.
    Part(ContextPiece<'static>),
    /// A part supplied when the declaration runs.
    Placeholder(Placeholder),
    /// A list of parts, in order.
    List(Vec<ContextTree>),
}

impl ContextTree {
    /// The tree of a known context. A nested list becomes a
    /// [`List`](Self::List), so every [`Part`](Self::Part) is a leaf.
    pub fn from_piece(piece: &ContextPiece<'_>) -> Self {
        match piece {
            ContextPiece::List(parts) => Self::List(parts.iter().map(Self::from_piece).collect()),
            other => Self::Part(other.clone().into_owned()),
        }
    }

    /// The one known part of a leaf, for the `testing` module's tests.
    #[cfg(all(test, feature = "testing"))]
    pub(crate) fn piece(&self) -> ContextPiece<'static> {
        match self {
            Self::Part(piece) => piece.clone(),
            other => panic!("not a leaf: {other}"),
        }
    }

    /// Whether this tree holds a placeholder anywhere.
    pub fn has_placeholder(&self) -> bool {
        match self {
            Self::Part(_) => false,
            Self::Placeholder(_) => true,
            Self::List(parts) => parts.iter().any(Self::has_placeholder),
        }
    }

    fn unit() -> Self {
        Self::Part(ContextPiece::Unit)
    }

    /// `head`, then `tail`: what [`NonEmpty::with`] nests.
    fn nest(head: Self, tail: Self) -> Self {
        Self::List(vec![head, tail])
    }

    fn render(&self, root: bool, out: &mut String) {
        match self {
            Self::Part(piece) => render_leaf(piece, out),
            Self::Placeholder(placeholder) => out.push_str(&placeholder.to_string()),
            Self::List(parts) => {
                let bare = root && parts.len() >= 2;
                if !bare {
                    out.push('(');
                }
                for (index, part) in parts.iter().enumerate() {
                    if index > 0 {
                        out.push_str(" / ");
                    }
                    part.render(false, out);
                }
                if !bare {
                    out.push(')');
                }
            }
        }
    }
}

impl fmt::Display for ContextTree {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut out = String::new();
        self.render(true, &mut out);
        f.write_str(&out)
    }
}

/// Render one leaf with its type. See the [module docs](self).
fn render_leaf(piece: &ContextPiece<'_>, out: &mut String) {
    match piece {
        ContextPiece::Text(text) => render_text(text, out),
        ContextPiece::Bytes(bytes) => render_hex(bytes, out),
        ContextPiece::Unit => out.push_str("()"),
        ContextPiece::U8(v) => out.push_str(&format!("{v}u8")),
        ContextPiece::U16(v) => out.push_str(&format!("{v}u16")),
        ContextPiece::U32(v) => out.push_str(&format!("{v}u32")),
        ContextPiece::U64(v) => out.push_str(&format!("{v}u64")),
        ContextPiece::U128(v) => out.push_str(&format!("{v}u128")),
        ContextPiece::I8(v) => out.push_str(&format!("{v}i8")),
        ContextPiece::I16(v) => out.push_str(&format!("{v}i16")),
        ContextPiece::I32(v) => out.push_str(&format!("{v}i32")),
        ContextPiece::I64(v) => out.push_str(&format!("{v}i64")),
        ContextPiece::I128(v) => out.push_str(&format!("{v}i128")),
        ContextPiece::Encoded(bytes) => {
            out.push_str("encoded:");
            render_hex(bytes, out);
        }
        // `from_piece` turns a list into a `List`, so a list never reaches
        // here. A part this crate does not know renders by its bytes.
        other => render_hex(other.clone().into_aad().as_bytes(), out),
    }
}

/// Plain text renders as it is. Text that is not plain, or that would read
/// as a placeholder or an encoded context, is quoted. The quoting is this
/// module's own, so it is stable: `"` and `\` take a backslash, and a
/// control or non-printing character is `\u{..}` with its code point in
/// hex.
fn render_text(text: &str, out: &mut String) {
    let reads_as_another_form = text.starts_with('{') || text.starts_with("encoded:");
    if Descriptor::is_plain(text) && !reads_as_another_form {
        out.push_str(text);
        return;
    }
    out.push('"');
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            ch if ch.is_control() || !is_printing(ch) => {
                out.push_str(&format!("\\u{{{:x}}}", u32::from(ch)));
            }
            ch => out.push(ch),
        }
    }
    out.push('"');
}

/// Whether a character shows on its own: not a format character such as a
/// zero-width or bidirectional mark, which would print as another name.
fn is_printing(ch: char) -> bool {
    !matches!(
        ch,
        '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2060}'..='\u{2064}' | '\u{FEFF}'
    )
}

fn render_hex(bytes: &[u8], out: &mut String) {
    out.push_str("0x");
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
}

/// The two contexts of one field or one leaf: the query context the terms
/// derive under, and the stored context the key and the AAD derive under.
/// They are the same when there is no binding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LeafContext {
    query: ContextTree,
    stored: ContextTree,
}

impl LeafContext {
    /// A context with no binding: the query context and the stored context
    /// are the same.
    pub fn one(context: ContextTree) -> Self {
        Self {
            stored: context.clone(),
            query: context,
        }
    }

    /// The query context: the scopes.
    pub fn query(&self) -> &ContextTree {
        &self.query
    }

    /// The stored context: the scopes, then the bindings.
    pub fn stored(&self) -> &ContextTree {
        &self.stored
    }

    /// Whether the stored context has a binding, so the two differ.
    pub fn has_binding(&self) -> bool {
        self.query != self.stored
    }

    fn write(&self, f: &mut fmt::Formatter<'_>, indent: &str) -> fmt::Result {
        if self.has_binding() {
            writeln!(f, "{indent}query context:  {}", self.query)?;
            writeln!(f, "{indent}stored context: {}", self.stored)
        } else {
            writeln!(f, "{indent}context: {}", self.query)
        }
    }
}

impl fmt::Display for LeafContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.write(f, "")
    }
}

/// The contexts of one field of a declaration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FieldContext {
    name: Option<Arc<str>>,
    context: LeafContext,
}

impl FieldContext {
    /// The name of the field, when the declaration names it. A declaration
    /// of one value has no name.
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// The query context and the stored context of the field.
    pub fn context(&self) -> &LeafContext {
        &self.context
    }
}

/// The contexts of a declaration, one for each field that is sealed or
/// indexed.
///
/// A part the caller supplies is a [`Placeholder`]. A passthrough field is
/// not listed: it is neither sealed nor indexed, so it has no context.
///
/// ```
/// use stack_encrypt::sem::EqualityTerm;
/// use stack_encrypt::target::{EncryptTarget, DecryptSource};
/// use stack_encrypt::{Encrypted, StackCipherText};
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
/// println!("{}", EncryptedUser::contexts());
/// // email
/// //   context: users / email
/// // notes
/// //   context: users / notes
/// # #[cfg(feature = "testing")]
/// stack_encrypt::assert_context!(
///     EncryptedUser::contexts(),
///     email = ["users", "email"],
///     notes = ["users", "notes"],
/// );
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Contexts {
    fields: Vec<FieldContext>,
}

impl Contexts {
    /// The fields, in the order the declaration lists them.
    pub fn fields(&self) -> &[FieldContext] {
        &self.fields
    }

    /// The contexts of the field named `name`.
    pub fn get(&self, name: &str) -> Option<&LeafContext> {
        self.fields
            .iter()
            .find(|field| field.name.as_deref() == Some(name))
            .map(FieldContext::context)
    }

    /// The one context of a declaration that names no field, such as a
    /// declaration of one value. `None` when the declaration has several
    /// fields, or none.
    pub fn single(&self) -> Option<&LeafContext> {
        match self.fields.as_slice() {
            [field] if field.name.is_none() => Some(&field.context),
            _ => None,
        }
    }

    /// Whether the declaration seals or indexes nothing.
    pub fn is_empty(&self) -> bool {
        self.fields.is_empty()
    }
}

impl fmt::Display for Contexts {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.fields.is_empty() {
            return writeln!(f, "no field is sealed or indexed");
        }
        for field in &self.fields {
            match &field.name {
                Some(name) => {
                    writeln!(f, "{name}")?;
                    field.context.write(f, "  ")?;
                }
                None => field.context.write(f, "")?,
            }
        }
        Ok(())
    }
}

/// The contexts a prepared call uses, with the caller's values filled in.
///
/// Each distinct context appears once, in the order the call's leaves run.
/// No key has been requested when this is read.
///
/// ```
/// # tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
/// use stack_encrypt::kms::FakeDataKeySource;
/// use stack_encrypt::{nonempty, EncryptInto, StackCipher, StackCipherText};
///
/// let cipher = StackCipher::builder().kms(FakeDataKeySource::new()).init().await?;
/// let keyset = cipher.default_keyset();
///
/// let call = String::from("ada@example.com")
///     .encrypt_into_with_context::<StackCipherText, _>(&keyset, nonempty!("users").with("email"));
/// println!("{}", call.context()); // context: users / email
/// # #[cfg(feature = "testing")]
/// stack_encrypt::assert_context!(call.context(), ["users", "email"]);
/// let _stored = call.await?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// # }).unwrap();
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CallContexts {
    contexts: Vec<LeafContext>,
    failed: bool,
}

impl CallContexts {
    pub(crate) fn from_pieces(
        pieces: &[(ContextPiece<'static>, ContextPiece<'static>)],
        failed: bool,
    ) -> Self {
        let mut contexts: Vec<LeafContext> = Vec::new();
        for (query, stored) in pieces {
            let context = LeafContext {
                query: ContextTree::from_piece(query),
                stored: ContextTree::from_piece(stored),
            };
            if !contexts.contains(&context) {
                contexts.push(context);
            }
        }
        // A ciphertext knows only the stored context it is sealed under. Beside
        // a term of the same field, it is the same leaf context: the term
        // shows the query context too, so the ciphertext's entry is dropped.
        let bound: Vec<ContextTree> = contexts
            .iter()
            .filter(|context| context.has_binding())
            .map(|context| context.stored.clone())
            .collect();
        contexts.retain(|context| context.has_binding() || !bound.contains(&context.stored));
        Self { contexts, failed }
    }

    /// Whether the call has already failed, before any key was requested.
    /// Awaiting it returns the error. A failed call shows no context.
    pub fn has_failed(&self) -> bool {
        self.failed
    }

    /// The distinct contexts, in order.
    pub fn contexts(&self) -> &[LeafContext] {
        &self.contexts
    }

    /// The one context of a call whose leaves share a context. `None` when
    /// the call uses several contexts, or none.
    pub fn single(&self) -> Option<&LeafContext> {
        match self.contexts.as_slice() {
            [context] => Some(context),
            _ => None,
        }
    }

    /// Whether the call seals and indexes nothing.
    pub fn is_empty(&self) -> bool {
        self.contexts.is_empty()
    }
}

impl fmt::Display for CallContexts {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.failed {
            return writeln!(f, "no context: the call has failed; await it for the error");
        }
        if self.contexts.is_empty() {
            return writeln!(f, "no context: the call seals and indexes nothing");
        }
        for context in &self.contexts {
            context.write(f, "")?;
        }
        Ok(())
    }
}

/// The parts a caller supplies to a declaration, as placeholders: a scope,
/// a binding, both, or neither.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CallerShape {
    scope: Option<Placeholder>,
    bind: Option<Placeholder>,
}

impl CallerShape {
    /// The caller supplies nothing.
    pub fn none() -> Self {
        Self::default()
    }

    /// The caller supplies one scope, shown as `placeholder`.
    pub fn scope(placeholder: Placeholder) -> Self {
        Self {
            scope: Some(placeholder),
            bind: None,
        }
    }

    /// The caller supplies one binding, shown as `placeholder`.
    pub fn bind(placeholder: Placeholder) -> Self {
        Self {
            scope: None,
            bind: Some(placeholder.as_bind()),
        }
    }

    /// The caller supplies a scope and a binding.
    pub fn both(scope: Placeholder, bind: Placeholder) -> Self {
        Self {
            scope: Some(scope),
            bind: Some(bind.as_bind()),
        }
    }

    /// The scope placeholder, if the caller supplies a scope.
    pub fn scope_placeholder(&self) -> Option<&Placeholder> {
        self.scope.as_ref()
    }

    /// The binding placeholder, if the caller supplies a binding.
    pub fn bind_placeholder(&self) -> Option<&Placeholder> {
        self.bind.as_ref()
    }

    fn named(self, scope: Option<&'static str>, bind: Option<&'static str>) -> Self {
        Self {
            scope: match (self.scope, scope) {
                (Some(placeholder), Some(name)) => Some(placeholder.renamed(name)),
                (placeholder, _) => placeholder,
            },
            bind: match (self.bind, bind) {
                (Some(placeholder), Some(name)) => Some(placeholder.renamed(name)),
                (placeholder, _) => placeholder,
            },
        }
    }
}

/// What the caller supplies to a declaration whose context input is this
/// type: the placeholders that stand for its parts in [`Contexts`].
///
/// Implemented for the context inputs of the crate. The derives and the
/// plan builder use it to render the root of a declaration. Sealed: a
/// context input is one of this crate's types.
pub trait SuppliedContext: sealed::Sealed {
    /// The placeholders for the caller's parts.
    fn supplies() -> CallerShape;
}

mod sealed {
    use crate::target::{
        AeadContext, CallerContext, DeclaredContext, DeclaredScopes, NoCallerContext,
        OptionalContext, RequiredContext,
    };
    pub trait Sealed {}
    impl Sealed for NoCallerContext {}
    impl Sealed for DeclaredScopes {}
    impl Sealed for DeclaredContext {}
    impl<C> Sealed for RequiredContext<C> {}
    impl<C> Sealed for OptionalContext<C> {}
    impl Sealed for CallerContext {}
    impl Sealed for AeadContext {}
}

impl SuppliedContext for NoCallerContext {
    fn supplies() -> CallerShape {
        CallerShape::none()
    }
}
impl SuppliedContext for DeclaredScopes {
    fn supplies() -> CallerShape {
        CallerShape::none()
    }
}
impl SuppliedContext for DeclaredContext {
    fn supplies() -> CallerShape {
        CallerShape::scope(Placeholder::optional("scope", "CallerContext"))
    }
}
impl<C: PartsShape> SuppliedContext for RequiredContext<C> {
    fn supplies() -> CallerShape {
        C::parts_shape()
    }
}
impl<C: PartsShape> SuppliedContext for OptionalContext<C> {
    fn supplies() -> CallerShape {
        let shape = C::parts_shape();
        CallerShape {
            scope: shape.scope.map(Placeholder::as_optional),
            bind: shape.bind.map(Placeholder::as_optional),
        }
    }
}
impl SuppliedContext for CallerContext {
    fn supplies() -> CallerShape {
        CallerShape::scope(Placeholder::of::<Self>())
    }
}
impl SuppliedContext for AeadContext {
    fn supplies() -> CallerShape {
        CallerShape::scope(Placeholder::of::<Self>())
    }
}

/// The placeholders for a context value `C` a caller passes: the scope and
/// binding slots of a [`Parts`], or one scope for any other context type.
/// Sealed: the context types this crate accepts implement it.
pub trait PartsShape: parts_sealed::Sealed {
    /// The placeholders.
    fn parts_shape() -> CallerShape;
}
mod parts_sealed {
    pub trait Sealed {}
    impl<S, B> Sealed for crate::target::Parts<S, B> {}
    impl<T> Sealed for crate::target::Scope<T> {}
    impl<T> Sealed for crate::target::Bind<T> {}
    impl Sealed for crate::target::CallerContext {}
    impl Sealed for crate::target::AeadContext {}
    impl Sealed for crate::target::ScalarContext {}
    impl<T> Sealed for crate::NonEmpty<T> {}
    macro_rules! sealed_integers {
        ($($ty:ty),* $(,)?) => {$( impl Sealed for $ty {} )*};
    }
    sealed_integers!(u8, u16, u32, u64, u128, i8, i16, i32, i64, i128);
}
impl<S: ScopePart, B: BindPart> PartsShape for Parts<S, B> {
    fn parts_shape() -> CallerShape {
        CallerShape {
            scope: S::type_name().map(|ty| Placeholder::required("scope", ty)),
            bind: B::type_name().map(|ty| Placeholder::required("bind", ty).as_bind()),
        }
    }
}
impl<T> PartsShape for Scope<T> {
    fn parts_shape() -> CallerShape {
        CallerShape::scope(Placeholder::scope::<T>())
    }
}
impl<T> PartsShape for Bind<T> {
    fn parts_shape() -> CallerShape {
        CallerShape::bind(Placeholder::bind::<T>())
    }
}
macro_rules! one_scope_shapes {
    ($($ty:ty),* $(,)?) => {$(
        impl PartsShape for $ty {
            fn parts_shape() -> CallerShape {
                CallerShape::scope(Placeholder::of::<$ty>())
            }
        }
    )*};
}
one_scope_shapes!(CallerContext, AeadContext, crate::target::ScalarContext);
impl<T> PartsShape for NonEmpty<T> {
    fn parts_shape() -> CallerShape {
        CallerShape::scope(Placeholder::of::<Self>())
    }
}
macro_rules! integer_shapes {
    ($($ty:ty),* $(,)?) => {$(
        impl PartsShape for $ty {
            fn parts_shape() -> CallerShape {
                CallerShape::scope(Placeholder::of::<$ty>())
            }
        }
    )*};
}
integer_shapes!(u8, u16, u32, u64, u128, i8, i16, i32, i64, i128);

/// The name of `T` without module paths, for a placeholder. For generated
/// code.
#[doc(hidden)]
pub fn type_name<T: ?Sized>() -> String {
    short_type_name::<T>()
}

/// The name of `T` without module paths: `NonEmpty<Identifier>`, not
/// `vitaminc_protected::NonEmpty<eql_bindings::encryption::Identifier>`.
pub(crate) fn short_type_name<T: ?Sized>() -> String {
    let full = std::any::type_name::<T>();
    let mut out = String::new();
    let mut segment = String::new();
    let flush = |segment: &mut String, out: &mut String| {
        if !segment.is_empty() {
            out.push_str(segment.rsplit("::").next().unwrap_or(""));
            segment.clear();
        }
    };
    for ch in full.chars() {
        if ch.is_alphanumeric() || ch == '_' || ch == ':' {
            segment.push(ch);
        } else {
            flush(&mut segment, &mut out);
            out.push(ch);
        }
    }
    flush(&mut segment, &mut out);
    out
}

/// The parts of a nonempty context, as one owned piece, still proven
/// nonempty. A context and its parts view are empty together, so the proof
/// carries over.
pub(crate) fn piece_of<'c>(
    context: NonEmpty<impl crate::IntoContext<'c>>,
) -> NonEmpty<ContextPiece<'static>> {
    NonEmpty::new(context.into_context().into_owned())
        .unwrap_or_else(|_| unreachable!("a nonempty context has nonempty parts"))
}

/// The shape of one leaf's context while a declaration is being built: the
/// context in terms of the one the declaration is handed when it runs.
///
/// Each combinator that changes the context a subtree runs under
/// ([`under`](crate::target::Encryption::under),
/// [`extend`](crate::target::Encryption::extend),
/// [`context_from`](crate::target::Encryption::context_from),
/// `parts_from`) substitutes [`Caller`](Self::Caller) in the subtree's
/// shapes, exactly where the engine substitutes the context. At the root,
/// `Caller` is the declaration's own input.
#[derive(Clone, Debug)]
pub(crate) enum Shape {
    /// The context this description is handed when it runs.
    Caller,
    /// The caller's parts, with the names a record gives them.
    NamedCaller {
        scope: Option<&'static str>,
        bind: Option<&'static str>,
    },
    /// A part known when the declaration is written.
    Known(ContextPiece<'static>),
    /// A known binding: a part that resolves into the bindings.
    #[cfg_attr(not(feature = "dynamic"), allow(dead_code))]
    KnownBind(ContextPiece<'static>),
    /// A part supplied when the declaration runs.
    Placeholder(Placeholder),
    /// The parts a record reads from its plaintext.
    StoredParts {
        scope: Option<Placeholder>,
        bind: Option<Placeholder>,
    },
    /// `own`, extended by `by`: what `DeclaredContext::under` and
    /// `Extends::extend` build.
    Under { own: Box<Shape>, by: Box<Shape> },
    /// A list of parts, some of them not known yet: a label the call names
    /// joined to a field's identity.
    List(Vec<Shape>),
    /// Known caller parts, applied one after another: what a data plan
    /// carries as its extension and its bindings.
    #[cfg_attr(not(feature = "dynamic"), allow(dead_code))]
    Chain(Vec<Shape>),
}

/// A shape resolved against the caller: the scopes, as one tree, and the
/// bindings, in order.
#[derive(Clone, Debug, Default)]
struct Resolved {
    scopes: Option<ContextTree>,
    bindings: Vec<ContextTree>,
}

impl Resolved {
    fn scope(tree: ContextTree) -> Self {
        Self {
            scopes: Some(tree),
            bindings: Vec::new(),
        }
    }

    /// This, extended by `other`: the scopes nest to the left, and the
    /// bindings follow those already given. The same rule as
    /// `CallerContext::then`.
    fn then(mut self, other: Resolved) -> Self {
        if let Some(scopes) = other.scopes {
            self.scopes = Some(match self.scopes.take() {
                Some(head) => ContextTree::nest(head, scopes),
                None => scopes,
            });
        }
        self.bindings.extend(other.bindings);
        self
    }

    fn into_leaf(self) -> LeafContext {
        let query = self.scopes.clone().unwrap_or_else(ContextTree::unit);
        let mut stored = self.scopes;
        for binding in self.bindings {
            stored = Some(match stored {
                Some(head) => ContextTree::nest(head, binding),
                None => binding,
            });
        }
        LeafContext {
            query,
            stored: stored.unwrap_or_else(ContextTree::unit),
        }
    }
}

impl Shape {
    /// Replace every [`Caller`](Self::Caller) with `caller`.
    pub(crate) fn substitute(self, caller: &Shape) -> Shape {
        match self {
            Shape::Caller => caller.clone(),
            Shape::Under { own, by } => Shape::Under {
                own: Box::new(own.substitute(caller)),
                by: Box::new(by.substitute(caller)),
            },
            Shape::List(parts) => Shape::List(
                parts
                    .into_iter()
                    .map(|part| part.substitute(caller))
                    .collect(),
            ),
            other => other,
        }
    }

    /// The shape of a subtree run under `own`, extended by the context it
    /// is handed.
    pub(crate) fn under(own: ContextPiece<'static>) -> Shape {
        Shape::Under {
            own: Box::new(Shape::Known(own)),
            by: Box::new(Shape::Caller),
        }
    }

    /// The shape of a subtree run under a label that is not known yet,
    /// joined to `identity` when the field has one, and extended by the
    /// context the subtree is handed.
    pub(crate) fn under_label(placeholder: Placeholder, identity: Option<&str>) -> Shape {
        let own = match identity {
            None => Shape::Placeholder(placeholder),
            Some(identity) => Shape::List(vec![
                Shape::Placeholder(placeholder),
                Shape::Known(ContextPiece::Text(Cow::Owned(identity.to_owned()))),
            ]),
        };
        Shape::Under {
            own: Box::new(own),
            by: Box::new(Shape::Caller),
        }
    }

    /// The shape of a subtree run under the parts a record reads from its
    /// plaintext, then the caller's parts. `scope` and `bind` are the name
    /// and the type of each stored part.
    pub(crate) fn stored_parts(
        scope: Option<(&'static str, String)>,
        bind: Option<(&'static str, String)>,
    ) -> Shape {
        Shape::Under {
            own: Box::new(Shape::StoredParts {
                scope: scope.map(|(name, ty)| Placeholder::from_plaintext(name, ty)),
                bind: bind.map(|(name, ty)| Placeholder::from_plaintext(name, ty).as_bind()),
            }),
            by: Box::new(Shape::Caller),
        }
    }

    /// The caller's parts, with the names a record gives them.
    pub(crate) fn named_caller(scope: Option<&'static str>, bind: Option<&'static str>) -> Shape {
        Shape::NamedCaller { scope, bind }
    }

    fn resolve(self, caller: &CallerShape) -> Resolved {
        match self {
            Shape::Caller => Self::caller_parts(caller.clone()),
            Shape::NamedCaller { scope, bind } => {
                Self::caller_parts(caller.clone().named(scope, bind))
            }
            Shape::Known(piece) => Resolved::scope(ContextTree::from_piece(&piece)),
            Shape::KnownBind(piece) => Resolved {
                scopes: None,
                bindings: vec![ContextTree::from_piece(&piece)],
            },
            Shape::Placeholder(placeholder) => match placeholder.kind {
                Kind::Scope => Resolved::scope(ContextTree::Placeholder(placeholder)),
                Kind::Bind => Resolved {
                    scopes: None,
                    bindings: vec![ContextTree::Placeholder(placeholder)],
                },
            },
            Shape::StoredParts { scope, bind } => Resolved {
                scopes: scope.map(ContextTree::Placeholder),
                bindings: bind.map(ContextTree::Placeholder).into_iter().collect(),
            },
            // A chain applies its parts one after another, each nesting to
            // the left of the context so far, as `DeclaredContext::under`
            // does.
            Shape::Under { own, by } => {
                let own = own.resolve(caller);
                match *by {
                    Shape::Chain(parts) => parts
                        .into_iter()
                        .fold(own, |resolved, part| resolved.then(part.resolve(caller))),
                    other => own.then(other.resolve(caller)),
                }
            }
            Shape::List(parts) => {
                let mut scopes = Vec::new();
                let mut bindings = Vec::new();
                for part in parts {
                    let resolved = part.resolve(caller);
                    scopes.extend(resolved.scopes);
                    bindings.extend(resolved.bindings);
                }
                Resolved {
                    scopes: Some(ContextTree::List(scopes)),
                    bindings,
                }
            }
            Shape::Chain(parts) => parts
                .into_iter()
                .fold(Resolved::default(), |resolved, part| {
                    resolved.then(part.resolve(caller))
                }),
        }
    }

    fn caller_parts(caller: CallerShape) -> Resolved {
        Resolved {
            scopes: caller.scope.map(ContextTree::Placeholder),
            bindings: caller
                .bind
                .map(ContextTree::Placeholder)
                .into_iter()
                .collect(),
        }
    }
}

/// The shape of one leaf of a declaration, with the name of the field it
/// belongs to once a record names it.
#[derive(Clone, Debug)]
pub(crate) struct LeafShape {
    name: Option<Arc<str>>,
    shape: Shape,
}

/// The shapes of every leaf of a declaration, in order.
pub(crate) type Shapes = Vec<LeafShape>;

impl LeafShape {
    /// The field this leaf is, as [`name`] named it.
    #[cfg_attr(not(feature = "dynamic"), allow(dead_code))]
    pub(crate) fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }
}

/// One named leaf under a context known when the declaration is written,
/// and extended by nothing: a data plan's EQL field, sealed under its label
/// by the resolver.
#[cfg_attr(not(feature = "dynamic"), allow(dead_code))]
pub(crate) fn known_leaf(name: &str, piece: ContextPiece<'static>) -> LeafShape {
    LeafShape {
        name: Some(Arc::from(name)),
        shape: Shape::Known(piece),
    }
}

/// The leaves with the caller's parts known, as a data plan carries them:
/// what [`resolve_under`] resolves, kept as shapes so more leaves can be
/// placed among them first.
#[cfg_attr(not(feature = "dynamic"), allow(dead_code))]
pub(crate) fn under_declared(shapes: Shapes, declared: &DeclaredContext) -> Shapes {
    let chain = Shape::Chain(
        declared
            .parts()
            .iter()
            .map(|part| {
                let (scopes, bindings) = part.pieces();
                let mut parts: Vec<Shape> = scopes.into_iter().map(Shape::Known).collect();
                parts.extend(bindings.into_iter().map(Shape::KnownBind));
                Shape::Chain(parts)
            })
            .collect(),
    );
    substitute(shapes, &chain)
}

/// One leaf that runs under the context it is handed.
pub(crate) fn caller_leaf() -> Shapes {
    vec![LeafShape {
        name: None,
        shape: Shape::Caller,
    }]
}

/// Substitute the caller in every leaf.
pub(crate) fn substitute(shapes: Shapes, caller: &Shape) -> Shapes {
    shapes
        .into_iter()
        .map(|leaf| LeafShape {
            name: leaf.name,
            shape: leaf.shape.substitute(caller),
        })
        .collect()
}

/// Name every leaf: a leaf with no name takes `name`, and a leaf a nested
/// record already named takes `name.<its name>`.
pub(crate) fn name(shapes: Shapes, name: &str) -> Shapes {
    let prefix: Arc<str> = Arc::from(name);
    shapes
        .into_iter()
        .map(|leaf| LeafShape {
            name: Some(match leaf.name {
                None => Arc::clone(&prefix),
                Some(inner) => Arc::from(format!("{prefix}.{inner}")),
            }),
            shape: leaf.shape,
        })
        .collect()
}

/// Resolve the leaves at the root of a declaration whose caller supplies
/// `caller`. Leaves with one name and one context collapse into one field:
/// a ciphertext and the terms beside it share a context.
pub(crate) fn resolve(shapes: Shapes, caller: CallerShape) -> Contexts {
    let mut fields: Vec<FieldContext> = Vec::new();
    for leaf in shapes {
        let field = FieldContext {
            name: leaf.name,
            context: leaf.shape.resolve(&caller).into_leaf(),
        };
        if fields.last() != Some(&field) {
            fields.push(field);
        }
    }
    Contexts { fields }
}

/// [`resolve`] with the caller's parts known: a data plan's extension and
/// bindings, as the declared context it runs under.
#[cfg(test)]
pub(crate) fn resolve_under(shapes: Shapes, declared: &DeclaredContext) -> Contexts {
    resolve(under_declared(shapes, declared), CallerShape::none())
}

#[cfg(test)]
mod tests {
    use super::*;
    use vitaminc_aead::IntoContext;

    fn shown<'a>(value: impl IntoContext<'a>) -> String {
        ContextTree::from_piece(&value.into_context()).to_string()
    }
    use vitaminc_protected::NonEmpty;

    #[test]
    fn short_type_names_drop_every_module_path() {
        assert_eq!(short_type_name::<NonEmpty<String>>(), "NonEmpty<String>");
        assert_eq!(short_type_name::<u64>(), "u64");
        assert_eq!(short_type_name::<&str>(), "&str");
        assert_eq!(short_type_name::<(u64, Vec<u8>)>(), "(u64, Vec<u8>)");
    }

    #[test]
    fn leaves_render_with_their_types() {
        let column = NonEmpty::<&str>::new("users").unwrap().with("email");
        assert_eq!(shown(column), "users / email");
        let row = NonEmpty::<&str>::new("users")
            .unwrap()
            .with("email")
            .with(7u64);
        assert_eq!(shown(row), "(users / email) / 7u64");
        assert_eq!(shown(7i64), "7i64");
        assert_eq!(shown("7"), "\"7\"");
        assert_eq!(shown(b"7".to_vec()), "0x37");
        assert_eq!(shown(()), "()");
        assert_eq!(shown("a/b"), "\"a/b\"");
        // Text that would read as a placeholder or an encoded context is
        // quoted, with this module's own escapes.
        assert_eq!(shown("{context: u64}"), "\"{context: u64}\"");
        assert_eq!(shown("encoded:0x01"), "\"encoded:0x01\"");
        // Plain text with quotes renders as it is. Text that is not plain
        // is quoted, and its quotes and backslashes are escaped.
        assert_eq!(shown("say \"hi\""), "say \"hi\"");
        assert_eq!(shown("a/\"b\"\\"), "\"a/\\\"b\\\"\\\\\"");
        assert_eq!(shown("tab\there"), "\"tab\\u{9}here\"");
        assert_eq!(shown("a\u{200B}b"), "\"a\\u{200b}b\"");
    }

    #[test]
    fn every_integer_width_renders_with_its_own_suffix() {
        assert_eq!(shown(1u8), "1u8");
        assert_eq!(shown(2u16), "2u16");
        assert_eq!(shown(3u32), "3u32");
        assert_eq!(shown(4u64), "4u64");
        assert_eq!(shown(5u128), "5u128");
        assert_eq!(shown(-1i8), "-1i8");
        assert_eq!(shown(-2i16), "-2i16");
        assert_eq!(shown(-3i32), "-3i32");
        assert_eq!(shown(-4i64), "-4i64");
        assert_eq!(shown(-5i128), "-5i128");
        assert_eq!(shown(Vec::<u8>::new()), "0x");
        assert_eq!(shown(vec![0xAB_u8, 0x01]), "0xab01");
        assert_eq!(shown(""), "\"\"");
        let encoded = ContextPiece::Encoded(Cow::Owned(vec![1, 2]));
        assert_eq!(
            ContextTree::from_piece(&encoded).to_string(),
            "encoded:0x0102"
        );
        let nested = ContextTree::from_piece(
            &NonEmpty::<&str>::new("a")
                .unwrap()
                .with(NonEmpty::<&str>::new("b").unwrap().with("c"))
                .into_context(),
        );
        assert_eq!(nested.to_string(), "a / (b / c)");
        assert!(matches!(nested, ContextTree::List(ref parts) if parts.len() == 2));
        assert!(!nested.has_placeholder());
        let with = ContextTree::List(vec![
            nested,
            ContextTree::Placeholder(Placeholder::of::<u64>()),
        ]);
        assert!(with.has_placeholder());
        let one = ContextTree::List(vec![ContextTree::Placeholder(Placeholder::of::<u64>())]);
        assert_eq!(one.to_string(), "({context: u64})");
    }

    #[test]
    fn placeholders_show_their_name_type_kind_and_optionality() {
        assert_eq!(Placeholder::of::<u64>().to_string(), "{context: u64}");
        assert_eq!(Placeholder::scope::<u64>().to_string(), "{scope: u64}");
        assert_eq!(Placeholder::bind::<u128>().to_string(), "{bind: u128}");
        assert_eq!(Placeholder::bind::<u128>().kind(), Kind::Bind);
        assert_eq!(
            Placeholder::optional("scope", "CallerContext").to_string(),
            "{scope?: CallerContext}"
        );
        assert_eq!(
            Placeholder::from_plaintext("column", "Identifier").to_string(),
            "{column: Identifier, from the plaintext}"
        );
        let placeholder = Placeholder::from_plaintext("column", "Identifier");
        assert_eq!(placeholder.name(), "column");
        assert_eq!(placeholder.type_name(), "Identifier");
        assert!(!placeholder.is_optional());
        assert_eq!(placeholder.supplier(), Supplier::Plaintext);
        assert_eq!(placeholder.kind(), Kind::Scope);
        let renamed = Placeholder::scope::<u64>().renamed("tenant").as_optional();
        assert_eq!(renamed.to_string(), "{tenant?: u64}");
        assert_eq!(renamed.supplier(), Supplier::Caller);
    }

    fn own() -> ContextPiece<'static> {
        NonEmpty::<&str>::new("users")
            .unwrap()
            .with("email")
            .into_context()
            .into_owned()
    }

    #[test]
    fn a_leaf_under_a_known_context_shows_the_caller_as_an_extension() {
        let leaf = substitute(caller_leaf(), &Shape::under(own()));
        let alone = resolve(leaf.clone(), CallerShape::none());
        assert_eq!(alone.to_string(), "context: users / email\n");
        let extended = resolve(leaf, CallerShape::scope(Placeholder::of::<u64>()));
        assert_eq!(
            extended.to_string(),
            "context: (users / email) / {context: u64}\n"
        );
    }

    #[test]
    fn a_binding_shows_a_query_context_and_a_stored_context() {
        let leaf = substitute(caller_leaf(), &Shape::under(own()));
        let bound = resolve(
            leaf.clone(),
            CallerShape::both(Placeholder::scope::<u64>(), Placeholder::bind::<u128>()),
        );
        assert_eq!(
            bound.to_string(),
            "query context:  (users / email) / {scope: u64}\n\
             stored context: ((users / email) / {scope: u64}) / {bind: u128}\n"
        );
        let single = bound.single().unwrap();
        assert!(single.has_binding());
        assert_eq!(single.query().to_string(), "(users / email) / {scope: u64}");
        let bind_only = resolve(leaf, CallerShape::bind(Placeholder::bind::<u128>()));
        assert_eq!(
            bind_only.to_string(),
            "query context:  users / email\nstored context: (users / email) / {bind: u128}\n"
        );
    }

    #[test]
    fn a_record_names_the_callers_parts() {
        let leaf = substitute(
            substitute(caller_leaf(), &Shape::under(own())),
            &Shape::named_caller(Some("tenant"), Some("row")),
        );
        let shown = resolve(
            leaf,
            CallerShape::both(Placeholder::scope::<u64>(), Placeholder::bind::<u128>()),
        );
        assert_eq!(
            shown.to_string(),
            "query context:  (users / email) / {tenant: u64}\n\
             stored context: ((users / email) / {tenant: u64}) / {row: u128}\n"
        );
    }

    #[test]
    fn stored_parts_come_before_the_callers() {
        let leaf = substitute(
            substitute(caller_leaf(), &Shape::under(own())),
            &Shape::stored_parts(Some(("tenant", "u64".to_owned())), None),
        );
        let shown = resolve(leaf, CallerShape::bind(Placeholder::bind::<u128>()));
        assert_eq!(
            shown.to_string(),
            "query context:  (users / email) / {tenant: u64, from the plaintext}\n\
             stored context: ((users / email) / {tenant: u64, from the plaintext}) / {bind: u128}\n"
        );
    }

    #[test]
    fn a_known_extension_nests_each_part_to_the_left() {
        let leaf = substitute(caller_leaf(), &Shape::under(own()));
        let none = resolve_under(leaf.clone(), &DeclaredContext::default());
        assert_eq!(none.to_string(), "context: users / email\n");
        let two = resolve_under(
            leaf.clone(),
            &DeclaredContext::default()
                .with(7u64)
                .with(NonEmpty::<&str>::new("eu").unwrap()),
        );
        assert_eq!(two.to_string(), "context: ((users / email) / 7u64) / eu\n");
        let bound = resolve_under(
            leaf,
            &DeclaredContext::default().with(Scope::new(7u64).bind(9u128)),
        );
        assert_eq!(
            bound.to_string(),
            "query context:  (users / email) / 7u64\nstored context: ((users / email) / 7u64) / 9u128\n"
        );
    }

    #[test]
    fn a_nested_record_prefixes_the_names_of_its_fields() {
        let leaves = name(name(caller_leaf(), "email"), "owner");
        let contexts = resolve(leaves, CallerShape::scope(Placeholder::of::<u64>()));
        assert_eq!(contexts.fields()[0].name(), Some("owner.email"));
    }

    #[test]
    fn leaves_with_one_name_and_one_context_collapse() {
        let piece = ContextPiece::Text(Cow::Borrowed("users"));
        let mut leaves = substitute(caller_leaf(), &Shape::under(piece.clone()));
        leaves.extend(substitute(caller_leaf(), &Shape::under(piece)));
        let contexts = resolve(name(leaves, "email"), CallerShape::none());
        assert_eq!(contexts.fields().len(), 1);
        assert_eq!(contexts.to_string(), "email\n  context: users\n");
    }

    #[test]
    fn contexts_are_read_by_field_name() {
        let leaves = name(caller_leaf(), "email");
        let contexts = resolve(leaves, CallerShape::scope(Placeholder::of::<u64>()));
        assert_eq!(contexts.fields().len(), 1);
        assert_eq!(contexts.fields()[0].name(), Some("email"));
        let expected = LeafContext::one(ContextTree::Placeholder(Placeholder::of::<u64>()));
        assert_eq!(contexts.get("email"), Some(&expected));
        assert_eq!(contexts.get("name"), None);
        assert!(contexts.single().is_none());
        assert!(!contexts.is_empty());

        let unnamed = resolve(caller_leaf(), CallerShape::scope(Placeholder::of::<u64>()));
        assert_eq!(unnamed.single(), Some(&expected));
        assert_eq!(unnamed.fields()[0].name(), None);

        let none = resolve(Vec::new(), CallerShape::none());
        assert!(none.is_empty());
        assert_eq!(none.to_string(), "no field is sealed or indexed\n");
    }

    #[test]
    fn a_caller_that_supplies_nothing_leaves_a_bare_leaf_as_the_unit_context() {
        let contexts = resolve(caller_leaf(), CallerShape::none());
        assert_eq!(contexts.to_string(), "context: ()\n");
    }

    #[test]
    fn the_supplied_context_of_each_input_is_what_the_caller_passes() {
        assert_eq!(NoCallerContext::supplies(), CallerShape::none());
        assert_eq!(DeclaredScopes::supplies(), CallerShape::none());
        assert_eq!(
            DeclaredContext::supplies(),
            CallerShape::scope(Placeholder::optional("scope", "CallerContext"))
        );
        assert_eq!(
            RequiredContext::<u64>::supplies(),
            CallerShape::scope(Placeholder::required("context", "u64"))
        );
        assert_eq!(
            RequiredContext::<Scope<u64>>::supplies(),
            CallerShape::scope(Placeholder::scope::<u64>())
        );
        assert_eq!(
            RequiredContext::<Parts<Scope<u64>, Bind<u128>>>::supplies(),
            CallerShape::both(Placeholder::scope::<u64>(), Placeholder::bind::<u128>())
        );
        assert_eq!(
            RequiredContext::<Parts<Option<Scope<u64>>, Bind<u128>>>::supplies(),
            CallerShape::both(Placeholder::scope::<u64>(), Placeholder::bind::<u128>())
        );
        assert_eq!(
            OptionalContext::<Parts<Option<Scope<u64>>, crate::target::NoBind>>::supplies(),
            CallerShape::scope(Placeholder::scope::<u64>().as_optional())
        );
        assert_eq!(
            OptionalContext::<u64>::supplies(),
            CallerShape::scope(Placeholder::optional("context", "u64"))
        );
        assert_eq!(
            CallerContext::supplies(),
            CallerShape::scope(Placeholder::required("context", "CallerContext"))
        );
        assert_eq!(
            AeadContext::supplies(),
            CallerShape::scope(Placeholder::required("context", "AeadContext"))
        );
        let shape = RequiredContext::<Bind<u128>>::supplies();
        assert!(shape.scope_placeholder().is_none());
        assert_eq!(
            shape.bind_placeholder().map(Placeholder::kind),
            Some(Kind::Bind)
        );
    }

    #[test]
    fn a_label_placeholder_joins_the_identity_it_is_given() {
        let with = substitute(
            caller_leaf(),
            &Shape::under_label(Placeholder::required("context", "Label"), Some("email")),
        );
        assert_eq!(
            resolve(with, CallerShape::none()).to_string(),
            "context: {context: Label} / email\n"
        );
        let without = substitute(
            caller_leaf(),
            &Shape::under_label(Placeholder::required("context", "Label"), None),
        );
        assert_eq!(
            resolve(without, CallerShape::none()).to_string(),
            "context: {context: Label}\n"
        );
    }

    #[test]
    fn call_contexts_list_each_distinct_context_once() {
        let a = "users".into_context().into_owned();
        let b = "orders".into_context().into_owned();
        let call = CallContexts::from_pieces(
            &[
                (a.clone(), a.clone()),
                (a.clone(), a.clone()),
                (b.clone(), b),
            ],
            false,
        );
        assert_eq!(call.contexts().len(), 2);
        assert_eq!(call.to_string(), "context: users\ncontext: orders\n");
        assert!(call.single().is_none());
        assert!(!call.is_empty());

        let one = CallContexts::from_pieces(&[(a.clone(), a.clone())], false);
        assert_eq!(
            one.single(),
            Some(&LeafContext::one(ContextTree::Part(a.clone())))
        );

        let bound = CallContexts::from_pieces(
            &[(
                a.clone(),
                ContextPiece::List(vec![a.clone(), ContextPiece::U128(9)]),
            )],
            false,
        );
        assert_eq!(
            bound.to_string(),
            "query context:  users\nstored context: users / 9u128\n"
        );
        assert!(bound.single().unwrap().has_binding());
        // A ciphertext sealed under the same stored context is the other
        // half of that field, not a context of its own.
        let stored = ContextPiece::List(vec![a.clone(), ContextPiece::U128(9)]);
        let with_ciphertext = CallContexts::from_pieces(
            &[(stored.clone(), stored.clone()), (a.clone(), stored)],
            false,
        );
        assert_eq!(with_ciphertext, bound);

        let none = CallContexts::from_pieces(&[], false);
        assert!(none.is_empty());
        assert!(none.single().is_none());
        assert!(!none.has_failed());
        assert_eq!(
            none.to_string(),
            "no context: the call seals and indexes nothing\n"
        );
        let failed = CallContexts::from_pieces(&[], true);
        assert!(failed.has_failed());
        assert_eq!(
            failed.to_string(),
            "no context: the call has failed; await it for the error\n"
        );
    }

    /// A call that has failed before any key was requested says so, and
    /// one that has not does not.
    #[test]
    fn a_call_knows_whether_it_has_failed() {
        let live = CallContexts::from_pieces(&[], false);
        assert!(!live.has_failed());
        let failed = CallContexts::from_pieces(&[], true);
        assert!(failed.has_failed());
    }
}
