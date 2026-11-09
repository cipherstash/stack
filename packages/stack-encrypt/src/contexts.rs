//! The contexts a declaration or a call uses, shown before any key is
//! requested.
//!
//! Every value is sealed under a context, and every search term is derived
//! under one. A wrong context loses data silently: a query under the wrong
//! context matches nothing, and gives no error. So a developer must be able
//! to see the context a declaration will use, and a test must be able to
//! state it.
//!
//! Two views exist:
//!
//! - [`Contexts`], from [`Encryption::contexts`](crate::target::Encryption::contexts).
//!   It lists the context of each field of a declaration. A part the caller
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
//! The `testing` feature adds [`assert_context!`](crate::assert_context),
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
//! | a part the caller supplies | `{context: u64}`; `{extension?: CallerContext}` when optional |
//! | a part read from the plaintext | `{context: NonEmpty<Identifier>, from the plaintext}` |
//!
//! Plain text is text the descriptor renders as it is: no `/`, no brackets,
//! no control characters, and not starting with a digit, a `-`, or `b64:`.
//! Text that would read as another form, starting with `{` or `encoded:`,
//! is quoted too. Quoting escapes `"` and `\` with a backslash, and any
//! other control or non-printing character as `\u{..}`.
//!
//! # What a placeholder stands for
//!
//! A placeholder is one node of the tree, but the part it stands for is
//! not always one part:
//!
//! - A placeholder of type `Label` stands for the label's segments, which
//!   splice into the list around it. `{tenant: Label, from the plaintext} / text`
//!   with the label `tenants/acme` is the flat list `tenants / acme / text`.
//! - An optional placeholder, such as the `{extension?: CallerContext}` of
//!   a plan, stands for no part, one part, or several parts applied in
//!   order, each nesting to the left of the one before.
//!
//! The text is the same once the values are known. The tree is not, so a
//! test that states such a context with [`assert_context!`](crate::assert_context)
//! states the placeholder, not the values.

use std::borrow::Cow;
use std::fmt;
use std::sync::Arc;

use vitaminc_aead::{ContextPiece, IntoAad};

use crate::target::{
    AeadContext, CallerContext, DeclaredContext, DeclaredScopes, NoCallerContext, OptionalContext,
    RequiredContext,
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

/// A part of a context that is not known until the declaration runs.
///
/// A placeholder names the part and its type. The type matters, because
/// `7u64` and `7i64` are different contexts. An optional placeholder stands
/// for a part the caller may leave out, such as the extension a plan accepts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Placeholder {
    name: Cow<'static, str>,
    ty: Cow<'static, str>,
    optional: bool,
    supplier: Supplier,
}

impl Placeholder {
    /// A part the caller must pass.
    pub fn required(name: impl Into<Cow<'static, str>>, ty: impl Into<Cow<'static, str>>) -> Self {
        Self {
            name: name.into(),
            ty: ty.into(),
            optional: false,
            supplier: Supplier::Caller,
        }
    }

    /// A part the caller may pass.
    pub fn optional(name: impl Into<Cow<'static, str>>, ty: impl Into<Cow<'static, str>>) -> Self {
        Self {
            optional: true,
            ..Self::required(name, ty)
        }
    }

    /// A part read from a field of the plaintext.
    pub fn from_plaintext(
        name: impl Into<Cow<'static, str>>,
        ty: impl Into<Cow<'static, str>>,
    ) -> Self {
        Self {
            supplier: Supplier::Plaintext,
            ..Self::required(name, ty)
        }
    }

    /// A required part of type `T`, named `context`. The type is shown
    /// without its module path.
    pub fn of<T: ?Sized>() -> Self {
        Self::required("context", short_type_name::<T>())
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

    /// The one known part of a leaf, for tests.
    #[cfg(test)]
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

/// The context of one field of a declaration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FieldContext {
    name: Option<Arc<str>>,
    context: ContextTree,
}

impl FieldContext {
    /// The name of the field, when the declaration names it. A declaration
    /// of one value has no name.
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// The context the field is sealed and indexed under.
    pub fn context(&self) -> &ContextTree {
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
/// assert_eq!(
///     EncryptedUser::contexts().to_string(),
///     "email\n  context: users / email\nnotes\n  context: users / notes\n",
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

    /// The context of the field named `name`.
    pub fn get(&self, name: &str) -> Option<&ContextTree> {
        self.fields
            .iter()
            .find(|field| field.name.as_deref() == Some(name))
            .map(FieldContext::context)
    }

    /// The one context of a declaration that names no field, such as a
    /// declaration of one value. `None` when the declaration has several
    /// fields, or none.
    pub fn single(&self) -> Option<&ContextTree> {
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
                Some(name) => writeln!(f, "{name}\n  context: {}", field.context)?,
                None => writeln!(f, "context: {}", field.context)?,
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
/// assert_eq!(call.context().to_string(), "context: users / email\n");
/// let _stored = call.await?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// # }).unwrap();
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CallContexts {
    contexts: Vec<ContextTree>,
    failed: bool,
}

impl CallContexts {
    pub(crate) fn from_pieces(pieces: &[ContextPiece<'static>], failed: bool) -> Self {
        let mut contexts: Vec<ContextTree> = Vec::new();
        for piece in pieces {
            let tree = ContextTree::from_piece(piece);
            if !contexts.contains(&tree) {
                contexts.push(tree);
            }
        }
        Self { contexts, failed }
    }

    /// Whether the call has already failed, before any key was requested.
    /// Awaiting it returns the error. A failed call shows no context.
    pub fn has_failed(&self) -> bool {
        self.failed
    }

    /// The distinct contexts, in order.
    pub fn contexts(&self) -> &[ContextTree] {
        &self.contexts
    }

    /// The one context of a call whose leaves share a context. `None` when
    /// the call uses several contexts, or none.
    pub fn single(&self) -> Option<&ContextTree> {
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
            writeln!(f, "context: {context}")?;
        }
        Ok(())
    }
}

/// What the caller supplies to a declaration whose context input is this
/// type: the placeholder that stands for it in [`Contexts`], or `None` when
/// the caller supplies nothing.
///
/// Implemented for the context inputs of the crate. The derives and the
/// plan builder use it to render the root of a declaration. Sealed: a
/// context input is one of this crate's types.
pub trait SuppliedContext: sealed::Sealed {
    /// The placeholder for the caller's part, or `None`.
    fn placeholder() -> Option<Placeholder>;
}

impl SuppliedContext for NoCallerContext {
    fn placeholder() -> Option<Placeholder> {
        None
    }
}
impl SuppliedContext for DeclaredScopes {
    fn placeholder() -> Option<Placeholder> {
        None
    }
}
impl SuppliedContext for DeclaredContext {
    fn placeholder() -> Option<Placeholder> {
        Some(Placeholder::optional("extension", "CallerContext"))
    }
}
impl<C> SuppliedContext for RequiredContext<C> {
    fn placeholder() -> Option<Placeholder> {
        Some(Placeholder::of::<C>())
    }
}
impl<C> SuppliedContext for OptionalContext<C> {
    fn placeholder() -> Option<Placeholder> {
        Some(Placeholder::optional("context", short_type_name::<C>()))
    }
}
impl SuppliedContext for CallerContext {
    fn placeholder() -> Option<Placeholder> {
        Some(Placeholder::of::<Self>())
    }
}
impl SuppliedContext for AeadContext {
    fn placeholder() -> Option<Placeholder> {
        Some(Placeholder::of::<Self>())
    }
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
/// [`context_from`](crate::target::Encryption::context_from)) substitutes
/// [`Caller`](Self::Caller) in the subtree's shapes, exactly where the
/// engine substitutes the context. At the root, `Caller` is the
/// declaration's own input.
#[derive(Clone, Debug)]
pub(crate) enum Shape {
    /// The context this description is handed when it runs.
    Caller,
    /// A part known when the declaration is written.
    Known(ContextPiece<'static>),
    /// A part supplied when the declaration runs.
    Placeholder(Placeholder),
    /// `own`, extended by `by`: what `DeclaredContext::under` and
    /// `Extends::extend` build.
    Under { own: Box<Shape>, by: Box<Shape> },
    /// A list of parts, some of them not known yet: a label the call names
    /// joined to a field's identity.
    List(Vec<Shape>),
    /// The parts of a known extension, applied in order: what a data plan
    /// carries as its extension. Empty when the extension adds nothing.
    #[cfg_attr(not(feature = "dynamic"), allow(dead_code))]
    Parts(Vec<ContextPiece<'static>>),
    /// A caller that supplies nothing.
    Absent,
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

    fn into_tree(self) -> Option<ContextTree> {
        match self {
            // An unsubstituted caller is a caller that supplies nothing.
            Shape::Caller | Shape::Absent => None,
            Shape::Known(piece) => Some(ContextTree::from_piece(&piece)),
            Shape::Placeholder(placeholder) => Some(ContextTree::Placeholder(placeholder)),
            Shape::List(parts) => Some(ContextTree::List(
                parts.into_iter().filter_map(Shape::into_tree).collect(),
            )),
            // Each part extends what came before it, nesting to the left,
            // as `DeclaredContext::under` nests.
            Shape::Under { own, by: parts } if matches!(*parts, Shape::Parts(_)) => {
                let Shape::Parts(parts) = *parts else {
                    unreachable!("matched above")
                };
                let mut tree = own.into_tree();
                for part in parts {
                    let part = ContextTree::from_piece(&part);
                    tree = Some(match tree {
                        Some(tree) => ContextTree::List(vec![tree, part]),
                        None => part,
                    });
                }
                tree
            }
            Shape::Parts(parts) => Shape::Under {
                own: Box::new(Shape::Absent),
                by: Box::new(Shape::Parts(parts)),
            }
            .into_tree(),
            Shape::Under { own, by } => match (own.into_tree(), by.into_tree()) {
                (Some(own), Some(by)) => Some(ContextTree::List(vec![own, by])),
                (Some(own), None) => Some(own),
                (None, Some(by)) => Some(by),
                (None, None) => None,
            },
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
pub(crate) fn resolve(shapes: Shapes, caller: Option<Placeholder>) -> Contexts {
    let caller = match caller {
        Some(placeholder) => Shape::Placeholder(placeholder),
        None => Shape::Absent,
    };
    resolve_with(shapes, &caller)
}

/// [`resolve`] with the caller's parts known: a data plan's extension.
#[cfg_attr(not(feature = "dynamic"), allow(dead_code))]
pub(crate) fn resolve_under(shapes: Shapes, parts: Vec<ContextPiece<'static>>) -> Contexts {
    resolve_with(shapes, &Shape::Parts(parts))
}

fn resolve_with(shapes: Shapes, caller: &Shape) -> Contexts {
    let mut fields: Vec<FieldContext> = Vec::new();
    for leaf in shapes {
        let context = leaf
            .shape
            .substitute(caller)
            .into_tree()
            .unwrap_or(ContextTree::Part(ContextPiece::Unit));
        let field = FieldContext {
            name: leaf.name,
            context,
        };
        if fields.last() != Some(&field) {
            fields.push(field);
        }
    }
    Contexts { fields }
}

#[cfg(test)]
mod tests {
    use super::*;
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
        use vitaminc_aead::IntoContext;
        let column = NonEmpty::<&str>::new("users").unwrap().with("email");
        let tree = ContextTree::from_piece(&column.into_context());
        assert_eq!(tree.to_string(), "users / email");

        let row = ContextTree::from_piece(
            &NonEmpty::<&str>::new("users")
                .unwrap()
                .with("email")
                .with(7u64)
                .into_context(),
        );
        assert_eq!(row.to_string(), "(users / email) / 7u64");

        assert_eq!(
            ContextTree::from_piece(&7i64.into_context()).to_string(),
            "7i64"
        );
        assert_eq!(
            ContextTree::from_piece(&"7".into_context()).to_string(),
            "\"7\""
        );
        // Text that would read as a placeholder or an encoded context is
        // quoted, with this module's own escapes.
        assert_eq!(
            ContextTree::from_piece(&"{context: u64}".into_context()).to_string(),
            "\"{context: u64}\""
        );
        assert_eq!(
            ContextTree::from_piece(&"encoded:0x01".into_context()).to_string(),
            "\"encoded:0x01\""
        );
        // Plain text with quotes renders as it is. Text that is not plain
        // is quoted, and its quotes and backslashes are escaped.
        assert_eq!(
            ContextTree::from_piece(&"say \"hi\"".into_context()).to_string(),
            "say \"hi\""
        );
        assert_eq!(
            ContextTree::from_piece(&"a/\"b\"\\".into_context()).to_string(),
            "\"a/\\\"b\\\"\\\\\""
        );
        assert_eq!(
            ContextTree::from_piece(&"tab\there".into_context()).to_string(),
            "\"tab\\u{9}here\""
        );
        assert_eq!(
            ContextTree::from_piece(&"a\u{200B}b".into_context()).to_string(),
            "\"a\\u{200b}b\""
        );
        assert_eq!(
            ContextTree::from_piece(&b"7".to_vec().into_context()).to_string(),
            "0x37"
        );
        assert_eq!(
            ContextTree::from_piece(&().into_context()).to_string(),
            "()"
        );
        assert_eq!(
            ContextTree::from_piece(&"a/b".into_context()).to_string(),
            "\"a/b\""
        );
    }

    #[test]
    fn placeholders_show_their_name_type_and_optionality() {
        assert_eq!(Placeholder::of::<u64>().to_string(), "{context: u64}");
        assert_eq!(
            Placeholder::optional("extension", "CallerContext").to_string(),
            "{extension?: CallerContext}"
        );
        assert_eq!(
            Placeholder::from_plaintext("column", "Identifier").to_string(),
            "{column: Identifier, from the plaintext}"
        );
    }

    #[test]
    fn a_leaf_under_a_known_context_shows_the_caller_as_an_extension() {
        use vitaminc_aead::IntoContext;
        let own = NonEmpty::<&str>::new("users")
            .unwrap()
            .with("email")
            .into_context()
            .into_owned();
        let leaf = substitute(caller_leaf(), &Shape::under(own));

        let alone = resolve(leaf.clone(), None);
        assert_eq!(alone.to_string(), "context: users / email\n");

        let extended = resolve(leaf, Some(Placeholder::of::<u64>()));
        assert_eq!(
            extended.to_string(),
            "context: (users / email) / {context: u64}\n"
        );
    }

    #[test]
    fn a_known_extension_nests_each_part_to_the_left() {
        use vitaminc_aead::IntoContext;
        let own = NonEmpty::<&str>::new("users")
            .unwrap()
            .with("email")
            .into_context()
            .into_owned();
        let leaf = substitute(caller_leaf(), &Shape::under(own));
        let none = resolve_under(leaf.clone(), vec![]);
        assert_eq!(none.to_string(), "context: users / email\n");
        let two = resolve_under(
            leaf,
            vec![
                7u64.into_context().into_owned(),
                "eu".into_context().into_owned(),
            ],
        );
        assert_eq!(two.to_string(), "context: ((users / email) / 7u64) / eu\n");
    }

    #[test]
    fn a_nested_record_prefixes_the_names_of_its_fields() {
        let leaves = name(name(caller_leaf(), "email"), "owner");
        let contexts = resolve(leaves, Some(Placeholder::of::<u64>()));
        assert_eq!(contexts.fields()[0].name(), Some("owner.email"));
    }

    #[test]
    fn leaves_with_one_name_and_one_context_collapse() {
        let own = ContextPiece::Text(Cow::Borrowed("users"));
        let mut leaves = substitute(caller_leaf(), &Shape::under(own.clone()));
        leaves.extend(substitute(caller_leaf(), &Shape::under(own)));
        let contexts = resolve(name(leaves, "email"), None);
        assert_eq!(contexts.fields().len(), 1);
        assert_eq!(contexts.to_string(), "email\n  context: users\n");
    }

    #[test]
    fn every_integer_width_renders_with_its_own_suffix() {
        use vitaminc_aead::IntoContext;
        fn shown<'a>(value: impl IntoContext<'a>) -> String {
            ContextTree::from_piece(&value.into_context()).to_string()
        }
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
        // A nested list inside a list is bracketed; a known list is a
        // `List`, never a `Part`.
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
        // One part at the root is bracketed, as the descriptor brackets it.
        let one = ContextTree::List(vec![ContextTree::Placeholder(Placeholder::of::<u64>())]);
        assert_eq!(one.to_string(), "({context: u64})");
    }

    #[test]
    fn a_placeholder_reports_its_parts() {
        let placeholder = Placeholder::from_plaintext("column", "Identifier");
        assert_eq!(placeholder.name(), "column");
        assert_eq!(placeholder.type_name(), "Identifier");
        assert!(!placeholder.is_optional());
        assert_eq!(placeholder.supplier(), Supplier::Plaintext);
        let optional = Placeholder::optional("context", "u64");
        assert!(optional.is_optional());
        assert_eq!(optional.supplier(), Supplier::Caller);
    }

    #[test]
    fn contexts_are_read_by_field_name() {
        let leaves = name(caller_leaf(), "email");
        let contexts = resolve(leaves, Some(Placeholder::of::<u64>()));
        assert_eq!(contexts.fields().len(), 1);
        assert_eq!(contexts.fields()[0].name(), Some("email"));
        assert_eq!(
            contexts.get("email"),
            Some(&ContextTree::Placeholder(Placeholder::of::<u64>()))
        );
        assert_eq!(contexts.get("name"), None);
        assert!(
            contexts.single().is_none(),
            "a named field is not a single context"
        );
        assert!(!contexts.is_empty());

        let unnamed = resolve(caller_leaf(), Some(Placeholder::of::<u64>()));
        assert_eq!(
            unnamed.single(),
            Some(&ContextTree::Placeholder(Placeholder::of::<u64>()))
        );
        assert_eq!(unnamed.fields()[0].name(), None);

        let none = resolve(Vec::new(), None);
        assert!(none.is_empty());
        assert_eq!(none.to_string(), "no field is sealed or indexed\n");
    }

    #[test]
    fn a_caller_that_supplies_nothing_leaves_a_bare_leaf_as_the_unit_context() {
        let contexts = resolve(caller_leaf(), None);
        assert_eq!(contexts.to_string(), "context: ()\n");
    }

    #[test]
    fn the_supplied_context_of_each_input_is_what_the_caller_passes() {
        assert_eq!(NoCallerContext::placeholder(), None);
        assert_eq!(DeclaredScopes::placeholder(), None);
        assert_eq!(
            DeclaredContext::placeholder(),
            Some(Placeholder::optional("extension", "CallerContext"))
        );
        assert_eq!(
            RequiredContext::<u64>::placeholder(),
            Some(Placeholder::required("context", "u64"))
        );
        assert_eq!(
            OptionalContext::<u64>::placeholder(),
            Some(Placeholder::optional("context", "u64"))
        );
        assert_eq!(
            CallerContext::placeholder(),
            Some(Placeholder::required("context", "CallerContext"))
        );
        assert_eq!(
            AeadContext::placeholder(),
            Some(Placeholder::required("context", "AeadContext"))
        );
    }

    #[test]
    fn a_label_placeholder_joins_the_identity_it_is_given() {
        let with = substitute(
            caller_leaf(),
            &Shape::under_label(Placeholder::required("context", "Label"), Some("email")),
        );
        assert_eq!(
            resolve(with, None).to_string(),
            "context: {context: Label} / email\n"
        );
        let without = substitute(
            caller_leaf(),
            &Shape::under_label(Placeholder::required("context", "Label"), None),
        );
        assert_eq!(
            resolve(without, None).to_string(),
            "context: {context: Label}\n"
        );
    }

    #[test]
    fn call_contexts_list_each_distinct_context_once() {
        use vitaminc_aead::IntoContext;
        let a = "users".into_context().into_owned();
        let b = "orders".into_context().into_owned();
        let call = CallContexts::from_pieces(&[a.clone(), a.clone(), b], false);
        assert_eq!(call.contexts().len(), 2);
        assert_eq!(call.to_string(), "context: users\ncontext: orders\n");
        assert!(call.single().is_none());
        assert!(!call.is_empty());

        let one = CallContexts::from_pieces(&[a], false);
        assert_eq!(
            one.single(),
            Some(&ContextTree::Part("users".into_context().into_owned()))
        );

        let none = CallContexts::from_pieces(&[], false);
        assert!(none.is_empty());
        assert!(none.single().is_none());
        assert_eq!(
            none.to_string(),
            "no context: the call seals and indexes nothing\n"
        );
    }
}
