//! The ZeroKMS **descriptor**: the context a data key is requested under,
//! rendered as the string ZeroKMS binds and logs.
//!
//! Every data-key request stack-encrypt makes — generate on encrypt,
//! retrieve on decrypt — carries the requesting context as its descriptor.
//! ZeroKMS HMACs the descriptor into the key `tag` it returns and requires
//! the same descriptor to re-derive the key, so a leaf sealed under
//! `users/email` cannot have its key retrieved under `users/name`: the
//! request fails at ZeroKMS, before any key material moves. The descriptor
//! is also what a ZeroKMS retrieval log records per key, which is what
//! makes the field readable in an audit trail. That is the legacy
//! `cipherstash-client` arrangement, on the stable descriptor channel.
//! Lock-context tags and decryption policies are a separate, newer channel
//! that stack-encrypt does not yet use.
//!
//! The descriptor is a string on the wire; a context is a value with parts
//! (its [`ContextPiece`] tree — text, bytes, integers, lists of those).
//! [`Descriptor::from_piece`] is the one rendering of those parts as a
//! string, and it is **frozen**: ZeroKMS binds the rendered string into the
//! tag, so changing the rendering strands every key issued under the old
//! one.
//!
//! Two kinds of value sit under the renderer. A **context** is anything
//! [`IntoContext`] — a literal, a pair, an integer, a `NonEmpty` chain — and
//! is arbitrary: a direct consumer of this crate seals under whatever parts
//! name its data. A [`Describe`] value is one whose parts *are* a descriptor
//! of its own: the identity data is keyed under, returned as the parts of a
//! [`Description`] so the implementor never writes rendered text.
//! [`Label`] is the first-class one — a path of plain segments, written and
//! read as `users/email` — and EQL's identifier (a table and a column) is the
//! same shape. Both are contexts too, through the same parts, so what
//! ZeroKMS binds and what the AEAD seals under never disagree.
//!
//! The descriptor follows the context's **parts**, not its encoded bytes,
//! so it and the AEAD encoding can disagree about whether two contexts are
//! one. They disagree in both directions, each in named cases:
//!
//! * The descriptor is *finer* for a pre-encoded
//!   [`Context`](vitaminc_aead::Context), which is one opaque bytes part.
//!   `("tenant", 7u64)` renders `tenant/7u64`; the same tuple passed
//!   through `into_aad()` first encodes to the same AAD bytes but renders
//!   `b64:` + those bytes. ZeroKMS refuses what the AEAD would open.
//! * The descriptor is *coarser* for shapes that render alike but encode
//!   apart: text and bytes with the same content render the same, and
//!   `7i64` renders as `7u64`, but since vitaminc 0.5 every leaf carries
//!   its type tag, so each pair is two contexts to the AEAD. ZeroKMS
//!   issues one key for both and logs one descriptor; the AEAD still
//!   refuses to open one under the other, so nothing opens that should
//!   not, but the ZeroKMS binding alone does not separate them.
//!
//! So a value must be opened under the context in the same **shape** it was
//! sealed under — the structured value both times, or the encoded `Context`
//! both times, text or bytes as it was sealed — not merely one with the
//! same bytes, and not merely one with the same descriptor.

use std::borrow::Cow;
use std::fmt::Write as _;
use std::sync::Arc;

use base64ct::{Base64Url, Encoding};
use vitaminc_aead::{ContextPiece, IntoAad, IntoContext};
use vitaminc_protected::{MaybeEmpty, NonEmpty};

/// A context rendered as the string sent to ZeroKMS with every data-key
/// request. See the [module docs](self).
///
/// Built from the same value a leaf is sealed under — a
/// [`NonEmpty<T>`](crate::NonEmpty) context on the target-directed path, the
/// caller's AAD on the cipher-directed one — so the descriptor and the leaf
/// AAD always agree.
///
/// One rendering serves every keyed leaf of a tree: the string is shared,
/// so cloning a `Descriptor` into each leaf's request costs a pointer, not
/// a copy, however long the context or large the tree.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Descriptor(Arc<str>);

impl Descriptor {
    /// The prefix that marks a base64-rendered text or byte part. A textual
    /// part that happens to begin with it is base64-rendered too, so the
    /// prefix is unambiguous.
    pub const BASE64_PREFIX: &'static str = "b64:";

    /// The separator between the parts of a list.
    pub const SEPARATOR: char = '/';

    /// The longest descriptor ZeroKMS accepts, in bytes of the rendered
    /// string: the protocol's [`MAX_DESCRIPTOR_LEN`](crate::kms::MAX_DESCRIPTOR_LEN).
    /// ZeroKMS derives key material over a fixed block of that size holding
    /// the descriptor, so a longer one cannot be bound. Every data-key
    /// request checks its descriptors against this before anything is sent
    /// ([`Error::DescriptorTooLong`](crate::Error::DescriptorTooLong)); a
    /// context is free to be long, but what it renders to must fit — and
    /// the base64 escape grows a part by a third, so an escaped part fits
    /// less than a plain one.
    pub const MAX_LEN: usize = stack_kms::MAX_DESCRIPTOR_LEN;

    /// Render `context` — any [`IntoContext`] type — from its parts.
    ///
    /// [`KeysetCipher::encrypt`](crate::KeysetCipher::encrypt) /
    /// [`StackCipher::decrypt`](crate::StackCipher::decrypt) and the target-directed
    /// leaves render the descriptor themselves; call this to see what a
    /// context will look like in the ZeroKMS log, or to check that it
    /// [`fits`](Self::fits) before sealing a large batch under it.
    ///
    /// ```
    /// use stack_encrypt::{nonempty, Descriptor};
    ///
    /// // A table and a column are two parts, joined by `/`.
    /// let column = nonempty!("users").with("email");
    /// assert_eq!(Descriptor::of(column).as_str(), "users/email");
    ///
    /// // A composite renders its parts in order: that column bound to a row
    /// // id. The nested pair is parenthesised.
    /// let row = column.with(7u64);
    /// assert_eq!(Descriptor::of(row).as_str(), "(users/email)/7u64");
    /// assert!(Descriptor::of(row).fits());
    ///
    /// // Rendered from the parts, so it follows the encoding: integers are
    /// // sign-blind, an empty part inside a list leaves a mark, and text that
    /// // could read as another form is escaped.
    /// assert_eq!(Descriptor::of(7i64), Descriptor::of(7u64));
    /// assert_eq!(Descriptor::of(Some("")).as_str(), "(b64:)");
    /// assert_eq!(Descriptor::of("users/email").as_str(), "b64:dXNlcnMvZW1haWw=");
    /// ```
    pub fn of<'a>(context: impl IntoContext<'a>) -> Self {
        Self::from_piece(&context.into_context())
    }

    /// Render a context's parts.
    ///
    /// # Frozen rendering
    ///
    /// * A **text** part, or a **bytes** part that is UTF-8, renders
    ///   **verbatim** when it is *plain*: non-empty, no control characters
    ///   and no invisible format characters (zero-width and bidirectional
    ///   marks, which would print as another name), none of `/`, `(`, `)`,
    ///   not beginning with
    ///   [`b64:`](Self::BASE64_PREFIX), and not beginning with an ASCII digit
    ///   or `-`. So a table and a column are two parts — the pair
    ///   `("users", "email")` renders `users/email`, readable in the ZeroKMS
    ///   log — and a single text part containing `/` is escaped, so it can
    ///   never be mistaken for one. Any other text or bytes part renders as
    ///   `b64:` followed by the URL-safe (padded) base64 of its bytes: the
    ///   standard alphabet's `/` would read as a separator; an **empty** part is therefore the bare prefix, `b64:`,
    ///   so `Some("")` is `(b64:)` and `None` is `()`. Text and bytes with
    ///   the same bytes render the same, though since vitaminc 0.5 they
    ///   encode differently: the rendering is of the parts, not the bytes.
    /// * An **integer** part renders as its little-endian value bytes read
    ///   as an unsigned number, with the width as a suffix: `7u64`. The
    ///   width is part of the rendering and the signedness is not: `7i64`
    ///   is `7u64`, and `-3i32` is `4294967293u32`. Since vitaminc 0.5 the
    ///   leaf's type tag carries the signedness, so `7i64` and `7u64` are
    ///   two contexts to the AEAD; the rendering, frozen before that, does
    ///   not follow.
    /// * A **list** renders its parts joined by [`/`](Self::SEPARATOR). At
    ///   the root, a list of two or more parts has no delimiters —
    ///   `nonempty!("users").with("email")` is `users/email` — and any other
    ///   list, nested or of fewer than two parts, is parenthesised:
    ///   `(users/email)/7u64` for that pair extended with a row id, `()`,
    ///   `a/(b/c)`.
    /// * At the root, the empty text or bytes part — the `()` AAD, or `""` —
    ///   renders as the empty string, which is what ZeroKMS receives when a
    ///   caller opts out of descriptors.
    ///
    /// The forms cannot be mistaken for one another (the plain-text rule
    /// reserves exactly the characters the other forms begin with or
    /// contain), so distinct part trees render apart except where the
    /// rendering is deliberately blind: text against bytes, and signed
    /// against unsigned of one width. A pre-encoded `Context` renders
    /// apart from the parts it was built from. See the [module docs](self).
    pub fn from_piece(piece: &ContextPiece<'_>) -> Self {
        let mut out = String::new();
        Self::render(piece, true, &mut out);
        Self(Arc::from(out))
    }

    fn render(piece: &ContextPiece<'_>, root: bool, out: &mut String) {
        match piece {
            ContextPiece::Text(text) => Self::render_bytes(text.as_bytes(), root, out),
            ContextPiece::Bytes(bytes) => Self::render_bytes(bytes, root, out),
            // Signed and unsigned of one width share their little-endian
            // value bytes; `as` reinterprets, so they render the same. Their
            // type tags differ on the AEAD side; the rendering is frozen
            // and does not follow.
            ContextPiece::U8(v) => Self::render_int(v, "u8", out),
            ContextPiece::U16(v) => Self::render_int(v, "u16", out),
            ContextPiece::U32(v) => Self::render_int(v, "u32", out),
            ContextPiece::U64(v) => Self::render_int(v, "u64", out),
            ContextPiece::U128(v) => Self::render_int(v, "u128", out),
            ContextPiece::I8(v) => Self::render_int(&(*v as u8), "u8", out),
            ContextPiece::I16(v) => Self::render_int(&(*v as u16), "u16", out),
            ContextPiece::I32(v) => Self::render_int(&(*v as u32), "u32", out),
            ContextPiece::I64(v) => Self::render_int(&(*v as u64), "u64", out),
            ContextPiece::I128(v) => Self::render_int(&(*v as u128), "u128", out),
            // A pre-encoded context is one opaque part: its bytes, escaped.
            ContextPiece::Encoded(bytes) => Self::render_bytes(bytes, root, out),
            ContextPiece::List(parts) => {
                let bare = root && parts.len() >= 2;
                if !bare {
                    out.push('(');
                }
                for (i, part) in parts.iter().enumerate() {
                    if i > 0 {
                        out.push(Self::SEPARATOR);
                    }
                    Self::render(part, false, out);
                }
                if !bare {
                    out.push(')');
                }
            }
            // `ContextPiece` is `#[non_exhaustive]`: a part this crate does not
            // know renders by its bytes, which cannot collide with a plain
            // rendering (the base64 form is reserved) and still binds.
            other => Self::render_bytes(other.clone().into_aad().as_bytes(), root, out),
        }
    }

    fn render_bytes(bytes: &[u8], root: bool, out: &mut String) {
        // The empty root is the empty descriptor; an empty part anywhere
        // else must leave a mark, or `Some("")` and `None` would both read
        // `()`. The base64 of nothing is nothing, so the mark is the bare
        // prefix — which no plain text can begin with.
        if bytes.is_empty() && root {
            return;
        }
        match std::str::from_utf8(bytes) {
            Ok(text) if Self::is_plain(text) => out.push_str(text),
            _ => {
                out.push_str(Self::BASE64_PREFIX);
                out.push_str(&Base64Url::encode_string(bytes));
            }
        }
    }

    fn render_int(value: &impl std::fmt::Display, suffix: &str, out: &mut String) {
        // Writing to a `String` cannot fail.
        let _ = write!(out, "{value}{suffix}");
    }

    /// Text that renders verbatim: non-empty, and nothing another form
    /// begins with or contains — exactly what a [`Label`] segment may be.
    /// One definition serves both, so a label always renders verbatim.
    fn is_plain(text: &str) -> bool {
        Label::check_segment(0, text).is_ok()
    }

    /// The rendered string, as sent to ZeroKMS.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The rendered length in bytes — what [`MAX_LEN`](Self::MAX_LEN) bounds.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the rendering is the empty string (the `()` context).
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Whether ZeroKMS can bind this descriptor: its rendered length is at
    /// most [`MAX_LEN`](Self::MAX_LEN).
    pub fn fits(&self) -> bool {
        self.len() <= Self::MAX_LEN
    }

    /// [`fits`](Self::fits) as the error a request path reports: `Ok` to go
    /// on, or the [`DescriptorTooLong`](crate::Error::DescriptorTooLong) that
    /// refuses the whole batch before a single request is built.
    pub(crate) fn check(&self) -> Result<(), crate::Error> {
        if self.fits() {
            Ok(())
        } else {
            Err(crate::Error::DescriptorTooLong { len: self.len() })
        }
    }
}

/// A value with a ZeroKMS descriptor of its own: the identity data is keyed
/// under. See the [module docs](self).
///
/// Implement it for the type that names where a value lives — a table and a
/// column, a document path, a tenant's record kind — and that name is what
/// ZeroKMS binds into the data key and logs on every retrieval. An
/// implementor returns the **parts** of its name as a [`Description`]; it
/// never writes the rendered string. The one renderer,
/// [`Descriptor::from_piece`], turns the parts into the string, so two
/// implementors render alike only when their parts are alike, and a part
/// that contains the separator is escaped rather than read as two. That is
/// what keeps an open trait safe as a key-derivation input: the implementor
/// chooses *what* the identity is, this crate chooses how it is spelled. A
/// `Description` is built from its first part, so a part cannot be forgotten.
/// The parts themselves are not checked: `Description::text("")` is the
/// empty text part and, alone, renders the empty descriptor, which binds no
/// identity, and `Description::part(None::<&str>)` renders `()`. A name
/// taken from a runtime string belongs in a [`Label`], which refuses what
/// would not render as itself; `Description` is for a type whose parts are
/// fixed by its definition.
///
/// A `Describe` type is sealed under as a context through the same parts:
/// [`to_context`](Self::to_context) is the [`ContextPiece`] the type's
/// [`IntoContext`] must return, so the descriptor ZeroKMS binds and the AAD
/// the ciphertext is sealed under are one value seen two ways. [`Label`] is
/// the ready-made implementor, a path of plain segments; EQL's identifier
/// (a table and a column) is the same shape with two.
///
/// ```
/// use stack_encrypt::{ContextPiece, Describe, Description, IntoContext};
///
/// /// A column of a database table.
/// struct Column {
///     table: &'static str,
///     name: &'static str,
/// }
///
/// impl Describe for Column {
///     fn describe(&self) -> Description {
///         Description::text(self.table).then_text(self.name)
///     }
/// }
///
/// // Sealed under as a context through the same two parts.
/// impl<'a> IntoContext<'a> for Column {
///     fn into_context(self) -> ContextPiece<'a> {
///         self.to_context()
///     }
/// }
///
/// let email = Column { table: "users", name: "email" };
/// assert_eq!(email.descriptor().as_str(), "users/email");
/// // A part containing the separator is one part, escaped — never a pair.
/// let odd = Column { table: "users/email", name: "x" };
/// assert_eq!(odd.descriptor().as_str(), "b64:dXNlcnMvZW1haWw=/x");
/// ```
pub trait Describe {
    /// The parts of this value's descriptor, in order, starting from the
    /// first: [`Description::text`] or [`Description::part`], then
    /// [`then_text`](Description::then_text) / [`then`](Description::then).
    fn describe(&self) -> Description;

    /// The parts as one context piece: the single part, or the list of the
    /// parts. What the type's [`IntoContext`] returns, so the AAD and the
    /// descriptor are derived from one tree.
    fn to_context(&self) -> ContextPiece<'static> {
        self.describe().into_context()
    }

    /// The descriptor ZeroKMS binds and logs: [`to_context`](Self::to_context)
    /// rendered by [`Descriptor::from_piece`].
    fn descriptor(&self) -> Descriptor {
        Descriptor::from_piece(&self.to_context())
    }
}

/// The parts of a [`Describe`] value's descriptor: a first part and any
/// number after it.
///
/// It holds parts, never rendered text, so an implementor cannot write a
/// separator, an escape prefix or a parenthesis into the descriptor: each
/// part is rendered by [`Descriptor::from_piece`] under the frozen rules,
/// and text that would read as another form is escaped there. It is built
/// from its first part, so there is no empty description.
///
/// As a context ([`IntoContext`]), one part is that part — a one-segment
/// name is the same context as the bare literal — and two or more are a
/// flat list of them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Description {
    first: ContextPiece<'static>,
    rest: Vec<ContextPiece<'static>>,
}

impl Description {
    /// A description whose first part is text. Plain text (see [`Label`])
    /// renders verbatim; any other text renders escaped.
    pub fn text(first: impl Into<String>) -> Self {
        Self::part(ContextPiece::Text(Cow::Owned(first.into())))
    }

    /// A description whose first part is any context part — an integer, a
    /// bytes part, a nested list — as the context encoding sees it.
    pub fn part<'a>(first: impl IntoContext<'a>) -> Self {
        Self {
            first: first.into_context().into_owned(),
            rest: Vec::new(),
        }
    }

    /// Append a text part.
    pub fn then_text(self, text: impl Into<String>) -> Self {
        self.then(ContextPiece::Text(Cow::Owned(text.into())))
    }

    /// Append any context part.
    pub fn then<'a>(mut self, part: impl IntoContext<'a>) -> Self {
        self.rest.push(part.into_context().into_owned());
        self
    }
}

impl<'a> IntoContext<'a> for Description {
    fn into_context(self) -> ContextPiece<'a> {
        if self.rest.is_empty() {
            self.first
        } else {
            let mut parts = Vec::with_capacity(1 + self.rest.len());
            parts.push(self.first);
            parts.extend(self.rest);
            ContextPiece::List(parts)
        }
    }
}

/// The name of the data a value is sealed under: a table and a column
/// (`users/email`), a document path (`documents/v2/body`), any name a direct
/// consumer of this crate chooses. ZeroKMS binds the data key to that name
/// and writes it in its log, spelled exactly as given. EQL's identifier, a
/// table and a column, is a `Label` of two segments.
///
/// # Naming and scoping
///
/// A context carries two kinds of information, and each has one spelling:
///
/// * A **name** says *what* the data is. Spell it as a `Label`.
/// * A **scope** says *which* slice of that data: a tenant, a row. Spell it
///   by extending the name with [`NonEmpty::with`] (or, on a derived record,
///   by the caller's context, which extends every field's own).
///
/// | What you mean | Spelling | ZeroKMS log |
/// |---|---|---|
/// | the `users.email` column | `Label::parse("users/email")?` | `users/email` |
/// | that column, tenant 7 | `NonEmpty::from(label).with(7u64)` | `(users/email)/7u64` |
/// | a deeper name | `Label::parse("documents/v2/body")?` | `documents/v2/body` |
/// | a one-part name | `Label::parse("users")?`, the same as `nonempty!("users")` | `users` |
///
/// Do not build a name with `with`, and do not put a scope into a `Label`.
/// The renderer keeps the two apart: a name is one flat list, a scope nests.
/// So `(users/email)/7u64` is never read as a three-segment name, and
/// `documents/v2/body` is never read as a scoped column.
///
/// A two-segment `Label` binds the same context a
/// `#[stash(struct = .., context = "<table>")]` derive gives a field, which
/// the derive spells `nonempty!("users").with("email")`. That is what lets a
/// label open a row a derive wrote, and a probe built from the label match
/// the terms the derive produced.
///
/// ```
/// use stack_encrypt::{nonempty, Descriptor, Label, NonEmpty};
///
/// // A name.
/// let email = Label::parse("users/email")?;
/// assert_eq!(email.to_string(), "users/email");
/// assert_eq!(Descriptor::of(&email).as_str(), "users/email");
/// assert_eq!(Label::new(["users", "email"])?, email);
///
/// // The same column, scoped to tenant 7.
/// let tenant_7 = NonEmpty::from(email.clone()).with(7u64);
/// assert_eq!(Descriptor::of(tenant_7).as_str(), "(users/email)/7u64");
///
/// // What a `struct = .., context = "users"` derive binds its `email` field under.
/// assert_eq!(Descriptor::of(&email), Descriptor::of(nonempty!("users").with("email")));
///
/// // Not a label: the separator inside a segment, and an empty segment.
/// assert!(Label::new(["users/email"]).is_err());
/// assert!(Label::parse("users//email").is_err());
/// # Ok::<(), stack_encrypt::LabelError>(())
/// ```
///
/// # Segments
///
/// Every segment is **plain** — non-empty, no control or invisible format
/// characters (zero-width and bidirectional marks), none of
/// `/`, `(`, `)`, not beginning with `b64:`, a digit or `-` — which is
/// exactly the text [`Descriptor::from_piece`] renders verbatim. So a
/// `Label` renders as its segments joined by [`/`](Descriptor::SEPARATOR),
/// its [`Display`](std::fmt::Display) *is* its descriptor, and
/// [`parse`](Self::parse) reads that string back losslessly: no segment can
/// contain the separator, so the split is unambiguous. A string that is not
/// a label is refused with a [`LabelError`] naming the segment, never
/// escaped silently.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Label(Box<[Box<str>]>);

impl Label {
    /// A label from its segments, each checked to be plain.
    pub fn new<I>(segments: I) -> Result<Self, LabelError>
    where
        I: IntoIterator,
        I::Item: AsRef<str>,
    {
        let segments = segments
            .into_iter()
            .enumerate()
            .map(|(index, segment)| {
                let segment = segment.as_ref();
                Self::check_segment(index, segment)?;
                Ok(Box::from(segment))
            })
            .collect::<Result<Box<[Box<str>]>, LabelError>>()?;
        if segments.is_empty() {
            return Err(LabelError::Empty);
        }
        Ok(Self(segments))
    }

    /// A label from its rendered form: segments separated by
    /// [`/`](Descriptor::SEPARATOR). The inverse of
    /// [`Display`](std::fmt::Display).
    pub fn parse(text: &str) -> Result<Self, LabelError> {
        Self::new(text.split(Descriptor::SEPARATOR))
    }

    /// The segments, in order; at least one.
    pub fn segments(&self) -> impl ExactSizeIterator<Item = &str> + '_ {
        self.0.iter().map(|s| &**s)
    }

    /// Whether `segment` is plain, as the error that says why not. This
    /// is the one definition of plain text: [`Descriptor::from_piece`]
    /// renders verbatim exactly what passes here.
    fn check_segment(index: usize, segment: &str) -> Result<(), LabelError> {
        if segment.is_empty() {
            return Err(LabelError::EmptySegment { index });
        }
        if segment.starts_with(Descriptor::BASE64_PREFIX)
            || segment.starts_with(|c: char| c.is_ascii_digit() || c == '-')
        {
            return Err(LabelError::ReservedPrefix { index });
        }
        for found in segment.chars() {
            if found == Descriptor::SEPARATOR {
                return Err(LabelError::Separator { index });
            }
            if found.is_control() || Self::INVISIBLE.contains(&found) || matches!(found, '(' | ')')
            {
                return Err(LabelError::Reserved { index, found });
            }
        }
        Ok(())
    }

    /// Format characters with no glyph of their own: the soft hyphen, the
    /// Arabic letter mark, the Mongolian vowel separator, the zero-width
    /// characters, the bidirectional embeddings, overrides and isolates, and
    /// the byte-order mark. `char::is_control` covers only `Cc`; these are
    /// `Cf`. A name containing one prints like another name in the ZeroKMS
    /// log, which is what a plain segment exists to prevent, so they are
    /// refused beside the control characters. The Go binding carries the
    /// same list, and the shared fixture holds the two together.
    const INVISIBLE: &'static [char] = &[
        '\u{00AD}', '\u{061C}', '\u{180E}', '\u{200B}', '\u{200C}', '\u{200D}', '\u{200E}',
        '\u{200F}', '\u{202A}', '\u{202B}', '\u{202C}', '\u{202D}', '\u{202E}', '\u{2060}',
        '\u{2061}', '\u{2062}', '\u{2063}', '\u{2064}', '\u{2066}', '\u{2067}', '\u{2068}',
        '\u{2069}', '\u{FEFF}',
    ];
}

impl Describe for Label {
    fn describe(&self) -> Description {
        let mut segments = self.segments();
        // A label has at least one segment by construction.
        let first = segments.next().unwrap_or("");
        segments.fold(Description::text(first), Description::then_text)
    }
}

impl<'a> IntoContext<'a> for Label {
    fn into_context(self) -> ContextPiece<'a> {
        self.to_context()
    }
}

impl<'a> IntoContext<'a> for &'a Label {
    fn into_context(self) -> ContextPiece<'a> {
        self.to_context()
    }
}

/// Never empty: a label has at least one non-empty segment.
impl MaybeEmpty for Label {
    fn is_empty(&self) -> bool {
        false
    }
}

/// A label is nonempty by construction, so it needs no runtime check to be
/// the context a target-directed leaf takes.
impl From<Label> for NonEmpty<Label> {
    #[allow(
        clippy::expect_used,
        reason = "NonEmpty::new fails only when MaybeEmpty::is_empty is true, and Label's is_empty is false by definition (directly above); NonEmpty has no unchecked constructor"
    )]
    fn from(label: Label) -> Self {
        NonEmpty::new(label).expect("a label has at least one non-empty segment")
    }
}

impl std::fmt::Display for Label {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (i, segment) in self.segments().enumerate() {
            if i > 0 {
                f.write_char(Descriptor::SEPARATOR)?;
            }
            f.write_str(segment)?;
        }
        Ok(())
    }
}

impl std::str::FromStr for Label {
    type Err = LabelError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::parse(text)
    }
}

/// Why a string is not a [`Label`] segment. `index` is the segment's
/// position, counting from zero.
///
/// A label is schema — a plan's context and its fields' names — so a message
/// may quote the character it refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error, miette::Diagnostic)]
#[non_exhaustive]
pub enum LabelError {
    /// No segments at all.
    #[error("a label needs at least one segment")]
    #[diagnostic(code(stack_encrypt::label_empty))]
    Empty,
    /// The segment is the empty string.
    #[error("label segment {index} is empty")]
    #[diagnostic(code(stack_encrypt::label_empty_segment))]
    EmptySegment { index: usize },
    /// The segment contains the separator, [`/`](Descriptor::SEPARATOR).
    #[error(
        "label segment {index} contains the separator '{}'",
        Descriptor::SEPARATOR
    )]
    #[diagnostic(
        code(stack_encrypt::label_separator),
        help("Give each segment as its own element rather than joining them with `/`.")
    )]
    Separator { index: usize },
    /// The segment contains a control character, an invisible format
    /// character or a parenthesis, which the descriptor reserves.
    #[error("label segment {index} contains {found:?}, which the descriptor reserves")]
    #[diagnostic(code(stack_encrypt::label_reserved))]
    Reserved { index: usize, found: char },
    /// The segment begins like another descriptor form: `b64:`, a digit or
    /// `-`.
    #[error("label segment {index} begins like another descriptor form (`b64:`, a digit or `-`)")]
    #[diagnostic(code(stack_encrypt::label_reserved_prefix))]
    ReservedPrefix { index: usize },
    /// The value a label was read from is not text at all: a number, bytes,
    /// a list or a composite where a context field's value should be a
    /// label such as `tenants/acme`.
    #[error("a label is read from text, and this value is not text")]
    #[diagnostic(code(stack_encrypt::label_not_text))]
    NotText,
}

impl crate::ErrorPayload for LabelError {
    fn payload(&self) -> serde_json::Map<String, serde_json::Value> {
        use crate::diagnostic::payload;
        match self {
            Self::Empty | Self::NotText => serde_json::Map::new(),
            Self::EmptySegment { index }
            | Self::Separator { index }
            | Self::ReservedPrefix { index } => payload([("segment", (*index).into())]),
            Self::Reserved { index, found } => payload([
                ("segment", (*index).into()),
                ("character", found.to_string().into()),
            ]),
        }
    }
}

impl std::fmt::Display for Descriptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for Descriptor {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use vitaminc_aead::Context;
    use vitaminc_protected::{nonempty, NonEmpty};

    use super::*;

    #[test]
    fn a_textual_context_is_its_own_descriptor() {
        assert_eq!(Descriptor::of("users").as_str(), "users");
        assert_eq!(Descriptor::of(nonempty!("users")).as_str(), "users");
        assert_eq!(
            Descriptor::of(String::from("naïve ünïcode")).as_str(),
            "naïve ünïcode"
        );
        assert_eq!(
            Descriptor::of(b"users".as_slice()).as_str(),
            "users",
            "bytes that are text render as the text they encode to"
        );
        assert_eq!(
            Descriptor::of(Context::from_encoded(b"users")).as_str(),
            "users",
            "already-encoded AAD renders by its bytes"
        );
    }

    #[test]
    fn the_empty_context_renders_empty() {
        // `()` and `""` encode to the same (empty) bytes: one descriptor.
        assert_eq!(
            Descriptor::of(()).as_str(),
            "",
            "unit context should render empty"
        );
        assert_eq!(
            Descriptor::of("").as_str(),
            "",
            "empty text should render empty"
        );
        assert_eq!(
            Descriptor::of(b"".as_slice()).as_str(),
            "",
            "empty bytes should render empty"
        );
        assert!(
            Descriptor::of(()).is_empty(),
            "unit context should be empty"
        );
        assert!(
            !Descriptor::of("users/email").is_empty(),
            "textual context should not be empty"
        );
    }

    /// Every view of a descriptor is the one rendering ZeroKMS is sent.
    #[test]
    fn display_and_as_ref_are_the_rendering() {
        let descriptor = Descriptor::of(nonempty!("users").with("email"));
        assert_eq!(descriptor.to_string(), "users/email");
        assert_eq!(AsRef::<str>::as_ref(&descriptor), "users/email");
    }

    #[test]
    fn integers_render_with_their_width_not_their_sign() {
        // Pinned: the rendering is bound into the ZeroKMS key tag, so a change
        // here strands every key generated under the old rendering.
        assert_eq!(Descriptor::of(7u64).as_str(), "7u64");
        assert_eq!(Descriptor::of(7u32).as_str(), "7u32");
        assert_eq!(
            Descriptor::of(u128::MAX).as_str(),
            format!("{}u128", u128::MAX)
        );
        // Signed integers encode to the same bytes as the unsigned of their
        // width, so they render as it: a `7i64` column and a `7u64` column
        // are one context.
        assert_eq!(Descriptor::of(7i64).as_str(), "7u64");
        assert_eq!(Descriptor::of(-3i32).as_str(), "4294967293u32");
        assert_eq!(Descriptor::of(-1i8).as_str(), "255u8");
        assert_eq!(
            Descriptor::of(i128::MIN).as_str(),
            format!("{}u128", i128::MIN as u128)
        );
    }

    #[test]
    fn an_empty_part_leaves_a_mark() {
        // The root empty context is the empty descriptor, but an empty part
        // inside a list must not vanish: `Some("")` and `None` encode
        // differently (a one-element list and an empty one).
        assert_eq!(Descriptor::of(Some("")).as_str(), "(b64:)");
        assert_eq!(Descriptor::of(None::<&str>).as_str(), "()");
        assert_eq!(Descriptor::of(("", "")).as_str(), "b64:/b64:");
        assert_eq!(
            Descriptor::of(nonempty!("users").with(Some(""))).as_str(),
            "users/(b64:)"
        );
        assert_eq!(
            Descriptor::of(nonempty!("users").with(None::<&str>)).as_str(),
            "users/()"
        );
        assert_eq!(
            Descriptor::of(nonempty!("users").with("")).as_str(),
            "users/b64:"
        );
    }

    #[test]
    fn shapes_that_render_alike_are_distinct_contexts() {
        // Text against bytes of one content, and signed against unsigned of
        // one width, render the same: the rendering was frozen before
        // vitaminc 0.5 tagged every leaf with its type. To the AEAD each
        // pair is two contexts, so the descriptor is coarser than the
        // encoding here — see the module docs.
        fn check<'a>(a: impl IntoAad<'a> + Clone, b: impl IntoAad<'a> + Clone) {
            let (da, db) = (Descriptor::of(a.clone()), Descriptor::of(b.clone()));
            assert_eq!(da, db, "expected one descriptor, got {da} vs {db}");
            assert_ne!(
                a.into_aad().as_bytes(),
                b.into_aad().as_bytes(),
                "{da}: expected the AEAD to separate the two shapes"
            );
        }
        check(7u64, 7i64);
        check(-3i32, 4_294_967_293u32);
        check("users", b"users".as_slice());
        check(("a/b", 7u64), (b"a/b".as_slice(), 7i64));

        // The empty root renders as the empty string whatever its shape.
        assert_eq!(
            Descriptor::of(()),
            Descriptor::of(""),
            "the empty context and the empty text both render empty"
        );
    }

    #[test]
    fn the_descriptor_is_finer_than_the_encoding_for_a_pre_encoded_context() {
        // A pre-encoded `Context` is one opaque bytes part: the descriptor
        // cannot recover the parts it was built from, so it renders the
        // bytes. Seal and open must present the context in the same shape.
        let structured = Descriptor::of(("tenant", 7u64));
        let encoded = Descriptor::of(("tenant", 7u64).into_aad());
        assert_eq!(structured.as_str(), "tenant/7u64");
        assert!(encoded.as_str().starts_with(Descriptor::BASE64_PREFIX));
        assert_ne!(structured, encoded);

        // Before vitaminc 0.5, different shapes could encode to the same
        // bytes (an empty list was a zero count, eight zero bytes, `0u64`).
        // Typed leaves closed that: the two now differ on the AEAD side as
        // they always did on the descriptor.
        assert_ne!(
            None::<&str>.into_aad().as_bytes(),
            0u64.into_aad().as_bytes(),
            "typed leaves separate the empty list from 0u64 on the AEAD side"
        );
        assert_eq!(Descriptor::of(None::<&str>).as_str(), "()");
        assert_eq!(Descriptor::of(0u64).as_str(), "0u64");
    }

    #[test]
    fn composites_render_their_parts_in_order() {
        assert_eq!(
            Descriptor::of(nonempty!("users").with("email")).as_str(),
            "users/email"
        );
        assert_eq!(
            Descriptor::of(nonempty!("users").with("email").with(7u64)).as_str(),
            "(users/email)/7u64",
            "`with` nests to the left, so the pair is a parenthesised part"
        );
        assert_eq!(
            Descriptor::of(NonEmpty::new("users").unwrap().with(7u64)),
            Descriptor::of(("users", 7u64)),
            "NonEmpty is transparent to the rendering"
        );
        assert_eq!(
            Descriptor::of(("tenant", (("users", "email"), 7u64))).as_str(),
            "tenant/((users/email)/7u64)",
            "a nested list is parenthesised"
        );
        assert_eq!(
            Descriptor::of(Some("users")).as_str(),
            "(users)",
            "a one-part list is parenthesised even at the root"
        );
        assert_eq!(Descriptor::of(None::<&str>).as_str(), "()");
    }

    #[test]
    fn text_that_could_read_as_another_form_is_escaped() {
        // Control characters.
        assert_eq!(Descriptor::of("a\0b").as_str(), "b64:YQBi");
        assert_eq!(
            Descriptor::of("line\nbreak").as_str(),
            "b64:bGluZQpicmVhaw=="
        );
        // The base64 prefix itself: `b64:YQ==` as *text* must not collide
        // with the rendering of the byte `a`.
        let text = Descriptor::of("b64:YQ==");
        assert_eq!(text.as_str(), "b64:YjY0OllRPT0=");
        assert_ne!(text, Descriptor::of("a"));
        // The list separator and delimiters. A single part containing `/` is
        // escaped, so `"users/email"` can never read as the pair
        // `("users", "email")`.
        assert_eq!(Descriptor::of("a/b").as_str(), "b64:YS9i");
        assert_ne!(
            Descriptor::of("users/email"),
            Descriptor::of(("users", "email")),
        );
        assert_eq!(Descriptor::of("(a)").as_str(), "b64:KGEp");
        // `|` is plain text now; it was the separator before.
        assert_eq!(Descriptor::of("a|b").as_str(), "a|b");
        // A leading digit or sign, which is how an integer begins.
        assert_eq!(Descriptor::of("7u64").as_str(), "b64:N3U2NA==");
        assert_eq!(Descriptor::of("-x").as_str(), "b64:LXg=");
    }

    #[test]
    fn the_limit_is_on_rendered_bytes() {
        // 512 two-byte characters render to 1024 bytes: over, though the
        // context is 512 characters "long".
        assert!(Descriptor::of("a".repeat(512)).fits());
        assert!(!Descriptor::of("a".repeat(513)).fits());
        assert!(!Descriptor::of("ü".repeat(512)).fits());
        assert_eq!(Descriptor::of("ü".repeat(256)).len(), 512);
        // The escape grows a part: 400 bytes of text with a `/` renders as
        // `b64:` + 536 base64 characters.
        let escaped = Descriptor::of(format!("/{}", "a".repeat(399)));
        assert_eq!(escaped.len(), 4 + 536);
        assert!(!escaped.fits());
    }

    #[test]
    fn a_clone_shares_the_rendering() {
        let descriptor = Descriptor::of("a".repeat(Descriptor::MAX_LEN));
        let clone = descriptor.clone();
        assert!(
            std::ptr::eq(descriptor.as_str(), clone.as_str()),
            "a clone must not copy the string: one rendering serves every leaf"
        );
    }

    #[test]
    fn invalid_utf8_renders_base64() {
        // URL-safe base64: the standard alphabet's `//4=` would read as
        // separators.
        assert_eq!(Descriptor::of(&[0xff, 0xfe][..]).as_str(), "b64:__4=");
    }

    #[test]
    fn distinct_encodings_never_share_a_descriptor() {
        let all = [
            Descriptor::of("users/email"),
            Descriptor::of("b64:users/email"),
            Descriptor::of(nonempty!("users/email").with(7u64)),
            Descriptor::of(nonempty!("users/email").with(8u64)),
            Descriptor::of(nonempty!("users/email").with(7u32)),
            Descriptor::of("users/email|7u64"),
            Descriptor::of(("users/email", ("7u64", ()))),
            Descriptor::of(Some("users/email")),
            Descriptor::of("(users/email)"),
            Descriptor::of(None::<&str>),
            Descriptor::of(Some("")),
            Descriptor::of(("", "")),
            Descriptor::of(nonempty!("users/email").with(None::<&str>)),
            Descriptor::of(nonempty!("users/email").with(Some(""))),
            Descriptor::of(nonempty!("users/email").with("")),
            Descriptor::of("()"),
            Descriptor::of("(b64:)"),
            Descriptor::of("b64:"),
            Descriptor::of(7u64),
            Descriptor::of(7u32),
            Descriptor::of(-7i64),
            Descriptor::of(0u64),
            Descriptor::of("7"),
            Descriptor::of(&[0xff, 0xfe][..]),
            Descriptor::of(()),
            // What `/` as the separator must keep apart: a pair from the same
            // text joined, a split moved across the separator, and joined
            // text that spells a nested list.
            Descriptor::of(("users", "email")),
            Descriptor::of(nonempty!("users").with("email").with(7u64)),
            Descriptor::of(("a/b", "c")),
            Descriptor::of(("a", "b/c")),
            Descriptor::of(("a", ("b", "c"))),
            Descriptor::of("(users/email)/7u64"),
            Descriptor::of("a|b"),
        ];
        for (i, a) in all.iter().enumerate() {
            for (j, b) in all.iter().enumerate() {
                assert_eq!(i == j, a == b, "{a} vs {b}");
            }
        }
    }
}

#[cfg(test)]
mod label_tests {
    use std::collections::HashMap;

    use vitaminc_protected::nonempty;

    use super::*;

    fn label(segments: &[&str]) -> Label {
        Label::new(segments).expect("a plain label")
    }

    #[test]
    fn a_label_renders_as_its_display_and_parses_back() {
        for segments in [
            &["users"][..],
            &["users", "email"],
            &["documents", "v2", "body"],
            &["naïve", "ünïcode", "with space"],
        ] {
            let label = label(segments);
            let text = label.to_string();
            assert_eq!(text, segments.join("/"));
            assert_eq!(Descriptor::of(&label).as_str(), text, "{label}");
            assert_eq!(Descriptor::of(label.clone()).as_str(), text, "{label}");
            assert_eq!(label.descriptor().as_str(), text, "{label}");
            assert_eq!(Label::parse(&text).as_ref(), Ok(&label), "{text}");
            assert_eq!(text.parse::<Label>().as_ref(), Ok(&label), "{text}");
        }
    }

    #[test]
    fn a_label_is_the_same_context_as_the_literal_and_the_pair() {
        // One segment is the bare literal; two are the pair a `struct = ..`
        // derive binds. Same parts, so the AEAD and the descriptor agree.
        assert_eq!(label(&["users"]).to_context(), "users".into_context());
        assert_eq!(
            label(&["users", "email"]).to_context(),
            nonempty!("users").with("email").into_context()
        );
        assert_eq!(
            Descriptor::of(label(&["users", "email"])),
            Descriptor::of(nonempty!("users").with("email"))
        );
        // Extended like any head: the row-scoped pair.
        assert_eq!(
            Descriptor::of(NonEmpty::from(label(&["users", "email"])).with(7u64)).as_str(),
            "(users/email)/7u64"
        );
        // Three segments are a flat list, which the nesting chain is not.
        assert_eq!(Descriptor::of(label(&["a", "b", "c"])).as_str(), "a/b/c");
        assert_eq!(
            Descriptor::of(nonempty!("a").with("b").with("c")).as_str(),
            "(a/b)/c"
        );
    }

    #[test]
    fn a_label_never_collides_with_text_that_contains_the_separator() {
        let pair = Descriptor::of(label(&["users", "email"]));
        assert_eq!(pair.as_str(), "users/email");
        assert_ne!(Descriptor::of("users/email"), pair);
        assert_ne!(Descriptor::of(nonempty!("users/email")), pair);
        assert_eq!(
            Label::new(["users/email"]),
            Err(LabelError::Separator { index: 0 })
        );
    }

    #[test]
    fn every_way_a_segment_is_not_plain_is_named() {
        assert_eq!(Label::new(Vec::<&str>::new()), Err(LabelError::Empty));
        assert_eq!(Label::parse(""), Err(LabelError::EmptySegment { index: 0 }));
        assert_eq!(
            Label::parse("users//email"),
            Err(LabelError::EmptySegment { index: 1 })
        );
        assert_eq!(
            Label::parse("users/"),
            Err(LabelError::EmptySegment { index: 1 })
        );
        assert_eq!(
            Label::new(["users", "a/b"]),
            Err(LabelError::Separator { index: 1 })
        );
        assert_eq!(
            Label::new(["b64:x"]),
            Err(LabelError::ReservedPrefix { index: 0 })
        );
        assert_eq!(
            Label::new(["users", "7"]),
            Err(LabelError::ReservedPrefix { index: 1 })
        );
        assert_eq!(
            Label::new(["-x"]),
            Err(LabelError::ReservedPrefix { index: 0 })
        );
        assert_eq!(
            Label::new(["a(b"]),
            Err(LabelError::Reserved {
                index: 0,
                found: '('
            })
        );
        assert_eq!(
            Label::new(["a)b"]),
            Err(LabelError::Reserved {
                index: 0,
                found: ')'
            })
        );
        assert_eq!(
            Label::new(["a\tb"]),
            Err(LabelError::Reserved {
                index: 0,
                found: '\t'
            })
        );
        assert_eq!(
            Label::new(["a\u{85}b"]),
            Err(LabelError::Reserved {
                index: 0,
                found: '\u{85}'
            })
        );
    }

    /// The one fixture both suites read; the Go label test reads the same
    /// file, so the Rust and Go rules cannot drift apart silently.
    fn segment_fixture() -> (Vec<String>, Vec<String>) {
        let json: serde_json::Value =
            serde_json::from_str(include_str!("../tests/fixtures/label_segments.json"))
                .expect("a valid fixture");
        let list = |key: &str| {
            json[key]
                .as_array()
                .expect("an array")
                .iter()
                .map(|v| v.as_str().expect("a string").to_owned())
                .collect::<Vec<_>>()
        };
        (list("plain"), list("not_plain"))
    }

    #[test]
    fn plain_text_and_label_segments_are_one_rule() {
        // The renderer writes verbatim exactly what a label accepts: tie the
        // two so neither can be loosened alone, on the fixture Go reads too.
        let (plain, not_plain) = segment_fixture();
        assert!(!plain.is_empty() && !not_plain.is_empty());
        for text in &plain {
            assert!(Descriptor::is_plain(text), "{text:?}");
            assert!(Label::new([text]).is_ok(), "{text:?}");
            // And verbatim means verbatim: a plain text's descriptor is itself.
            assert_eq!(Descriptor::of(text.as_str()).as_str(), text);
        }
        for text in &not_plain {
            assert!(!Descriptor::is_plain(text), "{text:?}");
            assert!(Label::new([text]).is_err(), "{text:?}");
            if !text.is_empty() {
                assert_ne!(Descriptor::of(text.as_str()).as_str(), text);
            }
        }
    }

    #[test]
    fn distinct_labels_render_apart() {
        // Every label of up to three segments over a small alphabet,
        // including segments that look like each other's joins: no two
        // render the same, and none renders like a literal containing `/`.
        let alphabet = ["a", "b", "ab", "a_b", "ba"];
        let mut seen: HashMap<String, Label> = HashMap::new();
        let mut labels = Vec::new();
        for x in alphabet {
            labels.push(label(&[x]));
            for y in alphabet {
                labels.push(label(&[x, y]));
                for z in alphabet {
                    labels.push(label(&[x, y, z]));
                }
            }
        }
        for l in labels {
            let rendered = Descriptor::of(&l).as_str().to_owned();
            if let Some(other) = seen.insert(rendered.clone(), l.clone()) {
                panic!("{l} and {other} both render {rendered}");
            }
            // A literal spelling the joined string is a different context —
            // except the one-segment label, which *is* the literal.
            if l.segments().len() > 1 {
                assert_ne!(
                    Descriptor::of(rendered.as_str()).as_str(),
                    rendered.as_str(),
                    "{l}"
                );
                assert_ne!(Descriptor::of(rendered.as_str()), Descriptor::of(&l), "{l}");
            } else {
                assert_eq!(Descriptor::of(rendered.as_str()), Descriptor::of(&l), "{l}");
            }
        }
        assert_eq!(seen.len(), 5 + 25 + 125);
    }

    struct Column {
        table: &'static str,
        name: &'static str,
    }

    impl Describe for Column {
        fn describe(&self) -> Description {
            Description::text(self.table).then_text(self.name)
        }
    }

    struct Tenant(u64);

    impl Describe for Tenant {
        fn describe(&self) -> Description {
            Description::text("tenant").then(self.0)
        }
    }

    struct One;

    impl Describe for One {
        fn describe(&self) -> Description {
            Description::text("users")
        }
    }

    #[test]
    fn a_describe_implementor_goes_through_the_one_renderer() {
        let email = Column {
            table: "users",
            name: "email",
        };
        assert_eq!(email.descriptor().as_str(), "users/email");
        assert_eq!(email.descriptor(), label(&["users", "email"]).descriptor());
        assert_eq!(
            Descriptor::from_piece(&email.to_context()),
            email.descriptor()
        );
        // Parts it gives that are not plain are escaped, never read as
        // structure: the implementor cannot smuggle a separator in.
        let odd = Column {
            table: "users/email",
            name: "x",
        };
        assert_eq!(odd.descriptor().as_str(), "b64:dXNlcnMvZW1haWw=/x");
        let paren = Column {
            table: "(users",
            name: "email)",
        };
        assert_eq!(paren.descriptor().as_str(), "b64:KHVzZXJz/b64:ZW1haWwp");
        // Any context part: an integer renders by its width.
        assert_eq!(Tenant(7).descriptor().as_str(), "tenant/7u64");
        // One part is the bare part, the same context as the literal.
        assert_eq!(One.to_context(), "users".into_context());
        assert_eq!(One.descriptor().as_str(), "users");
        // A description starting from a non-text part, and bytes as a part.
        let bytes_first = Description::part(b"users".as_slice()).then_text("email");
        assert_eq!(Descriptor::of(bytes_first).as_str(), "users/email");
        assert_eq!(Descriptor::of(Description::part(7u64)).as_str(), "7u64");
    }

    #[test]
    fn the_rendering_is_frozen() {
        // Golden renderings. Changing any of these re-keys every value ever
        // sealed under the shape, so a change here is a migration, not a
        // refactor.
        let cases: [(ContextPiece<'static>, &str); 11] = [
            ("users".into_context(), "users"),
            (label(&["users", "email"]).to_context(), "users/email"),
            (label(&["a", "b", "c"]).to_context(), "a/b/c"),
            (
                NonEmpty::from(label(&["users", "email"]))
                    .with(7u64)
                    .into_context(),
                "(users/email)/7u64",
            ),
            (nonempty!("a").with("b").with("c").into_context(), "(a/b)/c"),
            ("users/email".into_context(), "b64:dXNlcnMvZW1haWw="),
            (7u64.into_context(), "7u64"),
            ((-3i32).into_context(), "4294967293u32"),
            // A list inside a description nests, as it does anywhere: an
            // implementor that returns one does not get a flat label.
            (
                Description::text("a")
                    .then(nonempty!("b").with("c"))
                    .into_context(),
                "a/(b/c)",
            ),
            // A description's parts are not checked: the empty text part
            // alone is the empty descriptor, and an absent part is `()`.
            (Description::text(String::new()).into_context(), ""),
            (Description::part(None::<&str>).into_context(), "()"),
        ];
        for (piece, want) in cases {
            assert_eq!(Descriptor::from_piece(&piece).as_str(), want);
        }
    }
}
