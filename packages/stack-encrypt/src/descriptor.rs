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
//! (its [`AadPiece`] tree — text, bytes, integers, lists of those).
//! [`Descriptor::from_piece`] is the one rendering of those parts as a
//! string, and it is **frozen**: ZeroKMS binds the rendered string into the
//! tag, so changing the rendering strands every key issued under the old
//! one.
//!
//! The descriptor follows the context's **parts**, not its encoded bytes.
//! It is injective over encodings — two contexts that encode to different
//! AAD bytes never share a descriptor, so ZeroKMS's binding is at least as
//! strong as the AEAD's — but it is *finer* than the encoding in two named
//! cases, where contexts with identical AAD bytes get different
//! descriptors and ZeroKMS refuses what the AEAD would open:
//!
//! * A pre-encoded [`Aad`](vitaminc_aead::Aad) is one opaque bytes part.
//!   `("tenant", 7u64)` renders `tenant|7u64`; the same tuple passed
//!   through `into_aad()` first renders `b64:` + its encoded bytes.
//! * Different shapes can encode alike: `None::<&str>` (an empty list) and
//!   `0u64` are both eight zero bytes, and render `()` and `0u64`.
//!
//! So a value must be opened under the context in the same **shape** it was
//! sealed under — the structured value both times, or the encoded `Aad`
//! both times — not merely one with the same bytes.

use std::sync::Arc;

use base64ct::{Base64, Encoding};
use vitaminc_aead::{AadPiece, IntoAad};

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
    pub const SEPARATOR: char = '|';

    /// The longest descriptor ZeroKMS accepts, in bytes of the rendered
    /// string: the protocol's [`MAX_DESCRIPTOR_LEN`](stack_kms::MAX_DESCRIPTOR_LEN).
    /// ZeroKMS derives key material over a fixed block of that size holding
    /// the descriptor, so a longer one cannot be bound. Every data-key
    /// request checks its descriptors against this before anything is sent
    /// ([`Error::DescriptorTooLong`](crate::Error::DescriptorTooLong)); a
    /// context is free to be long, but what it renders to must fit — and
    /// the base64 escape grows a part by a third, so an escaped part fits
    /// less than a plain one.
    pub const MAX_LEN: usize = stack_kms::MAX_DESCRIPTOR_LEN;

    /// Render `context` — anything that encodes as AAD — from its parts.
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
    /// // A textual context is its own descriptor.
    /// assert_eq!(Descriptor::of("users/email").as_str(), "users/email");
    ///
    /// // A composite renders its parts in order: a field bound to a row id.
    /// let row = nonempty!("users/email").with(7u64);
    /// assert_eq!(Descriptor::of(row).as_str(), "users/email|7u64");
    /// assert!(Descriptor::of(row).fits());
    ///
    /// // Rendered from the parts, so it follows the encoding: integers are
    /// // sign-blind, an empty part inside a list leaves a mark, and text that
    /// // could read as another form is escaped.
    /// assert_eq!(Descriptor::of(7i64), Descriptor::of(7u64));
    /// assert_eq!(Descriptor::of(Some("")).as_str(), "(b64:)");
    /// assert_eq!(Descriptor::of("a|b").as_str(), "b64:YXxi");
    /// ```
    pub fn of<'a>(context: impl IntoAad<'a>) -> Self {
        Self::from_piece(&context.into_aad_piece())
    }

    /// Render a context's parts.
    ///
    /// # Frozen rendering
    ///
    /// * A **text** part, or a **bytes** part that is UTF-8, renders
    ///   **verbatim** when it is *plain*: non-empty, no control characters,
    ///   none of `|`, `(`, `)`, not beginning with
    ///   [`b64:`](Self::BASE64_PREFIX), and not beginning with an ASCII digit
    ///   or `-`. So a `&str` context — `users/email` — is its own
    ///   descriptor, readable in the ZeroKMS log. Any other text or bytes
    ///   part renders as `b64:` followed by the standard (padded) base64 of
    ///   its bytes; an **empty** part is therefore the bare prefix, `b64:`,
    ///   so `Some("")` is `(b64:)` and `None` is `()`. Text and bytes with
    ///   the same bytes render the same, as they encode the same.
    /// * An **integer** part renders as its encoded bytes read as an
    ///   unsigned number, with the width as a suffix: `7u64`. Integers
    ///   encode as untagged little-endian bytes, so the width is part of the
    ///   rendering and the signedness is not: `7i64` is `7u64`, and `-3i32`
    ///   is `4294967293u32` — the bytes it encodes to.
    /// * A **list** renders its parts joined by [`|`](Self::SEPARATOR). At
    ///   the root, a list of two or more parts has no delimiters —
    ///   `nonempty!("users/email").with(7u64)` is `users/email|7u64` — and
    ///   any other list, nested or of fewer than two parts, is parenthesised:
    ///   `(users/email)`, `()`, `a|(b|c)`.
    /// * At the root, the empty text or bytes part — the `()` AAD, or `""` —
    ///   renders as the empty string, which is what ZeroKMS receives when a
    ///   caller opts out of descriptors.
    ///
    /// The rendering is injective over encodings (the plain-text rule
    /// reserves exactly the characters the other forms begin with or
    /// contain), and finer than the encoding for a pre-encoded `Aad` and for
    /// shapes that happen to encode alike — see the [module docs](self).
    pub fn from_piece(piece: &AadPiece<'_>) -> Self {
        let mut out = String::new();
        Self::render(piece, true, &mut out);
        Self(Arc::from(out))
    }

    fn render(piece: &AadPiece<'_>, root: bool, out: &mut String) {
        match piece {
            AadPiece::Text(text) => Self::render_bytes(text.as_bytes(), root, out),
            AadPiece::Bytes(bytes) => Self::render_bytes(bytes, root, out),
            // Signed and unsigned of one width encode to the same
            // little-endian bytes; `as` reinterprets, so they render the
            // same too.
            AadPiece::U8(v) => Self::render_int(v, "u8", out),
            AadPiece::U16(v) => Self::render_int(v, "u16", out),
            AadPiece::U32(v) => Self::render_int(v, "u32", out),
            AadPiece::U64(v) => Self::render_int(v, "u64", out),
            AadPiece::U128(v) => Self::render_int(v, "u128", out),
            AadPiece::I8(v) => Self::render_int(&(*v as u8), "u8", out),
            AadPiece::I16(v) => Self::render_int(&(*v as u16), "u16", out),
            AadPiece::I32(v) => Self::render_int(&(*v as u32), "u32", out),
            AadPiece::I64(v) => Self::render_int(&(*v as u64), "u64", out),
            AadPiece::I128(v) => Self::render_int(&(*v as u128), "u128", out),
            AadPiece::List(parts) => {
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
            // `AadPiece` is `#[non_exhaustive]`: a part this crate does not
            // know renders by its bytes, which is still injective (the
            // base64 form is reserved) and still binds.
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
                out.push_str(&Base64::encode_string(bytes));
            }
        }
    }

    fn render_int(value: &impl std::fmt::Display, suffix: &str, out: &mut String) {
        use std::fmt::Write as _;
        // Writing to a `String` cannot fail.
        let _ = write!(out, "{value}{suffix}");
    }

    /// Text that renders verbatim: non-empty, and nothing another form
    /// begins with or contains.
    fn is_plain(text: &str) -> bool {
        !text.is_empty()
            && !text.starts_with(Self::BASE64_PREFIX)
            && !text.starts_with(|c: char| c.is_ascii_digit() || c == '-')
            && !text
                .chars()
                .any(|c| c.is_control() || matches!(c, '|' | '(' | ')'))
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
    use vitaminc_aead::Aad;
    use vitaminc_protected::{nonempty, NonEmpty};

    use super::*;

    #[test]
    fn a_textual_context_is_its_own_descriptor() {
        assert_eq!(Descriptor::of("users/email").as_str(), "users/email");
        assert_eq!(
            Descriptor::of(nonempty!("users/email")).as_str(),
            "users/email"
        );
        assert_eq!(
            Descriptor::of(String::from("naïve/ünïcode")).as_str(),
            "naïve/ünïcode"
        );
        assert_eq!(
            Descriptor::of(b"users/email".as_slice()).as_str(),
            "users/email",
            "bytes that are text render as the text they encode to"
        );
        assert_eq!(
            Descriptor::of(Aad::from_slice(b"users/email")).as_str(),
            "users/email",
            "already-encoded AAD renders by its bytes"
        );
    }

    #[test]
    fn the_empty_context_renders_empty() {
        // `()` and `""` encode to the same (empty) bytes: one descriptor.
        assert_eq!(Descriptor::of(()).as_str(), "");
        assert_eq!(Descriptor::of("").as_str(), "");
        assert_eq!(Descriptor::of(b"".as_slice()).as_str(), "");
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
        assert_eq!(Descriptor::of(("", "")).as_str(), "b64:|b64:");
        assert_eq!(
            Descriptor::of(nonempty!("users/email").with(Some(""))).as_str(),
            "users/email|(b64:)"
        );
        assert_eq!(
            Descriptor::of(nonempty!("users/email").with(None::<&str>)).as_str(),
            "users/email|()"
        );
        assert_eq!(
            Descriptor::of(nonempty!("users/email").with("")).as_str(),
            "users/email|b64:"
        );
    }

    #[test]
    fn contexts_that_encode_alike_render_alike() {
        let same = [
            (7u64.into_aad(), Descriptor::of(7u64), Descriptor::of(7i64)),
            (
                (-3i32).into_aad(),
                Descriptor::of(-3i32),
                Descriptor::of(4_294_967_293u32),
            ),
            (
                "users/email".into_aad(),
                Descriptor::of("users/email"),
                Descriptor::of(b"users/email".as_slice()),
            ),
            (().into_aad(), Descriptor::of(()), Descriptor::of("")),
            (
                ("a|b", 7u64).into_aad(),
                Descriptor::of(("a|b", 7u64)),
                Descriptor::of((b"a|b".as_slice(), 7i64)),
            ),
        ];
        for (aad, a, b) in same {
            assert_eq!(a, b, "{a} vs {b} over {:?}", aad.as_bytes());
        }
    }

    #[test]
    fn the_descriptor_is_finer_than_the_encoding_in_two_named_cases() {
        // A pre-encoded `Aad` is one opaque bytes part: the descriptor
        // cannot recover the parts it was built from, so it renders the
        // bytes. Seal and open must present the context in the same shape.
        let structured = Descriptor::of(("tenant", 7u64));
        let encoded = Descriptor::of(("tenant", 7u64).into_aad());
        assert_eq!(structured.as_str(), "tenant|7u64");
        assert!(encoded.as_str().starts_with(Descriptor::BASE64_PREFIX));
        assert_ne!(structured, encoded);

        // Different shapes can encode to the same bytes — an empty list is
        // a zero count, which is eight zero bytes, which is `0u64`. The
        // AEAD cannot tell them apart; the descriptor does.
        assert_eq!(
            None::<&str>.into_aad().as_bytes(),
            0u64.into_aad().as_bytes()
        );
        assert_eq!(Descriptor::of(None::<&str>).as_str(), "()");
        assert_eq!(Descriptor::of(0u64).as_str(), "0u64");
    }

    #[test]
    fn composites_render_their_parts_in_order() {
        assert_eq!(
            Descriptor::of(nonempty!("users/email").with(7u64)).as_str(),
            "users/email|7u64"
        );
        assert_eq!(
            Descriptor::of(NonEmpty::new("users/email").unwrap().with(7u64)),
            Descriptor::of(("users/email", 7u64)),
            "NonEmpty is transparent to the rendering"
        );
        assert_eq!(
            Descriptor::of(("tenant", ("users/email", 7u64))).as_str(),
            "tenant|(users/email|7u64)",
            "a nested list is parenthesised"
        );
        assert_eq!(
            Descriptor::of(Some("users/email")).as_str(),
            "(users/email)",
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
        // The list separator and delimiters.
        assert_eq!(Descriptor::of("a|b").as_str(), "b64:YXxi");
        assert_eq!(Descriptor::of("(a)").as_str(), "b64:KGEp");
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
        // The escape grows a part: 400 bytes of text with a `|` renders as
        // `b64:` + 536 base64 characters.
        let escaped = Descriptor::of(format!("|{}", "a".repeat(399)));
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
        assert_eq!(Descriptor::of(&[0xff, 0xfe][..]).as_str(), "b64://4=");
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
        ];
        for (i, a) in all.iter().enumerate() {
            for (j, b) in all.iter().enumerate() {
                assert_eq!(i == j, a == b, "{a} vs {b}");
            }
        }
    }
}
