//! A context's *parts*, before framing.
//!
//! [`IntoAad`] hands a consumer the final, PAE-framed byte string of a
//! context and nothing else — exactly what the AEAD wants, and nothing a
//! consumer that needs to *name* the parts can use: a key-management
//! service logging which field a data key was issued for, an audit trail,
//! a structured binding built from the same parts as the AAD. Recovering
//! the parts from the bytes would mean parsing PAE heuristically, which is
//! neither injective nor this crate's contract.
//!
//! [`IntoAad::into_aad_piece`] is the second view: the same context as an
//! [`AadPiece`] tree — text, bytes and integers at the leaves, PAE-framed
//! lists at the branches — which encodes to **exactly** the bytes
//! [`IntoAad::into_aad`] produces. It is a provided method, defaulting to
//! the whole encoding as one opaque `Bytes` leaf, so every context type has
//! a parts view and only the ones that override it expose structure.
//!
//! A [`ContextTag`](crate::ContextTag) hands its cipher a context whose
//! parts view is the whole tree, `List([extra_aad, tag])`, so a backend
//! that logs or binds the parts (a key-management service) reads them
//! straight from what it is given, while a backend that only wants bytes
//! pays nothing for the view.

use std::borrow::Cow;
use std::fmt;

use vitaminc_prf::{IntoPrfContext, PrfContext};
use vitaminc_protected::MaybeEmpty;

use super::{Aad, IntoAad};

/// One part of a context, or a list of parts.
///
/// [`IntoAad::into_aad_piece`] builds one from any context. The tree is a
/// stand-in for the value it was built from: it encodes to the same AAD
/// bytes through [`IntoAad`] and to the same PRF context through
/// [`IntoPrfContext`], so it can be passed anywhere a context is expected
/// (see [the rule below](#a-parts-tree-is-the-same-context-as-the-value-it-came-from)).
/// On the AAD side a list is written into a single buffer, however deeply
/// it nests. [`Display`](fmt::Display) renders a tree so that different
/// trees never print the same, for example `("users/email", 7u64)`, and
/// [`leaves`](Self::leaves) walks the parts in encoding order for a caller
/// that wants to render or bind them itself.
///
/// Integers keep their source type as their variant, so every tree that
/// can be built here encodes without truncation: `U8(7)` is one byte and
/// `U64(7)` is eight, exactly as `7u8` and `7u64` are.
///
/// `PartialEq` compares trees, not encodings. `Text("ab")` and
/// `Bytes(b"ab")` are unequal, as are `U64(7)` and `I64(7)`, even though
/// each pair encodes to the same bytes. To compare what the AEAD
/// authenticates, compare `into_aad().as_bytes()`.
///
/// # A parts tree is the same context as the value it came from
///
/// A context is used in two places: as the associated data an AEAD
/// authenticates ([`IntoAad`]) and as the context a PRF mixes into its key
/// derivation ([`IntoPrfContext`]). [`AadPiece`] implements both, and every
/// built-in context type follows one rule: converting the value gives the
/// same result as converting its parts tree, on both sides.
///
/// ```rust
/// use std::borrow::Cow;
/// use vitaminc_aead::{AadPiece, IntoAad};
/// use vitaminc_prf::IntoPrfContext;
///
/// let x = ("users/email", 7u64);
/// assert_eq!(
///     x.into_aad_piece().into_aad().as_bytes(),
///     x.into_aad().as_bytes()
/// );
/// assert_eq!(x.into_aad_piece().into_prf_context(), x.into_prf_context());
///
/// // A list built at runtime is therefore the same context as the
/// // static value with those parts.
/// let runtime = AadPiece::List(vec![
///     AadPiece::Text(Cow::Borrowed("users/email")),
///     AadPiece::U64(7),
/// ]);
/// assert_eq!(runtime.clone().into_aad().as_bytes(), x.into_aad().as_bytes());
/// assert_eq!(runtime.into_prf_context(), x.into_prf_context());
/// ```
///
/// This matters for a context that arrives as data rather than as a Rust
/// type, for example across an FFI boundary. It needs no mirror type of its
/// own, because a tree with the same parts is the same context:
///
/// - `Some(x)` is the one-element list and `None` is the empty list;
/// - `(a, b)` is the two-element list;
/// - `nonempty!(a).with(b).with(c)` is the nested list `((a, b), c)`;
/// - `()` is [`AadPiece::Unit`].
///
/// A flat list of three or more parts is also a valid context. It has no
/// tuple spelling in Rust, so build it with [`AadPiece::List`] directly.
/// The rule is checked by quickcheck for every built-in context type.
///
/// [`MaybeEmpty`] is implemented by the same rule the static types use, so
/// a tree can be wrapped in [`NonEmpty`](vitaminc_protected::NonEmpty):
/// text and bytes are empty at zero length, unit is empty, an integer never
/// is, and a list is empty only when every part is.
///
/// The enum is `#[non_exhaustive]`. The crate's own derived contexts
/// (`Aad::for_map_entry`, `Aad::for_leaf`, and so on) have no faithful
/// shape here yet, and adding one must not break a downstream `match`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AadPiece<'a> {
    /// Text; encodes as its UTF-8 bytes. `&str`, `String`.
    Text(Cow<'a, str>),
    /// Opaque bytes; encode as themselves. Byte slices and arrays,
    /// `Vec<u8>`, `Cow<[u8]>`, and an already-encoded [`Aad`].
    Bytes(Cow<'a, [u8]>),
    /// The unit context, `()`. Encodes as no bytes at all on the AAD side
    /// and as the empty context on the PRF side. Not the same as empty
    /// bytes, which the PRF side frames, or the empty list, which both
    /// sides frame.
    Unit,
    /// A `u8`; encodes as one little-endian byte, with no type tag — see
    /// the integer [`IntoAad`] impls.
    U8(u8),
    /// A `u16`; two little-endian bytes.
    U16(u16),
    /// A `u32`; four little-endian bytes.
    U32(u32),
    /// A `u64`; eight little-endian bytes.
    U64(u64),
    /// A `u128`; sixteen little-endian bytes.
    U128(u128),
    /// An `i8`; one two's-complement byte.
    I8(i8),
    /// An `i16`; two little-endian two's-complement bytes.
    I16(i16),
    /// An `i32`; four little-endian two's-complement bytes.
    I32(i32),
    /// An `i64`; eight little-endian two's-complement bytes.
    I64(i64),
    /// An `i128`; sixteen little-endian two's-complement bytes.
    I128(i128),
    /// A list of parts; encodes as their PAE. A tuple is the list of its
    /// halves, `Some(x)` the one-element list, `None` the empty list.
    List(Vec<AadPiece<'a>>),
}

impl<'a> AadPiece<'a> {
    /// Copy every borrowed part, so the tree can outlive its source.
    pub fn into_owned(self) -> AadPiece<'static> {
        match self {
            AadPiece::Text(text) => AadPiece::Text(Cow::Owned(text.into_owned())),
            AadPiece::Bytes(bytes) => AadPiece::Bytes(Cow::Owned(bytes.into_owned())),
            AadPiece::Unit => AadPiece::Unit,
            AadPiece::U8(v) => AadPiece::U8(v),
            AadPiece::U16(v) => AadPiece::U16(v),
            AadPiece::U32(v) => AadPiece::U32(v),
            AadPiece::U64(v) => AadPiece::U64(v),
            AadPiece::U128(v) => AadPiece::U128(v),
            AadPiece::I8(v) => AadPiece::I8(v),
            AadPiece::I16(v) => AadPiece::I16(v),
            AadPiece::I32(v) => AadPiece::I32(v),
            AadPiece::I64(v) => AadPiece::I64(v),
            AadPiece::I128(v) => AadPiece::I128(v),
            AadPiece::List(parts) => {
                AadPiece::List(parts.into_iter().map(AadPiece::into_owned).collect())
            }
        }
    }

    /// The non-list parts, depth first, in the order they are encoded.
    /// A leaf piece yields itself; an empty list yields nothing.
    ///
    /// Nesting is dropped, so distinct contexts can share a leaf sequence:
    /// `(("a", 1u8), "b")` and `("a", (1u8, "b"))` both yield `a, 1, b`
    /// while encoding to different bytes. Use this to render or bind the
    /// parts, not to identify the context; the bytes from [`IntoAad`] are
    /// its identity.
    pub fn leaves(&self) -> impl Iterator<Item = &AadPiece<'a>> {
        fn walk<'p, 'a>(piece: &'p AadPiece<'a>, out: &mut Vec<&'p AadPiece<'a>>) {
            match piece {
                AadPiece::List(parts) => parts.iter().for_each(|part| walk(part, out)),
                leaf => out.push(leaf),
            }
        }
        let mut out = Vec::new();
        walk(self, &mut out);
        out.into_iter()
    }

    /// The length of this piece's encoding, without producing it. A list is
    /// `8 + Σ(8 + part)`: the PAE count word plus a length word per part.
    fn encoded_len(&self) -> usize {
        match self {
            AadPiece::Text(text) => text.len(),
            AadPiece::Bytes(bytes) => bytes.len(),
            AadPiece::Unit => 0,
            AadPiece::U8(_) | AadPiece::I8(_) => 1,
            AadPiece::U16(_) | AadPiece::I16(_) => 2,
            AadPiece::U32(_) | AadPiece::I32(_) => 4,
            AadPiece::U64(_) | AadPiece::I64(_) => 8,
            AadPiece::U128(_) | AadPiece::I128(_) => 16,
            AadPiece::List(parts) => {
                8 + parts
                    .iter()
                    .map(|part| 8 + part.encoded_len())
                    .sum::<usize>()
            }
        }
    }

    /// The PAE of `head` followed by this piece, in one allocation: the
    /// bytes `List([Bytes(head), self])` encodes to, without building that
    /// list. `ContextTag` uses it to fold `(extra_aad, tag)` at the cost of
    /// the plain tuple encoding.
    pub(crate) fn pae_after(&self, head: &[u8]) -> Aad<'static> {
        let tail_len = self.encoded_len();
        let len = 8 + (8 + head.len()) + (8 + tail_len);
        let mut buf = Vec::with_capacity(len);
        buf.extend_from_slice(&2u64.to_le_bytes());
        buf.extend_from_slice(&(head.len() as u64).to_le_bytes());
        buf.extend_from_slice(head);
        buf.extend_from_slice(&(tail_len as u64).to_le_bytes());
        self.write_into(&mut buf);
        debug_assert_eq!(buf.len(), len, "encoded_len must equal the bytes written");
        Aad::new_owned(buf)
    }

    /// Appends this piece's encoding to `buf`: the same bytes `into_aad`
    /// produces, written in place so a nested list costs no intermediate
    /// buffers. Lists follow PAE exactly as [`Aad::pae`] does —
    /// `LE64(count) || (LE64(len(part)) || part)*` — which the
    /// `list_encodes_as_pae_of_its_parts` property pins.
    ///
    /// Each part's length word is reserved before the part is written and
    /// filled in after, from the bytes actually produced, so a tree of any
    /// shape is written in one pass. Computing `encoded_len` per part
    /// instead would rescan the subtree at every level, quadratic in depth
    /// for a left-deep list, and `AadPiece` is public, so callers can build
    /// one.
    fn write_into(&self, buf: &mut Vec<u8>) {
        match self {
            AadPiece::Text(text) => buf.extend_from_slice(text.as_bytes()),
            AadPiece::Bytes(bytes) => buf.extend_from_slice(bytes),
            AadPiece::Unit => {}
            AadPiece::U8(v) => buf.extend_from_slice(&v.to_le_bytes()),
            AadPiece::U16(v) => buf.extend_from_slice(&v.to_le_bytes()),
            AadPiece::U32(v) => buf.extend_from_slice(&v.to_le_bytes()),
            AadPiece::U64(v) => buf.extend_from_slice(&v.to_le_bytes()),
            AadPiece::U128(v) => buf.extend_from_slice(&v.to_le_bytes()),
            AadPiece::I8(v) => buf.extend_from_slice(&v.to_le_bytes()),
            AadPiece::I16(v) => buf.extend_from_slice(&v.to_le_bytes()),
            AadPiece::I32(v) => buf.extend_from_slice(&v.to_le_bytes()),
            AadPiece::I64(v) => buf.extend_from_slice(&v.to_le_bytes()),
            AadPiece::I128(v) => buf.extend_from_slice(&v.to_le_bytes()),
            AadPiece::List(parts) => {
                buf.extend_from_slice(&(parts.len() as u64).to_le_bytes());
                for part in parts {
                    let length_word = buf.len();
                    buf.extend_from_slice(&[0u8; 8]);
                    let start = buf.len();
                    part.write_into(buf);
                    let written = (buf.len() - start) as u64;
                    buf[length_word..start].copy_from_slice(&written.to_le_bytes());
                }
            }
        }
    }
}

/// Encodes to the same bytes as the value the tree was built from. A leaf
/// hands its storage to that value's own [`IntoAad`] impl without copying.
/// A list is written into one buffer sized up front, however deeply it
/// nests. The parts tree of a tree is itself.
impl<'a> IntoAad<'a> for AadPiece<'a> {
    fn into_aad_piece(self) -> AadPiece<'a> {
        self
    }

    fn into_aad(self) -> Aad<'a> {
        match self {
            AadPiece::Text(Cow::Borrowed(text)) => text.into_aad(),
            AadPiece::Text(Cow::Owned(text)) => text.into_aad(),
            AadPiece::Bytes(bytes) => bytes.into_aad(),
            AadPiece::Unit => ().into_aad(),
            AadPiece::U8(v) => v.into_aad(),
            AadPiece::U16(v) => v.into_aad(),
            AadPiece::U32(v) => v.into_aad(),
            AadPiece::U64(v) => v.into_aad(),
            AadPiece::U128(v) => v.into_aad(),
            AadPiece::I8(v) => v.into_aad(),
            AadPiece::I16(v) => v.into_aad(),
            AadPiece::I32(v) => v.into_aad(),
            AadPiece::I64(v) => v.into_aad(),
            AadPiece::I128(v) => v.into_aad(),
            list @ AadPiece::List(_) => {
                let len = list.encoded_len();
                let mut buf = Vec::with_capacity(len);
                list.write_into(&mut buf);
                debug_assert_eq!(buf.len(), len, "encoded_len must equal the bytes written");
                Aad::new_owned(buf)
            }
        }
    }
}

/// Derives the same PRF context as the value the tree was built from. A
/// leaf hands itself to the standard type's own [`IntoPrfContext`] impl
/// (text as a `str`, bytes as a `[u8]`, an integer as itself), so each
/// keeps its typed encoding. A list is [`PrfContext::pae`] over its parts,
/// which is exactly how the pair and `Option` impls frame theirs. Nothing
/// is encoded differently here.
impl<'a> IntoPrfContext<'a> for AadPiece<'a> {
    fn into_prf_context(self) -> PrfContext<'a> {
        match self {
            AadPiece::Text(Cow::Borrowed(text)) => text.into_prf_context(),
            AadPiece::Text(Cow::Owned(text)) => text.into_prf_context(),
            AadPiece::Bytes(bytes) => bytes.into_prf_context(),
            AadPiece::Unit => ().into_prf_context(),
            AadPiece::U8(v) => v.into_prf_context(),
            AadPiece::U16(v) => v.into_prf_context(),
            AadPiece::U32(v) => v.into_prf_context(),
            AadPiece::U64(v) => v.into_prf_context(),
            AadPiece::U128(v) => v.into_prf_context(),
            AadPiece::I8(v) => v.into_prf_context(),
            AadPiece::I16(v) => v.into_prf_context(),
            AadPiece::I32(v) => v.into_prf_context(),
            AadPiece::I64(v) => v.into_prf_context(),
            AadPiece::I128(v) => v.into_prf_context(),
            AadPiece::List(parts) => {
                let parts: Vec<PrfContext<'a>> = parts
                    .into_iter()
                    .map(IntoPrfContext::into_prf_context)
                    .collect();
                let pieces: Vec<&[u8]> = parts.iter().map(PrfContext::as_bytes).collect();
                PrfContext::pae(&pieces)
            }
        }
    }
}

/// The same emptiness rule the static types use, applied to the tree. Text
/// and bytes are empty at zero length. Unit is empty. An integer is never
/// empty, because even zero is information the caller chose. A list is
/// empty only when every part is, so `None` and `Some("")` are empty and
/// `("", 7u64)` is not, matching what `Option<T>` and `(A, B)` decide.
impl MaybeEmpty for AadPiece<'_> {
    fn is_empty(&self) -> bool {
        match self {
            AadPiece::Text(text) => text.is_empty(),
            AadPiece::Bytes(bytes) => bytes.is_empty(),
            AadPiece::Unit => true,
            AadPiece::U8(_)
            | AadPiece::U16(_)
            | AadPiece::U32(_)
            | AadPiece::U64(_)
            | AadPiece::U128(_)
            | AadPiece::I8(_)
            | AadPiece::I16(_)
            | AadPiece::I32(_)
            | AadPiece::I64(_)
            | AadPiece::I128(_) => false,
            AadPiece::List(parts) => parts.iter().all(MaybeEmpty::is_empty),
        }
    }
}

/// Renders the tree in Rust literal syntax, and different trees never
/// render the same. Text is quoted and escaped as `Debug` does, integers
/// carry their type suffix, bytes print as `0x`-prefixed hex, unit prints
/// as `()`, a list is parenthesised and comma-separated, and the empty list
/// prints as `None` (the context it is). So `("users/email", 7u64)` prints
/// as `("users/email", 7u64)`.
///
/// Each kind starts differently: `"` for text, a digit or `-` for an
/// integer, `0x` for bytes, `()` for unit, `(` followed by a part for a
/// list, and `None` for the empty list. Integer suffixes keep types of the
/// same width apart, and quoting keeps separators inside text from reading
/// as structure. Two contexts that authenticate different bytes therefore
/// never share a log line.
impl fmt::Display for AadPiece<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AadPiece::Text(text) => write!(f, "{text:?}"),
            AadPiece::Bytes(bytes) => {
                f.write_str("0x")?;
                bytes.iter().try_for_each(|byte| write!(f, "{byte:02x}"))
            }
            AadPiece::Unit => f.write_str("()"),
            AadPiece::U8(v) => write!(f, "{v}u8"),
            AadPiece::U16(v) => write!(f, "{v}u16"),
            AadPiece::U32(v) => write!(f, "{v}u32"),
            AadPiece::U64(v) => write!(f, "{v}u64"),
            AadPiece::U128(v) => write!(f, "{v}u128"),
            AadPiece::I8(v) => write!(f, "{v}i8"),
            AadPiece::I16(v) => write!(f, "{v}i16"),
            AadPiece::I32(v) => write!(f, "{v}i32"),
            AadPiece::I64(v) => write!(f, "{v}i64"),
            AadPiece::I128(v) => write!(f, "{v}i128"),
            AadPiece::List(parts) if parts.is_empty() => f.write_str("None"),
            AadPiece::List(parts) => {
                f.write_str("(")?;
                for (i, part) in parts.iter().enumerate() {
                    if i > 0 {
                        f.write_str(", ")?;
                    }
                    fmt::Display::fmt(part, f)?;
                }
                f.write_str(")")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use quickcheck_macros::quickcheck;
    use vitaminc_protected::NonEmpty;

    use super::*;

    /// The AAD half of the rule: the tree encodes to the value's own AAD bytes.
    fn agrees<'a, T>(value: T) -> bool
    where
        T: IntoAad<'a> + Clone,
    {
        value.clone().into_aad_piece().into_aad().as_bytes() == value.into_aad().as_bytes()
    }

    /// The PRF half of the rule: the tree derives the value's own PRF context.
    fn prf_agrees<'a, T>(value: T) -> bool
    where
        T: IntoAad<'a> + IntoPrfContext<'a> + Clone,
    {
        value.clone().into_aad_piece().into_prf_context() == value.into_prf_context()
    }

    /// Both halves: converting the value and converting its tree give the
    /// same result on both sides.
    fn is_identity<'a, T>(value: T) -> bool
    where
        T: IntoAad<'a> + IntoPrfContext<'a> + Clone,
    {
        agrees(value.clone()) && prf_agrees(value)
    }

    fn text(s: &'static str) -> AadPiece<'static> {
        AadPiece::Text(Cow::Borrowed(s))
    }

    /// The rule from the type docs, checked per built-in context type.
    mod given_a_text_context {
        use super::*;

        #[quickcheck]
        fn both_derivations_agree(s: String) -> bool {
            is_identity(s.as_str()) && is_identity(s)
        }
    }

    mod given_a_bytes_context {
        use super::*;

        #[quickcheck]
        fn both_derivations_agree(b: Vec<u8>) -> bool {
            is_identity(b.as_slice()) && is_identity(Cow::Borrowed(b.as_slice())) && is_identity(b)
        }

        #[test]
        fn fixed_arrays_agree_on_both_derivations() {
            assert!(
                is_identity([1u8, 2, 3]),
                "an owned array is its parts view on both derivations"
            );
            assert!(
                is_identity(&[4u8, 5, 6]),
                "a borrowed array is its parts view on both derivations"
            );
        }

        #[test]
        fn a_raw_aad_agrees_on_the_aad_side() {
            // `Aad` does not implement `IntoPrfContext`, so only the AAD
            // half of the rule applies to it.
            assert!(
                agrees(Aad::from_slice(b"raw")),
                "a raw `Aad` is one opaque `Bytes` leaf"
            );
        }
    }

    mod given_an_integer_context {
        use super::*;

        #[quickcheck]
        fn unsigned_widths_agree_on_both_derivations(
            a: u8,
            b: u16,
            c: u32,
            d: u64,
            e: u128,
        ) -> bool {
            is_identity(a) && is_identity(b) && is_identity(c) && is_identity(d) && is_identity(e)
        }

        #[quickcheck]
        fn signed_widths_agree_on_both_derivations(a: i8, b: i16, c: i32, d: i64, e: i128) -> bool {
            is_identity(a) && is_identity(b) && is_identity(c) && is_identity(d) && is_identity(e)
        }
    }

    mod given_a_composite_context {
        use super::*;

        #[quickcheck]
        fn both_derivations_agree(s: String, n: u64, o: Option<String>, b: Vec<u8>) -> bool {
            // Pairs, options, nesting in both directions, and `NonEmpty`:
            // every shape a runtime list has to be able to express.
            is_identity((s.as_str(), n))
                && is_identity(o.clone())
                && is_identity(((s.as_str(), n), b.as_slice()))
                && is_identity((s.as_str(), (n, b.as_slice())))
                && is_identity(Some((o.clone(), n)))
                && is_identity(Some(Some(n)))
                && is_identity(Option::<(String, u64)>::None)
                && (s.is_empty() || {
                    let proven = NonEmpty::new(s.as_str()).unwrap();
                    is_identity(proven)
                        && is_identity(proven.with(n))
                        && is_identity(proven.with(n).with(o))
                })
        }

        #[test]
        fn fixed_shapes_agree_on_both_derivations() {
            assert!(
                is_identity(Option::<&str>::None),
                "`None` is the empty list on both derivations"
            );
            assert!(
                is_identity(NonEmpty::new("users/email").unwrap()),
                "a proven leaf is transparent on both derivations"
            );
            assert!(
                is_identity(NonEmpty::new(("users/email", 7u64)).unwrap()),
                "a proven pair is transparent on both derivations"
            );
        }
    }

    mod given_a_runtime_list {
        use super::*;

        #[test]
        fn one_part_spells_some() {
            let some = AadPiece::List(vec![AadPiece::U64(7)]);
            assert_eq!(
                some.clone().into_aad_piece(),
                Some(7u64).into_aad_piece(),
                "a list of one is `Some` as a tree"
            );
            assert_eq!(
                some.into_prf_context(),
                Some(7u64).into_prf_context(),
                "a list of one is `Some` as a PRF context"
            );
        }

        #[test]
        fn no_parts_spells_none() {
            let none = AadPiece::List(vec![]);
            assert_eq!(
                none.into_prf_context(),
                Option::<u64>::None.into_prf_context(),
                "the empty list is `None` as a PRF context"
            );
        }

        #[test]
        fn two_parts_spell_the_pair() {
            let pair = AadPiece::List(vec![text("users/age"), AadPiece::U64(7)]);
            assert_eq!(
                pair.into_prf_context(),
                ("users/age", 7u64).into_prf_context(),
                "a list of two is the pair"
            );
        }

        #[test]
        fn two_parts_spell_the_proven_chain() {
            let pair = AadPiece::List(vec![text("users/age"), AadPiece::U64(7)]);
            assert_eq!(
                pair.into_prf_context(),
                NonEmpty::new("users/age")
                    .unwrap()
                    .with(7u64)
                    .into_prf_context(),
                "a list of two is `nonempty!(a).with(b)`"
            );
        }

        #[test]
        fn a_nested_list_spells_the_left_nested_chain() {
            let chained = AadPiece::List(vec![
                AadPiece::List(vec![text("users/age"), AadPiece::U64(7)]),
                text("eu"),
            ]);
            assert_eq!(
                chained.into_prf_context(),
                NonEmpty::new("users/age")
                    .unwrap()
                    .with(7u64)
                    .with("eu")
                    .into_prf_context(),
                "`with` chains nest to the left"
            );
        }

        #[test]
        fn a_flat_list_is_its_own_context_not_a_chain() {
            let flat = AadPiece::List(vec![text("users/age"), AadPiece::U64(7), text("eu")]);
            assert_ne!(
                flat.into_prf_context(),
                NonEmpty::new("users/age")
                    .unwrap()
                    .with(7u64)
                    .with("eu")
                    .into_prf_context(),
                "a flat n-ary list is its own context, not a chain"
            );
        }
    }

    mod given_the_unit_context {
        use super::*;

        #[test]
        fn is_the_unit_leaf() {
            assert_eq!(().into_aad_piece(), AadPiece::Unit, "`()` has its own leaf");
            assert_eq!(AadPiece::Unit.to_string(), "()", "unit prints as `()`");
        }

        #[test]
        fn both_sides_agree_on_its_own() {
            assert!(
                is_identity(()),
                "`()` is no AAD bytes and the empty PRF context"
            );
        }

        #[test]
        fn both_sides_agree_inside_a_composite() {
            // `()` on its own is empty, so it never reaches `NonEmpty`. Inside
            // a pair or a `with` chain it does, so the rule has to hold there.
            assert!(is_identity(("x", ())), "`()` as the second half of a pair");
            assert!(is_identity(((), "x")), "`()` as the first half of a pair");
            assert!(is_identity(Some(())), "`()` inside `Some`");
            assert!(
                is_identity(NonEmpty::new("x").unwrap().with(())),
                "`()` appended with `with`"
            );
            assert!(
                is_identity(NonEmpty::new("x").unwrap().with(Some(()))),
                "`Some(())` appended with `with`"
            );
        }

        #[test]
        fn is_not_empty_bytes_and_not_the_empty_list() {
            // Three different contexts: `()` encodes as no bytes, empty
            // bytes are framed on the PRF side, and the empty list is framed
            // on both. The tree keeps them apart, and so does `Display`.
            let empty_bytes = AadPiece::Bytes(Cow::Borrowed(&[]));
            let none = Option::<()>::None.into_aad_piece();
            assert_ne!(AadPiece::Unit, empty_bytes, "unit is not empty bytes");
            assert_ne!(AadPiece::Unit, none, "unit is not the empty list");
            assert_ne!(
                AadPiece::Unit.into_prf_context(),
                empty_bytes.clone().into_prf_context(),
                "unit and empty bytes are different PRF contexts"
            );
            assert_ne!(
                AadPiece::Unit.into_aad().as_bytes(),
                none.clone().into_aad().as_bytes(),
                "unit and the empty list are different AAD"
            );
            assert_ne!(AadPiece::Unit.to_string(), empty_bytes.to_string());
            assert_ne!(AadPiece::Unit.to_string(), none.to_string());
        }
    }

    mod given_a_tree {
        use super::*;

        #[quickcheck]
        fn a_list_derives_the_pae_of_its_parts(tree: Tree) -> bool {
            // The PRF-side twin of `list_encodes_as_pae_of_its_parts`: a
            // list's PRF context is `LE64(count) || (LE64(len) || part)*`
            // over its parts' PRF contexts, at every level. The expected
            // value is framed by hand here rather than with
            // `PrfContext::pae`, so the test does not share code with the
            // impl it checks.
            fn expected(piece: &AadPiece<'_>) -> Vec<u8> {
                match piece {
                    AadPiece::List(parts) => {
                        let parts: Vec<Vec<u8>> = parts.iter().map(expected).collect();
                        let mut out = (parts.len() as u64).to_le_bytes().to_vec();
                        for part in parts {
                            out.extend_from_slice(&(part.len() as u64).to_le_bytes());
                            out.extend_from_slice(&part);
                        }
                        out
                    }
                    leaf => leaf.clone().into_prf_context().as_bytes().to_vec(),
                }
            }
            tree.0.clone().into_prf_context().as_bytes() == expected(&tree.0).as_slice()
        }
    }

    mod given_emptiness {
        use super::*;

        #[quickcheck]
        fn agrees_with_the_static_types(s: String, n: u64, o: Option<String>) -> bool {
            s.is_empty() == s.as_str().into_aad_piece().is_empty()
                && !n.into_aad_piece().is_empty()
                && o.is_empty() == o.clone().into_aad_piece().is_empty()
                && (s.as_str(), n).is_empty() == (s.as_str(), n).into_aad_piece().is_empty()
                && (o.clone(), s.as_str()).is_empty() == (o, s.as_str()).into_aad_piece().is_empty()
        }

        #[test]
        fn fixed_shapes_follow_the_static_rule() {
            assert!(AadPiece::List(vec![]).is_empty(), "the empty list is empty");
            assert!(
                AadPiece::List(vec![text("")]).is_empty(),
                "a list of empty parts is empty"
            );
            assert!(
                !AadPiece::List(vec![text(""), AadPiece::U64(0)]).is_empty(),
                "an integer part makes a list non-empty, even zero"
            );
            assert!(
                !AadPiece::List(vec![AadPiece::List(vec![AadPiece::Bytes(Cow::Borrowed(
                    b"x"
                ))])])
                .is_empty(),
                "emptiness looks through nested lists"
            );
            assert!(
                NonEmpty::new(AadPiece::List(vec![AadPiece::U8(0)])).is_ok(),
                "a tree with an integer is provable non-empty"
            );
            assert!(
                NonEmpty::new(text("")).is_err(),
                "an empty text leaf is not provable non-empty"
            );
        }
    }

    #[test]
    fn a_composite_context_names_its_parts() {
        let piece = ("users/email", 7u64).into_aad_piece();
        assert_eq!(
            piece,
            AadPiece::List(vec![
                AadPiece::Text(Cow::Borrowed("users/email")),
                AadPiece::U64(7),
            ])
        );
        assert_eq!(piece.to_string(), "(\"users/email\", 7u64)");
    }

    #[test]
    fn integers_keep_their_type() {
        assert_eq!(7u32.into_aad_piece(), AadPiece::U32(7));
        assert_eq!((-7i16).into_aad_piece(), AadPiece::I16(-7));
        // Distinct widths, distinct bytes — as for `IntoAad`.
        assert_ne!(
            7u32.into_aad_piece().into_aad().as_bytes(),
            7u64.into_aad_piece().into_aad().as_bytes()
        );
    }

    #[test]
    fn options_are_lists() {
        assert_eq!(
            Option::<&str>::None.into_aad_piece(),
            AadPiece::List(vec![])
        );
        assert_eq!(
            Some("a").into_aad_piece(),
            AadPiece::List(vec![AadPiece::Text(Cow::Borrowed("a"))])
        );
        assert_eq!(Option::<&str>::None.into_aad_piece().to_string(), "None");
        assert_eq!(Some("a").into_aad_piece().to_string(), "(\"a\")");
    }

    #[test]
    fn equality_is_tree_identity_not_encoding_identity() {
        // Pinned because the type doc promises it: `==` tells trees apart
        // that the AEAD would not.
        let pairs: [(AadPiece<'_>, AadPiece<'_>); 2] = [
            ("ab".into_aad_piece(), b"ab".as_slice().into_aad_piece()),
            (7u64.into_aad_piece(), 7i64.into_aad_piece()),
        ];
        for (left, right) in pairs {
            assert_ne!(left, right);
            assert_eq!(left.into_aad().as_bytes(), right.into_aad().as_bytes());
        }
    }

    #[test]
    fn non_empty_is_transparent() {
        assert_eq!(
            NonEmpty::new(("users/email", 7u64))
                .unwrap()
                .into_aad_piece(),
            ("users/email", 7u64).into_aad_piece()
        );
    }

    #[test]
    fn bytes_display_as_hex() {
        assert_eq!(
            [0xdeu8, 0xad, 0xbe, 0xef].into_aad_piece().to_string(),
            "0xdeadbeef"
        );
        assert_eq!(
            Aad::from_slice(b"\x01\x02").into_aad_piece().to_string(),
            "0x0102"
        );
    }

    #[test]
    fn leaves_walk_in_encoding_order_and_drop_nesting() {
        let piece = ((("a", 1u8), Option::<&str>::None), (Some("b"), [9u8])).into_aad_piece();
        let leaves: Vec<String> = piece.leaves().map(ToString::to_string).collect();
        assert_eq!(leaves, ["\"a\"", "1u8", "\"b\"", "0x09"]);
        // A leaf is its own only leaf.
        assert_eq!("x".into_aad_piece().leaves().count(), 1);
        assert_eq!(Option::<&str>::None.into_aad_piece().leaves().count(), 0);
        // Nesting is not recoverable from the leaves, as the doc says.
        let left = (("a", 1u8), "b").into_aad_piece();
        let right = ("a", (1u8, "b")).into_aad_piece();
        assert!(left.leaves().eq(right.leaves()));
        assert_ne!(left.into_aad().as_bytes(), right.into_aad().as_bytes());
    }

    #[test]
    fn display_is_injective_where_it_used_to_collide() {
        // Same width, different type; text that looks like an integer; text
        // that looks like hex; `Some("")` against `None`; `()` against
        // `None`; text containing the separators. Each pair encodes
        // differently and must print differently.
        let pairs: [(AadPiece<'_>, AadPiece<'_>); 6] = [
            (7u64.into_aad_piece(), 7i64.into_aad_piece()),
            (("x", 7u64).into_aad_piece(), ("x", "7").into_aad_piece()),
            ("0xdead".into_aad_piece(), [0xdeu8, 0xad].into_aad_piece()),
            (
                Some("").into_aad_piece(),
                Option::<&str>::None.into_aad_piece(),
            ),
            (().into_aad_piece(), Option::<&str>::None.into_aad_piece()),
            (
                ("a, b", "c").into_aad_piece(),
                ("a", "b, c").into_aad_piece(),
            ),
        ];
        for (left, right) in pairs {
            assert_ne!(left.to_string(), right.to_string());
        }
        assert_eq!(
            ("a, b", (7u8, [1u8])).into_aad_piece().to_string(),
            "(\"a, b\", (7u8, 0x01))"
        );
        assert_eq!(Some("").into_aad_piece().to_string(), "(\"\")");
        assert_eq!((-7i16).into_aad_piece().to_string(), "-7i16");
    }

    /// A random tree, depth-bounded, over every leaf kind, for the
    /// encoding, ownership and rendering properties.
    #[derive(Debug, Clone)]
    struct Tree(AadPiece<'static>);

    impl quickcheck::Arbitrary for Tree {
        fn arbitrary(g: &mut quickcheck::Gen) -> Self {
            fn gen(g: &mut quickcheck::Gen, depth: u8) -> AadPiece<'static> {
                let kinds = if depth == 0 { 13 } else { 14 };
                match u8::arbitrary(g) % kinds {
                    0 => AadPiece::Text(Cow::Owned(String::arbitrary(g))),
                    1 => AadPiece::Bytes(Cow::Owned(Vec::arbitrary(g))),
                    2 => AadPiece::Unit,
                    3 => AadPiece::U8(u8::arbitrary(g)),
                    4 => AadPiece::U16(u16::arbitrary(g)),
                    5 => AadPiece::U32(u32::arbitrary(g)),
                    6 => AadPiece::U64(u64::arbitrary(g)),
                    7 => AadPiece::U128(u128::arbitrary(g)),
                    8 => AadPiece::I8(i8::arbitrary(g)),
                    9 => AadPiece::I16(i16::arbitrary(g)),
                    10 => AadPiece::I32(i32::arbitrary(g)),
                    11 => AadPiece::I64(i64::arbitrary(g)),
                    12 => AadPiece::I128(i128::arbitrary(g)),
                    _ => {
                        let n = usize::arbitrary(g) % 4;
                        AadPiece::List((0..n).map(|_| gen(g, depth - 1)).collect())
                    }
                }
            }
            Tree(gen(g, 3))
        }
    }

    /// One of each variant, for the exhaustive per-arm checks below.
    fn every_kind() -> Vec<AadPiece<'static>> {
        vec![
            AadPiece::Text(Cow::Borrowed("t")),
            AadPiece::Bytes(Cow::Borrowed(b"b")),
            AadPiece::Unit,
            AadPiece::U8(1),
            AadPiece::U16(2),
            AadPiece::U32(3),
            AadPiece::U64(4),
            AadPiece::U128(5),
            AadPiece::I8(-1),
            AadPiece::I16(-2),
            AadPiece::I32(-3),
            AadPiece::I64(-4),
            AadPiece::I128(-5),
            AadPiece::List(vec![AadPiece::U8(9)]),
        ]
    }

    #[test]
    fn every_kind_round_trips_through_into_owned_and_encodes_its_own_bytes() {
        for piece in every_kind() {
            let owned = piece.clone().into_owned();
            assert_eq!(owned, piece, "into_owned must not change the tree");
            assert_eq!(
                owned.into_aad().as_bytes(),
                piece.clone().into_aad().as_bytes(),
                "into_owned must not change the bytes"
            );
            // The single-buffer writer agrees with the leaf's own encoder.
            let mut buf = Vec::new();
            piece.write_into(&mut buf);
            assert_eq!(buf.len(), piece.encoded_len());
            assert_eq!(buf, piece.clone().into_aad().as_bytes());
        }
        let rendered: Vec<String> = every_kind().iter().map(ToString::to_string).collect();
        assert_eq!(
            rendered,
            [
                "\"t\"", "0x62", "()", "1u8", "2u16", "3u32", "4u64", "5u128", "-1i8", "-2i16",
                "-3i32", "-4i64", "-5i128", "(9u8)",
            ]
        );
    }

    #[quickcheck]
    fn into_owned_preserves_any_tree(tree: Tree) -> bool {
        let owned = tree.0.clone().into_owned();
        owned == tree.0 && owned.into_aad().as_bytes() == tree.0.into_aad().as_bytes()
    }

    #[quickcheck]
    fn display_is_injective(a: Tree, b: Tree) -> bool {
        // The rustdoc promise: distinct trees never render alike.
        a.0 == b.0 || a.0.to_string() != b.0.to_string()
    }

    #[quickcheck]
    fn list_encodes_as_pae_of_its_parts(tree: Tree) -> bool {
        // The single-buffer writer must produce exactly what `Aad::pae` over
        // the separately encoded parts produces, at every level.
        fn via_pae(piece: &AadPiece<'static>) -> Aad<'static> {
            match piece {
                AadPiece::List(parts) => {
                    let encoded: Vec<Aad<'static>> = parts.iter().map(via_pae).collect();
                    let refs: Vec<&[u8]> = encoded.iter().map(Aad::as_bytes).collect();
                    Aad::pae(&refs)
                }
                leaf => leaf.clone().into_aad().into_owned(),
            }
        }
        let expected = via_pae(&tree.0);
        let piece = tree.0;
        let len = piece.encoded_len();
        let actual = piece.into_aad();
        actual.as_bytes() == expected.as_bytes() && actual.as_bytes().len() == len
    }

    #[quickcheck]
    fn pae_after_is_the_two_element_list(head: Vec<u8>, tree: Tree) -> bool {
        let expected =
            AadPiece::List(vec![AadPiece::Bytes(Cow::Borrowed(&head)), tree.0.clone()]).into_aad();
        tree.0.pae_after(&head).as_bytes() == expected.as_bytes()
    }

    /// A deep left-nested list, the shape that made per-part `encoded_len`
    /// quadratic, still encodes as PAE at every level and in one pass.
    #[test]
    fn deep_left_nested_lists_encode_as_pae() {
        let mut piece = AadPiece::U8(1);
        for i in 0..=255u8 {
            piece = AadPiece::List(vec![piece, AadPiece::U8(i)]);
        }
        // Reference: encode bottom-up with `Aad::pae`, one level at a time.
        let mut expected = 1u8.into_aad().into_owned();
        for i in 0..=255u8 {
            let leaf = i.into_aad();
            expected = Aad::pae(&[expected.as_bytes(), leaf.as_bytes()]);
        }
        let len = piece.encoded_len();
        let actual = piece.into_aad();
        assert_eq!(actual.as_bytes(), expected.as_bytes());
        assert_eq!(actual.as_bytes().len(), len);
    }

    #[test]
    fn into_owned_preserves_the_tree_and_the_bytes() {
        let text = String::from("users/email");
        let piece = (text.as_str(), 7u64).into_aad_piece();
        let owned: AadPiece<'static> = piece.clone().into_owned();
        assert_eq!(owned, piece);
        assert_eq!(
            owned.into_aad().as_bytes(),
            (text.as_str(), 7u64).into_aad().as_bytes()
        );
    }

    #[test]
    fn a_piece_is_an_aad_wherever_one_is_taken() {
        // The tree stands in for the value: the same encoding either way.
        let from_value = ("users/email", 7u64).into_aad();
        let from_piece = ("users/email", 7u64).into_aad_piece().into_aad();
        assert_eq!(from_value.as_bytes(), from_piece.as_bytes());
        // And a hand-built tree encodes as the value it describes.
        let hand_built = AadPiece::List(vec![
            AadPiece::Text(Cow::Borrowed("users/email")),
            AadPiece::U64(7),
        ]);
        assert_eq!(hand_built.into_aad().as_bytes(), from_value.as_bytes());
    }
}
