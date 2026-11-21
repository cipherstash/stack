//! The token chain's public hash functions, written out from the design
//! rather than imported, because both sides of the harness need them on
//! bytes they observe: the database's half of the walk recomputes them over
//! a stored row's `iv`, a token it was sent and the selectors it holds, and
//! the simulator programs its random tags with them.
//!
//! These are the only functions of the real scheme the harness evaluates,
//! with the layout of a CLLW OPE term ([`cllw_ope`]), which the simulator
//! fills under a key of its own. Everything keyed (selectors, value
//! selectors, head tokens, member ranks, the OPE key) stays on the client
//! and is replaced by randomness in the simulator.
//! `chain_is_the_crates_chain` (in `calibration.rs`) holds them to the
//! crate's own walk, `JsonDocument::subtree`.

use sha2::{Digest, Sha256};

/// A sixteen-byte tag: a selector, a value selector or a token.
pub type Tag16 = [u8; 16];

/// An eight-byte tag: a parent tag `p` or a self tag `x`.
pub type Tag8 = [u8; 8];

fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    let mut out = [0; 32];
    out.copy_from_slice(&hasher.finalize());
    out
}

fn first<const N: usize>(full: [u8; 32]) -> [u8; N] {
    let mut tag = [0; N];
    tag.copy_from_slice(&full[..N]);
    tag
}

/// `H8("p" ‖ iv ‖ t(parent) ‖ LE32(o))`: the parent tag of the child at
/// ordinal `o` under the node whose token is `parent`.
pub fn parent_tag(iv: &Tag16, parent: &Tag16, ordinal: u32) -> Tag8 {
    first(sha256(&[b"p", iv, parent, &ordinal.to_le_bytes()]))
}

/// `H8("x" ‖ iv ‖ t(self))`: the self tag of the node whose token is
/// `token`, by which the database finds that node in a row.
pub fn self_tag(iv: &Tag16, token: &Tag16) -> Tag8 {
    first(sha256(&[b"x", iv, token]))
}

/// `H16("t" ‖ t(parent) ‖ s(member))`: an object member's token. No
/// ordinal, so the client derives it from the path alone.
pub fn member_token(parent: &Tag16, selector: &Tag16) -> Tag16 {
    first(sha256(&[b"t", parent, selector]))
}

/// `H16("t" ‖ t(array) ‖ s(element) ‖ LE32(i))`: an array element's token,
/// `i` its index. This is the pre-#1363 chain's rule for every child, kept
/// for elements, whose ordinal was always their index.
pub fn element_token(array: &Tag16, selector: &Tag16, index: u32) -> Tag16 {
    first(sha256(&[b"t", array, selector, &index.to_le_bytes()]))
}

/// Which rule a hit's self tag matched, as the database tests them: the
/// member rule first, then the element rule with the hit's ordinal.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Rule {
    Member,
    Element,
}

/// The token the database derives for a hit found at `ordinal` under the
/// node whose token is `parent`, and the rule that gave it: the member
/// rule's if the hit's self tag `x` is that token's, else the element
/// rule's if it is that one's, else none
/// (`eql_v4_internal.json_tree_hit_token`).
pub fn hit_token(
    iv: &Tag16,
    parent: &Tag16,
    selector: &Tag16,
    x: Option<&Tag8>,
    ordinal: u32,
) -> Option<(Tag16, Rule)> {
    let x = x?;
    let member = member_token(parent, selector);
    if self_tag(iv, &member) == *x {
        return Some((member, Rule::Member));
    }
    let element = element_token(parent, selector, ordinal);
    (self_tag(iv, &element) == *x).then_some((element, Rule::Element))
}

/// A CLLW OPE term over `bits` under `key`, with the structure
/// `cllw_ore::encrypt_ope_bits` gives it: a leading carry byte, then one
/// byte per bit, a keyed function of the bits before it plus the bit at
/// weight 128, the sums carried from right to left. The keyed function is
/// a stand-in (the real one is a keyed BLAKE3 under the column's key, which
/// the database never sees); the layout is public, and it is what makes two
/// terms agree to within one at every byte before the first bit their
/// plaintexts differ in.
pub fn cllw_ope(key: &[u8; 32], bits: &[bool]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bits.len() + 1);
    out.push(0);
    let mut prefix: Vec<u8> = Vec::with_capacity(bits.len());
    for &bit in bits {
        out.push(sha256(&[b"ope", key, &prefix])[0]);
        prefix.push(u8::from(bit));
    }
    let mut carry = 0u16;
    for (byte, &bit) in out[1..].iter_mut().rev().zip(bits.iter().rev()) {
        let sum = u16::from(*byte) + (u16::from(bit) << 7) + carry;
        *byte = sum as u8;
        carry = sum >> 8;
    }
    out[0] = carry as u8;
    out
}

/// How many leading plaintext bits two CLLW OPE terms show their values
/// share: the bytes after the carry byte before the first that differs by
/// more than one modulo 256, or the shorter term's bit count when there is
/// none. A shared bit's bytes differ only by a carry, zero or one; the first
/// differing bit's by 127 to 129. Terms under two keys share none, but where
/// a front byte ties to within a carry.
pub fn shared_bits(a: &[u8], b: &[u8]) -> usize {
    let bits = a.len().min(b.len()).saturating_sub(1);
    (1..=bits)
        .find(|&k| !matches!(a[k].wrapping_sub(b[k]), 0 | 1 | 255))
        .map_or(bits, |k| k - 1)
}

/// The simulator's stand-in for an object's random member ordinals: ranking
/// the members by a keyed function of the row's `iv`, the parent's token and
/// the member's selector gives, to an observer without `key`, a uniformly
/// random permutation per object per row, which is what the real scheme
/// draws from its generator. The simulator samples its own `key`.
pub fn simulated_rank(key: &[u8; 32], iv: &Tag16, parent: &Tag16, selector: &Tag16) -> Tag16 {
    first(sha256(&[b"rank", key, iv, parent, selector]))
}
