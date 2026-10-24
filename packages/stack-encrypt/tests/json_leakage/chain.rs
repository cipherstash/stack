//! The token chain's two public hash functions, written out from the design
//! rather than imported, because both sides of the harness need them on
//! bytes they observe: the database's half of the walk recomputes them over
//! a stored row's `iv`, a token it was sent and the selectors it holds, and
//! the simulator programs its random tags with them.
//!
//! These are the only functions of the real scheme the harness evaluates.
//! Everything keyed (selectors, value selectors, head tokens, member ranks)
//! stays on the client and is replaced by randomness in the simulator.
//! `the_harness_chain_is_the_crates_chain` (in `calibration.rs`) holds these
//! two to the crate's own walk, `JsonDocument::subtree`.

use sha2::{Digest, Sha256};

/// A sixteen-byte tag: a selector, a value selector or a token.
pub type Tag16 = [u8; 16];

/// An eight-byte parent tag.
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

/// `H8("p" ‖ iv ‖ t(parent) ‖ LE32(o))`: the parent tag of the child at
/// ordinal `o` under the node whose token is `parent`.
pub fn parent_tag(iv: &Tag16, parent: &Tag16, ordinal: u32) -> Tag8 {
    let full = sha256(&[b"p", iv, parent, &ordinal.to_le_bytes()]);
    let mut tag = [0; 8];
    tag.copy_from_slice(&full[..8]);
    tag
}

/// `H16("t" ‖ t(parent) ‖ s(child) ‖ LE32(o))`: the token of the child at
/// ordinal `o`, whose selector is `selector`.
pub fn child_token(parent: &Tag16, selector: &Tag16, ordinal: u32) -> Tag16 {
    let full = sha256(&[b"t", parent, selector, &ordinal.to_le_bytes()]);
    let mut tag = [0; 16];
    tag.copy_from_slice(&full[..16]);
    tag
}

/// The simulator's stand-in for the keyed member rank: any keyed function of
/// the parent's token and the member's selector will do, since the real one
/// is a PRF under a key the database never sees. The simulator samples its
/// own `key`.
pub fn simulated_rank(key: &[u8; 32], parent: &Tag16, selector: &Tag16) -> Tag16 {
    let full = sha256(&[b"rank", key, parent, selector]);
    let mut tag = [0; 16];
    tag.copy_from_slice(&full[..16]);
    tag
}
