//! The cascade: how a JSON document's ciphertexts commit to the tree.
//!
//! Every entry is sealed under an AAD that binds, beside its keyset, its
//! column, its key tag, its selector and its stored slot, the
//! [`ChildrenDigest`] of its children: SHA-256 over the AEAD tags of the
//! node's children, in ordinal order (an element's index, a member's place
//! in the random permutation its object drew). A node's AEAD tag covers its
//! own AAD, so it covers its children's tags, which cover theirs: the tag of
//! a node commits to every ciphertext beneath it, in its place. Sealing
//! therefore runs from the leaves up, and opening a node needs its
//! children's tags first.
//!
//! ```text
//!   {"a": 1, "b": [2, 3]}         each node's AAD binds, beside its own
//!                                 fields, the digest of its children's tags:
//!          root
//!         /    \                   root      : H("k" ‖ tag(a) ‖ tag(b))
//!        a      b                 b         : H("k" ‖ tag(b0) ‖ tag(b1))
//!              / \                 a, b0, b1 : H("k")             (leaves)
//!            b0   b1
//!
//!   sealing, leaves up:   b0, b1 ─→ tag(b0), tag(b1) ─→ b ─→ tag(b) ─┐
//!                         a ─────────────────────────────→ tag(a) ─┴→ root
//!
//!   opening, root down:   the root's children are the rows at its parent
//!                         tags, b's the rows at b's; each node opens under
//!                         the digest of the tags of the children found
//!                         beneath it, so a change anywhere below fails the
//!                         node above it.
//! ```
//!
//! `tag(x)` is the last sixteen bytes of `x`'s ciphertext, and `H` is
//! SHA-256. Because `tag(root)` covers `tag(a)` and `tag(b)`, and `tag(b)`
//! covers `tag(b0)` and `tag(b1)`, the root's tag commits to all five
//! ciphertexts in their places.
//!
//! What that proves, for a read that returns a node and everything beneath
//! it: the rows beneath the node are exactly the ones sealed there, complete,
//! each under the parent it was sealed under and in the order it was sealed
//! in, whatever order the rows arrive in. A row swapped, dropped, added,
//! repeated, reordered or moved under another parent changes a tag on the way
//! up, and the node above the change does not open ([`Error::Aead`]).
//!
//! What it does not prove: the place in the document of the node at the top
//! of a read. That node opens under its own selector and slot, and its label
//! is inside its ciphertext, so the client knows it is a genuine node at the
//! path asked for, but not which one when several share a selector (ADR
//! 0010's allowances: another element's node at depth `0`, another row's
//! entry, withheld rows).
//!
//! Nothing stored changes: the AAD is not stored, and the tag is already the
//! last sixteen bytes of every ciphertext.
//!
//! [`Error::Aead`]: crate::Error::Aead

use sha2::{Digest, Sha256};

/// The digest of a node's children's AEAD tags, bound into the node's AAD.
pub(crate) type ChildrenDigest = [u8; 32];

/// What the digest's input starts with, so it is never the hash of the bare
/// concatenation of the tags.
const CHILDREN_DOMAIN: &[u8] = b"k";

/// How many bytes of an AES-GCM ciphertext are its tag.
const AEAD_TAG_LEN: usize = 16;

/// The AEAD tag of a sealed entry: the last sixteen bytes of its ciphertext,
/// as vitaminc lays a leaf out (`version ‖ nonce ‖ ciphertext ‖ tag`).
/// Public, like the ciphertext it ends. A ciphertext shorter than a tag
/// (which no sealing produces, and which never opens) is taken whole, so it
/// still contributes what it is to its parent's digest.
pub(crate) fn aead_tag(c: &[u8]) -> &[u8] {
    &c[c.len().saturating_sub(AEAD_TAG_LEN)..]
}

/// `SHA-256("k" ‖ tag(c₀) ‖ tag(c₁) ‖ …)` over the ciphertexts of a node's
/// children, in ordinal order. Plain SHA-256, like the chain's other hashes:
/// the tags are public and fixed-width, and nothing secret is hashed.
pub(crate) fn children_digest<'c>(children: impl IntoIterator<Item = &'c [u8]>) -> ChildrenDigest {
    let mut hasher = Sha256::new();
    hasher.update(CHILDREN_DOMAIN);
    for c in children {
        hasher.update(aead_tag(c));
    }
    hasher.finalize().into()
}

/// The digest of no children: what a leaf, an empty container and the sealed
/// root open under. The sealed root's ciphertext is the whole document, and
/// the budget fallback returns it alone, so its AAD covers no other entry:
/// it commits to nothing beneath it, and the chain's heads (which chain from
/// nothing) are each checked only as the node at the top of a read.
pub(crate) fn no_children() -> ChildrenDigest {
    children_digest(std::iter::empty())
}

/// The children of each node, as indices into `parents`, in the order a
/// digest takes them: `parents[i]` is node `i`'s parent and its ordinal under
/// it, `None` for a node that chains from nothing (the root, and the chain's
/// heads under the sealed root).
pub(crate) fn children_of(
    parents: impl IntoIterator<Item = Option<(usize, u32)>>,
) -> Vec<Vec<usize>> {
    let parents: Vec<Option<(usize, u32)>> = parents.into_iter().collect();
    let mut children: Vec<Vec<(u32, usize)>> = vec![Vec::new(); parents.len()];
    for (index, parent) in parents.iter().enumerate() {
        if let Some((parent, ordinal)) = parent {
            if let Some(list) = children.get_mut(*parent) {
                list.push((*ordinal, index));
            }
        }
    }
    children
        .into_iter()
        .map(|mut list| {
            list.sort_unstable();
            list.into_iter().map(|(_, index)| index).collect()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use vitaminc_aead::{Cipher, Context, LocalCipherText};
    use vitaminc_encrypt::{Aes256Cipher, Key};
    use vitaminc_protected::Protected;

    #[test]
    fn the_aead_tag_is_the_last_sixteen_bytes_of_the_ciphertext() {
        let c: Vec<u8> = (0..40).collect();
        assert_eq!(aead_tag(&c), &c[24..]);
        assert_eq!(aead_tag(&c).len(), 16);
        assert_eq!(
            aead_tag(&[1, 2, 3]),
            &[1, 2, 3],
            "shorter than a tag: whole"
        );
        assert_eq!(aead_tag(&[]), &[] as &[u8]);
    }

    /// vitaminc lays a sealed leaf out as `version ‖ nonce ‖ ciphertext ‖
    /// tag`, and GCM's ciphertext is as long as its plaintext: so the last
    /// sixteen bytes are the tag, and flipping any of them, which changes
    /// nothing but the tag, is refused.
    #[test]
    fn a_sealed_leaf_ends_in_its_tag() {
        let cipher = Aes256Cipher::new(&Key::from([9; 32])).unwrap();
        let aad = Context::from_encoded(b"aad");
        let empty = cipher.seal(Protected::new(Vec::new()), &aad).unwrap();
        let five = cipher
            .seal(Protected::new(vec![1, 2, 3, 4, 5]), &aad)
            .unwrap();
        let header = empty.as_ref().len() - AEAD_TAG_LEN;
        assert_eq!(five.as_ref().len(), header + 5 + AEAD_TAG_LEN);
        for at in five.as_ref().len() - AEAD_TAG_LEN..five.as_ref().len() {
            let mut bytes = five.as_ref().to_vec();
            bytes[at] ^= 1;
            assert!(cipher.open(LocalCipherText::from(bytes), &aad).is_err());
        }
    }

    #[test]
    fn the_digest_covers_each_tag_in_order() {
        let a: Vec<u8> = (0..40).collect();
        let b: Vec<u8> = (100..140).collect();
        let ab = children_digest([a.as_slice(), b.as_slice()]);
        let ba = children_digest([b.as_slice(), a.as_slice()]);
        assert_ne!(ab, ba, "order is part of the digest");
        assert_ne!(ab, no_children(), "a container is not a leaf");
        assert_ne!(children_digest([a.as_slice()]), ab, "a dropped child");
        assert_ne!(
            children_digest([a.as_slice(), b.as_slice(), a.as_slice()]),
            ab,
            "an added child"
        );
        let mut tag_flipped = a.clone();
        tag_flipped[39] ^= 0xff;
        assert_ne!(
            children_digest([a.as_slice()]),
            children_digest([tag_flipped.as_slice()])
        );
        // Only the tag is digested: the rest of a ciphertext is covered by
        // the tag itself.
        let mut body_flipped = a.clone();
        body_flipped[0] ^= 0xff;
        assert_eq!(
            children_digest([a.as_slice()]),
            children_digest([body_flipped.as_slice()])
        );
        let mut plain = Sha256::new();
        plain.update(b"k");
        let empty: ChildrenDigest = plain.finalize().into();
        assert_eq!(no_children(), empty, "SHA-256 of the domain alone");
    }

    #[test]
    fn children_are_listed_in_ordinal_order() {
        // 0 is the root; 1 and 3 are its children at ordinals 1 and 0; 2 is
        // 1's child; 4 chains from nothing.
        let children = children_of([None, Some((0, 1)), Some((1, 0)), Some((0, 0)), None]);
        assert_eq!(children, vec![vec![3, 1], vec![2], vec![], vec![], vec![]]);
        assert_eq!(
            children_of([Some((7, 0))]),
            vec![Vec::<usize>::new()],
            "a parent out of range"
        );
    }
}
