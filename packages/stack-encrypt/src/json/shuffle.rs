//! The JSON index's random permutations: the slots a document's entries are
//! stored at, the ordinals of an object's members, the order of the pairs
//! and groups of a stored selector set `q`, and the order a containment
//! query sends its selectors in.
//!
//! Each permutation is uniformly random, drawn when the document is sealed
//! or the query derived, and then thrown away. Nothing reads one back: the
//! server finds entries by their tags and reads `q` as sets (`jsonb @>`),
//! and the client places a read's rows by the chain and checks them by the
//! cascade ([`cascade`](super::cascade)). So a permutation is derived from
//! nothing, keyed or not: anything it were derived from would have to be
//! kept from the database, and nothing is gained by being able to recompute
//! it. What the permutations hide, and what no order can hide, is on the
//! leakage page (`packages/eql/docs/reference/json-tree-leakage.md`).
//!
//! The draws come from vitaminc's [`SafeRand`] (ChaCha20, seeded from the
//! operating system for each document or query) through rand's
//! [`shuffle`](SliceRandom::shuffle), a Fisher–Yates shuffle with unbiased
//! index draws. The generator is not part of the format, since nothing
//! stored depends on it.

use rand::seq::SliceRandom;
use vitaminc::random::SafeRand;

use crate::Error;

/// Where the JSON index draws its permutations from: a fresh generator for
/// each document sealed or query derived, seeded from the operating system.
///
/// With the `test-support` feature a cipher can instead be given one seeded
/// stream ([`StackCipherBuilder::json_seed`](crate::StackCipherBuilder)),
/// which every generator is then seeded from, so that a run sealing the
/// same documents in the same sequence draws the same permutations and a
/// fixture can pin them.
pub(crate) struct Randomness {
    #[cfg(any(test, feature = "test-support"))]
    stream: Option<std::sync::Mutex<SafeRand>>,
}

impl Randomness {
    /// Every generator seeded from the operating system.
    pub(crate) const fn from_entropy() -> Self {
        Self {
            #[cfg(any(test, feature = "test-support"))]
            stream: None,
        }
    }

    /// Every generator seeded from one stream that starts at `seed`.
    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn seeded(seed: vitaminc_protected::Protected<[u8; 32]>) -> Self {
        Self {
            stream: Some(std::sync::Mutex::new(SafeRand::from_controlled_seed(seed))),
        }
    }

    /// A generator for one document or one query.
    pub(crate) fn generator(&self) -> Result<SafeRand, Error> {
        #[cfg(any(test, feature = "test-support"))]
        if let Some(stream) = &self.stream {
            use vitaminc::random::SeedableRng;
            // The stream holds no invariant a panic could break.
            let mut stream = stream
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            return Ok(SafeRand::from_rng(&mut *stream));
        }
        SafeRand::from_entropy()
            .map_err(|_| Error::Other("no entropy for the JSON index's permutations".into()))
    }
}

/// `items` in a uniformly random order.
pub(crate) fn shuffle<T>(items: &mut [T], rng: &mut SafeRand) {
    items.shuffle(rng);
}

/// A uniformly random permutation of `0..n`: the ordinals of an object's
/// `n` members, by their position in the object.
pub(crate) fn ordinals(n: u32, rng: &mut SafeRand) -> Vec<u32> {
    let mut ordinals: Vec<u32> = (0..n).collect();
    shuffle(&mut ordinals, rng);
    ordinals
}

/// The slot each of `n` nodes is stored at, by its index in the walk: the
/// root (index `0`) at slot `0`, where the sealed-root fallback finds it,
/// and the other nodes at a uniformly random permutation of the slots
/// `1..n`.
pub(crate) fn slots(n: usize, rng: &mut SafeRand) -> Vec<usize> {
    let mut slots: Vec<usize> = (0..n).collect();
    if let Some(rest) = slots.get_mut(1..) {
        shuffle(rest, rng);
    }
    slots
}

#[cfg(test)]
mod tests {
    use super::*;
    use vitaminc_protected::Protected;

    fn seeded(byte: u8) -> SafeRand {
        SafeRand::from_controlled_seed(Protected::new([byte; 32]))
    }

    fn is_permutation(items: &[usize], n: usize) -> bool {
        let mut sorted = items.to_vec();
        sorted.sort_unstable();
        sorted == (0..n).collect::<Vec<_>>()
    }

    #[test]
    fn the_ordinals_are_a_permutation() {
        for n in [0, 1, 2, 5, 300] {
            let ordinals = ordinals(n, &mut seeded(1));
            let as_usize: Vec<usize> = ordinals.iter().map(|&o| o as usize).collect();
            assert!(is_permutation(&as_usize, n as usize), "{n}: a permutation");
        }
        assert_ne!(
            ordinals(40, &mut seeded(1)),
            (0..40).collect::<Vec<_>>(),
            "not the identity (with overwhelming probability)"
        );
    }

    #[test]
    fn the_slots_are_a_permutation_with_the_root_first() {
        for n in [0, 1, 2, 3, 17, 200] {
            let slots = slots(n, &mut seeded(1));
            assert!(is_permutation(&slots, n), "{n}: a permutation");
            if n > 0 {
                assert_eq!(slots[0], 0, "{n}: the root at slot 0");
            }
        }
        assert_ne!(
            slots(50, &mut seeded(1)),
            (0..50).collect::<Vec<_>>(),
            "not the identity (with overwhelming probability)"
        );
    }

    /// Every arrangement of three items comes up, each about a sixth of the
    /// time: the shuffle reaches every permutation and favours none.
    #[test]
    fn the_shuffle_is_uniform_over_small_permutations() {
        let mut rng = seeded(2);
        let mut counts = std::collections::BTreeMap::new();
        let runs = 60_000;
        for _ in 0..runs {
            let mut items = [0, 1, 2];
            shuffle(&mut items, &mut rng);
            *counts.entry(items).or_insert(0usize) += 1;
        }
        assert_eq!(counts.len(), 6, "every permutation of three");
        for (perm, count) in counts {
            assert!(
                (9_000..11_000).contains(&count),
                "{perm:?} came up {count} times in {runs}"
            );
        }
    }

    #[test]
    fn a_seeded_source_repeats_and_entropy_does_not() {
        let order = |source: &Randomness| {
            let mut a = source.generator().unwrap();
            let mut b = source.generator().unwrap();
            (slots(30, &mut a), slots(30, &mut b))
        };
        let one = order(&Randomness::seeded(Protected::new([3; 32])));
        let two = order(&Randomness::seeded(Protected::new([3; 32])));
        assert_eq!(one, two, "the same seed, the same permutations");
        assert_ne!(one.0, one.1, "each document draws its own");
        let other = order(&Randomness::seeded(Protected::new([4; 32])));
        assert_ne!(one, other, "another seed, other permutations");
        let fresh = order(&Randomness::from_entropy());
        assert_ne!(fresh.0, fresh.1, "entropy draws a new one per document");
    }
}
