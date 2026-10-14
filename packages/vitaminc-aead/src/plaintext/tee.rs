//! Two sinks, one walk. This is what push-style containers buy.
//!
//! A tee asks both sides for an element sink and hands the pair to the
//! source as one sink, so both consumers receive every call in the same
//! order. Any sinks with the same error type compose, at any depth.

use super::kinds::{Logical, Physical};
use super::{MapSink, Plaintext, SeqSink, Sink};

/// A pair of sinks that forwards every call to both and pairs the results.
pub struct Tee<A, B>(pub A, pub B);

impl<A: Sink, B: Sink<Error = A::Error>> Sink for Tee<A, B> {
    type Ok = (A::Ok, B::Ok);
    type Error = A::Error;
    type Seq = Tee<A::Seq, B::Seq>;
    type Map = Tee<A::Map, B::Map>;

    fn scalar(self, ty: Option<Logical>, value: Physical<'_>) -> Result<Self::Ok, A::Error> {
        // `value` is borrowed, so both sides read the same bytes.
        Ok((self.0.scalar(ty, value)?, self.1.scalar(ty, value)?))
    }

    fn seq(self, len: Option<usize>) -> Result<Self::Seq, A::Error> {
        Ok(Tee(self.0.seq(len)?, self.1.seq(len)?))
    }

    fn map(self, len: Option<usize>) -> Result<Self::Map, A::Error> {
        Ok(Tee(self.0.map(len)?, self.1.map(len)?))
    }

    /// The one call a tee cannot share: each side walks the subtree for
    /// itself, so it is cloned. Passthrough is cleartext by contract.
    fn passthrough<P: Plaintext + Clone>(self, value: P) -> Result<Self::Ok, A::Error> {
        Ok((
            self.0.passthrough(value.clone())?,
            self.1.passthrough(value)?,
        ))
    }
}

impl<A: SeqSink, B: SeqSink<Error = A::Error>> SeqSink for Tee<A, B> {
    type Ok = (A::Ok, B::Ok);
    type Error = A::Error;
    type Element<'s>
        = Tee<A::Element<'s>, B::Element<'s>>
    where
        Self: 's;

    fn element(&mut self) -> Result<Self::Element<'_>, A::Error> {
        Ok(Tee(self.0.element()?, self.1.element()?))
    }

    fn end(self) -> Result<Self::Ok, A::Error> {
        Ok((self.0.end()?, self.1.end()?))
    }
}

impl<A: MapSink, B: MapSink<Error = A::Error>> MapSink for Tee<A, B> {
    type Ok = (A::Ok, B::Ok);
    type Error = A::Error;
    type Entry<'s>
        = Tee<A::Entry<'s>, B::Entry<'s>>
    where
        Self: 's;

    fn entry(&mut self, key: &str) -> Result<Self::Entry<'_>, A::Error> {
        Ok(Tee(self.0.entry(key)?, self.1.entry(key)?))
    }

    fn end(self) -> Result<Self::Ok, A::Error> {
        Ok((self.0.end()?, self.1.end()?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plaintext::record::{record, Record};
    use std::collections::BTreeMap;

    #[test]
    fn both_sides_see_the_same_walk() {
        let mut value = BTreeMap::new();
        value.insert("xs", vec![Some(1u32), None]);
        value.insert("name", vec![]);

        let mut left = Vec::new();
        let mut right = Vec::new();
        value
            .clone()
            .visit(Tee(Record(&mut left), Record(&mut right)))
            .expect("ok");

        assert_eq!(left, right);
        assert_eq!(left, record(value).expect("ok"));
    }

    #[test]
    fn a_tee_of_tees_still_shares_one_walk() {
        let (mut a, mut b, mut c) = (Vec::new(), Vec::new(), Vec::new());
        vec![vec![1i64, 2], vec![3]]
            .visit(Tee(Tee(Record(&mut a), Record(&mut b)), Record(&mut c)))
            .expect("ok");
        assert_eq!(a, b);
        assert_eq!(b, c);
        // Seq, then for each inner vec: Element, Seq, (Element, Scalar)*, EndSeq; then EndSeq.
        assert_eq!(a.len(), 14);
    }
}
