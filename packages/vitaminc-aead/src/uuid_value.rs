//! [`Uuid`]: a uuid that is wiped when dropped.

use vitaminc_protected::{OpaqueDebug, TimingSafeEq};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::plaintext::{depth, Encrypt, FixedType, Logical, Physical, Scalar, Sink, Width};
use crate::typed::FromScalar;

/// A uuid, held as its sixteen bytes and wiped when it is dropped.
///
/// It encrypts to the same leaf as [`uuid::Uuid`], owned or borrowed, so a
/// `uuid::Uuid` field can become a `Uuid` without changing its ciphertext.
///
/// ```
/// use vitaminc_aead::Uuid;
///
/// let id = uuid::Uuid::from_u128(7);
/// assert_eq!(Uuid::new(id).to_uuid(), id);
/// ```
///
/// A `Uuid` is plaintext, so it is handled as the data model's other
/// scalars are: a `uuid::Uuid` is `Copy` and is never wiped. Equality is
/// constant time (see [`TimingSafeEq`]). It is not `Copy` or `Clone`, and
/// it has no ordering or hash. `Debug` is redacted. `Default` is the nil
/// uuid, as for `uuid::Uuid`.
#[derive(Default, OpaqueDebug, TimingSafeEq, Zeroize, ZeroizeOnDrop)]
#[cfg_attr(docsrs, doc(cfg(feature = "uuid")))]
pub struct Uuid {
    /// The uuid's bytes, in its own (big-endian) order.
    bytes: [u8; 16],
}

impl Uuid {
    /// The uuid.
    pub fn new(uuid: uuid::Uuid) -> Self {
        Self {
            bytes: uuid.into_bytes(),
        }
    }

    /// The uuid, as a `uuid::Uuid`. The copy is the caller's to look
    /// after: it cannot be wiped.
    pub fn to_uuid(&self) -> uuid::Uuid {
        uuid::Uuid::from_bytes(self.bytes)
    }
}

impl From<uuid::Uuid> for Uuid {
    fn from(uuid: uuid::Uuid) -> Self {
        Self::new(uuid)
    }
}

impl From<Uuid> for uuid::Uuid {
    fn from(uuid: Uuid) -> Self {
        uuid.to_uuid()
    }
}

/// The same leaf as `uuid::Uuid`: sixteen bytes under the uuid type.
impl Encrypt for Uuid {
    const DEPTH: Option<usize> = depth::SCALAR;
    const FIXED: Option<FixedType> = <&Uuid as Encrypt>::FIXED;
    fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
        (&self).visit(sink)
    }
}

impl Encrypt for &Uuid {
    const DEPTH: Option<usize> = depth::SCALAR;
    const FIXED: Option<FixedType> = FixedType::new(Some(Logical::Uuid), Width::Bytes16);
    fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
        sink.scalar(Some(Logical::Uuid), Physical::Bytes(&self.bytes))
    }
}

impl Scalar for Uuid {}
impl Scalar for &Uuid {}
const _: () = assert!(depth::is_scalar(<Uuid as Encrypt>::DEPTH));

impl FromScalar for Uuid {
    const EXPECTED: &'static str = "uuid";
    fn from_scalar(ty: Option<Logical>, value: Physical<'_>) -> Option<Self> {
        uuid::Uuid::from_scalar(ty, value).map(Self::new)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::to_frame;
    use vitaminc_protected::Controlled;

    fn frame<P: Encrypt>(value: P) -> Vec<u8> {
        to_frame(value).expect("frames").risky_ref().to_vec()
    }

    #[test]
    fn it_walks_as_the_uuid_it_holds() {
        for id in [
            uuid::Uuid::nil(),
            uuid::Uuid::max(),
            uuid::Uuid::from_u128(0x0123_4567_89ab_cdef_0123_4567_89ab_cdef),
        ] {
            let held = Uuid::new(id);
            assert_eq!(held.to_uuid(), id);
            assert_eq!(frame(&held), frame(id));
            assert_eq!(frame(Uuid::new(id)), frame(id));
            assert_eq!(uuid::Uuid::from(Uuid::from(id)), id);
        }
        assert_eq!(<Uuid as Encrypt>::FIXED, <uuid::Uuid as Encrypt>::FIXED);
        assert_eq!(Uuid::default().to_uuid(), uuid::Uuid::nil());
        let decoded =
            Uuid::from_scalar(Some(Logical::Uuid), Physical::Bytes(&[7; 16])).expect("a uuid");
        assert_eq!(decoded.to_uuid(), uuid::Uuid::from_bytes([7; 16]));
        assert!(Uuid::from_scalar(Some(Logical::Uuid), Physical::Bytes(&[7; 15])).is_none());
    }

    #[test]
    fn it_compares_in_constant_time_wipes_and_redacts() {
        let id = |n| Uuid::new(uuid::Uuid::from_u128(n));
        assert!(bool::from(id(5).ts_eq(&id(5))));
        assert!(id(5) != id(6));
        let mut held = id(0xdead_beef);
        held.zeroize();
        assert!(held == Uuid::default());
        assert!(!format!("{:?}", id(0xdead_beef)).contains("deadbeef"));
    }
}
