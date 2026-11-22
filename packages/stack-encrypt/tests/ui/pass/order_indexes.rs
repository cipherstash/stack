//! Every type an ordering operator accepts takes each order index: as a set
//! of indexes, as an `Encrypted` target, and as a term on its own, owned or
//! borrowed. `order_index_on_bytes.rs` is the other side: bytes take none.
use stack_encrypt::sem::{OpeTerm, OreBlockTerm, OreTerm};
use stack_encrypt::target::{self, indexed, Borrowed, EncryptTarget};
use stack_encrypt::value::{Date, Decimal, Timestamp};
use stack_encrypt::{Encrypted, Ope, Ore, OreBlock};

macro_rules! takes_every_order_index {
    ($($ty:ty),+ $(,)?) => {$(
        let _ = indexed::<$ty, (), Borrowed, _>(Ore);
        let _ = indexed::<$ty, (), Borrowed, _>(Ope);
        let _ = indexed::<$ty, (), Borrowed, _>(OreBlock);
        let _ = <Encrypted<OreTerm<$ty>> as EncryptTarget<$ty>>::encryption::<()>();
        let _ = <Encrypted<OpeTerm<$ty>> as EncryptTarget<$ty>>::encryption::<()>();
        let _ = <Encrypted<OreBlockTerm<$ty>> as EncryptTarget<$ty>>::encryption::<()>();
        let _ = <OreTerm<$ty> as EncryptTarget<$ty>>::encryption::<()>();
        let _ = <OpeTerm<$ty> as EncryptTarget<$ty>>::encryption::<()>();
        let _ = <OreBlockTerm<$ty> as EncryptTarget<$ty>>::encryption::<()>();
        let _ = <OreTerm<$ty> as EncryptTarget<$ty>>::owned_encryption::<()>();
        let _ = <OpeTerm<$ty> as EncryptTarget<$ty>>::owned_encryption::<()>();
        let _ = <OreBlockTerm<$ty> as EncryptTarget<$ty>>::owned_encryption::<()>();
        let _ = target::ore::<$ty, (), Borrowed>();
        let _ = target::ope::<$ty, (), Borrowed>();
        let _ = target::ore_block::<$ty, (), Borrowed>();
    )+};
}

fn main() {
    takes_every_order_index!(
        u16, u32, u64, u128, i16, i32, i64, i128, f32, f64, String, Date, Timestamp, Decimal,
    );
}
