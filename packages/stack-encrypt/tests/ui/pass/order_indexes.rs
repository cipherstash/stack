//! Every type an ordering operator is answered over takes each order index:
//! in a plan, as an `Encrypted` target, and as a term on its own, owned or
//! borrowed. `order_index_on_bytes.rs` is the other side: bytes take none.
use stack_encrypt::sem::{OpeTerm, OreBlockTerm, OreTerm};
use stack_encrypt::target::{self, Borrowed, EncryptFrom, EncryptTarget};
use stack_encrypt::value::{Date, Decimal, Timestamp};
use stack_encrypt::{Encrypted, Ope, Ore, OreBlock, Plan};

macro_rules! takes_every_order_index {
    ($($ty:ty),+ $(,)?) => {$(
        let _ = Plan::context("t/v").with::<$ty, _>(Ore).build();
        let _ = Plan::context("t/v").with::<$ty, _>(Ope).build();
        let _ = Plan::context("t/v").with::<$ty, _>(OreBlock).build();
        let _ = <Encrypted<OreTerm<$ty>> as EncryptTarget<$ty>>::encryption::<()>();
        let _ = <Encrypted<OpeTerm<$ty>> as EncryptTarget<$ty>>::encryption::<()>();
        let _ = <Encrypted<OreBlockTerm<$ty>> as EncryptTarget<$ty>>::encryption::<()>();
        let _ = <OreTerm<$ty> as EncryptTarget<$ty>>::encryption::<()>();
        let _ = <OpeTerm<$ty> as EncryptTarget<$ty>>::encryption::<()>();
        let _ = <OreBlockTerm<$ty> as EncryptTarget<$ty>>::encryption::<()>();
        let _ = <OreTerm<$ty> as EncryptFrom<$ty>>::indexes();
        let _ = <OpeTerm<$ty> as EncryptFrom<$ty>>::indexes();
        let _ = <OreBlockTerm<$ty> as EncryptFrom<$ty>>::indexes();
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
