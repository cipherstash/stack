//! An order index stores a term that reveals the order of the rows. A UUID
//! has no order a query could use, so an order index on one would store that
//! term and answer nothing. vitaminc-ore's `Orderable` does not cover
//! `value::Uuid`, so it does not compile, as a set of indexes or as a target
//! of its own.
use stack_encrypt::target::{self, indexed, Borrowed};
use stack_encrypt::value::Uuid;
use stack_encrypt::{Ope, Ore, OreBlock};

fn main() {
    let _ = indexed::<Uuid, (), Borrowed, _>(Ore);
    let _ = indexed::<Uuid, (), Borrowed, _>(Ope);
    let _ = indexed::<Uuid, (), Borrowed, _>(OreBlock);
    let _ = target::ore::<Uuid, (), Borrowed>();
}
