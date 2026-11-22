//! An order index stores a term that reveals the order of the rows. No
//! ordering operator compares bytes, so an order index on bytes would store
//! that term and answer no query. vitaminc-ore's `Orderable` does not cover
//! bytes, so it does not compile: as a set of indexes, as a field of a
//! derived record, as a target of its own (owned or borrowed), or as the
//! low-level operation an index of another crate would be built from.
use stack_encrypt::sem::{OpeTerm, OreBlockTerm, OreTerm};
use stack_encrypt::target::{self, indexed, Borrowed, EncryptTarget};
use stack_encrypt::{Encrypted, Ope, Ore, OreBlock};
use zeroize::Zeroize;

#[derive(Clone, Zeroize)]
struct File {
    digest: Vec<u8>,
}

#[derive(EncryptTarget)]
#[stash(struct = File, scope = "files")]
struct EncryptedFile {
    digest: Encrypted<OreTerm<Vec<u8>>>,
}

fn main() {
    let _ = indexed::<Vec<u8>, (), Borrowed, _>(Ore);
    let _ = indexed::<Vec<u8>, (), Borrowed, _>(Ope);
    let _ = indexed::<Vec<u8>, (), Borrowed, _>(OreBlock);
    let _ = <OreTerm<Vec<u8>> as EncryptTarget<Vec<u8>>>::encryption::<()>();
    let _ = <OpeTerm<Vec<u8>> as EncryptTarget<Vec<u8>>>::encryption::<()>();
    let _ = <OreBlockTerm<Vec<u8>> as EncryptTarget<Vec<u8>>>::encryption::<()>();
    let _ = <OreTerm<Vec<u8>> as EncryptTarget<Vec<u8>>>::owned_encryption::<()>();
    let _ = target::ore::<Vec<u8>, (), Borrowed>();
    let _ = target::ope::<Vec<u8>, (), Borrowed>();
    let _ = target::ore_block::<Vec<u8>, (), Borrowed>();
}
