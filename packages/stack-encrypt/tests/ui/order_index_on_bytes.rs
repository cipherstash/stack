//! An order index stores a term that reveals the order of the rows. No
//! ordering operator is answered over bytes, so an order index on bytes
//! would store that term and answer no query. It does not compile, in a
//! plan, as a field of a derived record, or as a target of its own.
use stack_encrypt::sem::{OpeTerm, OreBlockTerm, OreTerm};
use stack_encrypt::target::EncryptTarget;
use stack_encrypt::{Encrypted, Ope, Ore, OreBlock, Plan};
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
    let _ = Plan::context("files/digest").with::<Vec<u8>, _>(Ore);
    let _ = Plan::context("files/digest").with::<Vec<u8>, _>(Ope);
    let _ = Plan::context("files/digest").with::<Vec<u8>, _>(OreBlock);
    let _ = <OpeTerm<Vec<u8>> as EncryptTarget<Vec<u8>>>::encryption::<()>();
    let _ = <OreBlockTerm<Vec<u8>> as EncryptTarget<Vec<u8>>>::encryption::<()>();
}
