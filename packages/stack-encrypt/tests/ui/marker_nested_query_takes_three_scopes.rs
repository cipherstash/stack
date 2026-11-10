//! A query takes at most three scopes. A field of the fourth record that
//! lists a scope of its own has no marker, and the error says why.
use stack_encrypt::sem::EqualityTerm;
use stack_encrypt::target::EncryptTarget;
use stack_encrypt::Encrypted;
use zeroize::Zeroize;

#[derive(Clone, Zeroize)]
struct Desk {
    tenant: u64,
    label: String,
}

#[derive(Clone, Zeroize)]
struct Wing {
    owner: u32,
    desk: Desk,
}

#[derive(Clone, Zeroize)]
struct Block {
    owner: u16,
    wing: Wing,
}

#[derive(Clone, Zeroize)]
struct Estate {
    owner: u8,
    block: Block,
}

#[derive(EncryptTarget)]
#[stash(struct = Desk, scope = "desks", scope(field = "tenant"))]
struct EncryptedDesk {
    #[stash(passthrough)]
    tenant: u64,
    label: Encrypted<EqualityTerm>,
}

#[derive(EncryptTarget)]
#[stash(struct = Wing, scope = "wings", scope(field = "owner"))]
struct EncryptedWing {
    #[stash(passthrough)]
    owner: u32,
    desk: EncryptedDesk,
}

#[derive(EncryptTarget)]
#[stash(struct = Block, scope = "blocks", scope(field = "owner"))]
struct EncryptedBlock {
    #[stash(passthrough)]
    owner: u16,
    wing: EncryptedWing,
}

#[derive(EncryptTarget)]
#[stash(struct = Estate, scope = "estates", scope(field = "owner"))]
struct EncryptedEstate {
    #[stash(passthrough)]
    owner: u8,
    block: EncryptedBlock,
}

fn main() {
    // Three records with a scope each.
    let _ = EncryptedEstate::BLOCK
        .field(EncryptedBlock::WING)
        .field(EncryptedWing::DESK);
    // A fourth.
    let _ = EncryptedEstate::BLOCK
        .field(EncryptedBlock::WING)
        .field(EncryptedWing::DESK)
        .field(EncryptedDesk::LABEL);
}
