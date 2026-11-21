//! A value holds at most one term per operator family: equality, match and
//! one ordering. So no tuple of four or five terms is a valid set, and none
//! is a target or answers a query. Each would compile and then always be
//! refused with `PlanError::IndexOverlap`.
use stack_encrypt::sem::{EqualityTerm, MatchTerms, OpeTerm, OreTerm};
use stack_encrypt::target::TermSet;
use stack_encrypt::Encrypted;
use zeroize::Zeroize;

fn term_set<S, T: TermSet<S>>() {}

#[derive(Clone, Zeroize)]
struct Note {
    body: String,
}

#[derive(stack_encrypt::target::EncryptTarget)]
#[stash(struct = Note, scope = "notes")]
struct EncryptedNote {
    body: Encrypted<(EqualityTerm, MatchTerms, OreTerm<String>, OpeTerm<String>)>,
}

fn main() {
    term_set::<String, (EqualityTerm, MatchTerms, OreTerm<String>, OpeTerm<String>)>();
    let _ = EncryptedNote::BODY.eq("x");
}
