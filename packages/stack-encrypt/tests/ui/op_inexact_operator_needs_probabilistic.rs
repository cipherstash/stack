//! A text match is approximate, so an index that answers `Matches` must send
//! a term that says how its answer is checked: an exact term cannot answer
//! it.
use stack_encrypt::op;
use stack_encrypt::sem::EqualityTerm;
use stack_encrypt::target::{CallerContext, ConsumeSource, Encryption, Index, IndexSpec};
use stack_encrypt::Equality;

struct Shortcut;

impl Index<String> for Shortcut {
    type Term = EqualityTerm;
    fn spec(&self) -> IndexSpec {
        IndexSpec::Equality
    }
    fn operation<'s, K: 'static, M: ConsumeSource<'s, String>>(
        &self,
    ) -> Encryption<'s, String, EqualityTerm, K, CallerContext, M> {
        Index::<String>::operation(&Equality)
    }
}

impl op::Supports<op::Matches, String> for Shortcut {
    type Query = EqualityTerm;
    type Verifier = ();
    fn check(&self, _: &String) -> Result<(), stack_encrypt::Error> {
        Ok(())
    }
    fn verifier(&self, _: &String) {}
    fn query((): (), term: EqualityTerm, _: op::QueryToken) -> EqualityTerm {
        term
    }
}

fn main() {}
