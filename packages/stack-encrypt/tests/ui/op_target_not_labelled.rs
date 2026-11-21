//! A target sealed under a context no label names (here an integer tenant
//! id) is not a `LabelledTarget`: a query from a field reference would derive under
//! the field reference's label and match nothing, so it does not compile, though the
//! type implements `Answers`.
use stack_encrypt::field_reference::{FieldReference, Root};
use stack_encrypt::sem::EqualityTerm;
use stack_encrypt::target::{equality, EncryptTarget, Encryption, IndexSpec, RequiredContext};
use stack_encrypt::{op, Equality, NonEmpty};

struct ByTenant;

impl EncryptTarget<String> for ByTenant {
    type ContextInput = RequiredContext<NonEmpty<u64>>;
    fn encryption<'s, K: 'static>() -> Encryption<'s, String, Self, K, Self::ContextInput>
    where
        String: 's,
    {
        equality().accepting().map(|_: EqualityTerm| ByTenant)
    }
    fn indexes() -> Vec<IndexSpec> {
        vec![IndexSpec::Equality]
    }
}

impl op::Answers<op::Eq, String> for ByTenant {
    type Via = Equality;
}

fn main() {
    let email = FieldReference::<Root<()>, ByTenant>::new("email", "users", "email", || unreachable!());
    let _ = email.eq("bob");
}
