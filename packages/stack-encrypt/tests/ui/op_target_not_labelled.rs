//! A target sealed under a context no label names (here an integer tenant
//! id) is not a `LabelledTarget`: a query on its plan would derive under
//! the label and match nothing, so it does not compile, though the type
//! implements `Answers`. (A named index needs the type to accept the label
//! as its context, which it does not either.)
use stack_encrypt::kms::FakeDataKeySource;
use stack_encrypt::sem::EqualityTerm;
use stack_encrypt::target::{EncryptFrom, Encryption, IndexSpec};
use stack_encrypt::{op, Equality, NonEmpty, Plan, StackCipher};

struct ByTenant;

impl EncryptFrom<String> for ByTenant {
    type Context = NonEmpty<u64>;
    fn encryption<'s, K: 'static>() -> Encryption<'s, String, Self, K, Self::Context>
    where
        String: 's,
    {
        <EqualityTerm as EncryptFrom<String>>::encryption()
            .accepting::<NonEmpty<u64>>()
            .map(|_| ByTenant)
    }
    fn indexes() -> Vec<IndexSpec> {
        vec![IndexSpec::Equality]
    }
}

impl op::Answers<op::Eq, String> for ByTenant {
    type Via = Equality;
}

async fn query(cipher: &StackCipher<FakeDataKeySource>) {
    let plan = Plan::value::<String>()
        .context("users/email")
        .encrypt_into::<ByTenant>()
        .build()
        .unwrap();
    let _ = cipher.query(op::Eq, "bob").on(&plan);
}

fn main() {}
