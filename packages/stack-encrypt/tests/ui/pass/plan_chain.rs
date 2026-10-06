//! The chain shapes that must compile: a value with a context, indexed,
//! field by field, a saved plan over a value and a collection, a query and
//! an opening, and several chains batched.
use stack_encrypt::registry::fake::FakeKeysetRegistry;
use stack_encrypt::plan::{Field, Fields};
use stack_encrypt::{Equality, Error, Match, Ore, Plan, StackCipher};

struct Person {
    email: String,
    age: u32,
}
impl Fields for Person {
    fn field_names(&self) -> Vec<&str> {
        vec!["email", "age"]
    }
}
impl Field<String> for Person {
    fn field(&self, name: &str) -> Option<&String> {
        (name == "email").then_some(&self.email)
    }
}
impl Field<u32> for Person {
    fn field(&self, name: &str) -> Option<&u32> {
        (name == "age").then_some(&self.age)
    }
}

async fn chains(cipher: &StackCipher<FakeKeysetRegistry>, person: &Person) -> Result<(), Error> {
    let doc = String::from("doc");
    let _ = cipher.encrypt(&doc).context("docs").await?;
    let _ = cipher.encrypt(&34u32).context("users/age").with((Equality, Ore)).await?;
    let _ = cipher
        .encrypt(person)
        .context("people")
        .fields()
        .encrypt_index::<String>("email", (Equality, Match::default()))
        .encrypt::<u32>("age")
        .keyset("tenant")
        .extend(7u64)
        .await?;
    let people_plan = Plan::context("people")
        .fields()
        .encrypt_index::<String>("email", Equality)
        .index::<u32>("age", Ore)
        .build()?;
    let row = cipher.encrypt(person).using(&people_plan).await?;
    let _ = cipher.open(row).using(&people_plan).await?;
    let email_plan = people_plan.field("email")?;
    let _ = cipher.query("bob@example.com").using(&email_plan).equality().await?;
    let age_plan = Plan::context("people/age").with((Equality, Ore)).build()?;
    let ages = vec![1u32, 2];
    let _ = cipher.encrypt(&ages).using(&age_plan).await?;
    let _ = cipher.query(&3u32).using(&age_plan).index::<Ore, _>().await?;
    let _ = stack_encrypt::all((
        cipher.encrypt(person).using(&people_plan),
        cipher.query(&3u32).using(&age_plan).equality(),
    ))
    .await?;
    Ok(())
}

fn main() {
    let _ = chains;
}
