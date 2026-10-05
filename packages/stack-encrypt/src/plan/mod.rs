//! The plan builder: one chained front door for writes, queries and reads.
//!
//! A **plan** is the saved tail of an encrypt call with the value left out:
//! a context, and either the indexes of one value or, field by field, each
//! field's. The write, the query and the read all take the same plan, so
//! none of them can spell a context differently from the others, and a query
//! cannot silently match nothing because its label drifted from the write's.
//!
//! Every chain starts on a [`StackCipher`](crate::StackCipher) and ends with
//! `.await`. Before the await nothing has touched a key: a chain lowers to a
//! [`Pending`](crate::Pending) synchronously ([`Operation::prepare`]) and the
//! await is what reaches ZeroKMS.
//!
//! # One value
//!
//! ```
//! # async fn example() -> Result<(), stack_encrypt::Error> {
//! use stack_encrypt::kms::FakeDataKeySource;
//! use stack_encrypt::sem::{EqualityTerm, OreTerm};
//! use stack_encrypt::{Equality, Ore, StackCipher};
//!
//! let cipher = StackCipher::builder().kms(FakeDataKeySource::new()).init().await?;
//!
//! // One tree, one context: the cipher-directed call, by name.
//! let doc = String::from("the body");
//! let sealed = cipher.encrypt(&doc).context("documents/v2/body").await?;
//!
//! // One value with indexes beside it. The tuple types the terms.
//! let out = cipher.encrypt(&34u32).context("users/age").with((Equality, Ore)).await?;
//! let (eq, ore): (EqualityTerm, OreTerm<u32>) = out.terms;
//! # let _ = (sealed, eq, ore, out.ciphertext);
//! # Ok(())
//! # }
//! # tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(example()).unwrap();
//! ```
//!
//! # Field by field
//!
//! `.fields()` seals each top-level field of the value on its own, under
//! `<context>/<field>`, so a field can be stored, read, indexed and queried
//! without the rest. Each field is named once, with one verb:
//!
//! - `encrypt(name)`: its ciphertext alone;
//! - `encrypt_index(name, indexes)`: its ciphertext with a non-empty index
//!   set beside it (one index or a tuple; `()` does not compile);
//! - `index(name, indexes)`: the indexes alone, no ciphertext, so the field
//!   is searchable but does not come back from decrypt;
//! - `passthrough(name)`: carried as it is, **unsealed and unauthenticated**.
//!
//! The value is taken apart through [`Fields`] and [`Field<F>`]. Rust cannot
//! learn a field's type from its name, so a field verb names it where the
//! value has fields of several types. The output is a [`FieldValues`].
//!
//! ```
//! # use stack_encrypt::plan::{Field, Fields};
//! # struct User { email: String, age: u32, notes: String, id: u64 }
//! # impl Fields for User {
//! #     fn field_names(&self) -> Vec<&str> { vec!["email", "age", "notes", "id"] }
//! # }
//! # impl Field<String> for User {
//! #     fn field(&self, name: &str) -> Option<&String> {
//! #         match name { "email" => Some(&self.email), "notes" => Some(&self.notes), _ => None }
//! #     }
//! # }
//! # impl Field<u32> for User {
//! #     fn field(&self, name: &str) -> Option<&u32> { (name == "age").then_some(&self.age) }
//! # }
//! # impl Field<u64> for User {
//! #     fn field(&self, name: &str) -> Option<&u64> { (name == "id").then_some(&self.id) }
//! # }
//! # async fn example() -> Result<(), stack_encrypt::Error> {
//! use stack_encrypt::kms::FakeDataKeySource;
//! use stack_encrypt::sem::{EqualityTerm, MatchTerms};
//! use stack_encrypt::{Encrypted, Equality, Match, Ore, StackCipher};
//!
//! let cipher = StackCipher::builder().kms(FakeDataKeySource::new()).init().await?;
//! let user = User { email: "bob@example.com".into(), age: 34, notes: "hi".into(), id: 42 };
//!
//! let mut row = cipher
//!     .encrypt(&user)
//!     .context("users")
//!     .fields()
//!     .encrypt_index::<String>("email", (Equality, Match::default()))
//!     .encrypt_index::<u32>("age", (Equality, Ore))
//!     .encrypt::<String>("notes")
//!     .passthrough::<u64>("id")
//!     .await?;
//!
//! let email: Encrypted<(EqualityTerm, MatchTerms)> = row.take("email")?;
//! assert_eq!(row.take::<u64>("id")?, 42);
//! # let _ = email;
//! # Ok(())
//! # }
//! # tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(example()).unwrap();
//! ```
//!
//! `.keyset(..)` names the keyset the data keys are minted under (a
//! [`KeysetCipher`](crate::KeysetCipher) in hand, or an id or name loaded
//! at the await), and `.extend(parts)` extends every field's context for one
//! call, as a derived record's caller context does. Both go anywhere in the
//! chain.
//!
//! # A saved plan, a query and a read
//!
//! [`Plan::context`] starts the same chain without a value, and
//! [`build`](FieldsBuilder::build) validates the whole plan once: a field
//! named twice, a label that is not plain, two fields under one identity,
//! passthrough on an indexed field, an index named twice, and (where the
//! type declares a [`schema`](Fields::schema)) a field the type lacks, one
//! it leaves unnamed or one at the wrong type are all refused there. A plan
//! is data: `Clone`, `Debug`, reusable.
//!
//! The same plan then writes ([`using`](EncryptBuilder::using)), queries
//! ([`query`](crate::StackCipher::query)) and reads
//! ([`open`](crate::StackCipher::open)):
//!
//! ```
//! # use stack_encrypt::plan::{Field, Fields};
//! # struct User { email: String, age: u32, notes: String, id: u64 }
//! # impl Fields for User {
//! #     fn field_names(&self) -> Vec<&str> { vec!["email", "age", "notes", "id"] }
//! # }
//! # impl Field<String> for User {
//! #     fn field(&self, name: &str) -> Option<&String> {
//! #         match name { "email" => Some(&self.email), "notes" => Some(&self.notes), _ => None }
//! #     }
//! # }
//! # impl Field<u32> for User {
//! #     fn field(&self, name: &str) -> Option<&u32> { (name == "age").then_some(&self.age) }
//! # }
//! # impl Field<u64> for User {
//! #     fn field(&self, name: &str) -> Option<&u64> { (name == "id").then_some(&self.id) }
//! # }
//! # async fn example() -> Result<(), stack_encrypt::Error> {
//! use stack_encrypt::kms::FakeDataKeySource;
//! use stack_encrypt::sem::{EqualityTerm, MatchTerms};
//! use stack_encrypt::{Encrypted, Equality, Match, Ore, Plan, StackCipher};
//!
//! let cipher = StackCipher::builder().kms(FakeDataKeySource::new()).init().await?;
//! let user = User { email: "bob@example.com".into(), age: 34, notes: "hi".into(), id: 42 };
//!
//! let users_plan: Plan<User, _> = Plan::context("users")
//!     .fields()
//!     .encrypt_index::<String>("email", (Equality, Match::default()))
//!     .encrypt_index::<u32>("age", (Equality, Ore))
//!     .encrypt::<String>("notes")
//!     .passthrough::<u64>("id")
//!     .build()?;
//!
//! // Write.
//! let row = cipher.encrypt(&user).using(&users_plan).await?;
//! let stored: &Encrypted<(EqualityTerm, MatchTerms)> = row.get("email").unwrap();
//!
//! // Query: derived under the label the write used, so it matches.
//! let email_plan = users_plan.field("email")?;
//! let probe = cipher.query("bob@example.com").using(&email_plan).equality().await?;
//! assert_eq!(probe, stored.terms.0);
//!
//! // Read: every field that can come back.
//! let back = cipher.open(row).using(&users_plan).await?;
//! assert_eq!(back.get::<String>("notes").map(String::as_str), Some("hi"));
//! assert_eq!(back.get::<u32>("age"), Some(&34));
//! # Ok(())
//! # }
//! # tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(example()).unwrap();
//! ```
//!
//! A query against an index the field never declared is
//! [`PlanError::IndexNotDeclared`], and one whose plaintext is not the
//! field's type is [`PlanError::FieldType`]: never a term that quietly
//! matches nothing. A one-value plan ([`ValuePlan`], from
//! `Plan::context(..).with(..)`) selects its query index by type instead, so
//! there an undeclared index does not compile; it also carries its plaintext
//! type, so opening through it yields that type.
//!
//! [`all`] settles several chains in one ZeroKMS request, and a saved plan
//! over a slice or a `Vec` settles every row in one.
//!
//! # How a chain lowers
//!
//! The builder adds no cryptographic operation and no executor; every call
//! lowers to the combinators in [`target`](crate::target), and the bytes are
//! theirs:
//!
//! | chain | combinators |
//! |---|---|
//! | `context(c)` alone | [`ciphertext`](crate::target::ciphertext)`().under(c)` |
//! | `with(x)`, `encrypt_index(name, x)` | [`indexed`](crate::target::indexed)`(x).under(label)` |
//! | `encrypt(name)` | `ciphertext().under(label)` |
//! | `index(name, x)` | [`Indexes::operations`](crate::Indexes::operations)`().under(label)` |
//! | `passthrough(name)` | [`passthrough`](crate::target::passthrough)`()` |
//! | `fields()` | each field picked out of the value by name, `zip`ped |
//! | `extend(parts)` | the [`DeclaredContext`](crate::target::DeclaredContext) the description runs under |
//! | `using(&plan)` | [`KeysetCipher::run`](crate::KeysetCipher::run) of [`Plan::encryption`] |
//! | `query(v).using(..).equality()` | the selected index's operation alone, `.under(label)` |
//! | `open(row).using(&plan)` | [`open`](crate::target::open) per field, run by `run_decryption` |
//! | `.await`, [`all`] | `Pending::zip`, then one settle |
//!
//! The cipher-directed and target-directed entry points on
//! [`KeysetCipher`](crate::KeysetCipher) remain; the chain is their fluent
//! spelling. The chain decrypts with [`open`](crate::StackCipher::open)
//! because [`StackCipher::decrypt`](crate::StackCipher::decrypt) is the
//! cipher-directed decrypt, and keeps its form.
mod build;
mod chain;
mod error;
mod values;

pub use build::{
    FieldKind, FieldPlan, FieldsBuilder, IntoLabel, Opens, Plan, PlanContext, Runs, ValuePlan,
    ValuePlanBuilder,
};
pub use chain::{
    all, All, Batch, EncryptBuilder, EncryptFields, EncryptIndexed, EncryptUsing,
    EncryptWithContext, KeysetChoice, OpenBuilder, OpenUsing, Operation, PlanKms, QueryBuilder,
    QueryIndex, QueryUsing,
};
pub use error::PlanError;
pub use values::{Field, FieldSchema, FieldValues, Fields};
