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
//! - `passthrough(name)`: carried as it is, **unsealed and unauthenticated**;
//! - `encrypt_into::<T, _>(name)`: laid out by the **target** type `T`,
//!   whose own `EncryptFrom` decides what is sealed, which terms sit beside
//!   it and which queries it answers. A field is either the data verbs above
//!   or one target, never both.
//!
//! A verb names its field by name, read through the value's [`Fields`] and
//! [`Field<F>`] (Rust cannot learn a field's type from its name, so a field
//! verb names it where the value has fields of several types), or by a
//! **picker**, a name with an accessor ([`pick`]`("email", |u: &User|
//! &u.email)`), which reads the field directly and needs neither impl nor
//! turbofish. The output is a [`FieldValues`].
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
//! let mut record = cipher
//!     .encrypt(&user)
//!     .context("users")
//!     .fields()
//!     .encrypt_index::<String>("email", (Equality, Match::default()))
//!     .encrypt_index::<u32>("age", (Equality, Ore))
//!     .encrypt::<String>("notes")
//!     .passthrough::<u64>("id")
//!     .await?;
//!
//! let email: Encrypted<(EqualityTerm, MatchTerms)> = record.take("email")?;
//! assert_eq!(record.take::<u64>("id")?, 42);
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
//! A plan is the same chain without a value. It starts one of two ways,
//! [`Plan::fields`] or [`Plan::value`], each with an optional `.context(c)`;
//! [`Plan::context`]`(c).fields()` and `Plan::context(c).with(..)` are the
//! common spellings. Its context comes from exactly one place: the plan
//! (`.context(c)`), the call that runs it
//! (`cipher.encrypt(&v).context(c).using(&plan)`, for a plan built without
//! one), or a field of the value
//! ([`context_field`](FieldsBuilder::context_field)); see [`Plan`].
//!
//!
//! [`build`](FieldsBuilder::build) validates the whole plan once: a field
//! named twice, a label that is not plain, two fields under one identity,
//! passthrough on an indexed field, a field both a target and data verbs,
//! a context given twice, an index named twice, and (where the type
//! declares a [`schema`](Fields::schema)) a field the type lacks, one it
//! leaves unnamed or one at the wrong type are all refused there. A plan is
//! data: `Clone`, `Debug`, reusable.
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
//! let record = cipher.encrypt(&user).using(&users_plan).await?;
//! let stored: &Encrypted<(EqualityTerm, MatchTerms)> = record.get("email").unwrap();
//!
//! // Query: derived under the label the write used, so it matches.
//! let email_plan = users_plan.field("email")?;
//! let query_value = cipher.query("bob@example.com").using(&email_plan).equality().await?;
//! assert_eq!(query_value, stored.terms.0);
//!
//! // Read: every field that can come back.
//! let back = cipher.open(record).using(&users_plan).await?;
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
//! matches nothing. A one-value plan given its indexes ([`ValuePlan`], from
//! `.with(..)`) selects its query index by type instead, so there an
//! undeclared index does not compile; it also carries its plaintext type,
//! so opening through it yields that type.
//!
//! [`all`] settles several chains in one ZeroKMS request, and a saved plan
//! over a slice or a `Vec` settles every record in one, both ways.
//!
//! # The derive emits a plan
//!
//! `#[derive(EncryptFrom)]` is a second author of the same grammar, not a
//! second executor. It emits `Record::plan()`, a chain built from the
//! record's attributes, and the record's `EncryptFrom::encryption()` is that
//! plan's description, mapped into the struct:
//!
//! - `#[stash(struct = User, context = "users")]` emits
//!   `Plan::context("users").fields()` with one
//!   `encrypt_into::<FieldType, _>(pick("name", |u: &User| &u.name))` per
//!   field (and `.identity(..)` where one is pinned). The field's own type
//!   decides its layout.
//! - `#[stash(plaintext = T)]` emits
//!   `Plan::value::<T>().encrypt_into::<(A, B, ..)>()`, the tuple of the
//!   derived fields' types, with no context of its own: every output shares
//!   the context the caller hands over
//!   ([`ValuePlan::encryption_with_context`]). With a
//!   `#[stash(context_field)]` it is
//!   `Plan::value::<T>().context_field::<C>().encrypt_into::<(A, B, ..)>()`,
//!   which carries that context out beside the outputs
//!   ([`ValueStart::context_field`]).
//!
//! So the derive's record and the hand-written chain are the same plan:
//!
//! ```
//! # async fn example() -> Result<(), stack_encrypt::Error> {
//! use stack_encrypt::kms::FakeDataKeySource;
//! use stack_encrypt::plan::pick;
//! use stack_encrypt::sem::EqualityTerm;
//! use stack_encrypt::{Encrypted, EncryptFrom, Plan, StackCipher, StackCipherText};
//!
//! struct User {
//!     email: String,
//!     nickname: String,
//! }
//!
//! #[derive(EncryptFrom)]
//! #[stash(struct = User, context = "users")]
//! struct EncryptedUser {
//!     email: Encrypted<EqualityTerm>,
//!     #[stash(identity = "handle")]
//!     nickname: StackCipherText,
//! }
//!
//! let derived = EncryptedUser::plan::<FakeDataKeySource>()?;
//! let by_hand: Plan<User, FakeDataKeySource> = Plan::context("users")
//!     .fields()
//!     .encrypt_into::<Encrypted<EqualityTerm>, _>(pick("email", |u: &User| &u.email))
//!     .encrypt_into::<StackCipherText, _>(pick("nickname", |u: &User| &u.nickname))
//!     .identity("handle")
//!     .build()?;
//! // The same fields, labels, layouts and indexes.
//! assert_eq!(format!("{derived:?}"), format!("{by_hand:?}"));
//! assert_eq!(derived.field("nickname")?.label().map(ToString::to_string).as_deref(), Some("users/handle"));
//!
//! // And the record's equality term is the one a query through the plan derives.
//! let cipher = StackCipher::builder().kms(FakeDataKeySource::new()).init().await?;
//! let user = User { email: "bob@example.com".into(), nickname: "bob".into() };
//! let record: EncryptedUser = cipher.default_keyset().encrypt_as(&user, ().into()).await?;
//! let query_value = cipher.query("bob@example.com").using(&by_hand.field("email")?).equality().await?;
//! assert_eq!(record.email.terms, query_value);
//! # Ok(())
//! # }
//! # tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(example()).unwrap();
//! ```
//!
//! # A binding lowers data into the same builder
//!
//! A language binding has no types to name, so it declares a record as
//! data. With the `dynamic` feature, [`dynamic::record`](crate::dynamic::record)
//! reads that declaration and lowers it into this builder — one context,
//! `encrypt` / `encrypt_index` / `index` / `passthrough` per field — and
//! runs the result through [`KeysetCipher::run`](crate::KeysetCipher::run)
//! and the plan's opener. It is the third author of this grammar, beside a
//! Rust chain and the derive, and not a second executor.
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
//! | `encrypt_into::<T, _>(name)`, `encrypt_into::<T>()` | `<T as EncryptFrom<F>>::encryption().under(label)`; `Encrypted<Terms>`'s is `indexed(..)` |
//! | `encrypt(name)` | `ciphertext().under(label)` |
//! | `index(name, x)` | [`Indexes::operations`](crate::Indexes::operations)`().under(label)` |
//! | `passthrough(name)` | [`passthrough`](crate::target::passthrough)`()` |
//! | `context_field(name)` | `passthrough()`, and its value is the context every other field runs under |
//! | `fields()` | each field picked out of the value (by name, or by a picker's accessor as `project` does), `zip`ped |
//! | `extend(parts)` | the [`DeclaredContext`](crate::target::DeclaredContext) the description runs under |
//! | `using(&plan)` | [`KeysetCipher::run`](crate::KeysetCipher::run) of [`Plan::encryption`] |
//! | `query(v).using(..).equality()` | the selected index's operation alone, `.under(label)` |
//! | `open(record).using(&plan)` | [`open`](crate::target::open) per field, run by `run_decryption` |
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
mod field_ref;
mod value;
mod values;

pub use build::{FieldKind, FieldPlan, FieldsBuilder, IntoLabel, Opens, Plan, PlanContext, Runs};
pub use chain::{
    all, All, Batch, EncryptBuilder, EncryptFields, EncryptIndexed, EncryptUsing,
    EncryptWithContext, KeysetChoice, OpenBuilder, OpenUsing, Operation, PlanKms, QueryBuilder,
    QueryIndex, QueryUsing,
};
pub use error::PlanError;
pub use field_ref::{pick, FieldRef};
pub use value::{
    ContextFieldStart, Indexed, Stored, Typed, ValueLayout, ValuePlan, ValuePlanBuilder,
    ValueShape, ValueStart,
};
pub use values::{Field, FieldSchema, FieldValues, Fields};
