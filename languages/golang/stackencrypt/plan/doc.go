// Package plan builds a record [stackencrypt.Plan] from what a domain
// schema already says about its fields, through a policy written in Go.
//
// Storage decisions do not belong in the schema. The schema carries facts —
// a field's name, its kind, and its annotations, such as Fideslang
// `data_categories` — and a [Policy], a pure function of a field's [Fact],
// decides what becomes of it: [Encrypt] into a [Target], [Plaintext], or
// [Fail]. Policies are ordinary values and compose: [When] is a rule,
// [FirstOf] takes the first rule that matches, and [Policy.OrElse] refines a
// shared base per message.
//
//	var category = plan.Key("fides.data_categories")
//
//	var Base = plan.FirstOf(
//	    plan.When(category.Under("user.government_id"), plan.Encrypt(plan.EQL(stackencrypt.Equality))),
//	    plan.When(category.Under("user.contact.email"), plan.Encrypt(plan.EQL(stackencrypt.Equality, stackencrypt.Match))),
//	    plan.When(category.Under("user"), plan.Encrypt(plan.EQL())),
//	)
//
//	var Individuals = plan.ForMessage(&Individual{}, plan.Table("individuals"),
//	    plan.FirstOf(
//	        plan.When(plan.Field("medicare_no"), plan.Encrypt(plan.EQL(stackencrypt.Equality)),
//	            plan.Column("medicare_number")),
//	    ).OrElse(Base),
//	)
//
//	var individuals = plan.MustPlanFor(plan.StructTags, Individuals)
//	// cipher.EncryptRecords(ctx, rows, stackencrypt.WithPlan(individuals))
//
// # Facts
//
// A [Source] makes the facts for a message. [StructTags] reads a Go
// struct's `facts` tags, naming each field as a schema would (the Go name
// in snake_case); a protobuf source reads descriptors and their custom
// options the same way, and needs nothing from this package beyond [Fact],
// [Source] and [Key]. [Message.Build] takes facts directly, so a generator
// or a test can build a plan without a source at all; [PlanFor] also checks
// the plan binds to the message's Go type.
//
// # Contexts
//
// A field's context is its AAD, its ZeroKMS data-key binding and its terms'
// PRF context, fixed when data is first written. For an [EQL] target the
// context is the column identity, "<table>/<column>" ([Identifier]): the
// table is the message's [Table], which is required and never derived from
// the message's name, and the column is the field's schema name unless the
// rule pins another with [Column] — the column's identity, which survives
// renames of the field and of the database column. A [Custom] target
// supplies its context itself.
//
// # Failing closed
//
// A field with annotations that no rule decides is an error when the plan
// is built ([ErrUnmatched]), naming the field and its annotations; there is
// no built-in default, so a catch-all, Plaintext included, is written in the
// policy. A field with no annotations that no rule names is not the
// policy's concern: it is left out of the plan and stored as it is. A
// message the policy encrypts nothing of has no plan to build
// ([ErrNothingEncrypted]): its records are stored without one. Build plans
// at startup with [MustPlanFor], so a gap stops the process before it
// writes anything.
package plan
