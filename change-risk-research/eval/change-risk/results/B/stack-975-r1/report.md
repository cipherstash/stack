## Change risk: Ready for normal review

**Impact if something goes wrong:** low · **Verification confidence:** low · `013e3ff31f..24f7b2c604`

Documentation-only change to the shipped `stash-postgres` agent skill: adds an "Absolute-value ranges" recipe that decomposes `min <= abs(amount) < max` over an EQL v3 ordered column into a positive and a negative signed range with four separately encrypted bounds, rewords one comment in the free-text recipe without changing its meaning, and adds a patch changeset for `stash`. No library, SQL or build code changes. The skill is copied into the `stash` CLI tarball and installed into customer repos by `stash init`, so wrong guidance would propagate, but I checked the recipe's logic (the negative branch's reversed inequalities and the bound values -10/-20 are correct; overlap at zero is harmless in a single WHERE) and its API surface (`types.DoubleOrd`, `queryType: 'orderAndRange'`, the `eql_v3.query_double_ord` domain and the `eql_v3_double_ord` x `query_double_ord` comparison operators all exist at head). The one residual risk is that the recipe is not exercised by any test, and no repo test covers range queries over negative doubles. Advisory verdict: ready for normal review.

### Failure scenarios

**FS-1 · Untested recipe could return wrong rows silently if copied into customer queries** (low impact, plausible)

- Trigger: An agent applies the recipe to a column or bound set where encrypted order terms do not order as the recipe assumes (e.g. negative doubles), or adapts it to a different ordered type.
- Mechanism: The recipe relies on eql_v3_double_ord order terms preserving plaintext order across sign. The SQL operators it uses exist (E-7) and the predicate logic is correct, but no test in the repo runs a range query over negative doubles (the double_ord e2e seeds only positive salaries, E-8; negative ordering is exercised only for bigint, E-9), and the recipe itself is not executed anywhere.
- Consequence: A customer filter returns too many or too few rows with no error. Recovery is a doc fix plus the customer correcting their query; no stored data is affected.
- Affects: stash npm package (packages/cli) dist/skills, Customer code written by agents following the skill
- Evidence: `skills/stash-postgres/SKILL.md:330-370`; `packages/eql/packages/eql/sql/cipherstash-encrypt.sql:31590-31660`; `examples/prisma/test/e2e/num.e2e.test.ts:37-42`; `packages/stack-drizzle/integration/relational.integration.test.ts:126-129`
- Existing verification: BigintOrd integration test seeds a negative balance and filters with gt(0n), covering sign ordering for bigint only. [exists_not_run]
- Missing verification: An e2e/integration check that runs the signed-range predicate over a DoubleOrd column seeded with negative, zero and positive values.
- Mitigation: Have a reviewer run the snippet once against a local EQL v3 database with mixed-sign values, or add a negative-value case to the double_ord e2e suite.

### Recommended controls

- Reviewer to confirm the negative-branch inequalities (`<= -min`, `> -max`) and run the snippet against a mixed-sign DoubleOrd column. (review_focus; FS-1, VG-1)
- Optionally add a negative-value case to examples/prisma/test/e2e/num.e2e.test.ts. (test; VG-1)

### What this assessment could not see

- Order-preservation of double_ord terms across sign is implemented outside what I read (encryption crate / protect-ffi); I did not verify it. FS-1 remains plausible rather than ruled out.
- No CI results, PR description or deployment context were available; nothing was run. Verification confidence is low; no test is claimed to pass.
- History signals show skills/stash-postgres/SKILL.md usually co-changes with other skills (stash-cli, stash-encryption, stash-indexing, stash-supabase). I did not check whether those skills should also get the recipe. Possible inconsistency across skills; not a release risk for this change.

_Inputs unavailable: pr_description, ci_results, architecture_docs, dependency_graph, deployment_context._

_Advisory only. claude-code (headless) · claude-opus-5-5 · change-risk 1.0.0._
