---
'@cipherstash/stack-prisma': minor
---

Move the bundled EQL v3 migrations to **eql-3.1.0**. Its install SQL changes
the version stamp (`eql_v3.version()` returns `'3.1.0'` and the `eql_v3`
schema comment reads `'3.1.0'`) and the ORE block comparator behind every
ordered ORE operator and the ORE operator class. The comparator now runs a
constant number of operations whatever two values share, closing a timing
leak. Ordering results are unchanged for well-formed values, but a block-ORE
text value with a malformed or mismatched-width term now raises on every
comparison against it. Check your `_ore` text columns before migrating; see
[U-004](../../../../packages/eql/docs/upgrading/v3.1.md#u-004-block-ore-text-comparisons-check-every-term).
No domain, wire format or index term changes.

Two artefacts carry the new bundle:

- A new upgrade edge, `20261005T0000_upgrade_eql_v3_3_1_0`, carrying the
  invariant `cipherstash:upgrade-eql-v3-bundle-3.1.0-v1`. Existing databases
  re-install through it on the next `prisma-next migration plan` followed by
  `prisma-next migrate`. **`migrate` alone is not enough**: only
  `migration plan` copies the new directory into your repo.
- The baseline install migration `20260601T0100_install_eql_v3_bundle`, which
  now bakes 3.1.0 and gains a sixth op, a no-SQL carrier for the new
  invariant, so fresh databases land on 3.1.0 from the single all-additive
  genesis edge and `db init` keeps working.

**A 1.2.x database walks one edge. A 1.0.0 or 1.1.x database walks three.**
1.2.x shipped eql-3.0.6, so `migrate` walks only the 3.1.0 edge. 1.0.0 and
1.1.x shipped eql-3.0.4, so `migrate` walks the 3.0.5, 3.0.6 and 3.1.0 edges in
one transaction, re-installing the ~2.6 MB bundle three times. As with every EQL
upgrade, each re-install opens with `DROP SCHEMA IF EXISTS eql_v3 CASCADE`:
re-run your grant script, and recreate functional indexes and anything else
depending on `eql_v3`.

**Action required, including on 1.2.x: the baseline changed again.** 1.2.0
and 1.2.1 shipped the baseline at eql-3.0.6, and this release changes those
published bytes. 1.0.0 to 1.1.1 shipped it at eql-3.0.4. If your project has a
`migrations/cipherstash/` directory generated against any earlier version,
delete it and re-run `prisma-next migration plan`:

```bash
rm -rf migrations/cipherstash
npx prisma-next migration plan
```

Your database keeps its markers, so already-applied invariants are not re-run.
If you skip the delete, a fresh `db init` from a 1.2.x directory refuses with
`Operation cipherstash.upgrade-eql-v3-bundle-3.1.0 has class "data" which is
not allowed by policy.` From a 1.0.0 or 1.1.x directory it refuses on the 3.0.5
edge instead. See "Upgrading from 1.0.0, 1.1.x or 1.2.x" in the package README.

**Why the baseline was re-emitted rather than given a second genesis edge.**
The 3.0.5 and 3.0.6 entries said this trade must be re-argued on adoption
numbers at each bump. Unlike the 3.0.6 re-emit, this one changes a published
baseline. The team chose it on these numbers: `@cipherstash/stack-prisma` had
481 npm downloads in the 30 days to 3 October 2026, and 384 in the last 7 of
those days, 305 of them on the 1.2.0 release day. The append-only alternative,
a second `from: null` genesis edge, would add another permanent ~2.6 MB copy of
the bundle. That choice was made when 3.1.0 changed only the version stamp; the
comparator change came after it and does not alter the trade, since every
database reaches the same bundle either way.
