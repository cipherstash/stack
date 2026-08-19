---
'stash': patch
---

`stash eql status` no longer reports ORE damage on a healthy database running a
different EQL version. The `_ord_ore` domains its poison CHECKs are counted over
come from the bundle this CLI pins, so a fallback install of an older EQL poisons
domains the pinned list only partly sees — which classified as an incoherent
half-install and told the operator to reinstall with `--force`, on the ordinary
"CLI upgraded, database not yet" case. The ORE probe now gates on the installed
version the same way `eql verify` does and reports that the state could not be
compared, pointing at `eql upgrade`.

Two hardening fixes to `stash eql verify` alongside it. Its cast check now
matches an EQL endpoint on either side, so a future bundle cast to or from a
`pg_catalog` type (`jsonb`, `text`) cannot enter the expected surface while being
unreadable as installed — which would have reported "Cast missing" on every
healthy database. And the parser that derives the expected surface from the
pinned bundle now fails loudly on any statement it does not model, instead of
silently omitting the objects it creates: a bundle that outgrows the parser can
no longer make `verify` report a partial install as complete.
