---
'@cipherstash/prisma-next': minor
---

**Breaking:** EQL v3 columns are now authored through **concrete per-domain constructors** — the constructor you choose *is* the capability set. The legacy boolean-option surface (`EncryptedString({ equality, freeTextSearch, orderAndRange })`) is not carried into v3.

- New per-domain constructors, one per exposed `public.eql_v3_*` domain:
  - Text: `EncryptedText` (storage), `EncryptedTextEq`, `EncryptedTextOrd` (eq + order/range), `EncryptedTextMatch` (free-text), `EncryptedTextSearch` (eq + free-text + order/range).
  - Scalars (Integer, Smallint, BigInt, Numeric, Real, Double, Date, Timestamp): `Encrypted<Fam>` (storage), `Encrypted<Fam>Eq`, `Encrypted<Fam>Ord`.
  - `EncryptedBoolean` — storage-only (`public.eql_v3_boolean`); there is no boolean equality constructor.
  - `EncryptedJson` — searchable encrypted JSONB (`public.eql_v3_json`, `ste_vec`), queried with `cipherstashJsonContains` (`@>` containment).
- **Impossible capability combinations have no constructor** (e.g. text equality + free-text without order/range) — they are unrepresentable, not runtime errors.
- **BigInt is a first-class v3 family** (`EncryptedBigInt` / `EncryptedBigIntEq` / `EncryptedBigIntOrd`, JS `bigint` plaintext, backed by `public.eql_v3_bigint*`).
- Use the `*V2` constructors (`EncryptedStringV2`, `EncryptedDoubleV2`, `EncryptedBigIntV2`, `EncryptedDateV2`, `EncryptedBooleanV2`, `EncryptedJsonV2`) to keep EQL v2 columns. A client is v2 or v3 — the two runtime descriptors are never co-registered.
- New `@cipherstash/prisma-next/v3` entry point: `cipherstashFromStackV3({ contractJson })` builds the v3 runtime descriptor, bulk-encrypt middleware, and a stack `EncryptionV3` client from the emitted contract.
- Query operators (`cipherstashEq`, `cipherstashGt`, `cipherstashBetween`, `cipherstashInArray`, …) lower to `eql_v3.*` functions with operands cast to the domain's query type (`$n::eql_v3.query_<domain>`); `cipherstashIlike` maps to `eql_v3.contains` (bloom-filter token containment, not SQL `LIKE`); ordering uses `eql_v3.ord_term` / `eql_v3.ord_term_ore` by the column's ordering flavour. The domains are `public.eql_v3_*`; the operator functions live in the `eql_v3` schema.
- A new baseline migration `20260601T0100_install_eql_v3_bundle` (invariant `cipherstash:install-eql-v3-bundle-v1`) installs the `public.eql_v3_*` domains and `eql_v3.*` functions from the pinned `@cipherstash/eql` release. Regenerate contracts and run migrations after changing constructors.
