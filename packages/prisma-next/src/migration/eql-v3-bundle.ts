/**
 * Vendored CipherStash EQL **v3** bundle SQL.
 *
 * v3 is the domain-based encryption model: the installer creates the `eql_v3`
 * schema, the `eql_v3.text*` domains (`text`, `text_eq`, `text_match`,
 * `text_ord`), and the extracted-index-term extractor functions
 * (`eq_term`/`ord_term`/`match_term`, `hmac_256`, `ore_block_u64_8_256`,
 * `bloom_filter`). Like the v2 bundle, CipherStash treats it as one indivisible
 * artefact: it flows into the `cipherstash:install-eql-v3-bundle-v1` migration
 * op **byte-for-byte**.
 *
 * Source lives in {@link ./eql-v3-install.generated} — a committed
 * `.generated.ts` produced by `scripts/vendor-eql-v3-install.ts` from
 * `__tests__/fixtures/cipherstash-encrypt-v3.sql`. See
 * `scripts/REFRESH_EQL_V3.md` for the refresh procedure.
 */
export { EQL_V3_INSTALL_SQL as EQL_V3_BUNDLE_SQL, EQL_V3_INSTALL_VERSION } from './eql-v3-install.generated'
