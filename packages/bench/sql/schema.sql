-- Bench fixture schema.
-- Single bench table covering text / int / jsonb encrypted columns plus the
-- three canonical EQL v3 functional indexes over the column-side index terms:
-- eq_term (hash), match_term (GIN bloom), ste_vec (GIN).
--
-- Mirrors `src/drizzle/setup.ts`: the columns are concrete `eql_v3_*` Postgres
-- domains (see `types.TextSearch` / `types.IntegerOrd` / `types.Json`). Install
-- the domains and index-term functions first with `stash eql install --eql-version 3`.
--
-- We deliberately do NOT create btree operator-class indexes: encrypted terms for
-- full-feature columns blow past the 2704-byte btree page-size limit, and the
-- bench's whole job is to validate that the functional-index path works.

DROP TABLE IF EXISTS bench;

CREATE TABLE bench (
    id        SERIAL PRIMARY KEY,
    enc_text  public.eql_v3_text_search NOT NULL,
    enc_int   public.eql_v3_integer_ord NOT NULL,
    enc_jsonb public.eql_v3_json_search NOT NULL
);

CREATE INDEX bench_text_hmac_idx
    ON bench USING hash (eql_v3.eq_term(enc_text));

CREATE INDEX bench_text_bloom_idx
    ON bench USING gin  (eql_v3.match_term(enc_text));

CREATE INDEX bench_jsonb_stevec_idx
    ON bench USING gin  (eql_v3.ste_vec(enc_jsonb));

ANALYZE bench;
