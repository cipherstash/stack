-- Bench fixture schema.
-- Single bench table covering text / int / jsonb encrypted columns plus the
-- three canonical EQL v3 functional indexes.
--
-- Mirrors `src/drizzle/setup.ts`: the columns are concrete `eql_v3_*` Postgres
-- domains (see `types.TextSearch` / `types.IntegerOrd` / `types.Json`). Install
-- the domains and index-term functions first with `stash eql install --eql-version 3`.
--
-- Each index expression must be the expression the matching EQL v3 operator
-- INLINES TO, not merely a term extractor for the same column. The adapter
-- emits a function call (`eql_v3.eq(col, term)`, `eql_v3.matches(...)`,
-- `col @> needle`); every one of those is `LANGUAGE sql IMMUTABLE STRICT`
-- with a single-SELECT body, so the planner inlines it, and Postgres applies
-- the same inlining to the stored index expression. The two only meet if the
-- index is built on the inlined form:
--
--   eql_v3.eq(a, b)      -> eql_v3.eq_term(a) = eql_v3.eq_term(b)
--   eql_v3.matches(a, b) -> eql_v3.match_term(a) @> eql_v3.match_term(b)
--   a @> b (json)        -> eql_v3.to_ste_vec_query(a)::jsonb
--                             @> eql_v3.to_ste_vec_query(b)::jsonb
--
-- That last one is why the JSON index is NOT on `eql_v3.ste_vec(...)`: that
-- function exists and the index builds happily, but nothing the adapter emits
-- ever mentions it, so the index is dead weight. The bundle says so itself, on
-- `eql_v3."@>"(eql_v3_json_search, eql_v3.query_json)`: "Inlines to native
-- `jsonb @>` over `eql_v3.to_ste_vec_query(a)::jsonb`, so a functional GIN
-- index on the same expression engages."
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
    ON bench USING gin  ((eql_v3.to_ste_vec_query(enc_jsonb)::jsonb));

ANALYZE bench;
