-- REQUIRE: src/v3/schema.sql

--! @file v3/sem/bloom_filter/types.sql
--! @brief Self-contained eql_v3 Bloom-filter SEM index-term type.

--! @brief Bloom-filter index term: a bit array stored as smallint[].
--!
--! Backs the `matches` fuzzy-match capability (the public `@@` operator /
--! `eql_v3.matches`) on the text match/search domains. The filter is read from
--! the `bf` field of an encrypted jsonb payload. The match wrapper body reduces
--! to native `smallint[]` array-containment (`@>`) on this domain — inherited
--! through the base type — so a functional GIN index on `eql_v3.match_term(col)`
--! engages; this type itself needs no custom operators.
--!
--! @note The public operator is `@@` (fuzzy bloom-token matching), NOT the
--!   containment operators `@>`/`<@`: the match is a probabilistic, one-sided
--!   n-gram token match, not containment. `@>`/`<@` on the text match
--!   domains now raise. Internally the `@@` wrapper still reduces to the base
--!   type's `@>` for GIN indexability.
--! @note Self-contained: references no eql_v2 symbol.
CREATE DOMAIN eql_v3_internal.bloom_filter AS smallint[];
