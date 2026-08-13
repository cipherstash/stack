-- REQUIRE: src/v3/schema.sql

--! @file v3/aggregates.sql
--! @brief Aggregates for grouping and deduplicating encrypted values.
--!
--! Provides `eql_v3.grouped_value` — the aggregate you need to run a `GROUP BY`
--! over an encrypted column and still get the encrypted value back.
--!
--! ## Grouping encrypted values
--!
--! Encryption in EQL is non-deterministic: encrypting the same value twice gives
--! two different ciphertexts. So you cannot group rows by comparing the stored
--! ciphertext. Instead you group by the column's *equality term*,
--! `eql_v3.eq_term(col)` — a deterministic keyed hash that is identical for equal
--! plaintexts. Counting how many rows share each encrypted value looks like this
--! (the term itself is opaque, so there is no reason to select it):
--!
--!   SELECT count(*)
--!   FROM users
--!   GROUP BY eql_v3.eq_term(email);
--!
--! The equality term is opaque, though — you usually want the encrypted value
--! itself back so your application can decrypt it. Adding the column to the
--! SELECT list is rejected:
--!
--!   SELECT email, count(*)                        -- email is not in GROUP BY
--!   FROM users
--!   GROUP BY eql_v3.eq_term(email);
--!   -- ERROR: column "email" must appear in the GROUP BY clause or be used in
--!   --        an aggregate function
--!
--! Every row in a group is an encryption of the same plaintext, so any one of
--! them represents the group. `eql_v3.grouped_value` is the aggregate that hands
--! one back:
--!
--!   SELECT eql_v3.grouped_value(email) AS email, count(*)
--!   FROM users
--!   GROUP BY eql_v3.eq_term(email);
--!
--! ## Deduplicating without an aggregate
--!
--! If you just want the distinct encrypted values (no per-group aggregate like
--! `count`), you do not need `grouped_value` — use `DISTINCT ON` on the equality
--! term, which lets you project the column directly:
--!
--!   SELECT DISTINCT ON (eql_v3.eq_term(email)) email
--!   FROM users
--!   ORDER BY eql_v3.eq_term(email);
--!
--! Deduplicate on `eql_v3.eq_term(col)`, never on the column itself: a plain
--! `SELECT DISTINCT email` compares the raw ciphertext, so two encryptions of the
--! same value are NOT collapsed.
--!
--! @note @internal Hand-written rather than catalog-generated: `grouped_value` is
--!   generic over every encrypted-domain type — each is a jsonb-backed domain, so
--!   a single aggregate over `jsonb` accepts them all and returns the value
--!   unchanged — unlike the per-type `min`/`max` aggregates. Re-creates the
--!   eql_v2 aggregate of the same name.

--! @brief State transition function for the grouped_value aggregate.
--! @internal
--!
--! Returns the running state so the first value the aggregate sees in a group
--! wins. Declared STRICT: PostgreSQL seeds the null initial state with the first
--! non-null input (without calling this function) and skips subsequent nulls, so
--! the aggregate resolves to the first non-null value in the group — the same
--! result the eql_v2 `COALESCE($1, $2)` state function produced.
--!
--! Per the encrypted-domain footgun rules this is `LANGUAGE plpgsql` with a
--! pinned `search_path`, matching the generated `min`/`max` state functions; an
--! aggregate state function is never a predicate the planner could inline, but
--! keeping the convention uniform avoids surprises.
--!
--! @param state jsonb Accumulated state (the first non-null value seen).
--! @param value jsonb New value from the current row.
--! @return jsonb The running state (first non-null value).
--!
--! @see eql_v3.grouped_value
CREATE FUNCTION eql_v3_internal.grouped_value_sfunc(state jsonb, value jsonb)
RETURNS jsonb
LANGUAGE plpgsql IMMUTABLE STRICT PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RETURN state;
END;
$$;

--! @brief Return a representative (first non-null) encrypted value per group.
--!
--! Returns the first non-null value encountered within a `GROUP BY` group. Its
--! primary use is projecting an encrypted column while grouping by that column's
--! equality term (`GROUP BY eql_v3.eq_term(col)`), where PostgreSQL will not let
--! you `SELECT col` directly — see the file header for the worked example.
--! Accepts any eql_v3 encrypted-domain value (each is a jsonb-backed domain) and
--! returns it unchanged, performing no decryption or comparison. `PARALLEL SAFE`
--! with a combine function, so it works under partial/parallel aggregation on
--! large `GROUP BY` workloads.
--!
--! @param input jsonb Encrypted values to aggregate.
--! @return jsonb The first non-null value in the group.
--!
--! @note Which value is "first" is arbitrary in the absence of an ordering, and
--!   is not deterministic under parallel aggregation. That is exactly what is
--!   wanted for the group-by-eq_term case (every value in a group is an
--!   encryption of the same plaintext, so any one represents the group) and it
--!   matches the eql_v2 original.
--!
--! Group encrypted rows by encrypted equality and project the encrypted
--! column. GROUP BY eql_v3.eq_term(...) groups by the HMAC equality term;
--! grouped_value(...) returns a representative ciphertext for each group so
--! PostgreSQL does not reject the bare column reference.
--!
--! @code{.sql}
--! SELECT eql_v3.grouped_value(encrypted_foo) AS encrypted_foo,
--!        count(*)
--! FROM some_table
--! GROUP BY eql_v3.eq_term(encrypted_foo);
--! @endcode
--!
--! @see eql_v3_internal.grouped_value_sfunc
--! @see eql_v3.eq_term
CREATE AGGREGATE eql_v3.grouped_value(jsonb) (
  sfunc = eql_v3_internal.grouped_value_sfunc,
  stype = jsonb,
  combinefunc = eql_v3_internal.grouped_value_sfunc,
  parallel = safe
);
