-- AUTOMATICALLY GENERATED FILE.
-- ONLY EQL VERSION: 4
-- REQUIRE: src/v3/schema.sql
-- REQUIRE: src/v3/scalars/text/query_text_range_types.sql
-- REQUIRE: src/v3/scalars/text/text_ord_ore_functions.sql
-- REQUIRE: src/v3/scalars/text/text_search_ore_functions.sql
-- REQUIRE: src/v3/scalars/text/text_ord_functions.sql
-- REQUIRE: src/v3/scalars/text/text_ord_ope_functions.sql
-- REQUIRE: src/v3/scalars/text/text_search_functions.sql
-- REQUIRE: src/v3/sem/ore_block_256/functions.sql
-- REQUIRE: src/v3/sem/ore_block_256/operators.sql
-- REQUIRE: src/v3/sem/ope_cllw/functions.sql

--! @file v3/scalars/text/query_text_range_functions.sql
--! @brief The bound accessors and `{{prefix}}.between` for text's range query domains.
--! @note EQL version {{eql_version}} only, like the range domains themselves.

--! @brief The low bound of a {{prefix}}.query_text_range_ore, as a block ORE term.
--!
--! Reads the bound with the term's own constructor, exactly as a single-bound
--! query operand's term is read, so a bound compares like that term would.
--! Internal: only `{{prefix}}.between`'s body calls it, so it is not part of
--! the public `{{prefix}}` surface.
--!
--! @param r {{prefix}}.query_text_range_ore Range query operand
--! @return {{prefix}}_internal.{{ore_block}} The low bound's term (included in the range), or NULL for a NULL range
--! @note IMMUTABLE and STRICT. It is evaluated once per query when
--!       `{{prefix}}.between` is served by an index, since its argument is the
--!       query's parameter, not a column.
CREATE FUNCTION {{prefix}}_internal.lo(r {{prefix}}.query_text_range_ore)
RETURNS {{prefix}}_internal.{{ore_block}}
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}_internal.{{ore_block}}(jsonb_build_object('ob', r::jsonb -> 'lo')) $$;

--! @brief The high bound of a {{prefix}}.query_text_range_ore, as a block ORE term.
--!
--! Reads the bound with the term's own constructor, exactly as a single-bound
--! query operand's term is read, so a bound compares like that term would.
--! Internal: only `{{prefix}}.between`'s body calls it, so it is not part of
--! the public `{{prefix}}` surface.
--!
--! @param r {{prefix}}.query_text_range_ore Range query operand
--! @return {{prefix}}_internal.{{ore_block}} The high bound's term (included in the range), or NULL for a NULL range
--! @note IMMUTABLE and STRICT. It is evaluated once per query when
--!       `{{prefix}}.between` is served by an index, since its argument is the
--!       query's parameter, not a column.
CREATE FUNCTION {{prefix}}_internal.hi(r {{prefix}}.query_text_range_ore)
RETURNS {{prefix}}_internal.{{ore_block}}
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}_internal.{{ore_block}}(jsonb_build_object('ob', r::jsonb -> 'hi')) $$;

--! @brief The low bound of a {{prefix}}.query_text_range_ope, as a CLLW OPE term.
--!
--! Reads the bound with the term's own constructor, exactly as a single-bound
--! query operand's term is read, so a bound compares like that term would.
--! Internal: only `{{prefix}}.between`'s body calls it, so it is not part of
--! the public `{{prefix}}` surface.
--!
--! @param r {{prefix}}.query_text_range_ope Range query operand
--! @return {{prefix}}_internal.ope_cllw The low bound's term (included in the range), or NULL for a NULL range
--! @note IMMUTABLE and STRICT. It is evaluated once per query when
--!       `{{prefix}}.between` is served by an index, since its argument is the
--!       query's parameter, not a column.
CREATE FUNCTION {{prefix}}_internal.lo(r {{prefix}}.query_text_range_ope)
RETURNS {{prefix}}_internal.ope_cllw
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}_internal.ope_cllw(jsonb_build_object('op', r::jsonb -> 'lo')) $$;

--! @brief The high bound of a {{prefix}}.query_text_range_ope, as a CLLW OPE term.
--!
--! Reads the bound with the term's own constructor, exactly as a single-bound
--! query operand's term is read, so a bound compares like that term would.
--! Internal: only `{{prefix}}.between`'s body calls it, so it is not part of
--! the public `{{prefix}}` surface.
--!
--! @param r {{prefix}}.query_text_range_ope Range query operand
--! @return {{prefix}}_internal.ope_cllw The high bound's term (included in the range), or NULL for a NULL range
--! @note IMMUTABLE and STRICT. It is evaluated once per query when
--!       `{{prefix}}.between` is served by an index, since its argument is the
--!       query's parameter, not a column.
CREATE FUNCTION {{prefix}}_internal.hi(r {{prefix}}.query_text_range_ope)
RETURNS {{prefix}}_internal.ope_cllw
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT {{prefix}}_internal.ope_cllw(jsonb_build_object('op', r::jsonb -> 'hi')) $$;

--! @brief Whether a public.{{prefix}}_text_ord_ore value lies in a range, both bounds included.
--!
--! True when `{{prefix}}_internal.lo(r) <= {{prefix}}.ord_term_ore(a) <= {{prefix}}_internal.hi(r)`.
--! The range is one operand, so a statement cannot pair the low bound of one
--! query with the high bound of another (ADR-0009, decision 7):
--! `WHERE {{prefix}}.between(col, $1::{{prefix}}.query_text_range_ore)`.
--!
--! @param a public.{{prefix}}_text_ord_ore Encrypted column value
--! @param r {{prefix}}.query_text_range_ore Range query operand: both bounds of one `BETWEEN`
--! @return boolean True when the value is in the range; NULL when either argument is NULL
--! @note Inlinable on purpose: `LANGUAGE sql`, one expression, IMMUTABLE, no
--!       `SET` clause, and not STRICT. PostgreSQL inlines a STRICT SQL function
--!       only when its body is strict, and `x AND y` is not, so STRICT would
--!       stop inlining. Inlined, the planner sees two comparisons on
--!       `{{prefix}}.ord_term_ore(a)`, which a btree index on that expression
--!       serves as one range scan. For this ORE range that index needs the
--!       default btree operator class on {{prefix}}_internal.{{ore_block}}, which the
--!       installer creates only with superuser privileges. Without it (on Supabase,
--!       for instance) the installer disables the ORE column domains and this ORE range,
--!       so use an OPE column (`public.{{prefix}}_text_ord`, `public.{{prefix}}_text_ord_ope`, `public.{{prefix}}_text_search`)
--!       and `{{prefix}}.query_text_range_ope`, which index everywhere.
--! @note `BETWEEN` is an SQL keyword, so call it schema-qualified:
--!       `{{prefix}}.between(...)` parses, a bare `between(...)` does not.
--! @note Cast the range to its exact domain, `$1::{{prefix}}.query_text_range_ore`.
--!       PostgreSQL resolves a function's domain arguments as their base type,
--!       `jsonb`, and every `between` overload takes jsonb domains, so an
--!       uncast `$1`, a `jsonb` parameter, or a range of another term or
--!       family matches several overloads and the statement fails with 42725
--!       ("function ... is not unique") before it runs. The single-bound
--!       operators resolve an untyped `$1`; `between` does not.
CREATE FUNCTION {{prefix}}.between(a public.{{prefix}}_text_ord_ore, r {{prefix}}.query_text_range_ore)
RETURNS boolean
LANGUAGE sql IMMUTABLE PARALLEL SAFE
AS $$ SELECT {{prefix}}.ord_term_ore(a) >= {{prefix}}_internal.lo(r) AND {{prefix}}.ord_term_ore(a) <= {{prefix}}_internal.hi(r) $$;

--! @brief Whether a public.{{prefix}}_text_search_ore value lies in a range, both bounds included.
--!
--! True when `{{prefix}}_internal.lo(r) <= {{prefix}}.ord_term_ore(a) <= {{prefix}}_internal.hi(r)`.
--! The range is one operand, so a statement cannot pair the low bound of one
--! query with the high bound of another (ADR-0009, decision 7):
--! `WHERE {{prefix}}.between(col, $1::{{prefix}}.query_text_range_ore)`.
--!
--! @param a public.{{prefix}}_text_search_ore Encrypted column value
--! @param r {{prefix}}.query_text_range_ore Range query operand: both bounds of one `BETWEEN`
--! @return boolean True when the value is in the range; NULL when either argument is NULL
--! @note Inlinable on purpose: `LANGUAGE sql`, one expression, IMMUTABLE, no
--!       `SET` clause, and not STRICT. PostgreSQL inlines a STRICT SQL function
--!       only when its body is strict, and `x AND y` is not, so STRICT would
--!       stop inlining. Inlined, the planner sees two comparisons on
--!       `{{prefix}}.ord_term_ore(a)`, which a btree index on that expression
--!       serves as one range scan. For this ORE range that index needs the
--!       default btree operator class on {{prefix}}_internal.{{ore_block}}, which the
--!       installer creates only with superuser privileges. Without it (on Supabase,
--!       for instance) the installer disables the ORE column domains and this ORE range,
--!       so use an OPE column (`public.{{prefix}}_text_ord`, `public.{{prefix}}_text_ord_ope`, `public.{{prefix}}_text_search`)
--!       and `{{prefix}}.query_text_range_ope`, which index everywhere.
--! @note `BETWEEN` is an SQL keyword, so call it schema-qualified:
--!       `{{prefix}}.between(...)` parses, a bare `between(...)` does not.
--! @note Cast the range to its exact domain, `$1::{{prefix}}.query_text_range_ore`.
--!       PostgreSQL resolves a function's domain arguments as their base type,
--!       `jsonb`, and every `between` overload takes jsonb domains, so an
--!       uncast `$1`, a `jsonb` parameter, or a range of another term or
--!       family matches several overloads and the statement fails with 42725
--!       ("function ... is not unique") before it runs. The single-bound
--!       operators resolve an untyped `$1`; `between` does not.
CREATE FUNCTION {{prefix}}.between(a public.{{prefix}}_text_search_ore, r {{prefix}}.query_text_range_ore)
RETURNS boolean
LANGUAGE sql IMMUTABLE PARALLEL SAFE
AS $$ SELECT {{prefix}}.ord_term_ore(a) >= {{prefix}}_internal.lo(r) AND {{prefix}}.ord_term_ore(a) <= {{prefix}}_internal.hi(r) $$;

--! @brief Whether a public.{{prefix}}_text_ord value lies in a range, both bounds included.
--!
--! True when `{{prefix}}_internal.lo(r) <= {{prefix}}.ord_term(a) <= {{prefix}}_internal.hi(r)`.
--! The range is one operand, so a statement cannot pair the low bound of one
--! query with the high bound of another (ADR-0009, decision 7):
--! `WHERE {{prefix}}.between(col, $1::{{prefix}}.query_text_range_ope)`.
--!
--! @param a public.{{prefix}}_text_ord Encrypted column value
--! @param r {{prefix}}.query_text_range_ope Range query operand: both bounds of one `BETWEEN`
--! @return boolean True when the value is in the range; NULL when either argument is NULL
--! @note Inlinable on purpose: `LANGUAGE sql`, one expression, IMMUTABLE, no
--!       `SET` clause, and not STRICT. PostgreSQL inlines a STRICT SQL function
--!       only when its body is strict, and `x AND y` is not, so STRICT would
--!       stop inlining. Inlined, the planner sees two comparisons on
--!       `{{prefix}}.ord_term(a)`, which a btree index on that expression
--!       serves as one range scan.
--! @note `BETWEEN` is an SQL keyword, so call it schema-qualified:
--!       `{{prefix}}.between(...)` parses, a bare `between(...)` does not.
--! @note Cast the range to its exact domain, `$1::{{prefix}}.query_text_range_ope`.
--!       PostgreSQL resolves a function's domain arguments as their base type,
--!       `jsonb`, and every `between` overload takes jsonb domains, so an
--!       uncast `$1`, a `jsonb` parameter, or a range of another term or
--!       family matches several overloads and the statement fails with 42725
--!       ("function ... is not unique") before it runs. The single-bound
--!       operators resolve an untyped `$1`; `between` does not.
CREATE FUNCTION {{prefix}}.between(a public.{{prefix}}_text_ord, r {{prefix}}.query_text_range_ope)
RETURNS boolean
LANGUAGE sql IMMUTABLE PARALLEL SAFE
AS $$ SELECT {{prefix}}.ord_term(a) >= {{prefix}}_internal.lo(r) AND {{prefix}}.ord_term(a) <= {{prefix}}_internal.hi(r) $$;

--! @brief Whether a public.{{prefix}}_text_ord_ope value lies in a range, both bounds included.
--!
--! True when `{{prefix}}_internal.lo(r) <= {{prefix}}.ord_term(a) <= {{prefix}}_internal.hi(r)`.
--! The range is one operand, so a statement cannot pair the low bound of one
--! query with the high bound of another (ADR-0009, decision 7):
--! `WHERE {{prefix}}.between(col, $1::{{prefix}}.query_text_range_ope)`.
--!
--! @param a public.{{prefix}}_text_ord_ope Encrypted column value
--! @param r {{prefix}}.query_text_range_ope Range query operand: both bounds of one `BETWEEN`
--! @return boolean True when the value is in the range; NULL when either argument is NULL
--! @note Inlinable on purpose: `LANGUAGE sql`, one expression, IMMUTABLE, no
--!       `SET` clause, and not STRICT. PostgreSQL inlines a STRICT SQL function
--!       only when its body is strict, and `x AND y` is not, so STRICT would
--!       stop inlining. Inlined, the planner sees two comparisons on
--!       `{{prefix}}.ord_term(a)`, which a btree index on that expression
--!       serves as one range scan.
--! @note `BETWEEN` is an SQL keyword, so call it schema-qualified:
--!       `{{prefix}}.between(...)` parses, a bare `between(...)` does not.
--! @note Cast the range to its exact domain, `$1::{{prefix}}.query_text_range_ope`.
--!       PostgreSQL resolves a function's domain arguments as their base type,
--!       `jsonb`, and every `between` overload takes jsonb domains, so an
--!       uncast `$1`, a `jsonb` parameter, or a range of another term or
--!       family matches several overloads and the statement fails with 42725
--!       ("function ... is not unique") before it runs. The single-bound
--!       operators resolve an untyped `$1`; `between` does not.
CREATE FUNCTION {{prefix}}.between(a public.{{prefix}}_text_ord_ope, r {{prefix}}.query_text_range_ope)
RETURNS boolean
LANGUAGE sql IMMUTABLE PARALLEL SAFE
AS $$ SELECT {{prefix}}.ord_term(a) >= {{prefix}}_internal.lo(r) AND {{prefix}}.ord_term(a) <= {{prefix}}_internal.hi(r) $$;

--! @brief Whether a public.{{prefix}}_text_search value lies in a range, both bounds included.
--!
--! True when `{{prefix}}_internal.lo(r) <= {{prefix}}.ord_term(a) <= {{prefix}}_internal.hi(r)`.
--! The range is one operand, so a statement cannot pair the low bound of one
--! query with the high bound of another (ADR-0009, decision 7):
--! `WHERE {{prefix}}.between(col, $1::{{prefix}}.query_text_range_ope)`.
--!
--! @param a public.{{prefix}}_text_search Encrypted column value
--! @param r {{prefix}}.query_text_range_ope Range query operand: both bounds of one `BETWEEN`
--! @return boolean True when the value is in the range; NULL when either argument is NULL
--! @note Inlinable on purpose: `LANGUAGE sql`, one expression, IMMUTABLE, no
--!       `SET` clause, and not STRICT. PostgreSQL inlines a STRICT SQL function
--!       only when its body is strict, and `x AND y` is not, so STRICT would
--!       stop inlining. Inlined, the planner sees two comparisons on
--!       `{{prefix}}.ord_term(a)`, which a btree index on that expression
--!       serves as one range scan.
--! @note `BETWEEN` is an SQL keyword, so call it schema-qualified:
--!       `{{prefix}}.between(...)` parses, a bare `between(...)` does not.
--! @note Cast the range to its exact domain, `$1::{{prefix}}.query_text_range_ope`.
--!       PostgreSQL resolves a function's domain arguments as their base type,
--!       `jsonb`, and every `between` overload takes jsonb domains, so an
--!       uncast `$1`, a `jsonb` parameter, or a range of another term or
--!       family matches several overloads and the statement fails with 42725
--!       ("function ... is not unique") before it runs. The single-bound
--!       operators resolve an untyped `$1`; `between` does not.
CREATE FUNCTION {{prefix}}.between(a public.{{prefix}}_text_search, r {{prefix}}.query_text_range_ope)
RETURNS boolean
LANGUAGE sql IMMUTABLE PARALLEL SAFE
AS $$ SELECT {{prefix}}.ord_term(a) >= {{prefix}}_internal.lo(r) AND {{prefix}}.ord_term(a) <= {{prefix}}_internal.hi(r) $$;
