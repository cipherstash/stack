-- REQUIRE: src/v3/schema.sql
-- REQUIRE: src/v3/sem/ore_block_256/types.sql
-- REQUIRE: src/v3/sem/ore_block_256/functions.sql

--! @file v3/sem/ore_block_256/operators.sql
--! @brief Comparison operators on {{prefix}}_internal.ore_block_256.
--!
--! The six backing functions are inlinable single-statement SQL so the planner
--! can fold the {{prefix}} comparison wrappers through to functional-index matching.

--! @brief Equality backing function for ORE block types
--! @internal
--!
--! @param a {{prefix}}_internal.ore_block_256 Left operand
--! @param b {{prefix}}_internal.ore_block_256 Right operand
--! @return boolean True if the ORE blocks are equal
--!
--! @see {{prefix}}_internal.compare_ore_block_256_terms
CREATE FUNCTION {{prefix}}_internal.ore_block_256_eq(a {{prefix}}_internal.ore_block_256, b {{prefix}}_internal.ore_block_256)
RETURNS boolean
  LANGUAGE sql
  IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT {{prefix}}_internal.compare_ore_block_256_terms(a, b) = 0
$$;

--! @brief Not-equal backing function for ORE block types
--! @internal
--!
--! @param a {{prefix}}_internal.ore_block_256 Left operand
--! @param b {{prefix}}_internal.ore_block_256 Right operand
--! @return boolean True if the ORE blocks are not equal
--!
--! @see {{prefix}}_internal.compare_ore_block_256_terms
CREATE FUNCTION {{prefix}}_internal.ore_block_256_neq(a {{prefix}}_internal.ore_block_256, b {{prefix}}_internal.ore_block_256)
RETURNS boolean
  LANGUAGE sql
  IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT {{prefix}}_internal.compare_ore_block_256_terms(a, b) <> 0
$$;

--! @brief Less-than backing function for ORE block types
--! @internal
--!
--! @param a {{prefix}}_internal.ore_block_256 Left operand
--! @param b {{prefix}}_internal.ore_block_256 Right operand
--! @return boolean True if the left operand is less than the right operand
--!
--! @see {{prefix}}_internal.compare_ore_block_256_terms
CREATE FUNCTION {{prefix}}_internal.ore_block_256_lt(a {{prefix}}_internal.ore_block_256, b {{prefix}}_internal.ore_block_256)
RETURNS boolean
  LANGUAGE sql
  IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT {{prefix}}_internal.compare_ore_block_256_terms(a, b) = -1
$$;

--! @brief Less-than-or-equal backing function for ORE block types
--! @internal
--!
--! @param a {{prefix}}_internal.ore_block_256 Left operand
--! @param b {{prefix}}_internal.ore_block_256 Right operand
--! @return boolean True if the left operand is less than or equal to the right operand
--!
--! @see {{prefix}}_internal.compare_ore_block_256_terms
CREATE FUNCTION {{prefix}}_internal.ore_block_256_lte(a {{prefix}}_internal.ore_block_256, b {{prefix}}_internal.ore_block_256)
RETURNS boolean
  LANGUAGE sql
  IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT {{prefix}}_internal.compare_ore_block_256_terms(a, b) != 1
$$;

--! @brief Greater-than backing function for ORE block types
--! @internal
--!
--! @param a {{prefix}}_internal.ore_block_256 Left operand
--! @param b {{prefix}}_internal.ore_block_256 Right operand
--! @return boolean True if the left operand is greater than the right operand
--!
--! @see {{prefix}}_internal.compare_ore_block_256_terms
CREATE FUNCTION {{prefix}}_internal.ore_block_256_gt(a {{prefix}}_internal.ore_block_256, b {{prefix}}_internal.ore_block_256)
RETURNS boolean
  LANGUAGE sql
  IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT {{prefix}}_internal.compare_ore_block_256_terms(a, b) = 1
$$;

--! @brief Greater-than-or-equal backing function for ORE block types
--! @internal
--!
--! @param a {{prefix}}_internal.ore_block_256 Left operand
--! @param b {{prefix}}_internal.ore_block_256 Right operand
--! @return boolean True if the left operand is greater than or equal to the right operand
--!
--! @see {{prefix}}_internal.compare_ore_block_256_terms
CREATE FUNCTION {{prefix}}_internal.ore_block_256_gte(a {{prefix}}_internal.ore_block_256, b {{prefix}}_internal.ore_block_256)
RETURNS boolean
  LANGUAGE sql
  IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT {{prefix}}_internal.compare_ore_block_256_terms(a, b) != -1
$$;


--! @brief = operator for ORE block types
--!
--! COMMUTATOR is the operator itself: equality is symmetric. Required for the
--! MERGES flag — without it the planner raises "could not find commutator" the
--! first time an ore_block equality is used as a join qual (e.g. via the inlined
--! {{prefix}}_internal.<T>_ord_ore equality wrappers).
CREATE OPERATOR public.= (
  FUNCTION={{prefix}}_internal.ore_block_256_eq,
  LEFTARG={{prefix}}_internal.ore_block_256,
  RIGHTARG={{prefix}}_internal.ore_block_256,
  COMMUTATOR = OPERATOR(public.=),
  NEGATOR = OPERATOR(public.<>),
  RESTRICT = eqsel,
  JOIN = eqjoinsel,
  HASHES,
  MERGES
);

--! @brief <> operator for ORE block types
CREATE OPERATOR public.<> (
  FUNCTION={{prefix}}_internal.ore_block_256_neq,
  LEFTARG={{prefix}}_internal.ore_block_256,
  RIGHTARG={{prefix}}_internal.ore_block_256,
  COMMUTATOR = OPERATOR(public.<>),
  NEGATOR = OPERATOR(public.=),
  RESTRICT = neqsel,
  JOIN = neqjoinsel,
  MERGES
);

--! @brief > operator for ORE block types
CREATE OPERATOR public.> (
  FUNCTION={{prefix}}_internal.ore_block_256_gt,
  LEFTARG={{prefix}}_internal.ore_block_256,
  RIGHTARG={{prefix}}_internal.ore_block_256,
  COMMUTATOR = OPERATOR(public.<),
  NEGATOR = OPERATOR(public.<=),
  RESTRICT = scalargtsel,
  JOIN = scalargtjoinsel
);

--! @brief < operator for ORE block types
CREATE OPERATOR public.< (
  FUNCTION={{prefix}}_internal.ore_block_256_lt,
  LEFTARG={{prefix}}_internal.ore_block_256,
  RIGHTARG={{prefix}}_internal.ore_block_256,
  COMMUTATOR = OPERATOR(public.>),
  NEGATOR = OPERATOR(public.>=),
  RESTRICT = scalarltsel,
  JOIN = scalarltjoinsel
);

--! @brief <= operator for ORE block types
CREATE OPERATOR public.<= (
  FUNCTION={{prefix}}_internal.ore_block_256_lte,
  LEFTARG={{prefix}}_internal.ore_block_256,
  RIGHTARG={{prefix}}_internal.ore_block_256,
  COMMUTATOR = OPERATOR(public.>=),
  NEGATOR = OPERATOR(public.>),
  RESTRICT = scalarlesel,
  JOIN = scalarlejoinsel
);

--! @brief >= operator for ORE block types
CREATE OPERATOR public.>= (
  FUNCTION={{prefix}}_internal.ore_block_256_gte,
  LEFTARG={{prefix}}_internal.ore_block_256,
  RIGHTARG={{prefix}}_internal.ore_block_256,
  COMMUTATOR = OPERATOR(public.<=),
  NEGATOR = OPERATOR(public.<),
  RESTRICT = scalargesel,
  JOIN = scalargejoinsel
);
