-- REQUIRE: src/v3/schema.sql
-- REQUIRE: src/v3/sem/ore_block_256/types.sql
-- REQUIRE: src/v3/sem/ore_block_256/functions.sql

--! @file v3/sem/ore_block_256/operators.sql
--! @brief Comparison operators on eql_v3_internal.ore_block_256.
--!
--! The six backing functions are inlinable single-statement SQL so the planner
--! can fold the eql_v3 comparison wrappers through to functional-index matching.

--! @brief Equality backing function for ORE block types
--! @internal
--!
--! @param a eql_v3_internal.ore_block_256 Left operand
--! @param b eql_v3_internal.ore_block_256 Right operand
--! @return boolean True if the ORE blocks are equal
--!
--! @see eql_v3_internal.compare_ore_block_256_terms
CREATE FUNCTION eql_v3_internal.ore_block_256_eq(a eql_v3_internal.ore_block_256, b eql_v3_internal.ore_block_256)
RETURNS boolean
  LANGUAGE sql
  IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT eql_v3_internal.compare_ore_block_256_terms(a, b) = 0
$$;

--! @brief Not-equal backing function for ORE block types
--! @internal
--!
--! @param a eql_v3_internal.ore_block_256 Left operand
--! @param b eql_v3_internal.ore_block_256 Right operand
--! @return boolean True if the ORE blocks are not equal
--!
--! @see eql_v3_internal.compare_ore_block_256_terms
CREATE FUNCTION eql_v3_internal.ore_block_256_neq(a eql_v3_internal.ore_block_256, b eql_v3_internal.ore_block_256)
RETURNS boolean
  LANGUAGE sql
  IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT eql_v3_internal.compare_ore_block_256_terms(a, b) <> 0
$$;

--! @brief Less-than backing function for ORE block types
--! @internal
--!
--! @param a eql_v3_internal.ore_block_256 Left operand
--! @param b eql_v3_internal.ore_block_256 Right operand
--! @return boolean True if the left operand is less than the right operand
--!
--! @see eql_v3_internal.compare_ore_block_256_terms
CREATE FUNCTION eql_v3_internal.ore_block_256_lt(a eql_v3_internal.ore_block_256, b eql_v3_internal.ore_block_256)
RETURNS boolean
  LANGUAGE sql
  IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT eql_v3_internal.compare_ore_block_256_terms(a, b) = -1
$$;

--! @brief Less-than-or-equal backing function for ORE block types
--! @internal
--!
--! @param a eql_v3_internal.ore_block_256 Left operand
--! @param b eql_v3_internal.ore_block_256 Right operand
--! @return boolean True if the left operand is less than or equal to the right operand
--!
--! @see eql_v3_internal.compare_ore_block_256_terms
CREATE FUNCTION eql_v3_internal.ore_block_256_lte(a eql_v3_internal.ore_block_256, b eql_v3_internal.ore_block_256)
RETURNS boolean
  LANGUAGE sql
  IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT eql_v3_internal.compare_ore_block_256_terms(a, b) != 1
$$;

--! @brief Greater-than backing function for ORE block types
--! @internal
--!
--! @param a eql_v3_internal.ore_block_256 Left operand
--! @param b eql_v3_internal.ore_block_256 Right operand
--! @return boolean True if the left operand is greater than the right operand
--!
--! @see eql_v3_internal.compare_ore_block_256_terms
CREATE FUNCTION eql_v3_internal.ore_block_256_gt(a eql_v3_internal.ore_block_256, b eql_v3_internal.ore_block_256)
RETURNS boolean
  LANGUAGE sql
  IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT eql_v3_internal.compare_ore_block_256_terms(a, b) = 1
$$;

--! @brief Greater-than-or-equal backing function for ORE block types
--! @internal
--!
--! @param a eql_v3_internal.ore_block_256 Left operand
--! @param b eql_v3_internal.ore_block_256 Right operand
--! @return boolean True if the left operand is greater than or equal to the right operand
--!
--! @see eql_v3_internal.compare_ore_block_256_terms
CREATE FUNCTION eql_v3_internal.ore_block_256_gte(a eql_v3_internal.ore_block_256, b eql_v3_internal.ore_block_256)
RETURNS boolean
  LANGUAGE sql
  IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT eql_v3_internal.compare_ore_block_256_terms(a, b) != -1
$$;


--! @brief = operator for ORE block types
--!
--! COMMUTATOR is the operator itself: equality is symmetric. Required for the
--! MERGES flag — without it the planner raises "could not find commutator" the
--! first time an ore_block equality is used as a join qual (e.g. via the inlined
--! eql_v3_internal.<T>_ord_ore equality wrappers).
CREATE OPERATOR public.= (
  FUNCTION=eql_v3_internal.ore_block_256_eq,
  LEFTARG=eql_v3_internal.ore_block_256,
  RIGHTARG=eql_v3_internal.ore_block_256,
  COMMUTATOR = OPERATOR(public.=),
  NEGATOR = OPERATOR(public.<>),
  RESTRICT = eqsel,
  JOIN = eqjoinsel,
  HASHES,
  MERGES
);

--! @brief <> operator for ORE block types
CREATE OPERATOR public.<> (
  FUNCTION=eql_v3_internal.ore_block_256_neq,
  LEFTARG=eql_v3_internal.ore_block_256,
  RIGHTARG=eql_v3_internal.ore_block_256,
  COMMUTATOR = OPERATOR(public.<>),
  NEGATOR = OPERATOR(public.=),
  RESTRICT = neqsel,
  JOIN = neqjoinsel,
  MERGES
);

--! @brief > operator for ORE block types
CREATE OPERATOR public.> (
  FUNCTION=eql_v3_internal.ore_block_256_gt,
  LEFTARG=eql_v3_internal.ore_block_256,
  RIGHTARG=eql_v3_internal.ore_block_256,
  COMMUTATOR = OPERATOR(public.<),
  NEGATOR = OPERATOR(public.<=),
  RESTRICT = scalargtsel,
  JOIN = scalargtjoinsel
);

--! @brief < operator for ORE block types
CREATE OPERATOR public.< (
  FUNCTION=eql_v3_internal.ore_block_256_lt,
  LEFTARG=eql_v3_internal.ore_block_256,
  RIGHTARG=eql_v3_internal.ore_block_256,
  COMMUTATOR = OPERATOR(public.>),
  NEGATOR = OPERATOR(public.>=),
  RESTRICT = scalarltsel,
  JOIN = scalarltjoinsel
);

--! @brief <= operator for ORE block types
CREATE OPERATOR public.<= (
  FUNCTION=eql_v3_internal.ore_block_256_lte,
  LEFTARG=eql_v3_internal.ore_block_256,
  RIGHTARG=eql_v3_internal.ore_block_256,
  COMMUTATOR = OPERATOR(public.>=),
  NEGATOR = OPERATOR(public.>),
  RESTRICT = scalarlesel,
  JOIN = scalarlejoinsel
);

--! @brief >= operator for ORE block types
CREATE OPERATOR public.>= (
  FUNCTION=eql_v3_internal.ore_block_256_gte,
  LEFTARG=eql_v3_internal.ore_block_256,
  RIGHTARG=eql_v3_internal.ore_block_256,
  COMMUTATOR = OPERATOR(public.<=),
  NEGATOR = OPERATOR(public.<),
  RESTRICT = scalargesel,
  JOIN = scalargejoinsel
);
