-- REQUIRE: src/v3/schema.sql

--! @file v3/scalars/functions.sql
--! @brief Shared blocker helper for the {{prefix}} encrypted-domain families.
--!
--! Per-domain wrapper functions live in src/v3/scalars/<T>/.
--! Blockers in those files delegate to encrypted_domain_unsupported_bool
--! so every domain raises a uniform domain-specific error rather than
--! letting an unsupported operator fall through to native jsonb
--! behaviour.

--! @brief Shared blocker helper. Raises 'operator X is not supported
--!        for TYPE' so unsupported domain operators surface a clear
--!        error rather than fall through to native jsonb behaviour.
--! @param type_name Domain type name ({{prefix}}.<T>*)
--! @param operator_name Operator symbol (=, <, @>, ->, etc.)
--! @return boolean (never returns; always raises)
CREATE FUNCTION {{prefix}}_internal.encrypted_domain_unsupported_bool(type_name text, operator_name text)
RETURNS boolean
IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RAISE EXCEPTION 'operator % is not supported for %', operator_name, type_name;
END;
$$ LANGUAGE plpgsql;

--! @brief Shared blocker helper returning jsonb. Identical to
--!        encrypted_domain_unsupported_bool but typed for blockers shadowing
--!        native operators whose result is jsonb (#>, -, #-, ||), so composed
--!        expressions resolve and the body raises rather than failing earlier
--!        with a misleading 'operator does not exist' on a boolean result.
--! @param type_name Domain type name ({{prefix}}.<T>*)
--! @param operator_name Operator symbol (#>, -, #-, ||, etc.)
--! @return jsonb (never returns; always raises)
CREATE FUNCTION {{prefix}}_internal.encrypted_domain_unsupported_jsonb(type_name text, operator_name text)
RETURNS jsonb
IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RAISE EXCEPTION 'operator % is not supported for %', operator_name, type_name;
END;
$$ LANGUAGE plpgsql;

--! @brief Shared blocker helper returning text. Identical to
--!        encrypted_domain_unsupported_bool but typed for blockers shadowing
--!        the native #>> operator whose result is text.
--! @param type_name Domain type name ({{prefix}}.<T>*)
--! @param operator_name Operator symbol (#>>)
--! @return text (never returns; always raises)
CREATE FUNCTION {{prefix}}_internal.encrypted_domain_unsupported_text(type_name text, operator_name text)
RETURNS text
IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RAISE EXCEPTION 'operator % is not supported for %', operator_name, type_name;
END;
$$ LANGUAGE plpgsql;
-- {{#v4}}

--! @brief Return a query operand unchanged when it carries the named term,
--!        and raise when it does not.
--!
--! An EQL v4 search-domain query operand ({{prefix}}.query_text_search,
--! {{prefix}}.query_text_search_ore) carries only the terms its operator
--! reads, so each extractor over it reads its term through this helper. A
--! missing term raises here rather than reading as NULL, which would compare
--! as no row.
--!
--! A term whose value is JSON `null` is missing, and so is an empty array: a
--! `bf` with no positions is the filter of text that cuts no match token (one
--! letter, or none), which a stored filter of the same text would contain, so
--! a query carrying it would match exactly the stored values no match query
--! should find.
--!
--! The raise happens where the operand is evaluated, not where the statement
--! is planned. A literal operand is folded at plan time and raises even over
--! an empty table; a bound parameter under a generic plan raises wherever the
--! extractor reads it (an index scan always does, to build its key), and a
--! plan that never reaches the predicate returns no row and no error.
--! @internal
--! @param val jsonb The query operand.
--! @param domain_name text The operand's domain, for the message.
--! @param term text The JSON key of the term the extractor reads (hm, op, ob, bf).
--! @param operators text The operators that read the term, for the message.
--! @return jsonb `val`, unchanged.
--! @throws invalid_parameter_value When `val` has no `term` key, or its value
--!         is JSON `null` or an empty array. The message names the domain, the
--!         term and the operators, never the operand.
CREATE FUNCTION {{prefix}}_internal.require_query_term(val jsonb, domain_name text, term text, operators text)
RETURNS jsonb
IMMUTABLE STRICT PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  IF NOT (val ? term)
    OR jsonb_typeof(val -> term) = 'null'
    OR (jsonb_typeof(val -> term) = 'array' AND jsonb_array_length(val -> term) = 0) THEN
    RAISE EXCEPTION '% value has no "%" term, the term % compare', domain_name, term, operators
      USING ERRCODE = 'invalid_parameter_value';
  END IF;
  RETURN val;
END;
$$ LANGUAGE plpgsql;
-- {{/v4}}
