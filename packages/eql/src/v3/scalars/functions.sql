-- REQUIRE: src/v3/schema.sql

--! @file v3/scalars/functions.sql
--! @brief Shared blocker helper for the eql_v3 encrypted-domain families.
--!
--! Per-domain wrapper functions live in src/v3/scalars/<T>/.
--! Blockers in those files delegate to encrypted_domain_unsupported_bool
--! so every domain raises a uniform domain-specific error rather than
--! letting an unsupported operator fall through to native jsonb
--! behaviour.

--! @brief Shared blocker helper. Raises 'operator X is not supported
--!        for TYPE' so unsupported domain operators surface a clear
--!        error rather than fall through to native jsonb behaviour.
--! @param type_name Domain type name (eql_v3.<T>*)
--! @param operator_name Operator symbol (=, <, @>, ->, etc.)
--! @return boolean (never returns; always raises)
CREATE FUNCTION eql_v3_internal.encrypted_domain_unsupported_bool(type_name text, operator_name text)
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
--! @param type_name Domain type name (eql_v3.<T>*)
--! @param operator_name Operator symbol (#>, -, #-, ||, etc.)
--! @return jsonb (never returns; always raises)
CREATE FUNCTION eql_v3_internal.encrypted_domain_unsupported_jsonb(type_name text, operator_name text)
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
--! @param type_name Domain type name (eql_v3.<T>*)
--! @param operator_name Operator symbol (#>>)
--! @return text (never returns; always raises)
CREATE FUNCTION eql_v3_internal.encrypted_domain_unsupported_text(type_name text, operator_name text)
RETURNS text
IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RAISE EXCEPTION 'operator % is not supported for %', operator_name, type_name;
END;
$$ LANGUAGE plpgsql;
