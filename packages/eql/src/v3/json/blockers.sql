-- REQUIRE: src/v3/schema.sql
-- REQUIRE: src/v3/json/types.sql
-- REQUIRE: src/v3/scalars/functions.sql

--! @file v3/json/blockers.sql
--! @brief Native-jsonb firewall for public.eql_v3_json_search.
--!
--! public.eql_v3_json_search SUPPORTS @> <@ -> ->> (see operators.sql). Comparisons
--! Ordered comparisons < <= > >= are supported on public.eql_v3_json_entry;
--! entry equality = <> is blocked because path entries carry no exact value
--! selector. Root-document comparisons are also blocked.
--! Every OTHER native jsonb operator reachable via domain fallback against the
--! base type jsonb is BLOCKED here so an encrypted column can never silently
--! route to plaintext-jsonb semantics. The blocked set is KNOWN_JSONB_OPERATORS
--! minus the supported ops: ? ?| ?& @? @@ #> #>> - #- ||.
--!
--! Each blocker is LANGUAGE plpgsql (NEVER STRICT — a STRICT blocker would let
--! PostgreSQL skip the body and return NULL on a NULL argument, bypassing the
--! exception) and delegates to the shared eql_v3.encrypted_domain_unsupported_*
--! helpers. Each blocker's RETURNS type matches the native operator it shadows
--! (#> -> jsonb, #>> -> text, - / #- / || -> jsonb; the rest are boolean) so a
--! composed expression resolves and the body raises 'operator not supported',
--! rather than failing earlier with a misleading 'operator does not exist' on a
--! boolean intermediate. The bound operator must resolve before native fallback,
--! so the firewall fires.

--! @brief Blocker: ? (key/element exists).
--! @param a public.eql_v3_json_search Left operand (encrypted payload).
--! @param b text Native RHS operand.
--! @return boolean Never returns; always raises 'operator not supported'.
CREATE FUNCTION eql_v3_internal.jsonb_blocked_exists(a public.eql_v3_json_search, b text)
RETURNS boolean
IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RETURN eql_v3_internal.encrypted_domain_unsupported_bool('public.eql_v3_json_search', '?');
END;
$$ LANGUAGE plpgsql;

CREATE OPERATOR ? (
  FUNCTION = eql_v3_internal.jsonb_blocked_exists,
  LEFTARG = public.eql_v3_json_search,
  RIGHTARG = text
);

--! @brief Blocker: ?| (any key exists).
--! @param a public.eql_v3_json_search Left operand (encrypted payload).
--! @param b text[] Native RHS operand.
--! @return boolean Never returns; always raises 'operator not supported'.
CREATE FUNCTION eql_v3_internal.jsonb_blocked_exists_any(a public.eql_v3_json_search, b text[])
RETURNS boolean
IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RETURN eql_v3_internal.encrypted_domain_unsupported_bool('public.eql_v3_json_search', '?|');
END;
$$ LANGUAGE plpgsql;

CREATE OPERATOR ?| (
  FUNCTION = eql_v3_internal.jsonb_blocked_exists_any,
  LEFTARG = public.eql_v3_json_search,
  RIGHTARG = text[]
);

--! @brief Blocker: ?& (all keys exist).
--! @param a public.eql_v3_json_search Left operand (encrypted payload).
--! @param b text[] Native RHS operand.
--! @return boolean Never returns; always raises 'operator not supported'.
CREATE FUNCTION eql_v3_internal.jsonb_blocked_exists_all(a public.eql_v3_json_search, b text[])
RETURNS boolean
IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RETURN eql_v3_internal.encrypted_domain_unsupported_bool('public.eql_v3_json_search', '?&');
END;
$$ LANGUAGE plpgsql;

CREATE OPERATOR ?& (
  FUNCTION = eql_v3_internal.jsonb_blocked_exists_all,
  LEFTARG = public.eql_v3_json_search,
  RIGHTARG = text[]
);

--! @brief Blocker: @? (jsonpath exists).
--! @param a public.eql_v3_json_search Left operand (encrypted payload).
--! @param b jsonpath Native RHS operand.
--! @return boolean Never returns; always raises 'operator not supported'.
CREATE FUNCTION eql_v3_internal.jsonb_blocked_jsonpath_exists(a public.eql_v3_json_search, b jsonpath)
RETURNS boolean
IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RETURN eql_v3_internal.encrypted_domain_unsupported_bool('public.eql_v3_json_search', '@?');
END;
$$ LANGUAGE plpgsql;

CREATE OPERATOR @? (
  FUNCTION = eql_v3_internal.jsonb_blocked_jsonpath_exists,
  LEFTARG = public.eql_v3_json_search,
  RIGHTARG = jsonpath
);

--! @brief Blocker: @@ (jsonpath predicate).
--! @param a public.eql_v3_json_search Left operand (encrypted payload).
--! @param b jsonpath Native RHS operand.
--! @return boolean Never returns; always raises 'operator not supported'.
CREATE FUNCTION eql_v3_internal.jsonb_blocked_jsonpath_match(a public.eql_v3_json_search, b jsonpath)
RETURNS boolean
IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RETURN eql_v3_internal.encrypted_domain_unsupported_bool('public.eql_v3_json_search', '@@');
END;
$$ LANGUAGE plpgsql;

CREATE OPERATOR @@ (
  FUNCTION = eql_v3_internal.jsonb_blocked_jsonpath_match,
  LEFTARG = public.eql_v3_json_search,
  RIGHTARG = jsonpath
);

--! @brief Blocker: #> (path extract, native returns jsonb).
--! @param a public.eql_v3_json_search Left operand (encrypted payload).
--! @param b text[] Native RHS operand.
--! @return jsonb Never returns; always raises 'operator not supported'.
CREATE FUNCTION eql_v3_internal.jsonb_blocked_path_extract(a public.eql_v3_json_search, b text[])
RETURNS jsonb
IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RETURN eql_v3_internal.encrypted_domain_unsupported_jsonb('public.eql_v3_json_search', '#>');
END;
$$ LANGUAGE plpgsql;

CREATE OPERATOR #> (
  FUNCTION = eql_v3_internal.jsonb_blocked_path_extract,
  LEFTARG = public.eql_v3_json_search,
  RIGHTARG = text[]
);

--! @brief Blocker: #>> (path extract as text).
--! @param a public.eql_v3_json_search Left operand (encrypted payload).
--! @param b text[] Native RHS operand.
--! @return text Never returns; always raises 'operator not supported'.
CREATE FUNCTION eql_v3_internal.jsonb_blocked_path_extract_text(a public.eql_v3_json_search, b text[])
RETURNS text
IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RETURN eql_v3_internal.encrypted_domain_unsupported_text('public.eql_v3_json_search', '#>>');
END;
$$ LANGUAGE plpgsql;

CREATE OPERATOR #>> (
  FUNCTION = eql_v3_internal.jsonb_blocked_path_extract_text,
  LEFTARG = public.eql_v3_json_search,
  RIGHTARG = text[]
);

--! @brief Blocker: - (delete key, text RHS; native returns jsonb).
--! @param a public.eql_v3_json_search Left operand (encrypted payload).
--! @param b text Native RHS operand.
--! @return jsonb Never returns; always raises 'operator not supported'.
CREATE FUNCTION eql_v3_internal.jsonb_blocked_delete_text(a public.eql_v3_json_search, b text)
RETURNS jsonb
IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RETURN eql_v3_internal.encrypted_domain_unsupported_jsonb('public.eql_v3_json_search', '-');
END;
$$ LANGUAGE plpgsql;

CREATE OPERATOR - (
  FUNCTION = eql_v3_internal.jsonb_blocked_delete_text,
  LEFTARG = public.eql_v3_json_search,
  RIGHTARG = text
);

--! @brief Blocker: - (delete index, integer RHS).
--! @param a public.eql_v3_json_search Left operand (encrypted payload).
--! @param b integer Native RHS operand.
--! @return jsonb Never returns; always raises 'operator not supported'.
CREATE FUNCTION eql_v3_internal.jsonb_blocked_delete_int(a public.eql_v3_json_search, b integer)
RETURNS jsonb
IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RETURN eql_v3_internal.encrypted_domain_unsupported_jsonb('public.eql_v3_json_search', '-');
END;
$$ LANGUAGE plpgsql;

CREATE OPERATOR - (
  FUNCTION = eql_v3_internal.jsonb_blocked_delete_int,
  LEFTARG = public.eql_v3_json_search,
  RIGHTARG = integer
);

--! @brief Blocker: - (delete keys, text[] RHS).
--! @param a public.eql_v3_json_search Left operand (encrypted payload).
--! @param b text[] Native RHS operand.
--! @return jsonb Never returns; always raises 'operator not supported'.
CREATE FUNCTION eql_v3_internal.jsonb_blocked_delete_array(a public.eql_v3_json_search, b text[])
RETURNS jsonb
IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RETURN eql_v3_internal.encrypted_domain_unsupported_jsonb('public.eql_v3_json_search', '-');
END;
$$ LANGUAGE plpgsql;

CREATE OPERATOR - (
  FUNCTION = eql_v3_internal.jsonb_blocked_delete_array,
  LEFTARG = public.eql_v3_json_search,
  RIGHTARG = text[]
);

--! @brief Blocker: #- (delete at path).
--! @param a public.eql_v3_json_search Left operand (encrypted payload).
--! @param b text[] Native RHS operand.
--! @return jsonb Never returns; always raises 'operator not supported'.
CREATE FUNCTION eql_v3_internal.jsonb_blocked_delete_path(a public.eql_v3_json_search, b text[])
RETURNS jsonb
IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RETURN eql_v3_internal.encrypted_domain_unsupported_jsonb('public.eql_v3_json_search', '#-');
END;
$$ LANGUAGE plpgsql;

CREATE OPERATOR #- (
  FUNCTION = eql_v3_internal.jsonb_blocked_delete_path,
  LEFTARG = public.eql_v3_json_search,
  RIGHTARG = text[]
);

--! @brief Blocker: || (concatenate, encrypted on the left).
--! @param a public.eql_v3_json_search Left operand (encrypted payload).
--! @param b jsonb Native RHS operand.
--! @return jsonb Never returns; always raises 'operator not supported'.
CREATE FUNCTION eql_v3_internal.jsonb_blocked_concat(a public.eql_v3_json_search, b jsonb)
RETURNS jsonb
IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RETURN eql_v3_internal.encrypted_domain_unsupported_jsonb('public.eql_v3_json_search', '||');
END;
$$ LANGUAGE plpgsql;

CREATE OPERATOR || (
  FUNCTION = eql_v3_internal.jsonb_blocked_concat,
  LEFTARG = public.eql_v3_json_search,
  RIGHTARG = jsonb
);

--! @brief Blocker: || (concatenate, encrypted on the right).
--! @param a jsonb Native LHS operand.
--! @param b public.eql_v3_json_search Right operand (encrypted payload).
--! @return jsonb Never returns; always raises 'operator not supported'.
CREATE FUNCTION eql_v3_internal.jsonb_blocked_concat_rhs(a jsonb, b public.eql_v3_json_search)
RETURNS jsonb
IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RETURN eql_v3_internal.encrypted_domain_unsupported_jsonb('public.eql_v3_json_search', '||');
END;
$$ LANGUAGE plpgsql;

CREATE OPERATOR || (
  FUNCTION = eql_v3_internal.jsonb_blocked_concat_rhs,
  LEFTARG = jsonb,
  RIGHTARG = public.eql_v3_json_search
);

------------------------------------------------------------------------------
-- Root-document comparison blockers.
------------------------------------------------------------------------------

--! @brief Blocker: root public.eql_v3_json_search document comparisons.
--! @param a public.eql_v3_json_search Left operand (encrypted payload).
--! @param b public.eql_v3_json_search Right operand (encrypted payload).
--! @return boolean Never returns; always raises 'operator not supported'.
CREATE FUNCTION eql_v3_internal.jsonb_blocked_compare_json_json(a public.eql_v3_json_search, b public.eql_v3_json_search)
RETURNS boolean
IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RETURN eql_v3_internal.encrypted_domain_unsupported_bool('public.eql_v3_json_search', 'comparison');
END;
$$ LANGUAGE plpgsql;

--! @brief Blocker: root public.eql_v3_json_search-to-jsonb comparisons.
--! @param a public.eql_v3_json_search Left operand (encrypted payload).
--! @param b jsonb Native RHS operand.
--! @return boolean Never returns; always raises 'operator not supported'.
CREATE FUNCTION eql_v3_internal.jsonb_blocked_compare_json_jsonb(a public.eql_v3_json_search, b jsonb)
RETURNS boolean
IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RETURN eql_v3_internal.encrypted_domain_unsupported_bool('public.eql_v3_json_search', 'comparison');
END;
$$ LANGUAGE plpgsql;

--! @brief Blocker: root jsonb-to-public.eql_v3_json_search comparisons.
--! @param a jsonb Native LHS operand.
--! @param b public.eql_v3_json_search Right operand (encrypted payload).
--! @return boolean Never returns; always raises 'operator not supported'.
CREATE FUNCTION eql_v3_internal.jsonb_blocked_compare_jsonb_json(a jsonb, b public.eql_v3_json_search)
RETURNS boolean
IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RETURN eql_v3_internal.encrypted_domain_unsupported_bool('public.eql_v3_json_search', 'comparison');
END;
$$ LANGUAGE plpgsql;

CREATE OPERATOR = (
  FUNCTION = eql_v3_internal.jsonb_blocked_compare_json_json,
  LEFTARG = public.eql_v3_json_search,
  RIGHTARG = public.eql_v3_json_search
);

CREATE OPERATOR = (
  FUNCTION = eql_v3_internal.jsonb_blocked_compare_json_jsonb,
  LEFTARG = public.eql_v3_json_search,
  RIGHTARG = jsonb
);

CREATE OPERATOR = (
  FUNCTION = eql_v3_internal.jsonb_blocked_compare_jsonb_json,
  LEFTARG = jsonb,
  RIGHTARG = public.eql_v3_json_search
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3_internal.jsonb_blocked_compare_json_json,
  LEFTARG = public.eql_v3_json_search,
  RIGHTARG = public.eql_v3_json_search
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3_internal.jsonb_blocked_compare_json_jsonb,
  LEFTARG = public.eql_v3_json_search,
  RIGHTARG = jsonb
);

CREATE OPERATOR <> (
  FUNCTION = eql_v3_internal.jsonb_blocked_compare_jsonb_json,
  LEFTARG = jsonb,
  RIGHTARG = public.eql_v3_json_search
);

CREATE OPERATOR < (
  FUNCTION = eql_v3_internal.jsonb_blocked_compare_json_json,
  LEFTARG = public.eql_v3_json_search,
  RIGHTARG = public.eql_v3_json_search
);

CREATE OPERATOR < (
  FUNCTION = eql_v3_internal.jsonb_blocked_compare_json_jsonb,
  LEFTARG = public.eql_v3_json_search,
  RIGHTARG = jsonb
);

CREATE OPERATOR < (
  FUNCTION = eql_v3_internal.jsonb_blocked_compare_jsonb_json,
  LEFTARG = jsonb,
  RIGHTARG = public.eql_v3_json_search
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3_internal.jsonb_blocked_compare_json_json,
  LEFTARG = public.eql_v3_json_search,
  RIGHTARG = public.eql_v3_json_search
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3_internal.jsonb_blocked_compare_json_jsonb,
  LEFTARG = public.eql_v3_json_search,
  RIGHTARG = jsonb
);

CREATE OPERATOR <= (
  FUNCTION = eql_v3_internal.jsonb_blocked_compare_jsonb_json,
  LEFTARG = jsonb,
  RIGHTARG = public.eql_v3_json_search
);

CREATE OPERATOR > (
  FUNCTION = eql_v3_internal.jsonb_blocked_compare_json_json,
  LEFTARG = public.eql_v3_json_search,
  RIGHTARG = public.eql_v3_json_search
);

CREATE OPERATOR > (
  FUNCTION = eql_v3_internal.jsonb_blocked_compare_json_jsonb,
  LEFTARG = public.eql_v3_json_search,
  RIGHTARG = jsonb
);

CREATE OPERATOR > (
  FUNCTION = eql_v3_internal.jsonb_blocked_compare_jsonb_json,
  LEFTARG = jsonb,
  RIGHTARG = public.eql_v3_json_search
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3_internal.jsonb_blocked_compare_json_json,
  LEFTARG = public.eql_v3_json_search,
  RIGHTARG = public.eql_v3_json_search
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3_internal.jsonb_blocked_compare_json_jsonb,
  LEFTARG = public.eql_v3_json_search,
  RIGHTARG = jsonb
);

CREATE OPERATOR >= (
  FUNCTION = eql_v3_internal.jsonb_blocked_compare_jsonb_json,
  LEFTARG = jsonb,
  RIGHTARG = public.eql_v3_json_search
);

------------------------------------------------------------------------------
-- Dropped single-entry containment blockers.
------------------------------------------------------------------------------

--! @brief Block document containment against an extracted path entry.
--! @param a public.eql_v3_json_search Encrypted document.
--! @param b public.eql_v3_json_entry Extracted path entry.
--! @return boolean Never returns; always raises 'operator not supported'.
--! @note An extracted path entry carries no value selector, so this signature
--!       cannot express exact equality. It is explicitly claimed to prevent
--!       PostgreSQL flattening both domains to native jsonb containment.
CREATE FUNCTION eql_v3_internal.jsonb_blocked_contains_entry(a public.eql_v3_json_search, b public.eql_v3_json_entry)
RETURNS boolean
IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RETURN eql_v3_internal.encrypted_domain_unsupported_bool('public.eql_v3_json_search', '@>');
END;
$$ LANGUAGE plpgsql;

CREATE OPERATOR @> (
  FUNCTION = eql_v3_internal.jsonb_blocked_contains_entry,
  LEFTARG = public.eql_v3_json_search,
  RIGHTARG = public.eql_v3_json_entry
);

--! @brief Block reverse containment from an extracted path entry.
--! @param a public.eql_v3_json_entry Extracted path entry.
--! @param b public.eql_v3_json_search Encrypted document.
--! @return boolean Never returns; always raises 'operator not supported'.
CREATE FUNCTION eql_v3_internal.jsonb_blocked_entry_contained(a public.eql_v3_json_entry, b public.eql_v3_json_search)
RETURNS boolean
IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RETURN eql_v3_internal.encrypted_domain_unsupported_bool('public.eql_v3_json_entry', '<@');
END;
$$ LANGUAGE plpgsql;

CREATE OPERATOR <@ (
  FUNCTION = eql_v3_internal.jsonb_blocked_entry_contained,
  LEFTARG = public.eql_v3_json_entry,
  RIGHTARG = public.eql_v3_json_search
);

------------------------------------------------------------------------------
-- Mixed jsonb containment blockers.
------------------------------------------------------------------------------

--! @brief Blocker: @> with encrypted root document and native jsonb.
--! @param a public.eql_v3_json_search Left operand (encrypted payload).
--! @param b jsonb Native RHS operand.
--! @return boolean Never returns; always raises 'operator not supported'.
CREATE FUNCTION eql_v3_internal.jsonb_blocked_contains_json_jsonb(a public.eql_v3_json_search, b jsonb)
RETURNS boolean
IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RETURN eql_v3_internal.encrypted_domain_unsupported_bool('public.eql_v3_json_search', '@>');
END;
$$ LANGUAGE plpgsql;

--! @brief Blocker: @> with native jsonb and encrypted root document.
--! @param a jsonb Native LHS operand.
--! @param b public.eql_v3_json_search Right operand (encrypted payload).
--! @return boolean Never returns; always raises 'operator not supported'.
CREATE FUNCTION eql_v3_internal.jsonb_blocked_contains_jsonb_json(a jsonb, b public.eql_v3_json_search)
RETURNS boolean
IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RETURN eql_v3_internal.encrypted_domain_unsupported_bool('public.eql_v3_json_search', '@>');
END;
$$ LANGUAGE plpgsql;

--! @brief Blocker: <@ with encrypted root document and native jsonb.
--! @param a public.eql_v3_json_search Left operand (encrypted payload).
--! @param b jsonb Native RHS operand.
--! @return boolean Never returns; always raises 'operator not supported'.
CREATE FUNCTION eql_v3_internal.jsonb_blocked_contained_json_jsonb(a public.eql_v3_json_search, b jsonb)
RETURNS boolean
IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RETURN eql_v3_internal.encrypted_domain_unsupported_bool('public.eql_v3_json_search', '<@');
END;
$$ LANGUAGE plpgsql;

--! @brief Blocker: <@ with native jsonb and encrypted root document.
--! @param a jsonb Native LHS operand.
--! @param b public.eql_v3_json_search Right operand (encrypted payload).
--! @return boolean Never returns; always raises 'operator not supported'.
CREATE FUNCTION eql_v3_internal.jsonb_blocked_contained_jsonb_json(a jsonb, b public.eql_v3_json_search)
RETURNS boolean
IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RETURN eql_v3_internal.encrypted_domain_unsupported_bool('public.eql_v3_json_search', '<@');
END;
$$ LANGUAGE plpgsql;

CREATE OPERATOR @> (
  FUNCTION = eql_v3_internal.jsonb_blocked_contains_json_jsonb,
  LEFTARG = public.eql_v3_json_search,
  RIGHTARG = jsonb
);

CREATE OPERATOR @> (
  FUNCTION = eql_v3_internal.jsonb_blocked_contains_jsonb_json,
  LEFTARG = jsonb,
  RIGHTARG = public.eql_v3_json_search
);

CREATE OPERATOR <@ (
  FUNCTION = eql_v3_internal.jsonb_blocked_contained_json_jsonb,
  LEFTARG = public.eql_v3_json_search,
  RIGHTARG = jsonb
);

CREATE OPERATOR <@ (
  FUNCTION = eql_v3_internal.jsonb_blocked_contained_jsonb_json,
  LEFTARG = jsonb,
  RIGHTARG = public.eql_v3_json_search
);
