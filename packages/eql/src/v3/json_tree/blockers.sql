-- ONLY EQL VERSION: 4
-- REQUIRE: src/v3/schema.sql
-- REQUIRE: src/v3/json_tree/types.sql
-- REQUIRE: src/v3/scalars/functions.sql
-- REQUIRE: src/v3/json_tree/functions.sql

--! @file v3/json_tree/blockers.sql
--! @brief Native-jsonb firewall for public.{{prefix}}_json_search.
--!
--! public.{{prefix}}_json_search SUPPORTS @> <@ -> ->> (see operators.sql), and
--! public.{{prefix}}_json_entry the ordered comparisons < <= > >= against an
--! ordering operand or another entry. Entry equality = <> is blocked: an
--! entry's ordering term is not an exact equality representation, and exact
--! equality at a path is containment on a value selector. An entry against
--! plain jsonb is blocked for every comparison, in both directions, so an
--! ordering operand that lost its `{{prefix}}.query_json_leaf` cast
--! raises instead of comparing ciphertext. Root-document comparisons are
--! blocked too. `ORDER BY col -> 'sel'` cannot be blocked without an operator
--! class, which needs a superuser: it sorts by jsonb's ordering of the entry,
--! so order by `{{prefix}}.ord_term(col -> 'sel')` instead. Every OTHER native jsonb operator reachable
--! via domain fallback against the base type jsonb is BLOCKED here, so an
--! encrypted column can never silently route to plaintext-jsonb semantics.
--!
--! Each blocker is LANGUAGE plpgsql (NEVER STRICT: a STRICT blocker would let
--! PostgreSQL skip the body and return NULL on a NULL argument, bypassing the
--! exception) and delegates to the shared {{prefix}}_internal.encrypted_domain_unsupported_*
--! helpers. Each blocker's RETURNS type matches the native operator it shadows
--! so a composed expression resolves and the body raises 'operator not
--! supported', rather than failing earlier on a boolean intermediate.
--!
--! The native jsonb FUNCTIONS that would run over the envelope are blocked
--! too, by overloads in `public` at the end of this file: see "Function-form
--! blockers" below.

--! @brief Blocker: ? (key/element exists).
--! @param a public.{{prefix}}_json_search Left operand (encrypted payload).
--! @param b text Native RHS operand.
--! @return boolean Never returns; always raises 'operator not supported'.
CREATE FUNCTION {{prefix}}_internal.json_tree_blocked_exists(a public.{{prefix}}_json_search, b text)
RETURNS boolean
IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RETURN {{prefix}}_internal.encrypted_domain_unsupported_bool('public.{{prefix}}_json_search', '?');
END;
$$ LANGUAGE plpgsql;

CREATE OPERATOR ? (
  FUNCTION = {{prefix}}_internal.json_tree_blocked_exists,
  LEFTARG = public.{{prefix}}_json_search,
  RIGHTARG = text
);

--! @brief Blocker: ?| (any key exists).
--! @param a public.{{prefix}}_json_search Left operand (encrypted payload).
--! @param b text[] Native RHS operand.
--! @return boolean Never returns; always raises 'operator not supported'.
CREATE FUNCTION {{prefix}}_internal.json_tree_blocked_exists_any(a public.{{prefix}}_json_search, b text[])
RETURNS boolean
IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RETURN {{prefix}}_internal.encrypted_domain_unsupported_bool('public.{{prefix}}_json_search', '?|');
END;
$$ LANGUAGE plpgsql;

CREATE OPERATOR ?| (
  FUNCTION = {{prefix}}_internal.json_tree_blocked_exists_any,
  LEFTARG = public.{{prefix}}_json_search,
  RIGHTARG = text[]
);

--! @brief Blocker: ?& (all keys exist).
--! @param a public.{{prefix}}_json_search Left operand (encrypted payload).
--! @param b text[] Native RHS operand.
--! @return boolean Never returns; always raises 'operator not supported'.
CREATE FUNCTION {{prefix}}_internal.json_tree_blocked_exists_all(a public.{{prefix}}_json_search, b text[])
RETURNS boolean
IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RETURN {{prefix}}_internal.encrypted_domain_unsupported_bool('public.{{prefix}}_json_search', '?&');
END;
$$ LANGUAGE plpgsql;

CREATE OPERATOR ?& (
  FUNCTION = {{prefix}}_internal.json_tree_blocked_exists_all,
  LEFTARG = public.{{prefix}}_json_search,
  RIGHTARG = text[]
);

--! @brief Blocker: @? (jsonpath exists).
--! @param a public.{{prefix}}_json_search Left operand (encrypted payload).
--! @param b jsonpath Native RHS operand.
--! @return boolean Never returns; always raises 'operator not supported'.
CREATE FUNCTION {{prefix}}_internal.json_tree_blocked_jsonpath_exists(a public.{{prefix}}_json_search, b jsonpath)
RETURNS boolean
IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RETURN {{prefix}}_internal.encrypted_domain_unsupported_bool('public.{{prefix}}_json_search', '@?');
END;
$$ LANGUAGE plpgsql;

CREATE OPERATOR @? (
  FUNCTION = {{prefix}}_internal.json_tree_blocked_jsonpath_exists,
  LEFTARG = public.{{prefix}}_json_search,
  RIGHTARG = jsonpath
);

--! @brief Blocker: @@ (jsonpath predicate).
--! @param a public.{{prefix}}_json_search Left operand (encrypted payload).
--! @param b jsonpath Native RHS operand.
--! @return boolean Never returns; always raises 'operator not supported'.
CREATE FUNCTION {{prefix}}_internal.json_tree_blocked_jsonpath_match(a public.{{prefix}}_json_search, b jsonpath)
RETURNS boolean
IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RETURN {{prefix}}_internal.encrypted_domain_unsupported_bool('public.{{prefix}}_json_search', '@@');
END;
$$ LANGUAGE plpgsql;

CREATE OPERATOR @@ (
  FUNCTION = {{prefix}}_internal.json_tree_blocked_jsonpath_match,
  LEFTARG = public.{{prefix}}_json_search,
  RIGHTARG = jsonpath
);

--! @brief Blocker: #> (path extract, native returns jsonb).
--! @param a public.{{prefix}}_json_search Left operand (encrypted payload).
--! @param b text[] Native RHS operand.
--! @return jsonb Never returns; always raises 'operator not supported'.
CREATE FUNCTION {{prefix}}_internal.json_tree_blocked_path_extract(a public.{{prefix}}_json_search, b text[])
RETURNS jsonb
IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RETURN {{prefix}}_internal.encrypted_domain_unsupported_jsonb('public.{{prefix}}_json_search', '#>');
END;
$$ LANGUAGE plpgsql;

CREATE OPERATOR #> (
  FUNCTION = {{prefix}}_internal.json_tree_blocked_path_extract,
  LEFTARG = public.{{prefix}}_json_search,
  RIGHTARG = text[]
);

--! @brief Blocker: #>> (path extract as text).
--! @param a public.{{prefix}}_json_search Left operand (encrypted payload).
--! @param b text[] Native RHS operand.
--! @return text Never returns; always raises 'operator not supported'.
CREATE FUNCTION {{prefix}}_internal.json_tree_blocked_path_extract_text(a public.{{prefix}}_json_search, b text[])
RETURNS text
IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RETURN {{prefix}}_internal.encrypted_domain_unsupported_text('public.{{prefix}}_json_search', '#>>');
END;
$$ LANGUAGE plpgsql;

CREATE OPERATOR #>> (
  FUNCTION = {{prefix}}_internal.json_tree_blocked_path_extract_text,
  LEFTARG = public.{{prefix}}_json_search,
  RIGHTARG = text[]
);

--! @brief Blocker: - (delete key, text RHS).
--! @param a public.{{prefix}}_json_search Left operand (encrypted payload).
--! @param b text Native RHS operand.
--! @return jsonb Never returns; always raises 'operator not supported'.
CREATE FUNCTION {{prefix}}_internal.json_tree_blocked_delete_text(a public.{{prefix}}_json_search, b text)
RETURNS jsonb
IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RETURN {{prefix}}_internal.encrypted_domain_unsupported_jsonb('public.{{prefix}}_json_search', '-');
END;
$$ LANGUAGE plpgsql;

CREATE OPERATOR - (
  FUNCTION = {{prefix}}_internal.json_tree_blocked_delete_text,
  LEFTARG = public.{{prefix}}_json_search,
  RIGHTARG = text
);

--! @brief Blocker: - (delete index, integer RHS).
--! @param a public.{{prefix}}_json_search Left operand (encrypted payload).
--! @param b integer Native RHS operand.
--! @return jsonb Never returns; always raises 'operator not supported'.
CREATE FUNCTION {{prefix}}_internal.json_tree_blocked_delete_int(a public.{{prefix}}_json_search, b integer)
RETURNS jsonb
IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RETURN {{prefix}}_internal.encrypted_domain_unsupported_jsonb('public.{{prefix}}_json_search', '-');
END;
$$ LANGUAGE plpgsql;

CREATE OPERATOR - (
  FUNCTION = {{prefix}}_internal.json_tree_blocked_delete_int,
  LEFTARG = public.{{prefix}}_json_search,
  RIGHTARG = integer
);

--! @brief Blocker: - (delete keys, text[] RHS).
--! @param a public.{{prefix}}_json_search Left operand (encrypted payload).
--! @param b text[] Native RHS operand.
--! @return jsonb Never returns; always raises 'operator not supported'.
CREATE FUNCTION {{prefix}}_internal.json_tree_blocked_delete_array(a public.{{prefix}}_json_search, b text[])
RETURNS jsonb
IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RETURN {{prefix}}_internal.encrypted_domain_unsupported_jsonb('public.{{prefix}}_json_search', '-');
END;
$$ LANGUAGE plpgsql;

CREATE OPERATOR - (
  FUNCTION = {{prefix}}_internal.json_tree_blocked_delete_array,
  LEFTARG = public.{{prefix}}_json_search,
  RIGHTARG = text[]
);

--! @brief Blocker: #- (delete at path).
--! @param a public.{{prefix}}_json_search Left operand (encrypted payload).
--! @param b text[] Native RHS operand.
--! @return jsonb Never returns; always raises 'operator not supported'.
CREATE FUNCTION {{prefix}}_internal.json_tree_blocked_delete_path(a public.{{prefix}}_json_search, b text[])
RETURNS jsonb
IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RETURN {{prefix}}_internal.encrypted_domain_unsupported_jsonb('public.{{prefix}}_json_search', '#-');
END;
$$ LANGUAGE plpgsql;

CREATE OPERATOR #- (
  FUNCTION = {{prefix}}_internal.json_tree_blocked_delete_path,
  LEFTARG = public.{{prefix}}_json_search,
  RIGHTARG = text[]
);

--! @brief Blocker: || (concatenate, encrypted on the left).
--! @param a public.{{prefix}}_json_search Left operand (encrypted payload).
--! @param b jsonb Native RHS operand.
--! @return jsonb Never returns; always raises 'operator not supported'.
CREATE FUNCTION {{prefix}}_internal.json_tree_blocked_concat(a public.{{prefix}}_json_search, b jsonb)
RETURNS jsonb
IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RETURN {{prefix}}_internal.encrypted_domain_unsupported_jsonb('public.{{prefix}}_json_search', '||');
END;
$$ LANGUAGE plpgsql;

CREATE OPERATOR || (
  FUNCTION = {{prefix}}_internal.json_tree_blocked_concat,
  LEFTARG = public.{{prefix}}_json_search,
  RIGHTARG = jsonb
);

--! @brief Blocker: || (concatenate, encrypted on the right).
--! @param a jsonb Native LHS operand.
--! @param b public.{{prefix}}_json_search Right operand (encrypted payload).
--! @return jsonb Never returns; always raises 'operator not supported'.
CREATE FUNCTION {{prefix}}_internal.json_tree_blocked_concat_rhs(a jsonb, b public.{{prefix}}_json_search)
RETURNS jsonb
IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RETURN {{prefix}}_internal.encrypted_domain_unsupported_jsonb('public.{{prefix}}_json_search', '||');
END;
$$ LANGUAGE plpgsql;

CREATE OPERATOR || (
  FUNCTION = {{prefix}}_internal.json_tree_blocked_concat_rhs,
  LEFTARG = jsonb,
  RIGHTARG = public.{{prefix}}_json_search
);

--! @brief Blocker: -> (element by position): positions are tokens, not selectors.
--! @param a public.{{prefix}}_json_search Left operand (encrypted payload).
--! @param b integer Native RHS operand.
--! @return jsonb Never returns; always raises 'operator not supported'.
CREATE FUNCTION {{prefix}}_internal.json_tree_blocked_select_int(a public.{{prefix}}_json_search, b integer)
RETURNS jsonb
IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RETURN {{prefix}}_internal.encrypted_domain_unsupported_jsonb('public.{{prefix}}_json_search', '->');
END;
$$ LANGUAGE plpgsql;

CREATE OPERATOR -> (
  FUNCTION = {{prefix}}_internal.json_tree_blocked_select_int,
  LEFTARG = public.{{prefix}}_json_search,
  RIGHTARG = integer
);

--! @brief Blocker: ->> (element by position, as text).
--! @param a public.{{prefix}}_json_search Left operand (encrypted payload).
--! @param b integer Native RHS operand.
--! @return text Never returns; always raises 'operator not supported'.
CREATE FUNCTION {{prefix}}_internal.json_tree_blocked_select_int_text(a public.{{prefix}}_json_search, b integer)
RETURNS text
IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RETURN {{prefix}}_internal.encrypted_domain_unsupported_text('public.{{prefix}}_json_search', '->>');
END;
$$ LANGUAGE plpgsql;

CREATE OPERATOR ->> (
  FUNCTION = {{prefix}}_internal.json_tree_blocked_select_int_text,
  LEFTARG = public.{{prefix}}_json_search,
  RIGHTARG = integer
);

--! @brief Blocker: root document = (document, document).
--! @param a public.{{prefix}}_json_search Left operand (encrypted payload).
--! @param b public.{{prefix}}_json_search Right operand (encrypted payload).
--! @return boolean Never returns; always raises 'operator not supported'.
CREATE FUNCTION {{prefix}}_internal.json_tree_blocked_compare_eq_doc_doc(a public.{{prefix}}_json_search, b public.{{prefix}}_json_search)
RETURNS boolean
IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RETURN {{prefix}}_internal.encrypted_domain_unsupported_bool('public.{{prefix}}_json_search', '=');
END;
$$ LANGUAGE plpgsql;

CREATE OPERATOR = (
  FUNCTION = {{prefix}}_internal.json_tree_blocked_compare_eq_doc_doc,
  LEFTARG = public.{{prefix}}_json_search,
  RIGHTARG = public.{{prefix}}_json_search
);

--! @brief Blocker: root document = (document, jsonb).
--! @param a public.{{prefix}}_json_search Left operand (encrypted payload).
--! @param b jsonb Native RHS operand.
--! @return boolean Never returns; always raises 'operator not supported'.
CREATE FUNCTION {{prefix}}_internal.json_tree_blocked_compare_eq_doc_jsonb(a public.{{prefix}}_json_search, b jsonb)
RETURNS boolean
IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RETURN {{prefix}}_internal.encrypted_domain_unsupported_bool('public.{{prefix}}_json_search', '=');
END;
$$ LANGUAGE plpgsql;

CREATE OPERATOR = (
  FUNCTION = {{prefix}}_internal.json_tree_blocked_compare_eq_doc_jsonb,
  LEFTARG = public.{{prefix}}_json_search,
  RIGHTARG = jsonb
);

--! @brief Blocker: root document = (jsonb, document).
--! @param a jsonb Native LHS operand.
--! @param b public.{{prefix}}_json_search Right operand (encrypted payload).
--! @return boolean Never returns; always raises 'operator not supported'.
CREATE FUNCTION {{prefix}}_internal.json_tree_blocked_compare_eq_jsonb_doc(a jsonb, b public.{{prefix}}_json_search)
RETURNS boolean
IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RETURN {{prefix}}_internal.encrypted_domain_unsupported_bool('public.{{prefix}}_json_search', '=');
END;
$$ LANGUAGE plpgsql;

CREATE OPERATOR = (
  FUNCTION = {{prefix}}_internal.json_tree_blocked_compare_eq_jsonb_doc,
  LEFTARG = jsonb,
  RIGHTARG = public.{{prefix}}_json_search
);

--! @brief Blocker: root document <> (document, document).
--! @param a public.{{prefix}}_json_search Left operand (encrypted payload).
--! @param b public.{{prefix}}_json_search Right operand (encrypted payload).
--! @return boolean Never returns; always raises 'operator not supported'.
CREATE FUNCTION {{prefix}}_internal.json_tree_blocked_compare_neq_doc_doc(a public.{{prefix}}_json_search, b public.{{prefix}}_json_search)
RETURNS boolean
IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RETURN {{prefix}}_internal.encrypted_domain_unsupported_bool('public.{{prefix}}_json_search', '<>');
END;
$$ LANGUAGE plpgsql;

CREATE OPERATOR <> (
  FUNCTION = {{prefix}}_internal.json_tree_blocked_compare_neq_doc_doc,
  LEFTARG = public.{{prefix}}_json_search,
  RIGHTARG = public.{{prefix}}_json_search
);

--! @brief Blocker: root document <> (document, jsonb).
--! @param a public.{{prefix}}_json_search Left operand (encrypted payload).
--! @param b jsonb Native RHS operand.
--! @return boolean Never returns; always raises 'operator not supported'.
CREATE FUNCTION {{prefix}}_internal.json_tree_blocked_compare_neq_doc_jsonb(a public.{{prefix}}_json_search, b jsonb)
RETURNS boolean
IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RETURN {{prefix}}_internal.encrypted_domain_unsupported_bool('public.{{prefix}}_json_search', '<>');
END;
$$ LANGUAGE plpgsql;

CREATE OPERATOR <> (
  FUNCTION = {{prefix}}_internal.json_tree_blocked_compare_neq_doc_jsonb,
  LEFTARG = public.{{prefix}}_json_search,
  RIGHTARG = jsonb
);

--! @brief Blocker: root document <> (jsonb, document).
--! @param a jsonb Native LHS operand.
--! @param b public.{{prefix}}_json_search Right operand (encrypted payload).
--! @return boolean Never returns; always raises 'operator not supported'.
CREATE FUNCTION {{prefix}}_internal.json_tree_blocked_compare_neq_jsonb_doc(a jsonb, b public.{{prefix}}_json_search)
RETURNS boolean
IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RETURN {{prefix}}_internal.encrypted_domain_unsupported_bool('public.{{prefix}}_json_search', '<>');
END;
$$ LANGUAGE plpgsql;

CREATE OPERATOR <> (
  FUNCTION = {{prefix}}_internal.json_tree_blocked_compare_neq_jsonb_doc,
  LEFTARG = jsonb,
  RIGHTARG = public.{{prefix}}_json_search
);

--! @brief Blocker: root document < (document, document).
--! @param a public.{{prefix}}_json_search Left operand (encrypted payload).
--! @param b public.{{prefix}}_json_search Right operand (encrypted payload).
--! @return boolean Never returns; always raises 'operator not supported'.
CREATE FUNCTION {{prefix}}_internal.json_tree_blocked_compare_lt_doc_doc(a public.{{prefix}}_json_search, b public.{{prefix}}_json_search)
RETURNS boolean
IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RETURN {{prefix}}_internal.encrypted_domain_unsupported_bool('public.{{prefix}}_json_search', '<');
END;
$$ LANGUAGE plpgsql;

CREATE OPERATOR < (
  FUNCTION = {{prefix}}_internal.json_tree_blocked_compare_lt_doc_doc,
  LEFTARG = public.{{prefix}}_json_search,
  RIGHTARG = public.{{prefix}}_json_search
);

--! @brief Blocker: root document < (document, jsonb).
--! @param a public.{{prefix}}_json_search Left operand (encrypted payload).
--! @param b jsonb Native RHS operand.
--! @return boolean Never returns; always raises 'operator not supported'.
CREATE FUNCTION {{prefix}}_internal.json_tree_blocked_compare_lt_doc_jsonb(a public.{{prefix}}_json_search, b jsonb)
RETURNS boolean
IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RETURN {{prefix}}_internal.encrypted_domain_unsupported_bool('public.{{prefix}}_json_search', '<');
END;
$$ LANGUAGE plpgsql;

CREATE OPERATOR < (
  FUNCTION = {{prefix}}_internal.json_tree_blocked_compare_lt_doc_jsonb,
  LEFTARG = public.{{prefix}}_json_search,
  RIGHTARG = jsonb
);

--! @brief Blocker: root document < (jsonb, document).
--! @param a jsonb Native LHS operand.
--! @param b public.{{prefix}}_json_search Right operand (encrypted payload).
--! @return boolean Never returns; always raises 'operator not supported'.
CREATE FUNCTION {{prefix}}_internal.json_tree_blocked_compare_lt_jsonb_doc(a jsonb, b public.{{prefix}}_json_search)
RETURNS boolean
IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RETURN {{prefix}}_internal.encrypted_domain_unsupported_bool('public.{{prefix}}_json_search', '<');
END;
$$ LANGUAGE plpgsql;

CREATE OPERATOR < (
  FUNCTION = {{prefix}}_internal.json_tree_blocked_compare_lt_jsonb_doc,
  LEFTARG = jsonb,
  RIGHTARG = public.{{prefix}}_json_search
);

--! @brief Blocker: root document <= (document, document).
--! @param a public.{{prefix}}_json_search Left operand (encrypted payload).
--! @param b public.{{prefix}}_json_search Right operand (encrypted payload).
--! @return boolean Never returns; always raises 'operator not supported'.
CREATE FUNCTION {{prefix}}_internal.json_tree_blocked_compare_lte_doc_doc(a public.{{prefix}}_json_search, b public.{{prefix}}_json_search)
RETURNS boolean
IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RETURN {{prefix}}_internal.encrypted_domain_unsupported_bool('public.{{prefix}}_json_search', '<=');
END;
$$ LANGUAGE plpgsql;

CREATE OPERATOR <= (
  FUNCTION = {{prefix}}_internal.json_tree_blocked_compare_lte_doc_doc,
  LEFTARG = public.{{prefix}}_json_search,
  RIGHTARG = public.{{prefix}}_json_search
);

--! @brief Blocker: root document <= (document, jsonb).
--! @param a public.{{prefix}}_json_search Left operand (encrypted payload).
--! @param b jsonb Native RHS operand.
--! @return boolean Never returns; always raises 'operator not supported'.
CREATE FUNCTION {{prefix}}_internal.json_tree_blocked_compare_lte_doc_jsonb(a public.{{prefix}}_json_search, b jsonb)
RETURNS boolean
IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RETURN {{prefix}}_internal.encrypted_domain_unsupported_bool('public.{{prefix}}_json_search', '<=');
END;
$$ LANGUAGE plpgsql;

CREATE OPERATOR <= (
  FUNCTION = {{prefix}}_internal.json_tree_blocked_compare_lte_doc_jsonb,
  LEFTARG = public.{{prefix}}_json_search,
  RIGHTARG = jsonb
);

--! @brief Blocker: root document <= (jsonb, document).
--! @param a jsonb Native LHS operand.
--! @param b public.{{prefix}}_json_search Right operand (encrypted payload).
--! @return boolean Never returns; always raises 'operator not supported'.
CREATE FUNCTION {{prefix}}_internal.json_tree_blocked_compare_lte_jsonb_doc(a jsonb, b public.{{prefix}}_json_search)
RETURNS boolean
IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RETURN {{prefix}}_internal.encrypted_domain_unsupported_bool('public.{{prefix}}_json_search', '<=');
END;
$$ LANGUAGE plpgsql;

CREATE OPERATOR <= (
  FUNCTION = {{prefix}}_internal.json_tree_blocked_compare_lte_jsonb_doc,
  LEFTARG = jsonb,
  RIGHTARG = public.{{prefix}}_json_search
);

--! @brief Blocker: root document > (document, document).
--! @param a public.{{prefix}}_json_search Left operand (encrypted payload).
--! @param b public.{{prefix}}_json_search Right operand (encrypted payload).
--! @return boolean Never returns; always raises 'operator not supported'.
CREATE FUNCTION {{prefix}}_internal.json_tree_blocked_compare_gt_doc_doc(a public.{{prefix}}_json_search, b public.{{prefix}}_json_search)
RETURNS boolean
IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RETURN {{prefix}}_internal.encrypted_domain_unsupported_bool('public.{{prefix}}_json_search', '>');
END;
$$ LANGUAGE plpgsql;

CREATE OPERATOR > (
  FUNCTION = {{prefix}}_internal.json_tree_blocked_compare_gt_doc_doc,
  LEFTARG = public.{{prefix}}_json_search,
  RIGHTARG = public.{{prefix}}_json_search
);

--! @brief Blocker: root document > (document, jsonb).
--! @param a public.{{prefix}}_json_search Left operand (encrypted payload).
--! @param b jsonb Native RHS operand.
--! @return boolean Never returns; always raises 'operator not supported'.
CREATE FUNCTION {{prefix}}_internal.json_tree_blocked_compare_gt_doc_jsonb(a public.{{prefix}}_json_search, b jsonb)
RETURNS boolean
IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RETURN {{prefix}}_internal.encrypted_domain_unsupported_bool('public.{{prefix}}_json_search', '>');
END;
$$ LANGUAGE plpgsql;

CREATE OPERATOR > (
  FUNCTION = {{prefix}}_internal.json_tree_blocked_compare_gt_doc_jsonb,
  LEFTARG = public.{{prefix}}_json_search,
  RIGHTARG = jsonb
);

--! @brief Blocker: root document > (jsonb, document).
--! @param a jsonb Native LHS operand.
--! @param b public.{{prefix}}_json_search Right operand (encrypted payload).
--! @return boolean Never returns; always raises 'operator not supported'.
CREATE FUNCTION {{prefix}}_internal.json_tree_blocked_compare_gt_jsonb_doc(a jsonb, b public.{{prefix}}_json_search)
RETURNS boolean
IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RETURN {{prefix}}_internal.encrypted_domain_unsupported_bool('public.{{prefix}}_json_search', '>');
END;
$$ LANGUAGE plpgsql;

CREATE OPERATOR > (
  FUNCTION = {{prefix}}_internal.json_tree_blocked_compare_gt_jsonb_doc,
  LEFTARG = jsonb,
  RIGHTARG = public.{{prefix}}_json_search
);

--! @brief Blocker: root document >= (document, document).
--! @param a public.{{prefix}}_json_search Left operand (encrypted payload).
--! @param b public.{{prefix}}_json_search Right operand (encrypted payload).
--! @return boolean Never returns; always raises 'operator not supported'.
CREATE FUNCTION {{prefix}}_internal.json_tree_blocked_compare_gte_doc_doc(a public.{{prefix}}_json_search, b public.{{prefix}}_json_search)
RETURNS boolean
IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RETURN {{prefix}}_internal.encrypted_domain_unsupported_bool('public.{{prefix}}_json_search', '>=');
END;
$$ LANGUAGE plpgsql;

CREATE OPERATOR >= (
  FUNCTION = {{prefix}}_internal.json_tree_blocked_compare_gte_doc_doc,
  LEFTARG = public.{{prefix}}_json_search,
  RIGHTARG = public.{{prefix}}_json_search
);

--! @brief Blocker: root document >= (document, jsonb).
--! @param a public.{{prefix}}_json_search Left operand (encrypted payload).
--! @param b jsonb Native RHS operand.
--! @return boolean Never returns; always raises 'operator not supported'.
CREATE FUNCTION {{prefix}}_internal.json_tree_blocked_compare_gte_doc_jsonb(a public.{{prefix}}_json_search, b jsonb)
RETURNS boolean
IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RETURN {{prefix}}_internal.encrypted_domain_unsupported_bool('public.{{prefix}}_json_search', '>=');
END;
$$ LANGUAGE plpgsql;

CREATE OPERATOR >= (
  FUNCTION = {{prefix}}_internal.json_tree_blocked_compare_gte_doc_jsonb,
  LEFTARG = public.{{prefix}}_json_search,
  RIGHTARG = jsonb
);

--! @brief Blocker: root document >= (jsonb, document).
--! @param a jsonb Native LHS operand.
--! @param b public.{{prefix}}_json_search Right operand (encrypted payload).
--! @return boolean Never returns; always raises 'operator not supported'.
CREATE FUNCTION {{prefix}}_internal.json_tree_blocked_compare_gte_jsonb_doc(a jsonb, b public.{{prefix}}_json_search)
RETURNS boolean
IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RETURN {{prefix}}_internal.encrypted_domain_unsupported_bool('public.{{prefix}}_json_search', '>=');
END;
$$ LANGUAGE plpgsql;

CREATE OPERATOR >= (
  FUNCTION = {{prefix}}_internal.json_tree_blocked_compare_gte_jsonb_doc,
  LEFTARG = jsonb,
  RIGHTARG = public.{{prefix}}_json_search
);

--! @brief Blocker: = between two extracted entries (no exact equality term).
--! @param a public.{{prefix}}_json_entry Left operand (entry).
--! @param b public.{{prefix}}_json_entry Right operand (entry).
--! @return boolean Never returns; always raises 'operator not supported'.
CREATE FUNCTION {{prefix}}_internal.json_tree_blocked_entry_eq(a public.{{prefix}}_json_entry, b public.{{prefix}}_json_entry)
RETURNS boolean
IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RETURN {{prefix}}_internal.encrypted_domain_unsupported_bool('public.{{prefix}}_json_entry', '=');
END;
$$ LANGUAGE plpgsql;

CREATE OPERATOR = (
  FUNCTION = {{prefix}}_internal.json_tree_blocked_entry_eq,
  LEFTARG = public.{{prefix}}_json_entry,
  RIGHTARG = public.{{prefix}}_json_entry
);

--! @brief Blocker: <> between two extracted entries.
--! @param a public.{{prefix}}_json_entry Left operand (entry).
--! @param b public.{{prefix}}_json_entry Right operand (entry).
--! @return boolean Never returns; always raises 'operator not supported'.
CREATE FUNCTION {{prefix}}_internal.json_tree_blocked_entry_neq(a public.{{prefix}}_json_entry, b public.{{prefix}}_json_entry)
RETURNS boolean
IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RETURN {{prefix}}_internal.encrypted_domain_unsupported_bool('public.{{prefix}}_json_entry', '<>');
END;
$$ LANGUAGE plpgsql;

CREATE OPERATOR <> (
  FUNCTION = {{prefix}}_internal.json_tree_blocked_entry_neq,
  LEFTARG = public.{{prefix}}_json_entry,
  RIGHTARG = public.{{prefix}}_json_entry
);

--! @brief Blocker: < (entry, jsonb): an ordering operand is typed.
--!
--! An entry compares with `{{prefix}}.query_json_leaf` or another
--! entry. Against plain jsonb, the native operator would compare the entry's
--! ciphertext object, which is what a query that forgets the operand's cast
--! would silently get.
--! @param a public.{{prefix}}_json_entry Left operand (entry).
--! @param b jsonb Native RHS operand.
--! @return boolean Never returns; always raises 'operator not supported'.
CREATE FUNCTION {{prefix}}_internal.json_tree_blocked_entry_lt_jsonb(a public.{{prefix}}_json_entry, b jsonb)
RETURNS boolean
IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RETURN {{prefix}}_internal.encrypted_domain_unsupported_bool('public.{{prefix}}_json_entry', '<');
END;
$$ LANGUAGE plpgsql;

CREATE OPERATOR < (
  FUNCTION = {{prefix}}_internal.json_tree_blocked_entry_lt_jsonb,
  LEFTARG = public.{{prefix}}_json_entry,
  RIGHTARG = jsonb
);

--! @brief Blocker: < (jsonb, entry).
--! @param a jsonb Native LHS operand.
--! @param b public.{{prefix}}_json_entry Right operand (entry).
--! @return boolean Never returns; always raises 'operator not supported'.
CREATE FUNCTION {{prefix}}_internal.json_tree_blocked_jsonb_lt_entry(a jsonb, b public.{{prefix}}_json_entry)
RETURNS boolean
IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RETURN {{prefix}}_internal.encrypted_domain_unsupported_bool('public.{{prefix}}_json_entry', '<');
END;
$$ LANGUAGE plpgsql;

CREATE OPERATOR < (
  FUNCTION = {{prefix}}_internal.json_tree_blocked_jsonb_lt_entry,
  LEFTARG = jsonb,
  RIGHTARG = public.{{prefix}}_json_entry
);

--! @brief Blocker: <= (entry, jsonb): an ordering operand is typed.
--!
--! An entry compares with `{{prefix}}.query_json_leaf` or another
--! entry. Against plain jsonb, the native operator would compare the entry's
--! ciphertext object, which is what a query that forgets the operand's cast
--! would silently get.
--! @param a public.{{prefix}}_json_entry Left operand (entry).
--! @param b jsonb Native RHS operand.
--! @return boolean Never returns; always raises 'operator not supported'.
CREATE FUNCTION {{prefix}}_internal.json_tree_blocked_entry_lte_jsonb(a public.{{prefix}}_json_entry, b jsonb)
RETURNS boolean
IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RETURN {{prefix}}_internal.encrypted_domain_unsupported_bool('public.{{prefix}}_json_entry', '<=');
END;
$$ LANGUAGE plpgsql;

CREATE OPERATOR <= (
  FUNCTION = {{prefix}}_internal.json_tree_blocked_entry_lte_jsonb,
  LEFTARG = public.{{prefix}}_json_entry,
  RIGHTARG = jsonb
);

--! @brief Blocker: <= (jsonb, entry).
--! @param a jsonb Native LHS operand.
--! @param b public.{{prefix}}_json_entry Right operand (entry).
--! @return boolean Never returns; always raises 'operator not supported'.
CREATE FUNCTION {{prefix}}_internal.json_tree_blocked_jsonb_lte_entry(a jsonb, b public.{{prefix}}_json_entry)
RETURNS boolean
IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RETURN {{prefix}}_internal.encrypted_domain_unsupported_bool('public.{{prefix}}_json_entry', '<=');
END;
$$ LANGUAGE plpgsql;

CREATE OPERATOR <= (
  FUNCTION = {{prefix}}_internal.json_tree_blocked_jsonb_lte_entry,
  LEFTARG = jsonb,
  RIGHTARG = public.{{prefix}}_json_entry
);

--! @brief Blocker: > (entry, jsonb): an ordering operand is typed.
--!
--! An entry compares with `{{prefix}}.query_json_leaf` or another
--! entry. Against plain jsonb, the native operator would compare the entry's
--! ciphertext object, which is what a query that forgets the operand's cast
--! would silently get.
--! @param a public.{{prefix}}_json_entry Left operand (entry).
--! @param b jsonb Native RHS operand.
--! @return boolean Never returns; always raises 'operator not supported'.
CREATE FUNCTION {{prefix}}_internal.json_tree_blocked_entry_gt_jsonb(a public.{{prefix}}_json_entry, b jsonb)
RETURNS boolean
IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RETURN {{prefix}}_internal.encrypted_domain_unsupported_bool('public.{{prefix}}_json_entry', '>');
END;
$$ LANGUAGE plpgsql;

CREATE OPERATOR > (
  FUNCTION = {{prefix}}_internal.json_tree_blocked_entry_gt_jsonb,
  LEFTARG = public.{{prefix}}_json_entry,
  RIGHTARG = jsonb
);

--! @brief Blocker: > (jsonb, entry).
--! @param a jsonb Native LHS operand.
--! @param b public.{{prefix}}_json_entry Right operand (entry).
--! @return boolean Never returns; always raises 'operator not supported'.
CREATE FUNCTION {{prefix}}_internal.json_tree_blocked_jsonb_gt_entry(a jsonb, b public.{{prefix}}_json_entry)
RETURNS boolean
IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RETURN {{prefix}}_internal.encrypted_domain_unsupported_bool('public.{{prefix}}_json_entry', '>');
END;
$$ LANGUAGE plpgsql;

CREATE OPERATOR > (
  FUNCTION = {{prefix}}_internal.json_tree_blocked_jsonb_gt_entry,
  LEFTARG = jsonb,
  RIGHTARG = public.{{prefix}}_json_entry
);

--! @brief Blocker: >= (entry, jsonb): an ordering operand is typed.
--!
--! An entry compares with `{{prefix}}.query_json_leaf` or another
--! entry. Against plain jsonb, the native operator would compare the entry's
--! ciphertext object, which is what a query that forgets the operand's cast
--! would silently get.
--! @param a public.{{prefix}}_json_entry Left operand (entry).
--! @param b jsonb Native RHS operand.
--! @return boolean Never returns; always raises 'operator not supported'.
CREATE FUNCTION {{prefix}}_internal.json_tree_blocked_entry_gte_jsonb(a public.{{prefix}}_json_entry, b jsonb)
RETURNS boolean
IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RETURN {{prefix}}_internal.encrypted_domain_unsupported_bool('public.{{prefix}}_json_entry', '>=');
END;
$$ LANGUAGE plpgsql;

CREATE OPERATOR >= (
  FUNCTION = {{prefix}}_internal.json_tree_blocked_entry_gte_jsonb,
  LEFTARG = public.{{prefix}}_json_entry,
  RIGHTARG = jsonb
);

--! @brief Blocker: >= (jsonb, entry).
--! @param a jsonb Native LHS operand.
--! @param b public.{{prefix}}_json_entry Right operand (entry).
--! @return boolean Never returns; always raises 'operator not supported'.
CREATE FUNCTION {{prefix}}_internal.json_tree_blocked_jsonb_gte_entry(a jsonb, b public.{{prefix}}_json_entry)
RETURNS boolean
IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RETURN {{prefix}}_internal.encrypted_domain_unsupported_bool('public.{{prefix}}_json_entry', '>=');
END;
$$ LANGUAGE plpgsql;

CREATE OPERATOR >= (
  FUNCTION = {{prefix}}_internal.json_tree_blocked_jsonb_gte_entry,
  LEFTARG = jsonb,
  RIGHTARG = public.{{prefix}}_json_entry
);

--! @brief Blocker: = (entry, jsonb): an ordering operand is typed.
--!
--! An entry compares with `{{prefix}}.query_json_leaf` or another
--! entry. Against plain jsonb, the native operator would compare the entry's
--! ciphertext object, which is what a query that forgets the operand's cast
--! would silently get.
--! @param a public.{{prefix}}_json_entry Left operand (entry).
--! @param b jsonb Native RHS operand.
--! @return boolean Never returns; always raises 'operator not supported'.
CREATE FUNCTION {{prefix}}_internal.json_tree_blocked_entry_eq_jsonb(a public.{{prefix}}_json_entry, b jsonb)
RETURNS boolean
IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RETURN {{prefix}}_internal.encrypted_domain_unsupported_bool('public.{{prefix}}_json_entry', '=');
END;
$$ LANGUAGE plpgsql;

CREATE OPERATOR = (
  FUNCTION = {{prefix}}_internal.json_tree_blocked_entry_eq_jsonb,
  LEFTARG = public.{{prefix}}_json_entry,
  RIGHTARG = jsonb
);

--! @brief Blocker: = (jsonb, entry).
--! @param a jsonb Native LHS operand.
--! @param b public.{{prefix}}_json_entry Right operand (entry).
--! @return boolean Never returns; always raises 'operator not supported'.
CREATE FUNCTION {{prefix}}_internal.json_tree_blocked_jsonb_eq_entry(a jsonb, b public.{{prefix}}_json_entry)
RETURNS boolean
IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RETURN {{prefix}}_internal.encrypted_domain_unsupported_bool('public.{{prefix}}_json_entry', '=');
END;
$$ LANGUAGE plpgsql;

CREATE OPERATOR = (
  FUNCTION = {{prefix}}_internal.json_tree_blocked_jsonb_eq_entry,
  LEFTARG = jsonb,
  RIGHTARG = public.{{prefix}}_json_entry
);

--! @brief Blocker: <> (entry, jsonb): an ordering operand is typed.
--!
--! An entry compares with `{{prefix}}.query_json_leaf` or another
--! entry. Against plain jsonb, the native operator would compare the entry's
--! ciphertext object, which is what a query that forgets the operand's cast
--! would silently get.
--! @param a public.{{prefix}}_json_entry Left operand (entry).
--! @param b jsonb Native RHS operand.
--! @return boolean Never returns; always raises 'operator not supported'.
CREATE FUNCTION {{prefix}}_internal.json_tree_blocked_entry_neq_jsonb(a public.{{prefix}}_json_entry, b jsonb)
RETURNS boolean
IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RETURN {{prefix}}_internal.encrypted_domain_unsupported_bool('public.{{prefix}}_json_entry', '<>');
END;
$$ LANGUAGE plpgsql;

CREATE OPERATOR <> (
  FUNCTION = {{prefix}}_internal.json_tree_blocked_entry_neq_jsonb,
  LEFTARG = public.{{prefix}}_json_entry,
  RIGHTARG = jsonb
);

--! @brief Blocker: <> (jsonb, entry).
--! @param a jsonb Native LHS operand.
--! @param b public.{{prefix}}_json_entry Right operand (entry).
--! @return boolean Never returns; always raises 'operator not supported'.
CREATE FUNCTION {{prefix}}_internal.json_tree_blocked_jsonb_neq_entry(a jsonb, b public.{{prefix}}_json_entry)
RETURNS boolean
IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RETURN {{prefix}}_internal.encrypted_domain_unsupported_bool('public.{{prefix}}_json_entry', '<>');
END;
$$ LANGUAGE plpgsql;

CREATE OPERATOR <> (
  FUNCTION = {{prefix}}_internal.json_tree_blocked_jsonb_neq_entry,
  LEFTARG = jsonb,
  RIGHTARG = public.{{prefix}}_json_entry
);

--! @brief Blocker: @> (document, entry): an entry is not a needle.
--! @param a public.{{prefix}}_json_search Left operand (encrypted payload).
--! @param b public.{{prefix}}_json_entry Right operand (entry).
--! @return boolean Never returns; always raises 'operator not supported'.
CREATE FUNCTION {{prefix}}_internal.json_tree_blocked_contains_entry(a public.{{prefix}}_json_search, b public.{{prefix}}_json_entry)
RETURNS boolean
IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RETURN {{prefix}}_internal.encrypted_domain_unsupported_bool('public.{{prefix}}_json_search', '@>');
END;
$$ LANGUAGE plpgsql;

CREATE OPERATOR @> (
  FUNCTION = {{prefix}}_internal.json_tree_blocked_contains_entry,
  LEFTARG = public.{{prefix}}_json_search,
  RIGHTARG = public.{{prefix}}_json_entry
);

--! @brief Blocker: <@ (entry, document).
--! @param a public.{{prefix}}_json_entry Left operand (entry).
--! @param b public.{{prefix}}_json_search Right operand (encrypted payload).
--! @return boolean Never returns; always raises 'operator not supported'.
CREATE FUNCTION {{prefix}}_internal.json_tree_blocked_contained_by_entry(a public.{{prefix}}_json_entry, b public.{{prefix}}_json_search)
RETURNS boolean
IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RETURN {{prefix}}_internal.encrypted_domain_unsupported_bool('public.{{prefix}}_json_search', '<@');
END;
$$ LANGUAGE plpgsql;

CREATE OPERATOR <@ (
  FUNCTION = {{prefix}}_internal.json_tree_blocked_contained_by_entry,
  LEFTARG = public.{{prefix}}_json_entry,
  RIGHTARG = public.{{prefix}}_json_search
);

--! @brief Blocker: @> (document, jsonb): a needle must be typed.
--! @param a public.{{prefix}}_json_search Left operand (encrypted payload).
--! @param b jsonb Native RHS operand.
--! @return boolean Never returns; always raises 'operator not supported'.
CREATE FUNCTION {{prefix}}_internal.json_tree_blocked_contains_jsonb(a public.{{prefix}}_json_search, b jsonb)
RETURNS boolean
IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RETURN {{prefix}}_internal.encrypted_domain_unsupported_bool('public.{{prefix}}_json_search', '@>');
END;
$$ LANGUAGE plpgsql;

CREATE OPERATOR @> (
  FUNCTION = {{prefix}}_internal.json_tree_blocked_contains_jsonb,
  LEFTARG = public.{{prefix}}_json_search,
  RIGHTARG = jsonb
);

--! @brief Blocker: @> (jsonb, document).
--! @param a jsonb Native LHS operand.
--! @param b public.{{prefix}}_json_search Right operand (encrypted payload).
--! @return boolean Never returns; always raises 'operator not supported'.
CREATE FUNCTION {{prefix}}_internal.json_tree_blocked_contains_jsonb_lhs(a jsonb, b public.{{prefix}}_json_search)
RETURNS boolean
IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RETURN {{prefix}}_internal.encrypted_domain_unsupported_bool('public.{{prefix}}_json_search', '@>');
END;
$$ LANGUAGE plpgsql;

CREATE OPERATOR @> (
  FUNCTION = {{prefix}}_internal.json_tree_blocked_contains_jsonb_lhs,
  LEFTARG = jsonb,
  RIGHTARG = public.{{prefix}}_json_search
);

--! @brief Blocker: <@ (document, jsonb).
--! @param a public.{{prefix}}_json_search Left operand (encrypted payload).
--! @param b jsonb Native RHS operand.
--! @return boolean Never returns; always raises 'operator not supported'.
CREATE FUNCTION {{prefix}}_internal.json_tree_blocked_contained_by_jsonb(a public.{{prefix}}_json_search, b jsonb)
RETURNS boolean
IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RETURN {{prefix}}_internal.encrypted_domain_unsupported_bool('public.{{prefix}}_json_search', '<@');
END;
$$ LANGUAGE plpgsql;

CREATE OPERATOR <@ (
  FUNCTION = {{prefix}}_internal.json_tree_blocked_contained_by_jsonb,
  LEFTARG = public.{{prefix}}_json_search,
  RIGHTARG = jsonb
);

--! @brief Blocker: <@ (jsonb, document).
--! @param a jsonb Native LHS operand.
--! @param b public.{{prefix}}_json_search Right operand (encrypted payload).
--! @return boolean Never returns; always raises 'operator not supported'.
CREATE FUNCTION {{prefix}}_internal.json_tree_blocked_contained_by_jsonb_lhs(a jsonb, b public.{{prefix}}_json_search)
RETURNS boolean
IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RETURN {{prefix}}_internal.encrypted_domain_unsupported_bool('public.{{prefix}}_json_search', '<@');
END;
$$ LANGUAGE plpgsql;

CREATE OPERATOR <@ (
  FUNCTION = {{prefix}}_internal.json_tree_blocked_contained_by_jsonb_lhs,
  LEFTARG = jsonb,
  RIGHTARG = public.{{prefix}}_json_search
);

------------------------------------------------------------------------------
-- Function-form blockers
------------------------------------------------------------------------------

--! Function-form blockers: native jsonb functions on the document and entry domains.
--!
--! The operators above leave the FUNCTION forms of the same operations open:
--! `jsonb_path_match(col, $1::jsonpath)` on a domain over jsonb resolves to
--! the native `pg_catalog` function, which runs over the stored envelope
--! (`{v, i, h, sv, q}`), finds none of the user's keys and returns false for
--! every row, with no error. Each overload below takes the domain as its
--! first argument and the native signature's other arguments (names and
--! defaults included, so a short or a named call resolves here too), and
--! raises `feature_not_supported` naming the function and the EQL operation
--! to use instead.
--!
--! They live in `public`, beside the domains: callers name these functions
--! unqualified, so an overload is a candidate only in a schema on the
--! caller's search path, and `public` is the one EQL already puts the
--! domains in. PostgreSQL looks
--! for an exact match on the argument types before it treats a domain as its
--! base type, which is what lets the overload win over `pg_catalog`; that is
--! the rule the operator blockers rely on too. It is also the overload's
--! limit: when ANY argument is untyped (a bare literal such as
--! `jsonb_path_match(col, '$.a == 1')`, or a parameter the driver sends with
--! no type), there is no exact match, the column is treated as jsonb, and
--! the native function runs. Only a call whose every argument has a type is
--! caught. An overload cannot close that, and nothing here tries to.
--!
--! The bodies raise on their own rather than through the
--! `{{prefix}}_internal` helpers: the domains outlive an uninstall of the
--! EQL schemas, and these overloads, which depend on nothing in them, go on
--! guarding the columns. `CREATE OR REPLACE`, like the CHECK validators in
--! `public`, so a reinstall over surviving domains succeeds.
--!
--! Deliberately NOT blocked: `jsonb_array_elements`,
--! `jsonb_array_elements_text` and `jsonb_array_length`. On either domain
--! the native function already raises (the envelope and an entry are
--! objects), so an overload buys only a different message, and costs what
--! every overload here costs: a plain-jsonb call whose first argument is
--! untyped, such as `jsonb_array_elements($1)` from a driver that sends no
--! parameter types, becomes ambiguous ('function ... is not unique') once
--! the overload exists, and must cast (`$1::jsonb`). The jsonb operators
--! above already impose that on untyped operands.

--! @brief Blocker: jsonb_path_exists(public.{{prefix}}_json_search, ...).
--! @param target public.{{prefix}}_json_search The encrypted document.
--! @param path jsonpath Native argument.
--! @param vars jsonb Native argument.
--! @param silent boolean Native argument.
--! @return boolean Never returns; always raises feature_not_supported.
CREATE OR REPLACE FUNCTION public.jsonb_path_exists(target public.{{prefix}}_json_search, path jsonpath, vars jsonb DEFAULT '{}'::jsonb, silent boolean DEFAULT false)
RETURNS boolean
IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RAISE EXCEPTION 'jsonb_path_exists is not supported for public.{{prefix}}_json_search: a jsonpath runs over the encrypted envelope, not the document, and matches nothing; query with EQL: col @> needle::{{prefix}}.query_json, or compare col -> selector with an {{prefix}}.query_json_leaf'
    USING ERRCODE = 'feature_not_supported', HINT = 'Cast the value to jsonb (col::jsonb) only to read the stored envelope itself.';
END;
$$ LANGUAGE plpgsql;

--! @brief Blocker: jsonb_path_exists_tz(public.{{prefix}}_json_search, ...).
--! @param target public.{{prefix}}_json_search The encrypted document.
--! @param path jsonpath Native argument.
--! @param vars jsonb Native argument.
--! @param silent boolean Native argument.
--! @return boolean Never returns; always raises feature_not_supported.
CREATE OR REPLACE FUNCTION public.jsonb_path_exists_tz(target public.{{prefix}}_json_search, path jsonpath, vars jsonb DEFAULT '{}'::jsonb, silent boolean DEFAULT false)
RETURNS boolean
STABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RAISE EXCEPTION 'jsonb_path_exists_tz is not supported for public.{{prefix}}_json_search: a jsonpath runs over the encrypted envelope, not the document, and matches nothing; query with EQL: col @> needle::{{prefix}}.query_json, or compare col -> selector with an {{prefix}}.query_json_leaf'
    USING ERRCODE = 'feature_not_supported', HINT = 'Cast the value to jsonb (col::jsonb) only to read the stored envelope itself.';
END;
$$ LANGUAGE plpgsql;

--! @brief Blocker: jsonb_path_match(public.{{prefix}}_json_search, ...).
--! @param target public.{{prefix}}_json_search The encrypted document.
--! @param path jsonpath Native argument.
--! @param vars jsonb Native argument.
--! @param silent boolean Native argument.
--! @return boolean Never returns; always raises feature_not_supported.
CREATE OR REPLACE FUNCTION public.jsonb_path_match(target public.{{prefix}}_json_search, path jsonpath, vars jsonb DEFAULT '{}'::jsonb, silent boolean DEFAULT false)
RETURNS boolean
IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RAISE EXCEPTION 'jsonb_path_match is not supported for public.{{prefix}}_json_search: a jsonpath runs over the encrypted envelope, not the document, and matches nothing; query with EQL: col @> needle::{{prefix}}.query_json, or compare col -> selector with an {{prefix}}.query_json_leaf'
    USING ERRCODE = 'feature_not_supported', HINT = 'Cast the value to jsonb (col::jsonb) only to read the stored envelope itself.';
END;
$$ LANGUAGE plpgsql;

--! @brief Blocker: jsonb_path_match_tz(public.{{prefix}}_json_search, ...).
--! @param target public.{{prefix}}_json_search The encrypted document.
--! @param path jsonpath Native argument.
--! @param vars jsonb Native argument.
--! @param silent boolean Native argument.
--! @return boolean Never returns; always raises feature_not_supported.
CREATE OR REPLACE FUNCTION public.jsonb_path_match_tz(target public.{{prefix}}_json_search, path jsonpath, vars jsonb DEFAULT '{}'::jsonb, silent boolean DEFAULT false)
RETURNS boolean
STABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RAISE EXCEPTION 'jsonb_path_match_tz is not supported for public.{{prefix}}_json_search: a jsonpath runs over the encrypted envelope, not the document, and matches nothing; query with EQL: col @> needle::{{prefix}}.query_json, or compare col -> selector with an {{prefix}}.query_json_leaf'
    USING ERRCODE = 'feature_not_supported', HINT = 'Cast the value to jsonb (col::jsonb) only to read the stored envelope itself.';
END;
$$ LANGUAGE plpgsql;

--! @brief Blocker: jsonb_path_query(public.{{prefix}}_json_search, ...).
--! @param target public.{{prefix}}_json_search The encrypted document.
--! @param path jsonpath Native argument.
--! @param vars jsonb Native argument.
--! @param silent boolean Native argument.
--! @return SETOF jsonb Never returns; always raises feature_not_supported.
CREATE OR REPLACE FUNCTION public.jsonb_path_query(target public.{{prefix}}_json_search, path jsonpath, vars jsonb DEFAULT '{}'::jsonb, silent boolean DEFAULT false)
RETURNS SETOF jsonb
IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RAISE EXCEPTION 'jsonb_path_query is not supported for public.{{prefix}}_json_search: a jsonpath runs over the encrypted envelope, not the document, and finds nothing; extract with EQL: col -> selector, {{prefix}}.json_tree_path_query(col, selector) or {{prefix}}.json_tree_subtree(col, tokens), and decrypt in the client'
    USING ERRCODE = 'feature_not_supported', HINT = 'Cast the value to jsonb (col::jsonb) only to read the stored envelope itself.';
END;
$$ LANGUAGE plpgsql;

--! @brief Blocker: jsonb_path_query_tz(public.{{prefix}}_json_search, ...).
--! @param target public.{{prefix}}_json_search The encrypted document.
--! @param path jsonpath Native argument.
--! @param vars jsonb Native argument.
--! @param silent boolean Native argument.
--! @return SETOF jsonb Never returns; always raises feature_not_supported.
CREATE OR REPLACE FUNCTION public.jsonb_path_query_tz(target public.{{prefix}}_json_search, path jsonpath, vars jsonb DEFAULT '{}'::jsonb, silent boolean DEFAULT false)
RETURNS SETOF jsonb
STABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RAISE EXCEPTION 'jsonb_path_query_tz is not supported for public.{{prefix}}_json_search: a jsonpath runs over the encrypted envelope, not the document, and finds nothing; extract with EQL: col -> selector, {{prefix}}.json_tree_path_query(col, selector) or {{prefix}}.json_tree_subtree(col, tokens), and decrypt in the client'
    USING ERRCODE = 'feature_not_supported', HINT = 'Cast the value to jsonb (col::jsonb) only to read the stored envelope itself.';
END;
$$ LANGUAGE plpgsql;

--! @brief Blocker: jsonb_path_query_array(public.{{prefix}}_json_search, ...).
--! @param target public.{{prefix}}_json_search The encrypted document.
--! @param path jsonpath Native argument.
--! @param vars jsonb Native argument.
--! @param silent boolean Native argument.
--! @return jsonb Never returns; always raises feature_not_supported.
CREATE OR REPLACE FUNCTION public.jsonb_path_query_array(target public.{{prefix}}_json_search, path jsonpath, vars jsonb DEFAULT '{}'::jsonb, silent boolean DEFAULT false)
RETURNS jsonb
IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RAISE EXCEPTION 'jsonb_path_query_array is not supported for public.{{prefix}}_json_search: a jsonpath runs over the encrypted envelope, not the document, and finds nothing; extract with EQL: col -> selector, {{prefix}}.json_tree_path_query(col, selector) or {{prefix}}.json_tree_subtree(col, tokens), and decrypt in the client'
    USING ERRCODE = 'feature_not_supported', HINT = 'Cast the value to jsonb (col::jsonb) only to read the stored envelope itself.';
END;
$$ LANGUAGE plpgsql;

--! @brief Blocker: jsonb_path_query_array_tz(public.{{prefix}}_json_search, ...).
--! @param target public.{{prefix}}_json_search The encrypted document.
--! @param path jsonpath Native argument.
--! @param vars jsonb Native argument.
--! @param silent boolean Native argument.
--! @return jsonb Never returns; always raises feature_not_supported.
CREATE OR REPLACE FUNCTION public.jsonb_path_query_array_tz(target public.{{prefix}}_json_search, path jsonpath, vars jsonb DEFAULT '{}'::jsonb, silent boolean DEFAULT false)
RETURNS jsonb
STABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RAISE EXCEPTION 'jsonb_path_query_array_tz is not supported for public.{{prefix}}_json_search: a jsonpath runs over the encrypted envelope, not the document, and finds nothing; extract with EQL: col -> selector, {{prefix}}.json_tree_path_query(col, selector) or {{prefix}}.json_tree_subtree(col, tokens), and decrypt in the client'
    USING ERRCODE = 'feature_not_supported', HINT = 'Cast the value to jsonb (col::jsonb) only to read the stored envelope itself.';
END;
$$ LANGUAGE plpgsql;

--! @brief Blocker: jsonb_path_query_first(public.{{prefix}}_json_search, ...).
--! @param target public.{{prefix}}_json_search The encrypted document.
--! @param path jsonpath Native argument.
--! @param vars jsonb Native argument.
--! @param silent boolean Native argument.
--! @return jsonb Never returns; always raises feature_not_supported.
CREATE OR REPLACE FUNCTION public.jsonb_path_query_first(target public.{{prefix}}_json_search, path jsonpath, vars jsonb DEFAULT '{}'::jsonb, silent boolean DEFAULT false)
RETURNS jsonb
IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RAISE EXCEPTION 'jsonb_path_query_first is not supported for public.{{prefix}}_json_search: a jsonpath runs over the encrypted envelope, not the document, and finds nothing; extract with EQL: col -> selector, {{prefix}}.json_tree_path_query(col, selector) or {{prefix}}.json_tree_subtree(col, tokens), and decrypt in the client'
    USING ERRCODE = 'feature_not_supported', HINT = 'Cast the value to jsonb (col::jsonb) only to read the stored envelope itself.';
END;
$$ LANGUAGE plpgsql;

--! @brief Blocker: jsonb_path_query_first_tz(public.{{prefix}}_json_search, ...).
--! @param target public.{{prefix}}_json_search The encrypted document.
--! @param path jsonpath Native argument.
--! @param vars jsonb Native argument.
--! @param silent boolean Native argument.
--! @return jsonb Never returns; always raises feature_not_supported.
CREATE OR REPLACE FUNCTION public.jsonb_path_query_first_tz(target public.{{prefix}}_json_search, path jsonpath, vars jsonb DEFAULT '{}'::jsonb, silent boolean DEFAULT false)
RETURNS jsonb
STABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RAISE EXCEPTION 'jsonb_path_query_first_tz is not supported for public.{{prefix}}_json_search: a jsonpath runs over the encrypted envelope, not the document, and finds nothing; extract with EQL: col -> selector, {{prefix}}.json_tree_path_query(col, selector) or {{prefix}}.json_tree_subtree(col, tokens), and decrypt in the client'
    USING ERRCODE = 'feature_not_supported', HINT = 'Cast the value to jsonb (col::jsonb) only to read the stored envelope itself.';
END;
$$ LANGUAGE plpgsql;

--! @brief Blocker: jsonb_extract_path(public.{{prefix}}_json_search, ...).
--! @param from_json public.{{prefix}}_json_search The encrypted document.
--! @param path_elems text[] Native argument.
--! @return jsonb Never returns; always raises feature_not_supported.
CREATE OR REPLACE FUNCTION public.jsonb_extract_path(from_json public.{{prefix}}_json_search, VARIADIC path_elems text[])
RETURNS jsonb
IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RAISE EXCEPTION 'jsonb_extract_path is not supported for public.{{prefix}}_json_search: the keys of the document are encrypted, so a key path finds nothing; extract with EQL: col -> selector, and decrypt the entry in the client'
    USING ERRCODE = 'feature_not_supported', HINT = 'Cast the value to jsonb (col::jsonb) only to read the stored envelope itself.';
END;
$$ LANGUAGE plpgsql;

--! @brief Blocker: jsonb_extract_path_text(public.{{prefix}}_json_search, ...).
--! @param from_json public.{{prefix}}_json_search The encrypted document.
--! @param path_elems text[] Native argument.
--! @return text Never returns; always raises feature_not_supported.
CREATE OR REPLACE FUNCTION public.jsonb_extract_path_text(from_json public.{{prefix}}_json_search, VARIADIC path_elems text[])
RETURNS text
IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RAISE EXCEPTION 'jsonb_extract_path_text is not supported for public.{{prefix}}_json_search: the keys of the document are encrypted, so a key path finds nothing; extract with EQL: col -> selector, and decrypt the entry in the client'
    USING ERRCODE = 'feature_not_supported', HINT = 'Cast the value to jsonb (col::jsonb) only to read the stored envelope itself.';
END;
$$ LANGUAGE plpgsql;

--! @brief Blocker: jsonb_each(public.{{prefix}}_json_search, ...).
--! @param from_json public.{{prefix}}_json_search The encrypted document.
--! @return SETOF record (key text, value jsonb) Never returns; always raises feature_not_supported.
CREATE OR REPLACE FUNCTION public.jsonb_each(from_json public.{{prefix}}_json_search, OUT key text, OUT value jsonb)
RETURNS SETOF record
IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RAISE EXCEPTION 'jsonb_each is not supported for public.{{prefix}}_json_search: it would list the encrypted envelope, not the document; list the children of a node with {{prefix}}.json_tree_children(col, token), and decrypt in the client'
    USING ERRCODE = 'feature_not_supported', HINT = 'Cast the value to jsonb (col::jsonb) only to read the stored envelope itself.';
END;
$$ LANGUAGE plpgsql;

--! @brief Blocker: jsonb_each_text(public.{{prefix}}_json_search, ...).
--! @param from_json public.{{prefix}}_json_search The encrypted document.
--! @return SETOF record (key text, value text) Never returns; always raises feature_not_supported.
CREATE OR REPLACE FUNCTION public.jsonb_each_text(from_json public.{{prefix}}_json_search, OUT key text, OUT value text)
RETURNS SETOF record
IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RAISE EXCEPTION 'jsonb_each_text is not supported for public.{{prefix}}_json_search: it would list the encrypted envelope, not the document; list the children of a node with {{prefix}}.json_tree_children(col, token), and decrypt in the client'
    USING ERRCODE = 'feature_not_supported', HINT = 'Cast the value to jsonb (col::jsonb) only to read the stored envelope itself.';
END;
$$ LANGUAGE plpgsql;

--! @brief Blocker: jsonb_object_keys(public.{{prefix}}_json_search, ...).
--! @param from_json public.{{prefix}}_json_search The encrypted document.
--! @return SETOF text Never returns; always raises feature_not_supported.
CREATE OR REPLACE FUNCTION public.jsonb_object_keys(from_json public.{{prefix}}_json_search)
RETURNS SETOF text
IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RAISE EXCEPTION 'jsonb_object_keys is not supported for public.{{prefix}}_json_search: it would list the encrypted envelope, not the document; list the children of a node with {{prefix}}.json_tree_children(col, token), and decrypt in the client'
    USING ERRCODE = 'feature_not_supported', HINT = 'Cast the value to jsonb (col::jsonb) only to read the stored envelope itself.';
END;
$$ LANGUAGE plpgsql;

--! @brief Blocker: jsonb_typeof(public.{{prefix}}_json_search, ...).
--! @param from_json public.{{prefix}}_json_search The encrypted document.
--! @return text Never returns; always raises feature_not_supported.
CREATE OR REPLACE FUNCTION public.jsonb_typeof(from_json public.{{prefix}}_json_search)
RETURNS text
IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RAISE EXCEPTION 'jsonb_typeof is not supported for public.{{prefix}}_json_search: the kind of every node is encrypted, so it would answer object for every row; decrypt the document in the client'
    USING ERRCODE = 'feature_not_supported', HINT = 'Cast the value to jsonb (col::jsonb) only to read the stored envelope itself.';
END;
$$ LANGUAGE plpgsql;

--! @brief Blocker: jsonb_strip_nulls(public.{{prefix}}_json_search, ...).
--! @param from_json public.{{prefix}}_json_search The encrypted document.
--! @param strip_in_arrays boolean Native argument.
--! @return jsonb Never returns; always raises feature_not_supported.
CREATE OR REPLACE FUNCTION public.jsonb_strip_nulls(from_json public.{{prefix}}_json_search, strip_in_arrays boolean DEFAULT false)
RETURNS jsonb
IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RAISE EXCEPTION 'jsonb_strip_nulls is not supported for public.{{prefix}}_json_search: an encrypted document cannot be edited in the database; decrypt it, change the plaintext and encrypt it again in the client'
    USING ERRCODE = 'feature_not_supported', HINT = 'Cast the value to jsonb (col::jsonb) only to read the stored envelope itself.';
END;
$$ LANGUAGE plpgsql;

--! @brief Blocker: jsonb_set(public.{{prefix}}_json_search, ...).
--! @param jsonb_in public.{{prefix}}_json_search The encrypted document.
--! @param path text[] Native argument.
--! @param replacement jsonb Native argument.
--! @param create_if_missing boolean Native argument.
--! @return jsonb Never returns; always raises feature_not_supported.
CREATE OR REPLACE FUNCTION public.jsonb_set(jsonb_in public.{{prefix}}_json_search, path text[], replacement jsonb, create_if_missing boolean DEFAULT true)
RETURNS jsonb
IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RAISE EXCEPTION 'jsonb_set is not supported for public.{{prefix}}_json_search: an encrypted document cannot be edited in the database; decrypt it, change the plaintext and encrypt it again in the client'
    USING ERRCODE = 'feature_not_supported', HINT = 'Cast the value to jsonb (col::jsonb) only to read the stored envelope itself.';
END;
$$ LANGUAGE plpgsql;

--! @brief Blocker: jsonb_insert(public.{{prefix}}_json_search, ...).
--! @param jsonb_in public.{{prefix}}_json_search The encrypted document.
--! @param path text[] Native argument.
--! @param replacement jsonb Native argument.
--! @param insert_after boolean Native argument.
--! @return jsonb Never returns; always raises feature_not_supported.
CREATE OR REPLACE FUNCTION public.jsonb_insert(jsonb_in public.{{prefix}}_json_search, path text[], replacement jsonb, insert_after boolean DEFAULT false)
RETURNS jsonb
IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RAISE EXCEPTION 'jsonb_insert is not supported for public.{{prefix}}_json_search: an encrypted document cannot be edited in the database; decrypt it, change the plaintext and encrypt it again in the client'
    USING ERRCODE = 'feature_not_supported', HINT = 'Cast the value to jsonb (col::jsonb) only to read the stored envelope itself.';
END;
$$ LANGUAGE plpgsql;

--! @brief Blocker: jsonb_pretty(public.{{prefix}}_json_search, ...).
--! @param from_json public.{{prefix}}_json_search The encrypted document.
--! @return text Never returns; always raises feature_not_supported.
CREATE OR REPLACE FUNCTION public.jsonb_pretty(from_json public.{{prefix}}_json_search)
RETURNS text
IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RAISE EXCEPTION 'jsonb_pretty is not supported for public.{{prefix}}_json_search: it would print the encrypted envelope, not the document; decrypt the document in the client'
    USING ERRCODE = 'feature_not_supported', HINT = 'Cast the value to jsonb (col::jsonb) only to read the stored envelope itself.';
END;
$$ LANGUAGE plpgsql;

--! @brief Blocker: jsonb_path_exists(public.{{prefix}}_json_entry, ...).
--! @param target public.{{prefix}}_json_entry An entry extracted from an encrypted document.
--! @param path jsonpath Native argument.
--! @param vars jsonb Native argument.
--! @param silent boolean Native argument.
--! @return boolean Never returns; always raises feature_not_supported.
CREATE OR REPLACE FUNCTION public.jsonb_path_exists(target public.{{prefix}}_json_entry, path jsonpath, vars jsonb DEFAULT '{}'::jsonb, silent boolean DEFAULT false)
RETURNS boolean
IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RAISE EXCEPTION 'jsonb_path_exists is not supported for public.{{prefix}}_json_entry: a jsonpath runs over the encrypted entry, not its value, and matches nothing; compare the entry with an {{prefix}}.query_json_leaf, or test the document with col @> needle::{{prefix}}.query_json'
    USING ERRCODE = 'feature_not_supported', HINT = 'Cast the value to jsonb (col::jsonb) only to read the stored envelope itself.';
END;
$$ LANGUAGE plpgsql;

--! @brief Blocker: jsonb_path_exists_tz(public.{{prefix}}_json_entry, ...).
--! @param target public.{{prefix}}_json_entry An entry extracted from an encrypted document.
--! @param path jsonpath Native argument.
--! @param vars jsonb Native argument.
--! @param silent boolean Native argument.
--! @return boolean Never returns; always raises feature_not_supported.
CREATE OR REPLACE FUNCTION public.jsonb_path_exists_tz(target public.{{prefix}}_json_entry, path jsonpath, vars jsonb DEFAULT '{}'::jsonb, silent boolean DEFAULT false)
RETURNS boolean
STABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RAISE EXCEPTION 'jsonb_path_exists_tz is not supported for public.{{prefix}}_json_entry: a jsonpath runs over the encrypted entry, not its value, and matches nothing; compare the entry with an {{prefix}}.query_json_leaf, or test the document with col @> needle::{{prefix}}.query_json'
    USING ERRCODE = 'feature_not_supported', HINT = 'Cast the value to jsonb (col::jsonb) only to read the stored envelope itself.';
END;
$$ LANGUAGE plpgsql;

--! @brief Blocker: jsonb_path_match(public.{{prefix}}_json_entry, ...).
--! @param target public.{{prefix}}_json_entry An entry extracted from an encrypted document.
--! @param path jsonpath Native argument.
--! @param vars jsonb Native argument.
--! @param silent boolean Native argument.
--! @return boolean Never returns; always raises feature_not_supported.
CREATE OR REPLACE FUNCTION public.jsonb_path_match(target public.{{prefix}}_json_entry, path jsonpath, vars jsonb DEFAULT '{}'::jsonb, silent boolean DEFAULT false)
RETURNS boolean
IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RAISE EXCEPTION 'jsonb_path_match is not supported for public.{{prefix}}_json_entry: a jsonpath runs over the encrypted entry, not its value, and matches nothing; compare the entry with an {{prefix}}.query_json_leaf, or test the document with col @> needle::{{prefix}}.query_json'
    USING ERRCODE = 'feature_not_supported', HINT = 'Cast the value to jsonb (col::jsonb) only to read the stored envelope itself.';
END;
$$ LANGUAGE plpgsql;

--! @brief Blocker: jsonb_path_match_tz(public.{{prefix}}_json_entry, ...).
--! @param target public.{{prefix}}_json_entry An entry extracted from an encrypted document.
--! @param path jsonpath Native argument.
--! @param vars jsonb Native argument.
--! @param silent boolean Native argument.
--! @return boolean Never returns; always raises feature_not_supported.
CREATE OR REPLACE FUNCTION public.jsonb_path_match_tz(target public.{{prefix}}_json_entry, path jsonpath, vars jsonb DEFAULT '{}'::jsonb, silent boolean DEFAULT false)
RETURNS boolean
STABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RAISE EXCEPTION 'jsonb_path_match_tz is not supported for public.{{prefix}}_json_entry: a jsonpath runs over the encrypted entry, not its value, and matches nothing; compare the entry with an {{prefix}}.query_json_leaf, or test the document with col @> needle::{{prefix}}.query_json'
    USING ERRCODE = 'feature_not_supported', HINT = 'Cast the value to jsonb (col::jsonb) only to read the stored envelope itself.';
END;
$$ LANGUAGE plpgsql;

--! @brief Blocker: jsonb_path_query(public.{{prefix}}_json_entry, ...).
--! @param target public.{{prefix}}_json_entry An entry extracted from an encrypted document.
--! @param path jsonpath Native argument.
--! @param vars jsonb Native argument.
--! @param silent boolean Native argument.
--! @return SETOF jsonb Never returns; always raises feature_not_supported.
CREATE OR REPLACE FUNCTION public.jsonb_path_query(target public.{{prefix}}_json_entry, path jsonpath, vars jsonb DEFAULT '{}'::jsonb, silent boolean DEFAULT false)
RETURNS SETOF jsonb
IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RAISE EXCEPTION 'jsonb_path_query is not supported for public.{{prefix}}_json_entry: a jsonpath runs over the encrypted entry, not its value, and finds nothing; decrypt the entry in the client'
    USING ERRCODE = 'feature_not_supported', HINT = 'Cast the value to jsonb (col::jsonb) only to read the stored envelope itself.';
END;
$$ LANGUAGE plpgsql;

--! @brief Blocker: jsonb_path_query_tz(public.{{prefix}}_json_entry, ...).
--! @param target public.{{prefix}}_json_entry An entry extracted from an encrypted document.
--! @param path jsonpath Native argument.
--! @param vars jsonb Native argument.
--! @param silent boolean Native argument.
--! @return SETOF jsonb Never returns; always raises feature_not_supported.
CREATE OR REPLACE FUNCTION public.jsonb_path_query_tz(target public.{{prefix}}_json_entry, path jsonpath, vars jsonb DEFAULT '{}'::jsonb, silent boolean DEFAULT false)
RETURNS SETOF jsonb
STABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RAISE EXCEPTION 'jsonb_path_query_tz is not supported for public.{{prefix}}_json_entry: a jsonpath runs over the encrypted entry, not its value, and finds nothing; decrypt the entry in the client'
    USING ERRCODE = 'feature_not_supported', HINT = 'Cast the value to jsonb (col::jsonb) only to read the stored envelope itself.';
END;
$$ LANGUAGE plpgsql;

--! @brief Blocker: jsonb_path_query_array(public.{{prefix}}_json_entry, ...).
--! @param target public.{{prefix}}_json_entry An entry extracted from an encrypted document.
--! @param path jsonpath Native argument.
--! @param vars jsonb Native argument.
--! @param silent boolean Native argument.
--! @return jsonb Never returns; always raises feature_not_supported.
CREATE OR REPLACE FUNCTION public.jsonb_path_query_array(target public.{{prefix}}_json_entry, path jsonpath, vars jsonb DEFAULT '{}'::jsonb, silent boolean DEFAULT false)
RETURNS jsonb
IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RAISE EXCEPTION 'jsonb_path_query_array is not supported for public.{{prefix}}_json_entry: a jsonpath runs over the encrypted entry, not its value, and finds nothing; decrypt the entry in the client'
    USING ERRCODE = 'feature_not_supported', HINT = 'Cast the value to jsonb (col::jsonb) only to read the stored envelope itself.';
END;
$$ LANGUAGE plpgsql;

--! @brief Blocker: jsonb_path_query_array_tz(public.{{prefix}}_json_entry, ...).
--! @param target public.{{prefix}}_json_entry An entry extracted from an encrypted document.
--! @param path jsonpath Native argument.
--! @param vars jsonb Native argument.
--! @param silent boolean Native argument.
--! @return jsonb Never returns; always raises feature_not_supported.
CREATE OR REPLACE FUNCTION public.jsonb_path_query_array_tz(target public.{{prefix}}_json_entry, path jsonpath, vars jsonb DEFAULT '{}'::jsonb, silent boolean DEFAULT false)
RETURNS jsonb
STABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RAISE EXCEPTION 'jsonb_path_query_array_tz is not supported for public.{{prefix}}_json_entry: a jsonpath runs over the encrypted entry, not its value, and finds nothing; decrypt the entry in the client'
    USING ERRCODE = 'feature_not_supported', HINT = 'Cast the value to jsonb (col::jsonb) only to read the stored envelope itself.';
END;
$$ LANGUAGE plpgsql;

--! @brief Blocker: jsonb_path_query_first(public.{{prefix}}_json_entry, ...).
--! @param target public.{{prefix}}_json_entry An entry extracted from an encrypted document.
--! @param path jsonpath Native argument.
--! @param vars jsonb Native argument.
--! @param silent boolean Native argument.
--! @return jsonb Never returns; always raises feature_not_supported.
CREATE OR REPLACE FUNCTION public.jsonb_path_query_first(target public.{{prefix}}_json_entry, path jsonpath, vars jsonb DEFAULT '{}'::jsonb, silent boolean DEFAULT false)
RETURNS jsonb
IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RAISE EXCEPTION 'jsonb_path_query_first is not supported for public.{{prefix}}_json_entry: a jsonpath runs over the encrypted entry, not its value, and finds nothing; decrypt the entry in the client'
    USING ERRCODE = 'feature_not_supported', HINT = 'Cast the value to jsonb (col::jsonb) only to read the stored envelope itself.';
END;
$$ LANGUAGE plpgsql;

--! @brief Blocker: jsonb_path_query_first_tz(public.{{prefix}}_json_entry, ...).
--! @param target public.{{prefix}}_json_entry An entry extracted from an encrypted document.
--! @param path jsonpath Native argument.
--! @param vars jsonb Native argument.
--! @param silent boolean Native argument.
--! @return jsonb Never returns; always raises feature_not_supported.
CREATE OR REPLACE FUNCTION public.jsonb_path_query_first_tz(target public.{{prefix}}_json_entry, path jsonpath, vars jsonb DEFAULT '{}'::jsonb, silent boolean DEFAULT false)
RETURNS jsonb
STABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RAISE EXCEPTION 'jsonb_path_query_first_tz is not supported for public.{{prefix}}_json_entry: a jsonpath runs over the encrypted entry, not its value, and finds nothing; decrypt the entry in the client'
    USING ERRCODE = 'feature_not_supported', HINT = 'Cast the value to jsonb (col::jsonb) only to read the stored envelope itself.';
END;
$$ LANGUAGE plpgsql;

--! @brief Blocker: jsonb_extract_path(public.{{prefix}}_json_entry, ...).
--! @param from_json public.{{prefix}}_json_entry An entry extracted from an encrypted document.
--! @param path_elems text[] Native argument.
--! @return jsonb Never returns; always raises feature_not_supported.
CREATE OR REPLACE FUNCTION public.jsonb_extract_path(from_json public.{{prefix}}_json_entry, VARIADIC path_elems text[])
RETURNS jsonb
IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RAISE EXCEPTION 'jsonb_extract_path is not supported for public.{{prefix}}_json_entry: the value of an entry is encrypted, so a key path finds nothing; decrypt the entry in the client'
    USING ERRCODE = 'feature_not_supported', HINT = 'Cast the value to jsonb (col::jsonb) only to read the stored envelope itself.';
END;
$$ LANGUAGE plpgsql;

--! @brief Blocker: jsonb_extract_path_text(public.{{prefix}}_json_entry, ...).
--! @param from_json public.{{prefix}}_json_entry An entry extracted from an encrypted document.
--! @param path_elems text[] Native argument.
--! @return text Never returns; always raises feature_not_supported.
CREATE OR REPLACE FUNCTION public.jsonb_extract_path_text(from_json public.{{prefix}}_json_entry, VARIADIC path_elems text[])
RETURNS text
IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RAISE EXCEPTION 'jsonb_extract_path_text is not supported for public.{{prefix}}_json_entry: the value of an entry is encrypted, so a key path finds nothing; decrypt the entry in the client'
    USING ERRCODE = 'feature_not_supported', HINT = 'Cast the value to jsonb (col::jsonb) only to read the stored envelope itself.';
END;
$$ LANGUAGE plpgsql;

--! @brief Blocker: jsonb_each(public.{{prefix}}_json_entry, ...).
--! @param from_json public.{{prefix}}_json_entry An entry extracted from an encrypted document.
--! @return SETOF record (key text, value jsonb) Never returns; always raises feature_not_supported.
CREATE OR REPLACE FUNCTION public.jsonb_each(from_json public.{{prefix}}_json_entry, OUT key text, OUT value jsonb)
RETURNS SETOF record
IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RAISE EXCEPTION 'jsonb_each is not supported for public.{{prefix}}_json_entry: it would list the fields of the encrypted entry, not its value; decrypt the entry in the client'
    USING ERRCODE = 'feature_not_supported', HINT = 'Cast the value to jsonb (col::jsonb) only to read the stored envelope itself.';
END;
$$ LANGUAGE plpgsql;

--! @brief Blocker: jsonb_each_text(public.{{prefix}}_json_entry, ...).
--! @param from_json public.{{prefix}}_json_entry An entry extracted from an encrypted document.
--! @return SETOF record (key text, value text) Never returns; always raises feature_not_supported.
CREATE OR REPLACE FUNCTION public.jsonb_each_text(from_json public.{{prefix}}_json_entry, OUT key text, OUT value text)
RETURNS SETOF record
IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RAISE EXCEPTION 'jsonb_each_text is not supported for public.{{prefix}}_json_entry: it would list the fields of the encrypted entry, not its value; decrypt the entry in the client'
    USING ERRCODE = 'feature_not_supported', HINT = 'Cast the value to jsonb (col::jsonb) only to read the stored envelope itself.';
END;
$$ LANGUAGE plpgsql;

--! @brief Blocker: jsonb_object_keys(public.{{prefix}}_json_entry, ...).
--! @param from_json public.{{prefix}}_json_entry An entry extracted from an encrypted document.
--! @return SETOF text Never returns; always raises feature_not_supported.
CREATE OR REPLACE FUNCTION public.jsonb_object_keys(from_json public.{{prefix}}_json_entry)
RETURNS SETOF text
IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RAISE EXCEPTION 'jsonb_object_keys is not supported for public.{{prefix}}_json_entry: it would list the fields of the encrypted entry, not its value; decrypt the entry in the client'
    USING ERRCODE = 'feature_not_supported', HINT = 'Cast the value to jsonb (col::jsonb) only to read the stored envelope itself.';
END;
$$ LANGUAGE plpgsql;

--! @brief Blocker: jsonb_typeof(public.{{prefix}}_json_entry, ...).
--! @param from_json public.{{prefix}}_json_entry An entry extracted from an encrypted document.
--! @return text Never returns; always raises feature_not_supported.
CREATE OR REPLACE FUNCTION public.jsonb_typeof(from_json public.{{prefix}}_json_entry)
RETURNS text
IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RAISE EXCEPTION 'jsonb_typeof is not supported for public.{{prefix}}_json_entry: the kind of the node is encrypted, so it would answer object for every entry; decrypt the entry in the client'
    USING ERRCODE = 'feature_not_supported', HINT = 'Cast the value to jsonb (col::jsonb) only to read the stored envelope itself.';
END;
$$ LANGUAGE plpgsql;

--! @brief Blocker: jsonb_strip_nulls(public.{{prefix}}_json_entry, ...).
--! @param from_json public.{{prefix}}_json_entry An entry extracted from an encrypted document.
--! @param strip_in_arrays boolean Native argument.
--! @return jsonb Never returns; always raises feature_not_supported.
CREATE OR REPLACE FUNCTION public.jsonb_strip_nulls(from_json public.{{prefix}}_json_entry, strip_in_arrays boolean DEFAULT false)
RETURNS jsonb
IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RAISE EXCEPTION 'jsonb_strip_nulls is not supported for public.{{prefix}}_json_entry: an encrypted entry cannot be edited in the database; decrypt the document, change the plaintext and encrypt it again in the client'
    USING ERRCODE = 'feature_not_supported', HINT = 'Cast the value to jsonb (col::jsonb) only to read the stored envelope itself.';
END;
$$ LANGUAGE plpgsql;

--! @brief Blocker: jsonb_set(public.{{prefix}}_json_entry, ...).
--! @param jsonb_in public.{{prefix}}_json_entry An entry extracted from an encrypted document.
--! @param path text[] Native argument.
--! @param replacement jsonb Native argument.
--! @param create_if_missing boolean Native argument.
--! @return jsonb Never returns; always raises feature_not_supported.
CREATE OR REPLACE FUNCTION public.jsonb_set(jsonb_in public.{{prefix}}_json_entry, path text[], replacement jsonb, create_if_missing boolean DEFAULT true)
RETURNS jsonb
IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RAISE EXCEPTION 'jsonb_set is not supported for public.{{prefix}}_json_entry: an encrypted entry cannot be edited in the database; decrypt the document, change the plaintext and encrypt it again in the client'
    USING ERRCODE = 'feature_not_supported', HINT = 'Cast the value to jsonb (col::jsonb) only to read the stored envelope itself.';
END;
$$ LANGUAGE plpgsql;

--! @brief Blocker: jsonb_insert(public.{{prefix}}_json_entry, ...).
--! @param jsonb_in public.{{prefix}}_json_entry An entry extracted from an encrypted document.
--! @param path text[] Native argument.
--! @param replacement jsonb Native argument.
--! @param insert_after boolean Native argument.
--! @return jsonb Never returns; always raises feature_not_supported.
CREATE OR REPLACE FUNCTION public.jsonb_insert(jsonb_in public.{{prefix}}_json_entry, path text[], replacement jsonb, insert_after boolean DEFAULT false)
RETURNS jsonb
IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RAISE EXCEPTION 'jsonb_insert is not supported for public.{{prefix}}_json_entry: an encrypted entry cannot be edited in the database; decrypt the document, change the plaintext and encrypt it again in the client'
    USING ERRCODE = 'feature_not_supported', HINT = 'Cast the value to jsonb (col::jsonb) only to read the stored envelope itself.';
END;
$$ LANGUAGE plpgsql;

--! @brief Blocker: jsonb_pretty(public.{{prefix}}_json_entry, ...).
--! @param from_json public.{{prefix}}_json_entry An entry extracted from an encrypted document.
--! @return text Never returns; always raises feature_not_supported.
CREATE OR REPLACE FUNCTION public.jsonb_pretty(from_json public.{{prefix}}_json_entry)
RETURNS text
IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, extensions, public
AS $$
BEGIN
  RAISE EXCEPTION 'jsonb_pretty is not supported for public.{{prefix}}_json_entry: it would print the encrypted entry, not its value; decrypt the entry in the client'
    USING ERRCODE = 'feature_not_supported', HINT = 'Cast the value to jsonb (col::jsonb) only to read the stored envelope itself.';
END;
$$ LANGUAGE plpgsql;
