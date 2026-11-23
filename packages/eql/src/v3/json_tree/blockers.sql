-- ONLY EQL VERSION: 4
-- REQUIRE: src/v3/schema.sql
-- REQUIRE: src/v3/json_tree/types.sql
-- REQUIRE: src/v3/scalars/functions.sql

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
