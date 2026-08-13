#!/usr/bin/env bash
#MISE description="DB-free self-test for the symbol-order cross-check (good passes, mis-ordered fails)"
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT

# GOOD: definer ordered before user. (a.sql RETURNS a non-owned type — the
# hmac_256 domain-capture branch is exercised separately by d.sql/e.sql below, so
# this pair isolates the eql_v3.eq_term define-before-use ordering it is testing.)
printf 'CREATE FUNCTION eql_v3.eq_term(a public.integer_eq) RETURNS text ...\n' > "$tmp/a.sql"
printf 'CREATE OPERATOR = ( FUNCTION = eql_v3.eq_term );\n' > "$tmp/b.sql"
printf '%s\n%s\n' "$tmp/a.sql" "$tmp/b.sql" > "$tmp/good_order.txt"
bash tasks/test/verify_symbol_order_v3.sh "$tmp/good_order.txt" \
  || { echo "FAIL: good order rejected"; exit 1; }
echo "ok: good order accepted"

# BAD: user ordered before definer.
printf '%s\n%s\n' "$tmp/b.sql" "$tmp/a.sql" > "$tmp/bad_order.txt"
if bash tasks/test/verify_symbol_order_v3.sh "$tmp/bad_order.txt" 2>/dev/null; then
  echo "FAIL: mis-ordered reference accepted"; exit 1
fi
echo "ok: mis-ordered reference rejected"

# COMMENT-ONLY reference must NOT trip the gate (doxygen @see).
printf -- '--! @see eql_v3.eq_term\nSELECT 1;\n' > "$tmp/c.sql"
printf '%s\n' "$tmp/c.sql" > "$tmp/comment_order.txt"
bash tasks/test/verify_symbol_order_v3.sh "$tmp/comment_order.txt" \
  || { echo "FAIL: comment-only reference tripped the gate"; exit 1; }
echo "ok: comment-only reference ignored"

# CREATE DOMAIN eql_v3_internal.* form (SEM index-term types hmac_256/ope_cllw/
# bloom_filter). A domain-form definer ordered before a function returning it
# must be ACCEPTED — pins the domain-capture branch's eql_v3_internal arm so the
# real surface (~165 refs to these three types) can never be misread as "defined
# nowhere" (which would tempt an allowlist entry).
printf 'CREATE DOMAIN eql_v3_internal.hmac_256 AS text;\n' > "$tmp/d.sql"
printf 'CREATE FUNCTION eql_v3.eq_term(a public.integer_eq) RETURNS eql_v3_internal.hmac_256 ...\n' > "$tmp/e.sql"
printf '%s\n%s\n' "$tmp/d.sql" "$tmp/e.sql" > "$tmp/domain_good.txt"
bash tasks/test/verify_symbol_order_v3.sh "$tmp/domain_good.txt" \
  || { echo "FAIL: CREATE DOMAIN eql_v3_internal.* definer not recognised"; exit 1; }
echo "ok: CREATE DOMAIN eql_v3_internal.* definition form recognised"

# And the same domain-form type used BEFORE it is created must be REJECTED
# (defined-later ordering violation on a SEM index-term type — the exact rot
# this gate exists to catch).
printf '%s\n%s\n' "$tmp/e.sql" "$tmp/d.sql" > "$tmp/domain_bad.txt"
if bash tasks/test/verify_symbol_order_v3.sh "$tmp/domain_bad.txt" 2>/dev/null; then
  echo "FAIL: eql_v3_internal.hmac_256 used before its CREATE DOMAIN accepted"; exit 1
fi
echo "ok: domain-form type used before definition rejected"

# CREATE DOMAIN eql_v3.* form. Query operands live in `eql_v3`, not `public`,
# because a query operand is never a column type: eql_v3.query_<T>_<cap> and
# eql_v3.query_json. Pins the domain-capture branch's eql_v3 arm. Without it
# every query domain on the surface reads as "defined nowhere" — the regression
# that reddened every build-dependent CI job.
printf 'CREATE DOMAIN eql_v3.query_integer_eq AS jsonb;\n' > "$tmp/q.sql"
printf 'CREATE FUNCTION eql_v3.eq(a public.integer_eq, b eql_v3.query_integer_eq) ...\n' > "$tmp/qf.sql"
printf '%s\n%s\n' "$tmp/q.sql" "$tmp/qf.sql" > "$tmp/qdomain_good.txt"
bash tasks/test/verify_symbol_order_v3.sh "$tmp/qdomain_good.txt" \
  || { echo "FAIL: CREATE DOMAIN eql_v3.* definer not recognised"; exit 1; }
echo "ok: CREATE DOMAIN eql_v3.* definition form recognised"

# And a query-operand domain used BEFORE it is created must still be REJECTED —
# proves the eql_v3 arm records a definition rather than silently suppressing the
# symbol (a check that never fires would pass the case above too).
printf '%s\n%s\n' "$tmp/qf.sql" "$tmp/q.sql" > "$tmp/qdomain_bad.txt"
if bash tasks/test/verify_symbol_order_v3.sh "$tmp/qdomain_bad.txt" 2>/dev/null; then
  echo "FAIL: eql_v3.query_integer_eq used before its CREATE DOMAIN accepted"; exit 1
fi
echo "ok: query-operand domain used before definition rejected"

# CREATE OPERATOR CLASS|FAMILY eql_v3_internal.* form (the conditional SEM
# ordered-index opclasses). A file that both creates the opclass and mentions it
# in a RAISE NOTICE (same file) must be ACCEPTED — pins the operator-class
# definition-capture branch so the real ore_block_256/ore_cllw operator_class.sql
# files (self-contained: def + NOTICE prose only) never read as "defined nowhere".
printf "CREATE OPERATOR FAMILY eql_v3_internal.ore_cllw_ops USING btree;\nCREATE OPERATOR CLASS eql_v3_internal.ore_cllw_ops USING btree FAMILY eql_v3_internal.ore_cllw_ops AS STORAGE text;\nRAISE NOTICE 'created operator class eql_v3_internal.ore_cllw_ops';\n" > "$tmp/opclass.sql"
printf '%s\n' "$tmp/opclass.sql" > "$tmp/opclass_order.txt"
bash tasks/test/verify_symbol_order_v3.sh "$tmp/opclass_order.txt" \
  || { echo "FAIL: CREATE OPERATOR CLASS/FAMILY definer not recognised"; exit 1; }
echo "ok: CREATE OPERATOR CLASS/FAMILY definition form recognised"

# An UNREADABLE path in the ordered list must FAIL the gate, not be silently
# skipped as an empty file (a skipped file's definitions/references go unchecked).
printf '%s\n' "$tmp/does-not-exist.sql" > "$tmp/missing_order.txt"
if bash tasks/test/verify_symbol_order_v3.sh "$tmp/missing_order.txt" 2>/dev/null; then
  echo "FAIL: unreadable path silently accepted"; exit 1
fi
echo "ok: unreadable path rejected"

# An EMPTY ordered list must FAIL, not report "OK (0 files)". A vacuous pass is
# indistinguishable in CI from a real one, so an emptied src/v3 would clear this
# gate and ship an installer containing nothing but the pin script.
: > "$tmp/empty_order.txt"
if bash tasks/test/verify_symbol_order_v3.sh "$tmp/empty_order.txt" 2>/dev/null; then
  echo "FAIL: empty ordered list passed vacuously"; exit 1
fi
echo "ok: empty ordered list rejected"

# Whitespace-only is empty too — the guard must not be fooled by a stray blank line.
printf '\n  \n' > "$tmp/blank_order.txt"
if bash tasks/test/verify_symbol_order_v3.sh "$tmp/blank_order.txt" 2>/dev/null; then
  echo "FAIL: whitespace-only ordered list passed vacuously"; exit 1
fi
echo "ok: whitespace-only ordered list rejected"

# An UNREADABLE ALLOWLIST must FAIL the gate. awk's `getline < file` returns <= 0
# both at EOF and on error, so an unguarded read loop silently yields an empty
# allowlist. That is fail-safe today only because the committed allowlist has no
# active entries; the moment one is added, a path typo would resurrect the very
# false positive the entry exists to suppress — and it would surface inside
# `mise run build`, i.e. inside a release.
if SYMBOL_ORDER_ALLOWLIST="$tmp/no-such-allowlist.txt" \
   bash tasks/test/verify_symbol_order_v3.sh "$tmp/good_order.txt" 2>/dev/null; then
  echo "FAIL: unreadable allowlist silently accepted"; exit 1
fi
echo "ok: unreadable allowlist rejected"

# The gate is STRICTER than PostgreSQL, deliberately, and the allowlist is the
# escape hatch. A `LANGUAGE plpgsql` body resolves its callees at execution time,
# so Postgres accepts a forward reference that this gate rejects. Pin both halves:
# the rejection (so the strictness is a choice, not an accident) and the release
# valve (so a real forward reference has a documented, reviewable way out).
printf 'CREATE FUNCTION eql_v3.caller() RETURNS int LANGUAGE plpgsql AS $$ BEGIN RETURN eql_v3.callee(); END; $$;\n' > "$tmp/caller.sql"
printf 'CREATE FUNCTION eql_v3.callee() RETURNS int LANGUAGE sql AS $$ SELECT 1 $$;\n' > "$tmp/callee.sql"
printf '%s\n%s\n' "$tmp/caller.sql" "$tmp/callee.sql" > "$tmp/plpgsql_order.txt"
if bash tasks/test/verify_symbol_order_v3.sh "$tmp/plpgsql_order.txt" 2>/dev/null; then
  echo "FAIL: plpgsql forward reference accepted — the gate's strictness is unpinned"; exit 1
fi
echo "ok: plpgsql forward reference rejected (documented strictness)"

printf 'eql_v3.callee  # forward-referenced from a plpgsql body\n' > "$tmp/allow.txt"
SYMBOL_ORDER_ALLOWLIST="$tmp/allow.txt" \
  bash tasks/test/verify_symbol_order_v3.sh "$tmp/plpgsql_order.txt" \
  || { echo "FAIL: allowlist did not release the plpgsql forward reference"; exit 1; }
echo "ok: allowlist releases a plpgsql forward reference"

# ---------------------------------------------------------------------------
# Overload resolution: the gate cannot tell overloads apart (a reference carries
# no argument types), so it must SAY so rather than report a bare OK. On the real
# surface eql_v3.eq has 186 definitions spanning files #55..#242 — keying on
# schema+name and keeping the MIN index means every eq reference after #55 passes
# for free. These three cases pin the boundary of what is still decidable.
# ---------------------------------------------------------------------------

# (a) Overloaded, and a later overload is still ahead of the reference: NOT
# decidable. Must pass (it is a structural limit, not rot) but must report the
# name as unresolvable instead of claiming a clean check.
printf 'CREATE FUNCTION eql_v3.eq(a public.integer_eq, b public.integer_eq) RETURNS boolean ...\n' > "$tmp/eq_int.sql"
printf 'CREATE OPERATOR = ( FUNCTION = eql_v3.eq, LEFTARG = public.text_eq, RIGHTARG = public.text_eq );\n' > "$tmp/eq_use.sql"
printf 'CREATE FUNCTION eql_v3.eq(a public.text_eq, b public.text_eq) RETURNS boolean ...\n' > "$tmp/eq_text.sql"
printf '%s\n%s\n%s\n' "$tmp/eq_int.sql" "$tmp/eq_use.sql" "$tmp/eq_text.sql" > "$tmp/overload_order.txt"
out="$(bash tasks/test/verify_symbol_order_v3.sh "$tmp/overload_order.txt")" \
  || { echo "FAIL: ambiguous overload treated as an error"; exit 1; }
case "$out" in
  *"unresolvable"*) echo "ok: ambiguous overload reported as unresolvable, not a bare OK" ;;
  *) echo "FAIL: overload blindness went unreported: [$out]"; exit 1 ;;
esac

# (b) The reference precedes EVERY definition of the name. Decidable without
# knowing which overload was meant — it is wrong either way. Pins that the
# ambiguity bail-out did not swallow this existing catch.
printf '%s\n%s\n%s\n' "$tmp/eq_use.sql" "$tmp/eq_int.sql" "$tmp/eq_text.sql" > "$tmp/overload_bad.txt"
if bash tasks/test/verify_symbol_order_v3.sh "$tmp/overload_bad.txt" 2>/dev/null; then
  echo "FAIL: reference before ALL overloads accepted — the preserved catch is gone"; exit 1
fi
echo "ok: reference before every overload still rejected"

# (c) Overloaded but every definition sits in ONE file ordered before the use, so
# the answer is sound whichever overload was meant — must stay fully checked, not
# written off as unresolvable. Mirrors the real eql_v3.ste_vec_contains and the
# CREATE OPERATOR FAMILY + CLASS pair sharing eql_v3_internal.ore_cllw_ops.
printf 'CREATE FUNCTION eql_v3.selector(a public.jsonb_entry) RETURNS text ...\nCREATE FUNCTION eql_v3.selector(a public.jsonb_query) RETURNS text ...\n' > "$tmp/sel_defs.sql"
printf 'SELECT eql_v3.selector(x);\n' > "$tmp/sel_use.sql"
printf '%s\n%s\n' "$tmp/sel_defs.sql" "$tmp/sel_use.sql" > "$tmp/samefile_order.txt"
out="$(bash tasks/test/verify_symbol_order_v3.sh "$tmp/samefile_order.txt")" \
  || { echo "FAIL: same-file overloads rejected"; exit 1; }
case "$out" in
  *"unresolvable"*) echo "FAIL: same-file overloads written off as unresolvable: [$out]"; exit 1 ;;
  *) echo "ok: overloads all defined before use stay soundly checked" ;;
esac

echo "symbol-order self-test passed"
