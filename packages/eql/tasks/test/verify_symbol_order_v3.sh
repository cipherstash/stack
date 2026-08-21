#!/usr/bin/env bash
#MISE description="Cross-check that every eql_v3/eql_v3_internal/public-domain symbol referenced in a file is defined by a file ordered earlier"
#
# This gate is deliberately STRICTER than PostgreSQL, in one direction: it treats
# every owned-schema token as a reference, wherever it appears, including inside a
# function body. PostgreSQL resolves a `LANGUAGE plpgsql` body's callees at
# execution time, so it accepts a plpgsql function that forward-references a
# function defined later in the installer. This gate rejects it.
#
# That is the intended trade: a define-before-use order is what makes a
# single-transaction install of the concatenated monolith safe for `LANGUAGE sql`
# bodies (which Postgres DOES resolve at CREATE time), and the checker cannot tell
# the two languages apart from a line-oriented scan. The cost is that a genuine
# plpgsql forward reference — mutual recursion, say — needs an entry in
# tasks/test/symbol_order_allowlist.txt.
#
# Scope: OVERLOADS ARE NOT RESOLVED HERE. Definitions and references are both
# keyed by schema+name with no argument list, because a reference carries no types
# to key on: a call site is a bare `eql_v3.eq(a, b)`, and CREATE OPERATOR supplies
# LEFTARG/RIGHTARG on other lines. Resolving that needs a type checker, not a
# line-oriented scan. eql_v3.eq has 186 definitions across files #55..#242, so for
# the hot names this gate decides almost nothing — it reports the count of such
# names rather than implying it checked them.
#
# That is not a hole in coverage, because Postgres already resolves overloads
# exactly, at CREATE time, when the concatenated monolith is installed:
#
#     mise run test:clean_install_v3
#
# which runs in CI on every relevant PR across PG 14-17, needs no CipherStash
# credentials, and is not skipped on forks. Verified: swapping text_eq_operators
# ahead of text_eq_functions passes THIS gate and fails that one with
# `function eql_v3.eq(text_eq, text_eq) does not exist`.
#
# So this gate is the DB-free pre-flight; the clean install is the authority. What
# this gate uniquely adds is (1) singleton symbols — hmac_256, the eql_v3.query_*
# domains, the opclasses, version() — where name identifies the object and the
# check is sound, and (2) the plpgsql strictness described above, which the clean
# install cannot catch because Postgres defers those bodies to execution time.
#
# Scope: this checks CROSS-FILE order only. A reference is compared against the
# index of the file that defines it (`defined[tok] > i`), so a symbol referenced
# in the same file that defines it always passes, regardless of line order within
# that file. That is deliberate: the conditional SEM opclass files define an
# operator class and then name it in a RAISE NOTICE in the same file, and several
# generated files reference a domain they just created. Enforcing intra-file order
# would flag all of them and push real definitions onto the allowlist, which is
# the opposite of what the allowlist is for. Postgres resolves within a single
# file's statements in statement order anyway, and that order comes from the
# renderers, not from the install order this gate exists to check.
#
# Note this runs inside `mise run build`, so it gates the release build, not just
# CI. A false positive blocks a release until allowlisted. Both the rejection and
# the allowlist escape hatch are pinned by tasks/test/symbol_order_selftest.sh.
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

ORDERED="${1:-src/deps-ordered-v3.txt}"
# Overridable so the self-test can exercise the missing-allowlist path without
# disturbing the committed one.
ALLOW="${SYMBOL_ORDER_ALLOWLIST:-tasks/test/symbol_order_allowlist.txt}"
test -f "$ORDERED" || { echo "ERROR: ordered file $ORDERED missing (run mise run build)" >&2; exit 2; }
# Refuse a zero-file run. Without this the checker reports "OK (0 files)" and exits
# 0 on an empty order — a pass that means "I checked nothing", indistinguishable in
# CI from "I checked everything". An emptied surface would sail through here, and
# through the self-containment file gate, into an installer holding only the pin
# script. (A short-but-non-empty order is caught by verify_installer_complete.sh;
# this gate only has to refuse the vacuous case, since the self-test drives it with
# one- and two-file lists.)
grep -qv '^[[:space:]]*$' "$ORDERED" || { echo "ERROR: ordered file $ORDERED is empty — refusing a vacuous check" >&2; exit 2; }
# awk's `getline < file` cannot distinguish EOF from an unreadable file, so an
# unguarded read loop turns a bad ALLOW path into a silently empty allowlist.
# Today that fails safe (nothing to suppress), but this gate runs inside
# `mise run build` — including the release build — so a typo in a future entry
# would resurrect the false positive it was added to suppress, at release time.
test -r "$ALLOW" || { echo "ERROR: allowlist $ALLOW missing or unreadable" >&2; exit 2; }

awk -v allowfile="$ALLOW" '
  BEGIN {
    idx = 0
    while ((getline a < allowfile) > 0) {
      sub(/#.*/, "", a); gsub(/[ \t]+/, "", a)
      if (a != "") allow[a] = 1
    }
  }
  # $0 here is a path from the ordered list.
  {
    idx++
    file = $0
    # Fail loudly on an UNREADABLE path rather than silently treating it as an
    # empty (zero-definition) file: getline returns -1 on error but 0 at EOF for
    # a genuinely empty file, so only -1 is a fault. This guards both passes — a
    # file flagged here sets bad=1, and the END block exits non-zero.
    if ((getline probe < file) < 0) {
      printf("ERROR: cannot read %s (listed in the ordered file)\n", file) > "/dev/stderr"
      bad = 1
    }
    close(file)
    # First pass over the file: record DEFINITIONS with this index (min index kept).
    while ((getline line < file) > 0) {
      # Strip trailing line comments so prose/doxygen never counts as code.
      sub(/--.*/, "", line)
      # CREATE [OR REPLACE] FUNCTION|AGGREGATE eql_v3(_internal).<name|"op">
      if (match(line, /CREATE[ \t]+(OR[ \t]+REPLACE[ \t]+)?(FUNCTION|AGGREGATE)[ \t]+(eql_v3_internal|eql_v3)\.("[^"]+"|[a-z0-9_]+)/)) {
        s = substr(line, RSTART, RLENGTH); sub(/.*(eql_v3_internal|eql_v3)\./, "", s)
        schema = (index(substr(line,RSTART,RLENGTH), "eql_v3_internal.") ? "eql_v3_internal." : "eql_v3.")
        key = schema s
        record_def(key, idx)
      }
      # CREATE DOMAIN (eql_v3_internal|eql_v3|public).<name>. All three schemas: the
      # SEM index-term types split across DDL forms — hmac_256/ope_cllw/bloom_filter
      # are `CREATE DOMAIN eql_v3_internal.<name>` (over text/bytea/smallint[]),
      # NOT `CREATE TYPE`. Capturing only `public.` here would leave the three
      # most-referenced foundational types (~165 refs) reporting "defined
      # nowhere" — a real gap, not an allowlist case. `eql_v3.` owns the
      # query-operand domains (`eql_v3.query_<T>_<cap>`, `eql_v3.query_json`),
      # which live outside `public` because a query operand is never a column
      # type: omitting the schema here leaves every one of them reporting
      # "defined nowhere". Only `public.` domains feed isdomain[] (that gates
      # which `public.*` REFERENCES are checked).
      # Test eql_v3_internal FIRST in both the alternation and the arms below, so
      # the `eql_v3` prefix cannot shadow it.
      if (match(line, /CREATE[ \t]+DOMAIN[ \t]+(eql_v3_internal|eql_v3|public)\.[a-z0-9_]+/)) {
        seg = substr(line, RSTART, RLENGTH)
        if (seg ~ /eql_v3_internal\./) { sub(/.*eql_v3_internal\./, "", seg); key = "eql_v3_internal." seg }
        else if (seg ~ /eql_v3\./)     { sub(/.*eql_v3\./, "", seg);          key = "eql_v3." seg }
        else                          { sub(/.*public\./, "", seg);          key = "public." seg; isdomain[seg] = 1 }
        record_def(key, idx)
      }
      # CREATE TYPE eql_v3_internal.<name> (the composite SEM types: ore_block_256, ore_cllw)
      if (match(line, /CREATE[ \t]+TYPE[ \t]+eql_v3_internal\.[a-z0-9_]+/)) {
        s = substr(line, RSTART, RLENGTH); sub(/.*eql_v3_internal\./, "", s)
        key = "eql_v3_internal." s; record_def(key, idx)
      }
      # CREATE OPERATOR CLASS|FAMILY (eql_v3_internal|eql_v3).<name>. The conditional
      # SEM ordered-index opclasses (ore_block_256_operator_class/_family,
      # ore_cllw_ops), created via EXECUTE / plpgsql for superusers. Each is fully
      # self-contained in its own operator_class.sql — the only other mentions are
      # RAISE NOTICE string-literal prose in the SAME file — so recognising this
      # definition form (like CREATE TYPE/DOMAIN above) keeps them from reading as
      # "defined nowhere", while still catching a genuine cross-file mis-order.
      if (match(line, /CREATE[ \t]+OPERATOR[ \t]+(CLASS|FAMILY)[ \t]+(eql_v3_internal|eql_v3)\.[a-z0-9_]+/)) {
        s = substr(line, RSTART, RLENGTH)
        schema = (index(s, "eql_v3_internal.") ? "eql_v3_internal." : "eql_v3.")
        sub(/.*(eql_v3_internal|eql_v3)\./, "", s)
        key = schema s; record_def(key, idx)
      }
    }
    close(file)
    order[idx] = file
  }
  END {
    # Second pass: for every file, collect REFERENCES (code only) and check them.
    for (i = 1; i <= idx; i++) {
      file = order[i]
      while ((getline line < file) > 0) {
        sub(/--.*/, "", line)               # drop comments
        rest = line
        # eql_v3.<name> and eql_v3_internal.<name|"op">
        while (match(rest, /(eql_v3_internal|eql_v3)\.("[^"]+"|[a-z0-9_]+)/)) {
          tok = substr(rest, RSTART, RLENGTH)
          rest = substr(rest, RSTART + RLENGTH)
          check(tok, i, file)
        }
        # public.<domain> — ONLY names we saw defined as a domain (avoids public tables/builtins).
        rest = line
        while (match(rest, /public\.[a-z0-9_]+/)) {
          tok = substr(rest, RSTART, RLENGTH); rest = substr(rest, RSTART + RLENGTH)
          name = tok; sub(/public\./, "", name)
          if (name in isdomain) check(tok, i, file)
        }
      }
      close(file)
    }
    if (bad) { print "symbol-order cross-check FAILED" > "/dev/stderr"; exit 1 }
    # Report the unresolvable set rather than folding it into a bare "OK". A pass
    # that says "OK (244 files)" while ~27 overloaded names went unchecked is the
    # same lie as the "OK (0 files)" vacuous pass refused above: indistinguishable
    # from having actually checked them.
    n_unchecked = 0
    for (t in unchecked) n_unchecked++
    if (n_unchecked > 0) {
      printf("symbol-order cross-check OK (%d files; %d overloaded name(s) unresolvable here — \
overload define-before-use is proven exactly by: mise run test:clean_install_v3)\n", idx, n_unchecked)
    } else {
      print "symbol-order cross-check OK (" idx " files)"
    }
  }
  # Record a definition of `key` at file index `i`. Tracks the min index (the
  # ordering check), the max, and the count — the latter two are what let check()
  # tell "resolvable" from "overloaded, and I cannot know which one".
  function record_def(key, i) {
    if (!(key in defined) || i < defined[key]) defined[key] = i
    if (!(key in defmax)  || i > defmax[key])  defmax[key]  = i
    defcount[key]++
  }
  function check(tok, i, file) {
    if (tok in allow) return
    if (!(tok in defined)) {
      # Referenced owned-schema symbol never defined anywhere: a real hole.
      printf("ERROR: %s references %s which is defined nowhere in the installer\n", file, tok) > "/dev/stderr"
      bad = 1; return
    }
    # Reference precedes even the EARLIEST definition of this name. Wrong whichever
    # overload was meant, so it is decidable without knowing which one. Checked
    # before the ambiguity bail-out below — dropping this would lose a real catch.
    if (defined[tok] > i) {
      printf("ERROR: %s references %s defined later (at #%d, used at #%d)\n", file, tok, defined[tok], i) > "/dev/stderr"
      bad = 1
      return
    }
    # Overloaded, and at least one overload is still ahead of this reference: the
    # right one may or may not be defined yet, and a line-oriented scan cannot say
    # which. Bare call sites (`eql_v3.eq(a, b)`) carry no types, and CREATE OPERATOR
    # supplies them via LEFTARG/RIGHTARG on other lines. Record, do not guess.
    #
    # When defmax <= i every overload already precedes the reference, so the answer
    # is sound regardless of which one was meant — that keeps the same-file overload
    # pairs (eql_v3.ste_vec_contains, eql_v3_internal.compare_ore_block_256_terms)
    # fully checked instead of written off.
    if (defcount[tok] > 1 && defmax[tok] > i) {
      unchecked[tok] = 1
      return
    }
  }
' "$ORDERED"
