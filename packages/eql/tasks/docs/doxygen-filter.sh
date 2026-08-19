#!/usr/bin/env bash
#MISE description="Doxygen input filter for SQL files"
set -euo pipefail

# Doxygen always calls an INPUT_FILTER with exactly one filename. Guard it so a
# stray invocation fails fast instead of `awk` blocking on stdin and hanging the
# docs job.
if [ "$#" -ne 1 ]; then
  echo "usage: $(basename "$0") <file.sql>" >&2
  exit 2
fi

# Prepares SQL for Doxygen's C++ parser. Four transforms:
#
#  1. Omit blocks marked `@cond deprecated_compatibility`. These functions
#     remain callable for backwards compatibility but must not appear in the
#     generated function reference or source browser.
#  2. `--!` doc comments -> `//!` so Doxygen sees them.
#  3. Strip dollar-quoted function bodies (`$$ ... $$`), leaving just the
#     declaration and its trailing clauses. Doxygen parses SQL heuristically as
#     C++, and body SQL derails it: a `::type` cast reads as C++ scope
#     resolution and drops the whole enclosing CREATE FUNCTION memberdef (this
#     silently lost jsonb_path_query and ~hundreds of generated extractor
#     overloads), while keywords/calls in bodies (`SELECT`, `RETURN NEXT`,
#     `array_length(...)`) get mis-parsed as spurious functions. Bodies carry no
#     documentation, so removing them is lossless for the generated reference
#     and leaves Doxygen only clean `CREATE FUNCTION name(args) RETURNS ...`
#     declarations to read. Only bare `$$` quoting is used in this codebase.
#  4. Strip CREATE AGGREGATE definition bodies, for the same reason and with the
#     same losslessness: `sfunc`/`stype`/`combinefunc`/`parallel` carry no
#     documentation. The trailing `( ... )` is a SECOND parenthesised group
#     after the signature, and C++ has no such form, so Doxygen misreads the
#     whole declaration — differently depending on the argument type:
#
#       CREATE AGGREGATE eql_v3.grouped_value(jsonb) (...)
#         -> a function NAMED `jsonb`. `eql_v3.grouped_value` is absorbed into
#            the return type and disappears from the docs entirely.
#       CREATE AGGREGATE eql_v3.min(public.eql_v3_bigint_ord) (...)
#         -> named `min`, but the argument list is truncated mid-body to
#            `(public.eql_v3_bigint_ord)(sfunc`.
#
#     Reducing each to a single `CREATE AGGREGATE name(argtype);` declaration
#     recovers the name in both cases and leaves a clean argument list.
awk '
  /^--![[:space:]]+@cond[[:space:]]+deprecated_compatibility[[:space:]]*$/ {
    inhidden = 1
    print ""
    next
  }
  inhidden && /^--![[:space:]]+@endcond[[:space:]]*$/ {
    inhidden = 0
    print ""
    next
  }
  inhidden { print ""; next }
  /^--!/ { print "//!" substr($0, 4); next }
  # Emit the signature up to its balanced closing paren, then skip the body.
  !inagg && /^[[:space:]]*CREATE[[:space:]]+AGGREGATE/ {
    depth = 0; sig = ""; rest = ""; closed = 0
    for (i = 1; i <= length($0); i++) {
      ch = substr($0, i, 1)
      if (closed) { rest = rest ch; continue }
      sig = sig ch
      if (ch == "(") depth++
      else if (ch == ")" && --depth == 0) closed = 1
    }
    # Only when the signature balances on this line (true for every aggregate
    # in this codebase); otherwise fall through to the generic handling.
    if (closed) {
      print sig ";"
      # Skip the body only if the statement does not also end on this line, so
      # a single-line `CREATE AGGREGATE x(y) (sfunc = z);` cannot leave the
      # skip latched and swallow the declarations that follow it.
      inagg = (index(rest, ";") == 0)
      next
    }
  }
  # A blank line per skipped body row, never nothing: Doxygen reports positions
  # in the FILTERED stream, so dropping the rows outright shifts every symbol
  # after an aggregate (max_sfunc at source line 41 was reported as 36). The
  # dollar-quoted body stripper below keeps the 1:1 line mapping the same way.
  inagg { print ""; if (index($0, ");")) inagg = 0; next }
  {
    out = ""
    s = $0
    while (length(s) > 0) {
      p = index(s, "$$")
      if (inbody) {
        if (p == 0) { s = ""; break }        # whole remainder is body: drop
        s = substr(s, p + 2)                  # resume after the closing $$
        inbody = 0
      } else {
        if (p == 0) { out = out s; break }    # no body marker: keep as-is
        out = out substr(s, 1, p - 1)         # keep code before opening $$
        s = substr(s, p + 2)
        inbody = 1
      }
    }
    # Regular SQL `--` comments read as C++ code to Doxygen (e.g.
    # `-- per-entry overloads (...)` mints a phantom `overloads(...)` function),
    # so neutralize them to C++ line comments on the (body-stripped) code.
    gsub(/--/, "//", out)
    print out
  }
' "$1"
