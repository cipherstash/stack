#!/usr/bin/env bash
#MISE description="Run Supabase splinter database linter against installed EQL"
#USAGE flag "--postgres <version>" help="PostgreSQL version (used for container check)" default="17" {
#USAGE   choices "14" "15" "16" "17"
#USAGE }
#USAGE flag "--port <port>" help="Postgres port" default="7432"
#USAGE flag "--user <user>" help="Postgres user" default="cipherstash"
#USAGE flag "--db <db>" help="Postgres database" default="cipherstash"

set -euo pipefail

# Scope: only findings in EQL-owned schemas are gated.
EQL_OWNED_SCHEMAS="('eql_v3', 'eql_v3_internal')"

# Pinned to splinter main as of 2026-04-27. Bump intentionally.
SPLINTER_SHA="55db5b1f28e58d816f7d9136eed87eabcd95868d"
SPLINTER_URL="https://raw.githubusercontent.com/supabase/splinter/${SPLINTER_SHA}/splinter.sql"

PG_PORT="${usage_port:-7432}"
PG_USER="${usage_user:-cipherstash}"
PG_DB="${usage_db:-cipherstash}"
PG_PASSWORD="${POSTGRES_PASSWORD:-password}"

PSQL=(psql -U "$PG_USER" -d "$PG_DB" -h localhost -p "$PG_PORT" -v ON_ERROR_STOP=1)
export PGPASSWORD="$PG_PASSWORD"

work_dir="$(mktemp -d)"
trap 'rm -rf "$work_dir"' EXIT

splinter_sql="$work_dir/splinter.sql"
all_findings_tsv="$work_dir/all_findings.tsv"
findings_tsv="$work_dir/findings.tsv"
allowlisted_tsv="$work_dir/allowlisted.tsv"
unused_allow_tsv="$work_dir/unused_allow.tsv"
summary_by_rule="$work_dir/by_rule.tsv"

echo "Fetching splinter@${SPLINTER_SHA}..."
curl -sSL --fail -o "$splinter_sql" "$SPLINTER_URL"

# Splinter calls has_table_privilege('anon', ...) etc., which errors if the role
# is missing. Create empty stand-ins so the lints can run on vanilla Postgres.
"${PSQL[@]}" -q <<'SQL'
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'anon') THEN
    CREATE ROLE anon NOLOGIN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN
    CREATE ROLE authenticated NOLOGIN;
  END IF;
END $$;
SQL

# Allowlist: each finding splinter emits is allowed only if rule + metadata
# (schema, name, type) match an entry below. Each entry must be justified.
#
# Format: TSV "rule\tschema\tname\ttype\treason" — kept as a heredoc so the
# justification lives next to the entry it covers. Keys are matched verbatim.
cat > "$work_dir/allowlist.tsv" <<'ALLOW'
# Encrypted-domain user types live in public; their wrapper functions live in the eql_v3 schema (the integer family and
# future scalar domains). Their inlinable extractors and comparison wrappers
# must stay unpinned for functional-index matching; splinter matches by
# (schema, name, type), so
# they need their own rows. The plpgsql blockers are pinned by
# tasks/pin_search_path_v3.sql and do not surface here.
function_search_path_mutable	eql_v3	eq_term	function	HMAC equality term extractor for the public *_eq domains: returns eql_v3.hmac_256. Must inline so `eql_v3.eq_term(col)` folds into the calling query and matches the functional hash/btree index built on the same expression. SET search_path would disable SQL function inlining (see PostgreSQL inline_function).
function_search_path_mutable	eql_v3	ord_term_ore	function	ORE-block order term extractor for the public *_ord_ore domains: returns eql_v3_internal.ore_block_256 (carrying the main DEFAULT btree opclass). Used inside the inlinable comparison wrappers and as the functional-index expression USING btree (eql_v3.ord_term_ore(col)); must inline. One overload per *_ord_ore domain (public.eql_v3_integer_ord_ore, eql_v3.query_integer_ord_ore).
function_search_path_mutable	eql_v3	match_term	function	Bloom-filter match term extractor for the public *_match domains: returns eql_v3.bloom_filter. Used inside the inlinable @@ fuzzy-match wrapper (eql_v3.matches) and as the functional-index expression USING gin (eql_v3.match_term(col)); must inline so the GIN index engages. SET search_path would disable SQL function inlining.
function_search_path_mutable	eql_v3	matches	function	Bloom fuzzy-match (@@) comparison wrapper on the public *_match domains — the public function-form equivalent of @@ (callable without the operator on Supabase/PostgREST); the CREATE OPERATOR also lives in eql_v3. Inlines to `match_term(a) @> match_term(b)` (bloom array-containment on the extracted terms); must reach the functional GIN index on eql_v3.match_term(col) for bloom-filter match to engage Bitmap Index Scan. (Renamed from eql_v3.contains; @>/<@ are containment, not the match, and now raise on the *_match domains.)
function_search_path_mutable	eql_v3	eq	function	Equality comparison wrapper on the public scalar domains — the public function-form equivalent of = (callable without the operator). Inlines to `eq_term(a) = eq_term(b)`; must reach the functional index on eql_v3.eq_term(col) for bare-form equality to engage Index Scan. The jsonb-entry overload is a pinned plpgsql blocker and does not surface here.
function_search_path_mutable	eql_v3	neq	function	Inequality comparison wrapper on the public domains — public function-form equivalent of <>. Same rationale as eql_v3.eq.
function_search_path_mutable	eql_v3	lt	function	Less-than comparison wrapper on the public ordered domains — public function-form equivalent of <. Inlines to `ord_term(a) < ord_term(b)`; must reach the functional btree index on eql_v3.ord_term(col) for range queries to engage Index Scan. Also covers the jsonb_entry lt wrapper (via ord_term → ope_cllw), which shares the same (schema, name, type) key.
function_search_path_mutable	eql_v3	lte	function	Less-than-or-equal comparison wrapper on the public ordered domains — public function-form equivalent of <=. Same rationale as eql_v3.lt.
function_search_path_mutable	eql_v3	gt	function	Greater-than comparison wrapper on the public ordered domains — public function-form equivalent of >. Same rationale as eql_v3.lt.
function_search_path_mutable	eql_v3	gte	function	Greater-than-or-equal comparison wrapper on the public ordered domains — public function-form equivalent of >=. Same rationale as eql_v3.lt.
function_search_path_mutable	eql_v3	min	function	Per-domain MIN aggregate on the public ordered domains (splinter labels aggregates type=function): ALTER AGGREGATE has no SET configuration_parameter syntax, and ALTER ROUTINE/FUNCTION reject aggregates. The aggregate's SFUNC (now eql_v3_internal.min_sfunc) carries a pinned search_path.
function_search_path_mutable	eql_v3	max	function	Per-domain MAX aggregate on the public ordered domains. Same as eql_v3.min.
function_search_path_mutable	eql_v3	grouped_value	function	Schema-generic grouped_value aggregate on eql_v3 (splinter labels aggregates type=function): returns a representative encrypted value per group so an encrypted column can be projected while grouping by its equality term. ALTER AGGREGATE has no SET configuration_parameter syntax, and ALTER ROUTINE/FUNCTION reject aggregates; the aggregate's SFUNC (eql_v3_internal.grouped_value_sfunc) carries a pinned search_path. Same as eql_v3.min / eql_v3.max.
function_search_path_mutable	eql_v3_internal	ore_block_256_eq	function	Inner comparator for the eql_v3_internal ore_block_256 type's `=` operator (self-contained SEM fork). The eql_v3 *_ord_ore comparison wrappers inline to `ord_term_ore(a) op ord_term_ore(b)`; the planner only carries that through to the functional ORE index if this inner function is also inlinable (no SET, IMMUTABLE).
function_search_path_mutable	eql_v3_internal	ore_block_256_neq	function	Inner comparator for the eql_v3_internal ore_block_256 `<>` operator. Same rationale as eql_v3_internal.ore_block_256_eq.
function_search_path_mutable	eql_v3_internal	ore_block_256_lt	function	Inner comparator for the eql_v3_internal ore_block_256 `<` operator. Same rationale as eql_v3_internal.ore_block_256_eq.
function_search_path_mutable	eql_v3_internal	ore_block_256_lte	function	Inner comparator for the eql_v3_internal ore_block_256 `<=` operator. Same rationale as eql_v3_internal.ore_block_256_eq.
function_search_path_mutable	eql_v3_internal	ore_block_256_gt	function	Inner comparator for the eql_v3_internal ore_block_256 `>` operator. Same rationale as eql_v3_internal.ore_block_256_eq.
function_search_path_mutable	eql_v3_internal	ore_block_256_gte	function	Inner comparator for the eql_v3_internal ore_block_256 `>=` operator. Same rationale as eql_v3_internal.ore_block_256_eq.
function_search_path_mutable	eql_v3_internal	hmac_256	function	HMAC equality extractor for the eql_v3 SEM fork (now in eql_v3_internal): inlinable SQL (jsonb) constructor used inside eql_v3.eq_term. Must inline so the functional hash/btree index on eql_v3.eq_term(col) engages.
function_search_path_mutable	eql_v3_internal	bloom_filter	function	Bloom-filter match extractor for the eql_v3 SEM fork (now in eql_v3_internal): inlinable SQL (jsonb) constructor used inside eql_v3.match_term. Must inline so the functional GIN index on eql_v3.match_term(col) engages. Mirrors eql_v3_internal.hmac_256.
function_search_path_mutable	eql_v3_internal	jsonb_array_to_bytea_array	function	Hand-written jsonb→bytea[] helper for the eql_v3 SEM fork (now in eql_v3_internal): inlinable SQL (no SET, IMMUTABLE). Reached per-encrypted-value through eql_v3_internal.ore_block_256; must inline so the planner can fold it into the calling query. Pinned by neither the structural skip (it takes bare jsonb, not a jsonb-backed domain) nor an inline-critical OID clause — it carries the documented `eql-inline-critical` COMMENT marker that tasks/pin_search_path_v3.sql honours.
function_search_path_mutable	eql_v3_internal	jsonb_array_to_ore_block_256	function	Hand-written jsonb→ore_block composite helper for the eql_v3 SEM fork (now in eql_v3_internal): inlinable SQL (no SET, IMMUTABLE). Same rationale as eql_v3_internal.jsonb_array_to_bytea_array — reached per-encrypted-value through eql_v3_internal.ore_block_256, carries the `eql-inline-critical` COMMENT marker.
function_search_path_mutable	eql_v3	ord_term	function	CLLW-OPE order term extractor for the public *_ord / *_ord_ope domains: returns eql_v3_internal.ope_cllw, a domain over bytea that inherits the native bytea comparison operators and DEFAULT btree opclass. Used inside the inlinable comparison wrappers and as the functional-index expression USING btree (eql_v3.ord_term(col)); must inline so the whole chain folds to native bytea comparisons the index can match. OPE backs the default _ord domain, so it takes the unqualified extractor name; block-ORE takes ord_term_ore. One overload per *_ord / *_ord_ope domain.
function_search_path_mutable	eql_v3_internal	ope_cllw	function	CLLW-OPE extractor for the eql_v3 SEM fork (now in eql_v3_internal): inlinable SQL (jsonb) constructor used inside eql_v3.ord_term, hex-decoding `op` to the bytea-backed eql_v3_internal.ope_cllw domain. The domain inherits bytea's native comparison operators and btree opclass, so the WHOLE comparison chain (wrapper -> ord_term -> this) is inlinable SQL and the functional btree index on eql_v3.ord_term(col) engages structurally — the hmac_256 pattern. Carries the `eql-inline-critical` COMMENT marker (bare jsonb arg escapes the structural domain-arg skip).
# Encrypted-JSONB document surface (src/v3/json): the hand-written
# public.eql_v3_json_search / json_entry / query_json domains and their selector/extractor/operator
# functions. Inlinable for functional-index matching; left unpinned by
# tasks/pin_search_path_v3.sql via either
# the structural jsonb-domain-arg skip or the documented `eql-inline-critical`
# COMMENT marker (the plpgsql blockers in blockers.sql are pinned and do not
# surface). Splinter matches by (schema, name, type), so they need their own rows.
function_search_path_mutable	eql_v3	->	function	Typed sv-element selector lookup on the eql_v3 encrypted-JSONB surface: inlinable SQL over a public.eql_v3_json_search domain arg so `col -> '<sel>'` folds into the calling query, preserving functional-index matching for ord_term on the extracted entry. Left unpinned by the structural domain-arg skip in pin_search_path_v3.sql. Two overloads: (json_search, text), (json_search, int).
function_search_path_mutable	eql_v3	->>	function	Text sv-element selector lookup on the eql_v3 encrypted-JSONB surface: inlinable SQL over a public.eql_v3_json domain arg, text-returning counterpart to eql_v3.->. Structural domain-arg skip. Two overloads: (json, text), (json, int).
function_search_path_mutable	eql_v3	@>	function	Containment (@>) operator wrapper on the eql_v3 encrypted-JSONB surface: inlinable SQL so the planner can match the functional GIN index on eql_v3.to_ste_vec_query(col)::jsonb. Structural domain-arg skip (public.eql_v3_json). Three overloads.
function_search_path_mutable	eql_v3	<@	function	Contained-by (<@) operator wrapper on the eql_v3 encrypted-JSONB surface: same rationale as eql_v3.@>. Three overloads.
function_search_path_mutable	eql_v3	selector	function	STE-vec entry selector extractor: typed (public.eql_v3_jsonb_entry) overload, inlinable so `eql_v3.selector(col -> 'sel')` folds into the calling query. Structural domain-arg skip. The (jsonb) overload is plpgsql with a pinned search_path and does not surface.
function_search_path_mutable	eql_v3	ope_term	function	STE-vec ordered-term extractor for public.eql_v3_jsonb_entry: inlinable so `eql_v3.ope_term(col -> 'sel')` folds into the calling range query and matches the functional btree index built on the same expression. SET search_path would disable SQL function inlining. The deprecated eq_term(json_entry) compatibility alias is pinned and does not surface.
function_search_path_mutable	eql_v3	to_ste_vec_query	function	Encrypted-JSONB query-document constructor (CAST WITH FUNCTION for eql_v3.query_jsonb): inlinable SQL over a public.eql_v3_json domain arg, structural domain-arg skip. Builds the ste_vec query value the @>/<@ wrappers compare against; must inline to fold into the calling query.
function_search_path_mutable	eql_v3	jsonb_document_contains	function	Typed encrypted-JSONB document containment engine backing the public.eql_v3_json_search @>/<@ operators: the inlinable SQL (public.eql_v3_json_search) overload folds to native jsonb containment over eql_v3.to_ste_vec_query(a/b)::jsonb, so the planner can match the functional GIN index on eql_v3.to_ste_vec_query(col)::jsonb. Structural domain-arg skip leaves this overload unpinned; the raw jsonb[] plpgsql overload has a fixed search_path and does not surface.
function_search_path_mutable	eql_v3	jsonb_array	function	ste_vec deterministic-field array extractor on the eql_v3 encrypted-JSONB surface: public inlinable SQL (raw jsonb arg) behind the documented functional GIN index expression eql_v3.jsonb_array(col). Takes bare jsonb, so it carries the documented `eql-inline-critical` COMMENT marker that pin_search_path_v3.sql honours rather than the structural skip.
function_search_path_mutable	eql_v3	jsonb_contains	function	Public GIN-inlining containment helper (function-form of @> over raw jsonb): unfolds to eql_v3.jsonb_array(a) @> eql_v3.jsonb_array(b). Carries the `eql-inline-critical` COMMENT marker.
function_search_path_mutable	eql_v3	jsonb_contained_by	function	Public GIN-inlining reverse-containment helper (function-form of <@ over raw jsonb): same as eql_v3.jsonb_contains.
function_search_path_mutable	eql_v3	jsonb_path_query	function	Field-level JSONB extractor on the eql_v3 encrypted-JSONB surface: inlinable SQL, carries the `eql-inline-critical` COMMENT marker so it stays unpinned and folds into the calling query.
function_search_path_mutable	eql_v3	jsonb_path_exists	function	Field-level JSONB EXISTS variant: same rationale as eql_v3.jsonb_path_query.
function_search_path_mutable	eql_v3	jsonb_path_query_first	function	Field-level JSONB LIMIT 1 variant: same rationale as eql_v3.jsonb_path_query.
function_search_path_mutable	eql_v3	meta_data	function	Encrypted-payload metadata extractor: inlinable SQL (raw jsonb arg), carries the `eql-inline-critical` COMMENT marker so it stays unpinned and folds into the calling query.
ALLOW

# Wrap splinter (a single bare SELECT expression) into a subquery we can
# aggregate from. Splinter starts with `set local search_path = ''` which only
# works inside a transaction, so wrap the whole thing in BEGIN/COMMIT.
splinter_body="$(tail -n +2 "$splinter_sql" | sed 's/;[[:space:]]*$//')"

# Pull all findings with their metadata, then split into allowlisted vs not.
# Scoped to EQL-owned schemas — see EQL_OWNED_SCHEMAS at the top of this file.
"${PSQL[@]}" -At -F $'\t' --quiet <<SQL > "$all_findings_tsv"
BEGIN;
SET LOCAL search_path = '';
SELECT
  name,
  level,
  detail,
  coalesce(metadata->>'schema', ''),
  coalesce(metadata->>'name', ''),
  coalesce(metadata->>'type', '')
FROM (${splinter_body}) splinter
WHERE coalesce(metadata->>'schema', '') IN ${EQL_OWNED_SCHEMAS}
ORDER BY level, name, detail;
COMMIT;
SQL

# Refuse to run with an empty allowlist. Without this guard, the awk
# discriminator below would still classify everything as allowlisted on
# an accidentally-empty file (e.g., a heredoc syntax error during edits)
# and the gate would silently pass any real findings.
if [[ ! -s "$work_dir/allowlist.tsv" ]]; then
  echo "splinter: allowlist.tsv is empty — refusing to run to avoid silently passing findings" >&2
  exit 2
fi

# Split: allowlisted entries match all of (rule, schema, name, type).
# Use FILENAME as the discriminator rather than NR == FNR so behavior is
# robust to either file being empty.
#
# The END block also emits allowlist rows that matched NO finding. An allowlist
# row is a standing waiver; once the function it covers is gone (e.g. the
# `ore_cllw` surface removed in the CLLW-OPE migration) the row is dead weight
# that would silently pre-waive a future re-introduction. Reporting unused rows
# enforces the same "registered but referenced by nothing" invariant the
# known-failures gate applies to suppressed tests. Comment (`#…`) and blank lines
# in the allowlist heredoc are skipped so they are never counted as unused rows.
awk -F'\t' \
  -v allowlist_file="$work_dir/allowlist.tsv" \
  -v allow_out="$allowlisted_tsv" \
  -v deny_out="$findings_tsv" \
  -v unused_out="$unused_allow_tsv" '
  FILENAME == allowlist_file {
    if (NF < 5 || $1 ~ /^[[:space:]]*#/) next
    key = $1 SUBSEP $2 SUBSEP $3 SUBSEP $4
    allow[key] = $5
    allow_desc[key] = $1 "\t" $2 "\t" $3 "\t" $4
    next
  }
  {
    key = $1 SUBSEP $4 SUBSEP $5 SUBSEP $6
    if (key in allow) {
      used[key] = 1
      print $0 "\t" allow[key] > allow_out
    } else {
      print $0 > deny_out
    }
  }
  END {
    for (k in allow)
      if (!(k in used))
        print allow_desc[k] > unused_out
  }
' "$work_dir/allowlist.tsv" "$all_findings_tsv"

# Touch in case awk didn't write a file (no findings, or no unused rows).
touch "$findings_tsv" "$allowlisted_tsv" "$unused_allow_tsv"

# Summary scoped to the same schemas the gate considers, so the count line
# matches what was actually checked.
"${PSQL[@]}" -At -F $'\t' --quiet <<SQL > "$summary_by_rule"
BEGIN;
SET LOCAL search_path = '';
SELECT level, name, count(*)
FROM (${splinter_body}) splinter
WHERE coalesce(metadata->>'schema', '') IN ${EQL_OWNED_SCHEMAS}
GROUP BY level, name
ORDER BY
  CASE level WHEN 'ERROR' THEN 0 WHEN 'WARN' THEN 1 WHEN 'INFO' THEN 2 ELSE 3 END,
  count(*) DESC;
COMMIT;
SQL

raw_total="$(wc -l < "$all_findings_tsv" | tr -d ' ')"
allowlisted_total="$(wc -l < "$allowlisted_tsv" | tr -d ' ')"
unused_total="$(wc -l < "$unused_allow_tsv" | tr -d ' ')"
total="$(wc -l < "$findings_tsv" | tr -d ' ')"
errors="$(awk -F'\t' '$2 == "ERROR"' "$findings_tsv" | wc -l | tr -d ' ')"
warns="$(awk -F'\t' '$2 == "WARN"' "$findings_tsv" | wc -l | tr -d ' ')"
infos="$(awk -F'\t' '$2 == "INFO"' "$findings_tsv" | wc -l | tr -d ' ')"

echo
echo "Splinter findings: raw=${raw_total} (allowlisted=${allowlisted_total}, unmatched=${total} — ERROR=${errors} WARN=${warns} INFO=${infos})"
echo
printf 'LEVEL\tRULE\tCOUNT (raw)\n'
cat "$summary_by_rule"

if [[ "$allowlisted_total" -gt 0 ]]; then
  echo
  echo "Allowlisted findings (accepted, see tasks/test/splinter.sh for justifications):"
  awk -F'\t' '{ printf "  - [%s] %s.%s (%s) — %s\n", $1, $4, $5, $6, $7 }' "$allowlisted_tsv"
fi

if [[ "$total" -gt 0 ]]; then
  echo
  echo "Findings not covered by the allowlist:"
  awk -F'\t' '{ printf "  - [%s] %s — %s\n", $2, $1, $3 }' "$findings_tsv"
fi

if [[ "$unused_total" -gt 0 ]]; then
  echo
  echo "Allowlist rows that matched NO finding (stale — remove them from tasks/test/splinter.sh):"
  awk -F'\t' '{ printf "  - [%s] %s.%s (%s)\n", $1, $2, $3, $4 }' "$unused_allow_tsv"
fi

# Write a GitHub Actions step summary if we're in CI.
if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
  {
    echo "## Supabase splinter (database linter)"
    echo
    echo "Pinned to [\`splinter@${SPLINTER_SHA:0:12}\`](https://github.com/supabase/splinter/tree/${SPLINTER_SHA})."
    echo "Scope: schemas owned by EQL (${EQL_OWNED_SCHEMAS//[\'()]/}). Findings outside these schemas are not reported."
    echo
    echo "**${raw_total} raw findings** (allowlisted: ${allowlisted_total}, unmatched: ${total} — ERROR: ${errors}, WARN: ${warns}, INFO: ${infos})"
    echo
    if [[ "$total" -gt 0 ]]; then
      echo "### Unmatched findings (action required)"
      echo
      echo "| Level | Rule | Detail |"
      echo "| --- | --- | --- |"
      awk -F'\t' '{
        gsub(/\|/, "\\|", $3);
        printf "| %s | `%s` | %s |\n", $2, $1, $3
      }' "$findings_tsv"
      echo
    elif [[ "$raw_total" -eq 0 ]]; then
      echo "EQL is splinter-clean against this pinned ruleset."
      echo
    else
      echo "EQL is splinter-clean (all findings covered by the allowlist)."
      echo
    fi
    if [[ "$unused_total" -gt 0 ]]; then
      echo "### Stale allowlist rows (action required)"
      echo
      echo "These allowlist rows matched no splinter finding — the function they waived is gone. Remove them from \`tasks/test/splinter.sh\`."
      echo
      echo "| Rule | Schema | Name | Type |"
      echo "| --- | --- | --- | --- |"
      awk -F'\t' '{ printf "| `%s` | `%s` | `%s` | %s |\n", $1, $2, $3, $4 }' "$unused_allow_tsv"
      echo
    fi
    if [[ "$allowlisted_total" -gt 0 ]]; then
      echo "<details><summary>Allowlisted findings (${allowlisted_total})</summary>"
      echo
      echo "| Rule | Schema | Name | Type | Reason |"
      echo "| --- | --- | --- | --- | --- |"
      awk -F'\t' '{
        gsub(/\|/, "\\|", $7);
        printf "| `%s` | `%s` | `%s` | %s | %s |\n", $1, $4, $5, $6, $7
      }' "$allowlisted_tsv"
      echo
      echo "</details>"
    fi
  } >> "$GITHUB_STEP_SUMMARY"
fi

# Fail on unmatched findings OR on stale (unused) allowlist rows — both are
# drift the gate exists to catch.
if [[ "$total" -gt 0 || "$unused_total" -gt 0 ]]; then
  exit 1
fi
