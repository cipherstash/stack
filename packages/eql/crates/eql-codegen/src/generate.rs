//! File renderers and orchestrator.

use std::path::{Path, PathBuf};

use eql_domains::{Domain, DomainFamily, Role, Term};

use crate::context::{domain_name, is_ord_capable, query_domain_name};
use crate::operator_surface::OPERATORS;

/// REQUIRE edge for the v3 schema file — pulled in by every generated file.
const V3_SCHEMA: &str = "src/v3/schema.sql";
/// REQUIRE edge for the hand-written shared blocker helper.
const V3_SCALARS_BLOCKER: &str = "src/v3/scalars/functions.sql";
/// REQUIRE edge for the ORE opclass capability-detection DO block — the
/// `ore_fallback.sql` file must sort after the attempt whose outcome it reads.
const V3_ORE_OPCLASS: &str = "src/v3/sem/ore_block_256/operator_class.sql";
/// Root of the generated per-type scalar surface. The single place the tree
/// layout is spelled out — keeps `types_path`/`scalar_path` and the REQUIRE
/// vecs from drifting if the surface ever relocates again.
const V3_SCALARS_DIR: &str = "src/v3/scalars";
/// REQUIRE edge for the hand-written json domain types (the json_entry domain).
const V3_JSON_TYPES: &str = "src/v3/json/types.sql";
/// REQUIRE edge for the hand-written json functions (the json_entry extractors
/// `eq_term`/`ord_term`). No cycle: json/* never REQUIREs src/v3/scalars/*.
const V3_JSON_FUNCTIONS: &str = "src/v3/json/functions.sql";
/// The catalog name of the `json` family's SteVec leaf domain. The three SteVec
/// domains are disambiguated by `Domain.name` (there is no distinct `Shape`), so
/// selecting the leaf is necessarily by name — the same way `dump.rs` resolves
/// them. Only the name is spelled here; the SQL type name is DERIVED below.
const JSON_ENTRY_DOMAIN: &str = "entry";

/// The fixed cross type: the extracted SteVec leaf, `public.eql_v3_json_entry`.
///
/// Derived from the catalog (`eql_domains::JSON`) via `Domain::full_name` +
/// `domain_name`, never spelled out — a literal would silently survive a catalog
/// rename (cf. #398 `jsonb` → `json`) or a `PUBLIC_TYPNAME_PREFIX` bump: codegen
/// would keep emitting the stale type, `codegen:parity` would still pass
/// (deterministic, just wrong), and the break would only surface at install time
/// as "type does not exist". Every other renderer constructs domain names this
/// way; this one must too.
fn json_entry_type() -> String {
    let entry = eql_domains::JSON
        .domains
        .iter()
        .find(|d| d.name == JSON_ENTRY_DOMAIN)
        .expect("catalog json family declares the SteVec `entry` domain");
    domain_name(&entry.full_name(eql_domains::JSON.name))
}

/// The generated file stem for a family's json_entry cross surface, e.g.
/// `json_entry_integer`. One place the stem is spelled, mirroring why
/// `V3_SCALARS_DIR` / `types_path` / `query_types_path` exist.
fn json_entry_stem(family_name: &str) -> String {
    format!("json_entry_{family_name}")
}

/// REQUIRE path for a family's generated json_entry cross functions file.
fn json_entry_functions_path(family_name: &str) -> String {
    scalar_path(
        family_name,
        &format!("{}_functions.sql", json_entry_stem(family_name)),
    )
}

/// REQUIRE path for a generated file `file` under a family's scalar dir.
fn scalar_path(family_name: &str, file: &str) -> String {
    format!("{V3_SCALARS_DIR}/{family_name}/{file}")
}

/// The second-parameter name for an operator's generated signature. The `->` and
/// `->>` path operators take a path *selector* as their right operand; every
/// other operator uses the generic `b`. This is a naming convention only — it
/// has no bearing on whether the operator is supported.
fn arg_b_name(symbol: &str) -> &'static str {
    match symbol {
        "->" | "->>" => "selector",
        _ => "b",
    }
}

/// REQUIRE path for a type's _types.sql. Port of `_types_path`.
fn types_path(family_name: &str) -> String {
    scalar_path(family_name, &format!("{family_name}_types.sql"))
}

/// Body for <T>_types.sql: every domain in one idempotent DO block.
/// Port of `render_types_file`.
pub fn render_types_file(spec: &DomainFamily) -> String {
    use crate::context::{domain_block, environment, TypesContext};
    let ctx = TypesContext {
        family_name: spec.name.to_string(),
        // Only scalar domains are generated. For a fully-scalar family this is
        // every domain (unchanged); for a mixed family (jsonb) it renders the
        // bare scalar storage domain and skips the hand-written SteVec domains.
        domains: spec
            .domains
            .iter()
            .filter(|d| d.is_scalar())
            .map(|d| domain_block(spec.name, d))
            .collect(),
    };
    environment()
        .get_template("types.sql")
        .unwrap()
        .render(&ctx)
        .expect("render types.sql")
}

/// Body for query_<T>_types.sql: a `public.query_<name>` operand domain per
/// TERM-BEARING domain — the index-terms-only twin (no `c`) whose operators
/// consume a query operand. Storage-only domains have no operators,
/// so no query twin.
pub fn render_query_types_file(spec: &DomainFamily) -> String {
    use crate::context::{environment, query_domain_block, TypesContext};
    let ctx = TypesContext {
        family_name: spec.name.to_string(),
        domains: spec
            .domains
            .iter()
            .filter(|d| !d.terms.is_empty())
            .map(|d| query_domain_block(spec.name, d))
            .collect(),
    };
    environment()
        .get_template("query_types.sql")
        .unwrap()
        .render(&ctx)
        .expect("render query_types.sql")
}

/// REQUIRE edges for a domain's _functions.sql. Port of `_functions_requires`.
fn functions_requires(family_name: &str, terms: &[Term]) -> Vec<String> {
    let mut reqs = vec![
        V3_SCHEMA.to_string(),
        types_path(family_name),
        V3_SCALARS_BLOCKER.to_string(),
    ];
    for extra in Term::term_requires(terms) {
        if !reqs.iter().any(|r| r == extra) {
            reqs.push(extra.to_string());
        }
    }
    reqs
}

/// Body for a domain's _functions.sql. Port of `render_functions_file`.
pub fn render_functions_file(family_name: &str, domain: &Domain) -> String {
    use crate::consts::sql_str;
    use crate::context::{
        environment, extractor_entry, unsupported_entry, wrapper_entry, FunctionsContext, SqlParam,
    };
    let name = domain.full_name(family_name);
    let dom = domain_name(&name);
    let domain_lit = sql_str(&dom);
    let supported = Term::operators_for_terms(domain.terms);
    let is_supported = |op: &str| supported.contains(&op);

    let mut entries = Vec::new();
    for term in Term::extractor_terms(domain.terms) {
        entries.push(extractor_entry(term));
    }
    for op in OPERATORS {
        let extractor = Term::extractor_for_operator(domain.terms, op.symbol.as_str());
        for sig in op.signatures {
            let rendered = sig.render(&dom);
            // A `blocker_only` overload (the `@@` jsonpath predicate) always falls
            // through to the blocker, even when the domain supports the symbol.
            if is_supported(op.symbol.as_str()) && !sig.blocker_only {
                if let Some(ex) = extractor {
                    entries.push(wrapper_entry(&dom, op, &rendered.left, &rendered.right, ex));
                    continue;
                }
            }
            let args = [
                SqlParam {
                    name: "a",
                    ty: rendered.left,
                },
                SqlParam {
                    name: arg_b_name(op.symbol.as_str()),
                    ty: rendered.right,
                },
            ];
            entries.push(unsupported_entry(op, args, &rendered.returns));
        }
    }

    let ctx = FunctionsContext {
        requires: functions_requires(family_name, domain.terms),
        family_name: family_name.to_string(),
        name,
        dom,
        domain_lit,
        entries,
    };
    environment()
        .get_template("functions.sql")
        .unwrap()
        .render(&ctx)
        .expect("render functions.sql")
}

/// Body for a domain's _operators.sql. Port of `render_operators_file`.
pub fn render_operators_file(family_name: &str, domain: &Domain) -> String {
    use crate::context::{environment, operator_entry, OperatorsContext};
    let name = domain.full_name(family_name);
    let dom = domain_name(&name);
    let supported = Term::operators_for_terms(domain.terms);
    let is_supported = |op: &str| supported.contains(&op);

    let mut operators = Vec::new();
    for op in OPERATORS {
        for sig in op.signatures {
            // CREATE OPERATOR only needs the operand types; `rendered.returns` is
            // intentionally discarded here (it matters only for the function body).
            let rendered = sig.render(&dom);
            // A `blocker_only` overload (the `@@` jsonpath predicate) is bound to
            // the internal blocker even on a domain that supports the symbol.
            operators.push(operator_entry(
                op,
                &rendered.left,
                &rendered.right,
                is_supported(op.symbol.as_str()) && !sig.blocker_only,
            ));
        }
    }

    let ctx = OperatorsContext {
        requires: vec![
            V3_SCHEMA.to_string(),
            types_path(family_name),
            scalar_path(family_name, &format!("{name}_functions.sql")),
        ],
        family_name: family_name.to_string(),
        name,
        dom,
        operators,
    };
    environment()
        .get_template("operators.sql")
        .unwrap()
        .render(&ctx)
        .expect("render operators.sql")
}

/// REQUIRE path for a family's query_<T>_types.sql.
fn query_types_path(family_name: &str) -> String {
    scalar_path(family_name, &format!("query_{family_name}_types.sql"))
}

/// Body for a term-bearing domain's query_<name>_functions.sql: the
/// query-operand extractor OVERLOADS (the same extractors, on
/// `eql_v3.query_<name>`) plus the comparison WRAPPERS binding the storage
/// domain to its query twin — for the domain's SUPPORTED operators only, in
/// both directions. Reuses the same `functions.sql` template as the storage
/// surface; a query operand carries the same terms, so each wrapper compares
/// `extractor(a)` to `extractor(b)` with no ciphertext cast.
pub fn render_query_functions_file(family_name: &str, domain: &Domain) -> String {
    use crate::consts::sql_str;
    use crate::context::{
        domain_name, environment, extractor_entry, query_domain_name, wrapper_entry,
        FunctionsContext,
    };
    let name = domain.full_name(family_name);
    let query_name = domain.query_name(family_name);
    let storage_dom = domain_name(&name);
    let query_dom = query_domain_name(&query_name);
    let supported = Term::operators_for_terms(domain.terms);

    let mut entries = Vec::new();
    // Extractor overloads on the query domain (the template renders `a {{ dom }}`
    // with dom = the query domain).
    for term in Term::extractor_terms(domain.terms) {
        entries.push(extractor_entry(term));
    }
    // Comparison wrappers: (storage, query) and its (query, storage) commutator,
    // for supported operators only (a query operand is never sent for a blocked
    // operator). `is_supported(op) ⟹ extractor_for_operator is Some`.
    //
    // Query twins deliberately emit NO blockers (unlike the storage surface). A
    // query operand only ever appears as the RHS of `col <op> operand`, and for
    // an unsupported `<op>` that predicate resolves against the STORAGE domain's
    // `(<storage>, jsonb)` blocker (the query operand degrades to its `jsonb`
    // base), which raises — so the realistic path is already protected. The only
    // unblocked cases are nonsensical `operand <op> operand` / `operand <op>
    // jsonb`, which no caller writes; blocking them would mean emitting the full
    // blocker matrix against every query twin for zero real-world coverage.
    for op in OPERATORS {
        if !supported.contains(&op.symbol.as_str()) {
            continue;
        }
        let extractor = Term::extractor_for_operator(domain.terms, op.symbol.as_str())
            .expect("a supported operator resolves an extractor");
        entries.push(wrapper_entry(
            &query_dom,
            op,
            &storage_dom,
            &query_dom,
            extractor,
        ));
        entries.push(wrapper_entry(
            &query_dom,
            op,
            &query_dom,
            &storage_dom,
            extractor,
        ));
    }

    let ctx = FunctionsContext {
        requires: vec![
            V3_SCHEMA.to_string(),
            query_types_path(family_name),
            scalar_path(family_name, &format!("{name}_functions.sql")),
        ],
        family_name: family_name.to_string(),
        name: query_name,
        domain_lit: sql_str(&query_dom),
        dom: query_dom,
        entries,
    };
    environment()
        .get_template("functions.sql")
        .unwrap()
        .render(&ctx)
        .expect("render query functions.sql")
}

/// Body for a term-bearing domain's query_<name>_operators.sql: a
/// `CREATE OPERATOR` binding `(storage_domain, query_<name>)` for every
/// supported operator, plus its `(query_<name>, storage_domain)` commutator, so
/// `col <op> $1::eql_v3.query_<name>` resolves to the query wrapper.
pub fn render_query_operators_file(family_name: &str, domain: &Domain) -> String {
    use crate::context::{
        domain_name, environment, operator_entry, query_domain_name, OperatorsContext,
    };
    let name = domain.full_name(family_name);
    let query_name = domain.query_name(family_name);
    let storage_dom = domain_name(&name);
    let query_dom = query_domain_name(&query_name);
    let supported = Term::operators_for_terms(domain.terms);

    let mut operators = Vec::new();
    for op in OPERATORS {
        if !supported.contains(&op.symbol.as_str()) {
            continue;
        }
        operators.push(operator_entry(op, &storage_dom, &query_dom, true));
        operators.push(operator_entry(op, &query_dom, &storage_dom, true));
    }

    let ctx = OperatorsContext {
        requires: vec![
            V3_SCHEMA.to_string(),
            query_types_path(family_name),
            scalar_path(family_name, &format!("{query_name}_functions.sql")),
        ],
        family_name: family_name.to_string(),
        name: query_name,
        dom: query_dom,
        operators,
    };
    environment()
        .get_template("operators.sql")
        .unwrap()
        .render(&ctx)
        .expect("render query operators.sql")
}

/// The term `public.eql_v3_json_entry` can serve, and the single source every
/// other decision in this surface derives from: `Term::Ope` — the deterministic
/// CLLW-OPE `op` term. A SteVec scalar (number/string) leaf emits exactly this
/// term (cipherstash-client `ste_plaintext_term.rs`: `Number`/`String` →
/// `Orderable` → `op`; only `Bool`/`Null`/`Object`/`Array` → a value-independent
/// structural `hm`).
///
/// `op` is deterministic, so byte-comparison on it is always a valid ORDERING —
/// which is all this seam uses it for. Equality does not live on the extract
/// surface at all: exact field equality is document containment on the
/// value selector (`col @> query_json`). See [`json_entry_cross_operators`].
const JSON_ENTRY_TERM: Term = Term::Ope;

/// The query operands a family binds to `public.eql_v3_json_entry`: every domain
/// carrying [`JSON_ENTRY_TERM`], in catalog order — provided the family's values
/// exist in JSON **as themselves**.
///
/// Capability-driven, not name-driven — the catalog's terms declare what a domain
/// can do, and this surface honours that (the same principle `is_ord_capable` and
/// `render_ore_fallback_file`'s `Term::Ore` filter follow). A family with no
/// Ope-carrying domain (boolean is storage-only; json has no scalar operands)
/// yields an empty list and emits no cross files, and an Ore-only domain
/// (`_ord_ore`) is excluded by construction — `json_entry` cannot produce a
/// block-ORE term. It also means the invariant "every bound operand provides
/// `ord_term`" is unrepresentable rather than asserted.
///
/// **The participation gate**
/// ([`eql_domains::ScalarKind::has_native_json_leaf`]) excludes `date` and
/// `timestamp` wholesale: JSON has no date/timestamp type — those values are
/// marshaled into ISO-8601 STRINGS, so a "date leaf" is a text leaf and the TEXT
/// surface owns it (ordering via `query_text_ord`; equality via `@>`
/// containment). Consistently, no client can build a temporal SteVec query term
/// (`OrderableTerm::try_from(&Plaintext)` refuses `NaiveDate`/`Timestamp`), so a
/// `(json_entry, query_date_ord)` wrapper could never see a real operand. Their
/// Ope-carrying operands are BLOCKED, not merely omitted — see
/// [`json_entry_cross_blocked_domains`].
///
/// `_eq` is excluded for free (it carries only `Term::Hm`): a SteVec path entry
/// carries neither that per-value `hm` nor its exact value selector, so a
/// `(json_entry, query_<T>_eq)` operator has no compatible equality term.
///
/// A `Term::Bloom`-bearing operand (text's `_search`) is excluded even though it
/// carries `Ope`: **SteVec has no match/bloom capability** — a leaf carries no
/// `match_term`, so `search` offers nothing over `_ord` while its domain CHECK
/// demands a `bf` the seam never reads and the caller would have to manufacture.
/// Binding it is the mirror of the `_eq` mistake: `_eq` matches nothing, `search`
/// matches but taxes the caller for an inert term. It too is blocked, not
/// omitted.
///
/// **Why excluded Ope-carrying operands get blockers.** `json_entry` and every
/// `query_<T>_<d>` are domains over `jsonb`, and PostgreSQL's operator resolution
/// flattens a domain to its base type, so an unclaimed `json_entry <op>
/// query_date_ord` would resolve to native `jsonb <op> jsonb` and answer silently
/// (`=` compares whole envelopes; `<` orders JSON objects — ZERO ROWS, no error).
/// Only an EXACT `(json_entry, query_<T>_<d>)` operator beats that flattening — a
/// `(json_entry, jsonb)` catch-all does not, because `jsonb <op> jsonb` is itself
/// an exact match once both sides flatten. The Ope-carrying excluded operands are
/// precisely the ones this seam's docs put in a caller's hands, so each gets an
/// exact-signature blocker.
///
/// Domain-x-domain pairs OUTSIDE the Ope set (`json_entry = query_integer_eq`,
/// `eql_v3_integer_eq = eql_v3_text_ord`, …) still flatten silently — a
/// project-wide property of the domain-over-jsonb design (the scalar surface's
/// blockers all target `(domain, native-type)` signatures), tracked separately.
fn json_entry_cross_domains(spec: &DomainFamily) -> Vec<&'static Domain> {
    // `expect`, not a permissive default, for the same reason as
    // `json_entry_cross_operators`: an unknown kind must fail the build loudly
    // rather than silently bind (or unbind) a family.
    let kind = eql_domains::kind_for(spec.name)
        .unwrap_or_else(|| panic!("catalog family `{}` declares no ScalarKind", spec.name));
    if !kind.has_native_json_leaf() {
        return Vec::new();
    }
    spec.domains
        .iter()
        .filter(|d| d.terms.contains(&JSON_ENTRY_TERM))
        .filter(|d| !d.terms.contains(&Term::Bloom))
        .collect()
}

/// The Ope-carrying operands this seam does NOT serve — the complement of
/// [`json_entry_cross_domains`] within the family's `Ope`-bearing domains.
/// **Blocked, never merely omitted** (the same rule
/// [`json_entry_cross_blocked_operators`] applies per-operator on served
/// operands, applied per-operand): each pair gets an exact-signature blocker for
/// every operator [`JSON_ENTRY_TERM`] provides, in both directions, so the
/// comparison raises instead of flattening to native `jsonb <op> jsonb`.
///
/// Two sources, both principled:
/// - a family failing the participation gate (`date`/`timestamp` — no native
///   JSON leaf) contributes ALL its Ope-carrying operands;
/// - a participating family contributes its `Term::Bloom`-bearing operands
///   (text's `_search` — SteVec has no match/bloom capability).
///
/// These are exactly the operand types a caller could plausibly reach for on
/// this seam (they carry the one term it serves), so silent-wrong is not an
/// acceptable failure mode for them.
fn json_entry_cross_blocked_domains(spec: &DomainFamily) -> Vec<&'static Domain> {
    let served = json_entry_cross_domains(spec);
    spec.domains
        .iter()
        .filter(|d| d.terms.contains(&JSON_ENTRY_TERM))
        .filter(|d| !served.iter().any(|s| s.name == d.name))
        .collect()
}

/// The operators this surface emits for a family's bound operands: the ORDERING
/// operators [`JSON_ENTRY_TERM`] provides (`<` `<=` `>` `>=`). Equality (`=` `<>`)
/// is deliberately excluded for EVERY family.
///
/// Derived from the term rather than from the operand's full term list, because
/// `json_entry` can only ever serve that one term. `Term::operators_for_terms`
/// over a domain's OWN terms would over-emit: text's `search` domain is
/// `[Hm, Ope, Bloom]`, so its supported set includes `@@` (Bloom) — which
/// `json_entry` has no `match_term` for, and which would render as a nonsensical
/// `ord_term(a) @@ ord_term(b)`. Asking the term what it provides keeps the
/// emitted set honest for every operand shape, present and future.
///
/// **Why equality never lives on the extract surface.** An extracted
/// `json_entry` is a PATH entry (`{s, c, op?}`); it carries no value selector, so
/// the only equality it could compute is `op` byte-comparison. `op` is
/// deterministic (a sound ordering for every kind) but not injective on every one
/// (`2^53`/`2^53+1` collide for `bigint`, `"café"`/`"cafe"` for `text`), and even
/// where injective it is the WRONG mechanism: exact field equality is document
/// containment on the value selector (`col @> $1::eql_v3.query_json`, where the
/// value-selector's *presence* in the stored document is the exact match). That
/// surface is the whole document, not an extracted leaf, so equality simply is not
/// an operation this seam can express. `=`/`<>` are therefore subtracted from
/// every family's served set and BLOCKED by [`json_entry_cross_blocked_operators`]
/// — a bare `json_entry = query_<T>_ord` must raise, not fall through to native
/// `jsonb = jsonb` (which compares whole envelopes and silently returns zero rows).
fn json_entry_cross_operators(spec: &DomainFamily) -> Vec<&'static str> {
    // Assert the family declares a kind — fail the build LOUDLY on an unknown one,
    // matching `json_entry_cross_domains`. The emitted set no longer BRANCHES on
    // the kind (equality left the extract surface in the new design), but keeping the
    // loud-fail contract at the seam that decides the operators is cheap insurance.
    eql_domains::kind_for(spec.name)
        .unwrap_or_else(|| panic!("catalog family `{}` declares no ScalarKind", spec.name));
    // Ranges only — subtract the equality operators for every family (see above).
    let mut ops = Term::operators_for_terms(&[JSON_ENTRY_TERM]);
    ops.retain(|op| !Term::Hm.operators().contains(op));
    ops
}

/// The operators [`JSON_ENTRY_TERM`] provides that a family's SERVED operands must
/// not answer — the complement of [`json_entry_cross_operators`]. **Blocked, never
/// merely omitted.**
///
/// `public.eql_v3_json_entry` and `eql_v3.query_<T>_<d>` are both domains over
/// `jsonb`, and an operator resolves against the ultimate base type. So leaving `=`
/// unbound does not make `json_entry = query_text_ord` a planner error — it falls
/// back to native `jsonb = jsonb`, compares whole payload objects, never matches,
/// and returns ZERO ROWS with no error. A blocker claims the exact signature so the
/// operator resolves to a `RAISE` instead.
///
/// This covers a SERVED operand's unsound operators (text's `=`), where the exact
/// signature beats the base-type flattening. Operands the seam does not serve at
/// all are NOT covered — see the caveat on [`json_entry_cross_domains`].
fn json_entry_cross_blocked_operators(spec: &DomainFamily) -> Vec<&'static str> {
    let supported = json_entry_cross_operators(spec);
    Term::operators_for_terms(&[JSON_ENTRY_TERM])
        .into_iter()
        .filter(|op| !supported.contains(op))
        .collect()
}

/// The extractor this surface uses on BOTH operands: [`JSON_ENTRY_TERM`]'s own
/// (`ord_term` → `ope_cllw`), asked of the `Term` rather than spelled out, so an
/// extractor rename stays a single catalog-side change.
///
/// Used for every operator rather than resolving per-operator through
/// `Term::extractor_for_operator`. That generic rule picks the first capable term
/// in the operand's list, so on a dual-term `[Hm, Ope]` operand (text's `_ord`)
/// it routes `=`/`<>` through `eq_term` — the per-value HMAC a SteVec scalar leaf
/// never carries. That rule is right for a scalar column and wrong for this seam:
/// `json_entry` serves exactly one term, so the extractor is a property of the
/// SEAM, not of the operator. Since [`json_entry_cross_operators`] already limits
/// the emitted set to what this term provides, the pairing is total.
fn json_entry_extractor() -> &'static str {
    JSON_ENTRY_TERM.extractor()
}

/// Body for a family's json_entry_<T>_functions.sql: comparison
/// WRAPPERS binding the fixed `public.eql_v3_json_entry` leaf to the family's
/// `_ord` / `_ord_ope` query operands, for every operator json_entry can serve
/// through `ord_term` → ope_cllw (op byte-comparison, which covers ordering and
/// equality), in both directions. Reuses the `functions.sql` template +
/// `wrapper_entry`: the left operand is the fixed json_entry type instead of the
/// family's storage domain, and no operand is `jsonb`, so each wrapper compares
/// `ord_term(a)` to `ord_term(b)` with no cast. Emits wrappers for the operators
/// this family's `op` term can serve soundly, plus BLOCKERS for the rest — see
/// [`json_entry_cross_blocked_operators`] for why omission is not an option.
///
/// `blocked_domains` (see [`json_entry_cross_blocked_domains`]) get blockers for
/// EVERY operator [`JSON_ENTRY_TERM`] provides, both directions — an unserved
/// Ope-carrying operand must raise, never flatten to `jsonb <op> jsonb`.
pub fn render_json_entry_cross_functions(
    spec: &DomainFamily,
    domains: &[&Domain],
    blocked_domains: &[&Domain],
) -> String {
    use crate::consts::sql_str;
    use crate::context::{
        environment, query_domain_name, unsupported_entry, wrapper_entry, FunctionsContext,
        SqlParam,
    };

    let family_name = spec.name;
    let json_entry = json_entry_type();
    let extractor = json_entry_extractor();
    let supported = json_entry_cross_operators(spec);
    let blocked = json_entry_cross_blocked_operators(spec);
    let mut requires = vec![
        V3_SCHEMA.to_string(),
        V3_JSON_TYPES.to_string(),
        V3_JSON_FUNCTIONS.to_string(),
        query_types_path(family_name),
    ];
    let mut entries = Vec::new();

    for d in domains {
        let query_dom = query_domain_name(&d.query_name(family_name));
        // The query-side extractor overload (ord_term on the query operand) lives
        // in the query domain's functions file.
        requires.push(scalar_path(
            family_name,
            &format!("{}_functions.sql", d.query_name(family_name)),
        ));
        for op in OPERATORS {
            let symbol = op.symbol.as_str();
            if supported.contains(&symbol) {
                // (json_entry, query) and its (query, json_entry) commutator. `dom`
                // (first arg of wrapper_entry) only drives the jsonb→domain cast in
                // extract_arg, which never fires here (neither operand is jsonb), so
                // the json_entry type is a safe placeholder.
                entries.push(wrapper_entry(
                    &json_entry,
                    op,
                    &json_entry,
                    &query_dom,
                    extractor,
                ));
                entries.push(wrapper_entry(
                    &json_entry,
                    op,
                    &query_dom,
                    &json_entry,
                    extractor,
                ));
            } else if blocked.contains(&symbol) {
                // Both directions, so neither can fall through to `jsonb = jsonb`.
                entries.push(unsupported_entry(
                    op,
                    [
                        SqlParam {
                            name: "a",
                            ty: json_entry.clone(),
                        },
                        SqlParam {
                            name: "b",
                            ty: query_dom.clone(),
                        },
                    ],
                    "boolean",
                ));
                entries.push(unsupported_entry(
                    op,
                    [
                        SqlParam {
                            name: "a",
                            ty: query_dom.clone(),
                        },
                        SqlParam {
                            name: "b",
                            ty: json_entry.clone(),
                        },
                    ],
                    "boolean",
                ));
            }
        }
    }

    // Unserved Ope-carrying operands: blockers for EVERY operator the term
    // provides, both directions (no wrapper exists to fall back on). Only the
    // operand TYPE is needed for the signature — no extractor call, so no
    // REQUIRE on the operand's functions file.
    let all_ops = Term::operators_for_terms(&[JSON_ENTRY_TERM]);
    for d in blocked_domains {
        let query_dom = query_domain_name(&d.query_name(family_name));
        for op in OPERATORS {
            if !all_ops.contains(&op.symbol.as_str()) {
                continue;
            }
            entries.push(unsupported_entry(
                op,
                [
                    SqlParam {
                        name: "a",
                        ty: json_entry.clone(),
                    },
                    SqlParam {
                        name: "b",
                        ty: query_dom.clone(),
                    },
                ],
                "boolean",
            ));
            entries.push(unsupported_entry(
                op,
                [
                    SqlParam {
                        name: "a",
                        ty: query_dom.clone(),
                    },
                    SqlParam {
                        name: "b",
                        ty: json_entry.clone(),
                    },
                ],
                "boolean",
            ));
        }
    }

    let ctx = FunctionsContext {
        requires,
        family_name: family_name.to_string(),
        name: json_entry_stem(family_name),
        domain_lit: sql_str(&json_entry),
        dom: json_entry,
        entries,
    };
    environment()
        .get_template("functions.sql")
        .unwrap()
        .render(&ctx)
        .expect("render json_entry cross functions")
}

/// Body for a family's json_entry_<T>_operators.sql: a CREATE
/// OPERATOR binding `(public.eql_v3_json_entry, query_<T>_<d>)` and its
/// `(query_<T>_<d>, public.eql_v3_json_entry)` commutator for every operator
/// [`JSON_ENTRY_TERM`] provides — bound to the public WRAPPER where the family's
/// `op` term serves it soundly (supported = true → COMMUTATOR/NEGATOR/RESTRICT/
/// JOIN metadata), and to the BLOCKER where it does not (supported = false → no
/// metadata; the operator resolves to a `RAISE` instead of falling through to
/// native `jsonb = jsonb`). `blocked_domains` bind every operator to a blocker.
pub fn render_json_entry_cross_operators(
    spec: &DomainFamily,
    domains: &[&Domain],
    blocked_domains: &[&Domain],
) -> String {
    use crate::context::{environment, operator_entry, query_domain_name, OperatorsContext};

    let family_name = spec.name;
    let json_entry = json_entry_type();
    // The SAME sets the functions renderer uses — both call
    // `json_entry_cross_operators` / `_blocked_operators`, so `supported` here
    // (which claims a public wrapper backs the operator, per `operator_entry`'s
    // contract) cannot drift from the wrappers/blockers actually emitted.
    let supported = json_entry_cross_operators(spec);
    let blocked = json_entry_cross_blocked_operators(spec);
    let mut operators = Vec::new();
    for d in domains {
        let query_dom = query_domain_name(&d.query_name(family_name));
        for op in OPERATORS {
            let symbol = op.symbol.as_str();
            let is_supported = if supported.contains(&symbol) {
                true
            } else if blocked.contains(&symbol) {
                false
            } else {
                continue;
            };
            operators.push(operator_entry(op, &json_entry, &query_dom, is_supported));
            operators.push(operator_entry(op, &query_dom, &json_entry, is_supported));
        }
    }
    // Unserved Ope-carrying operands: every operator resolves to its blocker
    // (mirrors the blocker entries `render_json_entry_cross_functions` emits).
    let all_ops = Term::operators_for_terms(&[JSON_ENTRY_TERM]);
    for d in blocked_domains {
        let query_dom = query_domain_name(&d.query_name(family_name));
        for op in OPERATORS {
            if !all_ops.contains(&op.symbol.as_str()) {
                continue;
            }
            operators.push(operator_entry(op, &json_entry, &query_dom, false));
            operators.push(operator_entry(op, &query_dom, &json_entry, false));
        }
    }

    let ctx = OperatorsContext {
        requires: vec![
            V3_SCHEMA.to_string(),
            V3_JSON_TYPES.to_string(),
            query_types_path(family_name),
            json_entry_functions_path(family_name),
        ],
        family_name: family_name.to_string(),
        name: json_entry_stem(family_name),
        dom: json_entry,
        operators,
    };
    environment()
        .get_template("operators.sql")
        .unwrap()
        .render(&ctx)
        .expect("render json_entry cross operators")
}

/// Body for a domain's _aggregates.sql, or None if not ord-capable.
/// Port of `render_aggregates_file`.
pub fn render_aggregates_file(family_name: &str, domain: &Domain) -> Option<String> {
    use crate::context::{environment, AggregatesContext, AGGREGATE_OPS};
    if !is_ord_capable(domain.terms) {
        return None;
    }
    let name = domain.full_name(family_name);
    let dom = domain_name(&name);
    let ctx = AggregatesContext {
        requires: vec![
            V3_SCHEMA.to_string(),
            types_path(family_name),
            scalar_path(family_name, &format!("{name}_functions.sql")),
            scalar_path(family_name, &format!("{name}_operators.sql")),
        ],
        family_name: family_name.to_string(),
        name,
        dom,                       // hoisted: one copy, template reads {{ dom }}
        aggregates: AGGREGATE_OPS, // iterate the const directly (no per-entry wrapper)
    };
    Some(
        environment()
            .get_template("aggregates.sql")
            .unwrap()
            .render(&ctx)
            .expect("render aggregates.sql"),
    )
}

/// The plain-English capability word for a domain's role, used in the poison
/// error's alternatives hint (`ore_fallback.sql`).
fn role_word(role: Role) -> &'static str {
    match role {
        Role::Eq => "equality",
        Role::Ord => "ordering",
        Role::Match => "match",
        Role::Storage => "storage",
    }
}

/// The alternatives hint for one poisoned domain: the same family's
/// term-bearing non-ORE siblings (the domains that stay fully functional
/// without the ORE operator class), each qualified by `qualify` and labelled
/// with its capability word, joined with " or ".
fn ore_alternatives(spec: &DomainFamily, qualify: &dyn Fn(&Domain) -> String) -> String {
    let alts: Vec<String> = spec
        .domains
        .iter()
        .filter(|d| !d.terms.is_empty() && !d.terms.contains(&Term::Ore))
        .map(|d| {
            format!(
                "{} ({})",
                qualify(d),
                role_word(Term::role_for_terms(d.terms))
            )
        })
        .collect();
    if alts.is_empty() {
        // Unreachable with the current catalog (every ORE-carrying family also
        // declares `_eq` and `_ord_ope`), but a future family must still render
        // a sentence, not an empty hint.
        "a non-ORE encrypted domain".to_string()
    } else {
        alts.join(" or ")
    }
}

/// Body for the cross-family `src/v3/scalars/ore_fallback.sql`.
///
/// The rendered DO block runs after the ORE opclass creation attempt
/// (`V3_ORE_OPCLASS`). If the default btree opclass for
/// `eql_v3_internal.ore_block_256` exists (superuser install) it is a no-op;
/// if the attempt was skipped (`insufficient_privilege` — cloud Supabase and
/// most managed Postgres), it poisons every ORE-carrying domain and its
/// query-operand twin with an always-raising CHECK constraint so the domains
/// fail loudly on first use instead of silently degrading to unindexable seq
/// scans. The poison function is plpgsql and non-STRICT per the
/// encrypted-domain footgun list, and the constraints are added NOT VALID so
/// a re-install over existing ORE data (written under an earlier superuser
/// install) does not abort — domain coercion enforces the CHECK on new values
/// regardless of validation status.
pub fn render_ore_fallback_file() -> String {
    use crate::consts::sql_str;
    use crate::context::{environment, OreFallbackContext, OreFallbackEntry};

    let mut requires = vec![V3_SCHEMA.to_string(), V3_ORE_OPCLASS.to_string()];
    let mut entries = Vec::new();
    for spec in eql_domains::scalar_families() {
        let ore_domains: Vec<&Domain> = spec
            .domains
            .iter()
            .filter(|d| d.terms.contains(&Term::Ore))
            .collect();
        if ore_domains.is_empty() {
            continue;
        }
        requires.push(types_path(spec.name));
        requires.push(scalar_path(
            spec.name,
            &format!("query_{}_types.sql", spec.name),
        ));
        let column_alts = ore_alternatives(spec, &|d| domain_name(&d.full_name(spec.name)));
        let query_alts = ore_alternatives(spec, &|d| query_domain_name(&d.query_name(spec.name)));
        for d in ore_domains {
            let col_name = domain_name(&d.full_name(spec.name));
            entries.push(OreFallbackEntry {
                name_literal: sql_str(&col_name),
                name: col_name,
                alternatives: sql_str(&column_alts),
            });
            let query_name = query_domain_name(&d.query_name(spec.name));
            entries.push(OreFallbackEntry {
                name_literal: sql_str(&query_name),
                name: query_name,
                alternatives: sql_str(&query_alts),
            });
        }
    }
    let ctx = OreFallbackContext { requires, entries };
    environment()
        .get_template("ore_fallback.sql")
        .unwrap()
        .render(&ctx)
        .expect("render ore_fallback.sql")
}

use std::fs;

use crate::writer::{
    ensure_generated_paths_writable, normalized_set, remove_generated_orphans,
    write_generated_file, GeneratedKind, WriteError,
};

/// Render every generated file for one type into memory, paired with its output
/// path under `out_dir`. Mirrors `bindings::render_bindings`: rendering happens
/// before any filesystem mutation, so a render `.expect` panic aborts the run
/// before a single file is written or deleted. Order matches `generate_type`'s
/// write order (types file, then per-domain functions/operators/aggregates).
pub fn render_type(spec: &DomainFamily, out_dir: &Path) -> Vec<(PathBuf, String)> {
    let family_name = spec.name;
    let mut rendered = vec![(
        out_dir.join(format!("{family_name}_types.sql")),
        render_types_file(spec),
    )];
    // Query-operand twin domains (term-only, no `c`) — only for families with at
    // least one term-bearing domain (storage-only families have no query surface).
    if spec.domains.iter().any(|d| !d.terms.is_empty()) {
        rendered.push((
            out_dir.join(format!("query_{family_name}_types.sql")),
            render_query_types_file(spec),
        ));
    }
    // Generate only scalar domains: identical to iterating every domain for a
    // fully-scalar family; for a mixed family (jsonb) it emits the bare scalar
    // storage surface and skips the hand-written SteVec domains under
    // `src/v3/json/`.
    for d in spec.domains.iter().filter(|d| d.is_scalar()) {
        let name = d.full_name(family_name);
        rendered.push((
            out_dir.join(format!("{name}_functions.sql")),
            render_functions_file(family_name, d),
        ));
        rendered.push((
            out_dir.join(format!("{name}_operators.sql")),
            render_operators_file(family_name, d),
        ));
        // Query-operand surface: extractor overloads + wrappers +
        // operators binding the storage domain to its `query_<name>` twin. Only
        // term-bearing domains have a query twin (storage-only = no operators).
        if !d.terms.is_empty() {
            let query_name = d.query_name(family_name);
            rendered.push((
                out_dir.join(format!("{query_name}_functions.sql")),
                render_query_functions_file(family_name, d),
            ));
            rendered.push((
                out_dir.join(format!("{query_name}_operators.sql")),
                render_query_operators_file(family_name, d),
            ));
        }
        if let Some(agg) = render_aggregates_file(family_name, d) {
            rendered.push((out_dir.join(format!("{name}_aggregates.sql")), agg));
        }
    }
    // json_entry cross-type operators: bind the fixed
    // public.eql_v3_json_entry leaf to every query operand this family declares
    // that carries the term json_entry can serve (Term::Ope) AND whose values
    // exist in JSON as themselves. Ope-carrying operands the seam does not serve
    // (date/timestamp — no native JSON leaf; text's Bloom-bearing `search`) get
    // blocker-only files so the pair raises instead of flattening to native
    // `jsonb <op> jsonb`. Both lists empty for boolean (storage-only) and json
    // (no scalar operands) → no cross files.
    let cross_domains = json_entry_cross_domains(spec);
    let cross_blocked = json_entry_cross_blocked_domains(spec);
    if !(cross_domains.is_empty() && cross_blocked.is_empty()) {
        let stem = json_entry_stem(family_name);
        rendered.push((
            out_dir.join(format!("{stem}_functions.sql")),
            render_json_entry_cross_functions(spec, &cross_domains, &cross_blocked),
        ));
        rendered.push((
            out_dir.join(format!("{stem}_operators.sql")),
            render_json_entry_cross_operators(spec, &cross_domains, &cross_blocked),
        ));
    }
    rendered
}

/// Regenerate every generated file for one type into `out_dir`, crash-safely.
/// Port of `generate_type`. Returns the written paths.
///
/// Ordering is render-all → preflight → write-all (atomic) → delete-orphans:
/// every current file is rendered to memory and written (each via an atomic
/// same-dir temp+rename) before any stale generated file is deleted. A render
/// panic or write error therefore can never leave the directory with files
/// deleted-but-not-rewritten. The trailing orphan sweep prunes generated SQL for
/// domains dropped from the catalog, marker-aware (hand-written files survive).
pub fn generate_type(spec: &DomainFamily, out_dir: &Path) -> Result<Vec<PathBuf>, WriteError> {
    let rendered = render_type(spec, out_dir);
    let targets: Vec<PathBuf> = rendered.iter().map(|(p, _)| p.clone()).collect();
    ensure_generated_paths_writable(&targets, GeneratedKind::Sql)?;

    let mut written: Vec<PathBuf> = Vec::with_capacity(rendered.len());
    for (path, body) in &rendered {
        write_generated_file(path, body, GeneratedKind::Sql)?;
        written.push(path.clone());
    }
    remove_generated_orphans(out_dir, GeneratedKind::Sql, &normalized_set(&written))?;
    Ok(written)
}

/// Generate every catalog type's gitignored SQL surface under `out_root`. The
/// single entry point: replaces Python's per-type and --all forms. The
/// plaintext fixture lists are not generated — they live in the catalog
/// (`eql_domains::INT4_VALUES` / `INT2_VALUES`), read directly by the SQLx tests.
pub fn generate_all(out_root: &Path) -> Result<i32, WriteError> {
    let scalars_root = out_root.join(V3_SCALARS_DIR);
    let mut all_written: Vec<PathBuf> = Vec::new();
    // Every family with at least one scalar domain: fully-scalar families are
    // unchanged; a mixed family (jsonb) contributes only its scalar storage
    // domain (the per-domain renderers filter `is_scalar()`).
    for spec in eql_domains::families_with_scalar_domains() {
        let family_name = spec.name;
        let out_dir = scalars_root.join(family_name);
        let written = generate_type(spec, &out_dir)?;

        for p in &written {
            let rel = p.strip_prefix(out_root).unwrap_or(p);
            println!("generated {}", rel.display());
        }
        println!("generated {} files for {family_name}", written.len());
        all_written.extend(written.iter().cloned());
    }

    // Cross-family ORE capability-detection fallback. Depth-1 under
    // src/v3/scalars (it spans families, so it belongs to no type dir), written
    // after every per-family surface so all its REQUIRE targets exist.
    let fallback_path = scalars_root.join("ore_fallback.sql");
    ensure_generated_paths_writable(std::slice::from_ref(&fallback_path), GeneratedKind::Sql)?;
    write_generated_file(
        &fallback_path,
        &render_ore_fallback_file(),
        GeneratedKind::Sql,
    )?;
    {
        let rel = fallback_path
            .strip_prefix(out_root)
            .unwrap_or(&fallback_path);
        println!("generated {}", rel.display());
    }
    all_written.push(fallback_path);

    // Orphan sweep across every scalar type dir. `generate_type` already prunes
    // stale files *within* a regenerated dir, but a type dropped from the catalog
    // entirely leaves a dir the generator never revisits — its generated SQL must
    // still go (this is the responsibility build.sh's filename-pattern `find
    // -delete` used to own, now marker-aware and inside codegen). Runs only after
    // every current type wrote successfully, so it never deletes-before-write.
    let keep = normalized_set(&all_written);
    if scalars_root.is_dir() {
        // `file_type()` does NOT follow symlinks (unlike `Path::is_dir`), so a
        // symlinked entry under scalars_root is skipped rather than traversed —
        // the orphan sweep can never delete files outside `out_root` through a
        // symlink.
        let mut subdirs: Vec<PathBuf> = Vec::new();
        for entry in fs::read_dir(&scalars_root)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                subdirs.push(entry.path());
            }
        }
        subdirs.sort();
        for dir in subdirs {
            for removed in remove_generated_orphans(&dir, GeneratedKind::Sql, &keep)? {
                let rel = removed.strip_prefix(out_root).unwrap_or(&removed);
                println!("removed orphan {}", rel.display());
            }
        }
        // Depth-1 sweep for cross-family generated files (ore_fallback.sql).
        // Marker-aware, so the hand-written depth-1 functions.sql (no
        // AUTO-GENERATED marker) is never touched.
        for removed in remove_generated_orphans(&scalars_root, GeneratedKind::Sql, &keep)? {
            let rel = removed.strip_prefix(out_root).unwrap_or(&removed);
            println!("removed orphan {}", rel.display());
        }
    }

    // No ordering manifest is emitted here. The installer order is derived by
    // `eql-codegen order` from a single walk of the whole src/v3 surface, so the
    // generator has no say in — and cannot disagree with — what gets ordered.
    let names: Vec<&str> = eql_domains::families_with_scalar_domains()
        .map(|s| s.name)
        .collect();
    println!("codegen: ok ({} types: {})", names.len(), names.join(", "));
    Ok(0)
}

/// Remove every generated SQL file under `out_root`'s `src/v3/scalars` tree —
/// the per-type subdirs plus depth-1 cross-family files (ore_fallback.sql) —
/// marker-aware. Replaces build.sh's filename-pattern `find -delete`: it
/// deletes only files carrying the AUTO-GENERATED marker, so a hand-written
/// `<T>_extensions.sql` and the hand-written depth-1
/// `src/v3/scalars/functions.sql` (no marker) are preserved. Returns the
/// removed paths.
pub fn clean_all(out_root: &Path) -> Result<Vec<PathBuf>, WriteError> {
    use crate::writer::clean_generated_files;
    let scalars_root = out_root.join(V3_SCALARS_DIR);
    if !scalars_root.is_dir() {
        return Ok(Vec::new());
    }
    // `file_type()` does NOT follow symlinks (unlike `Path::is_dir`), so a
    // symlinked entry under scalars_root is skipped, never descended into for
    // marker-aware deletion.
    let mut subdirs: Vec<PathBuf> = Vec::new();
    for entry in fs::read_dir(&scalars_root)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            subdirs.push(entry.path());
        }
    }
    subdirs.sort();
    let mut removed = Vec::new();
    // Depth-1 cross-family generated files (ore_fallback.sql); marker-aware,
    // so the hand-written depth-1 functions.sql survives.
    removed.extend(clean_generated_files(&scalars_root, GeneratedKind::Sql)?);
    for dir in subdirs {
        removed.extend(clean_generated_files(&dir, GeneratedKind::Sql)?);
    }
    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use eql_domains::CATALOG;

    fn spec(family_name: &str) -> &'static DomainFamily {
        CATALOG
            .iter()
            .find(|s| s.name == family_name)
            .expect("catalog family")
    }

    fn domain<'a>(spec: &'a DomainFamily, name: &str) -> &'a Domain {
        spec.domains
            .iter()
            .find(|d| d.name == name)
            .expect("domain name")
    }

    use std::fs;

    #[test]
    fn arg_b_name_is_selector_only_for_path_operators() {
        assert_eq!(arg_b_name("->"), "selector");
        assert_eq!(arg_b_name("->>"), "selector");
        assert_eq!(arg_b_name("="), "b");
        assert_eq!(arg_b_name("||"), "b");
        assert_eq!(arg_b_name("@>"), "b");
    }

    #[test]
    fn functions_render_supported_wrappers_and_unsupported_entries_from_catalog() {
        let s = spec("integer");
        let d = domain(s, "eq");
        let sql = render_functions_file("integer", d);
        // Supported wrapper (`=`) is PUBLIC; unsupported ops (`<`, `->` on an
        // equality-only domain) stay as internal blockers.
        assert!(sql.contains("CREATE FUNCTION eql_v3.eq("));
        assert!(sql.contains("AS $$ SELECT"));
        assert!(sql.contains("CREATE FUNCTION eql_v3_internal.lt("));
        assert!(sql.contains("RAISE EXCEPTION 'operator % is not supported for %', '<'"));
        assert!(sql.contains("CREATE FUNCTION eql_v3_internal.\"->\"("));
        assert!(sql.contains("RAISE EXCEPTION 'operator % is not supported for %', '->'"));
    }

    #[test]
    fn generate_type_writes_expected_files() {
        let d = crate::writer::test_support::tempdir();
        let s = spec("integer");
        let out = d.path().join("integer");
        let written = generate_type(s, &out).unwrap();
        let names: Vec<String> = written
            .iter()
            .map(|p| p.file_name().unwrap().to_str().unwrap().to_string())
            .collect();
        assert!(names.contains(&"integer_types.sql".to_string()));
        // Query-operand twin domains (term-only, no `c`) for the family.
        assert!(names.contains(&"query_integer_types.sql".to_string()));
        for dom in [
            "integer",
            "integer_eq",
            "integer_ord_ore",
            "integer_ord",
            "integer_ord_ope",
        ] {
            assert!(names.contains(&format!("{dom}_functions.sql")));
            assert!(names.contains(&format!("{dom}_operators.sql")));
        }
        // Query-operand functions/operators for the term-bearing domains only
        // (not the storage-only bare `integer`).
        for dom in [
            "integer_eq",
            "integer_ord_ore",
            "integer_ord",
            "integer_ord_ope",
        ] {
            assert!(names.contains(&format!("query_{dom}_functions.sql")));
            assert!(names.contains(&format!("query_{dom}_operators.sql")));
        }
        assert!(!names.contains(&"query_integer_functions.sql".to_string()));
        assert!(!names.contains(&"integer_aggregates.sql".to_string()));
        assert!(!names.contains(&"integer_eq_aggregates.sql".to_string()));
        assert!(names.contains(&"integer_ord_ore_aggregates.sql".to_string()));
        assert!(names.contains(&"integer_ord_aggregates.sql".to_string()));
        assert!(names.contains(&"integer_ord_ope_aggregates.sql".to_string()));
        // Query-operand + json_entry cross-type files for the term-bearing domains.
        assert!(names.contains(&"json_entry_integer_functions.sql".to_string()));
        assert!(names.contains(&"json_entry_integer_operators.sql".to_string()));
        // 1 types + 1 query_types + 2 per domain (5) + 2 query per term-bearing
        // domain (4) + 3 ord-capable aggregates = 1+1+10+8+3 = 23, plus the 2
        // json_entry cross files.
        assert_eq!(written.len(), 25);
        for p in &written {
            assert!(fs::read_to_string(p)
                .unwrap()
                .starts_with(&format!("{}\n", crate::consts::AUTO_GENERATED_MARKER)));
        }
    }

    #[test]
    fn generate_type_prunes_orphaned_generated_files() {
        // A generated file for a domain no longer produced (here: a stale
        // `integer_gone_functions.sql`) is pruned by the trailing orphan sweep, while
        // a hand-written file with no marker survives.
        let d = crate::writer::test_support::tempdir();
        let out = d.path().join("integer");
        fs::create_dir_all(&out).unwrap();
        let orphan = out.join("integer_gone_functions.sql");
        let hand = out.join("integer_extensions.sql");
        fs::write(
            &orphan,
            format!("{}\nSELECT 1;\n", crate::consts::AUTO_GENERATED_MARKER),
        )
        .unwrap();
        fs::write(&hand, "-- REQUIRE: src/v3/schema.sql\n-- hand-written\n").unwrap();

        generate_type(spec("integer"), &out).unwrap();

        assert!(!orphan.exists(), "stale generated file must be pruned");
        assert!(hand.exists(), "hand-written file must survive the sweep");
        assert!(
            out.join("integer_types.sql").exists(),
            "current files written"
        );
    }

    #[cfg(unix)]
    #[test]
    fn generate_type_failure_does_not_delete_before_writing() {
        // The write-then-delete discipline: if a write fails, nothing has been
        // deleted yet. Seed an existing generated target (old content) plus an
        // orphan, make the dir read-only so the first write fails, and assert both
        // survive untouched — the destructive orphan sweep never ran.
        use std::os::unix::fs::PermissionsExt;
        let d = crate::writer::test_support::tempdir();
        let out = d.path().join("integer");
        fs::create_dir_all(&out).unwrap();
        let marker = crate::consts::AUTO_GENERATED_MARKER;
        let types = out.join("integer_types.sql");
        let orphan = out.join("integer_gone_functions.sql");
        let old = format!("{marker}\n-- OLD\n");
        fs::write(&types, &old).unwrap();
        fs::write(&orphan, format!("{marker}\nSELECT 1;\n")).unwrap();

        let mut perms = fs::metadata(&out).unwrap().permissions();
        perms.set_mode(0o555);
        fs::set_permissions(&out, perms).unwrap();

        let err = generate_type(spec("integer"), &out).unwrap_err();

        let mut perms = fs::metadata(&out).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&out, perms).unwrap();

        assert!(matches!(err, WriteError::Io(_)), "expected Io, got {err:?}");
        assert_eq!(
            fs::read_to_string(&types).unwrap(),
            old,
            "existing target keeps old content — never deleted/truncated"
        );
        assert!(
            orphan.exists(),
            "orphan must survive: the delete step runs only after writes succeed"
        );
    }

    #[test]
    fn generate_all_prunes_orphaned_type_dir() {
        // A whole type dir for a token absent from the catalog (here: `bogus`) is
        // swept by generate_all's cross-dir orphan pass — the case build.sh's
        // `find -delete` used to own, now marker-aware inside codegen.
        let d = crate::writer::test_support::tempdir();
        let root = d.path();
        let bogus_dir = root.join(V3_SCALARS_DIR).join("bogus");
        fs::create_dir_all(&bogus_dir).unwrap();
        let bogus = bogus_dir.join("bogus_types.sql");
        let bogus_hand = bogus_dir.join("bogus_extensions.sql");
        fs::write(
            &bogus,
            format!("{}\nSELECT 1;\n", crate::consts::AUTO_GENERATED_MARKER),
        )
        .unwrap();
        fs::write(&bogus_hand, "-- hand-written, no marker\n").unwrap();

        generate_all(root).unwrap();

        assert!(
            !bogus.exists(),
            "generated file in a dropped type dir is pruned"
        );
        assert!(
            bogus_hand.exists(),
            "hand-written file in that dir survives"
        );
        assert!(
            root.join(V3_SCALARS_DIR)
                .join("integer/integer_types.sql")
                .exists(),
            "catalog types are generated"
        );
    }

    #[cfg(unix)]
    #[test]
    fn generate_all_does_not_follow_symlinked_subdir_for_orphan_sweep() {
        // A symlinked entry under src/v3/scalars must NOT be descended into by the
        // cross-dir orphan sweep: `file_type()` reports the entry as a symlink (not
        // a dir), so files in the link target — which live OUTSIDE out_root — are
        // never marker-deleted. With the old `Path::is_dir()` (symlink-following)
        // scan, the generated file under the target would be swept.
        let d = crate::writer::test_support::tempdir();
        let root = d.path();
        let scalars = root.join(V3_SCALARS_DIR);
        fs::create_dir_all(&scalars).unwrap();

        // An outside-the-tree dir holding a marker-bearing generated file that is
        // NOT part of any catalog write, i.e. an "orphan" the sweep would target if
        // it could reach it.
        let outside = d.path().join("outside-target");
        fs::create_dir_all(&outside).unwrap();
        let victim = outside.join("integer_types.sql");
        fs::write(
            &victim,
            format!("{}\nSELECT 1;\n", crate::consts::AUTO_GENERATED_MARKER),
        )
        .unwrap();

        // Plant the symlink as a scalars subdir entry pointing at the outside dir.
        std::os::unix::fs::symlink(&outside, scalars.join("evil")).unwrap();

        generate_all(root).unwrap();

        assert!(
            victim.exists(),
            "file behind a symlinked subdir must not be swept (no symlink traversal)"
        );
    }

    #[test]
    fn types_file_has_all_five_domains() {
        let sql = render_types_file(spec("integer"));
        assert!(sql.contains("-- REQUIRE: src/v3/schema.sql"));
        for dom in [
            "integer",
            "integer_eq",
            "integer_ord_ore",
            "integer_ord",
            "integer_ord_ope",
        ] {
            assert!(
                sql.contains(&format!("CREATE DOMAIN public.eql_v3_{dom} AS jsonb")),
                "missing {dom}"
            );
        }
    }

    #[test]
    fn generated_scalar_domains_are_created_only_in_public() {
        let sql = render_types_file(spec("integer"));
        assert!(sql.contains("CREATE DOMAIN public.eql_v3_integer AS jsonb"));
        assert!(sql.contains("CREATE DOMAIN public.eql_v3_integer_eq AS jsonb"));
        assert!(!sql.contains("CREATE DOMAIN eql_v3."));
        assert!(!sql.contains("CREATE DOMAIN eql_v3_internal."));
    }

    /// The non-empty-`ob` CHECK (issue #262) is emitted only on ORE-bearing
    /// domains. An empty ORE term (`ob: []`) is what encrypting the empty string
    /// into an ordered column produces; the constraint rejects it at the domain
    /// boundary. Domains carrying no `ob` — storage-only (`integer`),
    /// equality-only (`integer_eq`), and the OPE-bearing ordered domains
    /// (`integer_ord`, `integer_ord_ope`) — must NOT gain the clause.
    #[test]
    fn ore_bearing_domains_reject_empty_ob() {
        // Per-domain assertion: a domain's CREATE block carries the clause iff it
        // is ORE-bearing. Slice each domain's CHECK out of the rendered file so a
        // clause on the wrong domain cannot pass via whole-file `contains`.
        let sql = render_types_file(spec("integer"));
        let clause = "jsonb_array_length(VALUE -> 'ob') > 0";
        for (dom, expected) in [
            ("integer", false),
            ("integer_eq", false),
            ("integer_ord_ore", true),
            // The OPE term (`op`) is a single hex string, not an array — no
            // non-empty-array CHECK on the OPE-bearing domains, which since the
            // `_ord` default flipped to CLLW-OPE includes `_ord` itself.
            ("integer_ord", false),
            ("integer_ord_ope", false),
        ] {
            let head = format!("CREATE DOMAIN public.eql_v3_{dom} AS jsonb");
            let start = sql.find(&head).unwrap_or_else(|| panic!("missing {dom}"));
            // The CHECK ends at the closing `);` of this CREATE DOMAIN block.
            let end = start + sql[start..].find(");").expect("unterminated CHECK");
            let block = &sql[start..end];
            assert_eq!(
                block.contains(clause),
                expected,
                "domain {dom}: expected non-empty-ob CHECK present={expected}",
            );
        }
    }

    #[test]
    fn storage_functions_file_is_all_blockers() {
        let s = spec("integer");
        let sql = render_functions_file(s.name, domain(s, ""));
        // 44 native/comparison blockers + 3 `@@` symmetric-match blockers (a
        // storage domain supports no operators, so `@@`'s match overloads render
        // as blockers, exactly like `@>`/`<@`).
        assert_eq!(sql.matches("CREATE FUNCTION").count(), 47);
        assert!(!sql.contains("SET search_path"));
        assert_eq!(sql.matches("LANGUAGE plpgsql").count(), 47);
        assert_eq!(
            sql.matches("LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE")
                .count(),
            0
        );
    }

    #[test]
    fn eq_functions_file_counts() {
        let s = spec("integer");
        let sql = render_functions_file(s.name, domain(s, "eq"));
        // +3 vs the pre-`@@`-match surface: the three `@@` symmetric-match
        // overloads render as blockers on this eq domain (it does not carry Bloom).
        assert_eq!(sql.matches("CREATE FUNCTION").count(), 48);
        assert!(sql.contains("CREATE FUNCTION eql_v3.eq_term(a public.eql_v3_integer_eq)"));
        assert!(sql.contains("RETURNS eql_v3_internal.hmac_256"));
        assert_eq!(
            sql.matches("LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE")
                .count(),
            7
        );
        assert_eq!(sql.matches("LANGUAGE plpgsql").count(), 41);
        assert!(!sql.contains("SET search_path"));
    }

    /// The block-ORE ordered domain is now reached only by name: `_ord_ore`.
    /// (`_ord` is OPE-backed — see `ope_functions_file_counts`.)
    #[test]
    fn ore_functions_file_counts() {
        let s = spec("integer");
        let sql = render_functions_file(s.name, domain(s, "ord_ore"));
        // +3 vs the pre-`@@`-match surface (the three `@@` symmetric-match blockers).
        assert_eq!(sql.matches("CREATE FUNCTION").count(), 48);
        assert!(
            sql.contains("CREATE FUNCTION eql_v3.ord_term_ore(a public.eql_v3_integer_ord_ore)")
        );
        assert!(sql.contains("RETURNS eql_v3_internal.ore_block_256"));
        // Ore needs the hand-written comparison operators on the composite.
        assert!(sql.contains("-- REQUIRE: src/v3/sem/ore_block_256/functions.sql"));
        assert!(sql.contains("-- REQUIRE: src/v3/sem/ore_block_256/operators.sql"));
        assert_eq!(
            sql.matches("LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE")
                .count(),
            19
        );
        assert_eq!(sql.matches("LANGUAGE plpgsql").count(), 29);
    }

    /// The OPE ordered domains mirror the ORE one — same operator surface
    /// (18 wrappers), one extractor — but the extractor is the unqualified
    /// `ord_term` (OPE backs the default `_ord` domain; block-ORE takes the
    /// qualified `ord_term_ore`) returning the SEM `eql_v3_internal.ope_cllw`
    /// domain (over bytea), and the sole SEM REQUIRE edge is the extractor
    /// file: the bytea-backed domain inherits native comparison operators, so
    /// there is no hand-written operators.sql to depend on (unlike Ore).
    ///
    /// Both `_ord` (the default) and `_ord_ope` carry the OPE term, so both are
    /// asserted here.
    #[test]
    fn ope_functions_file_counts() {
        let s = spec("integer");
        for dom in ["ord", "ord_ope"] {
            let sql = render_functions_file(s.name, domain(s, dom));
            // +3 vs the pre-`@@`-match surface (the three `@@` symmetric-match blockers).
            assert_eq!(sql.matches("CREATE FUNCTION").count(), 48, "{dom}");
            assert!(
                sql.contains(&format!(
                    "CREATE FUNCTION eql_v3.ord_term(a public.eql_v3_integer_{dom})"
                )),
                "{dom}"
            );
            assert!(sql.contains("RETURNS eql_v3_internal.ope_cllw"), "{dom}");
            assert!(
                sql.contains("-- REQUIRE: src/v3/sem/ope_cllw/functions.sql"),
                "{dom}"
            );
            assert!(
                !sql.contains("-- REQUIRE: src/v3/sem/ope_cllw/operators.sql"),
                "{dom}"
            );
            assert_eq!(
                sql.matches("LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE")
                    .count(),
                19,
                "{dom}"
            );
            assert_eq!(sql.matches("LANGUAGE plpgsql").count(), 29, "{dom}");
        }
    }

    #[test]
    fn match_domain_renders_matches_wrapper_and_at_at_operator() {
        let s = spec("text");
        let fns = render_functions_file(s.name, domain(s, "match"));
        // The supported `@@` overloads are `eql_v3.matches` wrappers whose body
        // reduces to bloom array-containment `@>` on the extracted terms (so a
        // functional GIN index on `eql_v3.match_term(col)` engages) guarded by an
        // empty-needle clause: an empty needle bloom (`{}`) must match only a
        // value whose own bloom is also empty, never every row. The
        // top-level `@>` conjunct is preserved so the GIN index still engages;
        // in the normal non-empty-needle case the guard folds to a constant TRUE
        // and drops out.
        assert!(fns.contains(
            "CREATE FUNCTION eql_v3.matches(a public.eql_v3_text_match, b public.eql_v3_text_match)"
        ));
        assert!(fns.contains(
            "SELECT eql_v3.match_term(a) @> eql_v3.match_term(b) \
             AND (cardinality(eql_v3.match_term(b)) > 0 OR cardinality(eql_v3.match_term(a)) = 0)"
        ));
        // The guarded match wrapper is NOT STRICT: a STRICT SQL function with a
        // non-strict body (the guard's AND/OR) would stop inlining, losing the
        // functional GIN index. Its body propagates NULL on its own. The bare
        // (non-guarded) wrappers keep STRICT.
        assert!(fns.contains(
            "CREATE FUNCTION eql_v3.matches(a public.eql_v3_text_match, b public.eql_v3_text_match)\n\
             RETURNS boolean LANGUAGE sql IMMUTABLE PARALLEL SAFE\n"
        ));
        assert!(!fns.contains(
            "CREATE FUNCTION eql_v3.matches(a public.eql_v3_text_match, b public.eql_v3_text_match)\n\
             RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE\n"
        ));
        assert!(!fns.contains("eql_v3.contains("));
        assert!(!fns.contains("eql_v3.contained_by("));
        // `@>` / `<@` are now blockers on the match domain.
        assert!(fns.contains(
            "CREATE FUNCTION eql_v3_internal.contains(a public.eql_v3_text_match, b public.eql_v3_text_match)"
        ));
        assert!(fns.contains(
            "CREATE FUNCTION eql_v3_internal.contained_by(a public.eql_v3_text_match, b public.eql_v3_text_match)"
        ));
        // The `@@` jsonpath predicate stays a blocker even here (blocker_only).
        assert!(fns.contains(
            "CREATE FUNCTION eql_v3_internal.\"@@\"(a public.eql_v3_text_match, b jsonpath)"
        ));

        let ops = render_operators_file(s.name, domain(s, "match"));
        assert!(ops.contains("CREATE OPERATOR @@ ("));
        assert!(ops.contains("FUNCTION = eql_v3.matches,"));
        // The jsonpath `@@` operator binds the internal blocker.
        assert!(ops.contains("FUNCTION = eql_v3_internal.\"@@\","));
    }

    #[test]
    fn operators_file_operator_count() {
        let s = spec("integer");
        let sql = render_operators_file(s.name, domain(s, "eq"));
        // +3 vs the pre-`@@`-match surface: the three `@@` symmetric-match
        // overloads render as blocked operators on this eq domain.
        assert_eq!(sql.matches("CREATE OPERATOR").count(), 47);
    }

    #[test]
    fn generated_functions_reference_public_domain_arguments() {
        let s = spec("integer");
        let sql = render_functions_file(s.name, domain(s, "eq"));
        assert!(sql.contains("CREATE FUNCTION eql_v3.eq_term(a public.eql_v3_integer_eq)"));
        assert!(sql.contains(
            "CREATE FUNCTION eql_v3.eq(a public.eql_v3_integer_eq, b public.eql_v3_integer_eq)"
        ));
        assert!(sql.contains("CREATE FUNCTION eql_v3.eq(a public.eql_v3_integer_eq, b jsonb)"));
        assert!(sql.contains("CREATE FUNCTION eql_v3.eq(a jsonb, b public.eql_v3_integer_eq)"));
        assert!(!sql.contains("a eql_v3.integer_eq"));
    }

    #[test]
    fn supported_operators_bind_public_wrapper_blocked_bind_internal() {
        // The operator-equivalent invariant for operator-free platforms: a
        // SUPPORTED operator's backing function is PUBLIC (`eql_v3.<wrapper>`)
        // so it is callable by name without the operator; a BLOCKED operator's
        // backing function stays internal (`eql_v3_internal.<blocker>`).
        let s = spec("integer");
        let eq_sql = render_operators_file(s.name, domain(s, "eq"));
        // `=` is supported on integer_eq → public wrapper.
        assert!(eq_sql.contains("FUNCTION = eql_v3.eq,"));
        // `<` is unsupported on the equality-only domain → internal blocker.
        assert!(eq_sql.contains("FUNCTION = eql_v3_internal.lt,"));
        // native-jsonb blocker stays internal too.
        assert!(eq_sql.contains("FUNCTION = eql_v3_internal.\"||\","));

        // Ordered domain: comparison + range wrappers all public.
        let ord_sql = render_operators_file(s.name, domain(s, "ord"));
        for f in ["eq", "neq", "lt", "lte", "gt", "gte"] {
            assert!(
                ord_sql.contains(&format!("FUNCTION = eql_v3.{f},")),
                "ordered operator {f} must bind the public wrapper"
            );
        }

        // Bloom text_match: the `@@` fuzzy-match wrapper is supported → public;
        // the former containment operators `@>`/`<@` are now blockers (internal).
        let tm = spec("text");
        let tm_sql = render_operators_file(tm.name, domain(tm, "match"));
        assert!(tm_sql.contains("FUNCTION = eql_v3.matches,"));
        assert!(tm_sql.contains("FUNCTION = eql_v3_internal.contains,"));
        assert!(tm_sql.contains("FUNCTION = eql_v3_internal.contained_by,"));
    }

    #[test]
    fn aggregates_file_only_for_ord_variants() {
        let s = spec("integer");
        assert!(render_aggregates_file(s.name, domain(s, "")).is_none());
        assert!(render_aggregates_file(s.name, domain(s, "eq")).is_none());
        assert!(render_aggregates_file(s.name, domain(s, "ord")).is_some());
        assert!(render_aggregates_file(s.name, domain(s, "ord_ore")).is_some());
        assert!(render_aggregates_file(s.name, domain(s, "ord_ope")).is_some());
    }

    #[test]
    fn aggregates_file_carries_min_and_max_and_requires() {
        let s = spec("integer");
        let sql = render_aggregates_file(s.name, domain(s, "ord")).unwrap();
        assert_eq!(sql.matches("CREATE FUNCTION").count(), 2);
        assert_eq!(sql.matches("CREATE AGGREGATE").count(), 2);
        assert!(sql.contains("eql_v3_internal.min_sfunc"));
        assert!(sql.contains("eql_v3_internal.max_sfunc"));
        assert!(sql.contains("-- REQUIRE: src/v3/scalars/integer/integer_ord_operators.sql"));
        assert!(sql.contains("-- REQUIRE: src/v3/scalars/integer/integer_ord_functions.sql"));
        assert!(sql.contains("-- REQUIRE: src/v3/scalars/integer/integer_types.sql"));
    }

    /// `_ord` and `_ord_ope` are the twins: same term (`Ope`), so their rendered
    /// surfaces differ only in the domain name. `_ord_ore` is NOT a twin — it
    /// carries `Ore`, so its extractor and SEM type differ. (Before the default
    /// flipped to CLLW-OPE, `_ord`/`_ord_ore` were the twins.)
    #[test]
    fn ordered_files_byte_identical_modulo_typename() {
        let s = spec("integer");
        let ord = domain(s, "ord");
        let ope = domain(s, "ord_ope");
        let ore = domain(s, "ord_ore");
        // Normalize each file with its OWN domain name. A single fixed replace
        // chain would corrupt the `_ord` file: `integer_ord_ope` is a prefix of
        // `integer_ord_operators.sql`, so replacing the longer name first eats
        // into the `_operators.sql` filename.
        let norm = |sql: String, dom: &str| sql.replace(&format!("integer_{dom}"), "T");
        assert_eq!(
            norm(render_functions_file(s.name, ord), "ord"),
            norm(render_functions_file(s.name, ope), "ord_ope")
        );
        assert_eq!(
            norm(render_operators_file(s.name, ord), "ord"),
            norm(render_operators_file(s.name, ope), "ord_ope")
        );
        assert_eq!(
            norm(render_aggregates_file(s.name, ord).unwrap(), "ord"),
            norm(render_aggregates_file(s.name, ope).unwrap(), "ord_ope")
        );

        // The ORE domain is a genuinely different surface, not a renamed twin.
        assert_ne!(
            norm(render_functions_file(s.name, ord), "ord"),
            norm(render_functions_file(s.name, ore), "ord_ore"),
            "_ord (ope) and _ord_ore (ore) must not render identically"
        );
    }

    #[test]
    fn json_family_generates_only_its_scalar_storage_surface() {
        // The mixed json family renders exactly the bare scalar storage domain
        // (`public.eql_v3_json`): a types file + a functions file + an operators
        // file, all named for the bare family name. No query twin, no aggregates
        // (storage-only), and NONE of the hand-written SteVec domains
        // (`search`/`entry`/`query`) may leak a generated file.
        let s = spec("json");
        let rendered = render_type(s, std::path::Path::new("out"));
        let names: Vec<String> = rendered
            .iter()
            .map(|(p, _)| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            names,
            vec!["json_types.sql", "json_functions.sql", "json_operators.sql"],
            "json must emit exactly the bare scalar storage surface — the exact \
             file list also proves no SteVec domain (search/entry/query) leaked a \
             generated file"
        );
        let by = |suffix: &str| {
            &rendered
                .iter()
                .find(|(p, _)| p.file_name().unwrap().to_string_lossy().ends_with(suffix))
                .unwrap()
                .1
        };
        assert!(by("json_types.sql").contains("CREATE DOMAIN public.eql_v3_json AS jsonb"));
        // Storage-only (no terms) → every operator overload is a blocker, incl.
        // the three `@@` symmetric-match overloads (+3 vs the pre-match surface).
        assert_eq!(
            by("json_functions.sql").matches("CREATE FUNCTION").count(),
            47
        );
        assert_eq!(
            by("json_operators.sql").matches("CREATE OPERATOR").count(),
            47
        );
    }

    #[test]
    fn storage_only_and_json_families_emit_no_json_entry_cross_files() {
        for family in ["boolean", "json"] {
            let rendered = render_type(spec(family), std::path::Path::new("out"));
            assert!(
                !rendered.iter().any(|(p, _)| p
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with("json_entry_")),
                "{family} must emit no json_entry cross files"
            );
        }
    }

    // --- Coarsened footgun invariant guards (whole-file scans) ---

    #[test]
    fn blockers_are_never_strict_and_always_plpgsql() {
        let s = spec("integer");
        // Storage domain functions file is all blockers.
        let sql = render_functions_file("integer", domain(s, ""));
        // Every CREATE FUNCTION here is a blocker: none may be STRICT, all plpgsql.
        assert!(!sql.contains("STRICT"), "blocker marked STRICT");
        assert_eq!(
            sql.matches("CREATE FUNCTION").count(),
            sql.matches("LANGUAGE plpgsql").count(),
            "every blocker must be LANGUAGE plpgsql"
        );
    }

    #[test]
    fn inlinable_functions_have_no_set_search_path() {
        let s = spec("integer");
        // Extractors and wrappers (eq/ord functions files) are inlinable SQL.
        for name in ["eq", "ord"] {
            let sql = render_functions_file("integer", domain(s, name));
            // Inlinable rows are the LANGUAGE sql ones; none may pin search_path.
            for block in sql.split("CREATE FUNCTION").skip(1) {
                if block.contains("LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE") {
                    assert!(
                        !block.contains("SET search_path"),
                        "inlinable SQL function pins search_path"
                    );
                }
            }
        }
    }

    #[test]
    fn aggregate_state_functions_are_plpgsql_not_inlinable() {
        let s = spec("integer");
        let sql = render_aggregates_file("integer", domain(s, "ord")).unwrap();
        assert_eq!(sql.matches("CREATE FUNCTION").count(), 2);
        assert_eq!(
            sql.matches("LANGUAGE plpgsql IMMUTABLE STRICT PARALLEL SAFE")
                .count(),
            2
        );
        assert_eq!(
            sql.matches("LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE")
                .count(),
            0
        );
    }

    #[test]
    fn generated_function_like_docs_keep_required_tags() {
        let s = spec("integer");
        for d in s.domains {
            let sql = render_functions_file("integer", d);
            let functions = sql.matches("CREATE FUNCTION").count();
            assert_eq!(sql.matches("--! @return").count(), functions);
            assert!(
                sql.matches("--! @param").count() >= functions,
                "each generated function must keep at least one @param tag"
            );
            assert!(
                sql.matches("--! @brief").count() >= functions,
                "each generated function must keep @brief"
            );
        }

        let sql = render_aggregates_file("integer", domain(s, "ord")).unwrap();
        let function_like =
            sql.matches("CREATE FUNCTION").count() + sql.matches("CREATE AGGREGATE").count();
        assert_eq!(sql.matches("--! @return").count(), function_like);
        assert!(sql.matches("--! @param").count() >= function_like);
        assert!(sql.matches("--! @brief").count() >= function_like);
    }

    // --- Escaping guards over the context builders (synthetic inputs) ---

    #[test]
    fn unsupported_entry_preserves_operator_literal_and_domain_lit_is_escaped() {
        use crate::consts::sql_str;
        use crate::context::{unsupported_entry, FnEntry, SqlParam};
        use crate::operator_surface::operator;
        let dom = "eql_v3.o'dom";
        let domain_lit = sql_str(dom);
        let entry = unsupported_entry(
            &operator("<"),
            [
                SqlParam {
                    name: "a",
                    ty: dom.into(),
                },
                SqlParam {
                    name: "b",
                    ty: dom.into(),
                },
            ],
            "boolean",
        );
        match entry {
            FnEntry::Unsupported { operator_lit, .. } => {
                assert_eq!(domain_lit, "eql_v3.o''dom"); // quote doubled by sql_str
                assert_eq!(operator_lit, "<");
            }
            _ => panic!("expected unsupported-operator entry"),
        }
    }

    #[test]
    fn domain_block_escapes_quote_bearing_name() {
        use crate::context::domain_block;
        use eql_domains::{Domain, Shape};
        let block = domain_block(
            "integer",
            &Domain {
                name: "q",
                terms: &[],
                shape: Shape::Scalar,
            },
        );
        assert_eq!(block.typname, "eql_v3_integer_q"); // no quote present → unchanged
                                                       // keys are sql_str-escaped key tokens; none should carry a bare unescaped quote.
        assert!(block.keys.iter().all(|k| !k.contains("o'")));
    }

    #[test]
    fn ore_fallback_poisons_exactly_the_ore_carrying_domains_and_their_query_twins() {
        // Every domain carrying Term::Ore — and ONLY those — gets an
        // always-raising CHECK, on both the public column domain and its
        // eql_v3.query_* twin. Trailing space in the needle prevents
        // `integer_ord` prefix-matching `integer_ord_ore`.
        let sql = render_ore_fallback_file();
        for spec in eql_domains::scalar_families() {
            for d in spec.domains {
                let col = format!("ALTER DOMAIN public.{} ", spec.domain_name(d));
                let query = format!("ALTER DOMAIN eql_v3.{} ", d.query_name(spec.name));
                if d.terms.contains(&Term::Ore) {
                    assert!(sql.contains(&col), "missing poison for {col}");
                    assert!(sql.contains(&query), "missing poison for {query}");
                } else {
                    assert!(!sql.contains(&col), "unexpected poison for {col}");
                    assert!(!sql.contains(&query), "unexpected poison for {query}");
                }
            }
        }
    }

    #[test]
    fn ore_fallback_poison_function_is_plpgsql_and_not_strict() {
        // Footguns from the encrypted-domain list: the poison must be plpgsql
        // (never inlined → the RAISE cannot be planned away) and must not be
        // STRICT (a STRICT function is skipped on NULL input, silently letting
        // NULLs through the poisoned domain). Scope the STRICT assertion to the
        // CREATE FUNCTION statement — the file's doc header legitimately
        // mentions the word.
        let sql = render_ore_fallback_file();
        let start = sql
            .find("CREATE FUNCTION eql_v3_internal.ore_domain_unavailable")
            .expect("poison function present");
        let end = sql[start..].find("$poison$;").expect("function end") + start;
        let create_fn = &sql[start..end];
        assert!(create_fn.contains("LANGUAGE plpgsql"));
        assert!(!create_fn.contains("STRICT"));
        assert!(!create_fn.contains("RETURNS NULL ON NULL INPUT"));
    }

    #[test]
    fn ore_fallback_poison_constraints_are_not_valid() {
        // ALTER DOMAIN ... ADD CONSTRAINT validates existing stored data, and
        // the poison raises unconditionally — without NOT VALID, re-running
        // the installer over a database holding ORE values (written under an
        // earlier superuser install) would abort inside the DO block. NOT
        // VALID skips that scan; domain coercion still enforces the CHECK on
        // every new cast/insert regardless of validation status.
        let sql = render_ore_fallback_file();
        let adds = sql.matches("ADD CONSTRAINT eql_ore_unavailable").count();
        let not_valid = sql.matches(")) NOT VALID;").count();
        assert!(adds > 0, "poison constraints present");
        assert_eq!(adds, not_valid, "every poison constraint must be NOT VALID");
    }

    #[test]
    fn ore_fallback_requires_opclass_attempt_and_every_affected_family() {
        // The REQUIRE edges force tsort to place the fallback after the opclass
        // creation attempt (whose outcome it reads from pg_opclass) and after
        // every poisoned domain exists. Families with no ORE domain (boolean)
        // contribute no edge.
        let sql = render_ore_fallback_file();
        assert!(sql.contains("-- REQUIRE: src/v3/sem/ore_block_256/operator_class.sql"));
        for spec in eql_domains::scalar_families() {
            let types = format!(
                "-- REQUIRE: {}\n",
                scalar_path(spec.name, &format!("{}_types.sql", spec.name))
            );
            let query_types = format!(
                "-- REQUIRE: {}\n",
                scalar_path(spec.name, &format!("query_{}_types.sql", spec.name))
            );
            let has_ore = spec.domains.iter().any(|d| d.terms.contains(&Term::Ore));
            assert_eq!(
                sql.contains(&types),
                has_ore,
                "types edge for {}",
                spec.name
            );
            assert_eq!(
                sql.contains(&query_types),
                has_ore,
                "query types edge for {}",
                spec.name
            );
        }
    }

    #[test]
    fn generate_all_writes_ore_fallback_and_clean_all_removes_it() {
        // The cross-family fallback is depth-1 under src/v3/scalars: generate_all
        // writes it, clean_all's marker-aware depth-1 pass removes it, and the
        // hand-written depth-1 functions.sql (no marker) survives both.
        let d = crate::writer::test_support::tempdir();
        let root = d.path();
        let scalars = root.join(V3_SCALARS_DIR);
        fs::create_dir_all(&scalars).unwrap();
        let hand = scalars.join("functions.sql");
        fs::write(&hand, "-- hand-written, no marker\n").unwrap();

        generate_all(root).unwrap();
        let fallback = scalars.join("ore_fallback.sql");
        assert!(fallback.exists(), "generate_all writes ore_fallback.sql");

        let removed = clean_all(root).unwrap();
        assert!(!fallback.exists(), "clean_all removes ore_fallback.sql");
        assert!(removed.contains(&fallback));
        assert!(hand.exists(), "hand-written depth-1 functions.sql survives");
    }

    // --- json_entry <-> query_<T> cross-type operator surface ---

    #[test]
    fn json_entry_cross_domains_selects_every_ope_carrying_operand() {
        // Selection is by CAPABILITY: every domain carrying Term::Ope, whatever it
        // is named. integer declares exactly two.
        let names: Vec<&str> = json_entry_cross_domains(spec("integer"))
            .iter()
            .map(|d| d.name)
            .collect();
        assert_eq!(names, vec!["ord", "ord_ope"]);
        assert!(
            json_entry_cross_blocked_domains(spec("integer")).is_empty(),
            "integer serves every Ope-carrying operand — nothing to block"
        );
        // text declares a THIRD Ope-carrying operand — `search` [Hm, Ope, Bloom] —
        // and it does NOT bind: SteVec has no match/bloom capability, so `search`
        // offers nothing over `_ord` while its CHECK demands a `bf` the seam never
        // reads. Binding it would tax the caller for an inert term. It is BLOCKED,
        // not merely omitted (see json_entry_bloom_operand_is_blocked_not_bound).
        let text: Vec<&str> = json_entry_cross_domains(spec("text"))
            .iter()
            .map(|d| d.name)
            .collect();
        assert_eq!(text, vec!["ord", "ord_ope"]);
        let text_blocked: Vec<&str> = json_entry_cross_blocked_domains(spec("text"))
            .iter()
            .map(|d| d.name)
            .collect();
        assert_eq!(text_blocked, vec!["search"]);
        // Excluded BY CONSTRUCTION, no name list needed:
        //   `_eq`        [Hm]              — no Ope; a SteVec scalar leaf has no
        //                                    per-value `hm`, so it'd be dead surface.
        //   `_ord_ore`   [Hm, Ore]         — block-ORE; json_entry cannot produce it.
        //   `_search_ore`[Hm, Ore, Bloom]  — likewise.
        //   `_match`     [Bloom]           — Bloom only.
        //   `_search`    [Hm, Ope, Bloom]  — carries Ope, but Bloom-bearing.
        for excluded in ["eq", "ord_ore", "match", "search_ore", "search"] {
            assert!(
                !text.contains(&excluded),
                "{excluded} must not bind json_entry"
            );
        }
        // date/timestamp fail the PARTICIPATION gate wholesale: JSON has no
        // date/timestamp type — those values marshal into ISO-8601 strings, so a
        // "date leaf" IS a text leaf and the text surface owns it. Their
        // Ope-carrying operands land in the blocked list instead (coderdan's
        // review call on PR #410).
        for temporal in ["date", "timestamp"] {
            assert!(
                json_entry_cross_domains(spec(temporal)).is_empty(),
                "{temporal} has no native JSON leaf — it must not bind json_entry"
            );
            let blocked: Vec<&str> = json_entry_cross_blocked_domains(spec(temporal))
                .iter()
                .map(|d| d.name)
                .collect();
            assert_eq!(
                blocked,
                vec!["ord", "ord_ope"],
                "{temporal}'s Ope operands must be blocked, not merely omitted"
            );
        }
        // boolean (storage-only) and json (no scalar operands) contribute nothing
        // to either list.
        assert!(json_entry_cross_domains(spec("boolean")).is_empty());
        assert!(json_entry_cross_domains(spec("json")).is_empty());
        assert!(json_entry_cross_blocked_domains(spec("boolean")).is_empty());
        assert!(json_entry_cross_blocked_domains(spec("json")).is_empty());
    }

    #[test]
    fn json_entry_cross_operator_set_is_exactly_what_the_term_provides() {
        // The emitted set is Term::Ope's operators MINUS equality, not the operand's
        // own term list — otherwise text's `search` [Hm, Ope, Bloom] would drag in
        // `@@`, which json_entry has no match_term for and which would render as a
        // nonsensical `ord_term(a) @@ ord_term(b)`. Equality is excluded for EVERY
        // family: it lives on the document-containment surface
        // (`col @> query_json`, value-selector presence), never on an extracted leaf.
        let ops = json_entry_cross_operators(spec("integer"));
        assert_eq!(ops, vec!["<", "<=", ">", ">="]);
        for excluded in ["=", "<>", "@@", "@>"] {
            assert!(
                !ops.contains(&excluded),
                "{excluded} must never reach the extract surface"
            );
        }
        // And the extractor is the term's own, not a spelled-out literal.
        assert_eq!(json_entry_extractor(), Term::Ope.extractor());
    }

    #[test]
    fn json_entry_never_serves_equality_on_the_extract_surface() {
        // equality is not an extract operation for ANY family. An
        // extracted json_entry is a PATH entry ({s,c,op?}) carrying no value
        // selector, so the only equality it could offer is `op` byte-comparison —
        // lossy for text/bigint/numeric (café==cafe, 2^53==2^53+1) and, even where
        // injective (integer/smallint inject into f64, real/double ARE f64), the
        // WRONG mechanism. Exact field equality is document containment
        // (`col @> query_json`, value-selector presence). So every participating
        // family serves ordering only; `=`/`<>` are subtracted here and BLOCKED by
        // the renderer (see json_entry_cross_functions_* and _operators_*).
        for family in [
            "integer", "smallint", "real", "double", "bigint", "numeric", "text",
        ] {
            let ops = json_entry_cross_operators(spec(family));
            assert_eq!(
                ops,
                vec!["<", "<=", ">", ">="],
                "{family} must serve ordering only on the extract surface"
            );
            for eq_op in Term::Hm.operators() {
                assert!(
                    !ops.contains(eq_op),
                    "{family} must not serve `{eq_op}` on an extracted leaf — equality \
                     is document containment (query_json), never an extract op"
                );
            }
        }
    }

    #[test]
    fn json_entry_bloom_operand_is_blocked_not_bound() {
        // coderdan's review point: SteVec has no match/bloom capability, so
        // `search` is not served. And per this surface's own rule — blocked,
        // never merely omitted — it cannot simply be left unbound either:
        // `json_entry <op> query_text_search` would flatten to native
        // `jsonb <op> jsonb` and answer silently (zero rows, no error). Every
        // operator on the pair resolves to a blocker instead.
        let text: Vec<&str> = json_entry_cross_domains(spec("text"))
            .iter()
            .map(|d| d.name)
            .collect();
        assert_eq!(text, vec!["ord", "ord_ope"]);
        let s = spec("text");
        let served = json_entry_cross_domains(s);
        let blocked = json_entry_cross_blocked_domains(s);
        let sql = render_json_entry_cross_functions(s, &served, &blocked);
        assert!(
            sql.contains(
                "CREATE FUNCTION eql_v3_internal.eq(a public.eql_v3_json_entry, b eql_v3.query_text_search)"
            ),
            "search must get a per-pair blocker, not silent jsonb fallback"
        );
        assert!(
            !sql.contains("eql_v3.eq(a public.eql_v3_json_entry, b eql_v3.query_text_search)")
                || sql.contains(
                    "eql_v3_internal.eq(a public.eql_v3_json_entry, b eql_v3.query_text_search)"
                ),
            "search must never get a public WRAPPER"
        );
        let ops_sql = render_json_entry_cross_operators(s, &served, &blocked);
        // search: 6 operators × 2 directions, all backed by internal blockers.
        assert_eq!(
            ops_sql
                .matches("RIGHTARG = eql_v3.query_text_search")
                .count(),
            6
        );
        assert_eq!(
            ops_sql
                .matches("LEFTARG = eql_v3.query_text_search")
                .count(),
            6
        );
        // No wrapper backs any search pair: every search operator's FUNCTION is
        // eql_v3_internal (metadata-free), and the wrapper-backed count is
        // unchanged from the served operands alone.
        let served_only_ops = render_json_entry_cross_operators(s, &served, &[]);
        assert_eq!(
            ops_sql.matches("FUNCTION = eql_v3.").count(),
            served_only_ops.matches("FUNCTION = eql_v3.").count(),
            "blocked operands must add no public-wrapper-backed operators"
        );
    }

    #[test]
    fn json_entry_type_is_derived_from_the_catalog() {
        // Not a hardcoded literal: a catalog rename or PUBLIC_TYPNAME_PREFIX bump
        // must flow through rather than silently drift (cf. #398 jsonb -> json).
        assert_eq!(json_entry_type(), "public.eql_v3_json_entry");
        assert_eq!(json_entry_stem("integer"), "json_entry_integer");
        assert_eq!(
            json_entry_functions_path("integer"),
            "src/v3/scalars/integer/json_entry_integer_functions.sql"
        );
    }

    #[test]
    fn json_entry_cross_functions_bind_json_entry_to_query_operands() {
        let s = spec("integer");
        let domains = json_entry_cross_domains(s);
        let sql =
            render_json_entry_cross_functions(s, &domains, &json_entry_cross_blocked_domains(s));

        // integer's ord/ord_ope are [Ope]-only. The extract surface serves ORDERING
        // through ord_term — 4 ops × 2 operands × 2 dirs = 16 wrappers — plus
        // equality BLOCKERS — =,<> × 2 operands × 2 dirs = 8 — for 24 functions.
        // Equality is never an extract op; it is document containment.
        assert_eq!(sql.matches("CREATE FUNCTION").count(), 24);
        // Ordering IS a public wrapper through ord_term, both operands, both dirs.
        assert!(sql.contains(
            "CREATE FUNCTION eql_v3.lt(a public.eql_v3_json_entry, b eql_v3.query_integer_ord)"
        ));
        assert!(sql.contains("SELECT eql_v3.ord_term(a) < eql_v3.ord_term(b)"));
        assert!(sql.contains(
            "CREATE FUNCTION eql_v3.lt(a public.eql_v3_json_entry, b eql_v3.query_integer_ord_ope)"
        ));
        // ordering commutator (query on the left).
        assert!(sql.contains(
            "CREATE FUNCTION eql_v3.gte(a eql_v3.query_integer_ord, b public.eql_v3_json_entry)"
        ));
        // Equality is a BLOCKER, never a public wrapper — and never op-equality.
        assert!(sql.contains(
            "CREATE FUNCTION eql_v3_internal.eq(a public.eql_v3_json_entry, b eql_v3.query_integer_ord)"
        ));
        assert!(
            !sql.contains(
                "CREATE FUNCTION eql_v3.eq(a public.eql_v3_json_entry, b eql_v3.query_integer_ord)"
            ),
            "equality must not be a public wrapper on the extract surface"
        );
        assert!(
            !sql.contains("SELECT eql_v3.ord_term(a) = eql_v3.ord_term(b)"),
            "op-equality is gone — equality is document containment, not an extract op"
        );
        // The dropped `_eq` operand never appears, and no hmac equality route
        // is used for an extracted entry.
        assert!(!sql.contains("query_integer_eq"));
        assert!(!sql.contains("eql_v3.eq_term"));
        // Footguns: ordering wrappers are inlinable LANGUAGE sql, unpinned; the eq
        // blockers are LANGUAGE plpgsql (never inlinable, so the RAISE survives).
        assert!(!sql.contains("SET search_path"));
        assert_eq!(
            sql.matches("LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE")
                .count(),
            16
        );
        assert_eq!(sql.matches("LANGUAGE plpgsql").count(), 8);
        // REQUIRE edges pull in both sides (no cycle: the cross file's json deps —
        // json/types.sql + json/functions.sql — are themselves scalar-free; see D3).
        assert!(sql.contains("-- REQUIRE: src/v3/json/types.sql"));
        assert!(sql.contains("-- REQUIRE: src/v3/json/functions.sql"));
        assert!(sql.contains("-- REQUIRE: src/v3/scalars/integer/query_integer_types.sql"));
        assert!(sql.contains("-- REQUIRE: src/v3/scalars/integer/query_integer_ord_functions.sql"));
        assert!(
            sql.contains("-- REQUIRE: src/v3/scalars/integer/query_integer_ord_ope_functions.sql")
        );
        // The dropped `_eq` operand's functions file is NOT required.
        assert!(!sql.contains("query_integer_eq_functions.sql"));
    }

    #[test]
    fn json_entry_cross_operators_carry_planner_metadata() {
        let s = spec("integer");
        let domains = json_entry_cross_domains(s);
        let sql =
            render_json_entry_cross_operators(s, &domains, &json_entry_cross_blocked_domains(s));
        assert_eq!(sql.matches("CREATE OPERATOR").count(), 24);
        // Ordering operators are PUBLIC wrappers carrying commutator/negator/
        // selectivity metadata (operator-free platforms call the wrapper directly).
        assert!(sql.contains("FUNCTION = eql_v3.lt,"));
        assert!(sql.contains(
            "COMMUTATOR = >, NEGATOR = >=, RESTRICT = scalarltsel, JOIN = scalarltjoinsel"
        ));
        assert!(
            sql.contains("LEFTARG = public.eql_v3_json_entry, RIGHTARG = eql_v3.query_integer_ord")
        );
        assert!(sql.contains(
            "LEFTARG = public.eql_v3_json_entry, RIGHTARG = eql_v3.query_integer_ord_ope"
        ));
        // Equality operators are BLOCKERS: backed by eql_v3_internal, metadata-free
        // (equality is document containment, not an extract op).
        assert!(sql.contains("FUNCTION = eql_v3_internal.eq,"));
        assert!(sql.contains("FUNCTION = eql_v3_internal.neq,"));
        assert!(
            !sql.contains("RESTRICT = eqsel"),
            "no eqsel-carrying operator — equality is blocked on the extract surface"
        );
        // The dropped `_eq` operand never appears.
        assert!(!sql.contains("query_integer_eq"));
        assert!(sql.contains("-- REQUIRE: src/v3/scalars/integer/json_entry_integer_functions.sql"));
    }

    #[test]
    fn json_entry_cross_functions_text_emits_ordering_only_never_equality() {
        // text is the dual-term [Hm, Ope] operand shape. Like every family, it emits
        // ORDERING ONLY on the extract surface. `op` is deterministic, so
        // `ord_term(a) < …` is a sound collated order — the same one the scalar
        // `text_ord` domain already ships. Equality is not an extract op at all: it
        // is document containment (`col @> query_json`, value-selector presence).
        // Emitting a public `=` wrapper here would compare `op` — which additionally
        // needs INJECTIVITY that text lacks (cllw-ore's `orderize_string` collates
        // `"café"` and `"cafe"` to the same bytes) — so `=` is BLOCKED instead. This
        // test pins the blocker path for the dual-term operand; the equivalent for a
        // [Ope]-only operand is json_entry_cross_functions_bind_json_entry_to_query_operands.
        let s = spec("text");
        let domains = json_entry_cross_domains(s);
        assert_eq!(
            domains.iter().map(|d| d.name).collect::<Vec<_>>(),
            vec!["ord", "ord_ope"],
            "Bloom-bearing `search` must not bind — SteVec has no match capability"
        );
        let blocked_domains = json_entry_cross_blocked_domains(s);
        let sql = render_json_entry_cross_functions(s, &domains, &blocked_domains);

        // Ordering IS emitted, through ord_term.
        assert!(sql.contains(
            "CREATE FUNCTION eql_v3.lt(a public.eql_v3_json_entry, b eql_v3.query_text_ord)"
        ));
        assert!(sql.contains("SELECT eql_v3.ord_term(a) < eql_v3.ord_term(b)"));
        assert!(sql.contains(
            "CREATE FUNCTION eql_v3.gte(a public.eql_v3_json_entry, b eql_v3.query_text_ord)"
        ));

        // Equality is NOT emitted as a public wrapper, in either direction. This is
        // the false-positive gate; if it regresses, `-> '$.email' = $1` starts
        // matching rows with different plaintext.
        for fun in ["eql_v3.eq(", "eql_v3.neq("] {
            assert!(
                !sql.contains(fun),
                "text json_entry must emit no equality wrapper, found `{fun}`"
            );
        }
        assert!(
            !sql.contains("SELECT eql_v3.ord_term(a) = eql_v3.ord_term(b)"),
            "op-equality on text is a FALSE POSITIVE (orderize_string collates)"
        );

        // Equality IS emitted as a BLOCKER. Omitting it would not make `=` an
        // error: both operands are domains over jsonb, so an unbound `=` falls
        // back to native `jsonb = jsonb` — whole-payload comparison that never
        // matches and returns zero rows silently. The blocker claims the signature
        // so the operator raises instead.
        for blocker in [
            "CREATE FUNCTION eql_v3_internal.eq(a public.eql_v3_json_entry, b eql_v3.query_text_ord)",
            "CREATE FUNCTION eql_v3_internal.eq(a eql_v3.query_text_ord, b public.eql_v3_json_entry)",
            "CREATE FUNCTION eql_v3_internal.neq(a public.eql_v3_json_entry, b eql_v3.query_text_ord)",
        ] {
            assert!(sql.contains(blocker), "missing blocker: {blocker}");
        }
        assert!(
            sql.contains("RAISE EXCEPTION 'operator % is not supported for %'"),
            "the blocker must raise, not return NULL"
        );
        // Never STRICT, never LANGUAGE sql — a STRICT blocker returns NULL on a
        // NULL arg without running the body, and a LANGUAGE sql body is inlinable
        // and can be elided when the planner proves the result unused. Either way
        // the RAISE goes missing and the false positive comes back as a silent NULL.
        assert!(
            !sql.contains("RETURNS boolean IMMUTABLE STRICT PARALLEL SAFE\nAS $$ BEGIN RAISE"),
            "blockers must not be STRICT"
        );
        assert!(sql.contains("END; $$\nLANGUAGE plpgsql;"));

        // The eq_term/hm route never appears for the entry side either — a leaf has
        // no hm, so this would be dead surface rather than a fix.
        assert!(!sql.contains("eql_v3.eq_term"));
        assert!(
            !sql.contains("eql_v3.matches"),
            "Bloom @@ must not be emitted"
        );
        // Served: 2 operands × 2 dirs × (4 ordering wrappers + 2 equality
        // blockers) = 24. Blocked operand (`search`): 6 operators × 2 dirs = 12
        // blockers. Total 36, of which exactly the 16 ordering wrappers are
        // inlinable LANGUAGE sql — the rest are plpgsql blockers.
        assert_eq!(sql.matches("CREATE FUNCTION").count(), 36);
        assert_eq!(
            sql.matches("LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE")
                .count(),
            16
        );
        assert_eq!(sql.matches("LANGUAGE plpgsql;").count(), 20);
        // The Bloom-bearing `search` operand appears ONLY in blocker signatures
        // (eql_v3_internal), never in a public wrapper.
        for wrapper in ["eq", "neq", "lt", "lte", "gt", "gte"] {
            assert!(
                !sql.contains(&format!(
                    "CREATE FUNCTION eql_v3.{wrapper}(a public.eql_v3_json_entry, b eql_v3.query_text_search)"
                )),
                "search must never get a public `{wrapper}` wrapper"
            );
        }
        assert!(sql.contains(
            "CREATE FUNCTION eql_v3_internal.lt(a public.eql_v3_json_entry, b eql_v3.query_text_search)"
        ));
        // Ore / eq / match operands never appear at all.
        assert!(!sql.contains("match_term"));
        assert!(!sql.contains("query_text_match"));
        assert!(!sql.contains("query_text_eq"));
        assert!(!sql.contains("query_text_ord_ore"));
    }

    #[test]
    fn json_entry_temporal_families_are_blocked_not_bound() {
        // coderdan (PR #410): date/timestamp are not valid JSON values — JSON has
        // no temporal type, and in practice those values are marshaled into
        // ISO-8601 STRINGS. A "date leaf" is therefore a TEXT leaf: ordering is
        // served by query_text_ord (ISO-8601 string order IS chronological
        // order), equality by `@>` containment. Binding query_date_ord to
        // json_entry would be dead surface — cipherstash-client refuses to build
        // a SteVec query term from a temporal plaintext
        // (OrderableTerm::try_from(&Plaintext) => Err for NaiveDate/Timestamp),
        // so no real operand could ever reach the comparison.
        //
        // Per this surface's rule — blocked, never merely omitted — the pairs
        // still get exact-signature blockers: unclaimed, `json_entry <op>
        // query_date_ord` would flatten to native `jsonb <op> jsonb` and answer
        // silently. (It is also the one cast that would walk around the text
        // equality block: a date leaf and a text leaf are byte-identically
        // encoded, so `= query_date_ord` on a string leaf would be collated
        // equality by the back door.)
        for family in ["date", "timestamp"] {
            let s = spec(family);
            let served = json_entry_cross_domains(s);
            let blocked = json_entry_cross_blocked_domains(s);
            assert!(served.is_empty(), "{family} must serve no operand");
            let sql = render_json_entry_cross_functions(s, &served, &blocked);
            // 2 operands (ord, ord_ope) × 6 operators × 2 directions = 24
            // blockers, no wrappers.
            assert_eq!(sql.matches("CREATE FUNCTION").count(), 24, "{family}");
            assert_eq!(
                sql.matches("CREATE FUNCTION eql_v3_internal.").count(),
                24,
                "{family}: every function must be an internal blocker"
            );
            assert!(
                sql.contains(&format!(
                    "CREATE FUNCTION eql_v3_internal.eq(a public.eql_v3_json_entry, b eql_v3.query_{family}_ord)"
                )),
                "{family}: = must resolve to a blocker"
            );
            assert!(
                sql.contains(&format!(
                    "CREATE FUNCTION eql_v3_internal.lt(a eql_v3.query_{family}_ord_ope, b public.eql_v3_json_entry)"
                )),
                "{family}: both directions must be claimed"
            );
            // Blocker hygiene: plpgsql, never STRICT, always raises.
            assert_eq!(sql.matches("LANGUAGE plpgsql;").count(), 24, "{family}");
            assert!(
                !sql.contains("STRICT"),
                "{family}: blockers must not be STRICT"
            );
            assert!(sql.contains("RAISE EXCEPTION 'operator % is not supported for %'"));
            // No wrapper, no extractor call — nothing for a caller to invoke.
            assert!(!sql.contains("eql_v3.ord_term"), "{family}");
            assert!(!sql.contains("LANGUAGE sql"), "{family}");

            let ops_sql = render_json_entry_cross_operators(s, &served, &blocked);
            assert_eq!(ops_sql.matches("CREATE OPERATOR").count(), 24, "{family}");
            assert_eq!(
                ops_sql.matches("FUNCTION = eql_v3_internal.").count(),
                24,
                "{family}: every operator must resolve to its blocker"
            );
            assert!(
                !ops_sql.contains("COMMUTATOR"),
                "{family}: blocked operators carry no planner metadata"
            );
        }
    }
}
