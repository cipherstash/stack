# SDD ledger — plan: docs/plans/2026-10-08-python-sdk-tracer.md

Spec: Linear CIP-4340 (read in full, 2026-10-08, via `linear issue view CIP-4340`).
Execution: native (inline), per the user's choice at the plan handoff.
Worktree: `.claude/worktrees/python-sdk-tracer`, branch `worktree-python-sdk-tracer`,
cut from `origin/main` @ 6f388478c.

Setup: Ruling: base branch `feat/stack-encrypt-required-type` → `origin/main` —
#1095 and #1096 were squash-merged into main (no ancestry, so
`merge-base --is-ancestor` says no; the content check says yes). Verified on
`origin/main`: `FieldPlan.target: Option<String>`, the grammar line
`{ "context": …, "target": "<EQL type name>", "type": … }`, `"type"` **required
on every field with a term output**, plus both templates Task 4 needs
(`languages/golang/encrypt/guest/src/targets.rs`,
`packages/eql/crates/eql-bindings/src/encryption/targets.rs`) — cost if wrong:
the branch is cut from the wrong base and every task rebases once.

## Pre-flight scan

| Tasks | Produces → consumes | Finding |
|---|---|---|
| 1 → 2 | `stackencrypt._engine` (module with `version()`) → same | clean |
| 2 → 3 | `_markers`, `errors` → same | clean |
| 2 → 4 | `convert`, `errors` (Rust) → same | clean |
| 3 → 4 | `PlanSpec(model, context, fields)` → Task 4 adds `domains` and rewrites `fields[name]["target"]` from the pair form to the resolved name | **CONFLICT, known.** Task 3's `test_a_target_field_carries_context_and_type_but_no_outputs` asserts the pair form `{"index": "eq", "kind": "Utf8Str"}`; Task 4 Step 5 replaces it with `"TextEq"`. Ruling below. |
| 4 → 5 | `targets::Resolver`, `_engine.check_plan` → same | clean |
| 4 → 7 | `PlanSpec.domains[field]["sql_domain"]`, `["query_sql_domain"]` → same | clean |
| 5 → 6 | `Cipher.encrypt/.decrypt/.query` → same | clean |
| 5 → 7 | same | clean |
| 1-7 → 8 | the suite and the crate → CI invokes them | clean |

Setup: Ruling: the Task 3 / Task 4 `PlanSpec` conflict stands as the plan
wrote it — Task 3 asserts the pair form because that is what `_declare.py`
produces at that point, and Task 4 substitutes the resolved name because
that is what the wire grammar takes. Both assertions are correct at their own
task. Task 4 Step 5 carries the replacement text. — cost if wrong: one
assertion edited twice.

Setup: Ruling: `convert.rs`'s "no declared kind defaults to Int64" branch is
described in the plan as transitional behaviour of the data plan's optional
`"type"`. On `origin/main` `"type"` is **required** on any field with a term
output, so that branch is now reachable only for a passthrough or
ciphertext-only field. Keep the branch (those fields are real) and correct the
comment when Task 2 writes it. — cost if wrong: a stale comment.

Baseline: `cargo build -p stack-encrypt` (the dependency Task 1 adds) and
`cargo metadata --locked` on the root workspace. The repo-wide suite is not the
baseline: nothing in this plan touches the JS packages, EQL or the Go module,
and running their suites would prove nothing about the first failure that
matters here.

Baseline: `cargo metadata --locked` OK; `cargo build -p stack-encrypt` OK
(45.69s, exit 0). Log at `baseline.log`.

Setup: Ruling: every cargo command in this run needs
`dangerouslyDisableSandbox` — the sandbox denies writes to
`~/.cargo/registry`, so cargo cannot cache an index read or a crate
download, and `cargo metadata --locked` fails before it reaches the
lockfile. Sandboxed cargo is not recoverable by allowlisting a host; the
denial is a filesystem write to the shared cargo home. — cost if wrong: cargo
runs outside the sandbox, with the write access a normal local build has.
Task 1: complete (commits 6f38847..3f5a853, tests: ./languages/python/.venv/bin/python -m pytest languages/python/tests -v → ============================== 1 passed in 0.01s ===============================)

Task 1: Ruling: `stack-encrypt` dependency gains `features = ["dynamic",
"http"]` — the plan named neither. `dynamic` is NOT a default and gates the
entire `stack_encrypt::dynamic` module, which is every call site this shell
has; `eql-bindings`' own `stack-encrypt` feature takes the crate with
`default-features = false` and does not enable it, so this crate's line is
what turns it on for the graph. `http` is a default, named explicitly because
Task 5 needs `StackCipher::new()`'s credential discovery and a later
`default-features = false` would remove it silently. — cost if wrong: nothing
compiles, loudly, at the first `use`.

Task 1: Ruling: pyo3 `0.23` → `0.29` — 0.23 predates CPython 3.14, which is
the local interpreter (3.14.2, via mise). `cargo search pyo3` gives 0.29.3 as
current. abi3 would carry a build against an unknown-newer CPython anyway,
but there is no reason to start six years behind. — cost if wrong: a pyo3 API
difference in a later task; 0.29 keeps the `Bound<'_, PyModule>` shape the
plan's code already uses.

Task 1: Ruling: Step 11's `cargo build` → `cargo check && cargo fmt --check
&& cargo clippy --all-targets`. `pyo3`'s `extension-module` deliberately does
not link libpython, so `cargo build` fails with ~40 `Undefined symbols …
"_PyBytes_AsString"` lines on a correct crate. maturin passes `-undefined
dynamic_lookup`, so `maturin develop` in Step 8 is the link check. Plan
updated in place with the reason. — cost if wrong: none; the link is still
proven, by the step that can prove it.

Task 1: Ruling: two `.gitignore` additions the plan did not name — `.venv/`
and friends (maturin needs a virtualenv to install into, and the repo had no
Python ignores at all), and
`languages/python/python/stackencrypt/_engine*.so`, because `maturin
develop` installs editable by writing the built library into the package
SOURCE directory. The second was caught by reading `git status` after
staging: the `.so` was staged. — cost if wrong: a build artefact in git
history.

Task 1: Note (environment, not a ruling): cargo needs
`dangerouslyDisableSandbox` (see Setup), pip needs it too (the proxy's TLS
interception fails CPython's cert verification with `OSStatus -26276`, the
same error `gh` gives), and the repo's node scripts need node >= 20.11 for
`import.meta.dirname` — the shell's `node` and `mise x -- node` are both
20.3.1, so `lint-no-eql-registry-pins.mjs` was run with
`/Users/yuji/.local/share/mise/installs/node/24.11.1/bin/node` and passes
with the new `eql-bindings` path dependency.

Task 2: Ruling: the plan's kind names are wrong — `"Utf8Str"` → `"string"`,
`"Int64"` → `"int64"`, and so on. `dynamic::record`'s parser reads `"type"`
with `ValueKind: FromStr` over `ValueKind::name`'s LOWERCASE vocabulary
(`bool int32 int64 uint32 uint64 float32 float64 string bytes array
object`). `convert::kind` uses that same `parse()` rather than a table of its
own, so the shell cannot disagree with the engine about a name. Every test
and marker updated. — cost if wrong: every declaration is refused with
`Reason::UnknownType`, loudly.

Task 2: Ruling: the plan's `FfiValue` shapes are wrong —
`FfiValue::String` carries `Utf8String` (not `Vec<u8>`), which validates
UTF-8 at construction and holds the bytes in `Protected`; `FfiValue::Bytes`
carries `Protected<Vec<u8>>`. Both use `From`, and reading back needs
`risky_ref` from the `Controlled` trait, so `vitaminc-protected = "0.5.1"` is
a new dependency the plan did not name. `FfiValue` also has `Null`,
`Undefined`, `UInt32`, `UInt64` and `Float32`, all now handled. — cost if
wrong: none; the compiler named each one.

Task 2: Ruling: the plan's invented `Value::kind_of` does not exist. The real
check is `ValueKind::holds(&FfiValue) -> bool`, vitaminc's own, and
`FfiValue::kind() -> Option<ValueKind>` for a message. Using the engine's
predicate is the point — a shell that decided for itself what a kind accepts
would be a second rule. — cost if wrong: none.

Task 2: Ruling: the conversion is EXACT, and deliberately stricter than
`stack_encrypt::dynamic::read`. That function converts a number of another
width when the conversion is lossless, which is right for a QUERY value a
caller wrote as a literal. It is wrong for a stored field: `34` and `34.0`
derive different ORE terms, so accepting a float for a declared integer field
stores terms a later query cannot match. `float32` is refused rather than
narrowed for the same reason. — cost if wrong: a caller who passes `34.0` to
an `int64` field gets an error instead of a silent conversion; the remedy is
to pass `34`.

Task 2: Ruling: `PyObject` is not in pyo3 0.29's prelude; the type is
`Py<PyAny>`. — cost if wrong: none.

Task 2: Ruling: the width markers are a frozen `Kind` dataclass, not bare
strings as the plan wrote them. A bare `"int64"` in an `Annotated` is
indistinguishable from an unrelated `Annotated[str, "a note"]`, and
`_declare.py` would read the note as a declaration. `Kind("int64")` cannot be
confused with anything. — cost if wrong: one more name in the public
surface; backlog item 1 revisits the declaration shape anyway.

Task 2: Ruling: Python `None` encodes to `FfiValue::Null` and is then refused
by the declared kind, rather than being rejected as "no encoding". That keeps
the message accurate (`field declares string, got a value of kind null`) and
leaves `Null` available for a future nullable field, which the spec does not
ask for. Review Focus 4, covered by
`test_none_against_a_declared_kind_is_refused`. — cost if wrong: a nullable
field would need the kind check relaxed, which is a deliberate change rather
than a surprise.
Task 2: complete (commits 3f5a853..023ebe5, tests: ./languages/python/.venv/bin/python -m pytest languages/python/tests -q → 15 passed in 0.01s)

Task 3: Ruling: `_declare.fields` matches a width with `isinstance(e, Kind)`
rather than the plan's `e in _WIDTH_NAMES` string set — the Task 2 ruling
made the width markers a `Kind` dataclass. Covered by
`test_an_unrelated_annotation_is_not_read_as_a_declaration`, which would
have declared the kind "a note for the reader" under the string form. — cost
if wrong: none.

Task 3: Ruling: `"type"` is written for a TARGET field too, though the engine
takes it from the EQL type when absent. The module docs say a declared type
"must be the kind the EQL type is produced from", so writing it buys a free
agreement check between the annotation and the EQL catalog. — cost if wrong:
a declaration whose width disagrees with its EQL type is refused at plan
parse instead of silently taking the catalog's kind, which is the better
failure.

Task 3: Ruling: `PlanSpec.domains` is added NOW, defaulting to `{}`, rather
than in Task 4 as the plan wrote it. The pre-flight scan called the Task 3 /
Task 4 `PlanSpec` change a known conflict; giving the field a default here
means Task 4 fills it instead of changing the dataclass, so no Task 3
assertion moves and the frozen dataclass has one shape across the branch. The
Task 3 tests still assert the PAIR form of `"target"`, which is what
`_declare.py` produces; Task 4's substitution is what turns it into a name.
— cost if wrong: one unused field for one commit.
Task 3: complete (commits 023ebe5..f8f3036, tests: ./languages/python/.venv/bin/python -m pytest languages/python/tests -q → 26 passed in 0.02s)

Task 4: Ruling: `describe` and `convert` were copied verbatim from
`languages/golang/encrypt/guest/src/targets.rs`, as the plan's Step 3 said
to, and the two `todo_*` placeholders are gone. The real types are
`eql_bindings::encryption::targets::{Target, TargetError}` (not `Entry` /
`Error` as the plan guessed), and `plaintext_kind()` is a method. — cost if
wrong: none; these are the one mapping between eql-bindings' catalog and the
engine's, and a second spelling would be a second rule.

Task 4: FINDING from the Go guest's own test, now pinned here too: **the
engine produces exactly one EQL type today, `TextEq`.** Every other catalog
entry resolves `Unproducible`. So `match` and `ore` through an EQL target are
blocked by the CATALOG, not only by week-1 scope — backlog item 5 depends on
the engine producing those types, which is work outside this plan. The
scorecard must say so. `select` lists what is producible in its refusal, so
the message is actionable rather than "no such type".

Task 4: Ruling: `extension-module` moved OUT of `Cargo.toml`'s pyo3 features
and is supplied only by `[tool.maturin].features` in `pyproject.toml`. With
it on by default `cargo test` cannot link (a test binary is its own
executable and must link libpython, which the feature forbids). This is
pyo3's documented arrangement. The wheel still gets the feature; the Rust
tests now run. — cost if wrong: a `cargo build` of the lib now links
libpython, which is fine and is what every non-wheel build wants.

Task 4: Note (environment): `cargo test` here needs
`DYLD_FALLBACK_LIBRARY_PATH` pointing at the interpreter's `LIBDIR`
(`/Users/yuji/.local/share/mise/installs/python/3.14.2/lib`), because the
test binary links libpython by rpath and mise's install is not on the
default search path. Linux CI uses `LD_LIBRARY_PATH`. Task 8 must set it in
the workflow or the Rust tests fail at load with
`Library not loaded: @rpath/libpython3.14.dylib`.

Task 4: Ruling: pyo3 0.29 renamed `Bound::downcast` to `Bound::cast`. — cost
if wrong: none.

Task 4: Ruling: the Task 3 conflict resolved differently from the pre-flight
ruling. I had said Task 3's pair-form assertion "stands"; it does not —
`build()` substitutes the resolved name, so the pair is never visible from
`PlanSpec.fields`. Rather than flip the assertion, the pair is now asserted
against `_declare.fields()` directly
(`test_the_declaration_writes_a_target_request_not_an_eql_name`) and the name
against `build()` (`test_the_resolved_name_replaces_the_pair_in_the_wire_plan`).
Both facts stay covered, each at the layer that owns it — and the first is
the test that would catch an EQL type name creeping into Python. — cost if
wrong: none; strictly more coverage than either single assertion.
Task 4: complete (commits f8f3036d4a..d45f2f3, tests: ./languages/python/.venv/bin/python -m pytest languages/python/tests -q → 37 passed in 0.04s)

Rebase (2026-10-13): the branch was rebased by the user onto `main` @
576b8986e (#1175, Go release pipeline). Tasks 1-4 are now
6c3bc191f..bc785b2e6. One conflict, AGENTS.md's `languages/golang` entry —
main rewrote its last sentence and Task 1 had inserted `languages/python`
after that sentence; resolved by keeping both. Checked after: zero diff in
`packages/stack-encrypt`, `packages/eql/crates/eql-bindings` and
`languages/golang/encrypt/guest` between the bases, so the catalog is still
`TextEq`-only with the same four reasons; wheel rebuilds; 37/37 pass. Task 5's
untracked files survived. Task-done BASE for Task 5 is now bc785b2e6.

Task 5: Ruling: `encrypt` returns a list of DICTS (field name → column value),
not the plan's `list[bytes]`. The engine's result is a `CipherText` tree with
no byte form this shell knows, and SQL wants per-column values anyway: a
target field's EQL JSON as `bytes`, a passthrough's value as itself. `decrypt`
takes the same dicts and rebuilds the tree (`record_tree`, the inverse of
`stored_row`). So no record ever needs a serialised form, and Task 7 inserts
the dict's values directly. — cost if wrong: a caller who wanted one opaque
blob per row has to join the dict; none does.

Task 5: Ruling: a field with a bare `"c"` output (encrypted, not an EQL
target) is REFUSED by `stored_row` / `record_tree` with the field named. Its
node is a sealed subtree the shell cannot turn into a column value without a
tree codec, which the Go host has and this tracer does not need — its path is
EQL targets and passthroughs only. Refusing keeps that a decision rather
than a silent drop. — cost if wrong: a bare-ciphertext column needs the
codec added, which is a deliberate change.

Task 5: Ruling: the live gate is "does `_engine.Engine()` construct", not
"are `CS_*` set". No `CS_*` is set here, but `~/.cipherstash` holds a
`stash auth login` profile and the engine's `AutoStrategy` found it — the
live tests RAN, which the plan's env-var check would have skipped. The
`live` fixture returns the handle and `Cipher(plan, engine=live)` reuses it
across modules. — cost if wrong: a session with no credentials skips with
the engine's own reason in the message, which is better than guessing.

Task 5: Ruling: `plan::target` is idempotent — a bare string is an
already-resolved EQL name and goes back through `targets::named`. `build()`
stores the NAME in `PlanSpec.fields`, and every engine call re-parses those
fields; the first live run failed all eight calls on exactly this. Re-
resolving rather than trusting means a name that stopped being producible
between `build()` and the call is refused at the call. — cost if wrong: one
catalog lookup per call, no I/O.

Task 5: Ruling: `runtime::block_on` is bounded on `IntoFuture`, not
`Future` — the engine's `Pending` is a value that becomes a future when
awaited, so the chain can be built and zipped first. Converted before
`py.detach` so only the future, not `F`, must be `Send`. — cost if wrong:
none; the compiler named both.

Task 5: Ruling: `decrypt_with`'s `expected: Option<Label>` is `None`. It
guards a plan whose context comes from a field of the record
(`context_field` → `ContextMismatch`); this plan declares its context. —
cost if wrong: a context-field plan would skip that check; none exists here.

Task 5: Ruling: `from_ffi` maps `Object` → dict and `Array` → list,
recursively; the plan's version refused every container. An opened row IS an
`Object`. — cost if wrong: none.

Task 5: Ruling: `stack-auth = { path = "../../packages/stack-auth" }` added,
only to NAME `StackCipher<StackKms<stack_auth::AutoStrategy>>` in the
pyclass; stack-encrypt does not re-export `AutoStrategy`. — cost if wrong:
one more path dependency the lockfile already carried transitively.
Task 5: complete (commits bc785b2..8085642, tests: ./languages/python/.venv/bin/python -m pytest languages/python/tests -q → 46 passed in 4.54s)

Task 6: Ruling (plan revised, with the user, 2026-10-13): NO committed
fixture. The plan's `tests/fixtures/record.json` carried an equality term
that is an HMAC under the workspace keyset, so the committed bytes would pass
only in the workspace that generated them — the user's `TCDLFX5CQ6T5LKCP`
here, not CI's. The Rust side is now produced AT TEST TIME by a `parity`
bin (`seal` / `open`) under the same credentials as the Python side, so the
comparison holds in any workspace and nothing keyed to a keyset is
committed. The "do not commit your workspace's value" caveat is gone with
it. — cost if wrong: the parity test needs `cargo` and credentials at test
time; it needed credentials anyway, and the suite already needs a Rust
toolchain to build the wheel.

Task 6: Ruling (wording, from the user's correction): the check is NOT
"Python encrypted" vs "Rust encrypted" — Python never encrypts (G1). It is
the engine invoked THROUGH THE SHELL against the engine with nothing in
front of it, so the one thing it can catch is the shell drifting from the
engine's grammar. Docstrings and the plan say so. — cost if wrong: none; a
wrong description of a right test.

Task 6: Ruling: the record-tree walk moved out of `engine.rs` into
`src/tree.rs`, pure `FfiValue` in/out, and the bin includes it by `#[path]`
along with `targets.rs`. One walk and one resolver serve both sides; a copy
in each is exactly the disagreement the parity test exists to catch. The
bin's `#[allow(dead_code)]` on `mod targets` covers `select`/`named`, which
only the lib's plan resolution calls. — cost if wrong: `#[path]` is a
compile-time include, so a change to either file is a change to both,
which is the point.

Task 6: Note (environment): the bin links pyo3 through `targets.rs`, so like
`cargo test` it needs libpython on the loader path at run time. The test's
`subprocess` sets `DYLD_FALLBACK_LIBRARY_PATH` and `LD_LIBRARY_PATH` from
`sysconfig.get_config_var("LIBDIR")`, so it works under any interpreter
without a hand-set variable. Task 8's workflow needs the same for `cargo
test`. Making `targets.rs` pyo3-free would remove the need; left for the
FFI-comparison backlog item, since it is the kind of seam that decision
cares about.

Task 6: Finding: ciphertexts are never byte-equal (a fresh IV per seal), so
"the bytes agree" can only mean the deterministic TERM bit-for-bit; the
ciphertext is proven by cross-opening. The test says so in its docstring.
Task 6: complete (commits 8085642..a06d448, tests: ./languages/python/.venv/bin/python -m pytest languages/python/tests -q → 50 passed, 3 skipped in 11.53s)

Task 7 (in progress, 2026-10-13): `tests/test_postgres.py` written; it
collects and SKIPS (3) without `DATABASE_URL`, which is its RED until a
database exists. Database: `local/docker-compose.postgres.yml` (the file
CI's `integration-db` composes for its `postgres` variant), port 55432. The
pull of `ghcr.io/cipherstash/postgres-eql:17-2.3.1` was DENIED — the daemon
has a stale/underscoped `ghcr.io` login — and that is the user's credential,
so it is a stop. EQL v3 will be applied from the in-tree bundle
`packages/eql/packages/eql/sql/cipherstash-encrypt.sql` (3.0.6) through
psycopg rather than the `stash` CLI, which is not built here; the image
bakes in EQL v2 only, so the install is needed either way.

Task 7: Ruling: a stored EQL value crosses to psycopg as `Jsonb(bytes.decode())`,
not raw bytes. psycopg sends `bytes` as `bytea`, which no EQL domain
accepts; the domains are declared over `jsonb`. `Jsonb` is an adapter, not
an encoding — the bytes are neither inspected nor reshaped, and the domain
cast in the SQL is what the column applies. — cost if wrong: none for G1;
if a future driver accepts the bytes natively the helper goes away.

Task 7: Ruling (CORRECTS the Jsonb ruling above): a stored EQL value crosses
to psycopg as TEXT with a `::jsonb` cast in the SQL, not as `Jsonb(text)`.
`Jsonb(str)` wraps a Python STRING as the JSON value, so Postgres receives a
JSON string literal, `jsonb_typeof` is `'string'`, and
`eql_v3_text_eq_check` fails — which is how the first live run failed, all
three tests, on a correct engine output. Verified before changing anything:
the engine's JSON is `{v: 3, i: {t, c}, c, hm}` and the domain's check is
exactly `object ∧ has v,i,c,hm ∧ v = '3'`. `json.loads` + `Jsonb(dict)` would
also pass but re-serialises in Python; `text::jsonb` lets Postgres parse the
bytes untouched (G1). — cost if wrong: none; the cast is standard SQL.

Task 7: Ruling: the column is read back as `email::text` and `.encode()`d,
because psycopg loads a `jsonb` column into a Python dict and the shell
takes a stored EQL value as bytes. Postgres serialises the canonical jsonb
text; `.encode()` is the one Python step and reshapes nothing. — cost if
wrong: the canonical text is Postgres's key order, not the engine's; the
EQL type's opener reads keys by name, so order is immaterial (proven: the
read-back record decrypts).

Task 7: FINDING for the scorecard and the catalog: `TextEq` is now proven
end to end in PostgreSQL from Python — insert into `public.eql_v3_text_eq`,
equality query through `eql_v3.query_text_eq`, read back, open. That is the
proof the storage-only `Text` domain's `reason` says it is waiting on.

Task 7: Note (environment): the database was `local/docker-compose.postgres.yml`
(CI's `postgres` variant), image `postgres-eql:17-2.3.1` which bakes EQL v2
only; EQL v3 (3.0.6) was applied from the in-tree bundle
`packages/eql/packages/eql/sql/cipherstash-encrypt.sql` via
`docker exec -i … psql -v ON_ERROR_STOP=1`, because the `stash` CLI is not
built here and the asdf `psql` shim has no version. The GHCR pull needed the
user to re-login (`docker login ghcr.io`); the stored token was stale.
Task 7: complete (commits a06d448..01e09e8, tests: ./languages/python/.venv/bin/python -m pytest languages/python/tests -q → 53 passed in 19.37s)

STOPPED BY DECISION (2026-10-13), after Task 7 of 9. The user is treating
this attempt as a proto-prototype and restarting from `main` in a fresh
session: knowledge gained along the way, and a model they did not mean to
use. Tasks 8 (CI) and 9 (scorecard) were not started. The branch is kept
as `prototype/python-sdk-tracer`, not merged. The distilled handoff is
`docs/plans/2026-10-13-python-sdk-tracer-findings.md`; this ledger is
copied beside it as `…-ledger.md`. No final review was run — there is
nothing to merge — so the final-review section of this ledger is
deliberately absent.
