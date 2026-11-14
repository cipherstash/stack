# Python SDK tracer — findings from the first attempt

> **Superseded on `next` (2026-10-20).** This is a snapshot of `main` on
> 13 October 2026. The engine has since moved on the `next` branch: a
> record crosses as a frame (`ValueFrame`), not an `FfiValue` tree; Stack
> Encrypt's EQL types are v4 only (`public.eql_v4_text_eq`), not the v3
> domains this tracer stored into; most of the 51 EQL v4 types are
> producible (40 on 2026-10-20; `languages/golang/encrypt/eql/eql_gen.go`
> on `next` says which), not only `TextEq`; and the new kinds (`decimal`,
> `date`, `timestamp`) have landed. Read the engine sections as history. The
> Python and toolchain section (pyo3 0.29, maturin-only `extension-module`,
> libpython on the loader path, `Pending` as `IntoFuture`, width narrowing,
> the psycopg plumbing) still holds. The restart plan reads
> `packages/stack-encrypt/docs/language-integration.md` first; that guide
> is PR #1287, open against `next` as this header is written, and this
> document merges after it.

**Status:** a proto-prototype, stopped by decision on 2026-10-13 after 7 of 9
tasks, to be restarted fresh. The branch is kept as a reference under
`prototype/python-sdk-tracer`. **Do not merge it.** Read this file, then
the Python SDK discovery ticket, then start again from `next`.

The code is disposable. What follows is not: it is what the code proved,
and most of it would take days to rediscover.

## What was proven, live

Against ZeroKMS (through the `stash auth login` profile) and a Postgres with
EQL v3.0.6 applied — 53 tests green, 3 Rust unit tests green:

1. `import stackencrypt` from an `abi3-py39` wheel built by maturin over
   `stack-encrypt`, in a fourth Cargo workspace at `languages/python`.
2. `Plan.of(User).context("users").build()` reads `Annotated` hints into the
   engine's data plan, fails closed at `build()` on an undeclared field
   (import time when that call sits at module level — by convention, not by
   construction; see "Gaps against the discovery ticket's wording"), and the engine's
   own `plan_with` validates the rest with no credentials.
3. `Cipher(plan).encrypt(models)` seals a batch in **one** ZeroKMS request;
   an empty batch makes none; `decrypt` returns the model type; `query`
   returns a term.
4. **Byte parity with Rust**, produced at test time: the shell opens what
   Rust sealed, Rust opens what the shell sealed, and the equality term is
   byte-identical.
5. **The whole six-step path through PostgreSQL**: insert into
   `public.eql_v3_text_eq`, equality query through `eql_v3.query_text_eq`,
   read back, decrypt. This is the "TextEq proven end-to-end in PostgreSQL"
   that the catalog's storage-only `Text` domain records as its own blocker.

Not done: CI (Task 8) and the scorecard (Task 9).

## Findings about the engine and the catalog

These are facts about `main` as of 2026-10-13, independent of any Python
design choice.

- **`stack-encrypt`'s `dynamic` feature is the entire binding surface, and
  it is off by default.** `stack_encrypt::dynamic::record` — the data plan,
  `FfiValue`, `plan_with`, `encrypt_with`, `decrypt_with`, `query` — does not
  exist without it. `eql-bindings`' own `stack-encrypt` feature takes the
  crate with `default-features = false` and does **not** enable it; the
  binding crate must. `http` (credential discovery) is a default and should
  be named explicitly so it cannot be dropped silently.
- **The catalog produces exactly one EQL type: `TextEq`.** Every other entry
  resolves `Unproducible`, with four recorded reasons: 42 types because
  "how this family encodes a plaintext for the stack-encrypt producer
  profile is not specified; only the text family's encoding is"; `TextMatch`
  and the `Ope` types because "the engine derives match and OPE terms, but
  no EQL type is built from them yet"; the ORE types because "EQL stores a
  block ORE term and the engine derives a CLLW ORE term; the two are
  different algorithms"; `Text` because it "follows once TextEq is proven
  end-to-end in PostgreSQL". (Superseded: both are producible on `next`;
  see open question 1.) **Consequence for the discovery ticket:** decision 9 lists
  `equality`, `match`, `ore` as the engine features the four tasks need, and
  backlog item 5 is "`match` and `ore` queries". Neither is a Python change;
  both wait on the engine. Amend the ticket before anyone builds against it.
- **The engine-side design for that gap already exists:** "Value encodings
  for new EQL kinds" (7 Oct 2026, the same day as the discovery ticket's
  decisions; an internal design draft, since landed on `next` as
  `vitaminc-ore` and the new kinds, so the engine source is now the
  reference). What it established at the time:
  - The 42 non-text families are tracked in **#1130** and are "blocked on
    encoding, not on code". A kind must exist in **three** encodings owned
    by three crates — the ciphertext tag (`vitaminc-aead-value`), the
    equality domain (`vitaminc-prf`), the order encoding (`cllw-ore` /
    `ore-rs`) — and today they disagree about which types exist (`i16` is in
    two of three, so it cannot be a kind).
  - The ORE refusal is **#1132**: EQL v3 stores **block ORE** for the
    `_ord_ore` domains and **CLLW OPE** for `_ord` / `_ord_ope`; Stack
    Encrypt derives CLLW ORE and CLLW OPE and no block ORE. That is why
    `TextOrdOre` is refused although text is a kind.
  - The proposal: a `vitaminc-ore` crate with one order-preserving plaintext
    encoding (adopting `orderable-bytes`) and pluggable schemes (block ORE,
    CLLW ORE, CLLW OPE); new kinds `Int16`, `Date`, `Timestamp`, `Decimal`
    with new frozen tags from `0x0C`; a conformance test that fails unless
    every kind has all three encodings.
  - It does **not** cover `TextMatch`, whose blocker is different ("the
    engine derives match terms, but no EQL type is built from them yet").
    So `match` is a smaller, separate, unticketed piece of work; `ore` is
    this proposal.
  - **It reaches Python directly.** The kind table is "a cross-language
    commitment", and every new kind means a codec "in each binding": when
    `Int16` / `Date` / `Timestamp` / `Decimal` land, the shell's
    `convert.rs` grows an arm each, the width markers gain four names, and
    `Date` versus `Timestamp` is the same declaration ambiguity it already
    flags for Go's `time.Time`. The restart's declaration shape should
    leave room for that rather than hard-code today's nine scalar kinds.
- **The engine core does more than the catalog.** Through the bare-outputs
  path (`"outputs": ["c", "match"]`) it seals any kind and derives `eq`,
  `match`, `ore`, `ope`. What is `TextEq`-only is the *framing* into an EQL
  v3 column type, which is `eql-bindings`' catalog, not the engine.
- **`"type"` is required on every field with a term output** (#1096, now on
  `main`), and `admits` decides which kinds an index accepts: `Equality`
  takes the integer kinds, `string`, `bytes`; `Match` takes `string` only;
  `Ore`/`Ope` take anything but arrays and objects. Kind names are
  vitaminc's lowercase vocabulary (`string`, `int64`, `float64`, `bool`…),
  parsed with `ValueKind: FromStr`; use that parser, never a table.
- **A stored record is a `CipherText` tree, not bytes.** Per row a `Map`;
  per field a `Map` keyed by output: a target field's EQL JSON rides as a
  passthrough `FfiValue::Bytes` under `"eql"`, a passthrough field's value
  as a passthrough `FfiValue` under `"passthrough"`, a ciphertext as a
  sealed subtree under `"c"`. The first two extract directly to column
  values; the third needs a tree codec (the Go host has one). The tracer
  refused bare-`"c"` fields by name and lost nothing.
- **Ciphertexts are never byte-equal** (fresh IV per seal). "The bytes
  agree" can only mean the deterministic equality term; the ciphertext is
  proven by cross-opening.
- **The EQL identifier `i` is stamped from the plan's context** at encrypt
  time — `{"t": "<first context piece>", "c": "<field name>"}` — and is
  authenticated into the ciphertext. `.context("<table>")` and the SQL
  table should be the same word. Postgres does not check it.
- **Credentials:** `StackCipher::new()` → `AutoStrategy`: `CS_CLIENT_ACCESS_KEY`
  + `CS_WORKSPACE_CRN` (`auto_strategy.rs:120`), else the device session in
  `~/.cipherstash/<current_workspace>/auth.json` (`:129-133`); the client
  key likewise from `CS_CLIENT_ID`/`CS_CLIENT_KEY` or `secretkey.json`. A
  logged-in developer machine needs nothing set. **Any committed bytes
  keyed to a workspace keyset (equality terms) pass only in that
  workspace.** Produce the Rust side of a parity check at test time instead.
- **`TextEq` needs nothing from Postgres that does not already exist**, which
  is part of why it could ship first. Equality lives entirely in `hm`, the
  HMAC; the ciphertext `c` is sealed with a fresh IV, so two stored values
  for the same plaintext are *different* JSON and an index on the column
  itself never matches. The index EQL v3 is built for is a functional one on
  the extracted term —
  `create index … using hash (eql_v3.eq_term(col))` (or `btree`:
  the term's type rides on `bytea`'s default operator classes, so both work
  and only `=` means anything) — and the bundle marks the extractor
  `IMMUTABLE` and inlinable so the domain's `=` operator folds into the
  query and the planner engages that index "structurally". The tracer
  created **no** index on the encrypted column; its equality queries were
  sequential scans. The ORE / OPE domains are the ones that need EQL's own
  operator classes, because their terms do not sort as bytes.

## Findings about Python and the toolchain

- **pyo3 0.29, not 0.23**, for CPython 3.14. `abi3-py39` gives one wheel
  per platform and builds against an interpreter newer than pyo3 knows.
  Renames since the plan was written: `downcast` → `cast`, `allow_threads`
  → `detach`, `PyObject` → `Py<PyAny>`.
- **`extension-module` must be maturin-only** (`[tool.maturin].features`),
  not in `Cargo.toml`. On by default it stops `cargo test` and `cargo build`
  linking (`Undefined symbols … _Py*`); maturin supplies
  `-undefined dynamic_lookup`. `cargo check` is the compile check,
  `maturin develop` the link check.
- **Anything that links pyo3 outside a wheel needs libpython on the loader
  path** at run time (`DYLD_FALLBACK_LIBRARY_PATH` / `LD_LIBRARY_PATH` =
  `sysconfig.get_config_var("LIBDIR")`), including `cargo test` and a
  parity binary. CI must set it.
- **`Pending` is `IntoFuture`, not `Future`.** A sync shell is one Tokio
  runtime, `into_future()` *before* `py.detach`, then `block_on`. There is
  no second engine entry for sync, which keeps G6 reachable when async
  comes.
- **Python's `int` has no width** and `34`/`34.0` derive different ORE
  terms, so the annotation carries one (`Int64`, `Text`, …) and the shell
  narrows exactly — stricter than `dynamic::read`, which converts lossless
  widths and is right only for query literals. Check `bool` before `int`.
  `None` encodes to `FfiValue::Null` and is refused by the declared kind.
- **The width markers should be a type, not a bare string**, or an unrelated
  `Annotated[str, "a note"]` reads as a declaration.
- **psycopg plumbing** that touches no bytes: send a stored EQL value as
  text with `::jsonb` in the SQL (`Jsonb(str)` wraps a JSON *string* and
  fails the domain check); read it back as `email::text` and `.encode()`
  (psycopg otherwise returns a `dict`). Postgres reorders keys; read by
  name, never by position.
- **Environment quirks on this machine:** cargo and pip need the sandbox
  off (shared `~/.cargo` writes; the proxy's TLS breaks pip and `gh`);
  the repo's node scripts need node ≥ 20.11 (`import.meta.dirname`) — the
  shell's is 20.3.1, mise has 24.11.1; `ghcr.io/cipherstash/postgres-eql`
  needs a fresh `docker login ghcr.io`; the asdf `psql` shim has no
  version, so install EQL through the container's own `psql`.

## Design decisions made along the way (provisional — reviewers decide)

- Targets resolve by **(kind, index)**, not by EQL name: Python writes
  `{"kind": "string", "index": "eq"}` and the engine answers `TextEq` plus
  both SQL domains. No EQL name is written in Python. An explicit
  `EQL(name=...)` escape hatch exists.
- A **record is a dict of field name → column value** (EQL JSON as `bytes`,
  passthrough as itself). It is what SQL wants, and no record ever needs a
  serialised form.
- The **SQLAlchemy layer should be a separate PyPI distribution**, pure
  Python, depending on the core wheel — the user's call on 2026-10-13;
  not yet on the ticket. Backlog item 2 covers the call site, not the
  shipping unit, so this is unowned.
- The live-test gate is "does the engine construct", not "are `CS_*` set".

## Gaps against the discovery ticket's wording, found on re-reading

Two places where what was built is narrower than what the ticket says, and
the findings above would otherwise imply the ticket was met.

- **"The engine checks the declaration when Python defines the class"
  (week-1 step 2) — not quite.** The check runs at `build()`, one call
  later, wherever the caller puts that call.
  `Plan.of(User).context(…).build()` at module scope runs at import time
  **by convention**, because the call sits at module scope; nothing fires
  when the `class` statement finishes. A class decorator — `@stash.model("users")` above `@dataclass`
  — would run `build()` at class definition **by construction**, hold the
  `PlanSpec` on the class, and let the call site be `Cipher(User)`. It is a
  second way in (G6), so it has to earn its place: it carries the context,
  which is per-model and which `Annotated` cannot express, and it reaches
  the moment the ticket names. The stronger form makes it *the* way and
  retires `Plan.of` from the public surface. Costs: decorator order
  (`@dataclass(slots=True)` returns a new class, so a plan set below it is
  lost; a transforming base such as Pydantic's or SQLAlchemy's declarative
  may rewrite the class after it was read), and committing to "the model
  class owns its plan". A plain `@dataclass` below the decorator is
  **fine** — a class's annotations exist before `@dataclass` runs, so an
  earlier claim that the wrong order "sees no fields" was mistaken. Backlog
  item 1.
- **The model contract is not "a dataclass", and should not become one.**
  psycopg imposes nothing — it sees tuples and parameters. The shell relies
  on exactly three things: annotated fields readable through
  `get_type_hints(cls, include_extras=True)`; attribute access (`getattr`)
  on the way in; and a **keyword-argument constructor** matching the field
  names on the way out (`model(**row)` in `decrypt`). Dataclasses meet that
  with the least ceremony, which is the only reason the tracer used them.
  So do `attrs`, Pydantic, `NamedTuple`, and SQLAlchemy declarative models
  (default constructor takes kwargs) — the first user's actual classes.
  Restricting to `@dataclass` would exclude them while enforcing more than
  the code needs. State the contract explicitly (a `Protocol`), and let the
  SQLAlchemy layer supply a base that meets it. `is_dataclass` is the cheap
  guard for decorator order, not the right one.

## Defects found in the plan (`2026-10-08-python-sdk-tracer.md`)

All ruled on and ledgered; listed so the restart's plan does not repeat them:
missing `dynamic`/`http` features; pyo3 0.23; `cargo build` as a check;
`"Utf8Str"`-style kind names; `FfiValue::String(Vec<u8>)` (it is
`Utf8String`); an invented `Value::kind_of`; a committed workspace-keyed
fixture; "Python encrypted" wording (Python never encrypts — the check is
the engine *through the shell* against the engine bare); the record as
`list[bytes]`; `decrypt_with`'s fifth argument (`expected: Option<Label>`,
`None` for a declared context).

## Open questions for the restart

1. Re-read the discovery ticket's decision 9 and backlog item 5 against
   `next`, not against the catalog gap this document recorded on 13
   October. On `next` 40 of the 51 EQL v4 types are producible
   (`languages/golang/encrypt/eql/eql_gen.go` says which): `Text`,
   `TextMatch`, `TextSearch` (#1274) and the block ORE `Ord` types (#1280)
   among them, both merged on 2026-10-19. The 11 that are not are the
   order terms for `date`, `timestamp` and `decimal`, whose ordering is
   not decided, and the two JSON types (#1060). Amend the ticket from
   that list, and name only the dependencies that remain.
2. Which of those lands first, and does the week-1 restart wait for any of
   them? (Nothing in the six-step path needs them; `TextEq` is enough to
   prove the path, which it did.)
3. Width markers in annotations: `Annotated[int, Int64, ...]` works; is it
   acceptable to Python developers? (Backlog item 1's user test.)
4. Should `targets.rs` be pyo3-free, so a parity binary does not link the
   interpreter? Relevant to the FFI comparison (backlog item 3).
5. Packaging of the SQLAlchemy layer (above) — put it on the ticket.
6. Declaration entry point: keep `Plan.of(cls).context(…).build()`, add a
   class decorator beside it, or make the decorator the one way? This
   decides whether "checked when the class is defined" holds by
   construction.
7. The model contract: write it down as a `Protocol` (annotated fields,
   attribute access, kwargs constructor), and check SQLAlchemy declarative
   models against it before the layer is designed.
8. Indexing guidance for the SDK docs: the functional hash index on the
   extracted term is the one a `TextEq` column wants; on the v4 bundle the
   restart installs that is `eql_v4.eq_term(col)` on a
   `public.eql_v4_text_eq` column (`eql_v3.eq_term` on v3; there is no
   `_internal` extractor). The tracer never created one, and a user
   copying its SQL would not either.

## Where the record is

- The prototype branch: `prototype/python-sdk-tracer` — commits
  `6c3bc191f..` (Tasks 1–7), each message self-contained. This document
  and the ledger land on `next`; the files below exist only on that
  branch.
- The plan: `docs/plans/2026-10-08-python-sdk-tracer.md` on the prototype
  branch (revised in place there).
- The ledger: `docs/plans/2026-10-13-python-sdk-tracer-ledger.md` — every
  ruling with its cost, copied from the gitignored SDD workspace.
- How to run it: `languages/python/README.md` on the prototype branch.
