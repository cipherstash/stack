# Python SDK tracer — findings from the first attempt

**Status:** a proto-prototype, stopped by decision on 2026-10-13 after 7 of 9
tasks, to be restarted fresh. The branch is kept as a reference under
`prototype/python-sdk-tracer`. **Do not merge it.** Read this file, then
CIP-4340, then start again from `main`.

The code is disposable. What follows is not: it is what the code proved,
and most of it would take days to rediscover.

## What was proven, live

Against ZeroKMS (through the `stash auth login` profile) and a Postgres with
EQL v3.0.6 applied — 53 tests green, 3 Rust unit tests green:

1. `import stackencrypt` from an `abi3-py39` wheel built by maturin over
   `stack-encrypt`, in a fourth Cargo workspace at `languages/python`.
2. `Plan.of(User).context("users").build()` reads `Annotated` hints into the
   engine's data plan, fails closed at import on an undeclared field, and
   the engine's own `plan_with` validates the rest with no credentials.
3. `Cipher(plan).encrypt(models)` seals a batch in **one** ZeroKMS request;
   an empty batch makes none; `decrypt` returns the model type; `query`
   returns a term.
4. **Byte parity with Rust**, produced at test time: the shell opens what
   Rust sealed, Rust opens what the shell sealed, and the equality term is
   byte-identical.
5. **The whole six-step path through PostgreSQL**: insert into
   `public.eql_v3_text_eq`, equality query through `eql_v3.query_text_eq`,
   read back, decrypt. This is the "TextEq proven end to end in PostgreSQL"
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
  end to end in PostgreSQL". **Consequence for CIP-4340:** decision 9 lists
  `equality`, `match`, `ore` as the engine features the four tasks need, and
  backlog item 5 is "`match` and `ore` queries". Neither is a Python change;
  both wait on the engine. Amend the ticket before anyone builds against it.
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

1. Amend CIP-4340 decision 9 and backlog item 5 for the catalog gap.
2. Which engine work unblocks `match` (an EQL type over the existing term)
   and `ore` (an algorithm mismatch — larger)?
3. Width markers in annotations: `Annotated[int, Int64, ...]` works; is it
   acceptable to Python developers? (Backlog item 1's user test.)
4. Should `targets.rs` be pyo3-free, so a parity binary does not link the
   interpreter? Relevant to the FFI comparison (backlog item 3).
5. Packaging of the SQLAlchemy layer (above) — put it on the ticket.

## Where the record is

- This branch: `prototype/python-sdk-tracer` — commits
  `6c3bc191f..` (Tasks 1–7), each message self-contained.
- The plan: `docs/plans/2026-10-08-python-sdk-tracer.md` (revised in place).
- The ledger: `docs/plans/2026-10-13-python-sdk-tracer-ledger.md` — every
  ruling with its cost, copied from the gitignored SDD workspace.
- How to run it: `languages/python/README.md`.
