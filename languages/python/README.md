# stackencrypt (tracer)

A tracer for the Python SDK. Not released, and not for production.

## Run the round trip

1. Install the toolchain. maturin needs a virtual environment to install
   into, so make one:

       cd languages/python
       python3 -m venv .venv
       .venv/bin/pip install maturin
       .venv/bin/maturin develop --extras test

2. Set credentials (or run `npx stash auth login` first):

       export CS_WORKSPACE_CRN=... CS_CLIENT_ID=... CS_CLIENT_KEY=... CS_CLIENT_ACCESS_KEY=...

3. Start Postgres with EQL v3 installed, and point the tests at it:

       npx stash eql install --eql-version 3
       export DATABASE_URL=postgres://...

4. Run it:

       .venv/bin/python -m pytest tests -v

Tests that need credentials or a database skip without them, so step 4 runs
with nothing set — it just proves less.

## What it does

See `scorecard.md` for which of the eight SDK design principles hold, strain
or are untested.

## Notes for the next person

- **`stack-encrypt`'s `dynamic` feature is not a default**, and it is the
  whole of what this shell calls. `Cargo.toml` names it explicitly; dropping
  it removes `stack_encrypt::dynamic` and every call site here stops
  resolving.
- **This is its own Cargo workspace**, excluded from the root one, because it
  takes a path dependency on `eql-bindings` from the EQL workspace. The
  comment at the top of `Cargo.toml` has the reason.
- **One wheel per platform, not per interpreter.** The `abi3-py39` feature is
  what buys that. It is also what lets the crate build against a CPython
  newer than pyo3 knows about.
