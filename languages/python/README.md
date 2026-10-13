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

3. Start the repo's local Postgres (the same file CI composes), install
   EQL v3 into it from the in-tree bundle, and point the tests at it. The
   image bakes in EQL v2 only, so the install is needed either way; the
   bundle is plain SQL, and the container's own `psql` applies it. The
   image is on a private registry: `docker login ghcr.io` first if the pull
   is denied.

       docker compose -f local/docker-compose.postgres.yml up -d --wait
       docker exec -i cs-integration-postgres-postgres-1 \
         psql -q -v ON_ERROR_STOP=1 -U cipherstash -d cipherstash \
         < packages/eql/packages/eql/sql/cipherstash-encrypt.sql
       export DATABASE_URL=postgres://cipherstash:password@localhost:55432/cipherstash

   (`npx stash eql install --eql-version 3` does the same install through
   the CLI, once that is built.)

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
