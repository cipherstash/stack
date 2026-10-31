# EQL encryption fixtures

| File | Written by | Regenerated? |
| --- | --- | --- |
| `v4_rows.json` | the Go SDK's `TestV4RowsMatchTheCommittedFixture` | yes, with `EQL_UPDATE_FIXTURES=1` |
| `v4_queries.json` | the by-name dispatch in `tests/v4_types.rs` | yes, with `EQL_UPDATE_FIXTURES=1` |
| `v4_ordered_queries.json` | the by-name dispatch in `tests/v4_order.rs` | yes, with `EQL_UPDATE_FIXTURES=1` |
| `v4_ordered_rows.json` | the Go SDK's `TestV4OrderedRowsMatchTheCommittedFixture` | yes, with `EQL_UPDATE_FIXTURES=1` |
| `v4_ledger_queries.json` | the by-name dispatch in `tests/v4_date_time_numeric.rs` | yes, with `EQL_UPDATE_FIXTURES=1` |
| `v4_ledger_rows.json` | the Go SDK's `TestV4LedgerRowsMatchTheCommittedFixture` | yes, with `EQL_UPDATE_FIXTURES=1` |
| `text_eq_query.json`, `ste_vec_selectors.json` | `tests/text_eq.rs`, `tests/ste_vec_selectors.rs` | yes, see each test |
| `v4_smallint_rows.json` | the Go SDK's `TestV4SmallintRowsMatchTheCommittedFixture` | yes, with `EQL_UPDATE_FIXTURES=1` |
| `stored_v4_rows_v1.json` | copied from `v4_rows.json` at the next build | **never: frozen** |

`v4_ordered_queries.json` and `v4_ordered_rows.json` are not frozen: their
`op` bytes are the order terms Stack Encrypt writes today, so a change that moves
those bytes regenerates both together (Go writes the rows, Rust writes the
queries, each with `EQL_UPDATE_FIXTURES=1`). No frozen
`stored_v4_ordered_rows_*` file exists yet; one is cut once the order-term
bytes are final.

## `stored_v4_rows_v1.json` (FROZEN)

`Profile` rows the Go SDK's generated code stored with the `next` build, one
value of every EQL v4 type that build produced. Types made producible since
are sealed into their own regenerable row fixtures (see the table above),
the date, timestamp and numeric types by their own Go model (`Ledger`) into
`v4_ledger_rows.json`; a later frozen file covers them once it is cut.
`v4_rows.json` proves
the Go SDK and Rust agree *today* and is regenerated when the encoding moves.
This file is the opposite: it is never regenerated or edited, so a change
that breaks rows already stored fails instead of being regenerated away.

- `tests/v4_types.rs` (`frozen_rows_the_go_sdk_stored_still_open`) parses
  every stored value as its v4 type and opens it to the row's plaintext.
- `languages/golang/encrypt/eql_v4_test.go` (`TestFrozenV4RowsStillOpen`)
  seals the rows' plaintexts again and requires the same envelopes and
  terms (everything but each `c`), and opens every committed `c`.

Nothing writes this file and no environment variable redirects either test
to another file. **If either test fails, the change broke stored data.** Do
not regenerate the file. Fix the change, or, for a deliberate change to the
stored format, add `stored_v4_rows_v2.json` beside this one, keep v1, and
say in the CHANGELOG how v1 rows migrate.

The data-plan records Stack Encrypt stores outside EQL are frozen the same
way in `packages/stack-encrypt/tests/fixtures/stored_rows_v1.json`.
