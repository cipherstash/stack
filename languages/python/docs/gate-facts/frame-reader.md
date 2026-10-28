# Gate fact 1: the extension can read a decrypted record frame

Checked on 28 October 2026 for #1384. The spec in #1341 lists this fact as a gate on the first ticket.

## Result

The fact is true, with one correction to its wording.

The extension can walk the record frame that `stack_encrypt::dynamic::decrypt` returns, and recover each field's value kind. The extension needs only the public API of `stack-encrypt`. No new engine code is needed.

## The correction to the wording

The issue says the extension can "recover the value kind without decrypting". That is not possible for a sealed value. The kind of a sealed value is stored inside its encryption. The doc comment on `dynamic::decrypt` in `packages/stack-encrypt/src/dynamic/record.rs` says: "the type tag is inside the AEAD envelope, so only opening can see it."

The issue also says that the decrypt checks `DECRYPT_FOREIGN_ROW` and `DECRYPT_MALFORMED` depend on this fact. Neither check needs the value kind:

- `DECRYPT_FOREIGN_ROW` compares the stored `i` value with the expected table and column. The `i` value is plain JSON.
- `DECRYPT_MALFORMED` checks that the column value parses as EQL JSON.

What depends on this fact is the step after decrypting. That step builds model instances from the opened record and runs the `DECRYPT_KIND_MISMATCH` check. The spec in #1341 already puts the kind check after decrypting, so the spec needs no change.

## Versions checked

| Crate | Version | Source |
|---|---|---|
| `vitaminc-aead` | 0.8.1 | crates.io |
| `vitaminc-aead-frame` | 0.8.1 | crates.io |
| `stack-encrypt` | commit `98be0721f` | path dependency in this repository |

## How the reader works

`stack_encrypt::dynamic` re-exports the two parts the extension needs:

- `dynamic::frame::Frame::parse` checks that a byte buffer is exactly one frame, before any walk.
- `dynamic::plaintext::Sink` is the trait a walk calls once for each part of a value. The trait is public, and code outside the engine can implement it.

`Sink::scalar(ty, value)` receives each field's logical type, such as `Date`, and its physical value, such as an `i32`. Those two together are the value kind.

```rust
let record = ValueFrame::of(User)?;              // the type dynamic::decrypt returns
let frame = Frame::parse(record.risky_ref())?;   // refuses a malformed frame
frame.visit(Reader { .. })?;                     // a Sink written outside the engine
```

## The probe

The probe is `crates/core/tests/gate_frame_reader.rs`. Run it from `languages/python`:

```
cargo test --locked -p stackencrypt-core --test gate_frame_reader
```

The first test builds a record with a text field, an integer field, a date field, and a passthrough field. A `Sink` in the test file walks the record and records each field's kind, but no values. The second test checks that `Frame::parse` refuses a truncated frame.

Output on 28 October 2026:

```
test malformed_frame_bytes_are_refused_before_any_walk ... ok
test an_outside_sink_recovers_each_field_kind_from_a_record_frame ... ok
test result: ok. 2 passed; 0 failed
```

## What the probe does not show

The probe does not encrypt or decrypt. It builds the record with `ValueFrame::of`. The decrypt path returns the same type, `ValueFrame`, as `Pending<ValueFrame>`. The return type is in `packages/stack-encrypt/src/dynamic/record.rs`, at the `decrypt` function. A round trip through a real cipher is left to the decrypt ticket, #1390.
