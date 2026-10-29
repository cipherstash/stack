# Gate fact 2: an interrupt waits for the engine call, and dropped requests wipe their plaintext

Checked on 28 October 2026 for #1384. The spec in #1341 lists this fact as a gate on the first ticket. The sync contract for engine calls depends on it.

## Result

Both parts of the fact are true.

1. A `KeyboardInterrupt` sent during a call that released the GIL is raised only after the call returns. This was checked by running a probe.
2. A `Pending` that is dropped before it settles wipes the plaintext it contains. This was checked by reading the source, not by running anything.

The GIL is CPython's global interpreter lock. While a call has released it, other Python threads can run, and the Rust code runs without checking for Python signals.

## Part 1: the interrupt waits for the call

### The probe

The probe has two halves:

- `_probe_detached_sleep(millis)` in `crates/engine/src/lib.rs`. The function releases the GIL with `py.detach`, then blocks on a multi-thread tokio runtime for `millis` milliseconds. An engine call will block in the same way. The function exists only when the cargo feature `gate-probe` is built, and that feature is off in every normal build.
- `tests/test_gate_keyboard_interrupt.py`. The tests send `SIGINT` to the process 0.2 seconds into a 1-second call. They skip themselves when the extension was built without the feature.

Run it from `languages/python`:

```
MATURIN_PEP517_ARGS="--profile dev --features gate-probe" mise run build
.venv/bin/python -m pytest tests/test_gate_keyboard_interrupt.py -v
mise run build   # rebuild without the probe afterwards
```

### What it showed

Output on 28 October 2026, on macOS 14.8.9 (arm64) with Python 3.14.7 and pyo3 0.29.3:

```
test_interrupt_waits_for_the_detached_call_to_return PASSED
test_the_extension_is_usable_after_an_interrupt PASSED
1.02s call  test_the_extension_is_usable_after_an_interrupt
1.01s call  test_interrupt_waits_for_the_detached_call_to_return
```

- The `KeyboardInterrupt` arrived after 1.01 seconds. The signal was sent at 0.2 seconds, so the call was not cut short.
- After an interrupt, a second call to the extension succeeded.

As a control, the same signal interrupted a plain Python `time.sleep(1.0)` after 0.21 seconds. That shows the test sends the signal in time to interrupt a wait that does not release the GIL in Rust.

### What part 1 does not show

- The probe blocks on a tokio sleep, not on a real engine call. A real call adds network I/O to ZeroKMS. We expect network I/O to make no difference to how Python delivers a signal. A real call was not run.
- Only macOS was tested. Linux was not run. Windows was not tested, because the test sends the signal with `os.kill`.
- Only Python 3.14.7 was tested. The package supports Python 3.9 and later.

## Part 2: a dropped `Pending` wipes its plaintext

A `Pending` in `stack-encrypt` is a set of ZeroKMS requests plus a closure that builds the result from the responses. It is defined in `packages/stack-encrypt/src/target/pending.rs`. Dropping it before it settles drops the closure and everything the closure contains.

### What a `Pending` contains before it settles

- On encrypt, each field's plaintext. The engine stores it as a `ValueFrame` or as vitaminc's sealing `Pending`. Both keep their bytes in `Protected<Vec<u8>>`.
- On decrypt, only ciphertext and the plan. No plaintext exists until the key responses arrive.

`Protected<Vec<u8>>` wipes its bytes when it is dropped. `vitaminc-protected` 0.8.1 derives `ZeroizeOnDrop` for it, in `src/protected/mod.rs`, and has a test for that exact type.

The engine states the same rule for itself. The module docs in `packages/stack-encrypt/src/dynamic/mod.rs` say the engine stores a plaintext as a `ValueFrame`, "in a buffer wiped when it drops".

### Two exceptions, neither of them secret plaintext

- A passthrough value is a `PassthroughFrame`. That type is a plain `Vec<u8>`, so it is not wiped. Passthrough values are stored unencrypted, so this is by design.
- While a value is walked, a scalar can sit briefly on the stack as a plain integer. That copy is not wiped. `packages/stack-encrypt/src/value.rs`, lines 34 to 36, says so.

### What part 2 does not show

Nothing was run for part 2. A runnable check would drop a real `Pending` and read its memory afterwards, as `dropping_wipes_the_value_in_place` in `packages/stack-encrypt/src/value.rs` does for single values. That check needs a cipher with a fake key source. The EQL test crate in `packages/eql/tests/encryption` has one.
