---
'@cipherstash/protect-ffi': patch
---

Compile `eql-bindings` from this repository rather than from crates.io.

The native binding pinned `eql-bindings = "=3.0.2"` from the registry. It now
resolves by path from `packages/eql/crates/eql-bindings`, which ships at 3.0.5
alongside the `@cipherstash/eql` SQL bundle.

**No behaviour change.** `eql-bindings` is the Rust half of EQL — it EMITS the
encrypted payloads that the SQL half STORES and queries — and its Rust source is
byte-identical across 3.0.2, 3.0.4 and 3.0.5 (`src/`, `bindings/` and `schema/`
compared directly). What 3.0.3 through 3.0.5 changed was SQL, carried on the
shared lockstep version number. So the payloads this binding produces are the
same bytes before and after; what moves is the version stamped on the crate
compiled into `index.node`, from 3.0.2 to 3.0.5.

**Why it is worth a release anyway.** A registry pin let the two halves of EQL
drift apart silently. Nothing asserted they agreed: a mismatched pair compiles,
passes every suite, and fails in a database — because the failure is a payload
the installed SQL cannot read, which no unit test holds both sides of. Resolving
from the tree makes the skew unrepresentable: the emitter and the SQL are now
the same commit, and `pnpm run lint:eql-pins` fails any change that reintroduces
a registry pin on either.

The flip was taken while it was a no-op deliberately. Waiting for the first
release where the two halves genuinely diverge would have turned a provenance
change into a behaviour change that had to be argued under credentialed test.

Verified without credentials: `cargo build -p protect-ffi` clean, the crate test
suite green (310 passed) with `cargo fmt --check` clean, and a
`wasm32-unknown-unknown` build clean — the last of those being the target where a
cross-workspace path dependency would break first, since the EQL workspace never
otherwise builds for wasm32.
