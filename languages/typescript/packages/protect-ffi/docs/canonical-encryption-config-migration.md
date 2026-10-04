# CanonicalEncryptionConfig Migration

This document describes the breaking changes introduced when the FFI switched from
hand-rolled encrypt-config types to `cipherstash-config`'s `CanonicalEncryptionConfig`.

## What changed under the hood

The FFI now deserializes the encrypt config directly into
`cipherstash-config::CanonicalEncryptionConfig` rather than the previously
hand-rolled types in `encrypt_config.rs`. The public TypeScript types —
`EncryptConfig`, `CastAs`, `Indexes`, `SteVecIndexOpts`, `SteVecMode` — are
unchanged. Three JS-specific `cast_as` values are remapped to the library's
vocabulary before the config reaches the canonical type.

> **Since #142** that remap runs in Rust, at the deserialization boundary
> (`crates/protect-ffi/src/encrypt_config.rs`), not in a TypeScript layer at
> `newClient`. It applied only to the Neon entry while it was in JS; both
> bindings get it now. Nothing a caller writes changes.

---

## Breaking changes

### 1. SteVec `mode` default changed from `Compat` to `Standard`

The most significant change. A `ste_vec` index that omits `mode` now produces
`Standard` encoding instead of `Compat`. This follows the upstream library
default introduced in `cipherstash-config` 0.34.1-alpha.7.

**Impact:** The two encodings are not cross-compatible. Existing data stored
and indexed under `Compat` encoding cannot be queried using `Standard` encoding.
Any column that has stored ciphertext and relied on the previous `Compat`
default must be re-encrypted after this upgrade.

**To preserve the previous behaviour**, set `mode` explicitly:

```typescript
indexes: {
  ste_vec: {
    prefix: 'table/column',
    mode: 'compat'
  }
}
```

### 2. `match` index now requires a text-family `cast_as`

Previously unvalidated. A `match` index configured on a column whose `cast_as`
is not text-family (`'text'` or `'string'`) now fails at `newClient` with error
code `MATCH_REQUIRES_TEXT`.

**Example that now fails:**

```typescript
// Fails: number is not a text-family cast_as
{
  cast_as: 'number',
  indexes: { match: {} }
}
```

**To fix:** either change `cast_as` to a text-family value, or remove the
`match` index from the column.

Note that `cast_as: 'string'` is translated to `text` internally, so `match`
indexes on `'string'` columns continue to work.

### 3. `v` must be `1`

The config version field was previously unchecked. Any value other than `1`
now fails at `newClient` with error code `UNSUPPORTED_CONFIG_VERSION`.

```typescript
// Fails: v must be 1
{ v: 2, tables: { ... } }
```

### 4. Config-validation error message text changed

Config-validation error messages now come from `cipherstash-config`'s
`ConfigError` rather than the hand-rolled FFI error variants. The wording has
changed.

**Error codes are preserved and extended** — `STE_VEC_REQUIRES_JSON_CAST_AS`
retains the same code. Two new codes are added: `MATCH_REQUIRES_TEXT` and
`UNSUPPORTED_CONFIG_VERSION`. Consumers that branch on the error's `code` are
unaffected. (#146 later moved that `code` onto the thrown `Error` itself and
removed the `ProtectError` wrapper class; the values did not change.)

**Consumers that string-match on `err.message` for config-validation errors
must update their match strings** to align with the new `ConfigError` message
text.

---

## Explicitly not changed

`array_index_mode` still defaults to `'none'` for `ste_vec` indexes. The
underlying library defaults to `'all'`, but `array_index_mode: 'none'` is
injected for any `ste_vec` index that omits the field, preserving the previous
behaviour.

> **Since #142** that injection also runs in
> `crates/protect-ffi/src/encrypt_config.rs` rather than in TypeScript, so the
> wasm build gets the same default. Previously it required a wasm caller to set
> the field by hand, or silently indexed under `'all'`.

---

## Optional follow-ups (non-blocking, captured for future PRs)

The following items were identified during the migration but are not blocking:

- ~~**Unit tests for `inferErrorCode`** — the substring matches that map
  `ConfigError` message text to `ProtectErrorCode` values are currently
  untested. Adding tests would guard against future upstream wording changes
  causing silent code mismatches.~~ Done in #146, though not by testing the
  substrings: they are gone. The three config codes are decided by matching the
  `ConfigError` variant in `From<ConfigError> for Error`, so an upstream
  rewording cannot change them and an upstream rename is a compile error.
- **`Error::Credentials` display message** — the message text for this variant
  still reads "Configuration error" while the variant itself was renamed during
  the Rust refactor. Tightening the display template would improve clarity for
  callers who surface the raw message.

---

## Related documentation

- [JSONB API Reference](./jsonb-api-reference.md) — updated `cast_as` vocabulary,
  validation rules, and `SteVec mode` options
- [JSONB Integration Guide](./jsonb-integration.md) — architecture and data flow
