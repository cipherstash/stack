# @cipherstash/prisma-next-example

## 0.1.0-rc.4

### Patch Changes

- Updated dependencies [2e6f032]
- Updated dependencies [cf2c57c]
- Updated dependencies [508f1d5]
  - @cipherstash/prisma-next@1.0.0-rc.4
  - @cipherstash/stack@1.0.0-rc.4

## 0.1.0-rc.3

### Minor Changes

- a75513b: Convert the example app to EQL v3. Every column is now a concrete `public.eql_v3_*` domain authored with the per-domain constructors (`EncryptedTextSearch`, `EncryptedDoubleOrd`, `EncryptedBigIntOrd`, `EncryptedDateOrd`, `EncryptedBoolean`, `EncryptedJson`), wired through `cipherstashFromStackV3({ contractJson })`. The e2e harness runs the full v3 surface against live Postgres + ZeroKMS with no skips: the `eql*` operator vocabulary (equality/range plus `eqlMatch` free-text token search), `eqlAsc`/`eqlDesc` order-term sorting, encrypted JSON containment (`eqlJsonContains` — the v2 `cipherstashJsonb*` helpers do not exist in v3), lossless `bigint` beyond `Number.MAX_SAFE_INTEGER`, and the storage-only `eql_v3_boolean` refusal (`EncryptionOperatorError`) pinned as a feature. Migrations regenerate from the v3 contract: the initial app migration creates the `users` table against the v3 domains with zero `add_search_config` ops, and the cipherstash space carries both bundle baselines (v2 + v3).

### Patch Changes

- Updated dependencies [8b2551a]
- Updated dependencies [a75513b]
- Updated dependencies [4923c0a]
- Updated dependencies [a2f80ea]
  - @cipherstash/stack@1.0.0-rc.3
  - @cipherstash/prisma-next@1.0.0-rc.3

## 0.0.6-rc.2

### Patch Changes

- Updated dependencies [daa25b8]
- Updated dependencies [b085f66]
  - @cipherstash/prisma-next@1.0.0-rc.2
  - @cipherstash/stack@1.0.0-rc.2

## 0.0.6-rc.1

### Patch Changes

- Updated dependencies [e297f64]
- Updated dependencies [40ab142]
- Updated dependencies [5fe9a2f]
- Updated dependencies [7b53141]
  - @cipherstash/stack@1.0.0-rc.1
  - @cipherstash/prisma-next@0.4.0-rc.1

## 0.0.6-rc.0

### Patch Changes

- Updated dependencies [31ca318]
- Updated dependencies [c4787c0]
- Updated dependencies [66a0e02]
- Updated dependencies [cfd46ee]
- Updated dependencies [7eba32d]
- Updated dependencies [0ebf57e]
- Updated dependencies [d73a03c]
- Updated dependencies [89b903f]
- Updated dependencies [229ce59]
- Updated dependencies [50c0a9c]
- Updated dependencies [63ca540]
- Updated dependencies [5d23e80]
- Updated dependencies [1aa9a11]
- Updated dependencies [af2d04e]
- Updated dependencies [b8a3d20]
- Updated dependencies [a0f3b2c]
- Updated dependencies [d6d23be]
- Updated dependencies [f23f952]
- Updated dependencies [7c7dbca]
- Updated dependencies [5411a13]
- Updated dependencies [99f8b0a]
- Updated dependencies [fd33aad]
- Updated dependencies [8cd485d]
- Updated dependencies [9b65ae8]
  - @cipherstash/stack@1.0.0-rc.0
  - @cipherstash/prisma-next@0.4.0-rc.0

## 0.0.5

### Patch Changes

- Updated dependencies [cc62407]
- Updated dependencies [5e4f354]
- Updated dependencies [4ceefed]
- Updated dependencies [cb34d71]
- Updated dependencies [aa9c4b1]
- Updated dependencies [90d19fb]
- Updated dependencies [a5f5422]
- Updated dependencies [35b9ed6]
  - @cipherstash/stack@0.19.0
  - @cipherstash/prisma-next@0.3.2

## 0.0.4

### Patch Changes

- Updated dependencies [6e7ae4e]
- Updated dependencies [712d7fa]
  - @cipherstash/stack@0.18.0
  - @cipherstash/prisma-next@0.3.1

## 0.0.3

### Patch Changes

- Updated dependencies [f743fcc]
  - @cipherstash/stack@0.17.0
  - @cipherstash/prisma-next@0.3.0

## 0.0.2

### Patch Changes

- Updated dependencies [f2aca22]
- Updated dependencies [1c2fdbf]
  - @cipherstash/prisma-next@0.2.0
  - @cipherstash/stack@0.16.0

## 0.0.1

### Patch Changes

- Updated dependencies [dc02d0b]
  - @cipherstash/prisma-next@0.1.0
