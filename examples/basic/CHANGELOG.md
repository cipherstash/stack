# @cipherstash/basic-example

## 1.2.11

### Patch Changes

- Updated dependencies [f743fcc]
  - @cipherstash/stack@0.17.0

## 1.2.10

### Patch Changes

- Updated dependencies [1c2fdbf]
  - @cipherstash/stack@0.16.0

## 1.2.9

### Patch Changes

- Updated dependencies [afe6810]
  - @cipherstash/stack@0.15.3

## 1.2.8

### Patch Changes

- Updated dependencies [510c485]
  - @cipherstash/stack@0.15.2

## 1.2.7

### Patch Changes

- Updated dependencies [8513705]
  - @cipherstash/stack@0.15.1

## 1.2.6

### Patch Changes

- Updated dependencies [1929c8f]
  - @cipherstash/stack@0.15.0

## 1.2.5

### Patch Changes

- Updated dependencies [1e0d4c1]
  - @cipherstash/stack@0.14.0

## 1.2.4

### Patch Changes

- Updated dependencies [068f820]
  - @cipherstash/stack@0.13.0

## 1.2.3

### Patch Changes

- Updated dependencies [15764a8]
  - @cipherstash/stack@0.12.0

## 1.2.2

### Patch Changes

- Updated dependencies [b0e56b8]
  - @cipherstash/stack@0.11.0

## 1.2.1

### Patch Changes

- Updated dependencies [5245cd7]
  - @cipherstash/stack@0.10.0

## 1.2.0

### Minor Changes

- 2b907a1: Improve CLI user experience for developer onboarding.

### Patch Changes

- Updated dependencies [2b907a1]
  - @cipherstash/stack@0.9.0

## 1.1.22

### Patch Changes

- Updated dependencies [3414761]
  - @cipherstash/stack@0.8.0

## 1.1.21

### Patch Changes

- Updated dependencies [1be8f81]
  - @cipherstash/stack@0.7.0

## 1.1.20

### Patch Changes

- Updated dependencies [0b9fd7a]
  - @cipherstash/stack@0.6.0

## 1.1.19

### Patch Changes

- Updated dependencies [a645115]
  - @cipherstash/stack@0.5.0

## 1.1.18

### Patch Changes

- Updated dependencies [5c3f4e7]
  - @cipherstash/stack@0.4.0

## 1.1.17

### Patch Changes

- Updated dependencies [db72e2c]
- Updated dependencies [e769740]
  - @cipherstash/protect@10.5.0

## 1.1.16

### Patch Changes

- Updated dependencies [9ccaf68]
  - @cipherstash/protect@10.4.0

## 1.1.15

### Patch Changes

- Updated dependencies [a1fce2b]
- Updated dependencies [622b684]
  - @cipherstash/protect@10.3.0

## 1.1.14

### Patch Changes

- @cipherstash/protect@10.2.1

## 1.1.13

### Patch Changes

- Updated dependencies [de029de]
  - @cipherstash/protect@10.2.0

## 1.1.12

### Patch Changes

- Updated dependencies [ff4421f]
  - @cipherstash/protect@10.1.1

## 1.1.11

### Patch Changes

- Updated dependencies [6b87c17]
  - @cipherstash/protect@10.1.0

## 1.1.10

### Patch Changes

- @cipherstash/protect@10.0.2

## 1.1.9

### Patch Changes

- @cipherstash/protect@10.0.1

## 1.1.8

### Patch Changes

- Updated dependencies [788dbfc]
  - @cipherstash/protect@10.0.0

## 1.1.7

### Patch Changes

- Updated dependencies [c7ed7ab]
- Updated dependencies [211e979]
  - @cipherstash/protect@9.6.0

## 1.1.6

### Patch Changes

- Updated dependencies [6f45b02]
  - @cipherstash/protect@9.5.0

## 1.1.5

### Patch Changes

- @cipherstash/protect@9.4.1

## 1.1.4

### Patch Changes

- Updated dependencies [1cc4772]
  - @cipherstash/protect@9.4.0

## 1.1.3

### Patch Changes

- Updated dependencies [01fed9e]
  - @cipherstash/protect@9.3.0

## 1.1.2

### Patch Changes

- Updated dependencies [587f222]
  - @cipherstash/protect@9.2.0

## 1.1.1

### Patch Changes

- Updated dependencies [c8468ee]
  - @cipherstash/protect@9.1.0

## 1.1.0

### Minor Changes

- 1bc55a0: Implemented a more configurable pattern for the Protect client.

  This release introduces a new `ProtectClientConfig` type that can be used to configure the Protect client.
  This is useful if you want to configure the Protect client specific to your application, and will future proof any additional configuration options that are added in the future.

  ```ts
  import { protect, type ProtectClientConfig } from "@cipherstash/protect";

  const config: ProtectClientConfig = {
    schemas: [users, orders],
    workspaceCrn: "your-workspace-crn",
    accessKey: "your-access-key",
    clientId: "your-client-id",
    clientKey: "your-client-key",
  };

  const protectClient = await protect(config);
  ```

  The now deprecated method of passing your tables to the `protect` client is no longer supported.

  ```ts
  import { protect, type ProtectClientConfig } from "@cipherstash/protect";

  // old method (no longer supported)
  const protectClient = await protect(users, orders);

  // required method
  const config: ProtectClientConfig = {
    schemas: [users, orders],
  };

  const protectClient = await protect(config);
  ```

### Patch Changes

- Updated dependencies [1bc55a0]
  - @cipherstash/protect@9.0.0

## 1.0.12

### Patch Changes

- Updated dependencies [a471821]
  - @cipherstash/protect@8.4.0

## 1.0.11

### Patch Changes

- Updated dependencies [628acdc]
  - @cipherstash/protect@8.3.0

## 1.0.10

### Patch Changes

- Updated dependencies [0883e16]
  - @cipherstash/protect@8.2.0

## 1.0.9

### Patch Changes

- Updated dependencies [95c891d]
- Updated dependencies [18d3653]
  - @cipherstash/protect@8.1.0

## 1.0.8

### Patch Changes

- Updated dependencies [8a4ea80]
  - @cipherstash/protect@8.0.0

## 1.0.7

### Patch Changes

- Updated dependencies [2cb2d84]
  - @cipherstash/protect@7.0.0

## 1.0.6

### Patch Changes

- Updated dependencies [a564f21]
  - @cipherstash/protect@6.3.0

## 1.0.5

### Patch Changes

- Updated dependencies [fe4b443]
  - @cipherstash/protect@6.2.0

## 1.0.4

### Patch Changes

- Updated dependencies [43e1acb]
  - @cipherstash/protect@6.1.0

## 1.0.3

### Patch Changes

- Updated dependencies [f4d8334]
  - @cipherstash/protect@6.0.0

## 1.0.2

### Patch Changes

- Updated dependencies [499c246]
  - @cipherstash/protect@5.2.0

## 1.0.1

### Patch Changes

- Updated dependencies [5a34e76]
  - @cipherstash/protect@5.1.0

## 1.0.0

### Major Changes

- 76599e5: Rebrand jseql to protect.

### Patch Changes

- Updated dependencies [76599e5]
  - @cipherstash/protect@5.0.0

## 0.1.2

### Patch Changes

- Updated dependencies [5c08fe5]
  - @cipherstash/jseql@4.0.0

## 0.1.1

### Patch Changes

- Updated dependencies [e885975]
  - @cipherstash/jseql@3.9.0

## 0.1.0

### Minor Changes

- eeaec18: Implemented typing and import synatx for es6.

### Patch Changes

- Updated dependencies [eeaec18]
  - @cipherstash/jseql@3.8.0

## 0.0.6

### Patch Changes

- Updated dependencies [7b8ec52]
  - @cipherstash/jseql@3.7.0

## 0.0.5

### Patch Changes

- Updated dependencies [7480cfd]
  - @cipherstash/jseql@3.6.0

## 0.0.4

### Patch Changes

- Updated dependencies [c0123be]
  - @cipherstash/jseql@3.5.0

## 0.0.3

### Patch Changes

- Updated dependencies [9a3132c]
- Updated dependencies [9a3132c]
  - @cipherstash/jseql@3.4.0

## 0.0.2

### Patch Changes

- Updated dependencies [80ee5af]
  - @cipherstash/jseql@3.3.0

## 0.0.1

### Patch Changes

- Updated dependencies [0526f60]
- Updated dependencies [fbb2bcb]
  - @cipherstash/jseql@3.2.0
