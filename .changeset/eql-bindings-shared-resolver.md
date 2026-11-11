---
"@cipherstash/eql": minor
---

`eql-bindings` (the Rust crate released with this package) now ships a resolver for Stack Encrypt's dynamic interface: `eql_bindings::encryption::EqlTargets`, behind the `targets` feature. The dynamic interface runs a plan that arrives as data, and a field of that plan can name an EQL type, such as `"TextEq"`. A program gives Stack Encrypt the EQL types through its `TargetResolver` trait. Until now each program wrote its own resolver over `encryption::targets`. `EqlTargets` holds every type in `targets::targets()` and runs a named type's `encrypt_with`, `decrypt` and `query`. Two conversions come with it: `From<&Target>` for Stack Encrypt's `TargetDescriptor`, and `From<targets::TargetError>` for Stack Encrypt's `TargetError`. Stored bytes and query operands do not change. The SQL bundle and the TypeScript types do not change.
