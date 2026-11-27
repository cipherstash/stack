// Package vcvalue is the durable, dependency-free module of the vitaminc Go
// bindings: the value model — the types application code holds and stores —
// with no dependency on wazero, any crypto, or any wire format. A future
// stack-encrypt Go SDK is expected to import this module; the wasm reference
// harness (module vcencrypt) is one consumer of it.
//
// # The model
//
//   - Plain{V: ...} marks (and surfaces) a field that travels in the clear —
//     unencrypted and unauthenticated — beside the sealed ones. It is always
//     an explicit opt-in, never inferred.
//   - Sealed is one encrypted leaf (version || nonce || ciphertext || tag),
//     the only frozen byte format in the model. SealedEmptySeq and
//     SealedEmptyMap are its authenticated marker siblings for empty
//     composites; an absent value is a sealed null leaf (ADR 0001), padded
//     to the length of a value when its type is fixed width (TypedNull,
//     and a nil pointer to such a type; vitaminc#493). This
//     sealed family is vitaminc-encrypt's materialization of the model: another binding (a stack-encrypt SDK,
//     say) defines its own distinct sealed-leaf types and wires them to the
//     codec via vcffi's LeafSet — a stack-encrypt leaf is never a Sealed.
//   - Object is the ordered map-decode shape (entry order preserved, so
//     results compare deterministically); Field is one entry of it.
//
// All of the sealed leaf types and Plain implement driver.Valuer (and the
// leaves sql.Scanner), so a map-shaped ciphertext binds directly as database
// named parameters and sealed columns load back without conversion.
//
// # What is deliberately NOT here
//
// The transport codec — the wire encoding that carries a value tree across
// an FFI boundary — lives in the sibling module vcffi, shared by the
// bindings that own such a boundary (vcencrypt, the stack-encrypt Go SDK).
// It is not a storage format, so this module does not carry it: the only
// bytes an application should ever persist are the sealed leaves above. The
// Encryptable/Encoder extension point for custom encodings lives with the
// codec in vcffi for the same reason.
//
// The cross-language contract is the frozen tag table plus the sealed leaf
// encodings defined in the Rust crate vitaminc-aead's leaf codec — the
// model, not any package. A new tag is added only when a value class cannot be
// represented in the existing model, and requires a defined decode mapping
// for every supported language before it ships.
package vcvalue
