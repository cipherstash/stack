# Stack Encrypt API review: decision record

Started on 24 October 2026. Last updated on 8 November 2026.

This record lists the 22 issues the review of the `stack-encrypt` API
found. Each has its decision, the date, and a link to the section of the
[API plan](2026-10-24-stack-encrypt-api-plan.md) that records it. The
deliberation behind each decision is not kept. The plan is the source of
truth; where this record and the plan differ, the plan is right.

The companion documents are the [context
scenarios](2026-10-24-stack-encrypt-context-examples.md), [tag refinement
and caveats](2026-11-07-stack-encrypt-tag-refinement.md), [JSON
operations](2026-10-25-stack-encrypt-json-operations.md), [provider
capabilities](2026-10-25-stack-encrypt-provider-capabilities.md), and
[packaging and names](2026-10-25-stack-encrypt-packaging.md). The plan's
terms table defines every term used here.

## The stored format must stay compatible from 7 November 2026

Decided on 7 November 2026 by Dan: "The stored data must not break as of
now. The Go customer has already started implementation with rc.3. We can
make breaking changes to the code/API but not the stored format."

The stored format is what is written to the database. It includes
ciphertexts with their envelopes and headers. It includes index and search
terms. It includes JSON tree entries.

The baseline is what the Go module at tag `languages/golang/v0.1.0-rc.3`
writes, with the EQL v4 SQL bundle attached to that release. The tag is
commit `114e08448`, built on 2 November 2026 from `next` at `929451b49`.

From now on, a change that would alter the stored format must keep data
written by rc.3 readable and searchable. Otherwise it must add a new,
versioned format beside the rc.3 format. The Rust and Go code and APIs can
still change in breaking ways. The [API
plan](2026-10-24-stack-encrypt-api-plan.md#changes-that-would-alter-the-stored-format)
lists the planned work that this decision constrains.

### History: no backward compatibility with the prototype

On 25 October 2026 Dan clarified that this API had never shipped beyond an
early prototype. Backward compatibility, and migration of prototype data,
were not requirements. The decision of 7 November 2026 replaces that for
stored data. It still applies to the code and the APIs.

## Summary of status

Status on 8 November 2026, against `next` at `e4990e49b`.

| Issue | Status |
| --- | --- |
| 1. Cipher trait mismatch | Decided. Paired entry points (#1404); parameters named `context` still to rename |
| 2. Opaque ciphertext storage | Decided. `Ciphertext` (#1404); `OpaqueBlob` in #1503; text encodings open |
| 3. Plaintext-side encryption | Decided. The keyset is the receiver; `encrypt` or `encrypt_into` by who fixes the type |
| 4. Fixed context on the scalar derive | Decided. Declared scopes, then caller parts, in order (#1491) |
| 5. `EncryptFrom` has no `encrypt_from` | Decided. `EncryptTarget` and `DecryptSource` (#1404) |
| 6. Plan builder `encrypt_into` | Decided. Renamed `target`; the chain is replaced by `Planned` |
| 7. Mixed encrypted and plaintext fields | Decided. `passthrough` (#1504, in progress) |
| 8. Whole-value encryption and layouts | Decided. The derive lives on the encrypted struct |
| 9. Ownership across Stack and Vitamin C | Open. Proposal in the packaging document |
| 10. Public `encrypt_as` | Decided. Remove; still public on `next` |
| 11. Context from an input struct | Decided. Three sources; the builder is the one mechanism |
| 12. `Default` compared with optional context | Decided. A declaration lists the required parts |
| 13. JSON layouts and output adaptation | Decided. A target type with typed options; marker query methods |
| 14. Decrypt context variants | Decided. Paired, destination-directed (#1404, #1501) |
| 15. Go JSON work in pull request #1353 | Done. The Go JSON work merged |
| 16. Prior query design | Done. Its decisions are in the plan |
| 17. One name for definition selection | Decided. No `using` or `on`; marker-first queries and `Planned` |
| 18. Consuming inputs with cleanup | Decided. `OpaqueEncode`, `Zeroize`; borrowed values allowed |
| 19. First-release completeness | Decided. The JSON contract is live as rc.3; J14 and J17 open |
| 20. Keysets chosen from plaintext | Open. After the customer release |
| 21. Packaging and `AsyncCipher` | Open. The naming review, after the customer release |
| 22. Customer-driven order of work | Decided. Four work groups in customer order |

## 1. Cipher trait mismatch and the required context argument

Decided on 24 October 2026 by Dan. Encryption has two entry points: `encrypt`, and `encrypt_with_context`.
The common case therefore needs no empty context argument. Decryption has
the same pair. #1404 implemented them.

On 7 November 2026, Dan decided that every parameter
that takes a context is named `context`; six public methods still say
`aad`. See [Name context parameters
`context`](2026-10-24-stack-encrypt-api-plan.md#name-context-parameters-context).

Still open: how Stack's ciphers relate to Vitamin C's cipher traits. That
is issue 21.

## 2. The Node and SealedValue types make opaque ciphertext storage harder

Decided on 25 October 2026 by Dan. Ordinary encryption produces one opaque
`Ciphertext` (#1404). A composite value is encrypted as one ciphertext
through `OpaqueBlob<T>` (#1503). A collection encrypts element by element
(#1501).

On 7 November 2026, Dan decided that a byte string is one value. See
[Encrypt a byte
string](2026-10-24-stack-encrypt-api-plan.md#encrypt-a-byte-string) and
[Opaque blobs](2026-10-24-stack-encrypt-api-plan.md#opaque-blobs).

Still open: ciphertext as text in a column. See [Typed text encodings and
key tag
extraction](2026-10-24-stack-encrypt-api-plan.md#typed-text-encodings-and-key-tag-extraction).

## 3. Plaintext-side encryption has different syntax and context requirements

Decided on 24 October 2026 by Dan. The keyset is the receiver of ordinary
encryption: `keyset.encrypt(value)`. On 7 November 2026, Dan decided the rule for the two verbs. `encrypt` is
for a call where the marker or the plan fixes the output type.
`encrypt_into` is for a call where the caller names it. See [Encrypt
and decrypt one
value](2026-10-24-stack-encrypt-api-plan.md#encrypt-and-decrypt-one-value)
and [Other rules](2026-10-24-stack-encrypt-api-plan.md#other-rules).

## 4. The scalar derive cannot declare a fixed literal context

Decided on 7 November 2026 by Dan. A declaration supplies the first scopes of a context: the record name,
then the field's context name. The caller's
parts follow, in declared order: scopes, then bindings. #1491 made
repeated parts append in order, in Rust and in Go. See [Query context and
stored
context](2026-10-24-stack-encrypt-api-plan.md#query-context-and-stored-context).

## 5. EncryptFrom does not define encrypt_from

Decided on 25 October 2026 by Dan. A declaration and its execution are
separate. `EncryptTarget` and `DecryptSource` declare; `EncryptInto` and
`DecryptFrom` execute (#1404). The structural `EncryptFrom` and
`DecryptInto` are to be removed. See [Remove the structural
API](2026-10-24-stack-encrypt-api-plan.md#remove-the-structural-api).

## 6. The plan builder's encrypt_into reads like the execution method

Decided on 7 November 2026 by Dan. The builder's output method is renamed
`target`. The chain in `plan/chain.rs` shared the name. `Planned` replaces it. See [A request: `Planned` and its serialised
form](2026-10-24-stack-encrypt-api-plan.md#a-request-planned-and-its-serialised-form).

## 7. The output derive cannot mix encrypted and plaintext fields directly

Decided on 25 October 2026 by Dan. `#[stash(passthrough)]` on an output field copies the source field
unencrypted and unauthenticated. #1504 adds it.

On 8 November 2026, two safety rules were added. A plaintext field with
no counterpart in the encrypted struct is a compile error. A field is in
the clear only where `passthrough` is written. See [Record
derives](2026-10-24-stack-encrypt-api-plan.md#record-derives).

## 8. Clarify whole-value encryption, layouts, and searchable outputs

Decided on 7 and 8 November 2026 by Dan. The record derive lives on the
encrypted struct. That struct is the declaration. A field's indexes come
from its target type.

The derive emits one marker per field and `encryption_plan()`. A value
under a plan that is data is `Planned::new(&plan, value)`. See [Record
derives](2026-10-24-stack-encrypt-api-plan.md#record-derives) and [Field
markers and the encryption
plan](2026-10-24-stack-encrypt-api-plan.md#field-markers-and-the-encryption-plan).

## 9. Ownership of the value-encryption API across Stack and Vitamin C

Still open. The proposal is that Stack owns the public model for
encrypting values. Vitamin C keeps the primitives.

#1501 moved the crates to Vitamin C 0.9. `OpaqueEncode` now follows Vitamin C's `Scalar`
marker. The decision waits for the naming review. See [After the
customer
release](2026-10-24-stack-encrypt-api-plan.md#5-after-the-customer-release)
and the [packaging document](2026-10-25-stack-encrypt-packaging.md).

## 10. The public encrypt_as duplicates encrypt_into

Decided on 25 October 2026 by Dan. Remove `encrypt_as` from the public
API. It is still public on `next`, beside `target::legacy`. See [Remove
the structural
API](2026-10-24-stack-encrypt-api-plan.md#remove-the-structural-api).

## 11. Context fields do not yet take context from an input struct

Decided on 7 November 2026 by Dan. A field's context comes from one of
three sources: the declaration, a row field stored unsealed, or the caller
on every call. The plan builder is the one mechanism; the derive and the
dynamic grammar lower to it. The attribute spellings are placeholders for
the naming review. See [Context from fields and from the
caller](2026-10-24-stack-encrypt-api-plan.md#context-from-fields-and-from-the-caller).

## 12. Default is not the same as optional caller context

Decided on 7 November 2026 by Dan. A declaration lists the parts a caller
must supply, each with its kind and type. An undeclared part is refused in
Rust. Optional is the marked, rare case, because a query that omits an
optional part matches nothing silently. #1404 added the explicit context
inputs. See [Other rules](2026-10-24-stack-encrypt-api-plan.md#other-rules).

## 13. JSON layouts and adapting encrypted output

Decided on 7 November 2026 by Dan. A JSON field is a target type with
typed options, and `JsonTreeDocument` with the default options needs no
named type. A JSON query uses the same per-operator methods as a scalar
query, on the document's marker. See [Encrypt a JSON
document](2026-10-24-stack-encrypt-api-plan.md#encrypt-a-json-document)
and [Query a JSON
document](2026-10-24-stack-encrypt-api-plan.md#query-a-json-document).

Agreed follow-up: replace the serialisation round trips in the EQL JSON
adapter with direct typed conversions.

## 14. Decrypt convenience methods need explicit context variants

Decided on 25 October 2026 by Dan. Decryption mirrors encryption:
`decrypt_from` and `decrypt_from_with_context`, directed at the
destination type. The keyset has the same pair. #1404 implemented them
for one value, and #1501 for collections. On 7 November 2026, Dan decided
that a stored part passed on decrypt is checked against the row. See [One
context argument, and paired entry
points](2026-10-24-stack-encrypt-api-plan.md#one-context-argument-and-paired-entry-points).

## 15. Coordinate the Go JSON work with the shared API redesign

Done. The Go JSON work of #1353 merged in #1372, #1373, #1378, and #1402,
and the plan's Go section describes it. See [Call it from
Go](2026-10-24-stack-encrypt-api-plan.md#call-it-from-go).

## 16. Integrate the prior query design instead of reopening it

Done. Dan supplied the query design document, dated 21 October 2026. It
was reviewed on 25 October 2026, and again on 7 November 2026. Its
decisions are recorded in the plan. See [The query
engine](2026-10-24-stack-encrypt-api-plan.md#4-the-query-engine).

## 17. Use the same name to select a definition for encryption and queries

Decided on 7 November 2026 by Dan. There is no `using` method and no
`on`. A typed query starts from the field marker:
`EncryptedMember::EMAIL.eq(..).scope(..).encrypt(&keyset)`. A value under
a plan that is data is `Planned::new(&plan, value)`. See [Query a record
field](2026-10-24-stack-encrypt-api-plan.md#query-a-record-field) and [A
request: `Planned`](2026-10-24-stack-encrypt-api-plan.md#a-request-planned).

## 18. A single ciphertext needs inputs that are consumed and cleaned up

Decided on 25 October 2026 by Dan. `OpaqueEncode` and `OpaqueDecode` name
the single-value encoding traits. Plaintext types implement `Zeroize`, and
encryption wipes an owned plaintext, including on failure.

On 7 November 2026, Dan decided that a borrowed value may be encrypted
too. The caller then wipes the original. #1404, #1493, and #1501
implemented the owned cases. See [Encrypt borrowed
values](2026-10-24-stack-encrypt-api-plan.md#encrypt-borrowed-values) and
[Wipe plaintext in the remaining
cases](2026-10-24-stack-encrypt-api-plan.md#wipe-plaintext-in-the-remaining-cases).

## 19. First-release completeness and remaining review decisions

Decided on 25 October 2026 by Dan. Encoded ciphertext wrappers are
first-class field targets. ORE does not answer equality. The JSON
operation contract must be comprehensive for the first release.

That contract is now live and in use as the release candidate, Go
`v0.1.0-rc.3`. #1492 enrols it in conformance. Still open: opening one
child bound to its parent (J14 and J17). See [Open one child of a JSON
node](2026-10-24-stack-encrypt-api-plan.md#open-one-child-of-a-json-node-bound-to-its-parent).

## 20. Keysets chosen from plaintext, and optional provider policies

Still open. Dan asked for keyset routing from a field of the record, an
assessment of Vitamin C's `AsyncCipher`, and ZeroKMS lock context with
claim selectors. The [provider capabilities
document](2026-10-25-stack-encrypt-provider-capabilities.md) has the
proposal, for [after the customer
release](2026-10-24-stack-encrypt-api-plan.md#5-after-the-customer-release).

## 21. Packaging, naming, and retiring AsyncCipher

Still open. Dan favours retiring Vitamin C's `AsyncCipher` and moving
application encryption behaviour into Stack Encrypt. The [packaging document](2026-10-25-stack-encrypt-packaging.md) has the
proposal. The naming review judges it after the customer release. The plan's [names
deferred to the naming
review](2026-10-24-stack-encrypt-api-plan.md#names-deferred-to-the-naming-review)
lists every placeholder.

## 22. Customer-driven order of work: Go JSON and match search first

Decided on 25 October 2026 by Dan, and amended on 7 November 2026. The Go
customer's needs come first: JSON support and dependable match search,
including two-letter words. The stored format written by rc.3 must stay
compatible. The plan's [remaining
work](2026-10-24-stack-encrypt-api-plan.md#remaining-work) is in four
groups in that order, with the Rust API and the crate moves after the
customer release.
