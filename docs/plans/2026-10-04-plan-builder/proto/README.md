# Annotate protobuf fields for encryption rules

This example defines a protobuf field option and applies it to an `Individual` message.
The option carries [data categories](https://ethyca.github.io/fideslang/taxonomy/data_categories/) from [Fideslang](https://ethyca.github.io/fideslang/), a published taxonomy of personal data.
`buf generate` works for these protobuf files.

The Golang SDK for CipherStash Stack is planned and does not exist yet.
The rules that read the field options belong to the planned SDK.
The [Go example index](../README.md) lists every example and what was checked.

## What you will learn

- Define the `data_categories` field option.
- Annotate message fields while leaving one field uncategorised.
- Generate the Go protobuf package in `internal/pb`.

## Define the data category option

- **Purpose:** See how protobuf fields carry facts for encryption rules.
- **Related:** [The plan's policy declarations](../../2026-10-04-plan-builder.md#declarations-from-a-policy), [the rules walkthrough](../rules/README.md)
- **Needs:** Nothing

`classification.proto` extends `google.protobuf.FieldOptions` with `data_categories`.
Each value names one Fideslang data category, such as `user.contact.email`.

[`classification.proto`, lines 5 to 12](classification.proto#L5-L12)

```proto
import "google/protobuf/descriptor.proto";

option go_package = "example.com/app/internal/pb";

extend google.protobuf.FieldOptions {
  // The Fideslang data categories of a field.
  repeated string data_categories = 50001;
}
```

## Annotate the message fields

- **Purpose:** Follow each protobuf field into the policy rules.
- **Related:** [The rules walkthrough](../rules/README.md), [the generated individuals walkthrough](../individuals/README.md)
- **Needs:** Understand the `data_categories` option.

`name`, `email`, and `medicare_no` each carry a category.
`id` and `nickname` have no category, so message-specific rules must decide them.

[`individual.proto`, lines 9 to 15](individual.proto#L9-L15)

```proto
message Individual {
  int64 id = 1;
  string name = 2 [(classification.data_categories) = "user.name"];
  string email = 3 [(classification.data_categories) = "user.contact.email"];
  string medicare_no = 4 [(classification.data_categories) = "user.government_id"];
  string nickname = 5;
}
```

## Generate the Go protobuf package

- **Purpose:** Understand where buf writes the generated Go files.
- **Related:** [The generated protobuf walkthrough](../internal/pb/README.md)
- **Needs:** Install buf and `protoc-gen-go`.

`buf.gen.yaml` writes source-relative Go files into `../internal/pb`.

[`buf.gen.yaml`, lines 1 to 5](buf.gen.yaml#L1-L5)

```yaml
version: v2
plugins:
  - local: protoc-gen-go
    out: ../internal/pb
    opt: paths=source_relative
```

Run `buf generate` in this directory to generate the package again.
The committed files came from buf v1.50.0 and `protoc-gen-go` v1.26.0.
Adding a field to `Individual` does not stop the build.
CI runs `go generate ./...` and fails when a generated file differs from the committed file.

## What was checked

- **The policy example compiles against real protobuf code:**
  Run.
  buf v1.50.0 and `protoc-gen-go` wrote `internal/pb/`, and `go vet` passes.
- **A field added to the protobuf message does not stop the build:**
  Run.
  It builds, as the plan says: CI finds that change.
- **The protobuf source reads the field options, and the rules run:**
  Not run.
  Neither the source nor the generator exists.
