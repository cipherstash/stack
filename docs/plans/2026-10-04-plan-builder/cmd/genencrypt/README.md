# Generate encryption code from protobuf rules

This directory contains the command that is planned to turn protobuf rules into a generated file.
It connects the protobuf source, `rules.Individuals`, and the requested output path.
The Go software development kit (SDK) is planned and does not exist yet, so this code does not build in this repository.
The [Go example index](../../README.md) lists every example and what was checked.

## What you will learn

- Run `stashgen.Generate` with a protobuf source and policy.
- Review rule changes in the generated file.

## Connect the source, rules, and output

- **Purpose:** Follow the three inputs to the planned library generator.
- **Related:** [The plan's policy declarations](../../../2026-10-04-plan-builder.md#declarations-from-a-policy), [the rules walkthrough](../../rules/README.md), [the individuals walkthrough](../../individuals/README.md)
- **Needs:** Read the `rules.Individuals` policy first.

`protosource.New()` supplies protobuf descriptors and field options.
`rules.Individuals` supplies the field decisions.
`stashgen.Output` selects the generated file in the `individuals` package.
The output goes in your own `individuals` package, not `internal/pb`, which holds the generated type.
This separation stops the generate program from importing a file that it writes.

[`main.go`, lines 12 to 18](main.go#L12-L18)

```go
func main() {
	err := stashgen.Generate(protosource.New(), rules.Individuals,
		stashgen.Output("../individuals/individual_stash.go"))
	if err != nil {
		log.Fatal(err)
	}
}
```

The `stashgen`, `protosource`, and policy packages do not exist yet.

## Review rule changes in the generated file

- **Purpose:** See how reviewers inspect policy changes without running rules in the application.
- **Related:** [The generated individuals walkthrough](../../individuals/README.md), [the rules walkthrough](../../rules/README.md)
- **Needs:** Understand the generator inputs.

The [`rules` package](../../rules/README.md) runs this command through `go generate`.
The application calls the resulting `individuals.Encrypt` and `individuals.Decrypt` functions.
A rule change changes `individual_stash.go`, which gives a reviewer a concrete generated diff.
The application never runs the rules.

## What was checked

- **Every Go file type-checks:**
  Run.
  `go vet ./...` passes against a stub of the SDK.
  The stub is not in this repository, and it has signatures only.
- **The policy example compiles against real protobuf code:**
  Run.
  buf v1.50.0 and `protoc-gen-go` wrote `internal/pb/`, and `go vet` passes.
- **The protobuf source reads the field options, and the rules run:**
  Not run.
  Neither the source nor the generator exists.
- **The files `stashgen` writes:**
  Not run.
  `stashgen` does not exist, and the five `_stash.go` files are written by hand.
- **The SDK can be built with these signatures:**
  Not run.
- **`stashgen` checks a declaration with the embedded guest:**
  Not run.
