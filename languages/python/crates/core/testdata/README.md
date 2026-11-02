# Test data for the core crate

## `value-conformance.json`

This file is a copy of vitaminc's shared value corpus. Each vector gives a host value, its kind, and the exact bytes of its frame. `tests/value_conformance.rs` runs the vectors against the SDK's value conversion.

| | |
|---|---|
| Source | `testdata/value-conformance.json` in `cipherstash/vitaminc` |
| Commit | `06568ba93bd94455cce9887c98898ca0f96b6440`, the commit that `languages/golang/go.mod` names for `vcffi` and `vcvalue` |
| Git blob hash | `97475e1f4a5f0942bd3c79f4ac7a93352fa79194` |

The file is a copy because the published vitaminc crates do not include it. Never edit the copy by hand.

vitaminc only adds rows to this corpus. It never changes or removes a row. So an older copy is still correct. It can miss newer rows.

To update the copy, download the file at a newer commit and replace this one:

```sh
gh api "repos/cipherstash/vitaminc/contents/testdata/value-conformance.json?ref=<commit>" \
  -H "Accept: application/vnd.github.raw" > value-conformance.json
git hash-object value-conformance.json
```

Then record the new commit and blob hash in the table above. `cargo test` fails on a new vector of a kind the SDK writes, until the test handles it.
