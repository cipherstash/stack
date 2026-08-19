# @cipherstash/protect-ffi-linux-x64-musl

## 0.32.0

### Patch Changes

- a2b0b45: **This is the first release of these packages published from
  `cipherstash/stack`.** Every version up to and including 0.31.0 was published
  from `cipherstash/protectjs-ffi`, which is archived once this release is out.

  If you verify npm provenance, the attested source repository changes with this
  release:

  ```
  0.31.0   github.com/cipherstash/protectjs-ffi   .github/workflows/release.yml
  0.32.0   github.com/cipherstash/stack           .github/workflows/release.yml
  ```

  A verification policy that pins the source repository will reject 0.32.0 until
  it is updated. The packages, their contents and their maintainers are otherwise
  unchanged: the Rust source moved into the monorepo at
  `packages/protect-ffi/crates/protect-ffi`, and each of these packages'
  `repository.url` now names `cipherstash/stack`, with `repository.directory`
  pointing at its own stub under `packages/protect-ffi/platforms/`.

  `CHANGELOG.md` is also added to each package's published files, so this note and
  later ones are readable in the package you install rather than only on GitHub.

  The binaries themselves differ from 0.31.0 in one user-visible way: the Rust
  core's `InvariantViolation` message asks the reader to file an issue, and the
  repository it names has moved with the rest.
