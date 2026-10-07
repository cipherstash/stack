# Releasing the Go module

The module is `github.com/cipherstash/stack/languages/golang`. A version is the git tag `languages/golang/v<version>`, which is how Go finds the versions of a module in a subdirectory. Users depend on it with:

```
go get github.com/cipherstash/stack/languages/golang@v0.1.0
```

Only tagged versions work. A commit of `main` (`@main`, or a pseudo-version) has no guests in it, and fails on first use with `ErrGuestNotBuilt`.

## Cutting a release

1. Add a changeset naming the Go module, in the repository root's `.changeset/`, like any other package:

   ```
   ---
   '@cipherstash/golang': minor
   ---

   What changed, for someone who calls the Go module.
   ```

   Use `patch` for fixes and `minor` for new or changed behaviour. The module is pre-1.0, so a breaking change is a `minor` and the changeset says what breaks.

2. Merge the pull request. The Version Packages PR that `release.yml` keeps open now moves `languages/golang/package.json` to the next version and adds a section to `languages/golang/CHANGELOG.md`.

3. Merge the Version Packages PR. Its change to `languages/golang/package.json` starts `.github/workflows/release-golang.yml`, which releases that version. Nothing else is needed.

## What the workflow does

`plan` reads the version from `languages/golang/package.json`. A release is owed when the version has no tag. `0.0.0` means the module has never been released, and nothing happens. The release is built at the commit that set the version (the last commit to change its `"version"` line), so a re-run builds the same source whatever has merged since.

`build` runs twice, on separate runners, at that commit. Each run calls `scripts/golang-release-build.mjs`, which runs every guest's mise task (`wasm:guest:build`, `wasm:auth-guest:build`): build the release module, check its host imports with `scripts/check-wasm-imports.py`, and copy it into the module.

`publish` (`scripts/golang-release.mjs publish`) makes the release, and checks each step before the next:

1. The two builds must be identical, byte for byte. If they are not, nothing is tagged.
2. It makes the release commit on a scratch branch, `release-golang/v<version>`. The commit's only parent is the commit that set the version, and it adds the built guests and nothing else. It is made through the GitHub API, so GitHub signs it.
3. It downloads the module at that commit with `go mod download`, straight from GitHub, and checks every guest in it is the one that was built. This is what `go get` will receive.
4. It pushes the tag and deletes the scratch branch.
5. It writes a GitHub release: the changelog section, the `go get` line, and each guest's SHA-256. The release is not marked as the repository's latest, which stays an npm or EQL release.
6. It downloads the version through `proxy.golang.org`, which records it in the checksum database and lists it on pkg.go.dev, and checks the guests the proxy serves.

## Rehearsing a release

Run "Release Go" from the Actions tab with **Dry run** ticked, against the branch to rehearse (normally `main`). It builds the dispatched commit twice, compares the builds, makes the release commit on a scratch branch (`release-golang/dry-run/v<version>`), downloads the module from it with `go mod download` and checks the guests, then deletes the branch. It tags nothing and writes no release, and the log shows the release notes it would have written. Do this before the first release, and after any change to the guests' build or to this workflow.

## Why a release tags a commit that is not on main

The module embeds the WASI guests built from the Rust crates (`//go:embed wasm`), and Go fetches a module from the git tree at its tag. The built guests are gitignored on `main`, so a tag on a commit of `main` would give `go get` a module with no guests. Committing them to `main` instead would put a new binary in the history with every change to a guest, and every pull request that changes one would have to rebuild and commit it. So each release tags its own commit, on top of the commit that set the version, and `main` never holds a binary.

## Versions

The module has its own version, starting at `v0.1.0`, independent of the Rust crates. It embeds two guests from different crate version groups (stack-encrypt, and stack-auth with stack-profile), built from a commit rather than from a crates.io release, so no crate's version describes it.

`languages/golang/package.json` (`@cipherstash/golang`) exists only to carry that version. It is private, so it is never published to npm, and the release gate skips it.

## Checking a release

The SHA-256 of each guest is in the GitHub release and in the release commit's message. To rebuild them, check out the commit the release names and run each guest's mise task. The guests embed absolute source paths, so a rebuild matches byte for byte only from a checkout at the same path as the release runner's (`/home/runner/work/stack/stack`).

## When something goes wrong

- **A run failed before the tag was pushed.** Nothing is public. Fix the cause and run "Release Go" from the Actions tab (`workflow_dispatch`). It builds the same commit again, and reuses a scratch branch the failed run left behind.
- **The builds differed.** The build is not reproducible, so it cannot be released. Find what differs between the two artifacts (`golang-guests-first`, `golang-guests-second`) before trying again.
- **The tag was pushed but the GitHub release or the proxy check failed.** The version is public and cannot be changed. Write the GitHub release by hand if it is missing (`gh release create languages/golang/v<version> --notes-file …`). If what the proxy serves is wrong, release the next patch version: a Go version is recorded in the checksum database the first time anyone fetches it, so a tag is never moved or reused.
