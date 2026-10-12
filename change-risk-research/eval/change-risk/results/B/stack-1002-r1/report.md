## Change risk: Focused review required

**Impact if something goes wrong:** high · **Verification confidence:** low · `c93a39b034..2a38fb4e0d`

Adds the release machinery for the @cipherstash/auth napi packages (a six-target build matrix, a dispatch-only preflight, publish-auth in release.yml) and for the stack-auth/stack-profile crates (a release-crates job in release-plz.yml), plus an `auth` flag in the release gate. The new publishing paths are inert at head: all seven auth packages remain in FROZEN_PUBLISHERS, so an unpublished auth version fails `gate` before auth-artifacts can run, and the crates switch keys on the same entry. Merging this therefore publishes nothing new. The material risk is latent and lands at the arming PR: the auth Linux builds use plain cargo on ubuntu-latest / ubuntu-24.04-arm with no glibc floor (the FFI line pins 2.28 via zigbuild) and the musl leg omits the `-crt-static` flag the FFI build sets, so the first armed release could publish gnu binaries unloadable on older distros or fail and hold every JS release on that push. One live effect today: release-plz.yml's push filter now includes root Cargo.toml/Cargo.lock, so the already-armed EQL crates job (crates.io OIDC, contents: write) boots on unrelated root-workspace changes. No tests were run.

### Failure scenarios

**FS-1 · Armed auth release publishes gnu binaries with a glibc floor of the build runner** (high impact, plausible)

- Trigger: The arming PR removes the auth entries from FROZEN_PUBLISHERS and the next auth version is published by publish-auth.
- Mechanism: linux-x64-gnu and linux-arm64-gnu are built with plain `napi build` (cargo) on ubuntu-latest and ubuntu-24.04-arm (_build-auth-artifacts.yml:45-53, 116). The repository's FFI line deliberately cross-compiles gnu targets through cargo-zigbuild to pin a glibc 2.28 floor (scripts/ffi-release-matrix.mjs:58-67). A cdylib linked against a recent glibc picks up newer symbol versions. auth-preflight only checks that libc.so.6 is NEEDED (auth-preflight.yml:86-91), and its smoke test loads the binary on the same runner image, so a raised floor passes every check.
- Consequence: @cipherstash/auth (and @cipherstash/stack, CLI and wizard through it) fails at require time with `GLIBC_2.xx not found` on older Linux hosts (for example Amazon Linux 2, Debian 11, RHEL 8) that the FFI line supports. npm publishes are irreversible; recovery needs a new release.
- Affects: _build-auth-artifacts.yml and auth-preflight.yml, @cipherstash/auth and six @cipherstash/auth-* platform packages (npm), @cipherstash/stack, stash CLI and wizard (consumers of @cipherstash/auth)
- Evidence: `.github/workflows/_build-auth-artifacts.yml:45-116`; `scripts/ffi-release-matrix.mjs:58-67`; `.github/workflows/auth-preflight.yml:84-95`; `languages/typescript/packages/stack/package.json:232-245`
- Existing verification: auth-build-artifacts.test.mjs asserts the matrix covers six platforms and the build flags, not toolchain or glibc floor. [exists_not_run]; auth-preflight.yml checks ELF architecture and libc linkage, and smoke-loads linux-x64-gnu on ubuntu-latest. [unknown]
- Missing verification: A check of the highest GLIBC_ symbol version required by each gnu .node (objdump -T / readelf --version-info) against the intended floor.; Confirmation of which glibc floor cipherstash-suite's published auth binaries currently have, so the first release from here does not raise it.
- Mitigation: Build the gnu legs the way the FFI line does (cargo-zigbuild with an explicit `.2.28` target suffix, or an older manylinux-style container), and add a max-GLIBC-version assertion to the build or preflight before the arming PR.

**FS-2 · musl leg produces no .node and the armed release holds every JS publish on that push** (medium impact, plausible)

- Trigger: First armed run of auth-artifacts (or a preflight dispatch) on the linux-x64-musl leg.
- Mechanism: The musl leg installs musl-tools and runs plain `napi build --target x86_64-unknown-linux-musl` (_build-auth-artifacts.yml:54-56, 68-73, 116) without `RUSTFLAGS=-C target-feature=-crt-static`, which the FFI build sets for musl (_build-ffi-artifacts.yml:238). With static CRT, rustc does not emit a cdylib for musl, so `mv stack-auth-node.linux-x64-musl.node` fails. The wrapper job needs all binaries, publish-auth is skipped, and `release` requires publish-auth success whenever auth == 'true' (release.yml:471-482).
- Consequence: The `release` job does not run on that push, so changesets publish and the Version Packages PR update are held for all JS packages until the build is fixed. Fails loudly and publishes nothing broken.
- Affects: _build-auth-artifacts.yml and auth-preflight.yml, .github/workflows/release.yml (Release JS)
- Evidence: `.github/workflows/_build-auth-artifacts.yml:45-116`; `.github/workflows/_build-ffi-artifacts.yml:238`; `.github/workflows/release.yml:459-482`
- Existing verification: auth-preflight.yml would exercise the musl leg if dispatched before arming. [unknown]
- Missing verification: A recorded auth-preflight run (all seven tarballs built) before the arming PR merges.
- Mitigation: Set `-C target-feature=-crt-static` (and a musl linker if needed) for the musl leg as the FFI build does, and make a green auth-preflight run a precondition of the arming PR.

**FS-3 · Widened release-plz trigger boots the armed EQL crates job on unrelated root Cargo changes** (low impact, plausible)

- Trigger: Any push to main touching root Cargo.toml, Cargo.lock, release-plz.toml, cliff.toml or the two crate directories (for example a dependency bump).
- Mechanism: The push filter now includes root workspace files (release-plz.yml:46-54). @cipherstash/eql is no longer in FROZEN_PUBLISHERS (release-gate.mjs:163-184), so the EQL `release` job (contents: write, id-token: write for crates.io, GPG import when its preflight says publish is needed) runs on these pushes too (release-plz.yml:86-96). The file's own comment calls booting this job on every unrelated merge 'a standing credential exposure for no release' (release-plz.yml:33-37). A crates.io API failure reads as unpublished and drives the SQL guard and GPG import.
- Consequence: More runs of a credential-bearing job that normally no-op; on a crates.io API blip, a red release-plz run on main unrelated to the change. No publish unless eql-bindings has an unpublished version, which it would publish anyway on its own trigger.
- Affects: .github/workflows/release-plz.yml (crates.io publishing), eql-bindings crate release job (release-plz.yml `release`)
- Evidence: `.github/workflows/release-plz.yml:33-54`; `.github/workflows/release-plz.yml:86-96`; `scripts/release-gate.mjs:163-184`
- Missing verification: No test asserts which jobs a root-workspace-only push reaches.
- Mitigation: Accept knowingly, or make the EQL job skip when the push changed no packages/eql path (for example a dorny/paths-filter step or a git diff check before the credentialed steps).

### Recommended controls

- Confirm inertness: FROZEN_PUBLISHERS still holds all seven auth names, auth-artifacts/publish-auth carry no always(), and release-crates is keyed on `armed == 'true'` from the crates line. (review_focus; FS-1, FS-2)
- Before the arming PR, add a max-GLIBC-version assertion for both gnu .node files and align the gnu builds with the FFI line's zigbuild .2.28 floor (or the floor cipherstash-suite ships today). (test; FS-1, VG-1)
- Add `-C target-feature=-crt-static` for the musl leg, and require a green auth-preflight dispatch against the Version Packages branch as a precondition of arming. (other; FS-2, VG-2, VG-3)
- Decide explicitly whether the EQL release job should boot on root-workspace-only pushes; if not, path-scope it inside the workflow. (review_focus; FS-3)
- At arming, run `changeset status` with a sample patch changeset for an auth package to confirm the new fixed group plus workspace:* peerDependencies and onlyUpdatePeerDependentsWhenOutOfRange do not escalate to a major bump. (compatibility_check; VG-2)

### What this assessment could not see

- No CI results and no test runs: vitest and js-yaml are not installed and there is no network; running the gate script locally was not permitted in this session. All test evidence is exists_not_run; inertness rests on reading the code, not on an observed run.
- cipherstash-suite's current auth build (toolchain, glibc floor, musl flags) is unavailable. FS-1 and FS-2 cannot be stated as regressions against what is published today, only as gaps against this repository's FFI line.
- Whether rustc drops the musl cdylib under default crt-static, and which glibc symbol versions the auth crate pulls in, were inferred from toolchain behaviour, not observed. FS-1 and FS-2 are plausible_failure, not observed_defect.
- Test-file changes (eleven files) were skimmed for their assertions, not read in full; the six-line AGENTS.md and CONTRIBUTING.md edits were not reviewed hunk by hunk. Changesets fixed-group/peer-dependency bump behaviour was not exercised. A weakened guard or a changesets versioning surprise at arming could be missed.
- npm and crates.io trusted-publisher configuration and repository secrets (GPG_PRIVATE_KEY) are unavailable. Whether the arming PR alone is sufficient to publish cannot be judged.

_Inputs unavailable: pr_description, ci_results, dependency_graph, codeowners, deployment_context._

_Advisory only. claude-code (headless) · claude-opus-5-5 · change-risk 1.0.0._
