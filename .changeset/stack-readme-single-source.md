---
'@cipherstash/stack': patch
---

The npm README for `@cipherstash/stack` is now the root Stack README — the
package copy had drifted badly out of date. The root `README.md` is the single
source of truth: the package's `prebuild` script copies it in before every
build (npm cannot publish a symlink, so a real file has to ship in the
tarball), and a unit test fails CI if the two files ever drift apart.
