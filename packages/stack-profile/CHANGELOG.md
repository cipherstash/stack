# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

















### Fixes

- make ProfileStore writes atomic via tmp file + rename
- serialise refresh-token rotation across processes
- address Copilot review on Windows + crash durability





### Documentation

- fix stale 0.34.0-alpha.1 changelog headers



## [0.43.0] - 2026-10-02


### Features

- the crate builds for wasm32-wasip1, and names the lock file's path

### Miscellaneous

- per-crate rustdoc gates for the stack crates, fanned out by `doc`
- move to cipherstash/stack with its history: the first release from that repository's `release-plz.yml`, in a version group with stack-auth alone. No change to the API; the version follows stack-auth's breaking release

## [0.42.3] - 2026-08-26


## [0.42.2] - 2026-08-17


## [0.42.1] - 2026-08-12


## [0.42.0] - 2026-07-19


## [0.41.1] - 2026-07-17


## [0.41.0] - 2026-07-17


## [0.40.0] - 2026-07-09


## [0.34.0] - 2026-03-04

### Changed
- Consolidated all publishable crate versions to 0.34.0; version is now centralized via `workspace.package.version`
