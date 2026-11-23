//! An executable leakage profile for the JSON index (EQL v4 `json_tree`).
//! See `json_leakage/mod.rs` for what it is and how to read it.
//!
//! The real side derives its containment, equality and ordering queries
//! through a data plan, as a binding does, so the binary needs the
//! `dynamic` feature.
#![cfg(feature = "dynamic")]

mod common;
#[path = "json_leakage/mod.rs"]
mod leakage;
