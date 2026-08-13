//! `public.eql_v3_date_ord_ope` smoke suite — the shared `_ord_ope` literal-payload
//! tests (see `ope/support.rs`). The ope surface is byte-identical across the
//! ordered families modulo the domain name; the deeper single-type behaviour
//! (prefix order, blockers, ORDER BY forms, aggregates) lives on the integer
//! reference in `ope/integer_ord_ope.rs`.

crate::ope_ord_smoke!("eql_v3_date_ord_ope");

// Real-ciphertext coverage: the generated fixture's client-emitted
// `op` terms must order and compare like the plaintext oracle.
crate::ope_ord_fixture_smoke!("eql_v3_date_ord_ope", chrono::NaiveDate, "eql_v3_date");
