//! Self-expiring markers for assertions that are known to fail because of an
//! **open, identified** bug.
//!
//! The problem with `#[ignore]` is that it is silent in both directions: it
//! hides the failure, and it keeps hiding it after the bug is fixed. A stale
//! `#[ignore]` is indistinguishable from a passing test, so the assertion it
//! guards quietly stops guarding anything.
//!
//! [`known_failure`] inverts that. The assertion stays in the test, written the
//! way it *should* pass. The marker then asserts the opposite of what you want:
//!
//! - while the bug reproduces, the wrapped outcome is `Err` → the test **passes**
//!   and prints the issue number;
//! - once the bug is fixed, the wrapped outcome is `Ok` → the test **fails**,
//!   telling you to delete the marker.
//!
//! So a marker cannot outlive its bug, and CI turns red the day upstream ships
//! the fix rather than the day someone remembers to look.
//!
//! The second half of the contract — that the issue is real and still open — is
//! enforced outside Rust by `mise run test:known-failures`, which reads the
//! `ISSUE_*` constants below and queries GitHub. A marker pointing at a closed
//! or non-existent issue fails that gate.
//!
//! # Registry
//!
//! Every marker names one constant here. Add the constant, link the issue, and
//! reference it from the test — never an inline integer literal.
//!
//! | Issue | Symptom | Guarded by |
//! |---|---|---|
//! | [#387] | `hm(-0.0) != hm(+0.0)`: encrypted `=` on `real`/`double` disagrees with IEEE 754 for signed zero | `float_special::negative_zero_and_positive_zero_compare_equal_under_eq` |
//!
//! [#387]: https://github.com/cipherstash/encrypt-query-language/issues/387

use anyhow::{anyhow, Result};

/// The repository the `ISSUE_*` constants below refer to. Read by
/// `tasks/test/known-failures.sh`.
pub const KNOWN_FAILURE_REPO: &str = "cipherstash/encrypt-query-language";

/// `-0.0` and `+0.0` hash to different `hm` terms, because
/// `cipherstash-client`'s `Plaintext::to_vec()` feeds the raw `f64::to_be_bytes()`
/// (sign bit and all) into the HMAC, while the `orderable-bytes` ORE encoder
/// canonicalizes `-0.0 -> +0.0`. So encrypted `=` reports two IEEE-equal floats
/// as unequal, and `WHERE col = 0.0` misses rows stored as `-0.0`.
pub const ISSUE_FLOAT_SIGNED_ZERO_EQ: u64 = 387;

/// Mark `outcome` as a known failure attributable to an open issue.
///
/// Returns `Ok(())` **while `outcome` is `Err`** — i.e. while the bug still
/// reproduces — and `Err` once `outcome` becomes `Ok`, which means the bug is
/// fixed and this marker must be removed.
///
/// `what` describes the property that *should* hold, in the caller's words; it
/// is echoed in both messages so a failure here is self-explanatory without
/// opening the issue.
///
/// ```ignore
/// let equal = eq_cmp(&pool, a, b).await?;
/// let want = if equal { Ok(()) } else { Err(anyhow!("encrypted `=` returned false")) };
/// known_failure(ISSUE_FLOAT_SIGNED_ZERO_EQ, "-0.0 == +0.0 under public.eql_v3_double_eq", want)
/// ```
pub fn known_failure(issue: u64, what: &str, outcome: Result<()>) -> Result<()> {
    match outcome {
        Err(cause) => {
            // Not a silent skip: the reproduction is printed on every run, so a
            // `--nocapture` log shows exactly which bugs are still live.
            eprintln!(
                "known failure #{issue} still reproduces \
                 (https://github.com/{KNOWN_FAILURE_REPO}/issues/{issue}): \
                 {what} — {cause:#}"
            );
            Ok(())
        }
        Ok(()) => Err(anyhow!(
            "known failure #{issue} appears FIXED: `{what}` now holds. \
             Remove the `known_failure` marker (and its `ISSUE_*` constant) so the \
             assertion guards the behaviour again. \
             See https://github.com/{KNOWN_FAILURE_REPO}/issues/{issue}"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passes_while_the_bug_reproduces() {
        let still_broken = Err(anyhow!("encrypted `=` returned false"));
        assert!(known_failure(1, "-0.0 == +0.0", still_broken).is_ok());
    }

    #[test]
    fn fails_once_the_bug_is_fixed_so_the_marker_cannot_rot() {
        let now_fixed = Ok(());
        let err = known_failure(1, "-0.0 == +0.0", now_fixed)
            .expect_err("a passing assertion must fail the known-failure marker");
        let msg = err.to_string();
        assert!(msg.contains("appears FIXED"), "{msg}");
        assert!(msg.contains("Remove the `known_failure` marker"), "{msg}");
        assert!(msg.contains("issues/1"), "{msg}");
    }
}
