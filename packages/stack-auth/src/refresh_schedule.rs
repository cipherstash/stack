//! When a token is refreshed ahead of its expiry, and how long to wait
//! after a refresh fails.
//!
//! [`RefreshSchedule`] is the one rule every SDK follows. It is plain data:
//! it reads no clock and starts no task. A strategy on a native target
//! drives it from a background task of its own. A WebAssembly host drives
//! it from its own timer, through a strategy's
//! [`next_refresh`](crate::AccessKeyStrategy::next_refresh) and
//! [`refresh_now`](crate::AccessKeyStrategy::refresh_now).

use crate::Token;

/// How long before a token's expiry its refresh is due, at the earliest.
/// That is 30 seconds before the 90-second leeway in which a call would
/// refresh it anyway, so a failed refresh has time for retries.
pub const REFRESH_AHEAD_SECS: u64 = 120;

/// The refresh of each token is due at a random moment in the
/// [`REFRESH_JITTER_SECS`] after [`REFRESH_AHEAD_SECS`] before its expiry,
/// so processes whose tokens were issued together do not all refresh at
/// once.
pub const REFRESH_JITTER_SECS: u64 = 30;

/// The longest wait between two attempts after refreshes fail. The first
/// wait is about a second, and each failure doubles it up to this.
pub const BACKOFF_CAP_SECS: u64 = 30;

/// When the next refresh is due.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NextRefresh {
    /// Nothing to do until the strategy is used again: it has not been used
    /// since its last refresh, it has no token yet, or its token cannot be
    /// refreshed.
    Idle,
    /// Due at this time, in seconds since the Unix epoch. A time already
    /// past means now.
    At(u64),
}

/// The refresh plan for one strategy's token.
///
/// A token is refreshed ahead of its expiry only while the strategy is in
/// use: [`used`](Self::used) marks a call for a token, and every refresh
/// attempt clears the mark. So a process that stops asking for tokens stops
/// asking the token service too.
///
/// After a refresh fails, the next attempt waits: about a second after the
/// first failure, doubling with each one up to [`BACKOFF_CAP_SECS`], each
/// wait chosen at random between half its length and its length.
#[derive(Debug, Clone)]
pub struct RefreshSchedule {
    /// The expiry of the token the plan is for.
    expires_at: Option<u64>,
    /// When that token's refresh is due, or `None` when it cannot be
    /// refreshed.
    refresh_at: Option<u64>,
    used: bool,
    failures: u32,
    /// When the last refresh failed, and when the next may start.
    failed_at: u64,
    retry_at: Option<u64>,
    random: SplitMix64,
}

impl Default for RefreshSchedule {
    fn default() -> Self {
        Self::new()
    }
}

impl RefreshSchedule {
    /// A plan with no token yet.
    pub fn new() -> Self {
        Self::with_seed(SplitMix64::seed())
    }

    /// A plan whose random choices are fixed by `seed`, for tests.
    pub(crate) fn with_seed(seed: u64) -> Self {
        Self {
            expires_at: None,
            refresh_at: None,
            used: false,
            failures: 0,
            failed_at: 0,
            retry_at: None,
            random: SplitMix64(seed),
        }
    }

    /// Plan for `token`, the strategy's token at `now`. A token the plan has
    /// already seen changes nothing. A new one, from a refresh or from
    /// another process, ends any backoff, and its refresh is due
    /// [`REFRESH_AHEAD_SECS`] before its expiry, give or take the jitter, or
    /// half way through its remaining life if that is later.
    pub fn observe(&mut self, token: &Token, now: u64) {
        let expires_at = token.expires_at();
        if self.expires_at == Some(expires_at) {
            return;
        }
        self.expires_at = Some(expires_at);
        self.failures = 0;
        self.retry_at = None;
        let jitter = self.random.below(REFRESH_JITTER_SECS + 1);
        let ahead = expires_at.saturating_sub(REFRESH_AHEAD_SECS - jitter);
        let half_way = now.saturating_add(expires_at.saturating_sub(now) / 2);
        self.refresh_at = Some(ahead.max(half_way));
    }

    /// Mark a call for a token. Returns whether the plan was idle, so the
    /// caller knows to wake whoever drives it.
    pub fn used(&mut self) -> bool {
        let was_idle = !self.used;
        self.used = true;
        was_idle && self.refresh_at.is_some()
    }

    /// A refresh attempt is starting. It clears the mark of use: the next
    /// refresh ahead waits for another call.
    pub fn attempt_started(&mut self) {
        self.used = false;
    }

    /// The refresh attempt that started last failed at `now` with `error`.
    /// The next one waits for the backoff, and a refusal of the account
    /// (a usage limit, an organisation not yet provisioned) for at least a
    /// minute: retrying sooner cannot change the answer.
    pub fn refresh_failed(&mut self, error: &crate::AuthError, now: u64) {
        let at_least = if error.is_account_refusal() {
            crate::auto_refresh::DENIAL_TTL_SECS
        } else {
            0
        };
        self.attempt_failed(now, at_least);
    }

    /// [`refresh_failed`](Self::refresh_failed), with the minimum wait
    /// given directly.
    pub(crate) fn attempt_failed(&mut self, now: u64, at_least: u64) {
        self.failures = self.failures.saturating_add(1);
        let ceiling = 1u64
            .checked_shl(self.failures - 1)
            .unwrap_or(u64::MAX)
            .min(BACKOFF_CAP_SECS);
        let floor = ceiling.div_ceil(2);
        let wait = floor + self.random.below(ceiling - floor + 1);
        self.failed_at = now;
        self.retry_at = Some(now.saturating_add(wait.max(at_least)));
    }

    /// The token cannot be refreshed: it has no refresh credential. Nothing
    /// is due until a new token is observed.
    pub fn cannot_refresh(&mut self) {
        self.refresh_at = None;
    }

    /// When the next refresh is due.
    pub fn next(&self) -> NextRefresh {
        match self.refresh_at {
            Some(refresh_at) if self.used => {
                NextRefresh::At(refresh_at.max(self.retry_at.unwrap_or(0)))
            }
            _ => NextRefresh::Idle,
        }
    }

    /// Whether a refresh failed and its backoff has not ended by `now`. A
    /// call does not start a refresh of its own while it lasts.
    ///
    /// A clock that reads earlier than the failure (an NTP step, a restored
    /// snapshot) ends the backoff: how long has passed is then unknown, and
    /// asking again costs one request where waiting could lock the caller
    /// out until the clock catches up.
    pub fn backing_off(&self, now: u64) -> bool {
        self.retry_at
            .is_some_and(|retry_at| self.failed_at <= now && now < retry_at)
    }
}

/// A small, fast generator for the jitter. Not for secrets: it only spreads
/// refreshes over time.
#[derive(Debug, Clone)]
struct SplitMix64(u64);

impl SplitMix64 {
    /// A seed that differs between processes and between plans: the
    /// standard library's per-process hash keys, the time, and a counter.
    fn seed() -> u64 {
        use std::hash::{BuildHasher, Hasher};
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
        hasher.write_u64(COUNTER.fetch_add(1, Ordering::Relaxed));
        let nanos = web_time::SystemTime::now()
            .duration_since(web_time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default();
        hasher.write_u128(nanos);
        hasher.finish()
    }

    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// A value in `0..limit`; `limit` is small, so the bias is negligible.
    fn below(&mut self, limit: u64) -> u64 {
        self.next() % limit.max(1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SecretToken;
    use proptest::prelude::*;

    fn token(expires_at: u64) -> Token {
        Token {
            access_token: SecretToken::new("t"),
            refresh_token: None,
            token_type: "Bearer".into(),
            expires_at,
            region: None,
            client_id: None,
            device_instance_id: None,
            federated_from: None,
        }
    }

    fn due(plan: &RefreshSchedule) -> u64 {
        match plan.next() {
            NextRefresh::At(at) => at,
            NextRefresh::Idle => panic!("idle"),
        }
    }

    #[test]
    fn a_plan_with_no_token_is_idle() {
        let mut plan = RefreshSchedule::with_seed(1);
        plan.used();
        assert_eq!(plan.next(), NextRefresh::Idle);
    }

    #[test]
    fn an_unused_plan_is_idle_and_a_use_wakes_it() {
        let mut plan = RefreshSchedule::with_seed(1);
        plan.observe(&token(1_900), 1_000);
        assert_eq!(plan.next(), NextRefresh::Idle);
        assert!(plan.used(), "the first use reports an idle plan");
        assert!(!plan.used(), "a second use does not");
        assert!(matches!(plan.next(), NextRefresh::At(_)));
        plan.attempt_started();
        assert_eq!(plan.next(), NextRefresh::Idle);
    }

    #[test]
    fn a_use_before_any_token_wakes_nothing() {
        let mut plan = RefreshSchedule::with_seed(1);
        assert!(!plan.used());
    }

    #[test]
    fn a_token_that_cannot_be_refreshed_is_idle_until_a_new_one() {
        let mut plan = RefreshSchedule::with_seed(1);
        plan.observe(&token(1_900), 1_000);
        plan.used();
        plan.cannot_refresh();
        assert_eq!(plan.next(), NextRefresh::Idle);
        plan.observe(&token(1_900), 1_000);
        assert_eq!(plan.next(), NextRefresh::Idle, "the same token");
        plan.observe(&token(2_800), 1_900);
        assert!(matches!(plan.next(), NextRefresh::At(_)), "a new token");
    }

    #[test]
    fn the_first_backoff_is_one_second() {
        let mut plan = RefreshSchedule::with_seed(1);
        plan.observe(&token(1_900), 1_000);
        plan.used();
        plan.attempt_failed(1_790, 0);
        assert_eq!(plan.retry_at, Some(1_791));
        assert!(due(&plan) >= 1_791);
        assert!(plan.backing_off(1_790));
        assert!(!plan.backing_off(1_791));
    }

    #[test]
    fn a_refusal_of_the_account_waits_at_least_its_minimum() {
        let mut plan = RefreshSchedule::with_seed(1);
        plan.observe(&token(1_900), 1_000);
        plan.used();
        plan.attempt_failed(1_790, 60);
        assert_eq!(due(&plan), 1_850);
    }

    #[test]
    fn a_clock_that_goes_back_ends_the_backoff() {
        let mut plan = RefreshSchedule::with_seed(1);
        plan.observe(&token(1_900), 1_000);
        plan.attempt_failed(1_790, 60);
        assert!(plan.backing_off(1_800));
        assert!(!plan.backing_off(1_789));
    }

    #[test]
    fn a_new_token_ends_the_backoff() {
        let mut plan = RefreshSchedule::with_seed(1);
        plan.observe(&token(1_900), 1_000);
        for _ in 0..10 {
            plan.attempt_failed(1_790, 0);
        }
        assert!(plan.backing_off(1_790));
        plan.observe(&token(2_800), 1_791);
        assert!(!plan.backing_off(1_791));
        plan.attempt_failed(1_791, 0);
        assert_eq!(plan.retry_at, Some(1_792), "the failure count restarted");
    }

    proptest! {
        /// A token's refresh is due before it expires, no earlier than
        /// REFRESH_AHEAD_SECS before, and no later than the jitter allows
        /// or half way through its remaining life.
        #[test]
        fn a_refresh_is_due_ahead_of_expiry(
            seed: u64,
            now in 0u64..1 << 40,
            life in 1u64..100_000,
        ) {
            let mut plan = RefreshSchedule::with_seed(seed);
            plan.observe(&token(now + life), now);
            plan.used();
            let at = due(&plan);
            prop_assert!(at < now + life, "due at or after expiry");
            prop_assert!(at + REFRESH_AHEAD_SECS >= now + life, "due too early");
            prop_assert!(
                at <= (now + life).saturating_sub(REFRESH_AHEAD_SECS - REFRESH_JITTER_SECS)
                    || at == now + life / 2,
                "due later than the jitter or half way"
            );
        }

        /// The waits after failures stay between one second and the cap,
        /// and their upper bound never shrinks as failures mount.
        #[test]
        fn the_backoff_grows_to_its_cap(seed: u64, failures in 1usize..64) {
            let mut plan = RefreshSchedule::with_seed(seed);
            plan.observe(&token(1_000_000), 0);
            plan.used();
            let mut ceiling = 0;
            for n in 1..=failures {
                plan.attempt_failed(500, 0);
                let wait = plan.retry_at.unwrap() - 500;
                let this_ceiling = (1u64 << (n - 1).min(10)).min(BACKOFF_CAP_SECS);
                prop_assert!((1..=BACKOFF_CAP_SECS).contains(&wait));
                prop_assert!(wait <= this_ceiling && wait >= this_ceiling.div_ceil(2));
                prop_assert!(this_ceiling >= ceiling);
                ceiling = this_ceiling;
            }
        }

        /// A token observed again changes nothing.
        #[test]
        fn observing_the_same_token_again_keeps_the_plan(seed: u64, later in 0u64..1_000) {
            let mut plan = RefreshSchedule::with_seed(seed);
            plan.observe(&token(10_000), 1_000);
            plan.used();
            plan.attempt_failed(1_000, 0);
            let before = plan.clone();
            plan.observe(&token(10_000), 1_000 + later);
            prop_assert_eq!(plan.next(), before.next());
            prop_assert_eq!(plan.backing_off(1_000), before.backing_off(1_000));
        }

        /// Jitter spreads the plans of tokens issued together.
        #[test]
        fn tokens_issued_together_refresh_at_different_times(seed in 0u64..1_000) {
            let times: std::collections::HashSet<u64> = (0..64)
                .map(|i| {
                    let mut plan = RefreshSchedule::with_seed(seed * 64 + i);
                    plan.observe(&token(10_000), 9_100);
                    plan.used();
                    due(&plan)
                })
                .collect();
            prop_assert!(times.len() > 8, "only {} distinct times", times.len());
        }
    }
}
