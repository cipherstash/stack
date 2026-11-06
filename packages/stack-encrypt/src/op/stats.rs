//! How many rows to fetch for a probabilistic query: [`Stats`] in,
//! [`Limit`] out (ADR-0009, decision 5).
//!
//! A Bloom match returns every real match and some rows that matched by
//! chance. A non-matching row whose stored filter has fill `f` (the
//! fraction of its bits set) passes a query that sets `b` bits with
//! probability about `f^b`. Over a table the pass rate `p` is the *mean* of
//! each row's `f^b`, and the false positives a query scanning `N` rows
//! draws are `Poisson(λ = p·N)`. To expect `want` real matches at a given
//! confidence, fetch
//!
//! ```text
//! want + Poisson_quantile(λ, confidence)
//! ```
//!
//! rows. The bound is probabilistic: at 99% confidence one query in a
//! hundred draws more false positives than the quantile.

/// What a probabilistic query's [`target_limit`] knows of the table: how
/// many rows the predicate scans, how full their stored filters are, and
/// the confidence the fetch should meet.
///
/// The numbers come from the server, read by the application at startup or
/// on a timer and kept as plain numbers. None of them is secret: the server
/// holds the filters and the catalog holds the row count. A stale `Stats`
/// moves the confidence, never the correctness, because
/// [`verify`](super::Probabilistic::verify) still decides every row.
///
/// [`target_limit`]: super::Probabilistic::target_limit
#[derive(Clone, Debug, PartialEq)]
pub struct Stats {
    rows: u64,
    fill: Fill,
    confidence: f64,
}

/// Where a [`Stats`] takes the stored filters' fill from.
#[derive(Clone, Debug, PartialEq)]
enum Fill {
    /// The index's declared `expected_tokens` prior.
    Declared,
    /// A histogram of set-bit counts: `(bits, rows)` pairs.
    Measured(Vec<(u32, u64)>),
}

/// The confidence a [`Stats`] targets unless told otherwise.
pub const DEFAULT_CONFIDENCE: f64 = 0.99;

/// The largest fetch a [`Limit`] names: PostgreSQL's `LIMIT` is a signed
/// 64-bit integer.
pub const MAX_ROWS: u64 = i64::MAX as u64;

impl Stats {
    /// Statistics from the index's declared prior
    /// ([`MatchConfig::expected_tokens`](crate::sem::MatchConfig::expected_tokens))
    /// and an estimate of the rows the query scans.
    ///
    /// `rows` counts the rows the predicate can match: those whose value is
    /// not NULL, since a NULL stores no filter and never passes. One catalog
    /// read gives it, and gives no row while the count is unknown:
    ///
    /// ```sql
    /// SELECT (c.reltuples * (1 - coalesce(s.null_frac, 0)))::bigint
    /// FROM pg_class c
    /// LEFT JOIN pg_stats s
    ///   ON s.schemaname = 'public' AND s.tablename = 'users' AND s.attname = 'name'
    /// WHERE c.oid = 'users'::regclass AND c.reltuples >= 0
    /// ```
    ///
    /// `reltuples` is −1 for a table never vacuumed or analysed, such as one
    /// just bulk-loaded. That is an unknown count, not an empty table: a
    /// count of 0 would promise a fetch of exactly `want`. With no row,
    /// build no `Stats`; page with a cursor ([`Limit::Unbounded`]) or run
    /// `ANALYZE` first.
    ///
    /// The prior knows nothing about the spread of value lengths, so it
    /// underestimates a column of mixed lengths; measure the column
    /// ([`measured`](Self::measured)) once it holds data. An index that
    /// declares no prior gives [`Limit::Unbounded`].
    pub fn declared(rows: u64) -> Self {
        Self {
            rows,
            fill: Fill::Declared,
            confidence: DEFAULT_CONFIDENCE,
        }
    }

    /// Statistics from a measured histogram of the stored filters' set-bit
    /// counts, as `(bits, rows)` pairs, and an estimate of the rows the
    /// query scans, read as [`declared`](Self::declared) says.
    ///
    /// One aggregate over the column gives the histogram, with at most `m`
    /// buckets; a page sample bounds its cost on a large table:
    ///
    /// ```sql
    /// SELECT cardinality(eql_v4.match_term(name)) AS bits, count(*)
    /// FROM users TABLESAMPLE SYSTEM (1)
    /// WHERE name IS NOT NULL
    /// GROUP BY 1
    /// ```
    ///
    /// A page sample can select no page of a small table, so drop the
    /// `TABLESAMPLE` there. An empty histogram falls back to the declared
    /// prior.
    pub fn measured(rows: u64, histogram: impl IntoIterator<Item = (u32, u64)>) -> Self {
        Self {
            rows,
            fill: Fill::Measured(histogram.into_iter().collect()),
            confidence: DEFAULT_CONFIDENCE,
        }
    }

    /// Target `confidence` instead of 99%: the probability that the fetch
    /// holds `want` real matches when the table has that many. Outside the
    /// open interval `(0, 1)` there is no finite fetch to promise, and
    /// [`target_limit`](super::Probabilistic::target_limit) answers
    /// [`Limit::Unbounded`]. So it does past ten million expected false
    /// positives for a confidence above `1 − 1e-15`, which the conservative
    /// bound used there cannot meet.
    pub fn with_confidence(mut self, confidence: f64) -> Self {
        self.confidence = confidence;
        self
    }

    /// The rows the query scans.
    pub fn rows(&self) -> u64 {
        self.rows
    }

    /// The confidence the fetch targets.
    pub fn confidence(&self) -> f64 {
        self.confidence
    }

    /// The probability that one non-matching row passes a query that sets
    /// `bits` of an `m`-bit filter, or `None` when nothing is known of the
    /// stored filters' fill. `declared` is the fill of one stored filter
    /// under the index's prior, if it declares one.
    pub(crate) fn pass_rate(&self, bits: u32, m: u32, declared: Option<f64>) -> Option<f64> {
        let measured = match &self.fill {
            Fill::Measured(histogram) => mean_power(histogram, bits, m),
            Fill::Declared => None,
        };
        measured.or_else(|| declared.map(|fill| fill.powi(bits as i32)))
    }

    /// The fetch for `want` real matches at pass rate `p`. Wanting none
    /// is a fetch of none, whatever is known of the table.
    pub(crate) fn limit(&self, want: u64, pass_rate: Option<f64>) -> Limit {
        if want == 0 {
            return Limit::Rows(0);
        }
        let Some(p) = pass_rate else {
            return Limit::Unbounded;
        };
        let promisable = self.confidence > 0.0 && self.confidence < 1.0;
        if !promisable || !p.is_finite() {
            return Limit::Unbounded;
        }
        let lambda = p.clamp(0.0, 1.0) * self.rows as f64;
        match poisson_quantile(lambda, self.confidence) {
            Some(extra) => Limit::Rows(want.saturating_add(extra).min(MAX_ROWS)),
            None => Limit::Unbounded,
        }
    }
}

/// The mean of `(bits_i / m)^b` over a histogram of set-bit counts, or
/// `None` for an empty one. A count above `m` (a histogram from another
/// configuration) is a full filter.
fn mean_power(histogram: &[(u32, u64)], b: u32, m: u32) -> Option<f64> {
    // Summed as floats: counts from a caller need not fit a `u64` total.
    let rows: f64 = histogram.iter().map(|&(_, rows)| rows as f64).sum();
    if rows == 0.0 || m == 0 {
        return None;
    }
    let total: f64 = histogram
        .iter()
        .map(|&(bits, rows)| {
            let fill = (f64::from(bits) / f64::from(m)).min(1.0);
            rows as f64 * fill.powi(b as i32)
        })
        .sum();
    Some(total / rows)
}

/// The fill of one stored filter of `tokens` tokens, each setting `k` of
/// `m` bits: `1 − e^(−k·tokens/m)`.
pub(crate) fn expected_fill(tokens: u32, k: usize, m: u32) -> f64 {
    1.0 - (-(k as f64) * f64::from(tokens) / f64::from(m)).exp()
}

/// How many rows a probabilistic query should fetch. Never more than
/// [`MAX_ROWS`], the largest `LIMIT` PostgreSQL takes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Limit {
    /// Fetch this many rows: `want` and the false positives expected at the
    /// stated confidence.
    Rows(u64),
    /// No finite fetch can be promised: the statistics say nothing about
    /// the stored filters, or the confidence is not below 1 (or, past ten
    /// million expected false positives, not below `1 − 1e-15`). Page through
    /// the candidates with a cursor until `want` rows verify.
    Unbounded,
}

impl Limit {
    /// The rows to fetch, if a finite fetch can be promised.
    pub fn rows(self) -> Option<u64> {
        match self {
            Self::Rows(rows) => Some(rows),
            Self::Unbounded => None,
        }
    }

    /// The rows to fetch, or `page` when no finite fetch can be promised,
    /// for a caller that pages either way. Never more than [`MAX_ROWS`]:
    /// a larger `page` is cut to it.
    pub fn fetch_or(self, page: u64) -> u64 {
        self.rows().unwrap_or(page.min(MAX_ROWS))
    }
}

/// The smallest `q` with `P(X ≤ q) ≥ confidence` for `X ~ Poisson(λ)`.
///
/// The probabilities are summed over a window from `λ − 10√λ` (or 0) that is
/// `22√λ + 50` wide, which holds all but about `1e-23` of the mass, and
/// normalised by the window's total. Each term is kept as a log relative to
/// the window's first, so no term carries the cancellation of `−λ + k·ln λ − ln k!` at a
/// large `λ`, and the sums run from the small end, so a confidence close to
/// 1 compares against a tail summed without losing it to rounding. The
/// answer is exact to within one at any confidence below `1 − 1e-12`. The
/// work is about `22√λ` terms.
/// Past `1e7` expected false positives the query is hopeless anyway and the
/// answer is the conservative `λ + 8√λ`, which covers any confidence up to
/// [`FALLBACK_CONFIDENCE`]; above it there is no answer (`None`), since an
/// eight-sigma tail is about `6e-16`.
///
/// `λ ≤ 0` and NaN have a window of one term at 0, so the answer is 0.
pub(crate) fn poisson_quantile(lambda: f64, confidence: f64) -> Option<u64> {
    if lambda > 1e7 {
        return (confidence <= FALLBACK_CONFIDENCE)
            .then(|| (lambda + 8.0 * lambda.sqrt()).ceil() as u64);
    }
    let spread = lambda.sqrt();
    // A float-to-integer cast saturates, and maps NaN to 0.
    let start = (lambda - 10.0 * spread).floor().max(0.0) as u64;
    // `22√λ + 50` past `start` reaches `λ + 12√λ + 50`. Capped, so no input
    // makes the window large: below `1e7` it is at most about 70,000 terms.
    let width = ((22.0 * spread + 50.0).ceil() as u64).min(MAX_WINDOW);
    let ln_lambda = lambda.ln();
    // Each term is `e^log` with `log` relative to the window's first term.
    // From `λ − 10√λ` to the mode that ratio is at most about `e^50`, and
    // from 0 to the mode of a `λ` below 100 about `e^λ`, so no term
    // overflows and none of the mass is lost to underflow.
    let mut weights = Vec::with_capacity(width as usize + 1);
    let mut log_term = 0.0;
    for offset in 0..=width {
        if offset > 0 {
            log_term += ln_lambda - ((start + offset) as f64).ln();
        }
        weights.push(log_term.exp());
    }
    // Summed from the top down, where the terms are smallest, so the tail a
    // high confidence compares against is not lost to rounding.
    let total: f64 = weights.iter().rev().sum();
    let allowed = (1.0 - confidence) * total;
    // Walking down from the top, `above` is the mass strictly above `k`.
    // The answer is the lowest `k` whose mass above is within what the
    // confidence allows.
    let mut answer = start + width;
    let mut above = 0.0;
    for (offset, weight) in weights.iter().enumerate().rev() {
        if above <= allowed {
            answer = start + offset as u64;
            above += weight;
        } else {
            break;
        }
    }
    Some(answer)
}

/// The highest confidence [`poisson_quantile`]'s bound past `1e7` meets:
/// `λ + 8√λ` leaves about `6e-16` of the mass above it.
const FALLBACK_CONFIDENCE: f64 = 1.0 - 1e-15;

/// The most terms [`poisson_quantile`] sums: far more than any `λ` below
/// `1e7` needs, and a bound on the work whatever it is handed.
const MAX_WINDOW: u64 = 1 << 20;

#[cfg(test)]
mod tests {
    use super::*;

    /// Reference quantiles, computed exactly with `math.lgamma` in log space.
    #[test]
    fn the_poisson_quantile_matches_reference_values() {
        for (lambda, confidence, expected) in [
            (0.034, 0.99, 1),
            (0.439, 0.99, 3),
            (1.0, 0.5, 1),
            (1.0, 0.99, 4),
            (10.0, 0.99, 18),
            (57.8, 0.99, 76),
            (100.0, 0.99, 124),
            (245.0, 0.99, 282),
            (1000.0, 0.999, 1099),
            (3800.0, 0.99, 3944),
            (7600.0, 0.99, 7804),
            (1e6, 0.99, 1_002_327),
        ] {
            assert_eq!(
                poisson_quantile(lambda, confidence),
                Some(expected),
                "λ = {lambda}, confidence = {confidence}"
            );
        }
        assert_eq!(poisson_quantile(0.0, 0.99), Some(0));
        assert_eq!(poisson_quantile(-1.0, 0.99), Some(0));
    }

    #[test]
    fn past_ten_million_the_quantile_is_conservative() {
        let lambda = 4e7;
        let q = poisson_quantile(lambda, 0.999_999).unwrap();
        assert!(q as f64 >= lambda + 4.9 * lambda.sqrt(), "{q}");
        assert!(q as f64 <= lambda + 8.0 * lambda.sqrt() + 1.0, "{q}");
    }

    /// The bound past ten million covers an eight-sigma tail and no more:
    /// a confidence it cannot meet has no finite fetch.
    #[test]
    fn past_ten_million_a_confidence_beyond_eight_sigma_is_unbounded() {
        let at = (4e7 + 8.0 * 4e7f64.sqrt()).ceil() as u64;
        assert_eq!(poisson_quantile(4e7, FALLBACK_CONFIDENCE), Some(at));
        let beyond = FALLBACK_CONFIDENCE.next_up();
        assert_eq!(poisson_quantile(4e7, beyond), None);
        assert_eq!(poisson_quantile(4e7, 1.0f64.next_down()), None);
        assert_eq!(
            Stats::declared(u64::MAX)
                .with_confidence(beyond)
                .limit(10, Some(0.5)),
            Limit::Unbounded
        );
        assert_eq!(
            Stats::declared(u64::MAX)
                .with_confidence(FALLBACK_CONFIDENCE)
                .limit(10, Some(0.5)),
            Limit::Rows(MAX_ROWS)
        );
    }

    #[test]
    fn a_confidence_at_one_still_ends() {
        // A float CDF may never reach 1; the window's end ends the sum.
        let q = poisson_quantile(5.0, 1.0).unwrap();
        // The window starts at 0 and is `⌈22√5 + 50⌉` wide.
        assert!((20..=100).contains(&q), "{q}");
        assert_eq!(poisson_quantile(f64::NAN, 0.99), Some(0));
        // A confidence above 1 allows no mass at all: the window's end.
        assert_eq!(poisson_quantile(5.0, 1.5), Some(100));
        assert_eq!(poisson_quantile(7600.0, 1.5), Some(6728 + 1968));
    }

    /// High confidences over a large `λ`, where summing from `e^(−λ)`
    /// loses precision: the window is normalised instead. References are
    /// exact (mpmath's regularised incomplete gamma); the sum may land one
    /// above, never below.
    #[test]
    fn the_quantile_holds_at_high_confidence_and_large_lambda() {
        for (lambda, confidence, exact) in [
            (3.4e6, 0.9999, 3_406_860),
            (4_750_922.0, 1.0 - 1e-12, 4_766_263),
            (1e7, 0.99, 10_007_357),
        ] {
            let q = poisson_quantile(lambda, confidence).unwrap();
            assert!(
                q == exact || q == exact + 1,
                "λ = {lambda}, confidence = {confidence}: {q}, exact {exact}"
            );
        }
    }

    /// ADR-0009 decision 5's worked table: EQL v4 defaults (`k = 6`,
    /// `m = 2048`), a million rows, 99%.
    #[test]
    fn the_declared_prior_reproduces_the_worked_table() {
        let stats = Stats::declared(1_000_000);
        for (tokens, bits, want_extra) in [(20, 6, 1), (200, 6, 7805), (200, 18, 3)] {
            let fill = expected_fill(tokens, 6, 2048);
            let p = stats.pass_rate(bits, 2048, Some(fill));
            assert_eq!(
                stats.limit(10, p),
                Limit::Rows(10 + want_extra),
                "{tokens} stored tokens, {bits} query bits"
            );
        }
    }

    /// The mixed-length column of decision 5: half the rows hold 20 tokens,
    /// half 200. The mean of `f^b` is what the bound needs; the mean fill
    /// raised to `b` would promise a fetch about fifteen times too small.
    #[test]
    fn a_measured_histogram_uses_the_mean_of_the_power_not_the_power_of_the_mean() {
        let short = (expected_fill(20, 6, 2048) * 2048.0).round() as u32;
        let long = (expected_fill(200, 6, 2048) * 2048.0).round() as u32;
        let stats = Stats::measured(1_000_000, [(short, 500_000), (long, 500_000)]);
        let p = stats.pass_rate(6, 2048, None).unwrap();
        let lambda = p * 1e6;
        assert!((3700.0..3900.0).contains(&lambda), "λ = {lambda}");

        let mean_fill = (f64::from(short) + f64::from(long)) / 2.0 / 2048.0;
        assert!(mean_fill.powi(6) * 1e6 < 300.0);
        let Limit::Rows(rows) = stats.limit(10, Some(p)) else {
            panic!("a measured column has a finite fetch");
        };
        assert!(rows > 3800, "{rows}");
    }

    #[test]
    fn nothing_known_is_unbounded() {
        let stats = Stats::declared(1_000_000);
        assert_eq!(
            stats.limit(10, stats.pass_rate(6, 2048, None)),
            Limit::Unbounded
        );

        let empty = Stats::measured(1_000_000, []);
        assert_eq!(empty.pass_rate(6, 2048, None), None);
        assert_eq!(
            empty.pass_rate(6, 2048, Some(0.5)),
            Some(0.5f64.powi(6)),
            "an empty histogram falls back to the prior"
        );
    }

    #[test]
    fn a_confidence_outside_the_open_interval_is_unbounded() {
        for confidence in [0.0, 1.0, -0.5, 1.5, f64::NAN] {
            let stats = Stats::declared(1000).with_confidence(confidence);
            assert_eq!(
                stats.limit(10, Some(0.01)),
                Limit::Unbounded,
                "{confidence}"
            );
        }
        let stats = Stats::declared(1000).with_confidence(0.5);
        assert_eq!(stats.confidence(), 0.5);
        assert_eq!(stats.rows(), 1000);
        assert_eq!(stats.limit(10, Some(0.01)), Limit::Rows(10 + 10));
    }

    #[test]
    fn a_count_above_the_filter_size_is_a_full_filter() {
        let stats = Stats::measured(100, [(5000, 1)]);
        assert_eq!(stats.pass_rate(6, 2048, None), Some(1.0));
        // Every row passes: λ = 100, whose 99% quantile is 124.
        assert_eq!(stats.limit(1, Some(1.0)), Limit::Rows(1 + 124));
    }

    #[test]
    fn a_limit_reads_back_as_rows_or_a_page() {
        assert_eq!(Limit::Rows(12).rows(), Some(12));
        assert_eq!(Limit::Rows(12).fetch_or(50), 12);
        assert_eq!(Limit::Unbounded.rows(), None);
        assert_eq!(Limit::Unbounded.fetch_or(50), 50);
        assert_eq!(Limit::Unbounded.fetch_or(MAX_ROWS), MAX_ROWS);
        assert_eq!(
            Limit::Unbounded.fetch_or(u64::MAX),
            MAX_ROWS,
            "a page is cut to a SQL LIMIT"
        );
    }

    /// Wanting no rows is a fetch of none, even over a table whose every
    /// row passes and whose filters nothing is known about.
    #[test]
    fn wanting_no_rows_fetches_none() {
        let stats = Stats::declared(1_000_000);
        assert_eq!(stats.limit(0, Some(1.0)), Limit::Rows(0));
        assert_eq!(stats.limit(0, None), Limit::Rows(0));
        assert_eq!(stats.limit(1, Some(1.0)).rows().map(|r| r > 1), Some(true));
    }

    #[test]
    fn a_limit_fits_a_sql_limit() {
        assert_eq!(
            Stats::declared(10).limit(u64::MAX, Some(0.5)),
            Limit::Rows(MAX_ROWS)
        );
        // The largest count there is: what `reltuples` −1 becomes if a
        // caller casts it to a `u64`, rather than treating it as unknown as
        // `Stats::declared` says. Still a valid `LIMIT`.
        assert_eq!(
            Stats::declared(u64::MAX).limit(10, Some(0.5)),
            Limit::Rows(MAX_ROWS)
        );
    }

    #[test]
    fn histogram_counts_do_not_overflow() {
        let stats = Stats::measured(10, [(1024, u64::MAX), (2048, u64::MAX)]);
        let p = stats.pass_rate(1, 2048, None).unwrap();
        assert!((p - 0.75).abs() < 1e-12, "{p}");
    }
}
