//! Preflight gate: the Postgres shared lock table must be big enough for the
//! suite's concurrent `DROP ... CASCADE` load.
//!
//! Why this exists: the shipped uninstaller drops both `eql_v3` schemas with
//! `DROP ... CASCADE`. That takes a lock on every one of the ~5,700 objects it
//! removes and holds them until the transaction commits — `sqlx::raw_sql` sends
//! the whole script as ONE implicit transaction. `max_locks_per_transaction` is
//! not a per-transaction cap; it sizes the *cluster-wide* shared lock table as
//! `max_locks_per_transaction * max_connections`. At the stock 64 * 100 = 6,400
//! slots a single uninstall already holds ~89% of the table, so two overlapping
//! ones exhaust it — and the backends that then fail with `53200 out of shared
//! memory` are mostly INNOCENT tests that were merely installing EQL.
//!
//! That failure mode is maximally confusing: a handful of unrelated tests fail
//! ~20 minutes into CI with what reads like an out-of-memory error, and only on
//! whichever shard happened to pack the uninstall-heavy tests together. This
//! test converts it into one immediate, self-explanatory failure naming the
//! cause and the fix.
//!
//! `tests/docker-compose.yml` provisions the capacity (`-c
//! max_locks_per_transaction=1024`); this asserts the database under test
//! actually has it.

use anyhow::Result;
use eql_tests::property::connect_pool;

/// Locks held by one full run of the shipped uninstaller, measured against the
/// v3 surface (`DROP ... CASCADE` over ~5,682 objects, plus catalog locks).
/// This grows as the catalog grows — it is a measured floor, not a constant of
/// nature.
const LOCKS_PER_UNINSTALL: i64 = 5_700;

/// Worst-case simultaneous uninstalls: nextest runs one test per core, and CI
/// runners have 16. Every one of those slots could be an uninstall-heavy test.
const WORST_CASE_CONCURRENT_UNINSTALLS: i64 = 16;

/// The capacity the suite needs: ~91k slots. The compose setting (1024 * 100 =
/// 102,400) clears this; the stock default (6,400) misses it by ~14x.
const MIN_LOCK_TABLE_CAPACITY: i64 = LOCKS_PER_UNINSTALL * WORST_CASE_CONCURRENT_UNINSTALLS;

/// Read an integer GUC. Both settings are plain integers with no unit, so
/// `current_setting` parses cleanly.
async fn int_setting(pool: &sqlx::PgPool, name: &str) -> Result<i64> {
    let raw: String = sqlx::query_scalar(&format!("SELECT current_setting('{name}')"))
        .fetch_one(pool)
        .await?;
    Ok(raw.parse()?)
}

/// The lock table must hold the suite's worst-case concurrent uninstall load.
///
/// Asserts on the derived *capacity* rather than on `max_locks_per_transaction`
/// alone, so an operator who reaches the same headroom by a different split
/// (e.g. a larger `max_connections`) still passes.
#[tokio::test]
async fn lock_table_fits_concurrent_uninstalls() -> Result<()> {
    let pool = connect_pool().await?;

    let max_locks = int_setting(&pool, "max_locks_per_transaction").await?;
    let max_connections = int_setting(&pool, "max_connections").await?;
    let capacity = max_locks * max_connections;

    assert!(
        capacity >= MIN_LOCK_TABLE_CAPACITY,
        "Postgres shared lock table is too small for this suite: \
         max_locks_per_transaction ({max_locks}) * max_connections ({max_connections}) \
         = {capacity} slots, need >= {MIN_LOCK_TABLE_CAPACITY} \
         ({WORST_CASE_CONCURRENT_UNINSTALLS} concurrent uninstalls * \
         ~{LOCKS_PER_UNINSTALL} locks each).\n\
         \n\
         Left unfixed this does NOT fail here — it surfaces later as \
         `53200 out of shared memory` in whichever unrelated tests happen to run \
         alongside an uninstall.\n\
         \n\
         Fix: tests/docker-compose.yml sets `-c max_locks_per_transaction=1024`. \
         A container created before that change keeps the old setting, so recreate it:\n\
         \n    mise run postgres:down && mise run postgres:up postgres-17\n"
    );

    Ok(())
}
