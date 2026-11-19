// One-off database conversion entry point. It runs separately from application
// startup, during a write-maintenance window, against the assigned database.
// The unmigrated application has nothing to convert.
export async function migrate(_env = process.env) {}
