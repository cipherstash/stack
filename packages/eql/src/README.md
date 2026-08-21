### Adding SQL


- Never drop the configuration table as it may contain customer data and needs to live across EQL versions
- Everything else should have a `DROP IF EXISTS`
- Functions should be `DROP` and `CREATE`, instead of `CREATE OR REPLACE`
 - Data types cannot be changed once created, so dropping first is more flexible
- Keep `DROP` and `CREATE` together in the code
- Types need to be dropped last, add to the `666-drop_types.sql`




