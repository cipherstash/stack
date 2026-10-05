-- For sqlc only: sqlc cannot parse the EQL install bundle. Spell each domain
-- exactly as schema.sql and query.sql do, or its db_type override never matches.
CREATE SCHEMA eql_v3;

CREATE DOMAIN public.eql_v3_text_eq AS jsonb;
CREATE DOMAIN eql_v3.query_text_eq AS jsonb;
