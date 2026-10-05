-- For sqlc only: sqlc cannot parse the EQL install bundle. Spell each domain
-- exactly as schema.sql and query.sql do, or its db_type override never matches.
CREATE SCHEMA eql_v3;

CREATE DOMAIN public.eql_v3_text_search AS jsonb;
CREATE DOMAIN public.eql_v3_integer_ord AS jsonb;
CREATE DOMAIN public.eql_v3_json_search AS jsonb;

CREATE DOMAIN eql_v3.query_text_search AS jsonb;
CREATE DOMAIN eql_v3.query_integer_ord AS jsonb;
