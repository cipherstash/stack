-- Seed a users table with plaintext emails for e2e backfill testing.
--
-- The EQL v3 encrypted target column must be created separately (for example,
-- by Drizzle Kit), after which backfill encrypts `email` → `email_encrypted`.

DROP TABLE IF EXISTS users CASCADE;

CREATE TABLE users (
  id        bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  email     text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

INSERT INTO users (email)
SELECT 'user-' || g || '@example.com'
FROM generate_series(1, 5000) AS g;
