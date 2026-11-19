-- The tables the example generates from. The EQL v4 domains are the ones the
-- EQL v4 bundle installs; sqlc doesn't need their definitions.
CREATE TYPE user_status AS ENUM ('active', 'closed');

CREATE TABLE users (
    id uuid PRIMARY KEY,
    parent_id uuid REFERENCES users (id),
    created_at timestamptz NOT NULL,
    status user_status NOT NULL,
    given_name_eql4_search public.eql_v4_text_search NOT NULL,
    nickname_eql4 public.eql_v4_text,
    email_eql4_eq public.eql_v4_text_eq,
    dob_eql4 public.eql_v4_date,
    annotations_eql4_search public.eql_v4_json_search
);

CREATE TABLE contacts (
    id uuid PRIMARY KEY,
    user_id uuid NOT NULL REFERENCES users (id),
    email_eql4_eq eql_v4_text_eq NOT NULL,
    notes_eql4 eql_v4_text
);

-- A view gets no per-column values.
CREATE VIEW user_summaries AS SELECT id, status FROM users;
