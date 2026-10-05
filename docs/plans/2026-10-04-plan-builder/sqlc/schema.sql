CREATE TABLE users (
    id          bigint PRIMARY KEY,
    email       bytea  NOT NULL,
    email_eq    bytea  NOT NULL,
    email_match bytea  NOT NULL,
    age         bytea  NOT NULL,
    age_eq      bytea  NOT NULL,
    age_ore     bytea  NOT NULL,
    attrs       jsonb  NOT NULL,
    notes       bytea  NOT NULL
);

CREATE INDEX users_email_eq ON users (email_eq);
