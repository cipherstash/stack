CREATE TABLE users (
    id    bigint                     PRIMARY KEY,
    email public.eql_v3_text_search  NOT NULL,
    age   public.eql_v3_integer_ord  NOT NULL,
    attrs public.eql_v3_json_search  NOT NULL,
    notes public.eql_v3_text         NOT NULL
);
