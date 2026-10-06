CREATE TABLE users (
    id    bigint                 PRIMARY KEY,
    email public.eql_v3_text_eq  NOT NULL,
    name  public.eql_v3_text_eq  NOT NULL
);
