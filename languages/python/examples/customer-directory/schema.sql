CREATE TABLE customers (
    id         bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    email      public.eql_v4_text_eq NOT NULL,
    name       public.eql_v4_text NOT NULL,
    plan       text NOT NULL,
    created_at timestamptz NOT NULL
);

-- A B-tree index, because PostgreSQL cannot make a hash index unique.
CREATE UNIQUE INDEX customers_email_unique ON customers (eql_v4.eq_term(email));
