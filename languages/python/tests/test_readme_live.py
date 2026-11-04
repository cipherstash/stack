"""The README, run as a reader runs it: its SQL creates the table, and its
Python blocks encrypt, insert, select, decrypt and query, in order.

Needs the four CipherStash credentials and ``EQL_TEST_DATABASE_URL``, with
the EQL v4 bundle installed. The run gets a schema of its own, so the
README's ``users`` table meets no other test's.
"""

import uuid

import pytest
from _live import DATABASE_URL, LIVE, needs_database, run_python
from _readme import CHECK, blocks, program

pytestmark = [*LIVE, needs_database]


def test_a_reader_following_the_readme_finds_the_row_by_equality():
    psycopg = pytest.importorskip("psycopg")
    schema = f"readme_{uuid.uuid4().hex[:12]}"
    # public stays on the path: EQL's operators, such as the `=` the query
    # uses, are installed there unqualified.
    url = psycopg.conninfo.make_conninfo(DATABASE_URL, options=f"-c search_path={schema},public")
    with psycopg.connect(DATABASE_URL, autocommit=True) as conn:
        conn.execute(f"CREATE SCHEMA {schema}")
    try:
        with psycopg.connect(url, autocommit=True) as conn:
            for sql in blocks("sql"):
                conn.execute(sql)

        found = run_python(["-c", program() + CHECK], env={"DATABASE_URL": url})
    finally:
        with psycopg.connect(DATABASE_URL, autocommit=True) as conn:
            conn.execute(f"DROP SCHEMA {schema} CASCADE")

    assert found == [{"email": "a@example.com", "age": 3}]
