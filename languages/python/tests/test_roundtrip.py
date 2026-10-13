"""Live ZeroKMS. Skipped when no credentials resolve.

Sync calls only — async is backlog item 4. The engine's `Pending` is
`IntoFuture`, so the sync surface is one Tokio runtime and `block_on` with
the GIL released.
"""

from dataclasses import dataclass
from typing import Annotated

import pytest

from stackencrypt import EQL, Cipher, Equality, Int64, Passthrough, Plan, Text
from stackencrypt.errors import EngineError


@dataclass
class User:
    email: Annotated[str, Text, EQL(Equality)]
    age: Annotated[int, Int64, Passthrough()]


@pytest.fixture(scope="module")
def plan():
    return Plan.of(User).context("users").build()


@pytest.fixture(scope="module")
def cipher(live, plan):
    # `live` is the session's engine handle; reuse it rather than paying the
    # credential round trip again per module.
    return Cipher(plan, engine=live)


def test_a_batch_round_trips(cipher):
    users = [User(email=f"user{n}@example.com", age=30 + n) for n in range(5)]

    records = cipher.encrypt(users)
    assert len(records) == 5

    back = cipher.decrypt(records)
    assert [user.email for user in back] == [user.email for user in users]
    assert [user.age for user in back] == [user.age for user in users]
    assert all(isinstance(user, User) for user in back)


def test_a_passthrough_field_comes_back_as_an_int_not_a_float(cipher):
    [back] = cipher.decrypt(cipher.encrypt([User(email="n@example.com", age=41)]))

    assert back.age == 41
    assert isinstance(back.age, int)
    assert not isinstance(back.age, float)


def test_a_batch_makes_one_key_request(cipher):
    # Principle G5. The counter is the shell's; the assertion is that a
    # batch of five does not make five requests.
    users = [User(email=f"b{n}@example.com", age=n) for n in range(5)]
    before = cipher.key_requests

    cipher.encrypt(users)

    assert cipher.key_requests - before == 1


# Review Focus 5: an empty batch must not reach ZeroKMS at all.
def test_an_empty_batch_returns_empty_and_makes_no_request(cipher):
    before = cipher.key_requests

    assert cipher.encrypt([]) == []
    assert cipher.decrypt([]) == []

    assert cipher.key_requests == before


# Review Focus 4: the spec is silent on None. Refuse it with the field
# named rather than sealing it as something else.
def test_none_in_an_encrypted_field_is_refused(cipher):
    with pytest.raises(EngineError, match="email"):
        cipher.encrypt([User(email=None, age=1)])


def test_a_value_of_the_wrong_kind_is_refused_before_any_key(cipher):
    before = cipher.key_requests

    with pytest.raises(EngineError):
        cipher.encrypt([User(email="ok@example.com", age="not a number")])

    # The refusal is decided before the pending exists, so no key was minted.
    assert cipher.key_requests == before


def test_a_query_term_is_bytes(cipher):
    term = cipher.query("email", "user0@example.com")

    assert isinstance(term, bytes)
    assert term


def test_querying_a_field_the_plan_does_not_name_is_refused(cipher):
    with pytest.raises(EngineError, match="nickname"):
        cipher.query("nickname", "x")


def test_querying_a_passthrough_field_is_refused(cipher):
    # A passthrough field derives no term, so there is nothing to query by.
    with pytest.raises(EngineError, match="age"):
        cipher.query("age", 30)
