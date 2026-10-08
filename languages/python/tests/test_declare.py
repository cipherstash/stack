"""Reading a class's `Annotated` hints into the engine's data plan.

Pure Python: no engine call, no credentials, no database. The engine's own
plan checks are `test_plan.py`.
"""

from dataclasses import dataclass
from typing import Annotated

import pytest

from stackencrypt import EQL, Equality, Int64, Match, Passthrough, Plan, Text, _declare
from stackencrypt.errors import DeclarationError


@dataclass
class User:
    email: Annotated[str, Text, EQL(Equality)]
    age: Annotated[int, Int64, Passthrough()]
    id: Annotated[int, Int64, Passthrough()]


def test_engine_module_loads():
    import stackencrypt

    assert isinstance(stackencrypt.engine_version(), str)
    assert stackencrypt.engine_version() != ""


def test_a_target_field_carries_context_and_type_but_no_outputs():
    spec = Plan.of(User).context("users").build()

    assert spec.fields["email"]["context"] == ["users", "email"]
    assert spec.fields["email"]["type"] == "string"
    # A target field and an outputs field are exclusive in the wire grammar.
    assert "outputs" not in spec.fields["email"]


def test_the_declaration_writes_a_target_request_not_an_eql_name():
    # Read `_declare` directly: by the time `build()` returns, the engine's
    # resolver has replaced the request with the name it answered. The pair
    # is what Python writes, and that it writes NO EQL name is principle G1
    # at the declaration layer.
    written = _declare.fields(User, ("users",))

    assert written["email"]["target"] == {"index": "eq", "kind": "string"}


def test_a_passthrough_field_carries_outputs_and_no_target():
    spec = Plan.of(User).context("users").build()

    assert spec.fields["age"]["outputs"] == ["passthrough"]
    assert "target" not in spec.fields["age"]


def test_a_bare_index_field_carries_the_ciphertext_and_the_term():
    @dataclass
    class Plain:
        note: Annotated[str, Text, Match]

    spec = Plan.of(Plain).context("notes").build()

    assert spec.fields["note"]["outputs"] == ["c", "match"]
    assert spec.fields["note"]["type"] == "string"


def test_every_declared_field_appears_in_the_plan():
    spec = Plan.of(User).context("users").build()

    assert set(spec.fields) == {"email", "age", "id"}


# Review Focus 2: decision 20 — a field with no stash annotation stops the
# program at import, it does not quietly become a passthrough.
def test_a_field_with_no_stash_annotation_is_refused():
    @dataclass
    class Loose:
        email: Annotated[str, Text, EQL(Equality)]
        nickname: str

    with pytest.raises(DeclarationError, match="nickname"):
        Plan.of(Loose).context("users").build()


# Review Focus 1, at the declaration layer: an index needs a width, because
# the engine refuses a plan whose indexed field declares no type.
def test_an_indexed_field_with_no_width_type_is_refused():
    @dataclass
    class Untyped:
        age: Annotated[int, EQL(Equality)]

    with pytest.raises(DeclarationError, match="age"):
        Plan.of(Untyped).context("users").build()


def test_a_field_that_is_both_passthrough_and_encrypted_is_refused():
    @dataclass
    class Both:
        email: Annotated[str, Text, Passthrough(), EQL(Equality)]

    with pytest.raises(DeclarationError, match="email"):
        Plan.of(Both).context("users").build()


def test_a_field_with_both_a_target_and_a_bare_index_is_refused():
    @dataclass
    class Both:
        email: Annotated[str, Text, EQL(Equality), Match]

    with pytest.raises(DeclarationError, match="email"):
        Plan.of(Both).context("users").build()


def test_an_empty_context_is_refused():
    with pytest.raises(DeclarationError, match="context"):
        Plan.of(User).build()


def test_a_model_with_no_fields_is_refused():
    @dataclass
    class Empty:
        pass

    with pytest.raises(DeclarationError):
        Plan.of(Empty).context("users").build()


def test_an_unrelated_annotation_is_not_read_as_a_declaration():
    # `Kind` is a type, not a bare string, so a note in the annotation is a
    # note. Without that this field would declare the kind "a note".
    @dataclass
    class Noted:
        email: Annotated[str, "a note for the reader", Text, EQL(Equality)]

    spec = Plan.of(Noted).context("users").build()

    assert spec.fields["email"]["type"] == "string"
