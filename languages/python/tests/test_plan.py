"""The engine's own plan checks.

No credentials and no database: parsing a plan mints no key and makes no
request, so a declaration defect is an import-time error everywhere.

The catalog produces exactly one EQL type today, `TextEq`. The others are
present and unproducible, so a declaration that reaches for one gets the
catalog's reason rather than "unknown".
"""

from dataclasses import dataclass
from typing import Annotated

import pytest

from stackencrypt import (
    EQL,
    Bool,
    Equality,
    Int64,
    Match,
    Ore,
    Passthrough,
    Plan,
    Text,
)
from stackencrypt.errors import PlanError


@dataclass
class User:
    email: Annotated[str, Text, EQL(Equality)]
    age: Annotated[int, Int64, Passthrough()]


def test_a_good_plan_resolves_its_target_to_an_eql_type_and_domain():
    spec = Plan.of(User).context("users").build()

    resolved = spec.domains["email"]
    assert resolved["name"] == "TextEq"
    assert resolved["sql_domain"] == "public.eql_v3_text_eq"
    assert resolved["query_sql_domain"] == "eql_v3.query_text_eq"


def test_the_resolved_name_replaces_the_pair_in_the_wire_plan():
    spec = Plan.of(User).context("users").build()

    # What crosses to the engine is the name. The pair was a request.
    assert spec.fields["email"]["target"] == "TextEq"


def test_a_passthrough_field_has_no_domain():
    spec = Plan.of(User).context("users").build()

    assert "age" not in spec.domains


def test_an_explicit_eql_name_resolves():
    @dataclass
    class Named:
        email: Annotated[str, Text, EQL(name="TextEq")]

    spec = Plan.of(Named).context("users").build()

    assert spec.fields["email"]["target"] == "TextEq"
    assert spec.domains["email"]["sql_domain"] == "public.eql_v3_text_eq"


def test_an_unknown_eql_type_name_is_refused():
    @dataclass
    class Wrong:
        email: Annotated[str, Text, EQL(name="NoSuchType")]

    with pytest.raises(PlanError, match="NoSuchType"):
        Plan.of(Wrong).context("users").build()


def test_an_eql_type_the_engine_does_not_produce_says_so():
    @dataclass
    class Wrong:
        note: Annotated[str, Text, EQL(name="TextOrdOre")]

    with pytest.raises(PlanError, match="TextOrdOre"):
        Plan.of(Wrong).context("users").build()


# A match index is text-only. The engine's `admits` check is what refuses it
# on an integer, and it must fire at plan time, not at the first write.
def test_an_index_the_declared_type_does_not_admit_is_refused():
    @dataclass
    class Wrong:
        age: Annotated[int, Int64, Match]

    with pytest.raises(PlanError):
        Plan.of(Wrong).context("users").build()


def test_a_kind_and_index_pair_no_eql_type_serves_is_refused():
    @dataclass
    class Wrong:
        flag: Annotated[bool, Bool, EQL(Match)]

    with pytest.raises(PlanError, match="bool"):
        Plan.of(Wrong).context("users").build()


def test_an_ore_target_is_refused_because_the_engine_produces_none_yet():
    # Not a declaration defect — `ore` on text is a legal index and
    # `TextOrdOre` is in the catalog. The engine does not produce it yet, so
    # the refusal names what it does produce. Backlog item 5.
    @dataclass
    class Wrong:
        note: Annotated[str, Text, EQL(Ore)]

    with pytest.raises(PlanError, match="TextEq"):
        Plan.of(Wrong).context("users").build()


def test_a_bare_index_plan_needs_no_resolver_and_has_no_domains():
    # `outputs` rather than `target`: the engine returns ciphertext and
    # terms, and nothing frames them as EQL. Legal, and not what the
    # tracer's Postgres path uses.
    @dataclass
    class Bare:
        note: Annotated[str, Text, Equality]

    spec = Plan.of(Bare).context("notes").build()

    assert spec.fields["note"]["outputs"] == ["c", "eq"]
    assert spec.domains == {}
