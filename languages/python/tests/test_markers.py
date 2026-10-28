"""The markers: the generated EQL-type markers and the two hand-written ones.

The catalog itself is checked in Rust, where it lives: eql-codegen's
`py_eql_parity.rs` compares every marker with the Go `Types` table. These
tests check what a Python developer sees.
"""

import pytest

import stackencrypt
from stackencrypt import _eql
from stackencrypt._markers import Marker

ATTRIBUTES = (
    "name",
    "family",
    "suffix",
    "plaintext",
    "sql_domain",
    "indexes",
    "query",
    "query_sql_domain",
    "producible",
    "reason",
)

UNPRODUCIBLE = [marker.name for marker in _eql.TYPES if not marker.producible]


def test_the_common_markers_import_from_the_package():
    from stackencrypt import Ignore, Passthrough, Text, TextEq

    assert issubclass(TextEq, Marker)
    assert issubclass(Text, Marker)
    assert issubclass(Passthrough, Marker)
    assert issubclass(Ignore, Marker)


def test_text_eq_carries_the_catalog_row():
    from stackencrypt import TextEq

    assert {name: getattr(TextEq, name) for name in ATTRIBUTES} == {
        "name": "TextEq",
        "family": "text",
        "suffix": "Eq",
        "plaintext": "string",
        "sql_domain": "public.eql_v4_text_eq",
        "indexes": ("eq",),
        "query": "TextEqQuery",
        "query_sql_domain": "eql_v4.query_text_eq",
        "producible": True,
        "reason": None,
    }


def test_a_marker_without_a_query_has_no_query_domain():
    from stackencrypt import Text

    assert Text.query is None
    assert Text.query_sql_domain is None


@pytest.mark.parametrize("marker", _eql.TYPES, ids=lambda m: m.name)
def test_every_marker_carries_exactly_the_ten_attributes(marker):
    generated = [name for name in vars(marker) if not name.startswith("__")]
    assert tuple(generated) == ATTRIBUTES
    assert marker.__name__ == marker.name
    assert marker.producible is (marker.reason is None)


def test_types_lists_every_marker_class_in_the_module_once():
    classes = [
        value
        for value in vars(_eql).values()
        if isinstance(value, type) and issubclass(value, Marker) and value is not Marker
    ]
    assert len(_eql.TYPES) == len(set(_eql.TYPES))
    assert set(_eql.TYPES) == set(classes)


def test_the_package_exports_exactly_the_producible_markers():
    exported = set(_eql.__all__)
    assert exported == {marker.name for marker in _eql.TYPES if marker.producible}
    assert exported <= set(stackencrypt.__all__)
    for name in exported:
        assert getattr(stackencrypt, name) is getattr(_eql, name)


@pytest.mark.skipif(not UNPRODUCIBLE, reason="every catalog type is producible")
@pytest.mark.parametrize("name", UNPRODUCIBLE)
def test_an_unproducible_marker_does_not_import_from_the_package(name):
    with pytest.raises(ImportError):
        exec(f"from stackencrypt import {name}", {})
