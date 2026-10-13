"""Parity between the engine invoked through the Python shell and the engine
invoked from Rust — produced at test time, under one set of credentials.

Python never encrypts. Both sides run one engine; what differs is everything
in front of it. This is the test that catches the SHELL drifting from the
engine's grammar — a value tagged the wrong width, a plan missing its
`"type"`, a record tree rebuilt wrongly — while every other test stays green.

Ciphertexts are never byte-equal (a fresh IV per seal), so the bit-for-bit
comparison is the deterministic equality TERM; the ciphertext is checked by
cross-opening instead. Nothing here is committed from a keyset: the Rust
side is sealed in this run, so the comparison holds in any workspace.
"""

from __future__ import annotations

import base64
import json
import os
import pathlib
import subprocess
import sysconfig
from dataclasses import dataclass
from typing import Annotated

import pytest

from stackencrypt import EQL, Cipher, Equality, Int64, Passthrough, Plan, Text

CRATE = pathlib.Path(__file__).parents[1]
PLAINTEXT = {"email": "parity@example.com", "age": 41}


@dataclass
class User:
    email: Annotated[str, Text, EQL(Equality)]
    age: Annotated[int, Int64, Passthrough()]


def _loader_env() -> dict[str, str]:
    """The environment with this interpreter's libpython on the loader path.

    The bin links pyo3 (through the shared resolver), and a non-wheel build
    links libpython by rpath. A `python -m venv` interpreter's library dir
    is not on the default search path, so without this the bin dies at load
    with `Library not loaded: @rpath/libpython3.X.dylib`. Both the macOS and
    the Linux variable are set; each loader reads its own.
    """
    env = dict(os.environ)
    libdir = sysconfig.get_config_var("LIBDIR") or ""
    for name in ("DYLD_FALLBACK_LIBRARY_PATH", "LD_LIBRARY_PATH"):
        env[name] = os.pathsep.join(p for p in (libdir, env.get(name, "")) if p)
    return env


def parity(*args: str, stdin: str | None = None) -> dict:
    """Run the Rust side. `cargo run` compiles once and caches after."""
    result = subprocess.run(
        ["cargo", "run", "--quiet", "--bin", "parity", "--", *args],
        cwd=CRATE,
        env=_loader_env(),
        input=stdin,
        capture_output=True,
        text=True,
        check=True,
    )
    return json.loads(result.stdout)


@pytest.fixture(scope="module")
def plan():
    return Plan.of(User).context("users").build()


@pytest.fixture(scope="module")
def cipher(live, plan):
    return Cipher(plan, engine=live)


@pytest.fixture(scope="module")
def sealed_by_rust(live):
    # `live` so this skips, rather than fails, where no credentials resolve.
    return parity("seal")


def test_both_sides_build_the_same_plan(plan, sealed_by_rust):
    # Otherwise two different declarations legitimately give different
    # bytes, and the comparisons below mean nothing.
    assert sealed_by_rust["plan"] == plan.fields


def test_the_shell_opens_a_record_rust_sealed(cipher, sealed_by_rust):
    record = {
        "email": base64.b64decode(sealed_by_rust["record"]["email"]),
        "age": sealed_by_rust["record"]["age"],
    }

    [user] = cipher.decrypt([record])

    assert user.email == PLAINTEXT["email"]
    assert user.age == PLAINTEXT["age"]


def test_rust_opens_a_record_the_shell_sealed(cipher, live):
    [record] = cipher.encrypt([User(**PLAINTEXT)])
    wire = {
        "email": base64.b64encode(record["email"]).decode(),
        "age": record["age"],
    }

    assert parity("open", stdin=json.dumps(wire)) == PLAINTEXT


def test_the_equality_term_is_byte_identical(cipher, sealed_by_rust):
    term = cipher.query("email", PLAINTEXT["email"])

    assert term == base64.b64decode(sealed_by_rust["term"])
