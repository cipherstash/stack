"""The README's code, checked with no credentials. `test_readme_live.py`
runs it against ZeroKMS and PostgreSQL."""

import pathlib

from _readme import all_blocks, blocks, bound_names, check_names, fence_lines, program

MISE = pathlib.Path(__file__).resolve().parents[1] / "mise.toml"
BUNDLE = "packages/eql/release/cipherstash-encrypt-v4.sql"


def test_every_fence_is_read():
    # Each block has an opening and a closing fence line. A fence the parser
    # does not match would drop its block from the live run without notice.
    assert fence_lines() == 2 * len(all_blocks())


def test_the_python_blocks_compile_as_one_program():
    compile(program(), "README.md", "exec")


def test_the_python_blocks_bind_the_names_the_live_check_reads():
    # At the top level: the check runs at the top level too, so a name bound
    # only inside a function is not one it can read.
    assert check_names() == {"dataclasses", "users"}
    assert check_names() <= bound_names(program())


def test_the_readme_has_sql_for_the_live_test_to_run():
    assert blocks("sql")


def test_the_readme_installs_the_bundle_the_live_tests_install():
    # The live task cannot run the README's psql command from the root, so it
    # runs its own. Both must name the same bundle.
    [install] = [block for block in blocks("sh") if "psql" in block]
    assert BUNDLE in install
    assert f"../../{BUNDLE}" in MISE.read_text(encoding="utf-8")
