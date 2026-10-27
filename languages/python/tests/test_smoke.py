"""The walking skeleton: the pure-Python package and the extension load together.

One test per fact the first ticket promises. Nothing here encrypts.
"""

import importlib.metadata
import re

import stackencrypt


def test_version_is_the_installed_distribution_version():
    assert stackencrypt.__version__ == importlib.metadata.version("stackencrypt")


def test_version_starts_the_independent_semver_line():
    assert stackencrypt.__version__ == "0.1.0"


def test_engine_names_the_commit_the_extension_was_built_from():
    # `-dirty` when a packages/stack-* crate had local edits at build time.
    assert re.fullmatch(r"[0-9a-f]{40}(-dirty)?", stackencrypt.__engine__)


def test_the_engine_function_answers_from_the_extension():
    # The one trivial engine call: both halves are loaded if it answers, and
    # the answer is the same pair the package exposes as its two dunders.
    assert stackencrypt._engine.build_info() == (
        stackencrypt.__version__,
        stackencrypt.__engine__,
    )
