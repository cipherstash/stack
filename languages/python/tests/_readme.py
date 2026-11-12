"""The README's fenced code blocks, for `test_readme.py` and
`test_readme_live.py`. Not a test file: pytest collects nothing here."""

import ast
import builtins
import pathlib
import re
import textwrap
from typing import List, Set

README = pathlib.Path(__file__).resolve().parents[1] / "README.md"

# A fence may be indented, as in a list item, and may have words after its
# language, such as a title. The closing fence has the same indent.
_FENCE = re.compile(r"^( *)```(\w*)[^\n]*\n(.*?)^\1```[ \t]*$", re.MULTILINE | re.DOTALL)

# Every line that could open or close a fence, for the check that none is
# missed: a backtick or tilde fence, indented or inside a blockquote. The
# parser reads only the first kind, so any other fails that check.
_FENCE_LINE = re.compile(r"^[ \t>]*(```|~~~)", re.MULTILINE)

# Run after the README's Python blocks: print what the equality query found.
CHECK = """
import json as _json
print(_json.dumps([dataclasses.asdict(user) for user in users]))
"""


def text() -> str:
    return README.read_text(encoding="utf-8")


def fence_lines() -> int:
    return len(_FENCE_LINE.findall(text()))


def all_blocks() -> List[str]:
    return [lang for _, lang, _ in _FENCE.findall(text())]


def blocks(language: str) -> List[str]:
    """Every block of ``language`` in the README, in order, with the indent
    of a list item removed."""
    return [
        textwrap.dedent(body) for _, lang, body in _FENCE.findall(text()) if lang == language
    ]


def program() -> str:
    """The README's Python blocks as one program, in order. A reader runs
    them in one session, so each block may use the names of those before."""
    return "\n\n".join(blocks("python"))


class _TopLevel(ast.NodeVisitor):
    """The names a program binds at its top level. A function, class,
    lambda, or comprehension has a scope of its own, so its names are
    skipped."""

    def __init__(self) -> None:
        self.bound: Set[str] = set()

    def visit_Name(self, node: ast.Name) -> None:
        if isinstance(node.ctx, ast.Store):
            self.bound.add(node.id)

    def visit_alias(self, node: ast.alias) -> None:
        self.bound.add((node.asname or node.name).split(".")[0])

    def _own_scope(self, node: ast.AST) -> None:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            self.bound.add(node.name)

    visit_FunctionDef = visit_AsyncFunctionDef = visit_ClassDef = _own_scope
    visit_Lambda = visit_ListComp = visit_SetComp = visit_DictComp = _own_scope
    visit_GeneratorExp = _own_scope


def _top_level(source: str) -> _TopLevel:
    names = _TopLevel()
    names.visit(ast.parse(source))
    return names


def bound_names(source: str) -> Set[str]:
    """The names ``source`` assigns or imports at its top level."""
    return _top_level(source).bound


def check_names() -> Set[str]:
    """The names CHECK reads from the README's program: those it reads,
    less those it binds itself and Python's built-in names."""
    tree = ast.parse(CHECK)
    read = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load)}
    bound = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store)}
    bound |= {(a.asname or a.name) for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
    return read - bound - set(dir(builtins))
