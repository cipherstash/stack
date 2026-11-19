# Reads a project's settings file, .plain-language.json, which lists the names the
# project uses: "aXcelerate", "Ladder Climb and Lift". The checker reads each name as
# one word (see read_names in check.py).
#
# A project can list names and nothing else. It cannot turn a rule off or change a
# limit, because a switch like that hides real problems as well as false ones.
#
# A broken settings file is an error, never an empty list. Ignoring it would bring
# back every false finding the names were there to stop, with nothing to say why.
import json
import os
import re

FILE_NAME = ".plain-language.json"
KEYS = {"names"}
LETTER_OR_NUMBER = re.compile(r"[^\W_]")


class SettingsError(Exception):
    def __init__(self, path, reason):
        super().__init__(f"{path}: {reason}")
        self.path = path
        self.reason = reason


def find(start):
    """The settings file for a path: the first one in its folder or a folder above it.

    The search stops at the top of the git repository, the folder that contains .git.
    That is a folder in a normal clone, and a file in a worktree. A settings file
    outside the repository belongs to some other project.
    """
    folder = os.path.abspath(start if os.path.isdir(start) else os.path.dirname(start) or ".")
    while True:
        candidate = os.path.join(folder, FILE_NAME)
        if os.path.lexists(candidate):
            return candidate
        if os.path.lexists(os.path.join(folder, ".git")):
            return None
        parent = os.path.dirname(folder)
        if parent == folder:
            return None
        folder = parent


def _reject(constant):
    raise ValueError(f"{constant} is not valid JSON")


def load(path):
    """The names in one settings file, as a tuple."""
    try:
        with open(path, encoding="utf-8") as handle:
            raw = json.loads(handle.read(), parse_constant=_reject)
    except (OSError, UnicodeDecodeError, ValueError) as error:
        raise SettingsError(path, f"it cannot be read as JSON ({error})") from error
    if not isinstance(raw, dict):
        raise SettingsError(path, 'it must be a JSON object, such as {"names": ["aXcelerate"]}')
    unknown = sorted(set(raw) - KEYS)
    if unknown:
        raise SettingsError(path, f'"{unknown[0]}" is not a setting. The only setting is "names"')
    names = raw.get("names", [])
    if not isinstance(names, list):
        raise SettingsError(path, '"names" must be a list of strings')
    for name in names:
        if not isinstance(name, str) or not LETTER_OR_NUMBER.search(name):
            raise SettingsError(path, f'each name must be a string with a letter or a number in it, not {json.dumps(name)}')
        if name != name.strip():
            raise SettingsError(path, f"the name {json.dumps(name)} starts or ends with a space")
    return tuple(names)


def names_for(start):
    """The names for a file or a folder. With no settings file, there are none."""
    path = find(start)
    return load(path) if path else ()
