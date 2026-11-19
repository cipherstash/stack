# Turns Markdown into the pieces a reader reads as prose: paragraphs, list items,
# headings and table cells. Each piece records the source line of every part of its
# text, so a finding can name the line it came from.
#
# Code is left out, because code is exact and is not prose. Inline code becomes the
# one word CODE, and a URL becomes the one word URL, so a sentence that names
# `docs/a/long/path.md` counts it as one word.
#
# Each piece has two copies of its text. `text` is what the reader reads. `masked` is
# the same length, with everything inside double quotation marks blanked out, because
# a quoted phrase is somebody else's words: a sentence that says "write 'to', not 'in
# order to'" must not be reported for the phrase it is quoting.
#
# Python's re module has no \p{L} or \p{N}. [^\W_] matches a letter or a number, and
# [^\W\d_] matches a letter. Python's \w and \b also count letters such as "é" as part
# of a word, where JavaScript's do not, so "café" is one word here.
import re
import unicodedata
from collections import namedtuple
from functools import lru_cache

FENCE = re.compile(r"^\s*(```|~~~)")
HEADING = re.compile(r"^\s{0,3}(#{1,6})\s+")
TABLE_ROW = re.compile(r"^\s*\|")
TABLE_DIVIDER = re.compile(r"^[\s|:-]+$")
LIST_ITEM = re.compile(r"^(\s*)(?:[-*+]|\d+[.)])\s+(?:\[[ xX]\]\s+)?")
BLOCKQUOTE = re.compile(r"^\s*>\s?")
THEMATIC_BREAK = re.compile(r"^\s{0,3}(?:[-*_]\s*){3,}$")
# A metadata line, such as "purpose: Find your record". Markdown would join a run of
# them into one paragraph, but each is a separate statement, not part of a sentence.
FIELD_LINE = re.compile(r"^\s*[a-z][a-z0-9_-]*:\s")
CLOSING_HEADING_MARKS = re.compile(r"\s#+\s*$")
TABLE_EDGES = re.compile(r"^\s*\||\|\s*$")
ALLOW = "plain-language-allow"

PLACEHOLDERS = {"CODE", "URL"}

# JavaScript's "." does not match these line breaks, and Python's matches all but "\n".
ANY_BUT_LINE_BREAK = "[^\n\r  ]"

INLINE = [
    (re.compile("<!--" + ANY_BUT_LINE_BREAK + "*?-->"), " "),
    (re.compile(r"(`+)[\s\S]*?\1"), "CODE"),
    (re.compile(r"!\[([^\]]*)\]\([^)]*\)"), r"\1"),
    (re.compile(r"\[([^\]]+)\]\([^)]*\)"), r"\1"),
    (re.compile(r"\[([^\]]+)\]\[[^\]]*\]"), r"\1"),
    (re.compile(r"\[\^[^\]]+\]"), ""),
    (re.compile(r"<https?://[^>]+>"), "URL"),
    (re.compile(r"""https?://[^\s)\]>]+[^\s)\]>.,;:!?'"]"""), "URL"),
    (re.compile(r"</?[a-zA-Z][^>]*>"), " "),
    (re.compile(r"\\([\\`*_{}\[\]()#+\-.!|>])"), r"\1"),
    (re.compile(r"\*\*|__|~~|\*"), ""),
    (re.compile(r"(^|[^\w])_+|_+(?=[^\w]|$)"), r"\1"),
]
CALLOUT = re.compile(r"^\s*\[!(?:NOTE|TIP|IMPORTANT|WARNING|CAUTION)\]\s*", re.IGNORECASE)


def inline_text(line):
    """Rewrites one line of Markdown into the words a reader sees."""
    for pattern, replacement in INLINE:
        line = pattern.sub(replacement, line)
    return CALLOUT.sub("", line, count=1)


def _blank(match):
    text = match.group(0)
    return text[0] + " " * (len(text) - 2) + text[-1]


QUOTES = [
    re.compile(r'"[^"\n]{1,300}"'),
    re.compile(r"“[^”\n]{1,300}”"),
    re.compile(r"‘[^’\n]{1,300}’(?!\w)"),
    # Python's lookbehind cannot have alternatives of different widths, so "^" sits
    # outside it.
    re.compile(r"(?:^|(?<=[\s(\[]))'[^'\n]{1,100}'(?=[\s.,;:!?)\]]|$)"),
]


def mask_quotes(text):
    """Blanks out text between double quotation marks, keeping the length the same."""
    for pattern in QUOTES:
        text = pattern.sub(_blank, text)
    return text


class Piece:
    def __init__(self, kind, line):
        self.kind = kind
        self.line = line
        self.text = ""
        self.masked = ""
        self.indent = 0
        # For a heading, the number of # marks: 1 for a title, 2 for a section, and so on.
        self.level = 0
        # Each segment is (start, line): the offset in `text` where a source line begins.
        self.segments = []

    def add(self, raw, line):
        words = inline_text(raw).strip()
        if not words:
            return
        if self.text:
            self.text += " "
        self.segments.append((len(self.text), line))
        self.text += words

    def line_at(self, offset):
        line = self.line
        for start, segment_line in self.segments:
            if start > offset:
                break
            line = segment_line
        return line


def prose_units(markdown):
    """Reads Markdown and returns its prose pieces, in order."""
    lines = re.sub(r"\r\n?", "\n", markdown).split("\n")
    pieces = []
    current = None
    in_fence = False
    in_comment = False

    def finish():
        nonlocal current
        if current is not None and current.text:
            current.masked = mask_quotes(current.text)
            pieces.append(current)
        current = None

    start = 0
    if lines[0].strip() == "---":
        try:
            start = lines.index("---", 1) + 1
        except ValueError:
            pass

    for i in range(start, len(lines)):
        number = i + 1
        line = lines[i]

        if in_fence:
            if FENCE.search(line):
                in_fence = False
            continue
        if FENCE.search(line):
            finish()
            in_fence = True
            continue
        if in_comment:
            if "-->" in line:
                in_comment = False
            continue
        opening = line.find("<!--")
        if opening != -1 and line.find("-->", opening) == -1:
            if ALLOW in line:
                continue
            line = line[:opening]
            in_comment = True
        if ALLOW in line:
            continue

        while BLOCKQUOTE.search(line):
            line = BLOCKQUOTE.sub("", line, count=1)

        if not line.strip() or THEMATIC_BREAK.search(line):
            finish()
            continue

        heading = HEADING.search(line)
        if heading:
            finish()
            current = Piece("heading", number)
            current.level = len(heading.group(1))
            current.add(CLOSING_HEADING_MARKS.sub("", HEADING.sub("", line, count=1), count=1), number)
            finish()
            continue

        if TABLE_ROW.search(line):
            finish()
            if TABLE_DIVIDER.search(line):
                continue
            cells = TABLE_EDGES.sub("", inline_text(line)).split("|")
            for cell in cells:
                if not cell.strip():
                    continue
                piece = Piece("cell", number)
                piece.segments.append((0, number))
                piece.text = cell.strip()
                piece.masked = mask_quotes(piece.text)
                pieces.append(piece)
            continue

        item = LIST_ITEM.search(line)
        if item:
            finish()
            current = Piece("item", number)
            current.indent = len(item.group(1))
            current.add(line[item.end():], number)
            continue

        if current is not None and not FIELD_LINE.search(line) and current.kind in ("item", "paragraph"):
            current.add(line, number)
            continue

        finish()
        current = Piece("paragraph", number)
        current.add(line, number)
    finish()
    return pieces


# Abbreviations whose full stop does not end a sentence.
ABBREVIATIONS = re.compile(
    r"\b(?:e\.g|i\.e|etc|vs|cf|viz|approx|Mr|Mrs|Ms|Dr|St|No|Fig|Inc|Ltd|Pty|Jr|Sr|a\.m|p\.m|U\.S)\.",
    re.IGNORECASE,
)
HELD_STOP = "․"
SPACE = re.compile(r"\s+")
# A sentence ends at white space that comes after a full stop, question mark or
# exclamation mark, and before a capital letter or a number. Closing quotation marks,
# brackets and emphasis can come between the stop and the space, and opening ones
# between the space and the capital letter. JavaScript does this with a lookbehind of
# any width, which Python's re module does not allow, so these are checked by hand.
STOPS = ".!?"
CLOSERS = "\"'”’)]*_"
OPENERS = "\"'“‘([*_`"

Sentence = namedtuple("Sentence", "offset text")


def _starts_sentence(char):
    """True for an upper-case letter or a number, which JavaScript calls \\p{Lu} and \\p{N}."""
    category = unicodedata.category(char)
    return category == "Lu" or category[0] == "N"


@lru_cache(maxsize=4096)
def sentences(text):
    """Splits one piece of prose into sentences, each with its offset in the piece."""
    protected = ABBREVIATIONS.sub(lambda match: match.group(0).replace(".", HELD_STOP), text)
    found = []
    start = 0
    for space in SPACE.finditer(protected):
        before = space.start() - 1
        while before >= 0 and protected[before] in CLOSERS:
            before -= 1
        if before < 0 or protected[before] not in STOPS:
            continue
        after = space.end()
        while after < len(protected) and protected[after] in OPENERS:
            after += 1
        if after == len(protected) or not _starts_sentence(protected[after]):
            continue
        found.append(Sentence(start, text[start : space.start()]))
        start = space.end()
    if start < len(text):
        found.append(Sentence(start, text[start:]))
    return tuple(sentence for sentence in found if count_words(sentence.text) > 0)


LETTER_OR_NUMBER = re.compile(r"[^\W_]")


def count_words(text):
    return sum(1 for token in SPACE.split(text) if LETTER_OR_NUMBER.search(token))
