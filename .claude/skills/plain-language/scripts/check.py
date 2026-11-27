#!/usr/bin/env python3
# Checks prose against the plain-language rules in rules.json, and reports each
# problem with the line it is on, the ISO 24495 clause it breaks, and what to write
# instead.
#
# Usage:
#   python3 check.py [--json] [--block-only] [--chat] [file ...]
#
# With no file, it reads standard input. It exits 1 when there is a finding that
# must be fixed, and 0 otherwise, so it can sit in a script or a hook. It exits 2
# when a project's settings file is broken, and names the file.
#
# Each file is read with the names in the project's .plain-language.json (see
# settings.py). Standard input is read with the names for the current folder.
#
# It checks what a machine can check: word lists, sentence and paragraph length,
# asides that interrupt a sentence. It cannot decide whether the reader needs a
# sentence at all (ISO 24495-1 Principle 1), whether a word is familiar to this
# reader, or whether a metaphor that is not on the list is a metaphor. Those stay
# with the writer.
import json
import math
import os
import re
import sys
from decimal import ROUND_HALF_UP, Decimal
from functools import lru_cache

HERE = os.path.dirname(os.path.realpath(__file__))
# A hook runs this with "python3 -I", which leaves the script's own folder off the
# import path, so it is added here.
if HERE not in sys.path:
    sys.path.insert(0, HERE)

from prose import PLACEHOLDERS, count_words, prose_units, sentences  # noqa: E402
from settings import SettingsError, names_for  # noqa: E402

# The code points that JavaScript's \p{Extended_Pictographic} matches, which Python's
# re module cannot name. They were listed by Node.js 24.22, which uses Unicode 17.0.
EXTENDED_PICTOGRAPHIC_RANGES = (
    "A9 AE 203C 2049 2122 2139 2194-2199 21A9-21AA 231A-231B 2328 23CF 23E9-23F3",
    "23F8-23FA 24C2 25AA-25AB 25B6 25C0 25FB-25FE 2600-2604 260E 2611 2614-2615 2618",
    "261D 2620 2622-2623 2626 262A 262E-262F 2638-263A 2640 2642 2648-2653 265F-2660",
    "2663 2665-2666 2668 267B 267E-267F 2692-2697 2699 269B-269C 26A0-26A1 26A7",
    "26AA-26AB 26B0-26B1 26BD-26BE 26C4-26C5 26C8 26CE-26CF 26D1 26D3-26D4 26E9-26EA",
    "26F0-26F5 26F7-26FA 26FD 2702 2705 2708-270D 270F 2712 2714 2716 271D 2721 2728",
    "2733-2734 2744 2747 274C 274E 2753-2755 2757 2763-2764 2795-2797 27A1 27B0 27BF",
    "2934-2935 2B05-2B07 2B1B-2B1C 2B50 2B55 3030 303D 3297 3299 1F004 1F02C-1F02F",
    "1F094-1F09F 1F0AF-1F0B0 1F0C0 1F0CF-1F0D0 1F0F6-1F0FF 1F170-1F171 1F17E-1F17F",
    "1F18E 1F191-1F19A 1F1AE-1F1E5 1F201-1F20F 1F21A 1F22F 1F232-1F23A 1F23C-1F23F",
    "1F249-1F25F 1F266-1F321 1F324-1F393 1F396-1F397 1F399-1F39B 1F39E-1F3F0",
    "1F3F3-1F3F5 1F3F7-1F3FA 1F400-1F4FD 1F4FF-1F53D 1F549-1F54E 1F550-1F567",
    "1F56F-1F570 1F573-1F57A 1F587 1F58A-1F58D 1F590 1F595-1F596 1F5A4-1F5A5 1F5A8",
    "1F5B1-1F5B2 1F5BC 1F5C2-1F5C4 1F5D1-1F5D3 1F5DC-1F5DE 1F5E1 1F5E3 1F5E8 1F5EF",
    "1F5F3 1F5FA-1F64F 1F680-1F6C5 1F6CB-1F6D2 1F6D5-1F6E5 1F6E9 1F6EB-1F6F0",
    "1F6F3-1F6FF 1F7DA-1F7FF 1F80C-1F80F 1F848-1F84F 1F85A-1F85F 1F888-1F88F",
    "1F8AE-1F8AF 1F8BC-1F8BF 1F8C2-1F8CF 1F8D9-1F8FF 1F90C-1F93A 1F93C-1F945",
    "1F947-1F9FF 1FA58-1FA5F 1FA6E-1FAFF 1FC00-1FFFD",
)


def _character_class(ranges):
    parts = []
    for one in " ".join(ranges).split():
        first, _, last = one.partition("-")
        parts.append(re.escape(chr(int(first, 16))))
        if last:
            parts.append("-" + re.escape(chr(int(last, 16))))
    return "[" + "".join(parts) + "]"


EXTENDED_PICTOGRAPHIC = _character_class(EXTENDED_PICTOGRAPHIC_RANGES)


def compile_pattern(pattern, flags="i"):
    """Compiles a JavaScript pattern from rules.json as a Python one.

    Python reads the patterns in rules.json the same way JavaScript does, except for
    \\p{Extended_Pictographic}, which is replaced with the code points it stands for.
    Any other \\p{...} is an error, so a new rule that needs one fails here, not later.
    """
    pattern = pattern.replace(r"\p{Extended_Pictographic}", EXTENDED_PICTOGRAPHIC)
    return re.compile(pattern, re.IGNORECASE if "i" in flags else 0)


def load_rules(file=os.path.join(HERE, "rules.json")):
    with open(file, encoding="utf-8") as handle:
        raw = json.load(handle)

    def compile_rule(rule):
        flags = rule.get("flags")
        if flags is None:
            flags = "i"
        if "items" in rule:
            items = [{"re": compile_pattern(item["pattern"], flags), "instead": item.get("instead")} for item in rule["items"]]
        else:
            items = [{"re": compile_pattern(pattern, flags), "instead": None} for pattern in rule["patterns"]]
        return {**rule, "items": items}

    tv = raw["thingVerbs"]
    between = rf"(?:(?:{tv['between']})\s+){{0,3}}"
    things = "|".join(tv["things"])
    return {
        "limits": raw["limits"],
        "known": set(raw["knownAbbreviations"]),
        "shouted": set(raw["shoutedWords"]),
        "phrases": [compile_rule(rule) for rule in raw["phrases"]],
        "source": [compile_rule(rule) for rule in raw["sourcePatterns"]],
        "thingVerbs": {
            **tv,
            "subjects": [
                re.compile(rf"\b(?:{things})\s+{between}({tv['blockVerbs']})\b", re.IGNORECASE),
                re.compile(rf"\b(?:{'|'.join(tv['pronouns'])})\s+{between}({tv['pronounVerbs']})\b", re.IGNORECASE),
            ],
            "held": re.compile(rf"\b(?:{tv['heldVerbs']})\s+(?:{'|'.join(tv['heldThings'])})\b", re.IGNORECASE),
            "thingSubject": re.compile(
                rf"^\s*(?:(?:the|a|an|this|that|each|every|its|our|your|their|one|new)\s+)?(?:[\w-]+\s+){{0,2}}?(?:{things})\b",
                re.IGNORECASE,
            ),
            "anyVerb": re.compile(rf"\b(?:{tv['pronounVerbs']})\b", re.IGNORECASE),
            "person": re.compile(tv["person"], re.IGNORECASE),
        },
    }


PROSE_KINDS = {"paragraph", "item"}


@lru_cache(maxsize=16)
def names_pattern(names):
    if not names:
        return None
    # The longest name wins where two overlap, as "Lift" and "Lift and Shift" do.
    alternatives = "|".join(re.escape(name) for name in sorted(set(names), key=len, reverse=True))
    return re.compile(rf"(?<![^\W_])(?:{alternatives})(?![^\W_])")


def stand_in(match):
    # One word with a capital letter, so a name such as "aXcelerate" can start a
    # sentence. It has the name's length, so an offset into the piece is the same in
    # the reader's words. No rule matches it; a test checks lengths 1 to 60.
    return "N" + "n" * (len(match.group(0)) - 1)


def read_names(pieces, names):
    """Reads each of a project's names as one word.

    The checks read `text` and `masked`, in which each name is a stand-in word. What a
    finding shows the reader comes from `shown` and `shown_masked`, which keep the
    reader's own words.
    """
    pattern = names_pattern(tuple(names))
    for piece in pieces:
        piece.shown, piece.shown_masked = piece.text, piece.masked
        if pattern:
            piece.text = pattern.sub(stand_in, piece.text)
            piece.masked = pattern.sub(stand_in, piece.masked)


def shown(piece, start, end):
    return piece.shown_masked[start:end]


def excerpt_around(piece, index):
    found = sentences(piece.text)
    sentence = next((one for one in reversed(found) if one.offset <= index), found[0] if found else None)
    text = (piece.shown[sentence.offset : sentence.offset + len(sentence.text)] if sentence else piece.shown).strip()
    return f"{text[:157]}..." if len(text) > 160 else text


def last_line(piece):
    return piece.segments[-1][1] if piece.segments else piece.line


def finding(rule, piece, index, say):
    return {
        "id": rule["id"],
        "severity": rule["severity"],
        "clause": rule["clause"],
        "line": piece.line_at(index),
        "span": [piece.line, last_line(piece)],
        "excerpt": excerpt_around(piece, index),
        "say": say,
    }


def phrase_findings(piece, rules):
    found = []
    for rule in rules["phrases"]:
        if piece.kind in (rule.get("skipKinds") or []) or rule.get("scope") == "sentence":
            continue
        for item in rule["items"]:
            for match in item["re"].finditer(piece.masked):
                say = rule["say"].replace("{instead}", item["instead"] or "", 1)
                found.append({**finding(rule, piece, match.start(), say), "match": shown(piece, match.start(), match.end()).strip()})
    return found


# A thing given a person's verb: "the table holds a flag", "CODE gains one link". The
# subject decides, so "a member holds a capability" is literal and is not reported.
def thing_verb_findings(piece, sentence, masked, rules):
    tv = rules["thingVerbs"]
    rule = {"id": "thing-given-person-verb", "severity": "block", "clause": tv["clause"]}
    found = []

    def add(match):
        start, end = sentence.offset + match.start(), sentence.offset + match.end()
        found.append({**finding(rule, piece, start, tv["say"]), "match": shown(piece, start, end)})

    for pattern in tv["subjects"]:
        for match in pattern.finditer(masked):
            up_to_verb = masked[: match.end() - len(match.group(1))]
            if tv["person"].search(up_to_verb):
                continue
            add(match)
    for match in tv["held"].finditer(masked):
        add(match)
    # The subject is a thing and the verb comes later: "CODE is new and holds the glossary".
    if not found and tv["thingSubject"].search(masked):
        later = tv["anyVerb"].search(masked)
        if later and not tv["person"].search(masked[: later.end()]):
            add(later)
    return found


# Two clauses in one sentence: ", which" adding a second statement, or "and" joining two
# clauses that each have a verb, as in "Six decisions are made and eight are waiting".
HELPING_VERB = "(?:is|are|was|were|has|have|had|will|can|cannot|could|must|should|would|does|do|did)"
HELPING_VERB_WORD = re.compile(rf"\b{HELPING_VERB}\b")
JOINED_CLAUSE = re.compile(
    rf"\s(and|but)\s+(?!(?:what|which|who|whom|whose|where|when|why|how|whether|that|if)\b)(?:\S+\s+){{0,3}}?(?<!\bto\s){HELPING_VERB}\b"
)
WHICH = re.compile(r",\s+which\b")


def two_ideas_findings(piece, sentence, masked):
    rule = {"id": "two-ideas-in-one-sentence", "severity": "block", "clause": "1: 5.3.4 a)"}
    found = []
    which = WHICH.search(masked)
    if which:
        found.append(
            finding(rule, piece, sentence.offset + which.start(), '", which" adds a second idea to this sentence. Make it a sentence of its own.'),
        )
    for match in JOINED_CLAUSE.finditer(masked):
        if not HELPING_VERB_WORD.search(masked[: match.start()]):
            continue
        found.append(
            finding(rule, piece, sentence.offset + match.start(), f'"{match.group(1)}" joins two statements. Write two sentences: "Six decisions are made. Eight are waiting for you."'),
        )
        break
    return found


# House style: a comma after an opening "If" or "When" clause, and a serial comma
# before the "and" or "or" that ends a list of three or more.
OPENING_CLAUSE = re.compile(r"^\s*(?:If|When|Whenever|Unless|Once|Because|Although|Though|While|After|Before|Since|Until)\b")
# A letter or a number, then a run of letters, numbers, apostrophes and hyphens.
WORD_START = r"[^\W_]"
WORD_PART = r"(?:[^\W_]|['’-])"
LIST_END = re.compile(
    rf"({WORD_START}{WORD_PART}*(?:\s{WORD_PART}+){{0,3}}),\s({WORD_START}{WORD_PART}*(?:\s{WORD_PART}+){{0,3}})\s(and|or)\s{WORD_START}"
)
CLAUSE_WORDS = re.compile(r"\b(?:I|you|we|they|it|he|she|is|are|was|were|has|have|had|will|can|cannot|do|does|did|must|should|would|could)\b")
# A phrase after the comma, not a list item: "with your reason and the date", "such as Lift and Shift".
NOT_AN_ITEM = re.compile(
    r"^(?:and|or|nor|with|without|by|for|from|in|on|at|to|into|onto|of|as|then|so|but|which|who|whom|where|when|while|such|including|like|especially|plus|except|both|either|neither|each|every|not|only|also|even)\b|^[^\W\d_]+(?:ed|ing)\b",
    re.IGNORECASE,
)
# A past participle that is not regular: "inputs, run before the change", "the report, written last week".
IRREGULAR_PARTICIPLE = re.compile(
    r"^(?:run|made|done|given|taken|written|shown|seen|found|kept|left|sent|built|held|known|told|brought|bought|paid|led|lost|won|begun|chosen|drawn|driven|broken|spoken|thrown|hidden|grown)\b",
    re.IGNORECASE,
)
# A pair of words joined by "and" or "or", not the end of a list: "before and after", "in and out".
PAIRED_WORDS = {"before", "after", "in", "out", "up", "down", "on", "off", "over", "under", "back", "forth", "to", "from", "above", "below", "inside", "outside", "here", "there"}
# An opening phrase that ends at the first comma, not the first item of a list: "For the
# run without the skill, all hooks and skills were turned off." This misses a list that
# follows such a phrase directly, as in "In Python, Go and Rust", which is rarer.
OPENING_PHRASE = re.compile(r"^\s*(?:For|In|On|At|By|With|Without|From|To|During|Under|Over|Across|Through|Within|Like|Unlike|Despite|As|Per)\b")
LETTERS = re.compile(r"[^\W\d_]+")
SPACE = re.compile(r"\s+")


def comma_findings(piece, sentence, masked):
    found = []
    trimmed = masked.strip()
    if OPENING_CLAUSE.search(trimmed) and "," not in trimmed and not trimmed.endswith("?") and count_words(trimmed) > 4:
        found.append(
            finding(
                {"id": "comma-after-opening-clause", "severity": "block", "clause": "house style; 1: 5.3.3 d)"},
                piece,
                sentence.offset,
                'Put a comma after the opening clause: "If you need it, tell me where to keep it."',
            ),
        )
    for match in LIST_END.finditer(masked):
        first_comma = masked.find(",")
        comma_at = match.start() + len(match.group(1))
        if (OPENING_CLAUSE.search(trimmed) or OPENING_PHRASE.search(trimmed)) and comma_at == first_comma:
            continue
        second = match.group(2)
        if CLAUSE_WORDS.search(second) or NOT_AN_ITEM.search(second) or IRREGULAR_PARTICIPLE.search(second) or count_words(second) > 3:
            continue
        before = SPACE.split(second)[-1].lower()
        after = LETTERS.match(masked, match.end() - 1)
        after = after.group(0).lower() if after else ""
        if before in PAIRED_WORDS and after in PAIRED_WORDS:
            continue
        found.append(
            finding(
                {"id": "serial-comma", "severity": "block", "clause": "house style; 1: 5.3.3 d)"},
                piece,
                sentence.offset + match.start(),
                f'Put a comma before "{match.group(3)}" at the end of a list: "words, headings, and links".',
            ),
        )
        break
    return found


def sentence_phrase_findings(piece, sentence, masked, rules):
    found = []
    start = sentence.offset + len(masked) - len(masked.lstrip())
    for rule in rules["phrases"]:
        if rule.get("scope") != "sentence":
            continue
        for item in rule["items"]:
            match = item["re"].search(masked.strip())
            if match:
                words = shown(piece, start + match.start(), start + match.end())
                found.append({**finding(rule, piece, sentence.offset, rule["say"]), "match": words[:60]})
    return found


ASIDE_RULE = {
    "id": "aside-interrupts-sentence",
    "severity": "block",
    "clause": "1: 5.3.3 a) 3)",
}
ASIDES = [
    re.compile(r"\S\s+[—–]\s*((?:[^\s—–()]+\s+){4,}[^\s—–()]+)\s*[—–]\s+\S"),
    re.compile(r"\S\s+\(((?:[^\s—–()]+\s+){4,}[^\s—–()]+)\)\s+\S"),
]

# A sentence that opens with an -ing word and has no subject or helping verb, such as
# "Checking the filter now." A sentence like "Running setup rebuilds the package" is
# whole, and this cannot always tell the two apart, so it only advises.
ING_START = re.compile(r"^[A-Z][a-z]+ing\b")
AUXILIARY = re.compile(r"\b(?:is|are|was|were|be|been|has|have|had|does|do|did|can|could|will|would|should|must|may|might|I|we|you|it|they|he|she)\b", re.IGNORECASE)
ING_NOUNS = re.compile(r"^(?:Nothing|Anything|Something|Everything|Training|Testing|Pricing|Billing|Logging|Hosting|Morning|Evening|Spring|String|Thing)\b")
# Verbs that often follow an -ing subject: "Getting under $1,000 means a 74% cut."
COMMON_VERBS = re.compile(
    r"\b(?:means|removes|triples|doubles|halves|costs|takes|accepts|makes|needs|saves|shows|helps|stops|breaks|leaves|gives|adds|keeps|changes|marks|deletes|fails|rebuilds|stays|works|uses|causes|cuts|reduces|increases|affects|depends|requires|lets|puts|turns|moves|returns|sends|tells|matters|wins|beats|avoids|prevents|fixes|catches|misses|skips|runs)\b"
)
SEMICOLON_CLAUSE = re.compile(r";\s+[a-z]")


# A sentence that starts with a pronoun, not the name of its subject: "They skip any new
# file". "This" and "These" count only before a verb, because "This file" names the
# subject. After "This", a verb is a helping verb or a word that ends in "s". The word must
# not end in "ss", "us" or "is", so the checker does not report "This process".
ADVERB = r"(?:(?:also|only|still|just|then|now|alone|already|usually|often|always|never)\s+)?"
PRONOUN_START = re.compile(
    r"^[\"'“‘(\[]*(?:(It|They|Their|Its)\b"
    rf"|(This)\s+{ADVERB}(?:is|was|has|had|does|did|can|cannot|could|will|would|should|must|may|might|(?![a-z]*(?:ss|us|is)\b)[a-z]+s)\b"
    rf"|(These)\s+{ADVERB}(?:are|were|have|had|do|did|can|cannot|could|will|would|should|must|may|might|include|mean|depend|seem|come|make|give|take|show|need|run|cost)\b)"
)
# A purpose at the end of a sentence: "calls the callback with the observer, to match the
# real callback signature". The word after "to" must not start a noun phrase, as in
# "to the team".
PURPOSE_LAST = re.compile(
    r",\s+to\s+(?!(?:the|a|an|this|that|these|those|my|your|his|her|its|our|their|them|him|me|us|you|it|each|every|all|some|any|no|one|both|either|neither|which|what|whom)\b)[a-z]+\b[^,;:]*$"
)


def pronoun_start_findings(piece, sentence, masked):
    match = PRONOUN_START.search(masked.strip())
    if not match:
        return []
    word = next(group for group in match.groups() if group)
    return [
        finding(
            {"id": "pronoun-start", "severity": "advise", "clause": "1: 5.3.2 a); 5.3.3 a)"},
            piece,
            sentence.offset,
            f'This sentence starts with "{word}". Start it with the name of its subject: "The guards skip any new file", not "They skip any new file". A pronoun later in the sentence is fine.',
        ),
    ]


def purpose_last_findings(piece, sentence, masked):
    match = PURPOSE_LAST.search(masked.strip())
    if not match:
        return []
    return [
        finding(
            {"id": "purpose-last", "severity": "advise", "clause": "1: 5.2.2 a)"},
            piece,
            sentence.offset,
            'The purpose comes last, after ", to". Put the outcome first, then the method: "match the real callback signature, by calling the callback with the observer".',
        ),
    ]


def is_fragment(text):
    trimmed = text.strip()
    if not ING_START.search(trimmed) or ING_NOUNS.search(trimmed):
        return False
    return not AUXILIARY.search(trimmed) and not COMMON_VERBS.search(trimmed)


def sentence_findings(piece, rules):
    found = []
    sentence_words = rules["limits"]["sentenceWords"]
    for sentence in sentences(piece.text):
        words = count_words(sentence.text)
        if words > sentence_words:
            found.append(
                finding(
                    {"id": "long-sentence", "severity": "block", "clause": "1: 5.3.4 a), c)"},
                    piece,
                    sentence.offset,
                    f"This sentence has {words} words; the limit is {sentence_words}. Cut words first. Split it only if it still has more than one idea.",
                ),
            )
        masked = piece.masked[sentence.offset : sentence.offset + len(sentence.text)]
        found.extend(thing_verb_findings(piece, sentence, masked, rules))
        found.extend(two_ideas_findings(piece, sentence, masked))
        found.extend(comma_findings(piece, sentence, masked))
        found.extend(sentence_phrase_findings(piece, sentence, masked, rules))
        found.extend(pronoun_start_findings(piece, sentence, masked))
        found.extend(purpose_last_findings(piece, sentence, masked))
        for pattern in ASIDES:
            match = pattern.search(masked)
            if not match:
                continue
            found.append(
                finding(
                    ASIDE_RULE,
                    piece,
                    sentence.offset + match.start(),
                    "This aside cuts the sentence in half. Make it a sentence of its own, after this one, or delete it.",
                ),
            )
        if is_fragment(sentence.text):
            found.append(
                finding(
                    {"id": "no-subject", "severity": "advise", "clause": "1: 5.3.3 a), c)"},
                    piece,
                    sentence.offset,
                    'This looks like a fragment with no subject. Say who is doing it: "I am checking the filter", not "Checking the filter".',
                ),
            )
        if SEMICOLON_CLAUSE.search(masked):
            found.append(
                finding(
                    {"id": "semicolon-joins-ideas", "severity": "advise", "clause": "1: 5.3.4 a)"},
                    piece,
                    sentence.offset,
                    "A semicolon joins two ideas into one sentence. Make two sentences, or a list.",
                ),
            )
    return found


def paragraph_findings(piece, rules):
    paragraph_sentences = rules["limits"]["paragraphSentences"]
    count = len(sentences(piece.text))
    if piece.kind != "paragraph" or count <= paragraph_sentences:
        return []
    return [
        finding(
            {"id": "long-paragraph", "severity": "block", "clause": "1: 5.3.5 a)"},
            piece,
            0,
            f"This paragraph has {count} sentences; the limit is {paragraph_sentences}. A paragraph is one topic. Split it where the topic changes, or turn a run of parallel points into a list.",
        ),
    ]


GENERIC_HEADING = re.compile(
    r"^(?:introduction|overview|background|miscellaneous|misc|general|other|details|notes|further reading|more information|useful links|see also)$",
    re.IGNORECASE,
)
QUESTION_END = re.compile(r"\?\s*$")
TRAILING_STOP = re.compile(r"[:.]$")


def heading_findings(piece, rules):
    if piece.kind != "heading":
        return []
    found = []
    words = count_words(piece.text)
    if words > rules["limits"]["headingWords"]:
        found.append(
            finding(
                {"id": "long-heading", "severity": "advise", "clause": "1: 5.2.4 d)"},
                piece,
                0,
                f"This heading has {words} words. Keep a heading short enough to scan.",
            ),
        )
    if QUESTION_END.search(piece.text):
        found.append(
            finding(
                {"id": "heading-is-a-question", "severity": "block", "clause": "GOV.UK: clear structure; 1: 5.2.4 b)"},
                piece,
                0,
                'A heading is a statement, not a question: readers want answers. Write "Find members who have no unit", not "Which members have no unit?".',
            ),
        )
    if GENERIC_HEADING.search(TRAILING_STOP.sub("", piece.text.strip(), count=1)):
        found.append(
            finding(
                {"id": "generic-heading", "severity": "advise", "clause": "GOV.UK: clear structure; 1: 5.2.4 b)"},
                piece,
                0,
                "This heading does not say what the section contains. Name the topic, or start with a verb for a task.",
            ),
        )
    # A heading can give a thing a person's verb too: "What the checker cannot see".
    for sentence in sentences(piece.text):
        masked = piece.masked[sentence.offset : sentence.offset + len(sentence.text)]
        found.extend(thing_verb_findings(piece, sentence, masked, rules))
    return found


# Words ending in -ion, -ment, -ance or -ence are usually verbs turned into nouns.
# Three in one sentence make it slow to read.
NOUN_FROM_VERB = re.compile(r"\b[a-z]{3,}(?:tion|sion|ment|ance|ence)s?\b", re.IGNORECASE)


def noun_heavy_findings(piece):
    found = []
    for sentence in sentences(piece.text):
        nouns = NOUN_FROM_VERB.findall(sentence.text)
        if len(nouns) < 3:
            continue
        found.append(
            finding(
                {"id": "noun-heavy", "severity": "advise", "clause": "GOV.UK: clear language; 1: 5.3.4 b)"},
                piece,
                sentence.offset,
                f"This sentence has {len(nouns)} nouns made from verbs ({', '.join(nouns[:4])}). Turn some back into verbs and name who does them.",
            ),
        )
    return found


# The same word twice in a row, as in "the the". The first word can end a hyphenated word,
# as in "the stand-in in each test". CODE and URL stand for code and links. Two of them can
# come side by side.
REPEATED_WORD = re.compile(r"\b([^\W\d_]+)\s+\1\b", re.IGNORECASE)


def repeated_word_findings(piece):
    found = []
    for match in REPEATED_WORD.finditer(piece.masked):
        if any(word in PLACEHOLDERS for word in match.group(0).split()):
            continue
        # Two different names of the same length have the same stand-in word.
        second = match.end() - len(match.group(1))
        if shown(piece, match.start(1), match.end(1)).lower() != shown(piece, second, match.end()).lower():
            continue
        found.append(
            {
                **finding(
                    {"id": "repeated-word", "severity": "block", "clause": "1: 5.3.3 a)"},
                    piece,
                    match.start(),
                    'The same word comes twice in a row, which is hard to read. Write "the stand-in for each test", not "the stand-in in each test".',
                ),
                "match": shown(piece, match.start(), match.end()),
            }
        )
    return found


# Under a heading about questions, each list item must be a direct question. Write
# "Dependabot: should updates be grouped?", not "whether to group its updates". A heading
# covers every item until the next heading at its level or above.
#
# Only top-level items are checked, because a nested item contains a detail. Some parts of
# a section ask their questions in paragraphs, such as "Should stack use a merge queue? The
# choices are:". The lists in those parts contain options and details, so their items are
# not checked either.
QUESTION_HEADING = re.compile(r"\bquestions?\b", re.IGNORECASE)
QUESTION_MARK = re.compile(r"\?[\"'”’)\]]*(?:\s|$)")
# A list item that starts with "Whether", after any label such as "Dependabot:". The item
# "Whether or not you use mise, run the tests" is not reported. The clause after its comma
# makes it a whole sentence.
WHETHER_ITEM = re.compile(r"^(?:[^\s:][^:]{0,60}:\s+)?whether\b[^,]*$", re.IGNORECASE)


def question_item_findings(pieces):
    # The text between two headings is one part. Find the parts that ask a question in a
    # paragraph, keyed by the line of the heading that starts the part.
    asks_in_paragraphs = set()
    start = 0
    for piece in pieces:
        if piece.kind == "heading":
            start = piece.line
        elif piece.kind == "paragraph" and QUESTION_MARK.search(piece.text):
            asks_in_paragraphs.add(start)

    found = []
    headings = []
    start = 0
    for piece in pieces:
        if piece.kind == "heading":
            headings = [one for one in headings if one[0] < piece.level] + [(piece.level, bool(QUESTION_HEADING.search(piece.text)))]
            start = piece.line
            continue
        if piece.kind != "item":
            continue
        first = sentences(piece.text)
        first = first[0].text if first else piece.text
        if WHETHER_ITEM.search(first.strip()):
            found.append(
                finding(
                    {"id": "whether-item", "severity": "block", "clause": "1: 5.2.4"},
                    piece,
                    0,
                    'This item starts with "whether", so it is a question written as a statement. Write it as a direct question, under a heading for questions: "Does the RunsOn trial licence have an end date?"',
                ),
            )
        elif (
            any(is_question for _, is_question in headings)
            and piece.indent < 2
            and start not in asks_in_paragraphs
            and not QUESTION_MARK.search(first)
        ):
            found.append(
                finding(
                    {"id": "question-heading-items", "severity": "block", "clause": "1: 5.2.4"},
                    piece,
                    0,
                    'This item is under a heading about questions, but it is not a question. Write it as a direct question that ends with "?", such as "Dependabot: should updates be grouped?". Put a statement under another heading.',
                ),
            )
    return found


CAPITALS = re.compile(r"\b[A-Z]{2,}(?:['’][A-Z]+)?\b")


def shouted_findings(piece, rules):
    found = []
    for match in CAPITALS.finditer(piece.masked):
        if re.sub(r"['’]", "", match.group(0)) not in rules["shouted"]:
            continue
        found.append(
            finding(
                {"id": "shouted-word", "severity": "advise", "clause": "1: 5.2.3 a) 1), 5.3.7"},
                piece,
                match.start(),
                f'"{match.group(0)}" in capitals reads as shouting. Explain why the rule matters instead, or use bold for the one thing that must stand out.',
            ),
        )
    return found


ROMAN = re.compile(r"^(?=[MDCLXVI]+$)M{0,3}(CM|CD|D?C{0,3})(XC|XL|L?X{0,3})(IX|IV|V?I{0,3})$")
ABBREVIATION = re.compile(r"\b[A-Z][A-Z0-9]{1,5}s?\b")


def abbreviation_findings(pieces, rules):
    full_text = "\n".join(piece.text for piece in pieces)
    seen = set()
    found = []
    for piece in pieces:
        for match in ABBREVIATION.finditer(piece.masked):
            word = match.group(0)
            bare = word[:-1] if word.endswith("s") else word
            if bare in seen:
                continue
            seen.add(bare)
            if word in PLACEHOLDERS or word in rules["known"] or bare in rules["known"]:
                continue
            if word in rules["shouted"] or ROMAN.search(word) or word[0].isdigit():
                continue
            if re.search(rf"\(\s*{bare}s?\s*\)|\b{bare}s?\s+\(", full_text):
                continue
            found.append(
                finding(
                    {"id": "undefined-abbreviation", "severity": "advise", "clause": "1: 5.3.2 d), e)"},
                    piece,
                    match.start(),
                    f'"{word}" is not spelled out anywhere. Spell it out the first time, unless this reader already uses it.',
                ),
            )
    return found


def js_round(number):
    """Rounds the way JavaScript's Math.round does, which rounds a half up."""
    whole = math.floor(number)
    return whole + 1 if number - whole >= 0.5 else whole


def to_fixed(number, digits):
    """Formats a number the way JavaScript's toFixed does, which rounds a half up."""
    return str(Decimal(number).quantize(Decimal(1).scaleb(-digits), rounding=ROUND_HALF_UP))


def variation_findings(pieces, rules):
    limits = rules["limits"]
    min_variation = limits["minSentenceVariation"]
    lengths = [count_words(sentence.text) for piece in pieces if piece.kind == "paragraph" for sentence in sentences(piece.text)]
    if len(lengths) < limits["variationNeedsSentences"]:
        return []
    mean = sum(lengths) / len(lengths)
    # Added one at a time, as JavaScript does, so the result is the same to the last bit.
    squares = 0.0
    for n in lengths:
        squares += (n - mean) * (n - mean)
    spread = math.sqrt(squares / len(lengths))
    if spread >= min_variation:
        return []
    return [
        {
            "id": "flat-rhythm",
            "severity": "advise",
            "clause": "1: 5.3.4 c)",
            "line": pieces[0].line,
            "span": [pieces[0].line, pieces[0].line],
            "excerpt": "",
            "say": f"Sentence lengths barely vary (standard deviation {to_fixed(spread, 1)} words, floor {min_variation}). Mix short sentences with longer ones so the text does not read flat.",
        },
    ]


def line_finding(id, severity, clause, line, excerpt, say):
    return {"id": id, "severity": severity, "clause": clause, "line": line, "span": [line, line], "excerpt": excerpt.strip()[:160], "say": say}


NUMBER_CELL = re.compile(r"^[-+]?[$£€]?\d[\d,]*(?:\.\d+)?\s?(?:%|[a-zA-Z]{1,3})?$")
DIVIDER = re.compile(r"^[\s|:-]+$")
RIGHT_EDGE = re.compile(r":\s*$")
LEFT_EDGE = re.compile(r"^\s*:")
PERCENT = re.compile(r"^\**\s*(-?\d+(?:\.\d+)?)\s?%")


def table_findings(rows):
    """Checks one Markdown table. `rows` is [{line, raw, cells}], header first, divider second."""
    found = []
    header, divider, body = rows[0], rows[1] if len(rows) > 1 else None, rows[2:]
    if divider is None or not DIVIDER.search(divider["raw"]):
        return found
    columns = len(header["cells"])
    at = header["line"]
    if columns < 2 or len(body) < 2:
        found.append(line_finding("table-too-small", "advise", "GOV.UK: tables", at, header["raw"], "A table this small is easier to read as a sentence or a list."))
    aligns = ["right" if RIGHT_EDGE.search(cell) and not LEFT_EDGE.search(cell) else "other" for cell in divider["cells"]]

    def cell(row, c):
        return row["cells"][c] if c < len(row["cells"]) else ""

    for c in range(columns):
        values = [cell(row, c).strip() for row in body]
        empty = next((row for row in body if not cell(row, c).strip()), None)
        if empty:
            found.append(line_finding("empty-table-cell", "advise", "GOV.UK: tables", empty["line"], empty["raw"], 'An empty cell is ambiguous. Write "no data", "not applicable" or "0".'))
        numbers = [value.replace("**", "") for value in values if value]
        if len(numbers) >= 2 and all(NUMBER_CELL.search(value) for value in numbers):
            if (aligns[c] if c < len(aligns) else None) != "right":
                found.append(line_finding("numbers-not-right-aligned", "advise", "GOV.UK: tables; 3: 5.3.7 j)", divider["line"], header["raw"], f'Column "{header["cells"][c].strip()}" holds numbers. Right-align it with "---:" so the digits line up.'))
        # A cell that starts with a percentage, such as "52% ($1,700 a month)", counts too.
        percents = [PERCENT.search(value) for value in values if value]
        if len(percents) >= 3 and all(percents):
            total = sum(float(match.group(1)) for match in percents)
            if total > 101:
                found.append(line_finding("parts-exceed-whole", "advise", "3: 5.3.6, 5.3.7", header["line"], header["raw"], f'The percentages in "{header["cells"][c].strip()}" add up to {js_round(total)}%. If the rows are meant to be parts of one total, they overlap. Use one breakdown per table.'))
    return found


SOURCE_FENCE = re.compile(r"^\s*(```|~~~)")
CODE_SPAN = re.compile(r"(`+)[\s\S]*?\1")
SOURCE_TABLE_ROW = re.compile(r"^\s*\|")
SOURCE_TABLE_EDGES = re.compile(r"^\||\|$")
SOURCE_HEADING = re.compile(r"^\s{0,3}(#{1,6})\s")
BOLD_LINE = re.compile(r"^\s*\*\*[^*]+\*\*:?\s*$")
FOOTNOTE = re.compile(r"\[\^[^\]]+\]")
LINK = re.compile(r"\[([^\]]+)\]\(([^)\s]+)")


def structure_findings(markdown):
    found = []
    lines = markdown.split("\n")
    link_targets = {}
    in_fence = False
    previous_level = 0
    table = []

    def close_table():
        if table:
            found.extend(table_findings(table))
        table.clear()

    for i, line in enumerate(lines):
        number = i + 1
        if SOURCE_FENCE.search(line):
            in_fence = not in_fence
            continue
        if in_fence or "plain-language-allow" in line:
            continue
        text = CODE_SPAN.sub("CODE", line)

        if SOURCE_TABLE_ROW.search(text):
            cells = SOURCE_TABLE_EDGES.sub("", text.strip()).split("|")
            table.append({"line": number, "raw": line, "cells": cells})
            continue
        close_table()

        heading = SOURCE_HEADING.search(text)
        if heading:
            level = len(heading.group(1))
            if previous_level and level > previous_level + 1:
                found.append(line_finding("heading-level-skipped", "block", "GOV.UK: headings; 1: 5.2.3 d)", number, line, f"This heading jumps from level {previous_level} to level {level}. Screen reader users move by heading level, so do not skip one."))
            previous_level = level
        if BOLD_LINE.search(text) and (i == 0 or not lines[i - 1].strip()):
            found.append(line_finding("bold-as-heading", "advise", "GOV.UK: headings; 1: 5.2.3 d)", number, line, "A line of bold text used as a heading is not a heading to a screen reader. Use a Markdown heading."))
        if FOOTNOTE.search(text):
            found.append(line_finding("footnote", "advise", "GOV.UK: footnotes; 1: 5.2.5", number, line, "Footnotes are made for print. Put important information in the text, and leave the rest out."))
        for link in LINK.finditer(text):
            label = link.group(1).strip().lower()
            link_targets.setdefault(label, {})[link.group(2)] = number
    close_table()

    for label, targets in link_targets.items():
        if len(targets) < 2:
            continue
        at = max(targets.values())
        found.append(line_finding("link-text-reused", "advise", "GOV.UK: links", at, lines[at - 1], f'The link text "{label}" goes to {len(targets)} different places. Give each destination its own link text.'))
    return found


def source_findings(markdown, rules):
    found = []
    in_fence = False
    for i, line in enumerate(markdown.split("\n")):
        if SOURCE_FENCE.search(line):
            in_fence = not in_fence
        if in_fence or "plain-language-allow" in line:
            continue
        text = CODE_SPAN.sub("CODE", line)
        for rule in rules["source"]:
            for item in rule["items"]:
                if not item["re"].search(text):
                    continue
                found.append(
                    {
                        "id": rule["id"],
                        "severity": rule["severity"],
                        "clause": rule["clause"],
                        "line": i + 1,
                        "span": [i + 1, i + 1],
                        "excerpt": line.strip()[:160],
                        "say": rule["say"],
                    }
                )
    return found


# Python's \s and strip() count U+0085 and U+001C to U+001F as white space, but they are
# control characters, so here they become U+007F, which is not white space. They also
# leave out U+FEFF, which a file saved with a byte order mark starts with. It becomes
# U+205F, a space character that no rule names, so the first line can still be a
# heading. A plain space would not do, because some rules match a literal space.
# JavaScript reads all six characters this way. Each replacement is one character, so
# offsets and line numbers do not change.
WHITE_SPACE = str.maketrans({"﻿": " ", "\x85": "\x7f", "\x1c": "\x7f", "\x1d": "\x7f", "\x1e": "\x7f", "\x1f": "\x7f"})


def findings(markdown, rules=None, mode="file", names=()):
    """Every finding for one Markdown text, in line order. `mode` is "file" or "chat"; a
    chat reply is too short for the rhythm check to mean anything. `names` are the
    project's names, from its settings file."""
    if rules is None:
        rules = load_rules()
    markdown = markdown.translate(WHITE_SPACE)
    pieces = prose_units(markdown)
    read_names(pieces, names)
    found = [
        *source_findings(markdown, rules),
        *structure_findings(markdown),
        *abbreviation_findings(pieces, rules),
        *question_item_findings(pieces),
    ]
    for piece in pieces:
        found.extend(phrase_findings(piece, rules))
        found.extend(repeated_word_findings(piece))
        found.extend(heading_findings(piece, rules))
        found.extend(shouted_findings(piece, rules))
        if piece.kind in PROSE_KINDS:
            found.extend(sentence_findings(piece, rules))
            found.extend(paragraph_findings(piece, rules))
            found.extend(noun_heavy_findings(piece))
    if mode == "file":
        found.extend(variation_findings(pieces, rules))

    unique = {}
    for one in found:
        key = (one["id"], one["line"], one.get("match", one["excerpt"]))
        unique.setdefault(key, one)
    return sorted(unique.values(), key=lambda one: (one["line"], one["id"]))


def clause_name(clause):
    return re.sub(r"\b([13]): ", r"ISO 24495-\1 ", clause)


LABEL = {"block": "must fix", "advise": "consider"}


def format_finding(where, one):
    """One finding as text. `where` is a file name, or None for a chat reply, whose line
    numbers mean nothing to the reader."""
    place = f"{where}:{one['line']}  " if where else ""
    head = f"{place}{LABEL[one['severity']]}  {one['id']} ({clause_name(one['clause'])})"
    if one.get("match"):
        quote = f'  "{one["match"]}" in: {one["excerpt"]}'
    elif one["excerpt"]:
        quote = f"  {one['excerpt']}"
    else:
        quote = ""
    return "\n".join(part for part in (head, quote, f"  {one['say']}") if part)


def read_text(path):
    """Reads a file as UTF-8, keeping its line endings, as Node.js does."""
    with open(path, "rb") as handle:
        return handle.read().decode("utf-8", "replace")


def main(argv):
    as_json = "--json" in argv
    block_only = "--block-only" in argv
    mode = "chat" if "--chat" in argv else "file"
    files = [arg for arg in argv if not arg.startswith("--")]
    rules = load_rules()
    if files:
        inputs = [(file, read_text(file), file) for file in files]
    else:
        inputs = [("stdin", sys.stdin.buffer.read().decode("utf-8", "replace"), os.getcwd())]

    results = []
    for where, text, start in inputs:
        try:
            names = names_for(start)
        except SettingsError as error:
            print(f"The settings file {error.path} is broken: {error.reason}.", file=sys.stderr)
            return 2
        found = findings(text, rules, mode=mode, names=names)
        results.append({"where": where, "findings": [one for one in found if one["severity"] == "block"] if block_only else found})

    def total(severity):
        return sum(1 for result in results for one in result["findings"] if one["severity"] == severity)

    sys.stdout.reconfigure(encoding="utf-8")
    if as_json:
        print(json.dumps({"results": results, "mustFix": total("block"), "consider": total("advise")}, indent=2, ensure_ascii=False))
    else:
        for result in results:
            for one in result["findings"]:
                print(f"{format_finding(result['where'], one)}\n")
        print(f"{total('block')} must fix, {total('advise')} to consider.")
    return 1 if total("block") > 0 else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
