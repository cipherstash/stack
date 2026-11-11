---
name: plain-language
description: Plain language for prose a person reads, following ISO 24495-1:2023, ISO 24495-3:2026 and the GOV.UK content guidance. Use when writing a document, README, plan, spec, report, findings, summary, pull request description, commit message or code comment; when rewriting or reviewing text that is hard to read, full of jargon, metaphor, idiom or cliché; and when the user mentions plain language, plain English or ISO 24495.
---

# Plain language

Plain language means the reader can **find** what they need, **understand** it the first time, and **use** it (ISO 24495-1:2023, 3.1).
The reader decides whether text is plain, not the writer.
Every step below asks one question: what does this reader need to find, understand, and use?

The everyday rules are in [core.md](core.md).
A session hook normally adds them to the context of every session.
If core.md is not in your context, read it now. The steps below assume you have read it.

In clause references, "1:" means ISO 24495-1:2023. "3:" means ISO 24495-3:2026.
"GOV.UK" means the UK government's content guidance. It turns the standards into specific rules for words, headings, links, lists, and tables.

## Choose the branch

- **A chat reply:** core.md is enough. Do step 5b before you send it.
- **A new document or file:** do every step.
- **A rewrite of existing text:** do every step. Before you draft, list every fact in the original. In step 5, check that each fact is in the new version, or that you cut it on purpose and said so.
- **A review of someone else's text:** do step 1, then step 5. Report each problem with the sentence, the clause it breaks, and a rewrite. Do not rewrite the whole text unless the user asks.
- **Findings, investigations, measurements, or data:** also apply the Part 3 guidelines in [references/guidelines.md](references/guidelines.md), under "Part 3: technical and scientific writing".

## Steps

### 1. Name the reader, their purpose and their context

Before you draft, write down four things (1: 5.1.2 to 5.1.4):

- **Who reads it**, and what they already know about the subject.
- **Why they read it**: to do a task, to decide something, to understand something, or to check something.
- **Where they read it**: in a terminal, on a phone, on a pull request page, or on paper.
- **How they read it**: in a hurry or with time, and calm, or under pressure.

When the user has not said who the reader is, start from this table and adjust it to what you know.

| Document | Usual reader | What that reader needs first |
|---|---|---|
| Chat reply | The person you are working with | The answer, then anything you need from them |
| Code comment | A developer changing this code later | Why the code is this way, and what breaks if they change it |
| Commit message | A developer searching the history | What changed and why |
| Pull request description | The reviewer | What changed, why, and how to check it |
| README | Someone who has just found the project | What it is, and how to start using it |
| Guide or help page | A person doing a task, often not a specialist | The steps, in order |
| Incident or investigation report | Technical and non-technical readers together | What happened, the effect, what is known and unknown, and what happens next |
| Plan or design | The people who build it and the people who approve it | The decision, the reasons, and the open questions |
| Decision record | A developer reading it a year later, who was not there | The decision, the options considered and why each was rejected, and what gets harder as a result |

Sometimes you cannot tell who the reader is. If a wrong guess would waste the user's time, ask the user.

**Done when** you can state the reader, their purpose, and their context in one sentence each.

### 2. Choose the content

List the questions this reader needs answered (1: 5.1.6).
Plan one part of the document for each question.
Leave out everything else, including how you found things out, unless the reader needs it to trust the result.
Never leave out what the reader needs to act safely: risks, limits, failures, and what nobody checked.

When two readers need different things, the main reader's needs come first (1: 3.2).

**Done when** every planned part answers one of the reader's questions, and every question has a part.

### 3. Structure it

- Put the most important message first: the answer, the conclusion, or the action (1: 5.2.2 a; 3: 5.2.3 a).
- Group related information, and put what most readers need before what only some need (1: 5.2.2 d).
- Put steps in the order the reader does them, and each warning before the step it applies to (1: 5.2.2 c, e).
- In a document longer than a few paragraphs, use headings. Each heading says what the section below it contains, and stays short (1: 5.2.4).
- Follow the GOV.UK rules for headings, links, lists, and tables in [references/content-guidance.md](references/content-guidance.md). Read that file before you write a document with any of them.
- In a long or complex document, start with a short summary of the main points. Say what the document covers and what it does not (3: 5.2.2).
- Move background, method details, and references to the end or to an appendix (1: 5.2.5).
- When the document has more than one audience, label the parts meant for each one (1: 5.2.3 i).

**Done when** someone who reads only the headings and the first paragraph knows what the document says and where to find each part.

### 4. Write it

Apply every rule in core.md as you write, not afterwards.
These points need more judgement than core.md gives:

- When the reader needs several specialised terms, define each where it first appears. Add a glossary if there are many (3: 5.3.3 c).
- When a number means little on its own, compare it with something the reader knows (3: 5.3.2 h).
- Use a diagram, table, or image only when it shows something more clearly than text. Give it a caption that states its main message (1: 5.3.6; 3: 5.3.4).
- In a table, give it a title that states its message, right-align numbers, and do not merge cells (3: 5.3.7).
- Keep terms, tone, and formatting the same from start to end (1: 5.3.8).
- When one reader is not technical, write their part to them as "you", and give them their own list of actions. Do not put their tasks in a table full of technical rows (1: 5.2.3 i).
- In a rewrite, open with the specific thing the reader must do or must not change, by its name and file. If you add an explanation the original lacks, tell the user which parts you added.
- Give a document a title that makes sense on its own, using the GOV.UK rules for titles.
- Date a document that people will rely on later, and say who wrote it when that matters to the reader (3: 5.3.2 b, d).

**Done when** the draft answers every question from step 2.

### 5. Check it

#### a. Run the checker

Run the checker on every prose file you wrote:

```
python3 "${CLAUDE_SKILL_DIR}/scripts/check.py" path/to/file.md
```

For text that is not in a file, pipe it in and add `--chat`.
Fix every "must fix" finding.
Decide on each "consider" finding: fix it, or keep it because this reader needs it that way.

#### b. Reread it as the reader

Answer each question (Annex B of both standards, combined):

1. Is the most important message at the start?
2. Does every part answer a question this reader has? Is anything they need missing?
3. Can the reader find each part from the headings alone?
4. Does every item fit its heading?
5. Is every term one this reader knows, or explained where it first appears?
6. Does each sentence say one thing, literally, and name who does it?
7. Is each claim marked as checked, inferred or guessed, with its source?
8. Is every comparison complete, and does every number have a unit and context?
9. Is the tone respectful, and the same throughout?
10. In a rewrite, is every fact from the original present, or cut on purpose?

#### c. Tell the user what your check cannot show

Some documents are read by many people, or a misunderstanding of them is costly.
For those, say that testing with one real reader is the only way to know the document works (1: 5.4.3).
For a document that people will use for a long time, suggest when to review it (1: 5.4.4).

**Done when** the checker reports no "must fix" findings, and the answer to every question in 5b is yes.

## The checker and the hooks

`scripts/check.py` and two hooks read one list of rules, `scripts/rules.json`.
The Stop hook checks each chat reply, and the PostToolUse hook checks each Markdown or text file Claude writes.
Each sends the text back when it finds a "must fix" problem.

The checker finds wordy phrases, clichés, idioms, figurative words, the GOV.UK words to avoid, and symbols used for words.
It finds negative contractions, stacked hedges, long sentences, long paragraphs, and asides that interrupt a sentence.
It also finds headings that are questions, skipped heading levels, vague link text, and some table problems.

It cannot decide whether the reader needs a sentence, or whether this reader knows a word.
It cannot recognise a figure of speech that is missing from its list.
It does not find noun strings, incomplete comparisons, or hedges that go further than the evidence.
Those stay with you.

The checker skips code blocks, inline code, URLs, and text inside quotation marks.
A line containing `plain-language-allow` is skipped.
A file with `<!-- plain-language-check: off -->` on a line of its own is skipped.
Use that only for a file that lists banned phrases.

When a hook sends text back, fix the sentences it names and send the text again.
If a finding is wrong, such as a listed word used literally, rephrase the sentence anyway.
Then tell the user which rule fired wrongly, so they can change `rules.json`.

A repository can have writing rules of its own, in a CLAUDE.md, a style guide, or a content guidance folder.
Follow those too.
Where they are stricter than this skill, they win.

## Reference

[references/guidelines.md](references/guidelines.md) states every guideline of both standards in our own words, clause by clause.
You need it in three cases: for the detail of one guideline, for a clause to cite in a review, and for Part 3 work.

[references/content-guidance.md](references/content-guidance.md) states the GOV.UK rules that apply to Claude's writing, including the full list of words to avoid.
Read it before you write a document with headings, links, lists, or tables, and when the checker names a GOV.UK rule.
The GOV.UK guidance is licensed under the Open Government Licence v3.0. That licence allows reuse with credit.

The licence for each ISO standard is for one user. It prohibits copying.
If you have a copy, paraphrase it and cite the clause.
Never paste its text into this skill or into anything you write.
