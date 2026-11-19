# ISO 24495 guidelines, in our own words

This file restates every guideline in two standards, clause by clause:

- ISO 24495-1:2023, Plain language, Part 1: Governing principles and guidelines.
- ISO 24495-3:2026, Plain language, Part 3: Science writing.

It paraphrases them and does not quote them.
The licence for both standards is for one user. It prohibits copying, so do not paste their text here.

Each section ends with notes on what the guideline means for Claude's writing, marked "For Claude".

## Contents

- Part 1: the four principles
  - What Part 1 covers
  - Principle 1: readers get what they need
  - Principle 2: readers can find what they need
  - Principle 3: readers can understand what they find
  - Principle 4: readers can use the information
- Part 3: technical and scientific writing
  - What Part 3 covers
  - Principle 1 in Part 3
  - Principle 2 in Part 3
  - Principle 3 in Part 3
  - Principle 4 in Part 3

## Part 1: the four principles

### What Part 1 covers

**Plain language** is communication that is clear enough for its intended readers in its words, structure, and design (3.1).
They can easily find what they need, understand it, and use it.

A **reader** is anyone in the intended audience (3.2).
That includes people who skim or scan for one fact, and people who listen while a person or a screen reader reads the text aloud.
A document can have several audiences.
When their needs conflict, the main audience comes first.

A **document** is any information that is mostly text, printed or digital (3.3).
The standard's examples include an email, an error message, a form, a web page, and a video script.
**Information design** is how text, typography, images, and layout work together to help readers find, understand, and use information (3.7).
**Evaluation** is assessing how well readers do those three things (3.8).

The introduction makes three points that shape everything else:

- Plain language judges a document by how well readers can use it. A readability formula is a mechanical measure. It is not the test.
- Plain language is not easy language. Easy language is for people who have difficulty reading. Plain language suits a general audience.
- The four principles depend on each other. They are not steps to follow in order, and a document needs all four (clause 4).

**For Claude:** the checker in this skill is a mechanical measure. Passing it does not make text plain. Only the reader's ability to use the text does.

### Principle 1: readers get what they need

This principle is about the work before drafting (5.1.1).
Understand who the readers are and what they need, then choose the document type and content to fit.

#### Identify the readers (5.1.2)
Consider their literacy and language skills, cultural background, knowledge of the subject, accessibility needs, and the languages they understand.
Give them the document in a language they know.
Ways to learn about readers include past contact with them, interviews, surveys, and research about them.

#### Identify their purpose (5.1.3)
A reader might be doing any of these:

- following instructions to finish a task;
- deciding whether to do something;
- trying to understand a topic;
- finding out what the author wants from them;
- learning about something that interests them;
- gaining knowledge for a specific goal, such as a licence.

#### Identify their context (5.1.4)
Consider these questions about the readers:

- Where will they read it, and on what device?
- How much time will they have, and how long can they stay focused?
- How interested will they be?
- How will they feel while they read it?

The document type affects all of these.

#### Select the document type (5.1.5)
Choose the type that fits the readers, their purpose, and their context.
Something other than a document, such as a video, is acceptable when it serves the purpose better.

#### Select the content (5.1.6)
Keep the readers' needs first, even when the author must include some content for their own reasons.

- List the questions readers need answered.
- Choose content that fits the readers, their purpose, their context, and the document type.
- Leave out what they do not need.
- Consider the author's purposes as well.
- Select content ethically. Make it accurate, include nothing false, or misleading, and do not hide or omit anything readers need to know.

#### For Claude

- In chat, the reader is the person you are working with. The conversation shows what they know, so use it.
- For a file, the person you are working with is rarely the only reader. Ask who else reads it when the answer changes what you write.
- The context of a chat reply is a terminal. The reader often scans it after waiting for you, and wants the outcome first.
- Ethical content means reporting failures, skipped steps and unchecked assumptions as plainly as successes.

### Principle 2: readers can find what they need

Readers should be able to tell quickly what a document is about and whether it serves their purpose (5.2.1).
Structure and design make that possible, and headings matter most once a document runs past a few paragraphs.

#### Structure the document for readers (5.2.2)
Group related information and order it in a way that makes sense to the reader.

- Put the most important message where readers will find it, usually at the start.
- Introduce new information by building on what readers already know.
- Present instructions and processes in the order they happen.
- Put what most readers need before what only some readers need.
- When a mistake could cause damage or harm, put the warning about what not to do before the instruction.

#### Use information design (5.2.3)

- Show how elements relate. Make important elements stand out (prominence). Keep related elements together (proximity). Make elements with the same job look the same (similarity). Make the reading order obvious (sequence).
- Consider an image or other media to draw readers to a topic.
- Use headings so readers can scan the document and see its structure, with more than one level if needed.
- Make the hierarchy visible, with consistent heading styles and indentation.
- Use bulleted and numbered lists for information readers might otherwise miss.
- Choose typography that makes reading physically easier: font, size, line spacing, and contrast.
- Add a table of contents when it helps readers see the structure or find a section.
- Add an index when it helps readers find specific information.
- When there are several audiences, label which information is for which audience.

#### Use headings to help readers predict what comes next (5.2.4)
Start a new heading for each new topic.
Make each heading describe what follows it accurately.
Keep headings consistent, and short enough to scan.
Use enough headings to help readers find things, and no more.

#### Keep supplementary information separate (5.2.5)
Some information matters to few readers, such as the legal basis of a policy, a list of sources, or a detailed explanation.
Put it in an appendix, a bibliography, or another separate place.

#### For Claude

- Prominence works only when it is rare. When half the words in a reply are bold, nothing stands out.
- A short chat reply needs no headings. A reply with several separate topics does.
- In Markdown, a numbered list signals sequence and a bulleted list signals a set. Do not swap them.

### Principle 3: readers can understand what they find

Each element must be easy to understand. The elements must also work together so the reader understands the whole (5.3.1).

#### Choose familiar words (5.3.2)

- **a)** Choose words that make the meaning precise, so the text can be read only one way. Name the specific tool, not "a tool".
- **b)** Choose words that give the reader a mental picture. Give a concrete example rather than an abstract quality.
- **c)** Use a specialised term only when readers understand and prefer it, or when they need to learn it to reach their goal. In the second case, explain it where it first appears.
- **d)** Use an abbreviation only when readers know the short form better, or when the full form is very long.
- **e)** Spell out an abbreviation where it first appears, unless it is common and well understood.
- **f)** A short form of a long name is acceptable, but explain it where it first appears.
- **g)** Be consistent. Use the same word for the same meaning, and different words for different meanings.
- **h)** Use language that suits the culture of the readers. Consider the words used by the age, ethnic, religious, and other groups in the audience.

#### Write clear sentences (5.3.3)

- **a)** Use a clear structure. Use sentence patterns readers know. In English, that is usually subject, verb, object. Avoid structures that can be read two ways. Do not interrupt the main thought with extra information. Start a sentence with something the reader already knows, then add the new information.
- **b)** Address readers directly. In English, that means "you" and "your".
- **c)** Make clear who does what. In English, use the active voice unless there is a specific reason for the passive.
- **d)** Use grammar, spelling and punctuation that readers accept.
- **e)** Follow official or national language standards, unless they fail the readers in a particular case.

#### Write concise sentences (5.3.4)

- **a)** Put one idea in each sentence.
- **b)** Cut redundant words, vague modifiers, clichés, and anything else that costs the reader time and attention without adding meaning.
- **c)** Keep sentences reasonably short, and vary their length to give the text rhythm.

#### Write clear and concise paragraphs (5.3.5)
Give each paragraph one topic, and state the topic near the start.
Make the connections between and within paragraphs clear.

#### Consider images and multimedia (5.3.6)
Present information in other ways than text when that helps.
An image must support the text and not only decorate it.
Keep images simple, place them near the text they belong to, label them clearly, and leave space around them.

#### Project a respectful tone (5.3.7)
Readers who feel respected are more likely to read the document and act on it.
Word choice signals tone most, so use inclusive language that does not discriminate.
Structure, design, images, personal pronouns, and sentence patterns also signal tone.

#### Make the document cohesive (5.3.8)
Make clear how every word, sentence, paragraph, section, and image relates to the others.
Use consistent design, follow any relevant style guide, and keep the tone consistent.

#### For Claude

- Idioms and metaphors break 5.3.2 a) and b): they are imprecise, and the picture they create is the wrong one. "Load-bearing test" makes the reader picture a wall.
- An invented label, such as "the guard" or "option B", breaks 5.3.2 f) unless it was explained where it first appeared.
- An issue number or commit hash is a short form too. Say what it refers to.
- Synonym rotation, such as "check", "verify" and "confirm" for one action, breaks 5.3.2 g).
- Dropping articles and verbs to save words breaks 5.3.3 a) and d). Readers do not accept it as normal grammar.

### Principle 4: readers can use the information

Following Principles 1 to 3 makes a usable document likely, but only evaluation shows it (5.4.1).
Evaluate the document while it is written, with readers when possible, and from time to time while it is in use.

#### Evaluate while you write (5.4.2)
A plain language document rarely comes out right in one draft.
Review it against what you know about the readers, their purpose, and their context.
Check it against the principles, using a checklist if that helps.

#### Evaluate with readers (5.4.3)
Involving readers is the only way to know how they will react.
Decide how far to go by weighing four things:

- the time and resources available;
- how complex the document is;
- how many readers there are, and who they are;
- how serious it is if readers cannot use the document.

The methods range from asking one person for quick feedback to full usability testing.

#### Keep evaluating (5.4.4)
Re-evaluate a document that is used again and again.
Change it if it is still needed, or withdraw it if it is not.
Measure outcomes where possible: how many readers respond or follow the instructions correctly, how satisfied they are, and how many questions they ask.

#### For Claude

- 5.4.2 is the checker and the reread in step 5 of SKILL.md.
- Claude cannot test a document with readers (5.4.3). It can tell the user when that test matters.
- For a long-lived document, suggest a review date or a check that fails when the document goes stale.

## Part 3: technical and scientific writing

### What Part 3 covers

Part 3 adds guidelines for **science writing**: writing about a scientific subject for readers with a range of education, backgrounds, and interests (3.4).
It does not cover **scientific writing**: experts writing for others in the same field (3.5).
Part 1 still applies in full, and Part 3 is organised by the same four principles.

Part 3 also defines a **noun string**: two or more nouns run together to name one idea (3.3).
"Hospital employee safety protocol violation report form" is one.
Noun strings make text hard to understand.

**For Claude:** treat these as science writing:

- the results of an investigation or a debugging session;
- performance measurements and data analysis;
- research summaries;
- design decisions that cite evidence.

The reader of each is rarely an expert in exactly that question.

### Principle 1 in Part 3

#### Characterise the readers (5.1.2)
Science writing reaches readers with very different backgrounds, so plan for them in detail.
Knowing the readers settles the terms to use, how to organise the content, the critical information, the evidence to give, and where to publish.
Ask questions such as these:

- Are there distinct groups of readers with different backgrounds and purposes? What range of education can you expect?
- Are readers looking for general information on a current topic? How much do they know, and how familiar are they with the field's terms?
- Do readers need evidence to solve a problem, decide something, or support a policy? What context do they need to understand it?
- How well can readers interpret data, and what help will they need?
- Do readers face decisions about health or safety, or are some in a critical situation?
- Do readers come from different specialisations?
- Can you make the content accessible without oversimplifying it?

#### Identify the genre (5.1.3)
Learn and follow the conventions of the genre, and expect those conventions to change over time.
Some genres, such as plain language summaries of research, call for plain language explicitly.

#### Identify the purpose (5.1.4)
State the document's purpose in a way that suits the readers and the genre.
Put it in the title or headline, and near the start.
A clear purpose also shows which information is unnecessary, irrelevant, misleading or confusing.

#### Plan the document (5.1.5)
Before drafting, plan these:

- the main purpose and the main messages;
- the background readers need for context;
- the main sections, and an order that develops the content logically;
- a level of complexity that neither overwhelms nor oversimplifies;
- the evidence and examples that support each point;
- the images that will help, and where they go;
- how much to say about methods, since some readers need to judge reliability and others would be lost in the detail;
- the counter-arguments and how to answer them;
- the unknowns, uncertainties, and limits, and how much confidence the findings deserve;
- the conclusions, and why they matter;
- any actions readers can take, and how they can use the information;
- supplementary material such as appendices, glossaries, and references.

#### Present content ethically (5.1.6)
On top of Part 1's ethical guidance:

- Present data fairly. Do not select, skew, or distort data to favour one interpretation.
- State the limits and uncertainties of current knowledge, including whether results apply beyond the conditions studied.
- Do not mislead with a headline, an illustration, or a statement that does not match the facts.
- Consider saying how reliable your sources and their publishers are.
- State any conflict of interest or source of bias.
- Consider privacy, confidentiality, and social consequences when you handle sensitive data about people.
- Do not plagiarise, falsify, or fabricate.
- Say when technology helped produce the content, including content written or generated with artificial intelligence.

#### For Claude

- The limits clause is the one most often broken. A fix tested on one input has not been shown to work on every input, so say which input you tested.
- Fabrication includes stating a command's output, a file's contents, or a test result you did not see.
- For a document the user will publish, ask whether it should say that AI helped write it.

### Principle 2 in Part 3

#### Provide an overview (5.2.2)
At the start of a long or complex document, give an informative summary or a list of the main points.
When useful, say what the document covers and what it leaves out.

#### Structure the document for its readers (5.2.3)

- Lead with the most important points, such as the main conclusions, what they mean in practice, and how to apply them.
- Mark off different sections and kinds of content visually, with borders, lines, space, boxes, shading or indentation.
- Signal each shift in topic with a transition. Transitions can show logic ("therefore"), time ("then"), addition ("also") or the author's attitude ("not surprisingly").
- In a document with many figures or tables, link readers straight to the data.
- Point readers to further information: web pages, reading lists, or organisations that are good sources.

#### Provide navigation (5.2.4)
In a longer document, give readers signposts, because readers take different routes through it.

- Add a table of contents to a long or complex document.
- Provide links, bookmarks, or page numbers.
- Use informative headers and footers.
- Make the heading hierarchy clear, through consistent styling, or numbered headings such as 2.3 and 2.3.1.
- Consider boxed sidebars or call-outs to summarise what readers need to remember.
- Design the document to work on a phone when possible.
- Make the document work with assistive technology, and meet standards such as the Web Content Accessibility Guidelines.

**For Claude:** in Markdown, a blockquote callout such as `> [!NOTE]` is a sidebar. A relative link to a section or file is a bookmark.

### Principle 3 in Part 3

Part 3 repeats Part 1's language guidelines, and asks for a tone that is respectful and also empathetic where it suits the readers (5.3.1).

#### Indicate the status of information (5.3.2)
Tell readers where information came from and how far to rely on it:

- **a)** Point readers to sources they might not know about or cannot easily check.
- **b)** Name the authors and sponsors, so readers can judge expertise, reliability, and possible conflicts of interest.
- **c)** Cite quotations, paraphrases, data, and ideas from other sources, formally, or informally depending on the genre.
- **d)** Date the document, so readers can judge whether it is current.
- **e)** Say what kind of statement each one is. It might be an assumption, a hypothesis, a claim, an example, or a method. It might be a result, a conclusion, a limit, an extrapolation, a forecast, or an application.
- **f)** Make information that matters in an urgent or personal situation prominent.
- **g)** Describe and label variables and units using established conventions, such as SI units, or labels the readers know.
- **h)** Consider an everyday comparison when it suits the readers, such as giving a size as "about the size of an orange".

#### Use precise language (5.3.3)

- **a)** Keep style, terms, tone, and expression consistent. A deliberate change can be effective, for example to mark urgent information.
- **b)** Choose terms the readers are likely to know.
- **c)** Help readers learn important terms and abbreviations by defining them in context, in a sidebar or in a glossary. A short definition in context helps most.
- **d)** Consider an everyday alternative to a technical term, such as "kidney disease" for "nephropathy".
- **e)** Use specialised terms and abbreviations as Part 1 5.3.2 c) and d) describe.
- **f)** Choose hedging words with care. Words such as "typically", "roughly" and "can potentially" signal that an interpretation could change with new evidence. Where possible, tie each hedge to observed data or a number.
- **g)** Rewrite a noun string as a phrase that explains it. "Computer games that simulate human cognition" is easier than "computer human cognition simulation games".
- **h)** Keep parallel structure in sentences, paragraphs, and headings, so similar ideas have similar grammar.
- **i)** In a comparison, state both sides: what is compared with what.

#### Design effective images (5.3.4)

- Match the image to the structure of the data:
  - a line graph for continuous data;
  - a bar chart for separate categories;
  - a flow chart for a process;
  - a pie chart only for rough proportions;
  - a photograph for detail;
  - a line drawing to remove distracting detail.
- Match the image to what readers know, and show only the detail they need.
- Consider whether a table shows the data better than a paragraph.
- Give images informative titles, captions, and alternative text that state the main message.
- For digital documents, consider interactive charts, and make sure screen readers can use them.
- Avoid special effects that do not help readers understand.
- Give complete legends that match the data shown.
- Cite the source of any data or image that is not yours.
- Prefer black text on white for contrast, and add colour with care.
- Size tables and figures so they are legible on the devices readers use.
- Render graphics at a resolution that stays sharp when zoomed.
- Keep image styles consistent through the document.
- Follow accessibility good practice so every reader can use the images.

#### Identify important data displays (5.3.5)
Give the amount of data that suits the readers and the genre.
Some readers go straight to charts, others want the data explained, and their skill with charts varies widely.

- Put the important results or conclusions at or near the start.
- Design the central charts and tables to show the most important findings.
- Say in the text what readers should take from each chart or table. Help readers who are not used to data to interpret, compare, judge risk, and reason about cause and effect.
- Leave out data that does not support the main message. Move supporting data to an appendix or a repository.
- Make data appendices easy to follow, with consistent design and instructions for reading them.
- Do not pack paragraphs with numbers, and do not repeat at length the data a table already shows.

#### Characterise data (5.3.6)

- Present data in ways the readers are likely to understand.
- Use comments, captions, or notes to explain important features of the data and the statistical methods.
- When you use statistical terms, interpret them. When you give an average, also give the spread, such as a standard deviation, an interquartile range, or a confidence interval.
- Give numbers to an honest precision, with suitable decimal places or error bars.
- Explain how far readers can trust the data. **Reliability** is whether a measurement gives the same result when repeated. **Validity** is whether it measures what it claims to measure.
- Explain outliers and unexpected results.

#### Design effective tables (5.3.7)

- Give each table a title that states its main message.
- Choose an effective order of rows and columns, and keep the orientation the same throughout.
- Keep borders and lines to a minimum. Separate content with white space, light shading, or thin horizontal lines.
- Avoid splitting a table across pages, and keep column headings visible in long digital tables.
- Rather than make readers compare several tables, consider one table that makes the comparison easy.
- Keep text in high contrast with the background, and use a typeface whose numbers are easy to read.
- Balance content across columns so the table uses space well.
- Consider giving readers tools to find and view tables, charts, and diagrams.
- Do not merge cells, including heading cells, because merged cells break accessibility.
- Align comparable numbers to the right or on the decimal point, centre values that are not comparable, and align text to the left.
- Avoid complicated links from cells to table notes.

#### For Claude

- Status labels are the guideline Claude most needs. "Verified by running the test", "inferred from the code", and "not checked" are three different claims.
- A hedge such as "this should work" hides whether you tested it. Say what you ran and what it showed.
- In a Markdown table, `---:` right-aligns a column of numbers.
- A timing from one run is not a measurement. Give the number of runs and the spread.

### Principle 4 in Part 3

#### Increase usability (5.4.2)
Get feedback on how clear and effective the document is:

- Plan how to get feedback, and revise the document before the final version.
- Review it for errors and inconsistencies.
- Ask another author or editor to review it, especially the claims, the data, the methods, and the significance.
- Where possible, give readers a way to send feedback.

#### Check usability (5.4.3)
Check the document against these questions, in addition to Part 1's evaluation guidelines:

- Are there clear summaries or main messages at strategic points, such as before a change of topic and in the conclusion?
- Are specialised terms and abbreviations ones the readers know, and does the document help them learn the key terms?
- Would a familiar example or scenario help readers understand?
- Do images have complete legends, with all data explained? Can they be read on different devices?
- Does the document show the practical uses and real-world consequences of the information?
- Where it fits, does the document tell readers what to do next, or how to apply the information?

**For Claude:** in a report of findings, end with what the user can do next, and with what remains unknown.
