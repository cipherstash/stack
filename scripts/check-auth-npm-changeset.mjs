import fs from 'node:fs'
import parseChangeset from '@changesets/parse'

const changesetFiles = process.argv.slice(2).filter(Boolean)

if (changesetFiles.length === 0) {
  console.error(
    "::error::Release-relevant stack-auth changes require an @cipherstash/auth changeset. Run 'npx changeset' and commit the generated file.",
  )
  process.exit(1)
}

let hasAuthRelease = false

for (const changesetFile of changesetFiles) {
  const contents = fs.readFileSync(changesetFile, 'utf8')
  const lines = contents.split(/\r?\n/)
  const closingDelimiter = lines.indexOf('---', 1)

  if (lines[0] !== '---' || closingDelimiter === -1) {
    console.error(
      `::error file=${changesetFile}::Changeset must start with YAML frontmatter delimited by ---`,
    )
    process.exit(1)
  }

  if (
    lines
      .slice(closingDelimiter + 1)
      .join('\n')
      .trim().length === 0
  ) {
    console.error(
      `::error file=${changesetFile}::Changeset summary must not be empty`,
    )
    process.exit(1)
  }

  let changeset
  try {
    changeset = parseChangeset(contents)
  } catch (error) {
    console.error(
      `::error file=${changesetFile}::Invalid changeset: ${error.message}`,
    )
    process.exit(1)
  }

  if (
    changeset.releases.some(
      ({ name, type }) =>
        name === '@cipherstash/auth' &&
        (type === 'patch' || type === 'minor' || type === 'major'),
    )
  ) {
    hasAuthRelease = true
    console.log(
      `Found valid @cipherstash/auth release intent in ${changesetFile}`,
    )
  }
}

if (!hasAuthRelease) {
  console.error(
    "::error::Release-relevant stack-auth changes require an @cipherstash/auth changeset with a patch, minor, or major bump. Run 'npx changeset' and commit the generated file.",
  )
  process.exit(1)
}
