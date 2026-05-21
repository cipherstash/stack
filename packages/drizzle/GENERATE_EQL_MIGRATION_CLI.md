# generate-eql-migration CLI Command

A command-line tool for easily generating Drizzle migrations that install CipherStash EQL (Encrypt Query Language) in your PostgreSQL database.

## Purpose

This CLI automates the process of:
1. Creating a custom Drizzle migration file
2. Populating it with the EQL SQL schema (bundled from `@cipherstash/schema`)
3. Making it ready to apply to your database

## Installation

The command is automatically available when you install `@cipherstash/drizzle`:

```bash
pnpm add @cipherstash/drizzle
```

## Usage

### Basic Usage

From your project root (where your Drizzle config is located):

```bash
npx generate-eql-migration
```

This will:
- Generate a migration named `install-eql` in the `drizzle/` directory
- Fill it with the EQL SQL schema
- Show you next steps

### Options

```bash
Usage: generate-eql-migration [options]

Options:
  -n, --name <name>    Migration name (default: "install-eql")
  -o, --out <dir>      Output directory (default: "drizzle")
  -h, --help           Display this help message
```

### Examples

```bash
# Default: creates drizzle/XXXX_install-eql.sql
npx generate-eql-migration

# Custom name
npx generate-eql-migration --name setup-eql

# Custom output directory
npx generate-eql-migration --out migrations

# Both custom name and directory
npx generate-eql-migration --name init-eql --out db/migrations
```

## How It Works

1. **Calls drizzle-kit**: Executes `pnpm drizzle-kit generate --custom --name=<name>` to create an empty migration file
2. **Locates EQL SQL**: Finds `cipherstash-encrypt-2-1-8.sql` from the installed `@cipherstash/schema` package
3. **Populates migration**: Writes the EQL SQL content to the generated migration file
4. **Reports success**: Shows the path to the migration and next steps

## Implementation Details

- **Location**: `packages/drizzle/bin/generate-eql-migration.js`
- **Package.json entry**: `"bin": { "generate-eql-migration": "./bin/generate-eql-migration.js" }`
- **Dependencies**: 
  - Requires `drizzle-kit` (peer dependency, optional)
  - Reads SQL from `@cipherstash/schema` package
  - Uses Node.js built-in modules (fs, path, child_process)

## Error Handling

The CLI will exit with an error if:
- `drizzle-kit` is not installed or fails to generate the migration
- The EQL SQL file cannot be found in `@cipherstash/schema`
- The Drizzle output directory doesn't exist
- The generated migration file cannot be found

## After Running

Once the migration is created, apply it with:

```bash
npx drizzle-kit migrate
```

Or use your custom migration workflow.

## Comparison to Manual Process

### Before (manual):
```bash
npx drizzle-kit generate --custom --name=install-eql
curl -sL https://github.com/cipherstash/encrypt-query-language/releases/download/eql-2.2.1/cipherstash-encrypt.sql > drizzle/0001_install-eql.sql
npx drizzle-kit migrate
```

### After (automated):
```bash
npx generate-eql-migration
npx drizzle-kit migrate
```

## Benefits

1. **Offline-friendly**: Uses the bundled SQL file from `@cipherstash/schema` instead of downloading from GitHub
2. **Version-locked**: Always installs the EQL version that matches your installed `@cipherstash/schema` package
3. **Simplified workflow**: Single command instead of multiple steps
4. **Error-resistant**: Validates each step and provides clear error messages
5. **Flexible**: Supports custom names and output directories

## Troubleshooting

### "Failed to generate custom migration"
- Ensure `drizzle-kit` is installed: `pnpm add -D drizzle-kit`
- Check that you're running from the project root with a valid Drizzle config

### "Could not find EQL SQL file"
- Ensure `@cipherstash/schema` is installed (peer dependency)
- The CLI looks for `cipherstash-encrypt-2-1-8.sql` in the schema package

### "Drizzle directory not found"
- Run the command from your project root
- Or specify the correct path with `--out`

### "Could not find migration file"
- The CLI looks for files matching the pattern `*<name>.sql` in the output directory
- Check that `drizzle-kit` successfully created the migration
