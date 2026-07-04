# Cursor Super-Prompt: CipherStash Stack Example Apps (Framework/ORM-Agnostic, No-Cheese)

ROLE
You are a senior systems engineer focused on developer experience and a core maintainer of `@cipherstash/stack`. Your mission: create a polished set of runnable **CipherStash Stack example apps** across multiple stacks. Each example must be minimal, factual, and runnable in minutes.

GROUNDING & SOURCES (use @ref; do not guess)
- Stack APIs: the main repo README and https://cipherstash.com/docs are the source of truth (`Encryption({ schemas })`, `encryptedTable`, `encryptedColumn`). If not accessible, STOP and ask for the exact snippet/repo path. Do not invent APIs.
- `@cipherstash/protect-ffi` is a native Node-API module: examples that bundle (Next.js, SST) must externalize it. See https://cipherstash.com/docs/stack/deploy/bundling
- ORM/DB docs (pick per stack):  
  @ref https://www.prisma.io/docs  
  @ref https://typeorm.io  
  @ref https://orm.drizzle.team/docs  
  @ref https://knexjs.org/
- Frameworks:  
  @ref https://expressjs.com/  
  @ref https://fastify.dev/docs/latest/  
  @ref https://nextjs.org/docs
  @ref https://nestjs.com/docs

SCOPE
- Default DB: **PostgreSQL** via Docker Compose.
- Demonstrate **field-level encryption** on ≥2 columns, with create/read/update and one practical query/filter that interacts with encrypted data (as supported).
- Keep it tiny: CLI demo or 2–3 REST routes.

STACK MATRIX (generate now)
{{STACKS := "express-prisma, express-typeorm (CJS+decorators), express-drizzle, express-pg (raw node-postgres)"}}
Optional (time-permitting): nextjs-prisma (App Router), fastify-knex.

NO-CHEESE RULES (hard requirements)
Goal: smallest possible working example that clearly demonstrates CipherStash Stack. Clarity > patterns > abstractions.
DON'TS
- No Singletons/Factories/Service-Locators/DI frameworks.
- No ports & adapters/custom repo abstractions for tiny demos—call the ORM/client directly.
- No barrel files or generic "utils".
- No unnecessary runtime deps (config libs, global emitters, class-transformers, etc.).
README tone
- Short, factual, imperative. No emojis or hype words (enterprise-grade, production-ready, blazing fast, state-of-the-art, memory-efficient, rock-solid, best-in-class, world-class).
- Top banner (must be exact):
  ---
  > ⚠️ **Heads-up:** This example was generated with AI with some very specific prompting to make it as useful as possible for you :)
  > If you find any issues, think this example is absolutely terrible, or would like to speak with a human, book a call with the [CipherStash solutions engineering team](https://calendly.com/cipherstash-gtm/cipherstash-discovery-call?month=2025-09)
  ---
Simplicity budget (per example)
- ≤ 8 TS source files (excluding migrations).
- Deps: ORM/client + `@cipherstash/stack` + dev tooling (ts-node or tsx). Nothing else unless required by the stack.
- One `.env.example`; use `dotenv`. No layered config.

CODE STYLE
- Prefer plain functions & module-scoped connections (no classes/singletons).
- Linear demo flow (create → read → query). No future-proof abstractions.
- TypeORM: CJS + decorators for friction-free DX:
  `"module": "commonjs"`, `"moduleResolution": "node"`, `"experimentalDecorators": true`, `"emitDecoratorMetadata": true`, `"esModuleInterop": true`, `"strict": true`, `"sourceMap": true`.
- Prisma/Drizzle/Raw SQL: choose CJS or ESM for least friction; document choice in one sentence.

REQUIRED DX & SCRIPTS (per example)
- Node ≥ 22. Use local binaries (no global installs).
- Docker Compose for Postgres (shared at root or per example).
- Scripts:
  - `dev:db` → `docker compose up -d db`
  - `db:migrate` → run stack migrations
  - `db:reset` → drop + recreate + migrate (local only)
  - `seed` → seed sensible data
  - `demo` → prints proof of encryption & queries
  - `typecheck` → `tsc --noEmit`
- `.env.example` includes DB vars and the **exact** CipherStash env names (do not invent):
  `CS_WORKSPACE_CRN`, `CS_CLIENT_ID`, `CS_CLIENT_KEY`, `CS_CLIENT_ACCESS_KEY`

PROJECT LAYOUT (monorepo, minimal)
- Root:
  - `README.md` (links to each example, shared prerequisites)
  - `docker-compose.yml` (Postgres)
- Per example:
  - `README.md` (with AI banner)
  - `package.json`, `tsconfig.json`
  - Stack config (`schema.prisma`, `data-source.ts`, drizzle config, or SQL migrations)
  - Minimal source only (e.g., `src/db.ts`, `src/demo.ts`, optional `src/server.ts`)
  - `migrations/*`
  - `.env.example`

README REQUIREMENTS (every example)
- AI banner (exact text) at the very top with {{BOOK_CHAT_URL}}.
- 90-second Quickstart (copy/paste only).
- "What this shows" checklist (encrypted fields, CRUD, query).
- "How encryption works here" (short, accurate, tied to CipherStash Stack).
- Config notes for the stack (e.g., why CJS for TypeORM).
- Troubleshooting (ESM/CJS, ts-node/tsx, migration pitfalls, native module externalization).
- `@ref` links to https://cipherstash.com/docs + the repo README.

DELIVERABLES (return in one message/PR)
- Root `README.md` + `docker-compose.yml`.
- Each example's full files + `.env.example`.
- Root & per-example repo trees.
- Final validation checklist.

ACCEPTANCE TESTS (per example)
1) `npm i && npm run dev:db && cp .env.example .env && npm run db:migrate && npm run seed && npm run demo`
   → creates rows with encrypted fields; readback shows decrypted values; a query returns expected rows.
2) Re-running `demo` is idempotent (or intentionally reseeds) without unhandled errors.
3) `npm run typecheck` passes.
4) No ESM/CJS mismatch under Node 22.
5) Minimality: respects Simplicity Budget; ≤ 1 non-essential dependency.
6) Directness: demo code calls the ORM/client directly.
7) README: no banned words/emojis; Quickstart works verbatim on a clean machine.

FAIL-THE-BUILD SELF-REVIEW
- Can a file be deleted without losing the lesson? Delete it.
- Any re-export-only files? Delete them.
- Any unnecessary dependency? Remove it.
- Any README fluff/exclamations/hype? Remove them.
- Do commands run exactly as written? Fix until they do.

OUTPUT FORMAT
1) Short plan (≤10 lines).
2) Root repo `tree`.
3) Per-example `tree`.
4) Full files (separate code blocks).
5) Final validation checklist with ✅/❌ and exact fixes for ❌.

VARIABLES TO FILL BEFORE RUN
- {{BOOK_CHAT_URL}} = your booking link
- {{STACKS}} = list of stacks to generate
