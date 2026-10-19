# TrustVault

TrustVault lets hiring teams share private candidate documents with named reviewers and inspect a hash-linked audit trail.

_Replace the heading above with the project's name, and this line with one sentence describing what this app does for users._

## Run & Operate

- The `artifacts/trustvault: web` workflow runs the FastAPI app and serves the HTML/CSS/JavaScript UI.
- `python -m uvicorn trustvault.app.main:app --host 0.0.0.0 --port 8000` — run locally.
- `python -m pytest -q` — run TrustVault security tests.
- `pnpm run typecheck` — full typecheck across all packages
- `pnpm run build` — typecheck + build all packages
- `pnpm --filter @workspace/api-spec run codegen` — regenerate API hooks and Zod schemas from the OpenAPI spec
- `pnpm --filter @workspace/db run push` — push DB schema changes (dev only)
- Required for production: `SESSION_SECRET`

## Stack

- TrustVault: Python, FastAPI, SQLAlchemy, SQLite, Argon2, HTML/CSS/JavaScript, Pytest
- Workspace services: pnpm, TypeScript, Express API Server, PostgreSQL/Drizzle libraries

## Where things live

- `trustvault/app/api.py` — authenticated API, permission checks, upload validation, audit records.
- `trustvault/app/models.py` and `database.py` — SQLAlchemy models, SQLite setup, and demo seeding.
- `trustvault/app/static/` and `templates/index.html` — browser interface.
- `trustvault/tests/` — security and access-control tests.
- `README.md` — run, account, and deployment instructions.
- `THREATS.md` — security assumptions and limitations.

## Architecture decisions

- The API uses `/trustvault-api` because the pre-existing API Server already owns `/api`.
- Uploaded bytes are private files; SQLite stores only metadata and generated storage names.
- The audit hash chain detects ordinary row edits and reordering but is not immutable against a database administrator.
- Local SQLite and file storage are challenge/demo choices, not multi-instance production storage.

## Product

- Administrators manage users and review activity; owners upload and share documents; viewers access only documents explicitly shared with them.
- This is a fresher hiring challenge; keep all demo documents synthetic and disclose production-storage limitations.

## User preferences

- The requested implementation stack is FastAPI, SQLite for development, SQLAlchemy, vanilla HTML/CSS/JavaScript, and Pytest.

## Gotchas

- The demo accounts are public sample accounts; disable demo seeding before publishing with real documents.
- The production artifact disables demo seeding; bootstrap an administrator after publishing.

## Pointers

- See the `pnpm-workspace` skill for workspace structure, TypeScript setup, and package details
