# TrustVault

TrustVault is a full-stack document-sharing application for a hiring team. Owners upload private files and grant named users read or edit access. The server checks access on every protected document request, and significant actions are recorded in a hash-linked audit log.
## Demo Access

**Live Application:** https://trustvault-jnmc.onrender.com

### Demo Accounts
| Role | Username | Password |
|---|---|---|
| Admin | `admin` | `TvAdmin#2026!SecureK9` |
| Document Owner | `owner` | `VaultOwner!26` |
| Viewer | `viewer` | `VaultViewer!26` |
## Demo Video

Watch the TrustVault project demonstration:

[**Watch the 5-minute demo video on Google Drive**](https://drive.google.com/file/d/1w-3WBR9ej2arUrqVeXvfFjtMtiPbT-t9/view?usp=sharing)


Sign in using the live evaluation accounts listed in the Demo Accounts section below.
## Features

- Administrator, document owner, and viewer roles
- Uploads stored outside the public static directory
- Server-side read, download, edit, delete, and permission checks
- Extension, size, and file-content validation for uploads
- Named-user read/edit grants with immediate revocation
- Server-checked session records; logout, successful re-login, expiry, and account deactivation invalidate old cookies
- Search by document name, owner, category, and date
- Audit records for uploads, downloads, updates, deletions, permission changes, authentication, and denied access
- User administration, API documentation, sample accounts, and security tests

## Run locally

Requirements: Python 3.11 or newer.

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
export SESSION_SECRET="$(python -c 'import secrets; print(secrets.token_urlsafe(48))')"
python -m uvicorn trustvault.app.main:app --host 0.0.0.0 --port 8000
```

Open the app at port 8000. API documentation is at `/trustvault-api/docs`; the OpenAPI schema is at `/trustvault-api/openapi.json`.

The first development run creates a SQLite database at `trustvault/data/trustvault.db`, private files at `trustvault/data/private_files/`, and three safe demonstration accounts:

| Role | Username | Demo password |
| --- | --- | --- |
| Administrator | `admin` | `VaultAdmin!26` |
| Document owner | `owner` | `VaultOwner!26` |
| Viewer | `viewer` | `VaultViewer!26` |

These public demo credentials are for local evaluation only. Do not expose a deployment using them. Demo seeding defaults off when `TRUSTVAULT_ENV=production`; keep `TRUSTVAULT_DEMO_SEED=0`, set a unique `SESSION_SECRET`, and create the first administrator using `python -m trustvault.app.seed_admin`. The seed command asks for the password without echoing it.

## Replit

The registered app preview runs FastAPI at the root of the TrustVault app. The standalone local command uses port 8000; Replit assigns the preview service its own port. Set `SESSION_SECRET` in Replit Secrets before publishing. Production uses secure-only session cookies and disables demo seeding. Create the first administrator after publishing with `python -m trustvault.app.seed_admin`.

SQLite and local upload storage are intended for development and a single-instance demonstration. For a multi-instance production deployment, use a managed database and private object storage with backups and access controls. Do not put uploaded files in the static directory.

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `SESSION_SECRET` | Random per process in development | Signs the session cookie. Required in production. |
| `TRUSTVAULT_ENV` | `development` | Set to `production` to require the session secret and secure cookies. |
| `TRUSTVAULT_DATABASE_URL` | SQLite file under `trustvault/data/` | SQLAlchemy database URL. |
| `TRUSTVAULT_DEMO_SEED` | `1` in development; `0` by default in production | Set to `0` to skip sample users and documents. |
| `TRUSTVAULT_ADMIN_DEMO_PASSWORD` | `VaultAdmin!26` | Optional local demo admin password override. |
| `TRUSTVAULT_OWNER_DEMO_PASSWORD` | `VaultOwner!26` | Optional local demo owner password override. |
| `TRUSTVAULT_VIEWER_DEMO_PASSWORD` | `VaultViewer!26` | Optional local demo viewer password override. |

## Tests

```bash
python -m pytest -q
```

The tests exercise login, role checks, cross-user and direct-ID attacks, unauthorized downloads, edits and deletes, immediate permission revocation, privilege-escalation attempts, direct file URLs, denied-access auditing, search scoping, dashboard visibility, production seed defaults, read-only audit routes, and audit-chain limits. Do not treat the hash chain as a substitute for an external append-only audit service.

## Implementation map

- `trustvault/app/main.py` — FastAPI app, signed session-cookie middleware, security headers, `/`, `/healthz`, and the public static mount.
- `trustvault/app/security.py` — Argon2 password hashing, server-side session issuance/revocation checks, authenticated-user and CSRF checks, document authorization, and hash-linked audit writes/verification.
- `trustvault/app/api.py` — authentication, document, permission, user, audit, search, and dashboard endpoints; upload validation and authorized downloads.
- `trustvault/app/models.py` — user, revocable session, document, document-permission, and audit-log records.
- `trustvault/app/database.py` — SQLite development database, private file directory, schema creation, and sample seeding.
- `trustvault/app/static/js/app.js`, `trustvault/app/static/css/app.css`, `trustvault/app/templates/index.html` — browser interface and API calls.
- `trustvault/tests/test_security.py` — executable session lifecycle, authorization, upload, audit, and production-seeding checks.

## API and role map

All TrustVault API routes use the actual `/trustvault-api` prefix. The separate workspace API server owns `/api`; the test client rewrites its short `/api/...` test paths to the TrustVault prefix. The registered FastAPI app does not mount TrustVault endpoints at `/api`.

| Method and endpoint | Access enforced by the server |
| --- | --- |
| `POST /trustvault-api/auth/login` | Public; invalid credentials receive a generic response and are audited. |
| `GET /trustvault-api/session` | Public; returns the signed-in user or `null`. |
| `POST /trustvault-api/auth/logout` | Authenticated session and CSRF token; revokes the server-side session before clearing the cookie. |
| `GET /trustvault-api/dashboard` | Authenticated; document statistics and recent activity are scoped by role and access. |
| `GET /trustvault-api/documents` | Authenticated; searches by `q`, `owner`, `category`, `from`, and `to`, limited to visible documents. |
| `POST /trustvault-api/documents` | Owner or administrator plus CSRF token. |
| `GET /trustvault-api/documents/{document_id}` | Administrator, owner, or explicitly shared reader/editor. |
| `GET /trustvault-api/documents/{document_id}/download` | Same document-level read check; successful downloads are audited. |
| `PATCH /trustvault-api/documents/{document_id}` | Administrator, owner, or user with an `edit` grant, plus CSRF token. |
| `DELETE /trustvault-api/documents/{document_id}` | Administrator or document owner, plus CSRF token; an `edit` grant alone is insufficient. |
| `GET /trustvault-api/documents/{document_id}/permissions` | Administrator or document owner. |
| `PUT /trustvault-api/documents/{document_id}/permissions` | Administrator or document owner plus CSRF token; assigns `read` or `edit` to a named active user. |
| `DELETE /trustvault-api/documents/{document_id}/permissions/{target_user_id}` | Administrator or document owner plus CSRF token. |
| `GET /trustvault-api/users` | Administrator; owners receive only active non-administrator recipients; viewers are denied. |
| `POST /trustvault-api/users` and `DELETE /trustvault-api/users/{target_user_id}` | Administrator plus CSRF token. |
| `GET /trustvault-api/audit-logs` | Authenticated; administrators see all records, other roles are scoped to their activity and visible documents. |
| `GET /trustvault-api/audit-logs/integrity` | Administrator only. No audit-log create, update, or delete endpoint is registered. |

API documentation is at `/trustvault-api/docs`; the OpenAPI schema is at `/trustvault-api/openapi.json`.

## Permission model

- **Administrator:** user administration, audit-log oversight, and access to all documents.
- **Owner:** upload and manage owned documents; grant or revoke read/edit access for named users.
- **Viewer:** access only documents explicitly shared with them.
- **Read grant:** view metadata and download.
- **Edit grant:** read, download, and update document name/category; it does not grant delete rights.
- **Delete:** document owner or administrator only.

Every document operation is authorized on the server. Hiding a button in the browser is not treated as an access control.
