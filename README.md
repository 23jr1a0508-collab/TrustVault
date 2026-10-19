# TrustVault

TrustVault is a full-stack document-sharing application for a hiring team. Owners upload private files and grant named users read or edit access. The server checks access on every protected document request, and significant actions are recorded in a hash-linked audit log.

## Features

- Administrator, document owner, and viewer roles
- Uploads stored outside the public static directory
- Server-side read, download, edit, delete, and permission checks
- Extension, size, and file-content validation for uploads
- Named-user read/edit grants with immediate revocation
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

The first run creates a SQLite database at `trustvault/data/trustvault.db`, private files at `trustvault/data/private_files/`, and three safe demonstration accounts:

| Role | Username | Demo password |
| --- | --- | --- |
| Administrator | `admin` | `VaultAdmin!26` |
| Document owner | `owner` | `VaultOwner!26` |
| Viewer | `viewer` | `VaultViewer!26` |

These public demo credentials are for local evaluation only. Do not expose a deployment using them. For production, set `TRUSTVAULT_DEMO_SEED=0`, set a unique `SESSION_SECRET`, and create the first administrator using `python -m trustvault.app.seed_admin`. The seed command asks for the password without echoing it.

## Replit

The registered app preview runs FastAPI at the root of the TrustVault app. The standalone local command uses port 8000; Replit assigns the preview service its own port. Set `SESSION_SECRET` in Replit Secrets before publishing. Production uses secure-only session cookies and disables demo seeding. Create the first administrator after publishing with `python -m trustvault.app.seed_admin`.

SQLite and local upload storage are intended for development and a single-instance demonstration. For a multi-instance production deployment, use a managed database and private object storage with backups and access controls. Do not put uploaded files in the static directory.

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `SESSION_SECRET` | Random per process in development | Signs the session cookie. Required in production. |
| `TRUSTVAULT_ENV` | `development` | Set to `production` to require the session secret and secure cookies. |
| `TRUSTVAULT_DATABASE_URL` | SQLite file under `trustvault/data/` | SQLAlchemy database URL. |
| `TRUSTVAULT_DEMO_SEED` | `1` | Set to `0` to skip sample users and documents. |
| `TRUSTVAULT_ADMIN_DEMO_PASSWORD` | `VaultAdmin!26` | Optional local demo admin password override. |
| `TRUSTVAULT_OWNER_DEMO_PASSWORD` | `VaultOwner!26` | Optional local demo owner password override. |
| `TRUSTVAULT_VIEWER_DEMO_PASSWORD` | `VaultViewer!26` | Optional local demo viewer password override. |

## Tests

```bash
python -m pytest -q
```

The tests exercise login, role checks, direct-ID attacks, unauthorized downloads, upload validation, read/edit/delete permissions, immediate permission revocation, denied-access auditing, and audit-chain integrity. Do not treat the hash chain as a substitute for an external append-only audit service.

## Permission model

- **Administrator:** user administration, audit-log oversight, and access to all documents.
- **Owner:** upload and manage owned documents; grant or revoke read/edit access for named users.
- **Viewer:** access only documents explicitly shared with them.
- **Read grant:** view metadata and download.
- **Edit grant:** read, download, and update document name/category; it does not grant delete rights.
- **Delete:** document owner or administrator only.

Every document operation is authorized on the server. Hiding a button in the browser is not treated as an access control.
