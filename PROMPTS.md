# Build brief

TrustVault was created from a hiring-challenge brief for a secure document-sharing application. The product is intended for a hiring team that needs owners to share files with named reviewers while preserving a useful audit trail.

## Product requirements represented in the implementation

- Python, FastAPI, SQLAlchemy, SQLite for development, HTML/CSS/JavaScript, and Pytest
- Administrator, owner, and viewer roles
- Login, dashboard, document search/upload/detail, permissions, audit logs, admin overview, and user management
- Private file storage, upload validation, server-side authorization, CSRF-protected sessions, and audit logging
- Seed data, sample accounts, API docs, setup instructions, and security documentation

## Security design decisions

- A signed HttpOnly cookie carries a random session token; only its SHA-256 hash is stored in the database and checked on each authenticated request.
- Logout, successful re-login, expiry, and administrator deactivation invalidate the corresponding server-side session records.
- Passwords are hashed with Argon2.
- Access is checked on the server for each document operation; inaccessible IDs return the same 404 response.
- Edit permission does not imply delete permission.
- The audit history is hash-linked to detect ordinary changes; it is not described as immutable against database administrators.
- Production use disables demo seeding and requires deployment-managed secrets.

## Explicit limits

The implementation is a seven-day challenge baseline. It does not provide malware scanning, distributed audit anchoring, multi-instance SQLite coordination, or public-account rate limiting. Those limits are listed in `THREATS.md`.

## Actual implementation errors and corrections

This section records issues observed while building and auditing this project; it is not a list of hypothetical risks.

| Observed error | Correction made |
| --- | --- |
| The first audit-chain test failed because SQLite returned a timezone-naive timestamp while the hash payload used a timezone-aware value. | Normalize timestamps to UTC before canonicalizing the audit hash. |
| The initial FastAPI workflow was not connected to the root app preview, and the first registered artifact workflow failed with `ModuleNotFoundError: No module named 'trustvault'` because it started in the artifact subdirectory. | Register FastAPI as the TrustVault root app and launch from the workspace root with `cd ../..`. |
| TrustVault initially used `/api`, which was already routed to the separate workspace API Server. | Move TrustVault's actual API and docs to `/trustvault-api`; add a test confirming the real app prefix. |
| The first owner permission screen could not populate recipients because `/users` was administrator-only. | Permit owners to list active non-administrator recipients while keeping user creation/deactivation administrator-only. |
| The anonymous session check returned 401, which created a misleading browser error and denied-access event during normal login-page loading. | Return a nullable session response and let the UI render the login form for anonymous visitors. |
| Logout only cleared the signed cookie in the browser; a copied cookie remained valid on the server until its expiry. | Add a server-side session record containing only a token hash; validate it on every authenticated request and revoke it before returning from logout. Also revoke prior sessions on re-login and all sessions on account deactivation. |
| The browser's CSP blocked the external Google Fonts stylesheet. | Remove the external font import and use a system font stack. |
| The first new cross-owner audit test failed: access was denied, but a denied download was recorded as `read`. | Record the attempted action as `download`; the expanded tests then passed. |
| Demo seeding defaulted on even when `TRUSTVAULT_ENV=production` and `TRUSTVAULT_DEMO_SEED` was omitted. | Default seeding off in production and add a test for development-versus-production defaults. |
| `uv export --locked` could not export because the existing `uv.lock` needed an update. | Leave the project lock unchanged; resolve `requirements.txt` to a temporary file with `uv pip compile` and run the Python dependency audit against that temporary resolution. |

The first expanded test run had 1 failure in 12 tests because of the denied-download audit label. After that correction the 12-test suite passed. The prior audit suite reached 14 passing tests. Session-replay, session-rotation, session-expiry, and deactivation-revocation regression tests were then added; the latest run passed all 18 tests with one Starlette/httpx deprecation warning.
