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

## Dated AI-use log

Dates use the project-local calendar. Entries marked **approximate** are based on repository commit dates and/or the user's later description of the work; the exact original prompt timestamp was not preserved. Test results are stated only where they are present in the conversation or recorded run output.

### 1. 2026-10-19 (approximate) — Authorization and audit coverage

- **Goal:** Check TrustVault's challenge implementation for server-side role and document-permission enforcement, direct-ID access, unauthorized file access, and audit behavior.
- **AI-assisted work:** Inspected the existing FastAPI authorization paths and expanded the security tests for cross-user access, document operations, role escalation, private file routes, and denied-access auditing.
- **Check:** These regression cases are present in `trustvault/tests/test_security.py`. The exact test output for the 2026-10-19 commit is not preserved, so no result is attributed to that date.
- **Mistake or correction:** A later audit found a denied-download event was labeled `read`; that defect and its correction are recorded in entry 2.

### 2. 2026-10-19 (approximate; the user referred to this work as “yesterday” on 2026-10-20) — Denied-download audit event and production seeding

- **Goal:** Ensure denied downloads are recorded as download attempts and that demo accounts are not seeded by default in production.
- **AI-assisted work:** Changed the denied-download action to `download` and made production demo seeding default off; added/updated regression checks for the event and seed behavior.
- **Check:** The current cross-owner test checks the denied download's attempted action, and `test_demo_seed_is_on_by_default_only_outside_production` checks the production default. The historical first expanded run had 1 failure in 12 tests due to the mislabeled event; after correction the 12-test run passed. The exact dates of those two runs are unverified.
- **Mistake or correction:** The first implementation recorded the denied download as `read`. The failing regression test exposed it; the action was corrected to `download`.

### 3. 2026-10-20 — Server-side logout revocation

- **Goal:** Make logout invalidate a copied session immediately on the server, not just clear the current browser's cookie.
- **AI-assisted work:** Inspected the cookie-based authentication path, then added a `UserSession` record containing a hash of a random token, user ID, expiry, and revocation time. Authenticated requests now check that record; logout commits revocation before clearing the cookie.
- **Check:** Before the change, `python -m pytest -q` returned 14 passed with one deprecation warning. Afterwards, `test_logout_immediately_revokes_a_copied_session_cookie` replays the captured cookie and verifies the protected request receives 401 and the session is revoked.
- **Mistake or correction:** The prior implementation treated clearing the signed cookie as logout; it did not invalidate an already copied cookie. The server-side record corrected that gap.

### 4. 2026-10-20 — Session rotation, expiry, and deactivation

- **Goal:** Prevent an older cookie from remaining usable after a successful re-login, session expiry, or administrator deactivation.
- **AI-assisted work:** Added revocation of the current server session on successful re-login, checked server-side expiry on each authenticated request, and revoked all of a deactivated user's sessions.
- **Check:** Added `test_successful_login_revokes_the_previous_server_session`, `test_expired_server_session_is_rejected_even_with_a_valid_cookie`, and `test_deactivating_user_revokes_all_server_sessions`. All passed in the final 18-test run.
- **Mistake or correction:** No failing test or separate implementation mistake was observed for these three paths; the tests were added as regression coverage.

### 5. 2026-10-20 — Audit attribution for revoked-session attempts

- **Goal:** Keep a denied request auditable when a revoked cookie is rejected.
- **AI-assisted work:** During middleware inspection, found that clearing the invalid request session also removed its user ID before the 401 audit event was written. Preserved the actor ID only when the server-side session record matched that user, then used it for the denial audit.
- **Check:** `test_logout_immediately_revokes_a_copied_session_cookie` asserts that replay is rejected with 401 and that the denied-access audit event records the correct actor. The assertion passed in the final run.
- **Mistake or correction:** The prior denial middleware could lose actor attribution after the session was cleared. This was corrected without trusting an unmatched cookie user ID.

### 6. 2026-10-20 — Submission-readiness audit

- **Goal:** Check the required submission materials without changing application code or publishing.
- **AI-assisted work:** Checked the test command, security and setup documentation, prompt dates, demo-media files, and local Git status/history/remote configuration.
- **Check:** The audit found no dated entries in this file, no TrustVault demo plan or recording, and no verified public Git remote. The local history and working-tree status were inspected; no deployment or test run was initiated for this documentation audit.
- **Mistake or correction:** The existing error/correction table was useful but did not satisfy the dated AI-use-log requirement. This dated section was added while retaining the existing table and its claims.
