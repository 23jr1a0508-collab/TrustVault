# TrustVault security notes

## Assets and trust boundaries

- Uploaded document contents and original filenames
- User credentials, signed session cookies, and role/permission records
- Audit history and integrity hashes
- SQLite database and the private upload directory
- Browser-to-FastAPI requests across the same origin

The browser is untrusted. Every protected operation is authorized by the API, regardless of what controls the UI shows. Uploaded files are stored in `trustvault/data/private_files/`, not in the mounted static directory. FastAPI mounts only `trustvault/app/static/`; document bytes are returned only through the authenticated download route.

## Controls implemented

| Threat | Control |
| --- | --- |
| Password disclosure or weak storage | Argon2 password hashes; passwords are never returned by an API. |
| Session theft or tampering | Signed, HttpOnly cookie with `SameSite=Lax`; the cookie contains a random session token whose SHA-256 hash is stored server-side. The server checks that record, revocation state, user, and eight-hour expiry on every authenticated request; production cookies are secure-only. |
| Reuse of a copied cookie after logout, re-login, or account deactivation | Logout revokes the database session before clearing the browser cookie. Successful re-login revokes the previous cookie's session; administrator deactivation revokes all the target user's sessions. Tests replay captured cookies after each action. |
| Cross-site request forgery | Session-bound CSRF token required in `X-CSRF-Token` for authenticated mutations. |
| IDOR and role escalation | Server-side role, owner, and per-document permission checks on every protected route; inaccessible document IDs return 404. |
| Unauthorized download | Same access check as document read, followed by a private-file response and no-store cache header. |
| Permission revocation delay | Permissions are read from the database on each request; no authorization cache is used. |
| Path traversal | Client filenames are never used as storage paths; storage names are random UUIDs; resolved path must remain inside the private directory. |
| Extension/content mismatch | Allowlist plus basic signature checks for PDF/PNG/JPEG; UTF-8 checks for text; OOXML ZIP structure checks for DOCX/XLSX. These checks do not prove full file validity. |
| Oversized upload | Read limit of 10 MiB plus one byte; reject files above 10 MiB. |
| Browser MIME confusion / framing | `nosniff`, CSP, frame denial, and restrictive referrer/permissions headers. |
| Audit API tampering | The API exposes read endpoints only; there are no audit-log create, update, or delete routes. Tests send write methods and verify they are rejected. |
| Audit row edits or middle-chain changes | Each event hashes its canonical content and the preceding event hash; the administrator integrity endpoint verifies the chain. A test confirms an in-place row edit is detected. |

## Audit integrity limits

The hash chain makes ordinary row edits, missing middle records, and reordering detectable when the remaining chain is checked. It has no separately stored trusted head: deleting the final record or a suffix leaves a valid prefix, and a database writer can rewrite rows and recompute the entire chain. A passing integrity check therefore does not prove that the log was never truncated or rewritten by someone with database access. The in-process lock serializes writes within one application process only.

For production audit guarantees, send events to a separately administered append-only/WORM system or remote audit service, protect and rotate signing keys outside the database, alert on failed integrity checks, and back up the database and files independently.

## Known limitations and operational safeguards

- Demo accounts and their documented passwords are intentionally public for local evaluation. Seeding defaults off in production; keep it off and bootstrap a unique administrator before publishing.
- SQLite and local files are for development/single-instance demonstrations. Multi-instance deployments need a production database and private object storage with backups.
- Upload validation checks format structure, not malware. Do not open untrusted documents on privileged workstations; add antivirus/content-disarm scanning before production use.
- Authentication has no rate limiter or account lockout in this challenge implementation. Add provider-backed throttling before public exposure.
- Revoked and expired session rows are retained in SQLite; add a retention/cleanup policy before long-term production use.
- Administrators are trusted to access all documents and user records. Admin actions remain in the audit log.
- HTTPS termination and secret management are deployment responsibilities. Set `SESSION_SECRET` through the platform's secret manager; never commit it.
- User deactivation prevents future authentication and revokes that user's server-side sessions. Audit records are retained; no user or document is hard-deleted through user management.

## Challenge scope

This is a hiring-challenge implementation, not a compliance certification or a substitute for a professional security review. `PROMPTS.md` records the high-level build brief; see `tests/` for executable security behavior.

## Verification performed

- `python -m pytest -vv`: 18 passed, with one Starlette/httpx deprecation warning. The warning is from FastAPI's TestClient compatibility path; it did not fail the suite.
- The Python SAST scan returned no findings.
- `pip-audit` against a temporary resolution of the 9 direct requirements resolved 31 packages and reported no known vulnerabilities. This does not audit system packages or the separate pnpm workspace.
- The workspace-wide npm dependency scan reported 12 critical, 20 high, 10 moderate, and 2 low findings. It covers more than TrustVault: for example, `orval` is a dev dependency of `lib/api-spec`, while `proxy-addr` belongs to the separate Express API Server. These findings were not changed in this TrustVault-focused audit and require separate reachability triage.
- The HoundDog privacy scan failed with `HOUNDDOG_SCHEMA_MISMATCH`; it produced no usable result, so no clean HoundDog finding is claimed.
