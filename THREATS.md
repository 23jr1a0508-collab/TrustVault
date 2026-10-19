# TrustVault security notes

## Assets and trust boundaries

- Uploaded document contents and original filenames
- User credentials, signed session cookies, and role/permission records
- Audit history and integrity hashes
- SQLite database and the private upload directory
- Browser-to-FastAPI requests across the same origin

The browser is untrusted. Every protected operation is authorized by the API, regardless of what controls the UI shows. Uploaded files are stored in `trustvault/data/private_files/`, not in the mounted static directory; responses never disclose that storage path.

## Controls implemented

| Threat | Control |
| --- | --- |
| Password disclosure or weak storage | Argon2 password hashes; passwords are never returned by an API. |
| Session theft or tampering | Signed, HttpOnly session cookie; eight-hour expiry; `SameSite=Lax`; secure-only cookies in production. |
| Cross-site request forgery | Session-bound CSRF token required in `X-CSRF-Token` for authenticated mutations. |
| IDOR and role escalation | Server-side role, owner, and per-document permission checks on every protected route; inaccessible document IDs return 404. |
| Unauthorized download | Same access check as document read, followed by a private-file response and no-store cache header. |
| Permission revocation delay | Permissions are read from the database on each request; no authorization cache is used. |
| Path traversal | Client filenames are never used as storage paths; storage names are random UUIDs; resolved path must remain inside the private directory. |
| Extension/content mismatch | Allowlist plus magic-byte checks for PDF/PNG/JPEG; UTF-8 checks for text; OOXML ZIP structure checks for DOCX/XLSX. |
| Oversized upload | Read limit of 10 MiB plus one byte; reject files above 10 MiB. |
| Browser MIME confusion / framing | `nosniff`, CSP, frame denial, and restrictive referrer/permissions headers. |
| Audit record changes | Each event hashes its canonical content and the preceding event hash; administrator endpoint verifies the chain. |

## Audit integrity limits

The hash chain makes accidental edits, missing middle records, and reordering detectable when the remaining chain is checked. It is not a cryptographic signature backed by a separately protected key. An attacker with write access to the SQLite database can rewrite rows and recompute the entire chain; an attacker with filesystem access can also delete or replace the database. The in-process lock serializes writes within one application process only.

For production audit guarantees, send events to a separately administered append-only/WORM system or remote audit service, protect and rotate signing keys outside the database, alert on failed integrity checks, and back up the database and files independently.

## Known limitations and operational safeguards

- Demo accounts and their documented passwords are intentionally public for local evaluation. Disable demo seeding and bootstrap a unique administrator before publishing.
- SQLite and local files are for development/single-instance demonstrations. Multi-instance deployments need a production database and private object storage with backups.
- Upload validation checks format structure, not malware. Do not open untrusted documents on privileged workstations; add antivirus/content-disarm scanning before production use.
- Authentication has no rate limiter or account lockout in this challenge implementation. Add provider-backed throttling before public exposure.
- Administrators are trusted to access all documents and user records. Admin actions remain in the audit log.
- HTTPS termination and secret management are deployment responsibilities. Set `SESSION_SECRET` through the platform's secret manager; never commit it.
- User deactivation prevents future authentication and invalidates their session on the next request. Audit records are retained; no user or document is hard-deleted through user management.

## Challenge scope

This is a hiring-challenge implementation, not a compliance certification or a substitute for a professional security review. `PROMPTS.md` records the high-level build brief; see `tests/` for executable security behavior.
