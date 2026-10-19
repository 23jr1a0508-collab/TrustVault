# Build brief

TrustVault was created from a hiring-challenge brief for a secure document-sharing application. The product is intended for a hiring team that needs owners to share files with named reviewers while preserving a useful audit trail.

## Product requirements represented in the implementation

- Python, FastAPI, SQLAlchemy, SQLite for development, HTML/CSS/JavaScript, and Pytest
- Administrator, owner, and viewer roles
- Login, dashboard, document search/upload/detail, permissions, audit logs, admin overview, and user management
- Private file storage, upload validation, server-side authorization, CSRF-protected sessions, and audit logging
- Seed data, sample accounts, API docs, setup instructions, and security documentation

## Security design decisions

- Signed session cookies are used rather than browser-stored bearer tokens.
- Passwords are hashed with Argon2.
- Access is checked on the server for each document operation; inaccessible IDs return the same 404 response.
- Edit permission does not imply delete permission.
- The audit history is hash-linked to detect ordinary changes; it is not described as immutable against database administrators.
- Production use disables demo seeding and requires deployment-managed secrets.

## Explicit limits

The implementation is a seven-day challenge baseline. It does not provide malware scanning, distributed audit anchoring, multi-instance SQLite coordination, or public-account rate limiting. Those limits are listed in `THREATS.md`.
