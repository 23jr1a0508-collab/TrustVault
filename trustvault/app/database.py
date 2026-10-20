from __future__ import annotations

import os
from collections.abc import Generator
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import create_engine, select
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = PROJECT_ROOT / "data"
PRIVATE_FILES_DIR = DATA_DIR / "private_files"
DATA_DIR.mkdir(parents=True, exist_ok=True)
PRIVATE_FILES_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)


class Base(DeclarativeBase):
    pass


def _make_engine(database_url: str):
    connect_args = {"check_same_thread": False} if database_url.startswith("sqlite") else {}
    return create_engine(database_url, connect_args=connect_args, pool_pre_ping=True)


DATABASE_URL = os.getenv(
    "TRUSTVAULT_DATABASE_URL",
    f"sqlite:///{(DATA_DIR / 'trustvault.db').as_posix()}",
)
engine = _make_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def configure_database(database_url: str) -> None:
    """Replace the engine, primarily for isolated tests."""
    global engine
    engine.dispose()
    engine = _make_engine(database_url)
    SessionLocal.configure(bind=engine)


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def initialize_database() -> None:
    from .models import AuditLog, Document, DocumentPermission, User

    Base.metadata.create_all(bind=engine)
    seed_default = (
        "0"
        if os.getenv("TRUSTVAULT_ENV", "development").strip().lower() == "production"
        else "1"
    )
    if os.getenv("TRUSTVAULT_DEMO_SEED", seed_default).strip().lower() in {"0", "false", "no"}:
        return

    with SessionLocal() as db:
        if db.scalar(select(User.id).limit(1)) is not None:
            return

        from .security import hash_password, record_audit

        demo_passwords = {
            "admin": os.getenv("TRUSTVAULT_ADMIN_DEMO_PASSWORD", "VaultAdmin!26"),
            "owner": os.getenv("TRUSTVAULT_OWNER_DEMO_PASSWORD", "VaultOwner!26"),
            "viewer": os.getenv("TRUSTVAULT_VIEWER_DEMO_PASSWORD", "VaultViewer!26"),
        }
        admin = User(
            username="admin",
            display_name="Morgan Chen",
            password_hash=hash_password(demo_passwords["admin"]),
            role="administrator",
        )
        owner = User(
            username="owner",
            display_name="Alex Rivera",
            password_hash=hash_password(demo_passwords["owner"]),
            role="owner",
        )
        viewer = User(
            username="viewer",
            display_name="Jordan Lee",
            password_hash=hash_password(demo_passwords["viewer"]),
            role="viewer",
        )
        db.add_all([admin, owner, viewer])
        db.flush()

        sample_documents = [
            Document(
                name="Candidate interview brief",
                original_filename="candidate-interview-brief.txt",
                category="Candidate files",
                stored_filename="demo-interview-brief.txt",
                content_type="text/plain; charset=utf-8",
                size=0,
                owner_id=owner.id,
            ),
            Document(
                name="Hiring panel notes",
                original_filename="hiring-panel-notes.txt",
                category="Interview notes",
                stored_filename="demo-panel-notes.txt",
                content_type="text/plain; charset=utf-8",
                size=0,
                owner_id=owner.id,
            ),
        ]
        db.add_all(sample_documents)
        db.flush()
        PRIVATE_FILES_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
        sample_text = {
            "demo-interview-brief.txt": (
                "TrustVault demo document\n\n"
                "This safe sample demonstrates named-user document sharing. "
                "It contains no real candidate information.\n"
            ),
            "demo-panel-notes.txt": (
                "Hiring panel notes — demo only\n\n"
                "Replace this sample with a real file using the upload flow. "
                "No personal information is included.\n"
            ),
        }
        for filename, content in sample_text.items():
            path = PRIVATE_FILES_DIR / filename
            path.write_text(content, encoding="utf-8")
            path.chmod(0o600)
        for doc, filename in zip(sample_documents, sample_text, strict=True):
            doc.size = (PRIVATE_FILES_DIR / filename).stat().st_size

        db.add(
            DocumentPermission(
                document_id=sample_documents[0].id,
                user_id=viewer.id,
                level="read",
                granted_by_id=owner.id,
            )
        )
        record_audit(
            db,
            owner.id,
            "document_upload",
            f"document:{sample_documents[0].id}",
            {"name": sample_documents[0].name, "category": sample_documents[0].category},
        )
        record_audit(
            db,
            owner.id,
            "document_upload",
            f"document:{sample_documents[1].id}",
            {"name": sample_documents[1].name, "category": sample_documents[1].category},
        )
        record_audit(
            db,
            owner.id,
            "permission_grant",
            f"document:{sample_documents[0].id}",
            {"user_id": viewer.id, "username": viewer.username, "level": "read"},
        )
