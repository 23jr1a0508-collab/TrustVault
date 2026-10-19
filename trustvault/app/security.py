from __future__ import annotations

import hashlib
import json
import secrets
import threading
from datetime import datetime, timezone
from typing import Any

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from fastapi import Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from .database import get_db
from .models import AuditLog, Document, DocumentPermission, User


password_hasher = PasswordHasher()
_audit_lock = threading.RLock()
GENESIS_HASH = "0" * 64


def hash_password(password: str) -> str:
    return password_hasher.hash(password)


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        return password_hasher.verify(stored_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def public_user(user: User) -> dict[str, Any]:
    return {
        "id": user.id,
        "username": user.username,
        "display_name": user.display_name,
        "role": user.role,
        "active": user.active,
    }


def _audit_payload(
    event_id: int,
    actor_id: int | None,
    action: str,
    target: str,
    metadata_json: str,
    created_at: datetime,
) -> str:
    normalized_created_at = (
        created_at.replace(tzinfo=timezone.utc)
        if created_at.tzinfo is None
        else created_at.astimezone(timezone.utc)
    )
    return json.dumps(
        {
            "id": event_id,
            "actor_id": actor_id,
            "action": action,
            "target": target,
            "metadata_json": metadata_json,
            "created_at": normalized_created_at.isoformat(),
        },
        sort_keys=True,
        separators=(",", ":"),
    )


def record_audit(
    db: Session,
    actor_id: int | None,
    action: str,
    target: str,
    metadata: dict[str, Any] | None = None,
) -> AuditLog:
    """Append and commit one hash-linked audit record.

    The in-process lock serializes writes from this worker. It is not a defense
    against a database administrator who can rewrite the database and the full
    chain; see THREATS.md.
    """
    metadata_json = json.dumps(metadata or {}, sort_keys=True, separators=(",", ":"))
    with _audit_lock:
        previous = db.scalar(select(AuditLog).order_by(AuditLog.id.desc()).limit(1))
        event = AuditLog(
            actor_id=actor_id,
            action=action,
            target=target,
            metadata_json=metadata_json,
            created_at=datetime.now(timezone.utc),
            previous_hash=previous.integrity_hash if previous else GENESIS_HASH,
            integrity_hash="",
        )
        db.add(event)
        try:
            db.flush()
            payload = _audit_payload(
                event.id,
                event.actor_id,
                event.action,
                event.target,
                event.metadata_json,
                event.created_at,
            )
            event.integrity_hash = hashlib.sha256(
                f"{event.previous_hash}:{payload}".encode("utf-8")
            ).hexdigest()
            db.commit()
            return event
        except Exception:
            db.rollback()
            raise


def audit_chain_status(db: Session) -> dict[str, Any]:
    rows = db.scalars(select(AuditLog).order_by(AuditLog.id.asc())).all()
    previous_hash = GENESIS_HASH
    for event in rows:
        payload = _audit_payload(
            event.id,
            event.actor_id,
            event.action,
            event.target,
            event.metadata_json,
            event.created_at,
        )
        expected_hash = hashlib.sha256(f"{previous_hash}:{payload}".encode("utf-8")).hexdigest()
        if event.previous_hash != previous_hash or event.integrity_hash != expected_hash:
            return {"valid": False, "checked": len(rows), "broken_at": event.id}
        previous_hash = event.integrity_hash
    return {"valid": True, "checked": len(rows), "broken_at": None}


def require_user(request: Request, db: Session = Depends(get_db)) -> User:
    user_id = request.session.get("user_id")
    if not isinstance(user_id, int):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Sign in to continue.")
    user = db.get(User, user_id)
    if not user or not user.active:
        request.session.clear()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Your session is no longer active.")
    return user


def require_csrf(
    request: Request,
    user: User = Depends(require_user),
) -> User:
    expected = request.session.get("csrf_token")
    supplied = request.headers.get("X-CSRF-Token", "")
    if not expected or not supplied or not secrets.compare_digest(str(expected), supplied):
        raise HTTPException(status_code=403, detail="Your session expired. Refresh the page and try again.")
    return user


def get_document_or_deny(
    db: Session,
    document_id: int,
    user: User,
    action: str,
) -> tuple[Document, str]:
    document = db.get(Document, document_id)
    permission = db.scalar(
        select(DocumentPermission).where(
            DocumentPermission.document_id == document_id,
            DocumentPermission.user_id == user.id,
        )
    )
    if user.role == "administrator":
        level = "admin"
    elif document and document.owner_id == user.id:
        level = "owner"
    elif permission:
        level = permission.level
    else:
        level = ""
    if not document or not level or (action == "edit" and level not in {"owner", "admin", "edit"}):
        record_audit(
            db,
            user.id,
            "denied_access",
            f"document:{document_id}",
            {"attempted_action": action},
        )
        raise HTTPException(status_code=404, detail="Document not found or access is not permitted.")
    return document, level
