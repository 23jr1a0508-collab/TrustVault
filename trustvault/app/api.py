from __future__ import annotations

import io
import json
import re
import uuid
import zipfile
from datetime import date, datetime, time, timedelta, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Literal

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session, joinedload

from .database import PRIVATE_FILES_DIR, get_db
from .models import AuditLog, Document, DocumentPermission, User, utc_now
from .security import (
    audit_chain_status,
    get_document_or_deny,
    hash_password,
    get_session_user,
    issue_session,
    public_user,
    record_audit,
    require_csrf,
    require_user,
    revoke_session,
    revoke_user_sessions,
    verify_password,
)


router = APIRouter(prefix="/trustvault-api")
MAX_UPLOAD_BYTES = 10 * 1024 * 1024
MAX_DOC_NAME = 180
MAX_CATEGORY = 80
ALLOWED_EXTENSIONS = {".pdf", ".png", ".jpg", ".jpeg", ".txt", ".docx", ".xlsx"}
CONTENT_TYPES = {
    ".pdf": "application/pdf",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".txt": "text/plain; charset=utf-8",
    ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
}


class LoginInput(BaseModel):
    username: str = Field(min_length=1, max_length=80)
    password: str = Field(min_length=1, max_length=256)


class UserCreateInput(BaseModel):
    username: str = Field(min_length=3, max_length=80, pattern=r"^[A-Za-z0-9_.@+-]+$")
    display_name: str = Field(min_length=1, max_length=120)
    password: str = Field(min_length=12, max_length=256)
    role: Literal["administrator", "owner", "viewer"]


class DocumentUpdateInput(BaseModel):
    name: str = Field(min_length=1, max_length=MAX_DOC_NAME)
    category: str = Field(min_length=1, max_length=MAX_CATEGORY)


class PermissionInput(BaseModel):
    user_id: int
    level: Literal["read", "edit"]


def _user_or_404(db: Session, user_id: int) -> User:
    user = db.get(User, user_id)
    if not user or not user.active:
        raise HTTPException(status_code=404, detail="User not found.")
    return user


def _doc_permission(db: Session, document_id: int, user_id: int) -> DocumentPermission | None:
    return db.scalar(
        select(DocumentPermission).where(
            DocumentPermission.document_id == document_id,
            DocumentPermission.user_id == user_id,
        )
    )


def _document_json(db: Session, document: Document, viewer: User) -> dict[str, Any]:
    permission = _doc_permission(db, document.id, viewer.id)
    if viewer.role == "administrator":
        access = "admin"
    elif document.owner_id == viewer.id:
        access = "owner"
    else:
        access = permission.level if permission else None
    return {
        "id": document.id,
        "name": document.name,
        "category": document.category,
        "owner": {
            "id": document.owner.id,
            "display_name": document.owner.display_name,
            "username": document.owner.username,
        },
        "size": document.size,
        "content_type": document.content_type,
        "created_at": document.created_at.isoformat(),
        "updated_at": document.updated_at.isoformat(),
        "permission": access,
    }


def _audit_json(event: AuditLog) -> dict[str, Any]:
    actor = event.actor
    try:
        metadata = json.loads(event.metadata_json)
    except (TypeError, json.JSONDecodeError):
        metadata = {}
    return {
        "id": event.id,
        "action": event.action,
        "actor": {
            "id": actor.id,
            "username": actor.username,
            "display_name": actor.display_name,
        } if actor else None,
        "target": event.target,
        "metadata": metadata,
        "created_at": event.created_at.isoformat(),
        "integrity_hash": event.integrity_hash,
    }


def _is_document_manager(db: Session, document: Document, user: User) -> bool:
    return user.role == "administrator" or document.owner_id == user.id


def _deny_manager(db: Session, document: Document, user: User, attempted_action: str) -> None:
    record_audit(
        db,
        user.id,
        "denied_access",
        f"document:{document.id}",
        {"attempted_action": attempted_action},
    )
    raise HTTPException(status_code=404, detail="Document not found or access is not permitted.")


def _matches_file_content(filename: str, content: bytes) -> tuple[bool, str | None]:
    ext = Path(filename).suffix.lower()
    if ext not in ALLOWED_EXTENSIONS:
        return False, "This file type is not allowed. Upload a PDF, image, text, DOCX, or XLSX file."
    if not content:
        return False, "The file is empty."
    if ext == ".pdf":
        if not content.startswith(b"%PDF-"):
            return False, "The uploaded file extension does not match its PDF content."
        return True, CONTENT_TYPES[ext]
    if ext == ".png":
        if not content.startswith(b"\x89PNG\r\n\x1a\n"):
            return False, "The uploaded file extension does not match its PNG content."
        return True, CONTENT_TYPES[ext]
    if ext in {".jpg", ".jpeg"}:
        if not content.startswith(b"\xff\xd8\xff"):
            return False, "The uploaded file extension does not match its JPEG content."
        return True, CONTENT_TYPES[ext]
    if ext == ".txt":
        try:
            text = content.decode("utf-8-sig")
        except UnicodeDecodeError:
            return False, "Text uploads must be valid UTF-8."
        if "\x00" in text:
            return False, "Text uploads cannot contain binary data."
        return True, CONTENT_TYPES[ext]
    if ext in {".docx", ".xlsx"}:
        try:
            with zipfile.ZipFile(io.BytesIO(content)) as archive:
                names = set(archive.namelist())
                if any(PurePosixPath(name).is_absolute() or ".." in PurePosixPath(name).parts for name in names):
                    return False, "The Office file contains an invalid internal path."
                if sum(item.file_size for item in archive.infolist()) > 25 * 1024 * 1024:
                    return False, "The uncompressed Office file is too large."
                if "[Content_Types].xml" not in names:
                    return False, "The uploaded file does not contain a valid Office document structure."
                main_part = "word/document.xml" if ext == ".docx" else "xl/workbook.xml"
                if main_part not in names:
                    return False, "The uploaded file extension does not match its Office document content."
                if len(archive.read("[Content_Types].xml")) > 2 * 1024 * 1024:
                    return False, "The Office document contains invalid metadata."
        except (zipfile.BadZipFile, OSError, RuntimeError):
            return False, "The uploaded file is not a valid Office document."
        return True, CONTENT_TYPES[ext]
    return False, None


def _safe_original_filename(raw_name: str | None) -> str:
    name = (raw_name or "document").replace("\\", "/").split("/")[-1].strip()
    name = re.sub(r"[\x00-\x1f\x7f]", "", name)
    return name[:255] or "document"


def _date_start(value: date | None) -> datetime | None:
    return datetime.combine(value, time.min, tzinfo=timezone.utc) if value else None


@router.post("/auth/login")
def login(payload: LoginInput, request: Request, db: Session = Depends(get_db)):
    username = payload.username.strip().lower()
    user = db.scalar(select(User).where(func.lower(User.username) == username))
    if not user or not user.active or not verify_password(payload.password, user.password_hash):
        record_audit(db, None, "login_denied", "authentication", {"reason": "invalid_credentials"})
        raise HTTPException(status_code=401, detail="The username or password is incorrect.")

    revoke_session(request, db)
    session_token = issue_session(db, user.id)
    csrf_token = uuid.uuid4().hex + uuid.uuid4().hex
    request.session.clear()
    request.session["user_id"] = user.id
    request.session["session_token"] = session_token
    request.session["csrf_token"] = csrf_token
    record_audit(db, user.id, "login", "authentication")
    return {"user": public_user(user), "csrf_token": csrf_token}


@router.get("/session")
def session_info(request: Request, db: Session = Depends(get_db)):
    user = get_session_user(request, db)
    if not user:
        return {"user": None, "csrf_token": None}
    return {
        "user": public_user(user),
        "csrf_token": request.session.get("csrf_token"),
    }


@router.post("/auth/logout")
def logout(
    request: Request,
    user: User = Depends(require_csrf),
    db: Session = Depends(get_db),
):
    revoke_session(request, db, user.id)
    db.commit()
    request.session.clear()
    record_audit(db, user.id, "logout", "authentication")
    return {"ok": True}


@router.get("/dashboard")
def dashboard(user: User = Depends(require_user), db: Session = Depends(get_db)):
    if user.role == "administrator":
        visible_statement = select(Document)
    else:
        shared_ids = select(DocumentPermission.document_id).where(DocumentPermission.user_id == user.id)
        visible_statement = select(Document).where(
            or_(Document.owner_id == user.id, Document.id.in_(shared_ids))
        )
    visible_documents = db.scalars(visible_statement).all()
    visible_ids = [doc.id for doc in visible_documents]
    shared_count = db.scalar(
        select(func.count(func.distinct(DocumentPermission.document_id))).join(
            Document, Document.id == DocumentPermission.document_id
        ).where(
            DocumentPermission.document_id.in_(visible_ids or [-1]),
            Document.owner_id == user.id if user.role != "administrator" else True,
        )
    ) or 0
    download_query = select(func.count(AuditLog.id)).where(AuditLog.action == "document_download")
    if user.role != "administrator":
        download_query = download_query.where(
            AuditLog.target.in_([f"document:{document_id}" for document_id in visible_ids] or [""])
        )
    downloads = db.scalar(download_query) or 0
    recent_query = select(AuditLog).options(joinedload(AuditLog.actor)).order_by(AuditLog.id.desc())
    if user.role != "administrator":
        recent_query = recent_query.where(
            or_(
                AuditLog.actor_id == user.id,
                AuditLog.target.in_([f"document:{document_id}" for document_id in visible_ids] or [""]),
            )
        )
    recent = db.scalars(recent_query.limit(8)).unique().all()
    active_users = db.scalar(select(func.count(User.id)).where(User.active.is_(True))) or 0
    return {
        "stats": {
            "documents": len(visible_documents),
            "shared": shared_count,
            "downloads": downloads,
            "users": active_users if user.role == "administrator" else 0,
        },
        "recent_activity": [_audit_json(event) for event in recent],
    }


@router.get("/documents")
def list_documents(
    q: str = Query(default="", max_length=120),
    category: str | None = Query(default=None, max_length=MAX_CATEGORY),
    owner: str | None = Query(default=None, max_length=120),
    from_date: date | None = Query(default=None, alias="from"),
    to_date: date | None = Query(default=None, alias="to"),
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
):
    statement = select(Document).options(joinedload(Document.owner))
    if user.role != "administrator":
        shared_ids = select(DocumentPermission.document_id).where(DocumentPermission.user_id == user.id)
        statement = statement.where(or_(Document.owner_id == user.id, Document.id.in_(shared_ids)))
    if q:
        term = f"%{q.strip()}%"
        statement = statement.join(Document.owner).where(
            or_(Document.name.ilike(term), User.display_name.ilike(term), User.username.ilike(term))
        )
    if category:
        statement = statement.where(Document.category == category)
    if owner:
        term = f"%{owner.strip()}%"
        if not q:
            statement = statement.join(Document.owner)
        statement = statement.where(or_(User.display_name.ilike(term), User.username.ilike(term)))
    start = _date_start(from_date)
    end = _date_start(to_date + timedelta(days=1)) if to_date else None
    if start:
        statement = statement.where(Document.created_at >= start)
    if end:
        statement = statement.where(Document.created_at < end)
    documents = db.scalars(statement.order_by(Document.created_at.desc())).unique().all()
    return [_document_json(db, document, user) for document in documents]


@router.post("/documents")
async def upload_document(
    file: UploadFile = File(...),
    name: str = Form(min_length=1, max_length=MAX_DOC_NAME),
    category: str = Form(min_length=1, max_length=MAX_CATEGORY),
    user: User = Depends(require_csrf),
    db: Session = Depends(get_db),
):
    if user.role not in {"owner", "administrator"}:
        raise HTTPException(status_code=403, detail="Only document owners can upload files.")
    original_name = _safe_original_filename(file.filename)
    content = await file.read(MAX_UPLOAD_BYTES + 1)
    await file.close()
    if len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="Files must be 10 MB or smaller.")
    valid, content_type = _matches_file_content(original_name, content)
    if not valid or not content_type:
        raise HTTPException(
            status_code=415,
            detail=content_type or "The file extension and actual file content do not match.",
        )

    clean_name = name.strip()
    clean_category = category.strip()
    if not clean_name or not clean_category:
        raise HTTPException(status_code=422, detail="Document name and category are required.")
    storage_name = f"{uuid.uuid4().hex}{Path(original_name).suffix.lower()}"
    storage_path = PRIVATE_FILES_DIR / storage_name
    storage_path.write_bytes(content)
    storage_path.chmod(0o600)
    try:
        document = Document(
            name=clean_name,
            original_filename=original_name,
            category=clean_category,
            stored_filename=storage_name,
            content_type=content_type,
            size=len(content),
            owner_id=user.id,
        )
        db.add(document)
        db.flush()
        record_audit(db, user.id, "document_upload", f"document:{document.id}", {
            "name": document.name,
            "category": document.category,
            "size": document.size,
        })
    except Exception:
        db.rollback()
        storage_path.unlink(missing_ok=True)
        raise
    db.refresh(document)
    return _document_json(db, document, user)


@router.get("/documents/{document_id}")
def get_document(document_id: int, user: User = Depends(require_user), db: Session = Depends(get_db)):
    document, _ = get_document_or_deny(db, document_id, user, "download")
    document = db.scalar(
        select(Document).options(joinedload(Document.owner)).where(Document.id == document.id)
    )
    return _document_json(db, document, user)


@router.get("/documents/{document_id}/download")
def download_document(
    document_id: int,
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
):
    document, _ = get_document_or_deny(db, document_id, user, "read")
    path = (PRIVATE_FILES_DIR / document.stored_filename).resolve()
    if path.parent != PRIVATE_FILES_DIR.resolve() or not path.is_file():
        raise HTTPException(status_code=404, detail="The stored document is unavailable.")
    record_audit(
        db,
        user.id,
        "document_download",
        f"document:{document.id}",
        {"name": document.name},
    )
    return FileResponse(
        path,
        media_type=document.content_type,
        filename=document.original_filename,
        headers={"Cache-Control": "private, no-store"},
    )


@router.patch("/documents/{document_id}")
def update_document(
    document_id: int,
    payload: DocumentUpdateInput,
    user: User = Depends(require_csrf),
    db: Session = Depends(get_db),
):
    document, level = get_document_or_deny(db, document_id, user, "edit")
    if level not in {"owner", "admin", "edit"}:
        record_audit(db, user.id, "denied_access", f"document:{document_id}", {
            "attempted_action": "edit"
        })
        raise HTTPException(status_code=404, detail="Document not found or access is not permitted.")
    document.name = payload.name.strip()
    document.category = payload.category.strip()
    document.updated_at = utc_now()
    record_audit(
        db,
        user.id,
        "document_update",
        f"document:{document.id}",
        {"name": document.name, "category": document.category},
    )
    db.refresh(document)
    document = db.scalar(
        select(Document).options(joinedload(Document.owner)).where(Document.id == document.id)
    )
    return _document_json(db, document, user)


@router.delete("/documents/{document_id}")
def delete_document(
    document_id: int,
    user: User = Depends(require_csrf),
    db: Session = Depends(get_db),
):
    document = db.get(Document, document_id)
    if not document or (user.role != "administrator" and document.owner_id != user.id):
        record_audit(db, user.id, "denied_access", f"document:{document_id}", {
            "attempted_action": "delete"
        })
        raise HTTPException(status_code=404, detail="Document not found or access is not permitted.")
    path = PRIVATE_FILES_DIR / document.stored_filename
    target = f"document:{document.id}"
    name = document.name
    db.delete(document)
    record_audit(db, user.id, "document_delete", target, {"name": name})
    path.unlink(missing_ok=True)
    return {"ok": True}


@router.get("/documents/{document_id}/permissions")
def list_permissions(
    document_id: int,
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
):
    document = db.get(Document, document_id)
    if not document:
        record_audit(
            db,
            user.id,
            "denied_access",
            f"document:{document_id}",
            {"attempted_action": "view_permissions"},
        )
        raise HTTPException(status_code=404, detail="Document not found or access is not permitted.")
    if not _is_document_manager(db, document, user):
        _deny_manager(db, document, user, "view_permissions")
    permissions = db.scalars(
        select(DocumentPermission)
        .options(joinedload(DocumentPermission.user))
        .where(DocumentPermission.document_id == document_id)
        .order_by(DocumentPermission.id.asc())
    ).unique().all()
    return [
        {"user": public_user(permission.user), "level": permission.level}
        for permission in permissions
    ]


@router.put("/documents/{document_id}/permissions")
def grant_permission(
    document_id: int,
    payload: PermissionInput,
    user: User = Depends(require_csrf),
    db: Session = Depends(get_db),
):
    document = db.get(Document, document_id)
    if not document:
        record_audit(db, user.id, "denied_access", f"document:{document_id}", {
            "attempted_action": "grant_permission"
        })
        raise HTTPException(status_code=404, detail="Document not found or access is not permitted.")
    if not _is_document_manager(db, document, user):
        _deny_manager(db, document, user, "grant_permission")
    target_user = _user_or_404(db, payload.user_id)
    if target_user.id == document.owner_id:
        raise HTTPException(status_code=422, detail="The document owner already has full access.")
    permission = _doc_permission(db, document_id, target_user.id)
    if permission:
        permission.level = payload.level
        permission.granted_by_id = user.id
    else:
        permission = DocumentPermission(
            document_id=document_id,
            user_id=target_user.id,
            level=payload.level,
            granted_by_id=user.id,
        )
        db.add(permission)
    record_audit(
        db,
        user.id,
        "permission_grant",
        f"document:{document_id}",
        {"user_id": target_user.id, "username": target_user.username, "level": payload.level},
    )
    return {"user": public_user(target_user), "level": permission.level}


@router.delete("/documents/{document_id}/permissions/{target_user_id}")
def revoke_permission(
    document_id: int,
    target_user_id: int,
    user: User = Depends(require_csrf),
    db: Session = Depends(get_db),
):
    document = db.get(Document, document_id)
    if not document:
        record_audit(db, user.id, "denied_access", f"document:{document_id}", {
            "attempted_action": "revoke_permission"
        })
        raise HTTPException(status_code=404, detail="Document not found or access is not permitted.")
    if not _is_document_manager(db, document, user):
        _deny_manager(db, document, user, "revoke_permission")
    permission = _doc_permission(db, document_id, target_user_id)
    if not permission:
        raise HTTPException(status_code=404, detail="That user does not have access to this document.")
    db.delete(permission)
    record_audit(
        db,
        user.id,
        "permission_revoke",
        f"document:{document_id}",
        {"user_id": target_user_id},
    )
    return {"ok": True}


@router.get("/users")
def list_users(user: User = Depends(require_user), db: Session = Depends(get_db)):
    if user.role == "administrator":
        statement = select(User).order_by(User.display_name.asc())
    elif user.role == "owner":
        statement = (
            select(User)
            .where(User.active.is_(True), User.role != "administrator", User.id != user.id)
            .order_by(User.display_name.asc())
        )
    else:
        raise HTTPException(status_code=403, detail="Owner or administrator access is required.")
    users = db.scalars(statement).all()
    return [public_user(item) for item in users]


@router.post("/users")
def create_user(
    payload: UserCreateInput,
    user: User = Depends(require_csrf),
    db: Session = Depends(get_db),
):
    if user.role != "administrator":
        raise HTTPException(status_code=403, detail="Administrator access is required.")
    username = payload.username.strip().lower()
    if db.scalar(select(User).where(func.lower(User.username) == username)):
        raise HTTPException(status_code=409, detail="A user with that username already exists.")
    new_user = User(
        username=username,
        display_name=payload.display_name.strip(),
        password_hash=hash_password(payload.password),
        role=payload.role,
    )
    db.add(new_user)
    db.flush()
    record_audit(db, user.id, "user_create", f"user:{new_user.id}", {
        "username": username,
        "role": payload.role,
    })
    db.refresh(new_user)
    return public_user(new_user)


@router.delete("/users/{target_user_id}")
def deactivate_user(
    target_user_id: int,
    user: User = Depends(require_csrf),
    db: Session = Depends(get_db),
):
    if user.role != "administrator":
        raise HTTPException(status_code=403, detail="Administrator access is required.")
    target_user = _user_or_404(db, target_user_id)
    if target_user.id == user.id:
        raise HTTPException(status_code=409, detail="You cannot deactivate your own account.")
    if target_user.role == "administrator":
        active_admins = db.scalar(
            select(func.count(User.id)).where(User.role == "administrator", User.active.is_(True))
        ) or 0
        if active_admins <= 1:
            raise HTTPException(status_code=409, detail="The last active administrator cannot be deactivated.")
    target_user.active = False
    revoke_user_sessions(db, target_user.id)
    record_audit(
        db,
        user.id,
        "user_deactivate",
        f"user:{target_user.id}",
        {"username": target_user.username},
    )
    return {"ok": True}


@router.get("/audit-logs")
def list_audit_logs(
    limit: int = Query(default=100, ge=1, le=200),
    action: str | None = Query(default=None, max_length=60),
    q: str = Query(default="", max_length=120),
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
):
    statement = select(AuditLog).options(joinedload(AuditLog.actor))
    if user.role != "administrator":
        visible_ids = db.scalars(
            select(Document.id).where(
                or_(
                    Document.owner_id == user.id,
                    Document.id.in_(
                        select(DocumentPermission.document_id).where(
                            DocumentPermission.user_id == user.id
                        )
                    ),
                )
            )
        ).all()
        visible_targets = [f"document:{document_id}" for document_id in visible_ids]
        statement = statement.where(
            or_(
                AuditLog.actor_id == user.id,
                AuditLog.target.in_(visible_targets or [""]),
            )
        )
    if action:
        statement = statement.where(AuditLog.action == action)
    if q:
        term = f"%{q.strip()}%"
        statement = statement.where(
            or_(
                AuditLog.action.ilike(term),
                AuditLog.target.ilike(term),
                AuditLog.metadata_json.ilike(term),
            )
        )
    events = db.scalars(statement.order_by(AuditLog.id.desc()).limit(limit)).unique().all()
    return [_audit_json(event) for event in events]


@router.get("/audit-logs/integrity")
def get_audit_integrity(user: User = Depends(require_user), db: Session = Depends(get_db)):
    if user.role != "administrator":
        raise HTTPException(status_code=403, detail="Administrator access is required.")
    return audit_chain_status(db)
