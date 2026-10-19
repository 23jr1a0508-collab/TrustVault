from __future__ import annotations

import os
from pathlib import Path

os.environ["TRUSTVAULT_DEMO_SEED"] = "0"
os.environ["SESSION_SECRET"] = "test-only-session-secret-change-me-123456789"

from fastapi.testclient import TestClient
from sqlalchemy import select

from trustvault.app import api, database
from trustvault.app.main import app
from trustvault.app.models import AuditLog, Document, User
from trustvault.app.security import audit_chain_status, hash_password


class TrustVaultTestClient(TestClient):
    """Mirror the browser's prefix rewrite around the existing /api service."""

    def request(self, method, url, *args, **kwargs):
        if isinstance(url, str) and url.startswith("/api/"):
            url = url.replace("/api/", "/trustvault-api/", 1)
        return super().request(method, url, *args, **kwargs)


def _create_client() -> TestClient:
    return TrustVaultTestClient(app)


def _login(client: TestClient, username: str, password: str) -> str:
    response = client.post("/api/auth/login", json={"username": username, "password": password})
    assert response.status_code == 200, response.text
    return response.json()["csrf_token"]


def _upload(client: TestClient, token: str, name: str = "Review notes") -> dict:
    response = client.post(
        "/api/documents",
        headers={"X-CSRF-Token": token},
        data={"name": name, "category": "Candidate files"},
        files={"file": ("review-notes.txt", b"safe test file\n", "text/plain")},
    )
    assert response.status_code == 200, response.text
    return response.json()


def _install_test_users() -> dict[str, int]:
    with database.SessionLocal() as db:
        admin = User(
            username="admin-test",
            display_name="Admin Tester",
            password_hash=hash_password("admin-test-password"),
            role="administrator",
        )
        owner = User(
            username="owner-test",
            display_name="Owner Tester",
            password_hash=hash_password("owner-test-password"),
            role="owner",
        )
        viewer = User(
            username="viewer-test",
            display_name="Viewer Tester",
            password_hash=hash_password("viewer-test-password"),
            role="viewer",
        )
        db.add_all([admin, owner, viewer])
        db.commit()
        return {"admin": admin.id, "owner": owner.id, "viewer": viewer.id}


def _audit_actions() -> list[str]:
    with database.SessionLocal() as db:
        return [row.action for row in db.scalars(select(AuditLog).order_by(AuditLog.id)).all()]


def test_login_hashes_password_and_records_denied_attempt(tmp_path: Path, monkeypatch):
    database.configure_database(f"sqlite:///{tmp_path / 'login.db'}")
    database.Base.metadata.create_all(bind=database.engine)
    _install_test_users()
    client = _create_client()
    try:
        anonymous_session = client.get("/api/session")
        assert anonymous_session.status_code == 200
        assert anonymous_session.json()["user"] is None
        response = client.post(
            "/api/auth/login",
            json={"username": "owner-test", "password": "owner-test-password"},
        )
        assert response.status_code == 200
        assert len(response.json()["csrf_token"]) >= 32
        assert "password" not in response.json()["user"]

        invalid = _create_client()
        try:
            bad_response = invalid.post(
                "/api/auth/login",
                json={"username": "owner-test", "password": "incorrect-password"},
            )
            assert bad_response.status_code == 401
        finally:
            invalid.close()
        assert "login_denied" in _audit_actions()
    finally:
        client.close()


def test_direct_id_and_download_denied_until_permission_is_granted_and_revoked(tmp_path: Path):
    database.configure_database(f"sqlite:///{tmp_path / 'access.db'}")
    database.Base.metadata.create_all(bind=database.engine)
    _install_test_users()
    private_dir = tmp_path / "private"
    private_dir.mkdir()
    database.PRIVATE_FILES_DIR = private_dir
    api.PRIVATE_FILES_DIR = private_dir
    owner_client, viewer_client, admin_client = _create_client(), _create_client(), _create_client()
    try:
        owner_csrf = _login(owner_client, "owner-test", "owner-test-password")
        viewer_csrf = _login(viewer_client, "viewer-test", "viewer-test-password")
        admin_csrf = _login(admin_client, "admin-test", "admin-test-password")
        recipients = owner_client.get("/api/users")
        assert recipients.status_code == 200
        assert any(item["username"] == "viewer-test" for item in recipients.json())
        assert all(item["role"] != "administrator" for item in recipients.json())
        document = _upload(owner_client, owner_csrf)

        assert viewer_client.get(f"/api/documents/{document['id']}").status_code == 404
        assert viewer_client.get(f"/api/documents/{document['id']}/download").status_code == 404

        grant = owner_client.put(
            f"/api/documents/{document['id']}/permissions",
            headers={"X-CSRF-Token": owner_csrf},
            json={"user_id": document["owner"]["id"] + 1, "level": "read"},
        )
        # IDs are created in order: administrator, owner, viewer. Confirm the
        # intended account through the response rather than assuming arbitrary IDs.
        if grant.status_code != 200:
            with database.SessionLocal() as db:
                viewer_id = db.scalar(select(User.id).where(User.username == "viewer-test"))
            grant = owner_client.put(
                f"/api/documents/{document['id']}/permissions",
                headers={"X-CSRF-Token": owner_csrf},
                json={"user_id": viewer_id, "level": "read"},
            )
        assert grant.status_code == 200, grant.text
        assert viewer_client.get(f"/api/documents/{document['id']}").status_code == 200
        read_cannot_edit = viewer_client.patch(
            f"/api/documents/{document['id']}",
            headers={"X-CSRF-Token": viewer_csrf},
            json={"name": "Must not change", "category": "Candidate files"},
        )
        assert read_cannot_edit.status_code == 404
        download = viewer_client.get(f"/api/documents/{document['id']}/download")
        assert download.status_code == 200
        assert download.content == b"safe test file\n"

        with database.SessionLocal() as db:
            viewer_id = db.scalar(select(User.id).where(User.username == "viewer-test"))
        revoked = owner_client.delete(
            f"/api/documents/{document['id']}/permissions/{viewer_id}",
            headers={"X-CSRF-Token": owner_csrf},
        )
        assert revoked.status_code == 200
        assert viewer_client.get(f"/api/documents/{document['id']}/download").status_code == 404

        logs = admin_client.get("/api/audit-logs")
        assert logs.status_code == 200
        actions = [item["action"] for item in logs.json()]
        assert "denied_access" in actions
        assert "document_download" in actions
        assert "permission_revoke" in actions
        with database.SessionLocal() as db:
            stored_name = db.get(Document, document["id"]).stored_filename
        stored_path = private_dir / stored_name
        assert stored_path.is_file()
        deleted = owner_client.delete(
            f"/api/documents/{document['id']}",
            headers={"X-CSRF-Token": owner_csrf},
        )
        assert deleted.status_code == 200
        assert not stored_path.exists()
        assert "document_delete" in _audit_actions()
        assert admin_csrf
    finally:
        for client in (owner_client, viewer_client, admin_client):
            client.close()


def test_edit_grant_allows_metadata_update_but_not_delete(tmp_path: Path):
    database.configure_database(f"sqlite:///{tmp_path / 'edit.db'}")
    database.Base.metadata.create_all(bind=database.engine)
    ids = _install_test_users()
    private_dir = tmp_path / "private"
    private_dir.mkdir()
    database.PRIVATE_FILES_DIR = private_dir
    api.PRIVATE_FILES_DIR = private_dir
    owner_client, viewer_client = _create_client(), _create_client()
    try:
        owner_csrf = _login(owner_client, "owner-test", "owner-test-password")
        viewer_csrf = _login(viewer_client, "viewer-test", "viewer-test-password")
        document = _upload(owner_client, owner_csrf)
        grant = owner_client.put(
            f"/api/documents/{document['id']}/permissions",
            headers={"X-CSRF-Token": owner_csrf},
            json={"user_id": ids["viewer"], "level": "edit"},
        )
        assert grant.status_code == 200
        updated = viewer_client.patch(
            f"/api/documents/{document['id']}",
            headers={"X-CSRF-Token": viewer_csrf},
            json={"name": "Updated review notes", "category": "Updated"},
        )
        assert updated.status_code == 200
        assert updated.json()["name"] == "Updated review notes"
        deleted = viewer_client.delete(
            f"/api/documents/{document['id']}",
            headers={"X-CSRF-Token": viewer_csrf},
        )
        assert deleted.status_code == 404
        assert "denied_access" in _audit_actions()
    finally:
        owner_client.close()
        viewer_client.close()


def test_viewer_cannot_upload_and_admin_can_manage_users(tmp_path: Path):
    database.configure_database(f"sqlite:///{tmp_path / 'roles.db'}")
    database.Base.metadata.create_all(bind=database.engine)
    _install_test_users()
    owner_client, viewer_client, admin_client = _create_client(), _create_client(), _create_client()
    try:
        viewer_csrf = _login(viewer_client, "viewer-test", "viewer-test-password")
        blocked_upload = viewer_client.post(
            "/api/documents",
            headers={"X-CSRF-Token": viewer_csrf},
            data={"name": "Not allowed", "category": "Test"},
            files={"file": ("no.txt", b"no", "text/plain")},
        )
        assert blocked_upload.status_code == 403
        assert viewer_client.get("/api/users").status_code == 403

        admin_csrf = _login(admin_client, "admin-test", "admin-test-password")
        created = admin_client.post(
            "/api/users",
            headers={"X-CSRF-Token": admin_csrf},
            json={
                "username": "new-owner",
                "display_name": "New Owner",
                "password": "long-enough-password",
                "role": "owner",
            },
        )
        assert created.status_code == 200
        assert created.json()["role"] == "owner"
        assert "password" not in created.json()
        assert admin_client.get("/api/users").status_code == 200
        assert "denied_access" in _audit_actions()
    finally:
        for client in (owner_client, viewer_client, admin_client):
            client.close()


def test_upload_checks_extension_actual_content_and_size(tmp_path: Path):
    database.configure_database(f"sqlite:///{tmp_path / 'validation.db'}")
    database.Base.metadata.create_all(bind=database.engine)
    _install_test_users()
    private_dir = tmp_path / "private"
    private_dir.mkdir()
    database.PRIVATE_FILES_DIR = private_dir
    api.PRIVATE_FILES_DIR = private_dir
    client = _create_client()
    try:
        csrf = _login(client, "owner-test", "owner-test-password")
        mismatch = client.post(
            "/api/documents",
            headers={"X-CSRF-Token": csrf},
            data={"name": "Not a PDF", "category": "Test"},
            files={"file": ("spoof.pdf", b"plain text", "application/pdf")},
        )
        assert mismatch.status_code == 415
        too_large = client.post(
            "/api/documents",
            headers={"X-CSRF-Token": csrf},
            data={"name": "Too large", "category": "Test"},
            files={"file": ("large.txt", b"x" * (10 * 1024 * 1024 + 1), "text/plain")},
        )
        assert too_large.status_code == 413
        forbidden = client.post(
            "/api/documents",
            headers={"X-CSRF-Token": csrf},
            data={"name": "Bad extension", "category": "Test"},
            files={"file": ("script.exe", b"binary", "application/octet-stream")},
        )
        assert forbidden.status_code == 415
    finally:
        client.close()


def test_private_file_is_not_served_as_static_content(tmp_path: Path):
    database.configure_database(f"sqlite:///{tmp_path / 'private.db'}")
    database.Base.metadata.create_all(bind=database.engine)
    _install_test_users()
    private_dir = tmp_path / "private"
    private_dir.mkdir()
    database.PRIVATE_FILES_DIR = private_dir
    api.PRIVATE_FILES_DIR = private_dir
    client = _create_client()
    try:
        csrf = _login(client, "owner-test", "owner-test-password")
        document = _upload(client, csrf)
        with database.SessionLocal() as db:
            row = db.get(Document, document["id"])
            stored_name = row.stored_filename
        assert (private_dir / stored_name).is_file()
        assert client.get(f"/static/{stored_name}").status_code == 404
        assert "private_files" not in client.get(f"/api/documents/{document['id']}").text
    finally:
        client.close()


def test_audit_hash_chain_detects_record_mutation(tmp_path: Path):
    database.configure_database(f"sqlite:///{tmp_path / 'audit.db'}")
    database.Base.metadata.create_all(bind=database.engine)
    _install_test_users()
    client = _create_client()
    try:
        csrf = _login(client, "admin-test", "admin-test-password")
        assert client.get("/api/audit-logs/integrity").json()["valid"] is True
        with database.SessionLocal() as db:
            first = db.scalar(select(AuditLog).order_by(AuditLog.id.asc()))
            first.target = "changed-without-rehash"
            db.commit()
            result = audit_chain_status(db)
        assert result["valid"] is False
        assert result["broken_at"] is not None
        assert csrf
    finally:
        client.close()
