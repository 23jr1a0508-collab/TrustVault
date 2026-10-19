from __future__ import annotations

import os
import json
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


def _upload(
    client: TestClient,
    token: str,
    name: str = "Review notes",
    category: str = "Candidate files",
) -> dict:
    response = client.post(
        "/api/documents",
        headers={"X-CSRF-Token": token},
        data={"name": name, "category": category},
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


def test_actual_api_prefix_is_mounted_and_session_is_publicly_nullable(tmp_path: Path):
    database.configure_database(f"sqlite:///{tmp_path / 'prefix.db'}")
    database.Base.metadata.create_all(bind=database.engine)
    client = TestClient(app)
    try:
        assert client.get("/trustvault-api/session").status_code == 200
        assert client.get("/api/session").status_code == 404
    finally:
        client.close()


def test_direct_id_and_download_denied_until_permission_is_granted_and_revoked(tmp_path: Path):
    database.configure_database(f"sqlite:///{tmp_path / 'access.db'}")
    database.Base.metadata.create_all(bind=database.engine)
    ids = _install_test_users()
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
            json={"user_id": ids["viewer"], "level": "read"},
        )
        assert grant.status_code == 200, grant.text
        assert grant.json()["user"]["id"] == ids["viewer"]
        assert admin_client.get(f"/api/documents/{document['id']}").status_code == 200
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

        revoked = owner_client.delete(
            f"/api/documents/{document['id']}/permissions/{ids['viewer']}",
            headers={"X-CSRF-Token": owner_csrf},
        )
        assert revoked.status_code == 200
        assert viewer_client.get(f"/api/documents/{document['id']}").status_code == 404
        assert viewer_client.get(f"/api/documents/{document['id']}/download").status_code == 404
        assert all(
            item["id"] != document["id"]
            for item in viewer_client.get("/api/documents").json()
        )

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
        assert client.get(f"/trustvault/data/private_files/{stored_name}").status_code == 404
        assert client.get(f"/private_files/{stored_name}").status_code == 404
        assert "private_files" not in client.get(f"/api/documents/{document['id']}").text
    finally:
        client.close()


def test_cross_user_idor_read_download_edit_delete_and_permission_attacks_are_denied_and_audited(
    tmp_path: Path,
):
    database.configure_database(f"sqlite:///{tmp_path / 'cross-user.db'}")
    database.Base.metadata.create_all(bind=database.engine)
    ids = _install_test_users()
    private_dir = tmp_path / "private"
    private_dir.mkdir()
    database.PRIVATE_FILES_DIR = private_dir
    api.PRIVATE_FILES_DIR = private_dir
    with database.SessionLocal() as db:
        other_owner = User(
            username="other-owner",
            display_name="Other Owner",
            password_hash=hash_password("other-owner-password"),
            role="owner",
        )
        db.add(other_owner)
        db.commit()
        other_owner_id = other_owner.id

    owner_client, other_client = _create_client(), _create_client()
    try:
        owner_csrf = _login(owner_client, "owner-test", "owner-test-password")
        other_csrf = _login(other_client, "other-owner", "other-owner-password")
        document = _upload(owner_client, owner_csrf)
        doc_id = document["id"]

        assert all(item["id"] != doc_id for item in other_client.get("/api/documents").json())
        assert other_client.get(f"/api/documents/{doc_id}").status_code == 404
        assert other_client.get(f"/api/documents/{doc_id}/download").status_code == 404
        assert other_client.patch(
            f"/api/documents/{doc_id}",
            headers={"X-CSRF-Token": other_csrf},
            json={"name": "IDOR edit", "category": "Attacked"},
        ).status_code == 404
        assert other_client.delete(
            f"/api/documents/{doc_id}",
            headers={"X-CSRF-Token": other_csrf},
        ).status_code == 404
        assert other_client.get(f"/api/documents/{doc_id}/permissions").status_code == 404
        assert other_client.put(
            f"/api/documents/{doc_id}/permissions",
            headers={"X-CSRF-Token": other_csrf},
            json={"user_id": ids["viewer"], "level": "read"},
        ).status_code == 404
        assert other_client.delete(
            f"/api/documents/{doc_id}/permissions/{ids['viewer']}",
            headers={"X-CSRF-Token": other_csrf},
        ).status_code == 404

        with database.SessionLocal() as db:
            stored_name = db.get(Document, doc_id).stored_filename
            events = db.scalars(
                select(AuditLog).where(
                    AuditLog.action == "denied_access",
                    AuditLog.target == f"document:{doc_id}",
                )
            ).all()
        attempted = {json.loads(event.metadata_json)["attempted_action"] for event in events}
        assert attempted >= {
            "read",
            "download",
            "edit",
            "delete",
            "view_permissions",
            "grant_permission",
            "revoke_permission",
        }
        assert (private_dir / stored_name).is_file()
        assert other_owner_id != document["owner"]["id"]
    finally:
        owner_client.close()
        other_client.close()


def test_anonymous_cannot_read_or_download_document_even_with_its_id(tmp_path: Path):
    database.configure_database(f"sqlite:///{tmp_path / 'anonymous.db'}")
    database.Base.metadata.create_all(bind=database.engine)
    _install_test_users()
    private_dir = tmp_path / "private"
    private_dir.mkdir()
    database.PRIVATE_FILES_DIR = private_dir
    api.PRIVATE_FILES_DIR = private_dir
    owner_client, anonymous_client = _create_client(), _create_client()
    try:
        owner_csrf = _login(owner_client, "owner-test", "owner-test-password")
        document = _upload(owner_client, owner_csrf)
        with database.SessionLocal() as db:
            stored_name = db.get(Document, document["id"]).stored_filename

        assert anonymous_client.get(f"/api/documents/{document['id']}").status_code == 401
        assert anonymous_client.get(f"/api/documents/{document['id']}/download").status_code == 401
        assert anonymous_client.get(f"/static/{stored_name}").status_code == 404
        assert anonymous_client.get(f"/trustvault/data/private_files/{stored_name}").status_code == 404
        with database.SessionLocal() as db:
            denied = db.scalars(
                select(AuditLog).where(
                    AuditLog.action == "denied_access",
                    AuditLog.target == "/trustvault-api/documents/" + str(document["id"]) + "/download",
                )
            ).all()
        assert any(json.loads(event.metadata_json).get("status_code") == 401 for event in denied)
    finally:
        owner_client.close()
        anonymous_client.close()


def test_non_admin_cannot_escalate_role_or_manage_users_and_permissions(tmp_path: Path):
    database.configure_database(f"sqlite:///{tmp_path / 'escalation.db'}")
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
        payload = {
            "username": "attacker-admin",
            "display_name": "Attacker",
            "password": "long-enough-password",
            "role": "administrator",
        }
        assert viewer_client.post(
            "/api/users",
            headers={"X-CSRF-Token": viewer_csrf},
            json=payload,
        ).status_code == 403
        assert viewer_client.delete(
            f"/api/users/{ids['owner']}",
            headers={"X-CSRF-Token": viewer_csrf},
        ).status_code == 403
        assert viewer_client.put(
            f"/api/users/{ids['viewer']}",
            headers={"X-CSRF-Token": viewer_csrf},
            json={"role": "administrator"},
        ).status_code in {404, 405}
        assert viewer_client.put(
            f"/api/documents/{document['id']}/permissions",
            headers={"X-CSRF-Token": viewer_csrf},
            json={"user_id": ids["admin"], "level": "edit"},
        ).status_code == 404
        assert viewer_client.get("/api/audit-logs/integrity").status_code == 403
        with database.SessionLocal() as db:
            assert db.scalar(select(User).where(User.username == "attacker-admin")) is None
            assert db.get(User, ids["viewer"]).role == "viewer"
            assert db.get(User, ids["owner"]).active is True
    finally:
        owner_client.close()
        viewer_client.close()


def test_audit_hash_chain_detects_record_mutation(tmp_path: Path):
    database.configure_database(f"sqlite:///{tmp_path / 'audit.db'}")
    database.Base.metadata.create_all(bind=database.engine)
    _install_test_users()
    client = _create_client()
    try:
        csrf = _login(client, "admin-test", "admin-test-password")
        for method, path in (
            ("POST", "/api/audit-logs"),
            ("PUT", "/api/audit-logs"),
            ("DELETE", "/api/audit-logs"),
            ("PATCH", "/api/audit-logs/1"),
            ("DELETE", "/api/audit-logs/1"),
        ):
            response = client.request(method, path, headers={"X-CSRF-Token": csrf})
            assert response.status_code in {404, 405}
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


def test_audit_hash_chain_cannot_detect_deletion_of_the_tail_without_an_external_anchor(
    tmp_path: Path,
):
    database.configure_database(f"sqlite:///{tmp_path / 'audit-tail.db'}")
    database.Base.metadata.create_all(bind=database.engine)
    _install_test_users()
    first_client, second_client = _create_client(), _create_client()
    try:
        _login(first_client, "admin-test", "admin-test-password")
        _login(second_client, "owner-test", "owner-test-password")
        with database.SessionLocal() as db:
            latest = db.scalar(select(AuditLog).order_by(AuditLog.id.desc()))
            db.delete(latest)
            db.commit()
            result = audit_chain_status(db)
        # This passing assertion documents the chain's limit: it has no separate
        # trusted head/checkpoint, so removing a suffix leaves a valid prefix.
        assert result["valid"] is True
    finally:
        first_client.close()
        second_client.close()


def test_demo_seed_is_on_by_default_only_outside_production(tmp_path: Path, monkeypatch):
    monkeypatch.delenv("TRUSTVAULT_DEMO_SEED", raising=False)
    monkeypatch.setenv("TRUSTVAULT_ENV", "production")
    database.configure_database(f"sqlite:///{tmp_path / 'production-seed.db'}")
    database.initialize_database()
    with database.SessionLocal() as db:
        assert db.scalars(select(User)).all() == []

    monkeypatch.setenv("TRUSTVAULT_ENV", "development")
    database.configure_database(f"sqlite:///{tmp_path / 'development-seed.db'}")
    database.initialize_database()
    with database.SessionLocal() as db:
        assert {user.username for user in db.scalars(select(User)).all()} == {
            "admin",
            "owner",
            "viewer",
        }
