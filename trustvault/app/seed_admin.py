from __future__ import annotations

import getpass
import re

from sqlalchemy import select

from .database import Base, SessionLocal, engine, initialize_database
from .models import User
from .security import hash_password, record_audit


def main() -> None:
    initialize_database()
    Base.metadata.create_all(bind=engine)
    username = input("Admin username: ").strip().lower()
    display_name = input("Admin display name: ").strip()
    password = getpass.getpass("Admin password (12+ characters): ")
    if not re.fullmatch(r"[a-z0-9_.@+-]{3,80}", username):
        raise SystemExit("Username must be 3–80 characters: letters, numbers, dot, underscore, @, +, or hyphen.")
    if len(password) < 12:
        raise SystemExit("Password must contain at least 12 characters.")
    if not display_name or len(display_name) > 120:
        raise SystemExit("A display name of 1–120 characters is required.")

    with SessionLocal() as db:
        existing = db.scalar(select(User).where(User.username == username))
        if existing:
            raise SystemExit("That username already exists; no account was changed.")
        admin = User(
            username=username,
            display_name=display_name,
            password_hash=hash_password(password),
            role="administrator",
        )
        db.add(admin)
        db.flush()
        record_audit(db, None, "user_create", f"user:{admin.id}", {
            "username": username,
            "role": "administrator",
            "created_by": "bootstrap",
        })
    print("Administrator account created.")


if __name__ == "__main__":
    main()
