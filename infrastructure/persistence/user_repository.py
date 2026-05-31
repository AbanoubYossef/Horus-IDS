"""SQLite implementation of ``domain.ports.UserRepository``."""

from pathlib import Path
from typing import Optional

from domain.ports.user_repository import UserRepository
from infrastructure.persistence.database import get_db


class SqliteUserRepository(UserRepository):
    """Concrete user/session repository backed by SQLite."""

    def __init__(self, db_path: Path) -> None:
        self._db_path = db_path

    # ------------------------------------------------------------------
    # Users
    # ------------------------------------------------------------------

    def find_by_username_or_email(
        self, username: str, email: str
    ) -> Optional[dict]:
        """Return a user dict if *username* or *email* already exists."""
        with get_db(self._db_path) as conn:
            row = conn.execute(
                "SELECT id FROM users WHERE username = ? OR email = ?",
                (username, email),
            ).fetchone()
        return dict(row) if row else None

    def create_user(
        self,
        user_id: str,
        username: str,
        email: str,
        password_hash: str,
        salt: str,
        role: str,
        created_at: str,
    ) -> None:
        """Insert a new user row."""
        with get_db(self._db_path) as conn:
            conn.execute(
                "INSERT INTO users "
                "(id, username, email, password_hash, salt, role, created_at) "
                "VALUES (?,?,?,?,?,?,?)",
                (user_id, username, email, password_hash, salt, role, created_at),
            )

    def find_by_username(self, username: str) -> Optional[dict]:
        """Look up a user by username."""
        with get_db(self._db_path) as conn:
            row = conn.execute(
                "SELECT id, username, email, password_hash, salt, role, "
                "created_at FROM users WHERE username = ?",
                (username,),
            ).fetchone()
        return dict(row) if row else None

    # ------------------------------------------------------------------
    # Sessions
    # ------------------------------------------------------------------

    def create_session(
        self, token: str, user_id: str, expires_at: str, created_at: str
    ) -> None:
        """Insert a new session row."""
        with get_db(self._db_path) as conn:
            conn.execute(
                "INSERT INTO sessions "
                "(token, user_id, expires_at, created_at) "
                "VALUES (?,?,?,?)",
                (token, user_id, expires_at, created_at),
            )

    def get_session_user(
        self, token: str, now_iso: str
    ) -> Optional[dict]:
        """Resolve session token to user, or None if expired/invalid."""
        with get_db(self._db_path) as conn:
            row = conn.execute(
                "SELECT u.id, u.username, u.email, u.role, u.created_at "
                "FROM sessions s JOIN users u ON s.user_id = u.id "
                "WHERE s.token = ? AND s.expires_at > ?",
                (token, now_iso),
            ).fetchone()
        return dict(row) if row else None

    def delete_session(self, token: str) -> None:
        """Remove a session by its token."""
        with get_db(self._db_path) as conn:
            conn.execute(
                "DELETE FROM sessions WHERE token = ?", (token,)
            )
