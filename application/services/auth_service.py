"""Auth logic: register, login, logout, sessions."""

import hashlib
import secrets
from datetime import datetime, timezone, timedelta
from typing import Optional

from domain.exceptions import (
    UserAlreadyExistsError, InvalidCredentialsError,
    AuthenticationRequiredError,
)
from domain.ports.user_repository import UserRepository


class AuthService:
    def __init__(self, repo: UserRepository):
        self._repo = repo

    @staticmethod
    def _hash_password(password: str, salt: str | None = None) -> tuple[str, str]:
        if salt is None:
            salt = secrets.token_hex(16)
        hashed = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100_000)
        return hashed.hex(), salt

    @staticmethod
    def _verify_password(password: str, hashed: str, salt: str) -> bool:
        computed, _ = AuthService._hash_password(password, salt)
        return secrets.compare_digest(computed, hashed)

    def register(self, user_id: str, username: str, email: str,
                 password: str, role: str, now: str) -> dict:
        existing = self._repo.find_by_username_or_email(username, email)
        if existing:
            raise UserAlreadyExistsError("Username or email already exists")

        pwd_hash, salt = self._hash_password(password)
        self._repo.create_user(user_id, username, email, pwd_hash, salt, role, now)
        return {
            "user": {
                "id": user_id, "username": username, "email": email,
                "role": role, "created_at": now,
            }
        }

    def login(self, username: str, password: str) -> tuple[dict, str]:
        user = self._repo.find_by_username(username)
        if not user:
            raise InvalidCredentialsError("Invalid username or password")

        if not self._verify_password(password, user["password_hash"], user["salt"]):
            raise InvalidCredentialsError("Invalid username or password")

        token = secrets.token_hex(32)
        expires_at = (datetime.now(timezone.utc) + timedelta(days=7)).isoformat()
        now = datetime.now(timezone.utc).isoformat()
        self._repo.create_session(token, user["id"], expires_at, now)

        user_info = {k: user[k] for k in ("id", "username", "email", "role", "created_at")}
        return user_info, token

    def logout(self, token: Optional[str]) -> None:
        if token:
            self._repo.delete_session(token)

    def get_current_user(self, token: Optional[str]) -> Optional[dict]:
        if not token:
            return None
        now = datetime.now(timezone.utc).isoformat()
        return self._repo.get_session_user(token, now)

    def require_user(self, token: Optional[str]) -> dict:
        user = self.get_current_user(token)
        if not user:
            raise AuthenticationRequiredError("Authentication required")
        return user

