"""Port for user/session persistence -- implemented by infrastructure."""

from abc import ABC, abstractmethod
from typing import Optional


class UserRepository(ABC):
    @abstractmethod
    def find_by_username_or_email(self, username: str, email: str) -> Optional[dict]: ...

    @abstractmethod
    def create_user(self, user_id: str, username: str, email: str,
                    password_hash: str, salt: str, role: str, created_at: str) -> None: ...

    @abstractmethod
    def find_by_username(self, username: str) -> Optional[dict]: ...

    @abstractmethod
    def create_session(self, token: str, user_id: str,
                       expires_at: str, created_at: str) -> None: ...

    @abstractmethod
    def get_session_user(self, token: str, now_iso: str) -> Optional[dict]: ...

    @abstractmethod
    def delete_session(self, token: str) -> None: ...
