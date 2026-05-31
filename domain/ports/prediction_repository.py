"""Port for prediction persistence -- implemented by infrastructure."""

from abc import ABC, abstractmethod
from typing import Optional


class PredictionRepository(ABC):
    @abstractmethod
    def save(self, result: dict) -> None: ...

    @abstractmethod
    def save_many(self, results: list[dict]) -> None: ...

    @abstractmethod
    def list_paginated(
        self, limit: int, offset: int,
        severity: Optional[str] = None,
        attack_only: bool = False,
    ) -> tuple[list[dict], int]: ...

    @abstractmethod
    def get_stats(self, window: Optional[str] = None) -> dict: ...

    @abstractmethod
    def clear_all(self) -> None: ...

    @abstractmethod
    def retain(self, days: int) -> int: ...

    @abstractmethod
    def get_db_stats(self) -> dict: ...

    @abstractmethod
    def get_unalerted_attacks(self) -> list[dict]: ...
