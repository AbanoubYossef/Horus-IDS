"""Prediction history and statistics use cases."""

from typing import Optional

from domain.ports.prediction_repository import PredictionRepository


class HistoryService:
    def __init__(self, repo: PredictionRepository):
        self._repo = repo

    def list_predictions(
        self, limit: int, offset: int,
        severity: Optional[str] = None,
        attack_only: bool = False,
    ) -> dict:
        results, total = self._repo.list_paginated(limit, offset, severity, attack_only)
        return {"total": total, "limit": limit, "offset": offset, "results": results}

    def get_stats(self, window: Optional[str] = None) -> dict:
        return self._repo.get_stats(window)

    def clear(self) -> dict:
        self._repo.clear_all()
        return {"status": "cleared"}

    def retain(self, days: int) -> dict:
        deleted = self._repo.retain(days)
        return {"status": "retained", "deleted": deleted, "retained_days": days}

    def get_db_stats(self) -> dict:
        return self._repo.get_db_stats()
