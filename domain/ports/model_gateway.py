"""Port for ML model inference -- implemented by infrastructure."""

from abc import ABC, abstractmethod
from typing import Any


class ModelGateway(ABC):
    @abstractmethod
    def is_loaded(self) -> bool: ...

    @abstractmethod
    def predict_single(self, features_dict: dict, meta: dict | None = None) -> dict: ...

    @abstractmethod
    def predict_batch(self, feature_dicts: list[dict], metas: list[dict] | None = None) -> list[dict]: ...

    @abstractmethod
    def get_health_info(self) -> dict: ...

    @abstractmethod
    def get_classes(self) -> dict: ...

    @abstractmethod
    def get_features(self) -> dict: ...

    @abstractmethod
    def get_feature_rank(self) -> dict: ...
