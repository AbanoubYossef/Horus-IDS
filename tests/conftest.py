"""tests/conftest.py — Shared fixtures and mocks for the test suite."""

import json
import sys
import uuid
from pathlib import Path
from datetime import datetime, timezone
from contextlib import contextmanager
from unittest.mock import MagicMock

import numpy as np
import pytest
import sqlite3

# Make project root importable
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "capture"))

FIXTURES = PROJECT_ROOT / "tests" / "fixtures"


# ── Raw flow fixtures ─────────────────────────────────────────────────────────

@pytest.fixture(scope="session")
def sample_flows():
    with open(FIXTURES / "sample_flows.json") as f:
        return json.load(f)


@pytest.fixture(scope="session")
def benign_features(sample_flows):
    return sample_flows["benign"]


@pytest.fixture(scope="session")
def syn_flood_features(sample_flows):
    return sample_flows["syn_flood"]


@pytest.fixture(scope="session")
def port_scan_features(sample_flows):
    return sample_flows["port_scan"]


@pytest.fixture(scope="session")
def feature_names(benign_features):
    return list(benign_features.keys())


# ── Mock classes for Clean Architecture DI ────────────────────────────────────

ALL_CLASSES = [
    "BENIGN", "Bot", "DDoS", "DDoS Amplification", "DDoS Volumetric",
    "DoS GoldenEye", "DoS Hulk", "DoS Slow",
    "FTP-Patator", "PortScan", "SSH-Patator",
]

GROUPS = {
    "BENIGN":      ["BENIGN"],
    "DDoS-family": ["DDoS", "DDoS Amplification", "DDoS Volumetric"],
    "DoS-family":  ["DoS GoldenEye", "DoS Hulk", "DoS Slow"],
    "Brute-force": ["FTP-Patator", "SSH-Patator"],
    "PortScan":    ["PortScan"],
    "Bot":         ["Bot"],
}

SEVERITY_MAP = {
    "BENIGN": "info", "DDoS": "critical", "DoS GoldenEye": "critical",
    "DoS Hulk": "critical", "DoS Slow": "critical", "PortScan": "medium",
    "Bot": "high", "FTP-Patator": "medium", "SSH-Patator": "medium",
    "DDoS Amplification": "critical", "DDoS SYN Flood": "critical",
    "DDoS UDP Flood": "critical", "DDoS Volumetric": "critical",
}


class MockModelGateway:
    """In-memory mock that implements the ModelGateway interface."""

    def __init__(self, feature_names, predictions):
        self._feature_names = feature_names
        self._predictions = predictions

    def is_loaded(self):
        return True

    def predict_single(self, features_dict, meta=None):
        label = self._predictions["fine"]
        return {
            "id": str(uuid.uuid4()),
            "attack_type": label,
            "confidence": 0.95,
            "is_attack": label != "BENIGN",
            "severity": SEVERITY_MAP.get(label, "medium"),
            "group_pred": self._predictions["group"],
            "probabilities": {label: 0.95},
            "top_features": [
                {"name": self._feature_names[i], "value": 0.0, "rank": i}
                for i in range(min(6, len(self._feature_names)))
            ],
            "inference_ms": 1.23,
            "model": "Hierarchical 11-class (98.70% F1)",
            "created_at": datetime.now(timezone.utc).isoformat(),
            **(meta or {}),
        }

    def predict_batch(self, feature_dicts, metas=None):
        results = []
        for i in range(len(feature_dicts)):
            m = metas[i] if metas else None
            results.append(self.predict_single(feature_dicts[i], m))
        return results

    def get_health_info(self):
        return {
            "status": "ready",
            "model": "Hierarchical 11-class (Optuna XGBoost + 20 engineered features)",
            "architecture": {
                "level1": f"{len(GROUPS)} groups",
                "level2": [k for k in GROUPS if len(GROUPS[k]) > 1],
                "classes": len(ALL_CLASSES),
            },
            "classes": ALL_CLASSES,
            "features": len(self._feature_names),
            "performance": {},
        }

    def get_classes(self):
        return {
            "classes": ALL_CLASSES,
            "count": len(ALL_CLASSES),
            "groups": GROUPS,
            "severity_map": SEVERITY_MAP,
        }

    def get_features(self):
        rank = {f: i + 1 for i, f in enumerate(self._feature_names)}
        top30 = sorted(rank.items(), key=lambda x: x[1])[:30]
        return {
            "total": len(self._feature_names),
            "feature_names": list(self._feature_names),
            "top_30": [{"name": n, "rank": r} for n, r in top30],
        }

    def get_feature_rank(self):
        return {f: i + 1 for i, f in enumerate(self._feature_names)}


@pytest.fixture
def mock_model(feature_names, tmp_path):
    """Override DI dependencies so tests run without real models or DB files."""
    db_path = tmp_path / "test_horus.db"

    predictions = {"fine": "BENIGN", "group": "BENIGN"}
    mock_gateway = MockModelGateway(feature_names, predictions)

    from infrastructure.persistence.database import init_db, get_db
    from infrastructure.persistence.prediction_repository import SqlitePredictionRepository
    from infrastructure.persistence.user_repository import SqliteUserRepository
    from infrastructure.persistence.alert_repository import SqliteAlertRepository
    from infrastructure.websocket.manager import ConnectionManager
    from infrastructure.external.groq_client import GroqClient
    from application.services.prediction_service import PredictionService
    from application.services.history_service import HistoryService
    from application.services.auth_service import AuthService
    from application.services.alert_service import AlertService
    from application.services.analytics_service import AnalyticsService
    from application.services.ai_service import AiService
    from application.services.info_service import InfoService
    from data_utils import LABEL_MERGE, LABEL_MERGE_11CLASS, DATA_DIR

    init_db(db_path)

    pred_repo = SqlitePredictionRepository(db_path)
    user_repo = SqliteUserRepository(db_path)
    alert_repo = SqliteAlertRepository(db_path)
    ws = ConnectionManager()
    groq = GroqClient(api_key="", api_url="", model="test")

    from api.app import app
    from api import dependencies as deps

    app.dependency_overrides[deps.get_model_gateway] = lambda: mock_gateway
    app.dependency_overrides[deps.get_prediction_repo] = lambda: pred_repo
    app.dependency_overrides[deps.get_user_repo] = lambda: user_repo
    app.dependency_overrides[deps.get_alert_repo] = lambda: alert_repo
    app.dependency_overrides[deps.get_ws_manager] = lambda: ws
    app.dependency_overrides[deps.get_groq_client] = lambda: groq

    app.dependency_overrides[deps.get_prediction_service] = lambda: PredictionService(
        mock_gateway, pred_repo, LABEL_MERGE, LABEL_MERGE_11CLASS,
    )
    app.dependency_overrides[deps.get_history_service] = lambda: HistoryService(pred_repo)
    app.dependency_overrides[deps.get_auth_service] = lambda: AuthService(user_repo)
    app.dependency_overrides[deps.get_alert_service] = lambda: AlertService(alert_repo, pred_repo)
    app.dependency_overrides[deps.get_analytics_service] = lambda: AnalyticsService(pred_repo)
    app.dependency_overrides[deps.get_ai_service] = lambda: AiService(groq, pred_repo)

    info_svc = InfoService(mock_gateway, DATA_DIR, LABEL_MERGE, LABEL_MERGE_11CLASS)
    app.dependency_overrides[deps.get_info_service] = lambda: info_svc

    app.dependency_overrides[deps.require_model] = lambda: None

    ns = MagicMock()
    ns.predictions = predictions

    def set_prediction(fine, group=None):
        predictions["fine"] = fine
        predictions["group"] = group or fine

    ns.set_prediction = set_prediction

    yield ns

    app.dependency_overrides.clear()


@pytest.fixture
def client(mock_model):
    """FastAPI TestClient with all dependencies mocked via DI overrides."""
    from fastapi.testclient import TestClient
    from api.app import app
    return TestClient(app)
