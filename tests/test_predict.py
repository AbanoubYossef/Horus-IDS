"""
tests/test_api.py — FastAPI endpoint tests with mocked model

All tests use the `client` fixture from conftest.py which patches the api
module so no real model files are required.

Coverage:
  GET  /health
  GET  /classes
  GET  /features
  POST /predict            — BENIGN, attack, validation errors
  POST /predict/batch      — mixed results, size limit
  GET  /predictions        — pagination, filtering
  GET  /predictions/stats
  DELETE /predictions/clear
  POST /upload/csv         — with and without Label column
"""

import io
import json

import pytest


# ── Helpers ──────────────────────────────────────────────────────────────────

def _predict_payload(features, src_ip=None, dst_ip=None, dst_port=None, vlan_id=None):
    body = {"features_dict": features}
    if src_ip:   body["src_ip"]   = src_ip
    if dst_ip:   body["dst_ip"]   = dst_ip
    if dst_port: body["dst_port"] = dst_port
    if vlan_id:  body["vlan_id"]  = vlan_id
    return body


# ══════════════════════════════════════════════════════════════════════════════
#  POST /predict
# ══════════════════════════════════════════════════════════════════════════════

class TestPredict:

    def test_benign_prediction(self, client, benign_features):
        r = client.post("/predict", json=_predict_payload(benign_features))
        assert r.status_code == 200
        data = r.json()
        assert data["attack_type"] == "BENIGN"
        assert data["is_attack"] is False
        assert data["severity"] == "info"
        assert 0.0 <= data["confidence"] <= 1.0
        assert "id" in data
        assert "created_at" in data

    def test_attack_prediction(self, client, mock_model, syn_flood_features):
        mock_model.set_prediction("DDoS Volumetric", "DDoS-family")
        r = client.post("/predict", json=_predict_payload(
            syn_flood_features,
            src_ip="10.52.1.5",
            dst_ip="10.20.0.1",
            dst_port=80,
            vlan_id=52,
        ))
        assert r.status_code == 200
        data = r.json()
        assert data["attack_type"] == "DDoS Volumetric"
        assert data["is_attack"] is True
        assert data["severity"] == "critical"
        assert data["src_ip"] == "10.52.1.5"
        assert data["dst_ip"] == "10.20.0.1"
        assert data["vlan_id"] == 52

    def test_prediction_stored_in_db(self, client, benign_features):
        client.post("/predict", json=_predict_payload(benign_features))
        r = client.get("/predictions?limit=1")
        assert r.status_code == 200
        assert r.json()["total"] >= 1

    def test_empty_features_dict_accepted(self, client):
        """Empty dict defaults all features to 0 — should not 500."""
        r = client.post("/predict", json={"features_dict": {}})
        assert r.status_code == 200

    def test_missing_features_dict_rejected(self, client):
        r = client.post("/predict", json={"src_ip": "1.2.3.4"})
        assert r.status_code == 422

    def test_top_features_returned(self, client, benign_features):
        data = client.post("/predict", json=_predict_payload(benign_features)).json()
        assert isinstance(data["top_features"], list)
        assert len(data["top_features"]) > 0
        first = data["top_features"][0]
        assert "name" in first and "value" in first and "rank" in first

    def test_response_includes_group_pred(self, client, benign_features):
        data = client.post("/predict", json=_predict_payload(benign_features)).json()
        assert "group_pred" in data

    def test_inference_ms_positive(self, client, benign_features):
        data = client.post("/predict", json=_predict_payload(benign_features)).json()
        assert data["inference_ms"] >= 0


# ══════════════════════════════════════════════════════════════════════════════
#  POST /predict/batch
# ══════════════════════════════════════════════════════════════════════════════

class TestPredictBatch:

    def _make_batch(self, features_list, vlan_id=None):
        return [
            {"features_dict": f, "vlan_id": vlan_id}
            for f in features_list
        ]

    def test_batch_returns_all_results(self, client, benign_features):
        batch = self._make_batch([benign_features] * 5)
        r = client.post("/predict/batch", json=batch)
        assert r.status_code == 200
        data = r.json()
        assert data["total"] == 5
        assert len(data["results"]) == 5

    def test_batch_attack_count(self, client, mock_model, syn_flood_features):
        mock_model.set_prediction("DDoS Volumetric", "DDoS-family")
        batch = self._make_batch([syn_flood_features] * 3)
        data = client.post("/predict/batch", json=batch).json()
        assert data["attacks"] == 3
        assert data["benign"] == 0

    def test_batch_vlan_id_propagated(self, client, benign_features):
        batch = [{"features_dict": benign_features, "vlan_id": 11}]
        data = client.post("/predict/batch", json=batch).json()
        assert data["results"][0]["vlan_id"] == 11

    def test_batch_size_limit(self, client, benign_features):
        batch = self._make_batch([benign_features] * 501)
        r = client.post("/predict/batch", json=batch)
        assert r.status_code == 400
        assert "500" in r.json()["detail"]

    def test_single_item_batch(self, client, benign_features):
        batch = self._make_batch([benign_features])
        data = client.post("/predict/batch", json=batch).json()
        assert data["total"] == 1

    def test_inference_ms_positive(self, client, benign_features):
        batch = self._make_batch([benign_features] * 10)
        data = client.post("/predict/batch", json=batch).json()
        assert data["inference_ms"] >= 0


# ══════════════════════════════════════════════════════════════════════════════
#  GET /predictions
# ══════════════════════════════════════════════════════════════════════════════

class TestPredictions:

    def _seed(self, client, benign_features, n=5):
        for _ in range(n):
            client.post("/predict", json=_predict_payload(benign_features))

    def test_pagination_limit(self, client, benign_features):
        self._seed(client, benign_features, 5)
        r = client.get("/predictions?limit=2")
        assert r.status_code == 200
        data = r.json()
        assert len(data["results"]) <= 2

    def test_pagination_offset(self, client, benign_features):
        self._seed(client, benign_features, 6)
        page1 = client.get("/predictions?limit=3&offset=0").json()["results"]
        page2 = client.get("/predictions?limit=3&offset=3").json()["results"]
        ids1 = {r["id"] for r in page1}
        ids2 = {r["id"] for r in page2}
        assert ids1.isdisjoint(ids2), "Pages must not overlap"

    def test_filter_attack_only(self, client, mock_model, syn_flood_features, benign_features):
        mock_model.set_prediction("PortScan", "PortScan")
        client.post("/predict", json=_predict_payload(syn_flood_features))
        mock_model.set_prediction("BENIGN", "BENIGN")
        client.post("/predict", json=_predict_payload(benign_features))

        r = client.get("/predictions?attack_only=true")
        results = r.json()["results"]
        assert all(res["is_attack"] for res in results)

    def test_filter_by_severity(self, client, mock_model, syn_flood_features):
        mock_model.set_prediction("DDoS", "DDoS-family")
        client.post("/predict", json=_predict_payload(syn_flood_features))
        r = client.get("/predictions?severity=critical")
        results = r.json()["results"]
        assert all(res["severity"] == "critical" for res in results)

    def test_result_fields_present(self, client, benign_features):
        self._seed(client, benign_features, 1)
        result = client.get("/predictions?limit=1").json()["results"][0]
        for field in ["id", "attack_type", "confidence", "is_attack",
                      "severity", "created_at", "model"]:
            assert field in result, f"Missing field: {field}"

    def test_is_attack_is_bool(self, client, benign_features):
        self._seed(client, benign_features, 1)
        result = client.get("/predictions?limit=1").json()["results"][0]
        assert isinstance(result["is_attack"], bool)


# ══════════════════════════════════════════════════════════════════════════════
#  GET /predictions/stats
# ══════════════════════════════════════════════════════════════════════════════

class TestPredictionStats:

    def test_stats_structure(self, client, benign_features):
        client.post("/predict", json=_predict_payload(benign_features))
        r = client.get("/predictions/stats")
        assert r.status_code == 200
        data = r.json()
        for key in ["total_predictions", "total_attacks", "total_benign",
                    "avg_confidence", "by_severity", "by_attack_type", "recent"]:
            assert key in data, f"Missing stats key: {key}"

    def test_totals_consistent(self, client, benign_features):
        client.post("/predict", json=_predict_payload(benign_features))
        data = client.get("/predictions/stats").json()
        assert data["total_predictions"] == data["total_attacks"] + data["total_benign"]

    def test_avg_confidence_in_range(self, client, benign_features):
        client.post("/predict", json=_predict_payload(benign_features))
        data = client.get("/predictions/stats").json()
        assert 0.0 <= data["avg_confidence"] <= 1.0

    def test_recent_list_capped(self, client, benign_features):
        for _ in range(15):
            client.post("/predict", json=_predict_payload(benign_features))
        data = client.get("/predictions/stats").json()
        assert len(data["recent"]) <= 10


# ══════════════════════════════════════════════════════════════════════════════
#  DELETE /predictions/clear
# ══════════════════════════════════════════════════════════════════════════════

class TestClear:

    def test_clear_empties_db(self, client, benign_features):
        client.post("/predict", json=_predict_payload(benign_features))
        before = client.get("/predictions/stats").json()["total_predictions"]
        assert before > 0

        r = client.delete("/predictions/clear")
        assert r.status_code == 200

        after = client.get("/predictions/stats").json()["total_predictions"]
        assert after == 0


# ══════════════════════════════════════════════════════════════════════════════
#  POST /upload/csv
# ══════════════════════════════════════════════════════════════════════════════

class TestUploadCsv:

    def _make_csv(self, rows, include_label=True):
        import pandas as pd
        df = pd.DataFrame(rows)
        buf = io.StringIO()
        df.to_csv(buf, index=False)
        return buf.getvalue().encode()

    def test_csv_without_label(self, client, benign_features):
        csv_bytes = self._make_csv([benign_features] * 3, include_label=False)
        r = client.post(
            "/upload/csv",
            files={"file": ("test.csv", csv_bytes, "text/csv")},
        )
        assert r.status_code == 200
        data = r.json()
        assert data["total"] == 3
        assert data["accuracy"] is None

    def test_csv_with_label_computes_accuracy(self, client, benign_features):
        rows = [{**benign_features, "Label": "BENIGN"} for _ in range(4)]
        csv_bytes = self._make_csv(rows)
        r = client.post(
            "/upload/csv",
            files={"file": ("labelled.csv", csv_bytes, "text/csv")},
        )
        assert r.status_code == 200
        data = r.json()
        assert data["accuracy"] is not None
        assert 0.0 <= data["accuracy"] <= 1.0

    def test_csv_size_limit(self, client, benign_features):
        rows = [benign_features] * 10_001
        csv_bytes = self._make_csv(rows, include_label=False)
        r = client.post(
            "/upload/csv",
            files={"file": ("huge.csv", csv_bytes, "text/csv")},
        )
        assert r.status_code == 400

    def test_non_csv_rejected(self, client):
        r = client.post(
            "/upload/csv",
            files={"file": ("data.txt", b"not a csv", "text/plain")},
        )
        assert r.status_code == 400

    def test_results_stored_in_db(self, client, benign_features):
        before = client.get("/predictions/stats").json()["total_predictions"]
        csv_bytes = self._make_csv([benign_features] * 5, include_label=False)
        client.post(
            "/upload/csv",
            files={"file": ("test.csv", csv_bytes, "text/csv")},
        )
        after = client.get("/predictions/stats").json()["total_predictions"]
        assert after == before + 5


# ══════════════════════════════════════════════════════════════════════════════
#  Model-not-loaded (503) guard
# ══════════════════════════════════════════════════════════════════════════════

class TestModelNotLoaded:

    def test_predict_503_when_no_model(self, benign_features):
        from fastapi.testclient import TestClient
        from api.app import app
        from api import dependencies as deps
        from domain.exceptions import ModelNotLoadedError

        def _raise_not_loaded():
            raise ModelNotLoadedError("Model not loaded")

        app.dependency_overrides[deps.require_model] = _raise_not_loaded
        c = TestClient(app)
        r = c.post("/predict", json=_predict_payload(benign_features))
        assert r.status_code == 503
        app.dependency_overrides[deps.require_model] = lambda: None

    def test_batch_503_when_no_model(self, benign_features):
        from fastapi.testclient import TestClient
        from api.app import app
        from api import dependencies as deps
        from domain.exceptions import ModelNotLoadedError

        def _raise_not_loaded():
            raise ModelNotLoadedError("Model not loaded")

        app.dependency_overrides[deps.require_model] = _raise_not_loaded
        c = TestClient(app)
        r = c.post("/predict/batch", json=[{"features_dict": benign_features}])
        assert r.status_code == 503
        app.dependency_overrides[deps.require_model] = lambda: None
