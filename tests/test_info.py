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
#  /health
# ══════════════════════════════════════════════════════════════════════════════

class TestHealth:

    def test_returns_ready(self, client):
        r = client.get("/health")
        assert r.status_code == 200
        assert r.json()["status"] == "ready"

    def test_contains_performance_fields(self, client):
        data = client.get("/health").json()
        assert "model" in data
        assert "architecture" in data
        assert "features" in data


# ══════════════════════════════════════════════════════════════════════════════
#  /classes
# ══════════════════════════════════════════════════════════════════════════════

class TestClasses:

    def test_returns_11_classes(self, client):
        r = client.get("/classes")
        assert r.status_code == 200
        data = r.json()
        assert data["count"] == 11

    def test_benign_in_classes(self, client):
        classes = client.get("/classes").json()["classes"]
        assert "BENIGN" in classes

    def test_severity_map_present(self, client):
        sev = client.get("/classes").json()["severity_map"]
        assert sev["DDoS"] == "critical"
        assert sev["BENIGN"] == "info"
        assert sev["PortScan"] == "medium"


# ══════════════════════════════════════════════════════════════════════════════
#  /features
# ══════════════════════════════════════════════════════════════════════════════

class TestFeatures:

    def test_returns_feature_list(self, client, feature_names):
        r = client.get("/features")
        assert r.status_code == 200
        data = r.json()
        assert data["total"] == len(feature_names)
        assert isinstance(data["feature_names"], list)

    def test_top30_length(self, client):
        top30 = client.get("/features").json()["top_30"]
        assert len(top30) <= 30
        assert all("name" in f and "rank" in f for f in top30)


