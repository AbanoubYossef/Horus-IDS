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


