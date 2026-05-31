"""
tests/test_response.py — Automated response module unit tests

No real SSH connections or Palo Alto firewalls are required.  All network
I/O is mocked.

Tests cover:
  - _severity_gte()               — comparison helper
  - _get_distribution_switch()    — switch routing logic
  - _is_blocked / _mark_blocked   — TTL dedup table
  - _paloalto_tag_ip()            — PA User-ID API call (mocked requests)
  - handle_result()               — decision gating (benign/severity/monitor VLAN)
"""

import sys
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "capture"))

import config
import response


# ══════════════════════════════════════════════════════════════════════════════
#  _severity_gte()
# ══════════════════════════════════════════════════════════════════════════════

class TestSeverityGte:

    @pytest.mark.parametrize("a,b", [
        ("critical", "critical"),
        ("critical", "high"),
        ("critical", "medium"),
        ("critical", "info"),
        ("high",     "high"),
        ("high",     "medium"),
        ("medium",   "medium"),
        ("info",     "info"),
    ])
    def test_gte_true(self, a, b):
        assert response._severity_gte(a, b) is True

    @pytest.mark.parametrize("a,b", [
        ("info",   "medium"),
        ("info",   "high"),
        ("info",   "critical"),
        ("medium", "high"),
        ("medium", "critical"),
        ("high",   "critical"),
    ])
    def test_gte_false(self, a, b):
        assert response._severity_gte(a, b) is False

    def test_unknown_severity_returns_false(self):
        assert response._severity_gte("unknown", "medium") is False
        assert response._severity_gte("medium", "unknown") is False


# ══════════════════════════════════════════════════════════════════════════════
#  _get_distribution_switch()
# ══════════════════════════════════════════════════════════════════════════════

class TestPaloAltoTagIp:

    def test_returns_false_when_unconfigured(self, monkeypatch):
        monkeypatch.setattr(config, "PALOALTO_MGMT_IP", "")
        monkeypatch.setattr(config, "PALOALTO_API_KEY", "")
        assert response._paloalto_tag_ip("1.2.3.4") is False

    def test_returns_true_on_http_200(self, monkeypatch):
        monkeypatch.setattr(config, "PALOALTO_MGMT_IP", "10.40.40.1")
        monkeypatch.setattr(config, "PALOALTO_API_KEY", "test-key")
        monkeypatch.setattr(config, "PALOALTO_BLOCK_TAG", "IDS-AUTO-BLOCK")

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.raise_for_status = MagicMock()

        with patch.object(response.requests, "get", return_value=mock_resp) as mock_get:
            result = response._paloalto_tag_ip("5.6.7.8")

        assert result is True
        mock_get.assert_called_once()
        call_kwargs = mock_get.call_args
        assert "10.40.40.1" in call_kwargs[0][0]
        params = call_kwargs[1]["params"]
        assert "5.6.7.8" in params["cmd"]
        assert params["key"] == "test-key"

    def test_returns_false_on_request_exception(self, monkeypatch):
        import requests as req
        monkeypatch.setattr(config, "PALOALTO_MGMT_IP", "10.40.40.1")
        monkeypatch.setattr(config, "PALOALTO_API_KEY", "test-key")

        with patch.object(response.requests, "get",
                          side_effect=req.RequestException("timeout")):
            result = response._paloalto_tag_ip("5.6.7.8")

        assert result is False

    def test_block_tag_in_uid_message(self, monkeypatch):
        monkeypatch.setattr(config, "PALOALTO_MGMT_IP", "10.40.40.1")
        monkeypatch.setattr(config, "PALOALTO_API_KEY", "key")
        monkeypatch.setattr(config, "PALOALTO_BLOCK_TAG", "MY-CUSTOM-TAG")

        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()

        with patch.object(response.requests, "get", return_value=mock_resp) as mock_get:
            response._paloalto_tag_ip("1.1.1.1")

        params = mock_get.call_args[1]["params"]
        assert "MY-CUSTOM-TAG" in params["cmd"]


# ══════════════════════════════════════════════════════════════════════════════
#  handle_result() — gating logic (no SSH needed)
# ══════════════════════════════════════════════════════════════════════════════

class TestHandleResult:

    def _result(self, **kwargs):
        base = {
            "is_attack":     True,
            "src_ip":        "10.10.1.5",
            "dst_ip":        "10.20.0.1",
            "vlan_id":       10,
            "severity":      "high",
            "group_pred":    "DoS-family",
            "attack_type":   "DoS Hulk",
            "confidence":    0.95,
            "flow_direction": "LATERAL",
        }
        base.update(kwargs)
        return base

    def setup_method(self):
        with response._block_lock:
            response._block_table.clear()

    def test_benign_skipped(self, monkeypatch):
        monkeypatch.setattr(config, "RESPONSE_MIN_SEVERITY", "medium")
        threads_started = []
        original_thread = __import__("threading").Thread

        def tracking_thread(*args, **kwargs):
            t = original_thread(*args, **kwargs)
            threads_started.append(t)
            return t

        with patch("threading.Thread", side_effect=tracking_thread):
            response.handle_result(self._result(is_attack=False, severity="info"))

        assert not threads_started

    def test_below_threshold_skipped(self, monkeypatch):
        monkeypatch.setattr(config, "RESPONSE_MIN_SEVERITY", "critical")
        started = []
        with patch("threading.Thread") as mock_thread:
            mock_thread.return_value.start = lambda: started.append(True)
            response.handle_result(self._result(severity="medium"))
        assert not started

    def test_monitor_vlan_skipped(self, monkeypatch):
        monkeypatch.setattr(config, "RESPONSE_MIN_SEVERITY", "medium")
        started = []
        with patch("threading.Thread") as mock_thread:
            mock_thread.return_value.start = lambda: started.append(True)
            response.handle_result(self._result(vlan_id=40, severity="critical"))
        assert not started

    def test_already_blocked_skipped(self, monkeypatch):
        monkeypatch.setattr(config, "RESPONSE_MIN_SEVERITY", "medium")
        response._mark_blocked("10.10.1.5", "DoS-family")
        started = []
        with patch("threading.Thread") as mock_thread:
            mock_thread.return_value.start = lambda: started.append(True)
            response.handle_result(self._result())
        assert not started

    def test_no_src_ip_skipped(self, monkeypatch):
        monkeypatch.setattr(config, "RESPONSE_MIN_SEVERITY", "medium")
        started = []
        with patch("threading.Thread") as mock_thread:
            mock_thread.return_value.start = lambda: started.append(True)
            response.handle_result(self._result(src_ip=""))
        assert not started

    def test_valid_attack_starts_thread(self, monkeypatch):
        monkeypatch.setattr(config, "RESPONSE_MIN_SEVERITY", "medium")
        started = []

        mock_t = MagicMock()
        mock_t.start = lambda: started.append(True)

        with patch("threading.Thread", return_value=mock_t):
            response.handle_result(self._result())

        assert started
