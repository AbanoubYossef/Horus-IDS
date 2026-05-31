"""
tests/test_alert_router.py — Alert router severity escalation and syslog formatting

Tests cover:
  - Per-VLAN severity escalation (CRITICAL_VLANS, HIGH_VLANS)
  - Threshold filtering (ALERT_MIN_SEVERITY)
  - BENIGN flow suppression on non-critical VLANs
  - RFC 5424 message structure and SD-PARAM escaping
  - UDP syslog dispatch (socket mocked)
"""

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "capture"))

import config
import alert_router


# ══════════════════════════════════════════════════════════════════════════════
#  Severity escalation
# ══════════════════════════════════════════════════════════════════════════════

class TestBuildSyslog:

    def _result(self, **kwargs):
        base = {
            "id": "test-id",
            "attack_type": "PortScan",
            "confidence": 0.92,
            "is_attack": True,
            "severity": "medium",
            "group_pred": "PortScan",
            "src_ip": "192.168.10.5",
            "dst_ip": "10.13.1.1",
            "dst_port": 22,
            "vlan_id": 110,
        }
        base.update(kwargs)
        return base

    def test_valid_utf8_bytes(self):
        msg = alert_router._build_syslog(self._result(), "medium")
        assert isinstance(msg, bytes)
        msg.decode("utf-8")  # must not raise

    def test_starts_with_priority(self):
        msg = alert_router._build_syslog(self._result(), "medium").decode()
        assert msg.startswith("<")
        pri_end = msg.index(">")
        pri = int(msg[1:pri_end])
        assert 0 < pri < 192

    def test_rfc5424_version_field(self):
        msg = alert_router._build_syslog(self._result(), "critical").decode()
        assert ">1 " in msg

    def test_structured_data_contains_attack_type(self):
        msg = alert_router._build_syslog(self._result(), "medium").decode()
        assert 'attack_type="PortScan"' in msg

    def test_structured_data_contains_vlan(self):
        msg = alert_router._build_syslog(self._result(vlan_id=111), "high").decode()
        assert 'vlan_id="111"' in msg
        assert 'vlan_name="Finance-B1"' in msg

    def test_critical_priority_lower_number(self):
        crit = alert_router._build_syslog(self._result(), "critical").decode()
        info = alert_router._build_syslog(self._result(), "info").decode()
        crit_pri = int(crit[1:crit.index(">")])
        info_pri = int(info[1:info.index(">")])
        assert crit_pri < info_pri  # RFC 5424: lower number = higher severity

    def test_sd_param_escaping_quotes(self):
        result = self._result(attack_type='Test"Attack')
        msg = alert_router._build_syslog(result, "medium").decode()
        assert '\\"' in msg

    def test_sd_param_escaping_brackets(self):
        result = self._result(attack_type="Test]Attack")
        msg = alert_router._build_syslog(result, "medium").decode()
        assert "\\]" in msg

    def test_confidence_in_message(self):
        msg = alert_router._build_syslog(self._result(confidence=0.9876), "medium").decode()
        assert "confidence=" in msg

    def test_src_dst_in_message(self):
        msg = alert_router._build_syslog(self._result(), "medium").decode()
        assert "192.168.10.5" in msg
        assert "10.13.1.1" in msg


# ══════════════════════════════════════════════════════════════════════════════
#  dispatch() — full integration with socket mock
# ══════════════════════════════════════════════════════════════════════════════

class TestDispatch:

    def _attack_result(self, vlan_id=110, severity="medium", attack_type="PortScan"):
        return {
            "id": "test",
            "attack_type": attack_type,
            "confidence": 0.9,
            "is_attack": True,
            "severity": severity,
            "group_pred": attack_type,
            "src_ip": "10.10.1.5",
            "dst_ip": "10.13.1.1",
            "dst_port": 22,
            "vlan_id": vlan_id,
        }

    def test_attack_sends_syslog(self, monkeypatch):
        sent = []
        monkeypatch.setattr(alert_router, "_send_udp", lambda d, h, p: sent.append((d, h, p)))
        monkeypatch.setattr(config, "ALERT_MIN_SEVERITY", "medium")
        alert_router.dispatch(self._attack_result(vlan_id=110, severity="medium"))
        assert len(sent) == 1

    def test_benign_on_normal_vlan_suppressed(self, monkeypatch):
        sent = []
        monkeypatch.setattr(alert_router, "_send_udp", lambda d, h, p: sent.append((d, h, p)))
        benign = {
            "id": "x", "attack_type": "BENIGN", "confidence": 0.99,
            "is_attack": False, "severity": "info", "group_pred": "BENIGN",
            "src_ip": "10.10.1.1", "dst_ip": "10.20.0.1", "dst_port": 80,
            "vlan_id": 110,
        }
        alert_router.dispatch(benign)
        assert len(sent) == 0

    def test_benign_on_critical_vlan_sends(self, monkeypatch):
        sent = []
        monkeypatch.setattr(alert_router, "_send_udp", lambda d, h, p: sent.append((d, h, p)))
        monkeypatch.setattr(config, "ALERT_MIN_SEVERITY", "info")
        benign = {
            "id": "x", "attack_type": "BENIGN", "confidence": 0.99,
            "is_attack": False, "severity": "info", "group_pred": "BENIGN",
            "src_ip": "10.99.0.5", "dst_ip": "10.20.0.1", "dst_port": 80,
            "vlan_id": 99,
        }
        alert_router.dispatch(benign)
        assert len(sent) == 1

    def test_below_threshold_suppressed(self, monkeypatch):
        sent = []
        monkeypatch.setattr(alert_router, "_send_udp", lambda d, h, p: sent.append((d, h, p)))
        monkeypatch.setattr(config, "ALERT_MIN_SEVERITY", "critical")
        alert_router.dispatch(self._attack_result(vlan_id=110, severity="medium"))
        assert len(sent) == 0

    def test_vlan99_escalated_to_critical(self, monkeypatch):
        sent = []
        monkeypatch.setattr(alert_router, "_send_udp", lambda d, h, p: sent.append((d, h, p)))
        monkeypatch.setattr(config, "ALERT_MIN_SEVERITY", "medium")
        alert_router.dispatch(self._attack_result(vlan_id=99, severity="medium"))
        msg = sent[0][0].decode()
        assert "CRITICAL" in msg

    def test_syslog_sent_to_correct_server(self, monkeypatch):
        sent = []
        monkeypatch.setattr(alert_router, "_send_udp", lambda d, h, p: sent.append((d, h, p)))
        monkeypatch.setattr(config, "SYSLOG_SERVER", "10.40.0.20")
        monkeypatch.setattr(config, "SYSLOG_PORT", 514)
        monkeypatch.setattr(config, "ALERT_MIN_SEVERITY", "info")
        alert_router.dispatch(self._attack_result())
        assert sent[0][1] == "10.40.0.20"
        assert sent[0][2] == 514

    def test_socket_error_does_not_raise(self, monkeypatch):
        monkeypatch.setattr(alert_router, "_send_udp",
                            MagicMock(side_effect=OSError("network error")))
        alert_router.dispatch(self._attack_result(vlan_id=110))
