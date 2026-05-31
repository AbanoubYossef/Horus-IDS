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

class TestEscalateSeverity:

    @pytest.mark.parametrize("vlan_id", [99, 30, 40, 151, 251, 351, 451, 152, 252, 352, 452])
    def test_critical_vlans_always_escalate(self, vlan_id):
        assert alert_router._escalate_severity("info", vlan_id) == "critical"
        assert alert_router._escalate_severity("medium", vlan_id) == "critical"
        assert alert_router._escalate_severity("high", vlan_id) == "critical"
        assert alert_router._escalate_severity("critical", vlan_id) == "critical"

    @pytest.mark.parametrize("vlan_id", [111, 211, 311, 411, 112, 212, 113, 20, 21, 60])
    def test_high_vlans_escalate_medium_to_high(self, vlan_id):
        assert alert_router._escalate_severity("medium", vlan_id) == "high"

    @pytest.mark.parametrize("vlan_id", [111, 211, 311, 411, 112, 212, 113, 20, 21, 60])
    def test_high_vlans_dont_downgrade_critical(self, vlan_id):
        assert alert_router._escalate_severity("critical", vlan_id) == "critical"

    @pytest.mark.parametrize("vlan_id", [111, 211, 311, 411, 112, 212, 113, 20, 21, 60])
    def test_high_vlans_dont_downgrade_high(self, vlan_id):
        assert alert_router._escalate_severity("high", vlan_id) == "high"

    @pytest.mark.parametrize("vlan_id", [110, 210, 310, 410, 150, 250])
    def test_regular_vlans_unchanged(self, vlan_id):
        assert alert_router._escalate_severity("medium", vlan_id) == "medium"
        assert alert_router._escalate_severity("info", vlan_id) == "info"

    def test_unknown_vlan_unchanged(self):
        assert alert_router._escalate_severity("high", 999) == "high"


# ══════════════════════════════════════════════════════════════════════════════
#  Threshold filtering
# ══════════════════════════════════════════════════════════════════════════════

class TestAboveThreshold:

    def test_critical_above_medium_threshold(self, monkeypatch):
        monkeypatch.setattr(config, "ALERT_MIN_SEVERITY", "medium")
        assert alert_router._above_threshold("critical") is True
        assert alert_router._above_threshold("high") is True
        assert alert_router._above_threshold("medium") is True
        assert alert_router._above_threshold("info") is False

    def test_all_above_info_threshold(self, monkeypatch):
        monkeypatch.setattr(config, "ALERT_MIN_SEVERITY", "info")
        for sev in ["info", "medium", "high", "critical"]:
            assert alert_router._above_threshold(sev) is True

    def test_only_critical_above_critical_threshold(self, monkeypatch):
        monkeypatch.setattr(config, "ALERT_MIN_SEVERITY", "critical")
        assert alert_router._above_threshold("critical") is True
        assert alert_router._above_threshold("high") is False
        assert alert_router._above_threshold("medium") is False
        assert alert_router._above_threshold("info") is False


# ══════════════════════════════════════════════════════════════════════════════
#  VLAN name lookup
# ══════════════════════════════════════════════════════════════════════════════

class TestVlanName:

    @pytest.mark.parametrize("vlan_id, expected", [
        (110, "General-Users-B1"),
        (210, "General-Users-B2"),
        (111, "Finance-B1"),
        (311, "Finance-B3"),
        (112, "HR-B1"),
        (413, "IT-Admin-B4"),
        (20,  "App-Servers"),
        (21,  "File-Servers"),
        (30,  "Database"),
        (40,  "Security-Systems"),
        (150, "VoIP-B1"),
        (251, "Guest-WiFi-B2"),
        (352, "IoT-B3"),
        (60,  "DMZ"),
        (99,  "OOB-Management"),
        (199, "Management-B1"),
        (499, "Management-B4"),
    ])
    def test_known_vlans(self, vlan_id, expected):
        assert alert_router._vlan_name(vlan_id) == expected

    def test_unknown_vlan_fallback(self):
        assert alert_router._vlan_name(700) == "VLAN700"


# ══════════════════════════════════════════════════════════════════════════════
#  RFC 5424 message structure
# ══════════════════════════════════════════════════════════════════════════════

