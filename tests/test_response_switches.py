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

class TestGetDistributionSwitch:

    @pytest.mark.parametrize("src_ip, expected", [
        ("10.10.1.5",  "10.99.1.1"),   # VLAN 10, building 1 → Dis SW1
        ("10.11.2.10", "10.99.2.1"),   # VLAN 11, building 2 → Dis SW2
        ("10.51.3.7",  "10.99.3.1"),   # VLAN 51 (Guest-WiFi), building 3
        ("10.52.4.20", "10.99.4.1"),   # VLAN 52 (IoT), building 4
        ("10.20.0.1",  "10.99.0.252"), # App Server VLAN → Core SW1
        ("10.21.0.1",  "10.99.0.252"), # File Server VLAN → Core SW1
        ("10.30.0.1",  "10.99.0.252"), # Database VLAN → Core SW1
    ])
    def test_known_vlans(self, src_ip, expected):
        assert response._get_distribution_switch(src_ip) == expected

    def test_building_zero_out_of_range(self):
        assert response._get_distribution_switch("10.10.0.5") is None

    def test_management_vlan_returns_none(self):
        assert response._get_distribution_switch("10.99.0.1") is None

    def test_non_10_octet_returns_none(self):
        assert response._get_distribution_switch("192.168.1.1") is None

    def test_external_ip_returns_none(self):
        assert response._get_distribution_switch("8.8.8.8") is None

    def test_malformed_ip_returns_none(self):
        assert response._get_distribution_switch("not.an.ip") is None


# ══════════════════════════════════════════════════════════════════════════════
#  _is_blocked / _mark_blocked  (TTL dedup table)
# ══════════════════════════════════════════════════════════════════════════════

class TestBlockTable:

    def setup_method(self):
        """Clear the block table before each test."""
        with response._block_lock:
            response._block_table.clear()

    def test_new_ip_not_blocked(self):
        assert response._is_blocked("1.2.3.4") is False

    def test_marked_ip_is_blocked(self):
        response._mark_blocked("1.2.3.4")
        assert response._is_blocked("1.2.3.4") is True

    def test_different_ip_not_blocked(self):
        response._mark_blocked("1.2.3.4")
        assert response._is_blocked("5.6.7.8") is False

    def test_expired_ttl_clears_block(self, monkeypatch):
        monkeypatch.setattr(config, "RESPONSE_BLOCK_TTL", 0)
        response._mark_blocked("1.2.3.4")
        time.sleep(0.01)  # let the TTL expire
        assert response._is_blocked("1.2.3.4") is False


# ══════════════════════════════════════════════════════════════════════════════
#  _paloalto_tag_ip()
# ══════════════════════════════════════════════════════════════════════════════

