"""
tests/test_flow_capture.py — nfstream field mapping and batcher logic

nfstream is NOT required for these tests.  We mock nfstream Flow objects
using a simple namespace so every test runs offline.

Tests cover:
  - _map_flow() field mapping: ms→µs conversion, flag aggregation, defaults
  - Degenerate flow rejection (zero packets)
  - Feature name alignment with CICFlowMeter convention
  - FlowBatcher: batching by size, batching by timeout
"""

import struct
import socket
import sys
import time
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch, call
import threading

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "capture"))
import flow_capture


# ══════════════════════════════════════════════════════════════════════════════
#  Mock nfstream flow builder
# ══════════════════════════════════════════════════════════════════════════════

def _flow(**kwargs):
    """Build a minimal mock nfstream flow with sensible defaults."""
    defaults = {
        "bidirectional_duration_ms":  1000.0,
        "src2dst_packets":             10.0,
        "dst2src_packets":              8.0,
        "src2dst_bytes":             3200.0,
        "dst2src_bytes":             2400.0,
        "src2dst_max_ps":            1460.0,
        "src2dst_min_ps":              40.0,
        "src2dst_mean_ps":            320.0,
        "src2dst_stddev_ps":          280.0,
        "dst2src_max_ps":            1460.0,
        "dst2src_min_ps":              40.0,
        "dst2src_mean_ps":            300.0,
        "dst2src_stddev_ps":          260.0,
        "bidirectional_min_ps":        40.0,
        "bidirectional_max_ps":      1460.0,
        "bidirectional_mean_ps":      311.0,
        "bidirectional_stddev_ps":    270.0,
        "bidirectional_mean_piat_ms":  55.0,
        "bidirectional_stddev_piat_ms": 10.0,
        "bidirectional_max_piat_ms":  200.0,
        "bidirectional_min_piat_ms":    1.0,
        "src2dst_duration_ms":        950.0,
        "src2dst_mean_piat_ms":       105.0,
        "src2dst_stddev_piat_ms":      15.0,
        "src2dst_max_piat_ms":        300.0,
        "src2dst_min_piat_ms":          2.0,
        "dst2src_duration_ms":        900.0,
        "dst2src_mean_piat_ms":       128.0,
        "dst2src_stddev_piat_ms":      14.0,
        "dst2src_max_piat_ms":        280.0,
        "dst2src_min_piat_ms":          1.5,
        "src2dst_syn_packets":          1.0,
        "dst2src_syn_packets":          1.0,
        "src2dst_ack_packets":          9.0,
        "dst2src_ack_packets":          7.0,
        "src2dst_fin_packets":          1.0,
        "dst2src_fin_packets":          1.0,
        "src2dst_rst_packets":          0.0,
        "dst2src_rst_packets":          0.0,
        "src2dst_psh_packets":          3.0,
        "dst2src_psh_packets":          2.0,
        "src2dst_urg_packets":          0.0,
        "dst2src_urg_packets":          0.0,
        "src2dst_ece_packets":          0.0,
        "dst2src_ece_packets":          0.0,
        "protocol":                     6,   # TCP
        "vlan_id":                     10,
        "src_ip":               "192.168.10.5",
        "dst_ip":               "10.20.0.1",
        "dst_port":                    80,
    }
    defaults.update(kwargs)
    return SimpleNamespace(**defaults)


# ══════════════════════════════════════════════════════════════════════════════
#  _safe()
# ══════════════════════════════════════════════════════════════════════════════

class TestFlowBatcher:

    def _make_item(self, attack_type="BENIGN", vlan_id=10):
        return {
            "features_dict": {"Flow Duration": 1000.0},
            "src_ip": "10.10.0.1",
            "dst_ip": "10.20.0.1",
            "dst_port": 80,
            "vlan_id": vlan_id,
        }

    def test_flushes_on_batch_size(self, monkeypatch):
        import config
        monkeypatch.setattr(config, "BATCH_SIZE", 5)
        monkeypatch.setattr(config, "BATCH_TIMEOUT_S", 30.0)  # long timeout

        flushed = []
        monkeypatch.setattr(flow_capture, "_post_batch",
                            lambda batch: (flushed.append(len(batch)), {"results": [], "attacks": 0})[1])

        batcher = flow_capture.FlowBatcher()
        batcher.start()
        for _ in range(5):
            batcher.submit(self._make_item())

        # Wait for flush
        deadline = time.time() + 3.0
        while not flushed and time.time() < deadline:
            time.sleep(0.05)

        assert flushed, "Batcher should have flushed on BATCH_SIZE=5"
        assert flushed[0] == 5

    def test_flushes_on_timeout(self, monkeypatch):
        import config
        monkeypatch.setattr(config, "BATCH_SIZE", 100)
        monkeypatch.setattr(config, "BATCH_TIMEOUT_S", 0.2)

        flushed = []
        monkeypatch.setattr(flow_capture, "_post_batch",
                            lambda batch: (flushed.append(len(batch)), {"results": [], "attacks": 0})[1])

        batcher = flow_capture.FlowBatcher()
        batcher.start()
        batcher.submit(self._make_item())

        time.sleep(0.5)  # wait longer than timeout

        assert flushed, "Batcher should have flushed on timeout"
        assert flushed[0] == 1

    def test_no_flush_on_empty_queue(self, monkeypatch):
        import config
        monkeypatch.setattr(config, "BATCH_TIMEOUT_S", 0.1)

        flushed = []
        monkeypatch.setattr(flow_capture, "_post_batch",
                            lambda batch: (flushed.append(len(batch)), {"results": [], "attacks": 0})[1])

        batcher = flow_capture.FlowBatcher()
        batcher.start()
        time.sleep(0.3)  # nothing submitted

        assert not flushed, "Should not flush when queue is empty"

    def test_handle_result_called_per_prediction(self, monkeypatch):
        import config
        monkeypatch.setattr(config, "BATCH_SIZE", 1)
        monkeypatch.setattr(config, "BATCH_TIMEOUT_S", 30.0)

        handled = []
        mock_response = {
            "results": [{"attack_type": "BENIGN", "is_attack": False,
                         "severity": "info", "confidence": 0.99,
                         "group_pred": "BENIGN", "src_ip": "", "dst_ip": "",
                         "dst_port": 0}],
            "attacks": 0,
        }
        monkeypatch.setattr(flow_capture, "_post_batch", lambda batch: mock_response)
        monkeypatch.setattr(flow_capture, "dispatch", lambda r: None)
        monkeypatch.setattr(flow_capture, "handle_result", lambda r: handled.append(r))

        batcher = flow_capture.FlowBatcher()
        batcher.start()
        batcher.submit(self._make_item())

        deadline = time.time() + 3.0
        while not handled and time.time() < deadline:
            time.sleep(0.05)

        assert handled, "handle_result should have been called"

    def test_vlan_id_propagated_to_dispatch(self, monkeypatch):
        import config
        monkeypatch.setattr(config, "BATCH_SIZE", 1)
        monkeypatch.setattr(config, "BATCH_TIMEOUT_S", 30.0)

        dispatched = []
        mock_response = {
            "results": [{"attack_type": "BENIGN", "is_attack": False,
                         "severity": "info", "confidence": 0.99,
                         "group_pred": "BENIGN", "src_ip": "", "dst_ip": "",
                         "dst_port": 0}],
            "attacks": 0,
        }
        monkeypatch.setattr(flow_capture, "_post_batch", lambda batch: mock_response)
        monkeypatch.setattr(flow_capture, "dispatch", lambda r: dispatched.append(r))

        batcher = flow_capture.FlowBatcher()
        batcher.start()
        batcher.submit(self._make_item(vlan_id=52))

        deadline = time.time() + 3.0
        while not dispatched and time.time() < deadline:
            time.sleep(0.05)

        assert dispatched
        assert dispatched[0]["vlan_id"] == 52


# ══════════════════════════════════════════════════════════════════════════════
#  get_flow_direction()
# ══════════════════════════════════════════════════════════════════════════════

