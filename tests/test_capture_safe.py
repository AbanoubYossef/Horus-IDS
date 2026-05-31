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

class TestSafe:

    def test_returns_float(self):
        flow = _flow(bidirectional_duration_ms=500.0)
        assert flow_capture._safe(flow, "bidirectional_duration_ms") == 500.0

    def test_missing_field_returns_default(self):
        flow = SimpleNamespace()
        assert flow_capture._safe(flow, "nonexistent", 42.0) == 42.0

    def test_none_field_returns_default(self):
        flow = SimpleNamespace(some_field=None)
        assert flow_capture._safe(flow, "some_field", 7.0) == 7.0

    def test_nan_returns_default(self):
        import math
        flow = SimpleNamespace(val=float("nan"))
        assert flow_capture._safe(flow, "val", 0.0) == 0.0

    def test_zero_is_valid(self):
        flow = SimpleNamespace(val=0.0)
        assert flow_capture._safe(flow, "val", 99.0) == 0.0


# ══════════════════════════════════════════════════════════════════════════════
#  _map_flow() — field correctness
# ══════════════════════════════════════════════════════════════════════════════

