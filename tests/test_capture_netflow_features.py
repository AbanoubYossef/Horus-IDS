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

# ══════════════════════════════════════════════════════════════════════════════
#  _netflow_record_to_features() — unidirectional (v5) and bidirectional (v9)
# ══════════════════════════════════════════════════════════════════════════════

def _nf_rec(**kwargs):
    """Build a minimal NetFlow record dict with sensible defaults."""
    defaults = {
        "src_ip":      "10.10.0.1",
        "dst_ip":      "10.20.0.1",
        "src_port":    54321,
        "dst_port":    80,
        "pkts":        100,
        "octets":      120_000,
        "out_pkts":    0,
        "out_octets":  0,
        "duration_ms": 1000,
        "proto":       6,
        "tcp_flags":   0x02,   # SYN only
        "vlan_id":     10,
    }
    defaults.update(kwargs)
    return defaults




class TestNetflowRecordToFeatures:

    def test_returns_dict(self):
        assert isinstance(flow_capture._netflow_record_to_features(_nf_rec()), dict)

    def test_unidirectional_bwd_fields_zero(self):
        r = flow_capture._netflow_record_to_features(_nf_rec(out_pkts=0, out_octets=0))
        assert r["Total Backward Packets"] == 0.0
        assert r["Total Length of Bwd Packets"] == 0.0
        assert r["Bwd Packets/s"] == 0.0
        assert r["Bwd Header Length"] == 0.0

    def test_bidirectional_bwd_fields_populated(self):
        r = flow_capture._netflow_record_to_features(_nf_rec(out_pkts=50, out_octets=60_000))
        assert r["Total Backward Packets"] == 50.0
        assert r["Total Length of Bwd Packets"] == 60_000.0
        assert r["Bwd Packets/s"] > 0
        assert r["Bwd Header Length"] == pytest.approx(40.0 * 50)   # TCP

    def test_bidirectional_flow_bytes_uses_both_directions(self):
        r = flow_capture._netflow_record_to_features(_nf_rec(
            pkts=100, octets=120_000, out_pkts=50, out_octets=60_000, duration_ms=1000,
        ))
        assert r["Flow Bytes/s"] == pytest.approx((120_000 + 60_000) / 1.0)
        assert r["Flow Packets/s"] == pytest.approx((100 + 50) / 1.0)

    def test_duration_ms_to_us(self):
        r = flow_capture._netflow_record_to_features(_nf_rec(duration_ms=500))
        assert r["Flow Duration"] == pytest.approx(500_000.0)

    def test_syn_flag_extracted(self):
        r = flow_capture._netflow_record_to_features(_nf_rec(tcp_flags=0x02))
        assert r["SYN Flag Count"] == 1.0
        assert r["ACK Flag Count"] == 0.0

    def test_tcp_bwd_header_length(self):
        r = flow_capture._netflow_record_to_features(_nf_rec(
            proto=6, pkts=10, octets=5000, out_pkts=8, out_octets=3000,
        ))
        assert r["Fwd Header Length"] == pytest.approx(40.0 * 10)
        assert r["Bwd Header Length"] == pytest.approx(40.0 * 8)

    def test_udp_bwd_header_length(self):
        r = flow_capture._netflow_record_to_features(_nf_rec(
            proto=17, pkts=10, octets=5000, out_pkts=5, out_octets=2500,
        ))
        assert r["Fwd Header Length"] == pytest.approx(28.0 * 10)
        assert r["Bwd Header Length"] == pytest.approx(28.0 * 5)

    def test_zero_duration_no_division_error(self):
        import math
        r = flow_capture._netflow_record_to_features(_nf_rec(duration_ms=0))
        for k, v in r.items():
            assert math.isfinite(v), f"{k}={v} is not finite for zero-duration record"

    def test_all_values_finite(self):
        import math
        r = flow_capture._netflow_record_to_features(_nf_rec(out_pkts=30, out_octets=9000))
        for k, v in r.items():
            assert math.isfinite(v), f"{k}={v} is not finite"

    def test_subflow_mirrors_totals(self):
        r = flow_capture._netflow_record_to_features(_nf_rec(
            pkts=100, octets=120_000, out_pkts=50, out_octets=60_000,
        ))
        assert r["Subflow Fwd Packets"] == r["Total Fwd Packets"]
        assert r["Subflow Fwd Bytes"]   == r["Total Length of Fwd Packets"]
        assert r["Subflow Bwd Packets"] == r["Total Backward Packets"]
        assert r["Subflow Bwd Bytes"]   == r["Total Length of Bwd Packets"]


# ══════════════════════════════════════════════════════════════════════════════
#  NetFlow v5 parser
# ══════════════════════════════════════════════════════════════════════════════

def _build_nf5_packet(records):
    """Build a minimal NetFlow v5 UDP payload from a list of record dicts."""
    count = len(records)
    # Header: version=5, count, uptime=0, unix_secs=0, nsecs=0, seq=0, engine_type=0,
    #         engine_id=0, sample_interval=0
    header = struct.pack(">HHIIIIBBH", 5, count, 0, 0, 0, 0, 0, 0, 0)
    body = b""
    for rec in records:
        src = socket.inet_aton(rec.get("src_ip", "10.0.0.1"))
        dst = socket.inet_aton(rec.get("dst_ip", "10.0.0.2"))
        # nexthop, in_if, out_if, pkts, octets, first, last, src_port, dst_port,
        # pad, tcp_flags, proto, tos, src_as, dst_as, src_mask, dst_mask, pad2
        body += struct.pack(
            ">4s4s4sHHIIIIHHBBBBHHBBH",
            src, dst,
            socket.inet_aton("0.0.0.0"),  # nexthop
            0, 0,                          # in_if, out_if
            rec.get("pkts",    10),
            rec.get("octets",  1000),
            rec.get("first",   0),
            rec.get("last",    1000),      # 1000 ms duration
            rec.get("src_port", 12345),
            rec.get("dst_port", 80),
            0,                             # pad
            rec.get("tcp_flags", 0x02),    # SYN
            rec.get("proto",    6),        # TCP
            0,                             # tos
            0, 0,                          # src_as, dst_as
            0, 0,                          # masks
            0,                             # pad2
        )
    return header + body


