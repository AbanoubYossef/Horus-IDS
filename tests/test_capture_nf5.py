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




class TestParseNF5:

    def test_single_flow_parsed(self):
        pkt = _build_nf5_packet([{"src_ip": "10.10.0.1", "dst_ip": "10.20.0.1"}])
        flows = flow_capture._parse_nf5(pkt, "10.99.0.1")
        assert len(flows) == 1
        assert flows[0]["src_ip"] == "10.10.0.1"
        assert flows[0]["dst_ip"] == "10.20.0.1"

    def test_multiple_flows(self):
        recs = [
            {"src_ip": "10.10.0.1", "dst_ip": "10.20.0.1"},
            {"src_ip": "10.10.0.2", "dst_ip": "10.20.0.2"},
            {"src_ip": "10.51.1.5", "dst_ip": "10.20.0.1"},
        ]
        pkt = _build_nf5_packet(recs)
        flows = flow_capture._parse_nf5(pkt, "10.99.0.1")
        assert len(flows) == 3

    def test_duration_computed_from_first_last(self):
        pkt = _build_nf5_packet([{"first": 0, "last": 2000}])
        flows = flow_capture._parse_nf5(pkt, "10.99.0.1")
        assert flows[0]["duration_ms"] == pytest.approx(2000.0)

    def test_packet_and_octet_counts(self):
        pkt = _build_nf5_packet([{"pkts": 50, "octets": 75_000}])
        flows = flow_capture._parse_nf5(pkt, "10.99.0.1")
        assert flows[0]["pkts"]   == 50
        assert flows[0]["octets"] == 75_000

    def test_vlan_id_zero_for_v5(self):
        """NetFlow v5 has no VLAN field — always 0."""
        pkt = _build_nf5_packet([{}])
        flows = flow_capture._parse_nf5(pkt, "10.99.0.1")
        assert flows[0]["vlan_id"] == 0

    def test_wrong_version_rejected(self):
        # Build a packet with version=9 in the header — should be rejected by v5 parser
        header = struct.pack(">HHIIIIBBH", 9, 1, 0, 0, 0, 0, 0, 0, 0)
        flows = flow_capture._parse_nf5(header + b"\x00" * 48, "10.99.0.1")
        assert flows == []

    def test_truncated_packet_returns_empty(self):
        assert flow_capture._parse_nf5(b"\x00\x05", "10.99.0.1") == []

    def test_tcp_flags_preserved(self):
        pkt = _build_nf5_packet([{"tcp_flags": 0x12}])   # SYN+ACK
        flows = flow_capture._parse_nf5(pkt, "10.99.0.1")
        assert flows[0]["tcp_flags"] == 0x12

    def test_proto_preserved(self):
        pkt = _build_nf5_packet([{"proto": 17}])   # UDP
        flows = flow_capture._parse_nf5(pkt, "10.99.0.1")
        assert flows[0]["proto"] == 17
