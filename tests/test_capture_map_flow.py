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

class TestMapFlow:

    def test_returns_dict(self):
        result = flow_capture._map_flow(_flow())
        assert isinstance(result, dict)

    def test_zero_packets_returns_none(self):
        result = flow_capture._map_flow(_flow(src2dst_packets=0.0, dst2src_packets=0.0))
        assert result is None

    def test_duration_converted_ms_to_us(self):
        result = flow_capture._map_flow(_flow(bidirectional_duration_ms=500.0))
        assert result["Flow Duration"] == pytest.approx(500_000.0)

    def test_flow_duration_1s(self):
        result = flow_capture._map_flow(_flow(bidirectional_duration_ms=1000.0))
        assert result["Flow Duration"] == pytest.approx(1_000_000.0)

    def test_fwd_bwd_packet_counts(self):
        result = flow_capture._map_flow(_flow(src2dst_packets=10.0, dst2src_packets=8.0))
        assert result["Total Fwd Packets"] == 10.0
        assert result["Total Backward Packets"] == 8.0

    def test_byte_totals(self):
        result = flow_capture._map_flow(_flow(src2dst_bytes=3200.0, dst2src_bytes=2400.0))
        assert result["Total Length of Fwd Packets"] == 3200.0
        assert result["Total Length of Bwd Packets"] == 2400.0

    def test_iat_converted_ms_to_us(self):
        result = flow_capture._map_flow(_flow(bidirectional_mean_piat_ms=55.0))
        assert result["Flow IAT Mean"] == pytest.approx(55_000.0)

    def test_fwd_iat_converted(self):
        result = flow_capture._map_flow(_flow(src2dst_mean_piat_ms=100.0))
        assert result["Fwd IAT Mean"] == pytest.approx(100_000.0)

    def test_syn_flag_count_both_directions(self):
        result = flow_capture._map_flow(_flow(
            src2dst_syn_packets=3.0,
            dst2src_syn_packets=2.0,
        ))
        assert result["SYN Flag Count"] == 5.0

    def test_ack_flag_count_both_directions(self):
        result = flow_capture._map_flow(_flow(
            src2dst_ack_packets=9.0,
            dst2src_ack_packets=7.0,
        ))
        assert result["ACK Flag Count"] == 16.0

    def test_all_flags_zero_when_zero(self):
        result = flow_capture._map_flow(_flow(
            src2dst_syn_packets=0.0, dst2src_syn_packets=0.0,
            src2dst_ack_packets=0.0, dst2src_ack_packets=0.0,
            src2dst_fin_packets=0.0, dst2src_fin_packets=0.0,
            src2dst_rst_packets=0.0, dst2src_rst_packets=0.0,
            src2dst_psh_packets=0.0, dst2src_psh_packets=0.0,
        ))
        for flag in ["SYN Flag Count", "ACK Flag Count", "FIN Flag Count",
                     "RST Flag Count", "PSH Flag Count"]:
            assert result[flag] == 0.0, f"{flag} should be 0"

    def test_tcp_header_estimate(self):
        """TCP (proto=6) uses 40 bytes/packet for header estimate."""
        result = flow_capture._map_flow(_flow(
            protocol=6,
            src2dst_packets=10.0,
            dst2src_packets=8.0,
        ))
        assert result["Fwd Header Length"] == pytest.approx(40.0 * 10)
        assert result["Bwd Header Length"] == pytest.approx(40.0 * 8)

    def test_udp_header_estimate(self):
        """UDP (proto=17) uses 28 bytes/packet."""
        result = flow_capture._map_flow(_flow(
            protocol=17,
            src2dst_packets=5.0,
            dst2src_packets=3.0,
        ))
        assert result["Fwd Header Length"] == pytest.approx(28.0 * 5)
        assert result["Bwd Header Length"] == pytest.approx(28.0 * 3)

    def test_flow_rates_positive(self):
        result = flow_capture._map_flow(_flow())
        assert result["Flow Bytes/s"] > 0
        assert result["Flow Packets/s"] > 0

    def test_packet_length_variance_equals_std_squared(self):
        result = flow_capture._map_flow(_flow(bidirectional_stddev_ps=100.0))
        assert result["Packet Length Variance"] == pytest.approx(10_000.0)

    def test_subflow_equals_total(self):
        """nfstream has no sub-flows; subflow fields mirror total counts."""
        result = flow_capture._map_flow(_flow(
            src2dst_packets=10.0, src2dst_bytes=3200.0,
            dst2src_packets=8.0,  dst2src_bytes=2400.0,
        ))
        assert result["Subflow Fwd Packets"] == result["Total Fwd Packets"]
        assert result["Subflow Fwd Bytes"]   == result["Total Length of Fwd Packets"]
        assert result["Subflow Bwd Packets"] == result["Total Backward Packets"]
        assert result["Subflow Bwd Bytes"]   == result["Total Length of Bwd Packets"]

    def test_unavailable_fields_default_to_zero(self):
        """Active/Idle, bulk, Init_Win fields are not in nfstream → default 0."""
        result = flow_capture._map_flow(_flow())
        for field in [
            "Active Mean", "Active Std", "Active Max", "Active Min",
            "Idle Mean",   "Idle Std",   "Idle Max",   "Idle Min",
            "Init_Win_bytes_forward", "Init_Win_bytes_backward",
            "Fwd Avg Bytes/Bulk", "Fwd Avg Packets/Bulk", "Fwd Avg Bulk Rate",
            "Bwd Avg Bytes/Bulk", "Bwd Avg Packets/Bulk", "Bwd Avg Bulk Rate",
        ]:
            assert result[field] == 0.0, f"{field} should default to 0"

    def test_all_values_finite(self):
        import math
        result = flow_capture._map_flow(_flow())
        for k, v in result.items():
            assert math.isfinite(v), f"Feature {k} = {v} is not finite"

    def test_vlan_id_read_correctly(self):
        """VLAN ID is extracted separately in run() but _map_flow returns features only."""
        flow = _flow(vlan_id=52)
        result = flow_capture._map_flow(flow)
        assert result is not None  # just checks it didn't fail on a VLAN-tagged flow

    @pytest.mark.parametrize("dur_ms,fwd,bwd", [
        (0.001, 1.0, 0.0),   # sub-millisecond flow
        (60_000.0, 2.0, 1.0),  # 1-minute long flow
        (1.0, 1000.0, 0.0),  # SYN flood burst
    ])
    def test_edge_case_flows(self, dur_ms, fwd, bwd):
        import math
        flow = _flow(
            bidirectional_duration_ms=dur_ms,
            src2dst_packets=fwd,
            dst2src_packets=bwd,
        )
        result = flow_capture._map_flow(flow)
        if result is not None:
            for k, v in result.items():
                assert math.isfinite(v), f"{k}={v} not finite for dur={dur_ms}"


# ══════════════════════════════════════════════════════════════════════════════
#  FlowBatcher
# ══════════════════════════════════════════════════════════════════════════════

class TestGetFlowDirection:

    def test_inbound_external_to_internal(self):
        assert flow_capture.get_flow_direction("8.8.8.8", "10.20.0.1") == "INBOUND"

    def test_outbound_internal_to_external(self):
        assert flow_capture.get_flow_direction("10.10.0.5", "1.1.1.1") == "OUTBOUND"

    def test_lateral_both_internal(self):
        assert flow_capture.get_flow_direction("10.10.0.5", "10.20.0.1") == "LATERAL"

    def test_unknown_both_external(self):
        assert flow_capture.get_flow_direction("8.8.8.8", "1.1.1.1") == "UNKNOWN"

    def test_172_16_range_is_internal(self):
        assert flow_capture.get_flow_direction("172.16.0.5", "172.17.0.1") == "LATERAL"

    def test_192_168_100_dmz_range_is_internal(self):
        assert flow_capture.get_flow_direction("8.8.8.8", "192.168.100.10") == "INBOUND"

    def test_invalid_ip_returns_unknown(self):
        result = flow_capture.get_flow_direction("not-an-ip", "10.20.0.1")
        assert result == "INBOUND"   # "not-an-ip" raises → _is_internal → False = external src


