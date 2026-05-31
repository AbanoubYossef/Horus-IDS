"""capture/flow_mapper.py — Map nfstream/NetFlow data to CICFlowMeter features."""

import ipaddress
from typing import Optional


# ── Internal IP ranges (used for flow direction classification) ───────────────
_INTERNAL_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("192.168.100.0/24"),   # DMZ (future outside zone)
    ipaddress.ip_network("172.16.0.0/12"),
]


def _is_internal(ip_str: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in _INTERNAL_NETS)
    except ValueError:
        return False


def get_flow_direction(src_ip: str, dst_ip: str) -> str:
    """Classify as INBOUND, OUTBOUND, LATERAL, or UNKNOWN."""
    src_int = _is_internal(src_ip)
    dst_int = _is_internal(dst_ip)
    if not src_int and dst_int:
        return "INBOUND"
    if src_int and not dst_int:
        return "OUTBOUND"
    if src_int and dst_int:
        return "LATERAL"
    return "UNKNOWN"


# ══════════════════════════════════════════════════════════════════════════════
#  nfstream → CICFlowMeter feature mapping  (RSPAN path)
# ══════════════════════════════════════════════════════════════════════════════
# nfstream uses ms, CICFlowMeter uses µs → multiply by 1000

def _safe(flow, field, default=0.0):
    """Return flow field as float, or default if missing / None / NaN."""
    v = getattr(flow, field, default)
    if v is None:
        return float(default)
    try:
        f = float(v)
        return f if f == f else float(default)   # NaN check
    except (TypeError, ValueError):
        return float(default)


def _map_flow(flow) -> Optional[dict]:
    """
    Map one nfstream flow to a CICFlowMeter-compatible features_dict.
    Returns None if the flow has zero packets (degenerate).
    """
    dur_ms  = _safe(flow, "bidirectional_duration_ms")
    fwd_pkts = _safe(flow, "src2dst_packets")
    bwd_pkts = _safe(flow, "dst2src_packets")
    total_pkts = fwd_pkts + bwd_pkts

    if total_pkts == 0:
        return None

    dur_us  = dur_ms * 1000.0
    dur_s   = dur_ms / 1000.0

    fwd_bytes   = _safe(flow, "src2dst_bytes")
    bwd_bytes   = _safe(flow, "dst2src_bytes")
    total_bytes = fwd_bytes + bwd_bytes

    def flags(name):
        return (_safe(flow, f"src2dst_{name}_packets") +
                _safe(flow, f"dst2src_{name}_packets"))

    syn = flags("syn");  ack = flags("ack");  fin = flags("fin")
    rst = flags("rst");  psh = flags("psh");  urg = flags("urg")
    ece = flags("ece")

    proto       = _safe(flow, "protocol", 0)
    hdr_per_pkt = 40.0 if int(proto) == 6 else 28.0
    fwd_hdr     = hdr_per_pkt * fwd_pkts
    bwd_hdr     = hdr_per_pkt * bwd_pkts

    def iat_us(field):
        return _safe(flow, field) * 1000.0

    flow_bytes_s = total_bytes / dur_s if dur_s > 0 else 0.0
    flow_pkts_s  = total_pkts  / dur_s if dur_s > 0 else 0.0
    fwd_pkts_s   = fwd_pkts    / dur_s if dur_s > 0 else 0.0
    bwd_pkts_s   = bwd_pkts    / dur_s if dur_s > 0 else 0.0

    pkt_len_std = _safe(flow, "bidirectional_stddev_ps")
    pkt_len_var = pkt_len_std ** 2

    return {
        "Flow Duration":                    dur_us,
        "Total Fwd Packets":                fwd_pkts,
        "Total Backward Packets":           bwd_pkts,
        "Total Length of Fwd Packets":      fwd_bytes,
        "Total Length of Bwd Packets":      bwd_bytes,
        "Fwd Packet Length Max":            _safe(flow, "src2dst_max_ps"),
        "Fwd Packet Length Min":            _safe(flow, "src2dst_min_ps"),
        "Fwd Packet Length Mean":           _safe(flow, "src2dst_mean_ps"),
        "Fwd Packet Length Std":            _safe(flow, "src2dst_stddev_ps"),
        "Bwd Packet Length Max":            _safe(flow, "dst2src_max_ps"),
        "Bwd Packet Length Min":            _safe(flow, "dst2src_min_ps"),
        "Bwd Packet Length Mean":           _safe(flow, "dst2src_mean_ps"),
        "Bwd Packet Length Std":            _safe(flow, "dst2src_stddev_ps"),
        "Flow Bytes/s":                     flow_bytes_s,
        "Flow Packets/s":                   flow_pkts_s,
        "Fwd Packets/s":                    fwd_pkts_s,
        "Bwd Packets/s":                    bwd_pkts_s,
        "Flow IAT Mean":                    iat_us("bidirectional_mean_piat_ms"),
        "Flow IAT Std":                     iat_us("bidirectional_stddev_piat_ms"),
        "Flow IAT Max":                     iat_us("bidirectional_max_piat_ms"),
        "Flow IAT Min":                     iat_us("bidirectional_min_piat_ms"),
        "Fwd IAT Total":                    iat_us("src2dst_duration_ms"),
        "Fwd IAT Mean":                     iat_us("src2dst_mean_piat_ms"),
        "Fwd IAT Std":                      iat_us("src2dst_stddev_piat_ms"),
        "Fwd IAT Max":                      iat_us("src2dst_max_piat_ms"),
        "Fwd IAT Min":                      iat_us("src2dst_min_piat_ms"),
        "Bwd IAT Total":                    iat_us("dst2src_duration_ms"),
        "Bwd IAT Mean":                     iat_us("dst2src_mean_piat_ms"),
        "Bwd IAT Std":                      iat_us("dst2src_stddev_piat_ms"),
        "Bwd IAT Max":                      iat_us("dst2src_max_piat_ms"),
        "Bwd IAT Min":                      iat_us("dst2src_min_piat_ms"),
        "FIN Flag Count":                   fin,
        "SYN Flag Count":                   syn,
        "RST Flag Count":                   rst,
        "PSH Flag Count":                   psh,
        "ACK Flag Count":                   ack,
        "URG Flag Count":                   urg,
        "ECE Flag Count":                   ece,
        "Fwd Header Length":                fwd_hdr,
        "Bwd Header Length":                bwd_hdr,
        "Min Packet Length":                _safe(flow, "bidirectional_min_ps"),
        "Max Packet Length":                _safe(flow, "bidirectional_max_ps"),
        "Packet Length Mean":               _safe(flow, "bidirectional_mean_ps"),
        "Packet Length Std":                pkt_len_std,
        "Packet Length Variance":           pkt_len_var,
        "Average Packet Size":              _safe(flow, "bidirectional_mean_ps"),
        "Avg Fwd Segment Size":             _safe(flow, "src2dst_mean_ps"),
        "Avg Bwd Segment Size":             _safe(flow, "dst2src_mean_ps"),
        "Subflow Fwd Packets":              fwd_pkts,
        "Subflow Fwd Bytes":                fwd_bytes,
        "Subflow Bwd Packets":              bwd_pkts,
        "Subflow Bwd Bytes":                bwd_bytes,
        "Init_Win_bytes_forward":           0.0,
        "Init_Win_bytes_backward":          0.0,
        "act_data_pkt_fwd":                 fwd_pkts,
        "min_seg_size_forward":             _safe(flow, "src2dst_min_ps"),
        "Fwd Avg Bytes/Bulk":               0.0,
        "Fwd Avg Packets/Bulk":             0.0,
        "Fwd Avg Bulk Rate":                0.0,
        "Bwd Avg Bytes/Bulk":               0.0,
        "Bwd Avg Packets/Bulk":             0.0,
        "Bwd Avg Bulk Rate":                0.0,
        "Active Mean":                      0.0,
        "Active Std":                       0.0,
        "Active Max":                       0.0,
        "Active Min":                       0.0,
        "Idle Mean":                        0.0,
        "Idle Std":                         0.0,
        "Idle Max":                         0.0,
        "Idle Min":                         0.0,
        "Destination Port":                 _safe(flow, "dst_port"),
    }


# ══════════════════════════════════════════════════════════════════════════════
#  NetFlow → CICFlowMeter feature mapping
# ══════════════════════════════════════════════════════════════════════════════
# NetFlow is unidirectional — backward stats default to 0

def _netflow_record_to_features(rec: dict) -> dict:
    """Convert parsed NetFlow record to CICFlowMeter feature dict."""
    dur_ms     = float(rec.get("duration_ms", 0))
    dur_us     = dur_ms * 1000.0
    dur_s      = dur_ms / 1000.0

    fwd_pkts   = float(rec.get("pkts",       0))
    fwd_octets = float(rec.get("octets",     0))
    bwd_pkts   = float(rec.get("out_pkts",   0))   # 0 for v5 / unidirectional exporters
    bwd_octets = float(rec.get("out_octets", 0))   # 0 for v5 / unidirectional exporters

    total_pkts  = fwd_pkts + bwd_pkts
    total_bytes = fwd_octets + bwd_octets

    proto  = int(rec.get("proto", 0))
    flags  = int(rec.get("tcp_flags", 0))

    # TCP flags
    fin = float(flags & 0x01)
    syn = float((flags >> 1) & 0x01)
    rst = float((flags >> 2) & 0x01)
    psh = float((flags >> 3) & 0x01)
    ack = float((flags >> 4) & 0x01)
    urg = float((flags >> 5) & 0x01)

    flow_bytes_s = total_bytes / dur_s  if dur_s      > 0 else 0.0
    flow_pkts_s  = total_pkts  / dur_s  if dur_s      > 0 else 0.0
    fwd_pkts_s   = fwd_pkts    / dur_s  if dur_s      > 0 else 0.0
    bwd_pkts_s   = bwd_pkts    / dur_s  if dur_s      > 0 else 0.0
    avg_fwd_pkt  = fwd_octets  / fwd_pkts if fwd_pkts > 0 else 0.0
    avg_bwd_pkt  = bwd_octets  / bwd_pkts if bwd_pkts > 0 else 0.0
    total_pkts_n = total_pkts  if total_pkts > 0 else 1.0
    avg_pkt      = total_bytes / total_pkts_n

    hdr_per_pkt  = 40.0 if proto == 6 else 28.0
    fwd_hdr      = hdr_per_pkt * fwd_pkts
    bwd_hdr      = hdr_per_pkt * bwd_pkts

    return {
        "Flow Duration":                    dur_us,
        "Total Fwd Packets":                fwd_pkts,
        "Total Backward Packets":           bwd_pkts,
        "Total Length of Fwd Packets":      fwd_octets,
        "Total Length of Bwd Packets":      bwd_octets,
        "Fwd Packet Length Max":            avg_fwd_pkt,
        "Fwd Packet Length Min":            avg_fwd_pkt,
        "Fwd Packet Length Mean":           avg_fwd_pkt,
        "Fwd Packet Length Std":            0.0,
        "Bwd Packet Length Max":            avg_bwd_pkt,
        "Bwd Packet Length Min":            avg_bwd_pkt,
        "Bwd Packet Length Mean":           avg_bwd_pkt,
        "Bwd Packet Length Std":            0.0,
        "Flow Bytes/s":                     flow_bytes_s,
        "Flow Packets/s":                   flow_pkts_s,
        "Fwd Packets/s":                    fwd_pkts_s,
        "Bwd Packets/s":                    bwd_pkts_s,
        "Flow IAT Mean":                    0.0,
        "Flow IAT Std":                     0.0,
        "Flow IAT Max":                     0.0,
        "Flow IAT Min":                     0.0,
        "Fwd IAT Total":                    dur_us,
        "Fwd IAT Mean":                     0.0,
        "Fwd IAT Std":                      0.0,
        "Fwd IAT Max":                      0.0,
        "Fwd IAT Min":                      0.0,
        "Bwd IAT Total":                    0.0,
        "Bwd IAT Mean":                     0.0,
        "Bwd IAT Std":                      0.0,
        "Bwd IAT Max":                      0.0,
        "Bwd IAT Min":                      0.0,
        "FIN Flag Count":                   fin,
        "SYN Flag Count":                   syn,
        "RST Flag Count":                   rst,
        "PSH Flag Count":                   psh,
        "ACK Flag Count":                   ack,
        "URG Flag Count":                   urg,
        "ECE Flag Count":                   0.0,
        "Fwd Header Length":                fwd_hdr,
        "Bwd Header Length":                bwd_hdr,
        "Min Packet Length":                avg_fwd_pkt if fwd_pkts > 0 else avg_bwd_pkt,
        "Max Packet Length":                avg_pkt,
        "Packet Length Mean":               avg_pkt,
        "Packet Length Std":                0.0,
        "Packet Length Variance":           0.0,
        "Average Packet Size":              avg_pkt,
        "Avg Fwd Segment Size":             avg_fwd_pkt,
        "Avg Bwd Segment Size":             avg_bwd_pkt,
        "Subflow Fwd Packets":              fwd_pkts,
        "Subflow Fwd Bytes":                fwd_octets,
        "Subflow Bwd Packets":              bwd_pkts,
        "Subflow Bwd Bytes":                bwd_octets,
        "Init_Win_bytes_forward":           0.0,
        "Init_Win_bytes_backward":          0.0,
        "act_data_pkt_fwd":                 fwd_pkts,
        "min_seg_size_forward":             avg_fwd_pkt,
        "Fwd Avg Bytes/Bulk":               0.0,
        "Fwd Avg Packets/Bulk":             0.0,
        "Fwd Avg Bulk Rate":                0.0,
        "Bwd Avg Bytes/Bulk":               0.0,
        "Bwd Avg Packets/Bulk":             0.0,
        "Bwd Avg Bulk Rate":                0.0,
        "Active Mean":                      0.0,
        "Active Std":                       0.0,
        "Active Max":                       0.0,
        "Active Min":                       0.0,
        "Idle Mean":                        0.0,
        "Idle Std":                         0.0,
        "Idle Max":                         0.0,
        "Idle Min":                         0.0,
        "Destination Port":                 float(rec.get("dst_port", 0)),
    }
