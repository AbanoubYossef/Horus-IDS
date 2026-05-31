"""capture/sources/netflow_source.py — NetFlow v5/v9/IPFIX listener."""

import logging
import socket
import struct
import threading
from typing import Optional

import config
from flow_mapper import _netflow_record_to_features, get_flow_direction

log = logging.getLogger("flow_capture")


# ══════════════════════════════════════════════════════════════════════════════
#  NetFlow v5 parser
# ══════════════════════════════════════════════════════════════════════════════
# v5 header: version(2) count(2) uptime(4) unix_secs(4) nsecs(4) seq(4)
#            engine_type(1) engine_id(1) sample_interval(2) = 24 bytes
# v5 record: src(4) dst(4) nexthop(4) in_if(2) out_if(2) pkts(4) octets(4)
#            first(4) last(4) src_port(2) dst_port(2) pad(1) tcp_flags(1)
#            proto(1) tos(1) src_as(2) dst_as(2) src_mask(1) dst_mask(1)
#            pad2(2) = 48 bytes

_NF5_HDR = struct.Struct(">HHIIIIBBH")   # 24 bytes
_NF5_REC = struct.Struct(">4s4s4sHHIIIIHHBBBBHHBBH")  # 48 bytes


def _parse_nf5(data: bytes, src_addr: str) -> list:
    """Parse a NetFlow v5 UDP payload. Returns list of record dicts."""
    if len(data) < 24:
        return []
    hdr = _NF5_HDR.unpack_from(data, 0)
    if hdr[0] != 5:
        return []
    count = hdr[1]

    flows = []
    offset = 24
    for _ in range(count):
        if offset + 48 > len(data):
            break
        r = _NF5_REC.unpack_from(data, offset)
        offset += 48

        first_ms, last_ms = r[7], r[8]
        dur_ms = float(last_ms - first_ms) if last_ms >= first_ms else 0.0

        flows.append({
            "src_ip":      socket.inet_ntoa(r[0]),
            "dst_ip":      socket.inet_ntoa(r[1]),
            "src_port":    r[9],
            "dst_port":    r[10],
            "pkts":        r[5],
            "octets":      r[6],
            "duration_ms": dur_ms,
            "proto":       r[13],
            "tcp_flags":   r[12],
            "vlan_id":     0,       # v5 does not carry VLAN info
            "src_vlan":    0,
            "dst_vlan":    0,
        })
    return flows


# ══════════════════════════════════════════════════════════════════════════════
#  NetFlow v9 / IPFIX (v10) parser
# ══════════════════════════════════════════════════════════════════════════════
# Template cache: (exporter, source_id, template_id) → [(type, len), ...]
_nf9_templates: dict = {}
_nf9_lock = threading.Lock()

# v9 field types we care about
_NF9_FIELDS = {
    1:   "IN_BYTES",
    2:   "IN_PKTS",
    4:   "PROTOCOL",
    6:   "TCP_FLAGS",
    7:   "L4_SRC_PORT",
    8:   "IPV4_SRC_ADDR",
    11:  "L4_DST_PORT",
    12:  "IPV4_DST_ADDR",
    21:  "LAST_SWITCHED",
    22:  "FIRST_SWITCHED",
    23:  "OUT_BYTES",       # reverse-direction bytes (bidirectional exporters)
    24:  "OUT_PKTS",        # reverse-direction packets (bidirectional exporters)
    58:  "SRC_VLAN",
    59:  "DST_VLAN",
    152: "FLOW_START_MS",
    153: "FLOW_END_MS",
}

_NF9_HDR  = struct.Struct(">HHIIII")   # 20 bytes: ver count uptime unix seq src_id
_IPFIX_HDR = struct.Struct(">HHIII")   # 16 bytes: ver length export_time seq domain_id


def _parse_nf9_templates(data: bytes, exporter: str, source_id: int):
    """Parse Template FlowSet (flowset_id=0) and update the template cache."""
    pos = 0
    while pos + 4 <= len(data):
        tmpl_id, field_count = struct.unpack_from(">HH", data, pos)
        pos += 4
        if field_count == 0:
            break
        fields = []
        for _ in range(field_count):
            if pos + 4 > len(data):
                break
            ftype, flen = struct.unpack_from(">HH", data, pos)
            fields.append((ftype, flen))
            pos += 4
        with _nf9_lock:
            _nf9_templates[(exporter, source_id, tmpl_id)] = fields
        log.debug("NF9 template cached: exporter=%s src_id=%d tmpl_id=%d fields=%d",
                  exporter, source_id, tmpl_id, len(fields))


def _decode_nf9_record(data: bytes, template: list, source_id: int) -> Optional[dict]:
    """Decode one NetFlow v9/IPFIX data record using its template."""
    rec = {}
    pos = 0
    for ftype, flen in template:
        if pos + flen > len(data):
            break
        raw = data[pos:pos + flen]
        name = _NF9_FIELDS.get(ftype)
        if name:
            if name in ("IPV4_SRC_ADDR", "IPV4_DST_ADDR"):
                rec[name] = socket.inet_ntoa(raw) if flen == 4 else raw.hex()
            else:
                rec[name] = int.from_bytes(raw, "big")
        pos += flen

    src_ip = rec.get("IPV4_SRC_ADDR")
    dst_ip = rec.get("IPV4_DST_ADDR")
    if not src_ip or not dst_ip:
        return None

    if "FLOW_START_MS" in rec and "FLOW_END_MS" in rec:
        dur_ms = float(rec["FLOW_END_MS"] - rec["FLOW_START_MS"])
    elif "FIRST_SWITCHED" in rec and "LAST_SWITCHED" in rec:
        dur_ms = float(rec["LAST_SWITCHED"] - rec["FIRST_SWITCHED"])
    else:
        dur_ms = 0.0

    src_vlan = int(rec.get("SRC_VLAN", 0) or 0)
    dst_vlan = int(rec.get("DST_VLAN", 0) or 0)
    # Prefer source VLAN, fall back to dst
    vlan_id = src_vlan or dst_vlan

    return {
        "src_ip":       src_ip,
        "dst_ip":       dst_ip,
        "src_port":     rec.get("L4_SRC_PORT", 0),
        "dst_port":     rec.get("L4_DST_PORT", 0),
        "pkts":         rec.get("IN_PKTS",    0),
        "octets":       rec.get("IN_BYTES",   0),
        "out_pkts":     rec.get("OUT_PKTS",   0),   # reverse direction (0 for v5/unidirectional)
        "out_octets":   rec.get("OUT_BYTES",  0),   # reverse direction (0 for v5/unidirectional)
        "duration_ms":  dur_ms,
        "proto":        rec.get("PROTOCOL",   0),
        "tcp_flags":    rec.get("TCP_FLAGS",  0),
        "vlan_id":      vlan_id,
        "src_vlan":     src_vlan,
        "dst_vlan":     dst_vlan,
    }


def _parse_nf9(data: bytes, src_addr: str) -> list:
    """Parse a NetFlow v9 UDP payload. Returns list of record dicts."""
    if len(data) < 20:
        return []
    hdr = _NF9_HDR.unpack_from(data, 0)
    if hdr[0] != 9:
        return []
    count, source_id = hdr[1], hdr[5]
    pos = 20
    flows = []

    for _ in range(count):
        if pos + 4 > len(data):
            break
        fs_id, fs_len = struct.unpack_from(">HH", data, pos)
        if fs_len < 4:
            break
        fs_data = data[pos + 4: pos + fs_len]

        if fs_id == 0:
            _parse_nf9_templates(fs_data, src_addr, source_id)
        elif fs_id >= 256:
            tmpl_key = (src_addr, source_id, fs_id)
            with _nf9_lock:
                template = _nf9_templates.get(tmpl_key)
            if template:
                rec_size = sum(fl for _, fl in template)
                if rec_size > 0:
                    rpos = 0
                    while rpos + rec_size <= len(fs_data):
                        rec = _decode_nf9_record(fs_data[rpos:rpos + rec_size],
                                                 template, source_id)
                        if rec:
                            flows.append(rec)
                        rpos += rec_size
        pos += fs_len
    return flows


def _parse_ipfix(data: bytes, src_addr: str) -> list:
    """Parse an IPFIX (v10) UDP payload. Reuses v9 template cache."""
    if len(data) < 16:
        return []
    hdr = _IPFIX_HDR.unpack_from(data, 0)
    if hdr[0] != 10:
        return []
    domain_id = hdr[4]
    pos = 16
    flows = []

    while pos + 4 <= len(data):
        set_id, set_len = struct.unpack_from(">HH", data, pos)
        if set_len < 4:
            break
        set_data = data[pos + 4: pos + set_len]

        if set_id == 2:
            _parse_nf9_templates(set_data, src_addr, domain_id)
        elif set_id >= 256:
            tmpl_key = (src_addr, domain_id, set_id)
            with _nf9_lock:
                template = _nf9_templates.get(tmpl_key)
            if template:
                rec_size = sum(fl for _, fl in template)
                if rec_size > 0:
                    rpos = 0
                    while rpos + rec_size <= len(set_data):
                        rec = _decode_nf9_record(set_data[rpos:rpos + rec_size],
                                                 template, domain_id)
                        if rec:
                            flows.append(rec)
                        rpos += rec_size
        pos += set_len
    return flows


# ══════════════════════════════════════════════════════════════════════════════
#  NetFlow listener  (UDP 2055 — v5, v9, IPFIX/v10)
# ══════════════════════════════════════════════════════════════════════════════

class NetFlowListener(threading.Thread):
    """UDP listener for NetFlow v5/v9/IPFIX from switches."""

    def __init__(self, batcher):
        super().__init__(daemon=True, name="NetFlowListener")
        self._batcher = batcher

    def run(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # Avoid EADDRINUSE on service restart
        if hasattr(socket, "SO_REUSEPORT"):
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        sock.bind(("0.0.0.0", config.NETFLOW_PORT))
        sock.settimeout(1.0)
        log.info("NetFlow listener on UDP %d (v5/v9/IPFIX)", config.NETFLOW_PORT)

        total = 0
        while True:
            try:
                data, (src_addr, _) = sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError as exc:
                log.error("NetFlowListener socket error: %s", exc)
                continue

            try:
                records = self._parse(data, src_addr)
                for rec in records:
                    self._submit(rec)
                    total += 1
                if total % 10_000 == 0 and total > 0:
                    log.info("NetFlow records processed: %d", total)
            except Exception as exc:
                log.debug("NetFlow parse error from %s: %s", src_addr, exc)

    def _parse(self, data: bytes, src_addr: str) -> list:
        if len(data) < 2:
            return []
        version = struct.unpack_from(">H", data, 0)[0]
        if version == 5:
            return _parse_nf5(data, src_addr)
        elif version == 9:
            return _parse_nf9(data, src_addr)
        elif version == 10:
            return _parse_ipfix(data, src_addr)
        else:
            log.debug("Unknown NetFlow version %d from %s", version, src_addr)
            return []

    def _submit(self, rec: dict):
        features = _netflow_record_to_features(rec)
        if not features:
            return
        src_ip   = rec.get("src_ip", "")
        dst_ip   = rec.get("dst_ip", "")
        vlan_id  = int(rec.get("vlan_id", 0))
        src_vlan = int(rec.get("src_vlan", 0))
        dst_vlan = int(rec.get("dst_vlan", 0))
        # Fallback to topology inference for missing VLANs
        if src_vlan == 0:
            src_vlan = config.vlan_from_ip(src_ip)
        if dst_vlan == 0:
            dst_vlan = config.vlan_from_ip(dst_ip)
        if vlan_id == 0:
            vlan_id = src_vlan or dst_vlan
        flow_dict = {
            "features_dict": features,
            "src_ip":         src_ip,
            "dst_ip":         dst_ip,
            "src_port":       int(rec.get("src_port", 0)),
            "dst_port":       int(rec.get("dst_port", 0)),
            "protocol":       int(rec.get("proto", 0)),
            "vlan_id":        vlan_id,
            "src_vlan":       src_vlan,
            "dst_vlan":       dst_vlan,
            "flow_direction": get_flow_direction(src_ip, dst_ip),
            "input_path":     "netflow",
        }
        self._batcher.submit(flow_dict)
