"""capture/alert_router.py — Per-VLAN severity escalation + RFC 5424 syslog."""

import logging
import os
import socket
import time
from datetime import datetime, timezone

import config

log = logging.getLogger("alert_router")

# ── Syslog constants ──────────────────────────────────────────────────────────
FACILITY_LOCAL1 = 17

RFC5424_SEVERITY = {
    "info":     6,   # Informational
    "medium":   4,   # Warning
    "high":     3,   # Error
    "critical": 2,   # Critical
}

# ── Hostname (used as RFC 5424 HOSTNAME field) ────────────────────────────────
_HOSTNAME = socket.gethostname()
_APP_NAME = "horus-soc"
_PROCID   = str(os.getpid())

# ── UDP socket ──────────────────────────────────────────────────────────────
_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)


def _send_udp(data: bytes, host: str, port: int):
    """Send a UDP datagram. Extracted for testability."""
    _sock.sendto(data, (host, port))


# ══════════════════════════════════════════════════════════════════════════════
#  Severity escalation
# ══════════════════════════════════════════════════════════════════════════════

def _escalate_severity(severity: str, vlan_id: int) -> str:
    """Apply per-VLAN escalation (never downgrades)."""
    order = config.SEVERITY_ORDER
    current_idx = order.index(severity) if severity in order else 0

    if vlan_id in config.CRITICAL_VLANS:
        return "critical"

    if vlan_id in config.HIGH_VLANS:
        target_idx = order.index("high")
        return order[max(current_idx, target_idx)]

    return severity


def _above_threshold(severity: str) -> bool:
    order = config.SEVERITY_ORDER
    try:
        return order.index(severity) >= order.index(config.ALERT_MIN_SEVERITY)
    except ValueError:
        return True


# ══════════════════════════════════════════════════════════════════════════════
#  VLAN name lookup
# ══════════════════════════════════════════════════════════════════════════════

# VLAN naming: B1=1xx, B2=2xx, B3=3xx, B4=4xx; server VLANs are global
_BUILDING_NAMES = {1: "B1", 2: "B2", 3: "B3", 4: "B4"}

_BASE_VLAN_NAMES = {
    10: "General-Users",
    11: "Finance",
    12: "HR",
    13: "IT-Admin",
    50: "VoIP",
    51: "Guest-WiFi",
    52: "IoT",
    99: "Management",
}

VLAN_NAMES = {}

for _base, _name in _BASE_VLAN_NAMES.items():
    for _bldg_num, _bldg_label in _BUILDING_NAMES.items():
        VLAN_NAMES[_bldg_num * 100 + _base] = f"{_name}-{_bldg_label}"

VLAN_NAMES.update({
    20:  "App-Servers",
    21:  "File-Servers",
    30:  "Database",
    40:  "Security-Systems",
    99:  "OOB-Management",
    100: "RSPAN-IDS",
    60:  "DMZ",
    61:  "VPN-Pool",
    62:  "VPN-Admin",
    999: "Blackhole",
})

def _vlan_name(vlan_id: int) -> str:
    return VLAN_NAMES.get(vlan_id, f"VLAN{vlan_id}")


# ══════════════════════════════════════════════════════════════════════════════
#  RFC 5424 message builder
# ══════════════════════════════════════════════════════════════════════════════

def _build_syslog(result: dict, final_severity: str) -> bytes:
    """Build RFC 5424 syslog message with structured data."""
    rfc_sev    = RFC5424_SEVERITY.get(final_severity, 6)
    priority   = FACILITY_LOCAL1 * 8 + rfc_sev
    version    = 1
    timestamp  = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    msgid      = "IDS_ALERT" if result.get("is_attack") else "IDS_BENIGN"
    vlan_id    = result.get("vlan_id", 0)
    vlan_name  = _vlan_name(vlan_id)
    model_sev  = result.get("severity", "info")

    # Escape SD-PARAM reserved chars
    def sd_escape(v: str) -> str:
        return v.replace("\\", "\\\\").replace('"', '\\"').replace("]", "\\]")

    sd = (
        f'[horus@0 '
        f'attack_type="{sd_escape(str(result.get("attack_type", "UNKNOWN")))}" '
        f'confidence="{result.get("confidence", 0):.4f}" '
        f'group_pred="{sd_escape(str(result.get("group_pred", "")))}" '
        f'src_ip="{sd_escape(str(result.get("src_ip", ""))  )}" '
        f'dst_ip="{sd_escape(str(result.get("dst_ip", ""))  )}" '
        f'dst_port="{result.get("dst_port", 0)}" '
        f'vlan_id="{vlan_id}" '
        f'vlan_name="{vlan_name}" '
        f'model_sev="{model_sev}"'
        f']'
    )

    msg = (
        f"HORUS-IDS [{final_severity.upper()}] "
        f"{result.get('attack_type', 'UNKNOWN')} detected on {vlan_name} "
        f"(VLAN {vlan_id}) "
        f"src={result.get('src_ip', '-')} "
        f"dst={result.get('dst_ip', '-')}:{result.get('dst_port', 0)} "
        f"confidence={result.get('confidence', 0):.2%}"
    )

    syslog_line = (
        f"<{priority}>{version} {timestamp} {_HOSTNAME} "
        f"{_APP_NAME} {_PROCID} {msgid} {sd} {msg}"
    )
    return syslog_line.encode("utf-8", errors="replace")


# ══════════════════════════════════════════════════════════════════════════════
#  Public dispatch function
# ══════════════════════════════════════════════════════════════════════════════

def dispatch(result: dict):
    """Escalate severity, filter, and send syslog."""
    vlan_id      = int(result.get("vlan_id") or 0)
    model_sev    = result.get("severity", "info")
    is_attack    = result.get("is_attack", False)

    # Escalate before threshold check
    final_sev = _escalate_severity(model_sev, vlan_id)

    # Skip benign on non-critical VLANs
    if not is_attack and vlan_id not in config.CRITICAL_VLANS:
        return

    if not _above_threshold(final_sev):
        return

    msg_bytes = _build_syslog(result, final_sev)
    try:
        _send_udp(msg_bytes, config.SYSLOG_SERVER, config.SYSLOG_PORT)
    except OSError as exc:
        log.error("Failed to send syslog: %s", exc)
        return

    log.info(
        "[%s] %s on %s (VLAN %d) | src=%s dst=%s:%s | conf=%.2f",
        final_sev.upper(),
        result.get("attack_type", "?"),
        _vlan_name(vlan_id),
        vlan_id,
        result.get("src_ip", "-"),
        result.get("dst_ip", "-"),
        result.get("dst_port", "-"),
        result.get("confidence", 0),
    )
