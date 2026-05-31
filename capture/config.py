"""capture/config.py — Env-based configuration for the capture service."""

import os

# ── HORUS API ──────────────────────────────────────────────────────────────
HORUS_API_URL = os.environ.get("HORUS_API_URL", "http://127.0.0.1:8000")
HORUS_API_KEY = os.environ.get("HORUS_API_KEY", "")

# ── Network interfaces ──────────────────────────────────────────────────────
# eth1: RSPAN mirror (read-only)  |  eth0: management NIC (VLAN 40)
CAPTURE_IFACE = os.environ.get("CAPTURE_IFACE", "eth1")
MGMT_IFACE    = os.environ.get("MGMT_IFACE",    "eth0")

# ── Syslog destination (reached via eth0) ───────────────────────────────────
SYSLOG_SERVER = os.environ.get("SYSLOG_SERVER", "127.0.0.1")
SYSLOG_PORT   = int(os.environ.get("SYSLOG_PORT", "514"))

# ── Batching ────────────────────────────────────────────────────────────────
BATCH_SIZE      = int(os.environ.get("BATCH_SIZE",      "100"))
BATCH_TIMEOUT_S = float(os.environ.get("BATCH_TIMEOUT_S", "2.0"))

# ── Alerting ────────────────────────────────────────────────────────────────
SEVERITY_ORDER    = ["info", "medium", "high", "critical"]
ALERT_MIN_SEVERITY = os.environ.get("ALERT_MIN_SEVERITY", "medium")

# ── Per-VLAN severity overrides ─────────────────────────────────────────────
# VLAN scheme: B1=1xx, B2=2xx, B3=3xx, B4=4xx. Server VLANs are global.
# Any detection on these VLANs → always CRITICAL
CRITICAL_VLANS = {
    151, 251, 351, 451,           # Guest-WiFi
    152, 252, 352, 452,           # IoT
    30, 40, 99,                   # Database, Security, OOB-Mgmt
    199, 299, 399, 499,           # Per-building management
}

# Escalate to HIGH minimum
HIGH_VLANS = {
    20, 21,                       # App/File Servers
    111, 211, 311, 411,           # Finance
    112, 212, 312, 412,           # HR
    113, 213, 313, 413,           # IT-Admin
    60,                           # DMZ
}

# Stay at MEDIUM minimum
MEDIUM_VLANS = {
    110, 210, 310, 410,           # General Users
    150, 250, 350, 450,           # VoIP
}

# Alert only, no automated response (IDS host + OOB management)
MONITOR_VLANS = {
    40,
    99, 199, 299, 399, 499,
}

# ── IP → VLAN / building inference ──────────────────────────────────────────
# 10.{base}.{building}.{host} → VLAN = building*100 + base (per-building)
# 10.{vlan}.x.x → VLAN = base (global/server VLANs)
_PER_BUILDING_BASES = {10, 11, 12, 13, 50, 51, 52, 99}
_GLOBAL_VLAN_BASES  = {20, 21, 30, 40, 60, 61, 62, 100}


def vlan_from_ip(ip: str) -> int:
    """Infer VLAN from IP, 0 if unknown. Used for untagged frames."""
    if not ip:
        return 0
    parts = ip.split(".")
    if len(parts) != 4 or parts[0] != "10":
        return 0
    try:
        base = int(parts[1])
        bldg = int(parts[2])
    except ValueError:
        return 0
    if base in _PER_BUILDING_BASES and 1 <= bldg <= 4:
        return bldg * 100 + base
    if base in _GLOBAL_VLAN_BASES:
        return base
    return 0


def building_from_ip(ip: str) -> int:
    """Return 1..4 for per-building IPs, 0 for global/server/unknown."""
    if not ip:
        return 0
    parts = ip.split(".")
    if len(parts) != 4 or parts[0] != "10":
        return 0
    try:
        base = int(parts[1])
        bldg = int(parts[2])
    except ValueError:
        return 0
    if base in _PER_BUILDING_BASES and 1 <= bldg <= 4:
        return bldg
    return 0

# ── Inbound listener ports ───────────────────────────────────────────────────
NETFLOW_PORT       = int(os.environ.get("NETFLOW_PORT",        "2055"))
SYSLOG_LISTEN_PORT = int(os.environ.get("SYSLOG_LISTEN_PORT",  "514"))
SNMP_PORT          = int(os.environ.get("SNMP_PORT",           "162"))

# ── Active response via SSH ───────────────────────────────────────────────────
SSH_KEY_PATH          = os.environ.get("SSH_KEY_PATH",          os.path.expanduser("~/.ssh/utcnbogyou_lab"))
SSH_KNOWN_HOSTS       = os.environ.get("SSH_KNOWN_HOSTS",       os.path.expanduser("~/.ssh/horus_known_hosts"))
SSH_USER              = os.environ.get("SSH_USER",              "UTCNBOGYOU")
SSH_ENABLE_PASSWORD   = os.environ.get("SSH_ENABLE_PASSWORD",   "")
RESPONSE_MIN_SEVERITY = os.environ.get("RESPONSE_MIN_SEVERITY", "high")
RESPONSE_BLOCK_TTL    = int(os.environ.get("RESPONSE_BLOCK_TTL", "300"))  # dedup TTL in seconds

# VLAN → switch management IPs (format: "vlan:ip;ip,vlan:ip")
_SWITCH_MAP_RAW = os.environ.get("SWITCH_VLAN_MAP", "")

def _parse_switch_map(raw: str) -> dict:
    """Parse "vlan:ip;ip,vlan:ip" → {vlan_int: [ip, ...]}"""
    result = {}
    for entry in raw.split(","):
        entry = entry.strip()
        if ":" not in entry:
            continue
        vlan_str, ips_str = entry.split(":", 1)
        try:
            vlan = int(vlan_str.strip())
            ips = [ip.strip() for ip in ips_str.split(";") if ip.strip()]
            if ips:
                result[vlan] = ips
        except ValueError:
            pass
    return result

SWITCH_VLAN_MAP = _parse_switch_map(_SWITCH_MAP_RAW)

# ── Palo Alto Next-Gen Firewall ─────────────────────────────────────────────
PALOALTO_MGMT_IP   = os.environ.get("PALOALTO_MGMT_IP",   "")
PALOALTO_API_KEY   = os.environ.get("PALOALTO_API_KEY",   "")
PALOALTO_BLOCK_TAG = os.environ.get("PALOALTO_BLOCK_TAG", "IDS-AUTO-BLOCK")
PALOALTO_CA_CERT   = os.environ.get("PALOALTO_CA_CERT",   "")

# ── Security management zone (10.40.40.0/24) — not yet active ───────────────
SIEM_IP         = os.environ.get("SIEM_IP",         "10.40.40.10")
NTP_IP          = os.environ.get("NTP_IP",           "10.40.40.40")
TACACS_IP       = os.environ.get("TACACS_IP",        "10.40.40.60")
FREERADIUS_IP   = os.environ.get("FREERADIUS_IP",    "10.40.40.61")
ANSIBLE_IP      = os.environ.get("ANSIBLE_IP",       "10.40.40.70")
JUMP_SERVER_IP  = os.environ.get("JUMP_SERVER_IP",   "10.40.40.80")

# ── Logging ──────────────────────────────────────────────────────────────────
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")
