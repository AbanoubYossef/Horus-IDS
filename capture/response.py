"""capture/response.py — Automated switch response via SSH on VLAN 99."""

import logging
import os
import re
import threading
import time
from datetime import datetime, timezone
from typing import Optional

import paramiko
import requests

import config

log = logging.getLogger("response")

# ── Severity ordering ────────────────────────────────────────────────────────
_SEV_ORDER = ["info", "medium", "high", "critical"]


def _severity_gte(a: str, b: str) -> bool:
    try:
        return _SEV_ORDER.index(a) >= _SEV_ORDER.index(b)
    except ValueError:
        return False


# ── In-memory block table: (src_ip, group) → expiry monotonic time ──────────
_block_table: dict = {}
_block_lock  = threading.Lock()


def _is_blocked(src_ip: str, group: str = "") -> bool:
    key = (src_ip, group)
    with _block_lock:
        expiry = _block_table.get(key)
        if expiry is None:
            return False
        if time.monotonic() > expiry:
            del _block_table[key]
            return False
        return True


def _mark_blocked(src_ip: str, group: str = ""):
    key = (src_ip, group)
    with _block_lock:
        _block_table[key] = time.monotonic() + config.RESPONSE_BLOCK_TTL


# ── Switch selection: src_ip → management IP on VLAN 99 ─────────────────────

def _get_distribution_switch(src_ip: str) -> Optional[str]:
    """Map src_ip to its distribution/core switch management IP."""
    try:
        parts = src_ip.split(".")
        if len(parts) != 4 or parts[0] != "10":
            return None
        vlan_oct  = int(parts[1])
        bldg_oct  = int(parts[2])

        if vlan_oct in (10, 11, 12, 13, 50, 51, 52):
            if 1 <= bldg_oct <= 4:
                return f"10.99.{bldg_oct}.1"
        elif vlan_oct in (20, 21, 30, 40):
            return "10.99.0.252"   # Core SW1
    except (ValueError, IndexError):
        pass
    return None


# ── SSH helpers ──────────────────────────────────────────────────────────────

def _open_shell(switch_ip: str) -> Optional[paramiko.SSHClient]:
    """Open an SSH connection to switch_ip. Returns client or None on failure."""
    try:
        client = paramiko.SSHClient()
        known_hosts = config.SSH_KNOWN_HOSTS
        if known_hosts and os.path.isfile(known_hosts):
            client.load_host_keys(known_hosts)
            client.set_missing_host_key_policy(paramiko.RejectPolicy())
        else:
            if known_hosts:
                log.warning("SSH_KNOWN_HOSTS file not found: %s — falling back to AutoAddPolicy", known_hosts)
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            hostname=switch_ip,
            port=22,
            username=config.SSH_USER,
            key_filename=config.SSH_KEY_PATH,
            timeout=10,
            look_for_keys=False,
            allow_agent=False,
        )
        return client
    except paramiko.AuthenticationException:
        log.error("SSH auth failed for %s — verify SSH_KEY_PATH and SSH_USER", switch_ip)
    except paramiko.SSHException as exc:
        log.error("SSH error reaching %s: %s", switch_ip, exc)
    except OSError as exc:
        log.error("Network error reaching %s: %s", switch_ip, exc)
    return None


def _shell_run(client: paramiko.SSHClient, commands: list) -> str:
    """Send commands on an interactive shell. Returns terminal output."""
    shell = client.invoke_shell(width=220, height=50)
    time.sleep(0.5)
    shell.recv(8192)     # drain login banner + prompt

    for cmd in commands:
        shell.send(cmd + "\n")
        time.sleep(0.15)

    time.sleep(1.0)
    output = b""
    while shell.recv_ready():
        output += shell.recv(8192)
    return output.decode("utf-8", errors="replace")


def _ssh_exec(switch_ip: str, commands: list, action_label: str) -> bool:
    """SSH to switch_ip, execute commands, log output. Returns True on success."""
    client = _open_shell(switch_ip)
    if client is None:
        return False
    try:
        output = _shell_run(client, commands)
        log.warning("[RESPONSE/%s→%s]\n  Commands: %s\n  Output: %s",
                    action_label, switch_ip,
                    " | ".join(commands),
                    output.strip().replace("\n", " ↵ "))
        return True
    finally:
        client.close()


# ── MAC → interface lookup ───────────────────────────────────────────────────

def _expand_interface(abbr: str) -> str:
    """Expand Cisco IOS abbreviated interface names."""
    for short, full in (
        ("Gi", "GigabitEthernet"),
        ("Fa", "FastEthernet"),
        ("Te", "TenGigabitEthernet"),
        ("Po", "Port-channel"),
        ("Vl", "Vlan"),
        ("Et", "Ethernet"),
    ):
        if abbr.startswith(short):
            return full + abbr[len(short):]
    return abbr


def _lookup_source_interface(switch_ip: str, src_ip: str) -> Optional[str]:
    """ARP → MAC → interface lookup via SSH. Returns interface name or None."""
    client = _open_shell(switch_ip)
    if client is None:
        return None
    try:
        shell = client.invoke_shell(width=220, height=50)
        time.sleep(0.5)
        shell.recv(8192)

        # ARP lookup
        shell.send(f"show ip arp {src_ip}\n")
        time.sleep(0.6)
        arp_out = shell.recv(8192).decode("utf-8", errors="replace")

        # Parse Cisco ARP output for MAC
        mac = None
        for line in arp_out.splitlines():
            parts = line.split()
            for tok in parts:
                if re.match(r'^[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}$', tok, re.I):
                    mac = tok.lower()
                    break
            if mac:
                break

        if not mac:
            log.debug("No ARP entry for %s on %s", src_ip, switch_ip)
            return None

        # MAC table lookup
        shell.send(f"show mac address-table address {mac}\n")
        time.sleep(0.6)
        mac_out = shell.recv(8192).decode("utf-8", errors="replace")

        # Parse MAC table for interface
        iface = None
        for line in mac_out.splitlines():
            if mac.lower() in line.lower():
                parts = line.split()
                if parts:
                    raw = parts[-1]
                    # Skip trunk/port-channel entries
                    if not raw.lower().startswith("po"):
                        iface = _expand_interface(raw)
                        break

        return iface

    except Exception as exc:
        log.error("Interface lookup failed on %s for %s: %s", switch_ip, src_ip, exc)
        return None
    finally:
        client.close()


# ── Palo Alto PAN-OS User-ID API block ──────────────────────────────────────

def _paloalto_tag_ip(src_ip: str) -> bool:
    """Tag src_ip on the Palo Alto via User-ID API for edge blocking."""
    if not config.PALOALTO_MGMT_IP or not config.PALOALTO_API_KEY:
        log.warning(
            "[RESPONSE] INBOUND DDoS from %s — Palo Alto not configured "
            "(PALOALTO_MGMT_IP / PALOALTO_API_KEY unset). Syslog alert sent. "
            "Set vars when outside zone is built.", src_ip
        )
        return False

    uid_msg = (
        "<uid-message><version>1.0</version><type>update</type><payload>"
        "<register>"
        f'<entry ip="{src_ip}"><tag><member>{config.PALOALTO_BLOCK_TAG}</member></tag></entry>'
        "</register>"
        "</payload></uid-message>"
    )
    url = f"https://{config.PALOALTO_MGMT_IP}/api/"
    params = {
        "type":   "user-id",
        "action": "set",
        "key":    config.PALOALTO_API_KEY,
        "cmd":    uid_msg,
    }
    verify = config.PALOALTO_CA_CERT if config.PALOALTO_CA_CERT else False
    if not verify:
        log.warning("[RESPONSE] PALOALTO_CA_CERT not set — TLS verification disabled for PA API call")
    try:
        resp = requests.get(url, params=params, timeout=10, verify=verify)
        resp.raise_for_status()
        log.warning(
            "[RESPONSE] PA block applied: src=%s tag=%s http=%s",
            src_ip, config.PALOALTO_BLOCK_TAG, resp.status_code,
        )
        return True
    except requests.RequestException as exc:
        log.error("[RESPONSE] Palo Alto API error for %s: %s", src_ip, exc)
        return False


# ── IOS command templates ────────────────────────────────────────────────────

def _ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _acl_block_commands(src_ip: str, vlan_id: int) -> list:
    """Deny src_ip in ACL-IDS-BLOCK, apply inbound on VLAN SVI."""
    return [
        "configure terminal",
        "ip access-list extended ACL-IDS-BLOCK",
        f" deny ip host {src_ip} any log",
        " permit ip any any",
        "exit",
        f"interface vlan {vlan_id}",
        " ip access-group ACL-IDS-BLOCK in",
        "exit",
        "end",
    ]


def _shutdown_port_commands(interface: str, src_ip: str) -> list:
    """Shut down an access port and stamp it with a quarantine description."""
    return [
        "configure terminal",
        f"interface {interface}",
        f" description QUARANTINED-BY-IDS-{_ts()}-src-{src_ip}",
        " shutdown",
        "exit",
        "end",
    ]


def _isolate_vlan999_commands(interface: str, src_ip: str) -> list:
    """Move an access port to VLAN 999 (blackhole) and stamp description."""
    return [
        "configure terminal",
        f"interface {interface}",
        f" description ISOLATED-BY-IDS-{_ts()}-src-{src_ip}",
        " switchport access vlan 999",
        "exit",
        "end",
    ]


def _rate_limit_commands(interface: str, rate_bps: int = 100_000_000) -> list:
    """Rate-limit on port-channel for DDoS mitigation (default 100 Mbps)."""
    burst = rate_bps // 8       # normal burst = 1 second worth of bytes
    excess = burst * 2
    return [
        "configure terminal",
        f"interface {interface}",
        f" rate-limit input {rate_bps} {burst} {excess} "
        f"conform-action transmit exceed-action drop",
        "exit",
        "end",
    ]


# ── Public entry point ───────────────────────────────────────────────────────

def handle_result(result: dict):
    """Dispatch automated response for a prediction result (runs in daemon thread)."""
    if not result.get("is_attack", False):
        return

    src_ip   = result.get("src_ip", "")
    dst_ip   = result.get("dst_ip", "")
    vlan_id  = int(result.get("vlan_id") or 0)
    severity = result.get("severity", "info")
    group    = result.get("group_pred", "")
    attack   = result.get("attack_type", "")
    conf     = result.get("confidence", 0.0)
    direction = result.get("flow_direction", "UNKNOWN")

    if not src_ip or src_ip in ("-", ""):
        return

    # Skip monitor-only VLANs
    if vlan_id in config.MONITOR_VLANS:
        log.info("[RESPONSE] Skipping VLAN %d (MONITOR_ONLY) — human review required", vlan_id)
        return

    if not _severity_gte(severity, config.RESPONSE_MIN_SEVERITY):
        return

    if _is_blocked(src_ip, group):
        log.debug("[RESPONSE] %s/%s already blocked (TTL active)", src_ip, group)
        return

    switch_ip = _get_distribution_switch(src_ip)
    if switch_ip is None:
        log.debug("[RESPONSE] No switch mapping for src=%s VLAN=%d", src_ip, vlan_id)
        return

    _mark_blocked(src_ip, group)

    log.warning(
        "[RESPONSE] %s / %s | src=%s dst=%s VLAN=%d dir=%s sev=%s conf=%.2f → switch %s",
        group, attack, src_ip, dst_ip, vlan_id, direction, severity, conf, switch_ip,
    )

    # Dispatch in background thread
    threading.Thread(
        target=_execute_response,
        args=(group, attack, direction, src_ip, dst_ip, vlan_id, switch_ip),
        daemon=True,
        name=f"Response-{src_ip}",
    ).start()


# ── Response strategies (one per Level 1 group) ─────────────────────────────

def _respond_ddos(group, src_ip, dst_ip, vlan_id, switch_ip, direction):
    if direction == "LATERAL":
        cmds = _acl_block_commands(src_ip, vlan_id)
        _ssh_exec(switch_ip, cmds, "DDoS_ACL_BLOCK")
    else:
        _paloalto_tag_ip(src_ip)


def _respond_dos(group, src_ip, dst_ip, vlan_id, switch_ip, direction):
    cmds = _acl_block_commands(src_ip, vlan_id)
    _ssh_exec(switch_ip, cmds, "DoS_ACL_BLOCK")


def _respond_bruteforce(group, src_ip, dst_ip, vlan_id, switch_ip, direction):
    cmds = _acl_block_commands(src_ip, vlan_id)
    _ssh_exec(switch_ip, cmds, "BRUTE_ACL_BLOCK")
    iface = _lookup_source_interface(switch_ip, src_ip)
    if iface:
        cmds = _shutdown_port_commands(iface, src_ip)
        _ssh_exec(switch_ip, cmds, "BRUTE_PORT_SHUTDOWN")
    else:
        log.info("[RESPONSE] Brute-force: could not resolve access port for %s "
                 "— ACL block applied, port shutdown skipped", src_ip)


def _respond_isolate(group, src_ip, dst_ip, vlan_id, switch_ip, direction):
    iface = _lookup_source_interface(switch_ip, src_ip)
    if iface:
        cmds = _isolate_vlan999_commands(iface, src_ip)
        _ssh_exec(switch_ip, cmds, f"{group.upper()}_VLAN999_ISOLATE")
    else:
        log.info("[RESPONSE] %s: could not resolve access port for %s — falling back to ACL", group, src_ip)
        cmds = _acl_block_commands(src_ip, vlan_id)
        _ssh_exec(switch_ip, cmds, f"{group.upper()}_ACL_FALLBACK")


def _respond_bot(group, src_ip, dst_ip, vlan_id, switch_ip, direction):
    _respond_isolate(group, src_ip, dst_ip, vlan_id, switch_ip, direction)
    log.warning("[RESPONSE] Bot: C2 destination logged — dst_ip=%s src=%s VLAN=%d "
                "— check other devices for same C2 contact", dst_ip, src_ip, vlan_id)


_RESPONSE_STRATEGIES = {
    "DDoS-family": _respond_ddos,
    "DoS-family":  _respond_dos,
    "Brute-force": _respond_bruteforce,
    "PortScan":    _respond_isolate,
    "Bot":         _respond_bot,
}


def _execute_response(group: str, attack: str, direction: str,
                      src_ip: str, dst_ip: str, vlan_id: int, switch_ip: str):
    """Dispatch to the registered strategy for this Level 1 group."""
    strategy = _RESPONSE_STRATEGIES.get(group)
    if strategy:
        strategy(group, src_ip, dst_ip, vlan_id, switch_ip, direction)
