"""capture/sources/syslog_source.py — Syslog receiver (inbound from switches)."""

import logging
import socket
import threading

import config

log = logging.getLogger("flow_capture")


class SyslogReceiver(threading.Thread):
    """Listens for switch syslog messages and logs security-relevant ones."""

    # IOS message IDs → WARNING
    _ALERT_IDS = {
        "PSECURE_VIOLATION",
        "IPACCESSLOGP",
        "IPACCESSLOGDP",
        "SSH_FAILED",
        "LOGIN_FAILED",
        "DHCP_SNOOPING_ERRMSG",
        "OSPF-5-ADJCHG",
        "OSPF_ADJCHG",
    }

    # IOS message IDs → INFO
    _INFO_IDS = {
        "UPDOWN",
        "CHANGED",
    }

    def run(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("0.0.0.0", config.SYSLOG_LISTEN_PORT))
        sock.settimeout(1.0)
        log.info("Syslog receiver on UDP %d (switch events inbound)",
                 config.SYSLOG_LISTEN_PORT)

        while True:
            try:
                data, (src_addr, _) = sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError as exc:
                log.error("SyslogReceiver socket error: %s", exc)
                continue

            try:
                msg = data.decode("utf-8", errors="replace").strip()
                self._handle(src_addr, msg)
            except Exception as exc:
                log.debug("Syslog parse error from %s: %s", src_addr, exc)

    def _handle(self, src_addr: str, msg: str):
        upper = msg.upper()

        if any(aid in upper for aid in self._ALERT_IDS):
            log.warning("[SWITCH-SYSLOG] switch=%s msg=%s", src_addr, msg)
        elif any(iid in upper for iid in self._INFO_IDS):
            log.info("[SWITCH-SYSLOG] switch=%s msg=%s", src_addr, msg)
        else:
            log.debug("[SWITCH-SYSLOG] switch=%s msg=%s", src_addr, msg)
