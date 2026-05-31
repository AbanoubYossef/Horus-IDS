"""capture/sources/snmp_source.py — SNMP trap receiver (v1/v2c/v3, minimal BER)."""

import logging
import socket
import threading

import config

log = logging.getLogger("flow_capture")


class SNMPTrapReceiver(threading.Thread):
    """Listens for SNMP traps and logs security-relevant ones at WARNING."""

    _KNOWN_TRAPS = {
        "1.3.6.1.6.3.1.1.5.1": "coldStart",
        "1.3.6.1.6.3.1.1.5.2": "warmStart",
        "1.3.6.1.6.3.1.1.5.3": "linkDown",
        "1.3.6.1.6.3.1.1.5.4": "linkUp",
        "1.3.6.1.6.3.1.1.5.5": "authenticationFailure",
        "1.3.6.1.6.3.1.1.5.6": "egpNeighborLoss",
        "1.3.6.1.4.1.9.9.315.0.0.1": "ciscoPortSecurityViolation",
        "1.3.6.1.4.1.9.9.41.2.0.1":  "clogMessageGenerated",
    }

    _ALERT_TRAPS = {
        "authenticationFailure",
        "ciscoPortSecurityViolation",
        "linkDown",
    }

    def run(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("0.0.0.0", config.SNMP_PORT))
        sock.settimeout(1.0)
        log.info("SNMP trap receiver on UDP %d", config.SNMP_PORT)

        while True:
            try:
                data, (src_addr, _) = sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError as exc:
                log.error("SNMPTrapReceiver socket error: %s", exc)
                continue

            try:
                self._handle(src_addr, data)
            except Exception as exc:
                log.debug("SNMP parse error from %s: %s", src_addr, exc)

    # ── Minimal BER helpers ──────────────────────────────────────────────────

    def _ber_tlv(self, data: bytes, pos: int):
        """Return (tag, value_bytes, next_pos) or None on error."""
        if pos >= len(data):
            return None
        tag  = data[pos]; pos += 1
        if pos >= len(data):
            return None
        b = data[pos]; pos += 1
        if b < 0x80:
            length = b
        else:
            nb = b & 0x7f
            if pos + nb > len(data):
                return None
            length = int.from_bytes(data[pos:pos + nb], "big")
            pos += nb
        if pos + length > len(data):
            return None
        return tag, data[pos:pos + length], pos + length

    def _decode_oid(self, raw: bytes) -> str:
        if not raw:
            return ""
        first = raw[0]
        parts = [str(first // 40), str(first % 40)]
        i = 1; val = 0
        while i < len(raw):
            b = raw[i]; i += 1
            val = (val << 7) | (b & 0x7f)
            if not (b & 0x80):
                parts.append(str(val)); val = 0
        return ".".join(parts)

    # ── Trap dispatcher ──────────────────────────────────────────────────────

    def _handle(self, src_addr: str, data: bytes):
        # SEQUENCE wrapper
        tlv = self._ber_tlv(data, 0)
        if not tlv or tlv[0] != 0x30:
            return
        inner = tlv[1]

        # version: 0=v1, 1=v2c, 3=v3
        tlv = self._ber_tlv(inner, 0)
        if not tlv or tlv[0] != 0x02:
            return
        version = int.from_bytes(tlv[1], "big")
        pos = tlv[2]

        if version == 3:
            self._handle_v3(src_addr, inner, pos)
            return

        # community string (v1/v2c)
        tlv = self._ber_tlv(inner, pos)
        if not tlv or tlv[0] != 0x04:
            return
        community = tlv[1].decode("utf-8", errors="replace")
        pos = tlv[2]

        # PDU (0xA4=v1, 0xA6=v2c)
        tlv = self._ber_tlv(inner, pos)
        if not tlv:
            return
        pdu_tag, pdu_data, _ = tlv

        trap_oid = ""

        if pdu_tag == 0xA4:
            # v1: enterprise OID
            t2 = self._ber_tlv(pdu_data, 0)
            if t2 and t2[0] == 0x06:
                trap_oid = self._decode_oid(t2[1])

        elif pdu_tag == 0xA6:
            # v2c: skip request-id, error-status, error-index
            p2 = 0
            for _ in range(3):
                t2 = self._ber_tlv(pdu_data, p2)
                if not t2:
                    return
                p2 = t2[2]
            # varbinds
            t2 = self._ber_tlv(pdu_data, p2)
            if not t2 or t2[0] != 0x30:
                return
            varbinds = t2[1]
            # Find snmpTrapOID.0
            vpos = 0
            while vpos < len(varbinds):
                vb = self._ber_tlv(varbinds, vpos)
                if not vb or vb[0] != 0x30:
                    break
                vpos = vb[2]
                oid_tlv = self._ber_tlv(vb[1], 0)
                if not oid_tlv or oid_tlv[0] != 0x06:
                    continue
                oid_str = self._decode_oid(oid_tlv[1])
                if "1.3.6.1.6.3.1.1.4.1" in oid_str:
                    val_tlv = self._ber_tlv(vb[1], oid_tlv[2])
                    if val_tlv and val_tlv[0] == 0x06:
                        trap_oid = self._decode_oid(val_tlv[1])
                    break

        label = self._KNOWN_TRAPS.get(trap_oid, trap_oid or "unknown")
        if label in self._ALERT_TRAPS:
            log.warning("[SNMP-TRAPv%d] switch=%s community=%s trap=%s oid=%s",
                        version + 1, src_addr, community, label, trap_oid)
        else:
            log.info("[SNMP-TRAPv%d] switch=%s community=%s trap=%s",
                     version + 1, src_addr, community, label)

    def _handle_v3(self, src_addr: str, inner: bytes, pos: int):
        """Parse SNMPv3 trap. Encrypted (authPriv) traps are logged but not decoded."""
        # msgGlobalData
        t = self._ber_tlv(inner, pos)
        if not t or t[0] != 0x30:
            return
        msg_global = t[1]; pos = t[2]

        # skip msgID, msgMaxSize
        p2 = 0
        for _ in range(2):
            t2 = self._ber_tlv(msg_global, p2)
            if not t2:
                return
            p2 = t2[2]

        # msgFlags (bit0=auth, bit1=priv)
        t2 = self._ber_tlv(msg_global, p2)
        if not t2 or t2[0] != 0x04 or not t2[1]:
            return
        priv_flag = bool(t2[1][0] & 0x02)

        # skip security params
        t = self._ber_tlv(inner, pos)
        if not t or t[0] != 0x04:
            return
        pos = t[2]

        # scopedPDU
        t = self._ber_tlv(inner, pos)
        if not t:
            return

        if priv_flag or t[0] != 0x30:
            log.info("[SNMP-TRAPv3] switch=%s authPriv trap received "
                     "(encrypted — cannot decode without USM privacy key)", src_addr)
            return

        # plaintext scopedPDU: skip contextEngineID + contextName
        scoped = t[1]; p2 = 0
        for _ in range(2):
            t2 = self._ber_tlv(scoped, p2)
            if not t2:
                return
            p2 = t2[2]

        # PDU (0xA6 = SNMPv2-Trap)
        t2 = self._ber_tlv(scoped, p2)
        if not t2 or t2[0] != 0xA6:
            return
        pdu_data = t2[1]

        # skip request-id, error-status, error-index
        p3 = 0
        for _ in range(3):
            t3 = self._ber_tlv(pdu_data, p3)
            if not t3:
                return
            p3 = t3[2]

        # varbinds
        t3 = self._ber_tlv(pdu_data, p3)
        if not t3 or t3[0] != 0x30:
            return
        varbinds = t3[1]

        trap_oid = ""
        vpos = 0
        while vpos < len(varbinds):
            vb = self._ber_tlv(varbinds, vpos)
            if not vb or vb[0] != 0x30:
                break
            vpos = vb[2]
            oid_tlv = self._ber_tlv(vb[1], 0)
            if not oid_tlv or oid_tlv[0] != 0x06:
                continue
            oid_str = self._decode_oid(oid_tlv[1])
            if "1.3.6.1.6.3.1.1.4.1" in oid_str:
                val_tlv = self._ber_tlv(vb[1], oid_tlv[2])
                if val_tlv and val_tlv[0] == 0x06:
                    trap_oid = self._decode_oid(val_tlv[1])
                break

        label = self._KNOWN_TRAPS.get(trap_oid, trap_oid or "unknown")
        if label in self._ALERT_TRAPS:
            log.warning("[SNMP-TRAPv3] switch=%s trap=%s oid=%s", src_addr, label, trap_oid)
        else:
            log.info("[SNMP-TRAPv3] switch=%s trap=%s", src_addr, label)
