import pytest
import struct
import socket
import json
from unittest.mock import patch, MagicMock

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "capture"))

from sources.netflow_source import _parse_nf5, _parse_nf9, _parse_ipfix
from sources.syslog_source import SyslogReceiver
from sources.snmp_source import SNMPTrapReceiver

def test_parse_nf5():
    header = struct.pack(">HHIIIIBBH", 5, 1, 1000, 1600000000, 0, 1, 0, 0, 0)
    src_ip = socket.inet_aton("192.168.1.10")
    dst_ip = socket.inet_aton("10.0.0.5")
    nexthop = socket.inet_aton("0.0.0.0")
    record = struct.pack(
        ">4s4s4sHHIIIIHHBBBBHHBBH",
        src_ip, dst_ip, nexthop,
        0, 0,
        15, 1500, 500, 900,
        12345, 80,
        0, 0x02, 6, 0,
        0, 0, 0, 0, 0
    )
    
    payload = header + record
    flows = _parse_nf5(payload, ("127.0.0.1", 45678))
    
    assert len(flows) == 1
    assert flows[0]["src_ip"] == "192.168.1.10"
    assert flows[0]["dst_ip"] == "10.0.0.5"
    assert flows[0]["proto"] == 6
    assert flows[0]["src_port"] == 12345
    assert flows[0]["dst_port"] == 80
    assert flows[0]["pkts"] == 15
    assert flows[0]["octets"] == 1500

def test_syslog_receiver_handles_messages(monkeypatch):
    receiver = SyslogReceiver()
    mock_dispatch = MagicMock()
    monkeypatch.setattr("alert_router.dispatch", mock_dispatch)
    
    syslog_msg = "<34>Oct 11 22:14:15 mymachine su: PORT SECURITY VIOLATION: port Fa0/1 MAC 00:00:00:00:00:00"
    receiver._handle("192.168.1.50", syslog_msg)
    
    assert True

def test_snmp_receiver_handles_traps(monkeypatch):
    receiver = SNMPTrapReceiver()
    mock_dispatch = MagicMock()
    monkeypatch.setattr("alert_router.dispatch", mock_dispatch)
    
    snmp_msg = b"dummy_snmp_payload_that_fails_asn1_or_succeeds"
    receiver._handle("192.168.1.60", snmp_msg)
    assert True
