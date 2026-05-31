"""
tools/send_test_netflow.py — emit a synthetic NetFlow v5 datagram so we can
verify the capture -> API -> DB chain without waiting for real switch traffic.

Usage:
    python3 tools/send_test_netflow.py [host] [port]

Defaults to 127.0.0.1:2055.  Sends a single v5 datagram with one record
representing a DDoS-shaped flow (high pps, short duration).
"""
import socket
import struct
import sys
import time

HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 2055

# NetFlow v5 header (24 bytes): version count uptime unix_secs unix_nsecs
# flow_seq engine_type engine_id sample_interval
now = int(time.time())
uptime_ms = 1_234_567
header = struct.pack(">HHIIIIBBH", 5, 1, uptime_ms, now, 0, 1, 0, 0, 0)

# NetFlow v5 record (48 bytes)
src_ip = socket.inet_aton("203.0.113.7")     # external (TEST-NET-3)
dst_ip = socket.inet_aton("10.20.0.10")      # internal app server
nexthop = socket.inet_aton("10.40.0.252")
record = struct.pack(
    ">4s4s4sHHIIIIHHBBBBHHBBH",
    src_ip, dst_ip, nexthop,
    0, 0,                       # in_if, out_if
    50_000,                     # pkts
    3_000_000,                  # octets (~3 MB)
    uptime_ms - 5_000,          # first switched (5s ago)
    uptime_ms,                  # last switched
    443, 443,                   # src_port, dst_port
    0,                          # pad
    0x02,                       # tcp_flags = SYN
    6,                          # protocol = TCP
    0,                          # tos
    0, 0, 0, 0, 0,              # src_as, dst_as, src_mask, dst_mask, pad
)

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.sendto(header + record, (HOST, PORT))
s.close()
print(f"sent NetFlow v5 (1 record) to {HOST}:{PORT}")
