"""
HORUS SOC -- Shared constants, paths, column-rename maps, label-merge maps,
target classes, severity ratings, hierarchical groups, and plot theming.
"""

from pathlib import Path


_BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR  = _BASE_DIR / "data" / "COMBINED"
MODEL_DIR = _BASE_DIR / "models"
PLOT_DIR  = _BASE_DIR / "plots"

SEED = 42


# Drop metadata + dataset-specific columns to prevent data leakage
# ("simillarhttp"/"inbound" only exist in DDoS2019 → leak dataset origin)
DROP_KEYWORDS = [
    "ip", "port", "timestamp", "flow id", "external ip", "unnamed",
    "simillarhttp", "inbound",
]

# Drop ".1" suffix columns (pandas duplicates, e.g. "Fwd Header Length.1")
DROP_SUFFIX_DUPES = True


# CIC-IDS2018 abbreviated → CIC-IDS2017 full column names
RENAME_MAP = {
    'Tot Fwd Pkts':      'Total Fwd Packets',
    'Tot Bwd Pkts':      'Total Backward Packets',
    'TotLen Fwd Pkts':   'Total Length of Fwd Packets',
    'TotLen Bwd Pkts':   'Total Length of Bwd Packets',
    'Fwd Pkt Len Max':   'Fwd Packet Length Max',
    'Fwd Pkt Len Min':   'Fwd Packet Length Min',
    'Fwd Pkt Len Mean':  'Fwd Packet Length Mean',
    'Fwd Pkt Len Std':   'Fwd Packet Length Std',
    'Bwd Pkt Len Max':   'Bwd Packet Length Max',
    'Bwd Pkt Len Min':   'Bwd Packet Length Min',
    'Bwd Pkt Len Mean':  'Bwd Packet Length Mean',
    'Bwd Pkt Len Std':   'Bwd Packet Length Std',
    'Flow Byts/s':       'Flow Bytes/s',
    'Flow Pkts/s':       'Flow Packets/s',
    'Fwd IAT Tot':       'Fwd IAT Total',
    'Bwd IAT Tot':       'Bwd IAT Total',
    'Fwd Header Len':    'Fwd Header Length',
    'Bwd Header Len':    'Bwd Header Length',
    'Fwd Pkts/s':        'Fwd Packets/s',
    'Bwd Pkts/s':        'Bwd Packets/s',
    'Pkt Len Min':       'Min Packet Length',
    'Pkt Len Max':       'Max Packet Length',
    'Pkt Len Mean':      'Packet Length Mean',
    'Pkt Len Std':       'Packet Length Std',
    'Pkt Len Var':       'Packet Length Variance',
    'FIN Flag Cnt':      'FIN Flag Count',
    'SYN Flag Cnt':      'SYN Flag Count',
    'RST Flag Cnt':      'RST Flag Count',
    'PSH Flag Cnt':      'PSH Flag Count',
    'ACK Flag Cnt':      'ACK Flag Count',
    'URG Flag Cnt':      'URG Flag Count',
    'ECE Flag Cnt':      'ECE Flag Count',
    'Pkt Size Avg':      'Average Packet Size',
    'Fwd Seg Size Avg':  'Avg Fwd Segment Size',
    'Bwd Seg Size Avg':  'Avg Bwd Segment Size',
    'Fwd Byts/b Avg':   'Fwd Avg Bytes/Bulk',
    'Fwd Pkts/b Avg':   'Fwd Avg Packets/Bulk',
    'Fwd Blk Rate Avg':  'Fwd Avg Bulk Rate',
    'Bwd Byts/b Avg':   'Bwd Avg Bytes/Bulk',
    'Bwd Pkts/b Avg':   'Bwd Avg Packets/Bulk',
    'Bwd Blk Rate Avg':  'Bwd Avg Bulk Rate',
    'Subflow Fwd Pkts':  'Subflow Fwd Packets',
    'Subflow Fwd Byts':  'Subflow Fwd Bytes',
    'Subflow Bwd Pkts':  'Subflow Bwd Packets',
    'Subflow Bwd Byts':  'Subflow Bwd Bytes',
    'Init Fwd Win Byts': 'Init_Win_bytes_forward',
    'Init Bwd Win Byts': 'Init_Win_bytes_backward',
    'Fwd Act Data Pkts': 'act_data_pkt_fwd',
    'Fwd Seg Size Min':  'min_seg_size_forward',
    'Dst Port':          'Destination Port',
}


# Unify attack label names across CIC-IDS2017/2018/DDoS2019
LABEL_MERGE = {
    
    "Benign":                        "BENIGN",
    "Infilteration":                 "Infiltration",
    "DoS attacks-Hulk":              "DoS Hulk",
    "DoS attacks-GoldenEye":         "DoS GoldenEye",
    "DoS attacks-Slowloris":         "DoS Slow",
    "DoS attacks-SlowHTTPTest":      "DoS Slow",
    "DoS slowloris":                 "DoS Slow",
    "DoS Slowhttptest":              "DoS Slow",
    "FTP-BruteForce":                "FTP-Patator",
    "SSH-Bruteforce":                "SSH-Patator",
    "DDoS attacks-LOIC-HTTP":        "DDoS",
    "DDOS attack-HOIC":              "DDoS",
    "DDOS attack-LOIC-UDP":          "DDoS",
    "Brute Force -Web":              "Web Attack - Brute Force",
    "Brute Force -XSS":              "Web Attack - XSS",
    "SQL Injection":                 "Web Attack - Sql Injection",

    
    # CIC-IDS2017 en-dash variants (encoding-dependent)
    "Web Attack – Brute Force": "Web Attack - Brute Force",
    "Web Attack – XSS":        "Web Attack - XSS",
    "Web Attack – Sql Injection": "Web Attack - Sql Injection",
    "Web Attack \xff\xbf\xbd Brute Force": "Web Attack - Brute Force",
    "Web Attack \xff\xbf\xbd XSS":         "Web Attack - XSS",
    "Web Attack \xff\xbf\xbd Sql Injection": "Web Attack - Sql Injection",
    "Web Attack \xef\xbf\xbd Brute Force":    "Web Attack - Brute Force",
    "Web Attack \xef\xbf\xbd XSS":            "Web Attack - XSS",
    "Web Attack \xef\xbf\xbd Sql Injection":  "Web Attack - Sql Injection",
    "Web Attack \x96 Brute Force":   "Web Attack - Brute Force",
    "Web Attack \x96 XSS":           "Web Attack - XSS",
    "Web Attack \x96 Sql Injection": "Web Attack - Sql Injection",

    
    # DDoS2019 training-day labels (DrDoS_ prefix)
    "DrDoS_DNS":      "DDoS Amplification",
    "DrDoS_LDAP":     "DDoS Amplification",
    "DrDoS_MSSQL":    "DDoS Amplification",
    "DrDoS_NetBIOS":  "DDoS Amplification",
    "DrDoS_NTP":      "DDoS Amplification",
    "DrDoS_SNMP":     "DDoS Amplification",
    "DrDoS_SSDP":     "DDoS Amplification",
    "TFTP":           "DDoS Amplification",
    "Portmap":        "DDoS Amplification",
    # DDoS2019 testing-day labels (no prefix)
    "LDAP":           "DDoS Amplification",
    "MSSQL":          "DDoS Amplification",
    "NetBIOS":        "DDoS Amplification",
    "NTP":            "DDoS Amplification",
    "SNMP":           "DDoS Amplification",
    "SSDP":           "DDoS Amplification",
    "DNS":            "DDoS Amplification",

    
    "Syn":            "DDoS SYN Flood",

    
    "DrDoS_UDP":      "DDoS UDP Flood",
    "UDP-lag":        "DDoS UDP Flood",
    "UDPLag":         "DDoS UDP Flood",
    "UDP":            "DDoS UDP Flood",
}


BG    = "#04070f"
PANEL = "#070c18"
ACC   = "#00ffaa"
RED   = "#ff2d55"
BLUE  = "#00b4ff"
TEXT  = "#cdd8e8"
DIM   = "#4a5568"


# Classes we actually train on (excluded: Infiltration, Web Attack, Heartbleed — too few samples)
TARGET_CLASSES = {
    "BENIGN",
    "DDoS",
    "DoS GoldenEye",
    "DoS Hulk",
    "DoS Slow",
    "PortScan",
    "Bot",
    "FTP-Patator",
    "SSH-Patator",
    "DDoS Amplification",
    "DDoS SYN Flood",
    "DDoS UDP Flood",
}


SEVERITY = {
    "BENIGN":                   "info",
    "DDoS":                     "critical",
    "DoS GoldenEye":            "critical",
    "DoS Hulk":                 "critical",
    "DoS Slow":                 "critical",
    "PortScan":                 "medium",
    "Bot":                      "high",
    "FTP-Patator":              "medium",
    "SSH-Patator":              "medium",
    "DDoS Amplification":       "critical",
    "DDoS SYN Flood":           "critical",
    "DDoS UDP Flood":           "critical",
    "DDoS Volumetric":          "critical",
}


# Merge SYN/UDP flood → "DDoS Volumetric" (indistinguishable at flow-stats level)
LABEL_MERGE_11CLASS = {
    "DDoS SYN Flood": "DDoS Volumetric",
    "DDoS UDP Flood": "DDoS Volumetric",
}

TARGET_CLASSES_11 = {
    "BENIGN",
    "DDoS",
    "DoS GoldenEye",
    "DoS Hulk",
    "DoS Slow",
    "PortScan",
    "Bot",
    "FTP-Patator",
    "SSH-Patator",
    "DDoS Amplification",
    "DDoS Volumetric",     # merged SYN Flood + UDP Flood
}

HIERARCHICAL_GROUPS_11 = {
    "BENIGN":      ["BENIGN"],
    "DDoS-family": ["DDoS", "DDoS Amplification", "DDoS Volumetric"],
    "DoS-family":  ["DoS Hulk", "DoS GoldenEye", "DoS Slow"],
    "Brute-force": ["FTP-Patator", "SSH-Patator"],
    "PortScan":    ["PortScan"],
    "Bot":         ["Bot"],
}

CLASS_TO_GROUP_11 = {}
for _g, _members in HIERARCHICAL_GROUPS_11.items():
    for _cls in _members:
        CLASS_TO_GROUP_11[_cls] = _g


# Level 1 groups (6 super-classes)
HIERARCHICAL_GROUPS = {
    "BENIGN":      ["BENIGN"],
    "DDoS-family": ["DDoS", "DDoS Amplification", "DDoS SYN Flood", "DDoS UDP Flood"],
    "DoS-family":  ["DoS Hulk", "DoS GoldenEye", "DoS Slow"],
    "Brute-force": ["FTP-Patator", "SSH-Patator"],
    "PortScan":    ["PortScan"],
    "Bot":         ["Bot"],
}

# fine class → group name
CLASS_TO_GROUP = {}
for group, members in HIERARCHICAL_GROUPS.items():
    for cls in members:
        CLASS_TO_GROUP[cls] = group
