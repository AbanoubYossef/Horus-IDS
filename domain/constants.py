"""Domain constants -- attack taxonomy, severity, hierarchical groups."""

SEVERITY_MAP = {
    "BENIGN":             "info",
    "DDoS":               "critical",
    "DoS GoldenEye":      "critical",
    "DoS Hulk":           "critical",
    "DoS Slow":           "critical",
    "PortScan":           "medium",
    "Bot":                "high",
    "FTP-Patator":        "medium",
    "SSH-Patator":        "medium",
    "DDoS Amplification": "critical",
    "DDoS SYN Flood":     "critical",
    "DDoS UDP Flood":     "critical",
    "DDoS Volumetric":    "critical",
}

HIERARCHICAL_GROUPS = {
    "BENIGN":      ["BENIGN"],
    "DDoS-family": ["DDoS", "DDoS Amplification", "DDoS SYN Flood", "DDoS UDP Flood"],
    "DoS-family":  ["DoS Hulk", "DoS GoldenEye", "DoS Slow"],
    "Brute-force": ["FTP-Patator", "SSH-Patator"],
    "PortScan":    ["PortScan"],
    "Bot":         ["Bot"],
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

TARGET_CLASSES_11 = {
    "BENIGN", "DDoS", "DoS GoldenEye", "DoS Hulk", "DoS Slow",
    "PortScan", "Bot", "FTP-Patator", "SSH-Patator",
    "DDoS Amplification", "DDoS Volumetric",
}
