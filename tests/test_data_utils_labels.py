"""
tests/test_data_utils.py — Unit tests for data_utils.py

Tests cover:
  - LABEL_MERGE normalisation across all three dataset formats
  - RENAME_MAP column normalisation
  - engineer_features() output shapes, names, and value ranges
  - DROP_KEYWORDS — metadata columns are correctly excluded
  - preprocess_df() on synthetic DataFrames (no file I/O)
"""

import numpy as np
import pandas as pd
import pytest

from data_utils import (
    LABEL_MERGE,
    LABEL_MERGE_11CLASS,
    RENAME_MAP,
    DROP_KEYWORDS,
    engineer_features,
)


# ══════════════════════════════════════════════════════════════════════════════
#  LABEL_MERGE
# ══════════════════════════════════════════════════════════════════════════════

class TestLabelMerge:
    """All variant label names collapse to canonical forms."""

    @pytest.mark.parametrize("raw, expected", [
        ("Benign",                    "BENIGN"),
        ("DoS attacks-Hulk",          "DoS Hulk"),
        ("DoS attacks-GoldenEye",     "DoS GoldenEye"),
        ("DoS attacks-Slowloris",     "DoS Slow"),
        ("DoS attacks-SlowHTTPTest",  "DoS Slow"),
        ("FTP-BruteForce",            "FTP-Patator"),
        ("SSH-Bruteforce",            "SSH-Patator"),
        ("DDoS attacks-LOIC-HTTP",    "DDoS"),
        ("DDOS attack-HOIC",          "DDoS"),
        ("DDOS attack-LOIC-UDP",      "DDoS"),
        ("DrDoS_DNS",                 "DDoS Amplification"),
        ("DrDoS_LDAP",                "DDoS Amplification"),
        ("DrDoS_NTP",                 "DDoS Amplification"),
        # Syn/UDP → later merged to DDoS Volumetric via LABEL_MERGE_11CLASS
        ("Syn",                       "DDoS SYN Flood"),
        ("UDP",                       "DDoS UDP Flood"),
    ])
    def test_cic_ids2018_variants(self, raw, expected):
        result = LABEL_MERGE.get(raw, raw)
        assert result == expected, f"LABEL_MERGE[{raw!r}] = {result!r}, expected {expected!r}"

    def test_unicode_web_attack_en_dash(self):
        label = "Web Attack \u2013 Brute Force"
        assert LABEL_MERGE[label] == "Web Attack - Brute Force"

    def test_mojibake_web_attack(self):
        label = "Web Attack ï¿½ XSS"
        assert LABEL_MERGE[label] == "Web Attack - XSS"

    def test_benign_passthrough(self):
        """BENIGN is already canonical — not in the map."""
        assert "BENIGN" not in LABEL_MERGE

    def test_unknown_label_unchanged(self):
        assert LABEL_MERGE.get("SomeUnknownAttack", "SomeUnknownAttack") == "SomeUnknownAttack"


class TestLabelMerge10Class:
    """10-class merge map collapses further DDoS2019 sub-types."""

    @pytest.mark.parametrize("raw, expected", [
        ("DDoS SYN Flood", "DDoS Volumetric"),
        ("DDoS UDP Flood", "DDoS Volumetric"),
    ])
    def test_ddos_volumetric_merge(self, raw, expected):
        result = LABEL_MERGE_11CLASS.get(raw, raw)
        assert result == expected


# ══════════════════════════════════════════════════════════════════════════════
#  RENAME_MAP
# ══════════════════════════════════════════════════════════════════════════════

class TestRenameMap:
    """CIC-IDS2018 abbreviated names map to CIC-IDS2017 full names."""

    @pytest.mark.parametrize("abbrev, full", [
        ("Tot Fwd Pkts",      "Total Fwd Packets"),
        ("Tot Bwd Pkts",      "Total Backward Packets"),
        ("Flow Byts/s",       "Flow Bytes/s"),
        ("Flow Pkts/s",       "Flow Packets/s"),
        ("FIN Flag Cnt",      "FIN Flag Count"),
        ("SYN Flag Cnt",      "SYN Flag Count"),
        ("Pkt Len Min",       "Min Packet Length"),
        ("Pkt Len Max",       "Max Packet Length"),
        ("Init Fwd Win Byts", "Init_Win_bytes_forward"),
        ("Init Bwd Win Byts", "Init_Win_bytes_backward"),
        ("Dst Port",          "Destination Port"),
    ])
    def test_mapping(self, abbrev, full):
        assert RENAME_MAP[abbrev] == full

    def test_rename_applied_to_dataframe(self):
        df = pd.DataFrame([[1, 2, 3]], columns=["Tot Fwd Pkts", "Tot Bwd Pkts", "Label"])
        df.rename(columns=RENAME_MAP, inplace=True)
        assert "Total Fwd Packets" in df.columns
        assert "Total Backward Packets" in df.columns
        assert "Tot Fwd Pkts" not in df.columns


# ══════════════════════════════════════════════════════════════════════════════
#  DROP_KEYWORDS
# ══════════════════════════════════════════════════════════════════════════════

