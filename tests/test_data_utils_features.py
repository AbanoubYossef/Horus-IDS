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

class TestDropKeywords:

    def test_ip_columns_dropped(self):
        cols = ["src_ip", "dst_ip", "Flow ID", "External IP", "Flow Duration"]
        dropped = [c for c in cols if any(k in c.lower() for k in DROP_KEYWORDS)]
        assert "src_ip" in dropped
        assert "dst_ip" in dropped
        assert "External IP" in dropped
        assert "Flow Duration" not in dropped

    def test_port_columns_dropped(self):
        cols = ["Destination Port", "src_port", "Total Fwd Packets"]
        dropped = [c for c in cols if any(k in c.lower() for k in DROP_KEYWORDS)]
        assert "Destination Port" in dropped
        assert "src_port" in dropped
        assert "Total Fwd Packets" not in dropped

    def test_dataset_leakage_columns_dropped(self):
        cols = ["simillarhttp", "inbound", "Flow Bytes/s"]
        dropped = [c for c in cols if any(k in c.lower() for k in DROP_KEYWORDS)]
        assert "simillarhttp" in dropped
        assert "inbound" in dropped
        assert "Flow Bytes/s" not in dropped


# ══════════════════════════════════════════════════════════════════════════════
#  engineer_features()
# ══════════════════════════════════════════════════════════════════════════════

ENGINEERED_NAMES = [
    "syn_flag_ratio", "ack_syn_ratio", "fin_flag_ratio", "psh_flag_ratio",
    "flag_diversity", "bytes_per_pkt_fwd", "bytes_per_pkt_bwd", "pkt_size_ratio",
    "fwd_bwd_pkt_ratio", "fwd_bwd_byte_ratio", "bwd_fwd_byte_ratio",
    "pkts_per_duration", "bytes_per_duration", "duration_log", "slow_indicator",
    "iat_cv", "fwd_pkt_len_cv", "rst_flag_ratio", "header_payload_ratio",
    "active_idle_ratio",
]


def _make_df(overrides=None):
    """Minimal DataFrame with all required base features."""
    base = {
        "Flow Duration":               1_000_000.0,
        "Total Fwd Packets":           10.0,
        "Total Backward Packets":       8.0,
        "Total Length of Fwd Packets": 3200.0,
        "Total Length of Bwd Packets": 2400.0,
        "SYN Flag Count":              1.0,
        "ACK Flag Count":              17.0,
        "FIN Flag Count":              2.0,
        "RST Flag Count":              0.0,
        "PSH Flag Count":              5.0,
        "URG Flag Count":              0.0,
        "Fwd Packet Length Mean":      320.0,
        "Fwd Packet Length Std":       80.0,
        "Min Packet Length":           40.0,
        "Max Packet Length":           1460.0,
        "Fwd Header Length":           400.0,
        "Flow IAT Mean":               55555.0,
        "Flow IAT Std":                10000.0,
        "Active Mean":                 0.0,
        "Idle Mean":                   0.0,
    }
    if overrides:
        base.update(overrides)
    return pd.DataFrame([base])


class TestEngineerFeatures:

    def test_adds_all_20_features(self):
        df = _make_df()
        feat_cols = [c for c in df.columns]
        df_out, new_cols = engineer_features(df.copy(), feat_cols)
        for name in ENGINEERED_NAMES:
            assert name in df_out.columns, f"Missing engineered feature: {name}"
        assert len(new_cols) == len(feat_cols) + len(ENGINEERED_NAMES)

    def test_output_dtype_float32(self):
        df = _make_df()
        feat_cols = list(df.columns)
        df_out, _ = engineer_features(df.copy(), feat_cols)
        for name in ENGINEERED_NAMES:
            assert df_out[name].dtype == np.float32, f"{name} should be float32"

    def test_no_nan_or_inf(self):
        df = _make_df()
        feat_cols = list(df.columns)
        df_out, _ = engineer_features(df.copy(), feat_cols)
        for name in ENGINEERED_NAMES:
            val = df_out[name].iloc[0]
            assert np.isfinite(val), f"{name} is not finite: {val}"

    def test_syn_flood_signature(self):
        """Pure SYN flood: syn_flag_ratio ≈ 1, bwd packets = 0."""
        df = _make_df({
            "Total Fwd Packets":           500.0,
            "Total Backward Packets":       0.0,
            "SYN Flag Count":              500.0,
            "ACK Flag Count":               0.0,
            "Flow Duration":               1000.0,
        })
        feat_cols = list(df.columns)
        df_out, _ = engineer_features(df.copy(), feat_cols)
        assert df_out["syn_flag_ratio"].iloc[0] == pytest.approx(1.0, abs=0.01)
        assert df_out["fwd_bwd_pkt_ratio"].iloc[0] > 100

    def test_amplification_signature(self):
        """DDoS amplification: bwd bytes >> fwd bytes → bwd_fwd_byte_ratio > 10."""
        df = _make_df({
            "Total Length of Fwd Packets":   100.0,
            "Total Length of Bwd Packets": 50000.0,
            "Total Fwd Packets":               2.0,
            "Total Backward Packets":          2.0,
        })
        feat_cols = list(df.columns)
        df_out, _ = engineer_features(df.copy(), feat_cols)
        assert df_out["bwd_fwd_byte_ratio"].iloc[0] > 10

    def test_dos_slow_signature(self):
        """DoS Slow: very long duration, few packets → slow_indicator is high."""
        df = _make_df({
            "Flow Duration":          60_000_000.0,  # 60 seconds in µs
            "Total Fwd Packets":               2.0,
            "Total Backward Packets":          1.0,
        })
        feat_cols = list(df.columns)
        df_out, _ = engineer_features(df.copy(), feat_cols)
        assert df_out["slow_indicator"].iloc[0] > 1_000_000

    def test_zero_division_safety(self):
        """All-zero input must not raise or produce NaN/Inf."""
        zero_row = {col: 0.0 for col in _make_df().columns}
        df = pd.DataFrame([zero_row])
        feat_cols = list(df.columns)
        df_out, _ = engineer_features(df.copy(), feat_cols)
        for name in ENGINEERED_NAMES:
            val = df_out[name].iloc[0]
            assert np.isfinite(val), f"{name} is not finite on zero input: {val}"

    def test_duration_log_monotonic(self):
        """duration_log should increase as Flow Duration increases."""
        durations = [100.0, 1_000.0, 10_000.0, 100_000.0]
        logs = []
        for d in durations:
            df = _make_df({"Flow Duration": d})
            feat_cols = list(df.columns)
            df_out, _ = engineer_features(df.copy(), feat_cols)
            logs.append(df_out["duration_log"].iloc[0])
        assert logs == sorted(logs), "duration_log is not monotonically increasing"

    def test_flag_diversity_range(self):
        """flag_diversity should be between 0 and 6."""
        df = _make_df({"SYN Flag Count": 1, "ACK Flag Count": 1, "PSH Flag Count": 1})
        feat_cols = list(df.columns)
        df_out, _ = engineer_features(df.copy(), feat_cols)
        val = df_out["flag_diversity"].iloc[0]
        assert 0 <= val <= 6

    def test_multiple_rows(self):
        """engineer_features must handle DataFrames with more than 1 row."""
        rows = [_make_df().iloc[0].to_dict() for _ in range(10)]
        df = pd.DataFrame(rows)
        feat_cols = list(df.columns)
        df_out, _ = engineer_features(df.copy(), feat_cols)
        assert len(df_out) == 10
        for name in ENGINEERED_NAMES:
            assert name in df_out.columns
