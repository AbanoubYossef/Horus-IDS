import pytest
import pandas as pd
import numpy as np
from infrastructure.ml.feature_engineering import engineer_features

def test_engineer_features_creates_columns():
    data = {
        "Total Fwd Packets": [10, 5, 0],
        "Total Backward Packets": [8, 0, 0],
        "Total Length of Fwd Packets": [1000, 500, 0],
        "Total Length of Bwd Packets": [2000, 0, 0],
        "Flow Duration": [1000000, 500000, 0],
        "SYN Flag Count": [1, 1, 0],
        "ACK Flag Count": [8, 0, 0],
        "FIN Flag Count": [1, 0, 0],
        "RST Flag Count": [0, 0, 0],
        "PSH Flag Count": [2, 0, 0],
        "URG Flag Count": [0, 0, 0],
        "Min Packet Length": [40, 40, 0],
        "Max Packet Length": [1500, 100, 0],
        "Flow IAT Mean": [10000, 5000, 0],
        "Flow IAT Std": [2000, 1000, 0],
        "Fwd Packet Length Mean": [100, 100, 0],
        "Fwd Packet Length Std": [10, 10, 0],
        "Fwd Header Length": [200, 100, 0],
        "Active Mean": [0, 0, 0],
        "Idle Mean": [0, 0, 0],
    }
    
    df = pd.DataFrame(data)
    initial_cols = list(df.columns)
    
    new_df, new_feat_cols = engineer_features(df.copy(), initial_cols.copy())
    
    assert "syn_flag_ratio" in new_df.columns
    assert "bytes_per_pkt_fwd" in new_df.columns
    assert "duration_log" in new_df.columns
    
    # No NaN/inf from division by zero
    assert not new_df.isnull().values.any()
    assert not np.isinf(new_df.values).any()
    
    # 1 SYN out of 18 total packets
    assert new_df["syn_flag_ratio"].iloc[0] == pytest.approx(1 / 18, rel=1e-3)
    
def test_engineer_features_missing_columns_handled_safely():
    df = pd.DataFrame({"Total Fwd Packets": [10]})
    # Missing columns → zero
    new_df, new_feat_cols = engineer_features(df, ["Total Fwd Packets"])
    assert "syn_flag_ratio" in new_df.columns
    assert new_df["syn_flag_ratio"].iloc[0] == 0.0
