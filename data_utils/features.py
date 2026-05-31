"""
HORUS SOC -- Feature engineering for network intrusion detection.
"""

import numpy as np


def engineer_features(df, feat_cols):
    """Add engineered features to help distinguish attack sub-types."""
    eps = 1e-8  # avoid division by zero

    # 0 if column missing
    def col(name):
        return df[name].values.astype(np.float64) if name in df.columns else np.zeros(len(df))

    total_pkts = col("Total Fwd Packets") + col("Total Backward Packets") + eps
    fwd_pkts   = col("Total Fwd Packets") + eps
    bwd_pkts   = col("Total Backward Packets") + eps
    fwd_bytes  = col("Total Length of Fwd Packets") + eps
    bwd_bytes  = col("Total Length of Bwd Packets") + eps
    duration   = col("Flow Duration") + eps

    new_features = {}

    
    syn_count = col("SYN Flag Count")
    ack_count = col("ACK Flag Count")
    fin_count = col("FIN Flag Count")
    rst_count = col("RST Flag Count")
    psh_count = col("PSH Flag Count")

    new_features["syn_flag_ratio"]  = syn_count / total_pkts
    new_features["ack_syn_ratio"]   = ack_count / (syn_count + eps)
    new_features["fin_flag_ratio"]  = fin_count / total_pkts
    new_features["psh_flag_ratio"]  = psh_count / total_pkts
    new_features["flag_diversity"]  = (
        (syn_count > 0).astype(np.float64) +
        (ack_count > 0).astype(np.float64) +
        (fin_count > 0).astype(np.float64) +
        (rst_count > 0).astype(np.float64) +
        (psh_count > 0).astype(np.float64) +
        (col("URG Flag Count") > 0).astype(np.float64)
    )

    
    new_features["bytes_per_pkt_fwd"]   = fwd_bytes / fwd_pkts
    new_features["bytes_per_pkt_bwd"]   = bwd_bytes / bwd_pkts
    new_features["pkt_size_ratio"]      = (col("Min Packet Length") + eps) / (col("Max Packet Length") + eps)

    
    new_features["fwd_bwd_pkt_ratio"]   = col("Total Fwd Packets") / bwd_pkts
    new_features["fwd_bwd_byte_ratio"]  = fwd_bytes / bwd_bytes
    new_features["bwd_fwd_byte_ratio"]  = bwd_bytes / fwd_bytes   # amplification detector

    
    new_features["pkts_per_duration"]   = total_pkts / duration
    new_features["bytes_per_duration"]  = (fwd_bytes + bwd_bytes) / duration
    new_features["duration_log"]        = np.log1p(col("Flow Duration"))
    new_features["slow_indicator"]      = col("Flow Duration") / total_pkts

    
    iat_mean = col("Flow IAT Mean") + eps
    iat_std  = col("Flow IAT Std")
    new_features["iat_cv"]             = iat_std / iat_mean

    fwd_len_mean = col("Fwd Packet Length Mean") + eps
    fwd_len_std  = col("Fwd Packet Length Std")
    new_features["fwd_pkt_len_cv"]     = fwd_len_std / fwd_len_mean

    
    new_features["rst_flag_ratio"]     = rst_count / total_pkts          # reset behaviour
    new_features["header_payload_ratio"] = (                             # SYN floods = all header
        col("Fwd Header Length") / (fwd_bytes + eps)
    )
    new_features["active_idle_ratio"]  = (                               # DoS Slow active/idle
        col("Active Mean") / (col("Idle Mean") + eps)
    )

    # Add to DataFrame
    added = []
    for name, values in new_features.items():
        df[name] = np.nan_to_num(values, nan=0.0, posinf=0.0, neginf=0.0).astype(np.float32)
        added.append(name)

    feat_cols = feat_cols + added
    print(f"  ▸ Engineered {len(added)} new features → {len(feat_cols)} total features")
    return df, feat_cols
