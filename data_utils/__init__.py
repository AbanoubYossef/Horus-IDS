"""
HORUS SOC -- Shared Data Utilities

Common constants, column renaming, label merging, data loading,
preprocessing, and plot theming used across all training scripts.

Datasets:  CIC-IDS2017 + CIC-IDS2018 + CIC-DDoS2019
Pipeline:  Load CSVs -> rename columns -> merge labels -> balance
"""

from .constants import (
    _BASE_DIR,
    DATA_DIR,
    MODEL_DIR,
    PLOT_DIR,
    SEED,
    DROP_KEYWORDS,
    DROP_SUFFIX_DUPES,
    RENAME_MAP,
    LABEL_MERGE,
    LABEL_MERGE_11CLASS,
    TARGET_CLASSES,
    TARGET_CLASSES_11,
    SEVERITY,
    HIERARCHICAL_GROUPS,
    HIERARCHICAL_GROUPS_11,
    CLASS_TO_GROUP,
    CLASS_TO_GROUP_11,
    BG,
    PANEL,
    ACC,
    RED,
    BLUE,
    TEXT,
    DIM,
)

from .features import engineer_features

from .loading import (
    load_csv_data,
    random_split_csv_data,
    preprocess_dataframe,
    balance_classes,
    compute_far,
)

__all__ = [
    # constants
    "_BASE_DIR",
    "DATA_DIR",
    "MODEL_DIR",
    "PLOT_DIR",
    "SEED",
    "DROP_KEYWORDS",
    "DROP_SUFFIX_DUPES",
    "RENAME_MAP",
    "LABEL_MERGE",
    "LABEL_MERGE_11CLASS",
    "TARGET_CLASSES",
    "TARGET_CLASSES_11",
    "SEVERITY",
    "HIERARCHICAL_GROUPS",
    "HIERARCHICAL_GROUPS_11",
    "CLASS_TO_GROUP",
    "CLASS_TO_GROUP_11",
    "BG",
    "PANEL",
    "ACC",
    "RED",
    "BLUE",
    "TEXT",
    "DIM",
    # features
    "engineer_features",
    # loading
    "load_csv_data",
    "random_split_csv_data",
    "preprocess_dataframe",
    "balance_classes",
    "compute_far",
]
