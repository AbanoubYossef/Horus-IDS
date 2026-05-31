"""
HORUS SOC -- Data loading, preprocessing, balancing, and evaluation utilities.
"""

import gc
import numpy as np
import pandas as pd
from pathlib import Path
from tqdm import tqdm

from .constants import (
    DATA_DIR,
    SEED,
    DROP_KEYWORDS,
    DROP_SUFFIX_DUPES,
    RENAME_MAP,
    LABEL_MERGE,
    TARGET_CLASSES,
)



def load_csv_data(data_dir=None, max_rows_per_file=250_000):
    """Load all CSVs from data_dir, rename columns, drop metadata, return one DataFrame."""
    if data_dir is None:
        data_dir = DATA_DIR
    csv_files = sorted(Path(data_dir).glob("**/*.csv"))
    if not csv_files:
        raise FileNotFoundError(f"No CSV files found in: {Path(data_dir).resolve()}")
    print(f"  ▸ Found {len(csv_files)} CSV file(s)")

    all_rows = []
    for f in tqdm(csv_files, desc="  Loading", ncols=70):
        chunks = []
        rows_so_far = 0
        try:
            for chunk in pd.read_csv(f, low_memory=False, encoding="latin-1", chunksize=50_000):
                chunk.rename(columns=RENAME_MAP, inplace=True)
                chunk.columns = chunk.columns.str.strip()
                chunk = chunk.loc[:, ~chunk.columns.duplicated()]
                drop_cols = [c for c in chunk.columns
                             if any(k in c.lower() for k in DROP_KEYWORDS)]
                # Drop ".1" suffix duplicates
                if DROP_SUFFIX_DUPES:
                    drop_cols += [c for c in chunk.columns
                                  if '.' in c and c.rsplit('.', 1)[-1].isdigit()]
                chunk.drop(columns=drop_cols, errors="ignore", inplace=True)
                for col in chunk.select_dtypes(include="number").columns:
                    if col != "Label":
                        chunk[col] = chunk[col].astype("float32")
                chunks.append(chunk)
                rows_so_far += len(chunk)
                if rows_so_far >= max_rows_per_file:
                    break
        except Exception as e:
            print(f"  ⚠ {f.name}: {e}")
            continue
        if chunks:
            all_rows.append(pd.concat(chunks, ignore_index=True))
        del chunks
        gc.collect()

    df = pd.concat(all_rows, ignore_index=True)
    del all_rows
    gc.collect()
    return df


def random_split_csv_data(data_dir=None, train_rows_per_file=250_000,
                          unseen_rows_per_file=100_000, seed=SEED):
    """Shuffle each CSV with a per-file seed, split into train / unseen sets."""
    if data_dir is None:
        data_dir = DATA_DIR
    csv_files = sorted(Path(data_dir).glob("**/*.csv"))
    if not csv_files:
        raise FileNotFoundError(f"No CSV files found in: {Path(data_dir).resolve()}")
    print(f"  ▸ Found {len(csv_files)} CSV file(s)")

    train_rows = []
    unseen_rows = []
    for file_idx, f in enumerate(tqdm(csv_files, desc="  Loading (random split)", ncols=70)):
        try:
            df = pd.read_csv(f, low_memory=False, encoding="latin-1")
        except Exception as e:
            print(f"  ⚠ {f.name}: {e}")
            continue

        df.rename(columns=RENAME_MAP, inplace=True)
        df.columns = df.columns.str.strip()
        df = df.loc[:, ~df.columns.duplicated()]

        # Drop metadata columns
        drop_cols = [c for c in df.columns if any(k in c.lower() for k in DROP_KEYWORDS)]
        # Drop ".1" suffix duplicates
        if DROP_SUFFIX_DUPES:
            drop_cols += [c for c in df.columns
                          if '.' in c and c.rsplit('.', 1)[-1].isdigit()]
        if drop_cols:
            df.drop(columns=drop_cols, errors="ignore", inplace=True)

        for col in df.select_dtypes(include="number").columns:
            if col != "Label":
                df[col] = df[col].astype("float32")

        n = len(df)
        idx = np.arange(n)
        # Unique seed per file
        rng = np.random.default_rng(seed + file_idx)
        rng.shuffle(idx)

        n_train  = min(train_rows_per_file, n)
        n_unseen = min(unseen_rows_per_file, max(0, n - n_train))
        train_idx  = idx[:n_train]
        unseen_idx = idx[n_train:n_train + n_unseen]

        train_rows.append(df.iloc[train_idx])
        if n_unseen > 0:
            unseen_rows.append(df.iloc[unseen_idx])

        del df
        gc.collect()

    train_df  = pd.concat(train_rows, ignore_index=True) if train_rows else pd.DataFrame()
    unseen_df = pd.concat(unseen_rows, ignore_index=True) if unseen_rows else pd.DataFrame()
    del train_rows, unseen_rows
    gc.collect()
    return train_df, unseen_df


def preprocess_dataframe(df, target_classes=None):
    """Clean labels, coerce numerics, drop zero-variance features."""
    df = df.loc[:, ~df.columns.duplicated()]

    # Find label column
    label_col = next((c for c in df.columns if c.lower().strip() == "label"), None)
    if label_col is None:
        raise ValueError("Cannot find 'Label' column.")
    df.rename(columns={label_col: "Label"}, inplace=True)

    # Unify label names
    df["Label"] = df["Label"].astype(str).str.strip()
    df["Label"] = df["Label"].replace(LABEL_MERGE)

    # Filter to target classes before variance check
    if target_classes is not None:
        before = len(df)
        df = df[df["Label"].isin(target_classes)].copy()
        print(f"  ▸ Filtered to {len(target_classes)} target classes: {before:,} → {len(df):,} rows")

    # Coerce to numeric
    feat_cols = [c for c in df.columns if c != "Label"]
    df[feat_cols] = df[feat_cols].apply(pd.to_numeric, errors="coerce")
    df.replace([np.inf, -np.inf], np.nan, inplace=True)

    # Drop mostly-NaN rows
    df.dropna(thresh=int(len(df.columns) * 0.7), inplace=True)
    df.fillna(0, inplace=True)

    # Remove zero-variance columns
    stds = df[feat_cols].std()
    zero_var = stds[stds <= 1e-6].index.tolist()
    if zero_var:
        print(f"  ▸ Dropped {len(zero_var)} zero-variance features: {zero_var[:5]}{'...' if len(zero_var) > 5 else ''}")
    feat_cols = stds[stds > 1e-6].index.tolist()

    print(f"  ▸ Shape: {df.shape}  Features: {len(feat_cols)}")
    print(f"  ▸ Classes: {sorted(df['Label'].unique())}")

    return df[feat_cols + ["Label"]].copy(), feat_cols


def balance_classes(df, feat_cols, max_per_class=100_000, min_per_class=200, seed=SEED):
    """Over/under-sample classes to balance the dataset. Returns (X, y, label_encoder)."""
    from sklearn.preprocessing import LabelEncoder

    le = LabelEncoder()
    df["y"] = le.fit_transform(df["Label"])

    balanced = []
    for cls in sorted(df["y"].unique()):          # sorted for determinism
        sub = df[df["y"] == cls]
        if len(sub) > max_per_class:
            sub = sub.sample(max_per_class, random_state=seed)
        elif len(sub) < min_per_class:
            sub = sub.sample(min_per_class, replace=True, random_state=seed)
        balanced.append(sub)
    df = pd.concat(balanced, ignore_index=True).sample(frac=1, random_state=seed)

    X = df[feat_cols].values.astype(np.float32)
    y = df["y"].values

    print(f"  ▸ Balanced: {len(y):,} samples across {len(le.classes_)} classes")
    return X, y, le


def compute_far(y_true, y_pred, le):
    """Compute False Alarm Rate: fraction of BENIGN flows misclassified as attacks."""
    benign_label = le.transform(["BENIGN"])[0]
    benign_mask = y_true == benign_label
    if benign_mask.sum() > 0:
        return float((y_pred[benign_mask] != benign_label).mean())
    return float('nan')
