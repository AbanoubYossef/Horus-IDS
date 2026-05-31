"""HORUS SOC — Sample CIC-DDoS2019 CSVs into data/COMBINED/ for training."""

import pandas as pd
import numpy as np
from pathlib import Path

from data_utils import RENAME_MAP, DROP_KEYWORDS, DROP_SUFFIX_DUPES

SEED = 42
rng = np.random.default_rng(SEED)


DDOS2019_DIR = Path("./data/cic-ddos2019-30gb-full-dataset-csv-files")
COMBINED_DIR = Path("./data/COMBINED")


# 60/40 train/unseen split per group
GROUPS = {
    "DDoS Amplification": {
        "label": "DDoS Amplification",
        "sample_total": 400_000,  # 250K train + 150K unseen
        "files": [
            ("01-12", "DrDoS_DNS.csv"),
            ("01-12", "DrDoS_LDAP.csv"),
            ("01-12", "DrDoS_MSSQL.csv"),
            ("01-12", "DrDoS_NetBIOS.csv"),
            ("01-12", "DrDoS_NTP.csv"),
            ("01-12", "DrDoS_SNMP.csv"),
            ("01-12", "DrDoS_SSDP.csv"),
            ("01-12", "TFTP.csv"),
            ("03-11", "LDAP.csv"),
            ("03-11", "MSSQL.csv"),
            ("03-11", "NetBIOS.csv"),
            ("03-11", "Portmap.csv"),
        ],
    },
    "DDoS SYN Flood": {
        "label": "DDoS SYN Flood",
        "sample_total": 400_000,  # 250K train + 100K unseen (need >350K)
        "files": [
            ("01-12", "Syn.csv"),
            ("03-11", "Syn.csv"),
        ],
    },
    "DDoS UDP Flood": {
        "label": "DDoS UDP Flood",
        "sample_total": 400_000,  # 250K train + 100K unseen (need >350K)
        "files": [
            ("01-12", "DrDoS_UDP.csv"),
            ("01-12", "UDPLag.csv"),
            ("03-11", "UDP.csv"),
            ("03-11", "UDPLag.csv"),
        ],
    },
}


def sample_group(group_name, config):
    """Sample rows from multiple files, relabel, and return a DataFrame."""
    label = config["label"]
    target = config["sample_total"]
    files = config["files"]

    print(f"\n  ── {group_name} (target: {target:,} rows) ──")

    # Count rows per file
    file_counts = []
    for subfolder, fname in files:
        fpath = DDOS2019_DIR / subfolder / fname
        if not fpath.exists():
            print(f"    ⚠ Missing: {fpath}")
            continue
        with open(fpath, "rb") as f:
            nlines = sum(1 for _ in f) - 1  # subtract header
        file_counts.append((fpath, nlines))
        print(f"    {subfolder}/{fname}: {nlines:,} rows")

    if not file_counts:
        print(f"    ✗ No files found for {group_name}")
        return None

    total_available = sum(n for _, n in file_counts)
    per_file_target = target // len(file_counts)

    print(f"    Total available: {total_available:,}")
    print(f"    Sampling ~{per_file_target:,} per file")

    all_chunks = []
    rows_collected = 0

    for fpath, nlines in file_counts:
        n_sample = min(per_file_target, nlines)
        # Random sample via skip indices
        if nlines > n_sample:
            skip_idx = sorted(rng.choice(range(1, nlines + 1), size=nlines - n_sample, replace=False))
            df = pd.read_csv(fpath, skiprows=skip_idx, low_memory=False, encoding="latin-1")
        else:
            df = pd.read_csv(fpath, low_memory=False, encoding="latin-1")

        df.columns = df.columns.str.strip()
        df.rename(columns=RENAME_MAP, inplace=True)

        # Drop metadata + duplicate columns
        drop_cols = [c for c in df.columns
                     if "Unnamed" in c or any(k in c.lower() for k in DROP_KEYWORDS)]
        if DROP_SUFFIX_DUPES:
            drop_cols += [c for c in df.columns
                          if '.' in c and c.rsplit('.', 1)[-1].isdigit()]
        df.drop(columns=drop_cols, errors="ignore", inplace=True)

        # Set label
        if "Label" in df.columns:
            df["Label"] = label
        elif " Label" in df.columns:
            df.rename(columns={" Label": "Label"}, inplace=True)
            df["Label"] = label

        all_chunks.append(df)
        rows_collected += len(df)
        print(f"    ✓ {fpath.name}: sampled {len(df):,} rows")

        if rows_collected >= target:
            break

    result = pd.concat(all_chunks, ignore_index=True)

    # Final shuffle and cap
    if len(result) > target:
        result = result.sample(target, random_state=SEED).reset_index(drop=True)

    print(f"    ▸ Final: {len(result):,} rows labeled '{label}'")
    return result


def main():
    print("=" * 62)
    print("  HORUS SOC — CIC-DDoS2019 Sampler")
    print("  Output: data/COMBINED/ (column-aligned with CIC-IDS2017/2018)")
    print("=" * 62)

    COMBINED_DIR.mkdir(parents=True, exist_ok=True)

    for group_name, config in GROUPS.items():
        df = sample_group(group_name, config)
        if df is not None:
            safe_name = group_name.replace(" ", "_")
            out_path = COMBINED_DIR / f"DDoS2019_{safe_name}.csv"
            df.to_csv(out_path, index=False)
            print(f"    ✓ Saved → {out_path} ({len(df):,} rows)")

    # Verify
    print("\n" + "=" * 62)
    print("  COMBINED folder contents:")
    for f in sorted(COMBINED_DIR.glob("*.csv")):
        if f.is_symlink():
            print(f"    {f.name} (symlink)")
        else:
            size_mb = f.stat().st_size / 1024 / 1024
            print(f"    {f.name} ({size_mb:.0f} MB)")
    print("=" * 62)
    print("  Done! Next → python3 train_xgboost.py")


if __name__ == "__main__":
    main()
