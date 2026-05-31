"""HORUS SOC — Evaluate hierarchical 11-class model on unseen data."""

import json, joblib, warnings, time, gc
import numpy as np
import pandas as pd
from pathlib import Path

from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import (
    classification_report, f1_score, accuracy_score,
    precision_score, recall_score, confusion_matrix, roc_auc_score,
)

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import xgboost as xgb

from data_utils import (
    DATA_DIR, MODEL_DIR, PLOT_DIR, SEED,
    LABEL_MERGE, LABEL_MERGE_11CLASS, TARGET_CLASSES_11,
    HIERARCHICAL_GROUPS_11, CLASS_TO_GROUP_11,
    BG, PANEL, ACC, RED, BLUE, TEXT, DIM,
    random_split_csv_data, engineer_features,
)

warnings.filterwarnings("ignore")

PLOT_DIR.mkdir(exist_ok=True)
HIER_DIR   = MODEL_DIR / "hierarchical_11class"
SKIP_ROWS  = 250_000
MAX_UNSEEN = 100_000

ENGINEERED_FEATURE_NAMES = {
    "syn_flag_ratio", "ack_syn_ratio", "fin_flag_ratio", "psh_flag_ratio",
    "flag_diversity", "bytes_per_pkt_fwd", "bytes_per_pkt_bwd", "pkt_size_ratio",
    "fwd_bwd_pkt_ratio", "fwd_bwd_byte_ratio", "bwd_fwd_byte_ratio",
    "pkts_per_duration", "bytes_per_duration", "duration_log", "slow_indicator",
    "iat_cv", "fwd_pkt_len_cv", "rst_flag_ratio", "header_payload_ratio",
    "active_idle_ratio",
}



def style_fig(fig):
    fig.patch.set_facecolor(BG)
    return fig

def style_ax(ax, title=""):
    ax.set_facecolor(PANEL)
    ax.tick_params(colors=DIM, labelsize=8)
    ax.xaxis.label.set_color(DIM)
    ax.yaxis.label.set_color(DIM)
    for s in ax.spines.values():
        s.set_edgecolor("#1a2535")
    if title:
        ax.set_title(title, color=TEXT, fontsize=10, fontweight="bold", pad=10)
    ax.grid(True, color="#0d1a2d", linewidth=0.6, alpha=0.8)
    return ax



#  1. LOAD MODEL ARTIFACTS

def load_hierarchical_model():
    print("  Loading hierarchical 11-class model...")
    with open(HIER_DIR / "config_11class.json") as f:
        cfg = json.load(f)

    scaler     = joblib.load(HIER_DIR / "scaler.pkl")
    le_fine    = joblib.load(HIER_DIR / "fine_label_encoder.pkl")
    le_group   = joblib.load(HIER_DIR / "level1_label_encoder.pkl")
    feat_names = joblib.load(HIER_DIR / "feature_names.pkl")

    l1_model = xgb.XGBClassifier()
    l1_model.load_model(str(HIER_DIR / "level1_xgb.json"))

    l2_models = {}
    l2_encoders = {}
    for grp, members in HIERARCHICAL_GROUPS_11.items():
        if len(members) <= 1:
            continue
        safe = grp.replace("-", "_").replace(" ", "_")
        mp = HIER_DIR / f"level2_{safe}_xgb.json"
        lp = HIER_DIR / f"level2_{safe}_label_encoder.pkl"
        if mp.exists() and lp.exists():
            m = xgb.XGBClassifier()
            m.load_model(str(mp))
            l2_models[grp] = m
            l2_encoders[grp] = joblib.load(lp)

    print(f"  ✓ Model loaded — {len(le_fine.classes_)} classes, "
          f"{len(le_group.classes_)} groups, {len(feat_names)} features")
    print(f"  ✓ Level 2 sub-models: {list(l2_models.keys())}")
    return cfg, scaler, le_fine, le_group, feat_names, l1_model, l2_models, l2_encoders



#  2. LOAD UNSEEN DATA

def load_unseen_data():
    print("  Loading unseen data (random split, per file)...")
    _, unseen_df = random_split_csv_data(
        data_dir=DATA_DIR,
        train_rows_per_file=SKIP_ROWS,
        unseen_rows_per_file=MAX_UNSEEN,
        seed=SEED,
    )
    return unseen_df



#  3. PREPROCESS

def preprocess(df):
    df.columns = df.columns.str.strip()
    df = df.loc[:, ~df.columns.duplicated()]

    label_col = next((c for c in df.columns if c.lower().strip() == "label"), None)
    if label_col is None:
        raise ValueError("Cannot find 'Label' column in data.")
    df.rename(columns={label_col: "Label"}, inplace=True)
    df["Label"] = df["Label"].astype(str).str.strip().replace(LABEL_MERGE)
    df["Label"] = df["Label"].replace(LABEL_MERGE_11CLASS)

    df = df[df["Label"].isin(TARGET_CLASSES_11)].copy()

    feat_cols = [c for c in df.columns if c != "Label"]
    df[feat_cols] = df[feat_cols].apply(pd.to_numeric, errors="coerce")
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.dropna(thresh=int(len(df.columns) * 0.7), inplace=True)
    df.fillna(0, inplace=True)

    print(f"  ▸ Shape after cleaning : {df.shape}")
    print(f"  ▸ Class distribution (unseen data):")
    vc = df["Label"].value_counts()
    for cls, cnt in vc.items():
        bar = "█" * min(40, int(cnt / vc.max() * 40))
        print(f"    {cls:<42} {cnt:>8,}  {bar}")

    return df



#  4. HIERARCHICAL PREDICTION

def hierarchical_predict(X, l1_model, l2_models, l2_encoders, le_group):
    group_preds = l1_model.predict(X)
    group_names = le_group.inverse_transform(group_preds)
    fine_preds = np.empty(len(X), dtype=object)

    for group_name, members in HIERARCHICAL_GROUPS_11.items():
        mask = group_names == group_name
        if mask.sum() == 0:
            continue
        if len(members) == 1:
            fine_preds[mask] = members[0]
        elif group_name in l2_models:
            sub_preds = l2_models[group_name].predict(X[mask])
            fine_preds[mask] = l2_encoders[group_name].inverse_transform(sub_preds)
        else:
            fine_preds[mask] = members[0]
    return fine_preds, group_names



#  5. CONFUSION MATRIX PLOT

def plot_confusion_matrix(y_true, y_pred, class_names):
    present = sorted(set(y_true) | set(y_pred))
    names = [class_names[i] for i in present if i < len(class_names)]
    cm = confusion_matrix(y_true, y_pred, labels=present)
    cm_norm = cm.astype(float) / (cm.sum(axis=1, keepdims=True) + 1e-8)

    fig, ax = plt.subplots(figsize=(10, 8))
    style_fig(fig)
    style_ax(ax, "Hierarchical 11-Class — Confusion Matrix (Unseen Data)")
    ax.imshow(cm_norm, cmap="Blues", vmin=0, vmax=1)

    k = len(names)
    ax.set_xticks(range(k))
    ax.set_yticks(range(k))
    short = [c[:14] for c in names]
    ax.set_xticklabels(short, rotation=45, ha="right", fontsize=7, color=TEXT)
    ax.set_yticklabels(short, fontsize=7, color=TEXT)
    ax.set_xlabel("Predicted", color=DIM, fontsize=9)
    ax.set_ylabel("Actual", color=DIM, fontsize=9)
    for i in range(k):
        for j in range(k):
            v = cm_norm[i, j]
            c = cm[i, j]
            if c > 0:
                ax.text(j, i, f"{v:.2f}\n({c:,})", ha="center", va="center",
                        fontsize=5.5, color=TEXT if v < 0.5 else PANEL)

    path = PLOT_DIR / "unseen_confusion_matrix.png"
    plt.savefig(path, dpi=150, bbox_inches="tight", facecolor=BG)
    plt.close()
    print(f"  ✓ Confusion matrix → {path}")



#  6. PER-CLASS F1 CHART

def plot_per_class_f1(y_true, y_pred, class_names):
    present = sorted(set(y_true) | set(y_pred))
    names = [class_names[i] for i in present if i < len(class_names)]
    pcf = f1_score(y_true, y_pred, labels=present, average=None, zero_division=0)
    n = len(names)

    fig, ax = plt.subplots(figsize=(12, 7))
    style_fig(fig)
    style_ax(ax, "Per-Class F1 Score — Hierarchical 11-Class (Unseen Data)")

    colors = [ACC if v >= 0.95 else BLUE if v >= 0.85 else RED for v in pcf]
    bars = ax.barh(range(n), pcf, color=colors, alpha=0.85, height=0.6)

    for bar, val in zip(bars, pcf):
        ax.text(val + 0.01, bar.get_y() + bar.get_height() / 2,
                f"{val:.4f}", va="center", fontsize=8, color=TEXT)

    ax.set_yticks(range(n))
    ax.set_yticklabels(names, fontsize=9, color=TEXT)
    ax.set_xlim(0, 1.15)
    ax.set_xlabel("F1 Score", color=DIM)
    ax.axvline(x=0.95, color=ACC, linestyle="--", alpha=0.3, linewidth=0.8)
    ax.axvline(x=0.85, color=BLUE, linestyle="--", alpha=0.3, linewidth=0.8)

    path = PLOT_DIR / "unseen_per_class_f1.png"
    plt.savefig(path, dpi=150, bbox_inches="tight", facecolor=BG)
    plt.close()
    print(f"  ✓ Per-class F1 chart → {path}")



#  7. SAVE REPORT

def save_report(metrics, report_text, total_samples, elapsed):
    path = PLOT_DIR / "unseen_eval_report.txt"
    with open(path, "w") as fh:
        fh.write("═" * 70 + "\n")
        fh.write("  HORUS SOC — Unseen Data Evaluation Report\n")
        fh.write("  Model: Hierarchical 11-Class (Optuna XGBoost)\n")
        fh.write("  Datasets: CIC-IDS2017 + CIC-IDS2018 + CIC-DDoS2019\n")
        fh.write("═" * 70 + "\n\n")
        fh.write(f"  Total unseen samples : {total_samples:,}\n")
        fh.write(f"  Rows skipped (train) : {SKIP_ROWS:,}\n")
        fh.write(f"  Evaluation time      : {elapsed:.1f}s\n\n")
        fh.write("─" * 70 + "\n")
        fh.write("  Hierarchical 11-Class\n")
        fh.write("─" * 70 + "\n")
        fh.write(f"  Level 1 (groups)  Acc: {metrics['l1_acc']*100:.2f}%  "
                 f"F1: {metrics['l1_f1']*100:.2f}%\n\n")
        auc_v = metrics.get('auc', float('nan'))
        fh.write(f"  Accuracy={metrics['acc']*100:.2f}%  "
                 f"Precision={metrics['prec']*100:.2f}%  "
                 f"Recall={metrics['rec']*100:.2f}%  "
                 f"F1(w)={metrics['f1w']*100:.2f}%  "
                 f"F1(m)={metrics['f1m']*100:.2f}%  "
                 f"AUC={auc_v*100:.2f}%  "
                 f"FAR={metrics['far']*100:.4f}%\n\n")
        fh.write(f"  Inference: {metrics['inf_time']:.2f}s "
                 f"({metrics['flows_per_sec']:.0f} flows/sec)\n\n")
        fh.write(report_text + "\n\n")
        fh.write("═" * 70 + "\n")
    print(f"  ✓ Full report → {path}")



#  MAIN

def main():
    np.random.seed(SEED)
    t_start = time.time()

    

    # Load model
    print("Starting Loading model artifacts...")
    (cfg, scaler, le_fine, le_group, feat_names,
     l1_model, l2_models, l2_encoders) = load_hierarchical_model()

    # Load unseen data
    print("Starting Loading unseen data...")
    raw_df = load_unseen_data()
    print(f"  ▸ Total unseen rows loaded: {len(raw_df):,}")

    # Preprocess
    print("Starting Preprocessing...")
    df = preprocess(raw_df)
    del raw_df
    gc.collect()

    if len(df) == 0:
        print("\n  ✗ No matching samples found.")
        return

    # Engineer features
    print("Starting Engineering features & aligning...")
    base_feats = [f for f in feat_names if f not in ENGINEERED_FEATURE_NAMES]
    df, _ = engineer_features(df, base_feats)

    X_df = pd.DataFrame(index=df.index)
    for f in feat_names:
        X_df[f] = df[f].values.astype(np.float32) if f in df.columns else 0.0
    X = scaler.transform(X_df.values.astype(np.float32)).astype(np.float32)

    y_true_names = df["Label"].values
    y_true = le_fine.transform(y_true_names)

    # Predict
    print("Starting Running hierarchical prediction...")
    t0 = time.time()
    pred_names, pred_groups = hierarchical_predict(
        X, l1_model, l2_models, l2_encoders, le_group)
    inf_time = time.time() - t0
    y_pred = le_fine.transform(pred_names)

    # Level 1 metrics
    y_group_true = np.array([CLASS_TO_GROUP_11[n] for n in y_true_names])
    y_group_pred = np.array([CLASS_TO_GROUP_11[n] for n in pred_names])
    l1_acc = accuracy_score(y_group_true, y_group_pred)
    l1_f1 = f1_score(y_group_true, y_group_pred, average="weighted", zero_division=0)

    # Full metrics
    acc  = accuracy_score(y_true, y_pred)
    prec = precision_score(y_true, y_pred, average="weighted", zero_division=0)
    rec  = recall_score(y_true, y_pred, average="weighted", zero_division=0)
    f1w  = f1_score(y_true, y_pred, average="weighted", zero_division=0)
    f1m  = f1_score(y_true, y_pred, average="macro", zero_division=0)

    benign_idx = np.where(le_fine.classes_ == "BENIGN")[0]
    if len(benign_idx):
        bm = y_true == benign_idx[0]
        far = (y_pred[bm] != benign_idx[0]).mean() if bm.sum() > 0 else float('nan')
    else:
        far = float('nan')

    try:
        from sklearn.preprocessing import label_binarize
        n_cls = len(le_fine.classes_)
        yb = label_binarize(y_true, classes=list(range(n_cls)))
        pb = label_binarize(y_pred, classes=list(range(n_cls)))
        auc = roc_auc_score(yb, pb, multi_class="ovr", average="weighted")
    except ValueError:
        auc = float('nan')

    report = classification_report(y_true, y_pred, target_names=le_fine.classes_,
                                   zero_division=0, digits=4)

    # Print results
    elapsed = time.time() - t_start
    flows_sec = len(X) / inf_time

    print(f"\n  {'─'*60}")
    print(f"  HIERARCHICAL 10-CLASS — Unseen Data Results")
    print(f"  {'─'*60}")
    print(f"  Level 1 (groups)  Acc: {l1_acc*100:.2f}%  F1: {l1_f1*100:.2f}%")
    print(f"  {'─'*60}")
    print(f"  {'Metric':<16} {'Value':>10}")
    print(f"  {'─'*16} {'─'*10}")
    print(f"  {'Accuracy':<16} {acc*100:>9.2f}%")
    print(f"  {'Precision':<16} {prec*100:>9.2f}%")
    print(f"  {'Recall':<16} {rec*100:>9.2f}%")
    print(f"  {'F1 (weighted)':<16} {f1w*100:>9.2f}%")
    print(f"  {'F1 (macro)':<16} {f1m*100:>9.2f}%")
    print(f"  {'AUC':<16} {auc*100:>9.2f}%")
    print(f"  {'FAR':<16} {far*100:>9.4f}%")
    print(f"\n{report}")
    print(f"  Inference: {inf_time:.2f}s ({flows_sec:.0f} flows/sec)")

    # Plots
    print("\n  Generating plots...")
    plot_confusion_matrix(y_true, y_pred, list(le_fine.classes_))
    plot_per_class_f1(y_true, y_pred, list(le_fine.classes_))

    # Save report
    metrics = {
        "acc": acc, "prec": prec, "rec": rec,
        "f1w": f1w, "f1m": f1m, "auc": auc, "far": far,
        "l1_acc": l1_acc, "l1_f1": l1_f1,
        "inf_time": inf_time, "flows_per_sec": flows_sec,
    }
    save_report(metrics, report, len(df), elapsed)

    # Summary
    
    print(f"  Unseen samples : {len(df):,}")
    print(f"  Total time     : {elapsed:.1f}s")
    print(f"  Results saved to:")
    print(f"    plots/unseen_eval_report.txt")
    print(f"    plots/unseen_confusion_matrix.png")
    print(f"    plots/unseen_per_class_f1.png")
    print("═" * 70 + "\n")


if __name__ == "__main__":
    main()
