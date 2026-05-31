"""HORUS SOC — 11-Class Hierarchical Classifier (SYN+UDP → Volumetric merge)."""

import json, joblib, time, warnings, gc, sys
import numpy as np

SCRIPT_START_TIME = time.time()  # Track total script execution time
import pandas as pd
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent.parent))

from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    f1_score, accuracy_score, precision_score, recall_score,
    classification_report, roc_auc_score, confusion_matrix,
)
import xgboost as xgb
import optuna

optuna.logging.set_verbosity(optuna.logging.WARNING)
warnings.filterwarnings("ignore")

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from data_utils import (
    MODEL_DIR, PLOT_DIR, DATA_DIR, SEED,
    TARGET_CLASSES_11, LABEL_MERGE, LABEL_MERGE_11CLASS,
    HIERARCHICAL_GROUPS_11, CLASS_TO_GROUP_11,
    BG, PANEL, ACC, RED, BLUE, TEXT, DIM,
    random_split_csv_data, preprocess_dataframe,
    balance_classes, compute_far, engineer_features,
)

MODEL_DIR.mkdir(exist_ok=True)
PLOT_DIR.mkdir(exist_ok=True)
HIER11_DIR = MODEL_DIR / "hierarchical_11class"
HIER11_DIR.mkdir(exist_ok=True)

MAX_ROWS_PER_FILE = 250_000
MAX_PER_CLASS     = 100_000
OPTUNA_TRIALS     = 30
SKIP_ROWS         = 250_000
MAX_UNSEEN        = 100_000

print("=" * 70)
print("  HORUS SOC — 11-class Hierarchical Classifier (Experiment 3)")
print("  Smart merge: DDoS SYN Flood + UDP Flood → DDoS Volumetric")
print("  + 20 engineered features + Optuna tuning")
print("  Datasets: CIC-IDS2017 + CIC-IDS2018 + CIC-DDoS2019")
print("=" * 70)



# Train Optuna-tuned XGBoost

def train_xgb_optuna(X_tr, y_tr, X_val, y_val, n_classes, level_name,
                     n_trials=OPTUNA_TRIALS):
    """Optuna-tuned XGBoost. Handles binary and multi-class automatically."""
    print(f"\n  ── Optuna tuning: {level_name} ({n_classes} classes, {n_trials} trials) ──")
    is_binary = n_classes == 2

    def objective(trial):
        params = {
            "n_estimators":     trial.suggest_int("n_estimators", 300, 1200),
            "max_depth":        trial.suggest_int("max_depth", 6, 14),
            "learning_rate":    trial.suggest_float("learning_rate", 0.01, 0.15, log=True),
            "subsample":        trial.suggest_float("subsample", 0.7, 1.0),
            "colsample_bytree": trial.suggest_float("colsample_bytree", 0.6, 1.0),
            "min_child_weight": trial.suggest_int("min_child_weight", 1, 10),
            "gamma":            trial.suggest_float("gamma", 0.0, 0.3),
            "reg_alpha":        trial.suggest_float("reg_alpha", 1e-3, 1.0, log=True),
            "reg_lambda":       trial.suggest_float("reg_lambda", 0.5, 5.0),
        }
        if is_binary:
            model = xgb.XGBClassifier(**params, objective="binary:logistic",
                tree_method="hist", device="cuda", eval_metric="logloss",
                early_stopping_rounds=25, random_state=SEED, n_jobs=-1, verbosity=0)
        else:
            model = xgb.XGBClassifier(**params, objective="multi:softprob",
                num_class=n_classes, tree_method="hist", device="cuda",
                eval_metric="mlogloss", early_stopping_rounds=25,
                random_state=SEED, n_jobs=-1, verbosity=0)
        model.fit(X_tr, y_tr, eval_set=[(X_val, y_val)], verbose=False)
        preds = model.predict(X_val)
        return f1_score(y_val, preds, average="macro", zero_division=0)

    study = optuna.create_study(direction="maximize",
                                sampler=optuna.samplers.TPESampler(seed=SEED))
    study.optimize(objective, n_trials=n_trials, show_progress_bar=True)

    best = study.best_params
    print(f"  ▸ Best macro-F1: {study.best_value*100:.2f}%")
    print(f"  ▸ Best params: depth={best['max_depth']} lr={best['learning_rate']:.4f} "
          f"est={best['n_estimators']} sub={best['subsample']:.2f}")

    if is_binary:
        final = xgb.XGBClassifier(**best, objective="binary:logistic",
            tree_method="hist", device="cuda", eval_metric="logloss",
            early_stopping_rounds=25, random_state=SEED, n_jobs=-1, verbosity=0)
    else:
        final = xgb.XGBClassifier(**best, objective="multi:softprob",
            num_class=n_classes, tree_method="hist", device="cuda",
            eval_metric="mlogloss", early_stopping_rounds=25,
            random_state=SEED, n_jobs=-1, verbosity=0)
    final.fit(X_tr, y_tr, eval_set=[(X_val, y_val)], verbose=False)
    return final, best



# Hierarchical prediction logic

def hierarchical_predict(X, l1_model, l2_models, l2_encoders,
                         le_group, hier_groups):
    group_preds = l1_model.predict(X)
    group_names = le_group.inverse_transform(group_preds)
    fine_preds = np.empty(len(X), dtype=object)

    for group_name, members in hier_groups.items():
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
    return fine_preds



# Confusion matrix plotting

def style_fig(fig):
    fig.patch.set_facecolor("white"); return fig

def style_ax(ax, title=""):
    ax.set_facecolor("white")
    ax.tick_params(colors="black", labelsize=8)
    ax.xaxis.label.set_color("black"); ax.yaxis.label.set_color("black")
    for s in ax.spines.values(): s.set_edgecolor("black")
    if title: ax.set_title(title, color="black", fontsize=10, fontweight="bold", pad=10)
    return ax

def plot_cm(y_true, y_pred, class_names, filename, title):
    present = sorted(set(y_true) | set(y_pred))
    names = [class_names[i] for i in present if i < len(class_names)]
    cm = confusion_matrix(y_true, y_pred, labels=present)
    cm_norm = cm.astype(float) / (cm.sum(axis=1, keepdims=True) + 1e-8)
    fig, ax = plt.subplots(figsize=(10, 8))
    style_fig(fig); style_ax(ax, title)
    ax.imshow(cm_norm, cmap="Blues", vmin=0, vmax=1)
    k = len(names)
    ax.set_xticks(range(k)); ax.set_yticks(range(k))
    short = [c[:14] for c in names]
    ax.set_xticklabels(short, rotation=45, ha="right", fontsize=9, color="black")
    ax.set_yticklabels(short, fontsize=9, color="black")
    ax.set_xlabel("Predicted", color="black", fontsize=11); ax.set_ylabel("Actual", color="black", fontsize=11)
    for i in range(k):
        for j in range(k):
            v = cm_norm[i, j]
            if v > 0.005:  # Only show text if > 0.5%
                ax.text(j, i, f"{v*100:.1f}%", ha="center", va="center",
                        fontsize=8, color="black" if v < 0.5 else "white")
    plt.savefig(PLOT_DIR / filename, dpi=150, bbox_inches="tight", facecolor="white")
    plt.close()
    print(f"  ✓ Confusion matrix → {PLOT_DIR / filename}")



# Load, preprocess, and train the model

print("Starting Loading training data...")
df_train, _ = random_split_csv_data(
    train_rows_per_file=MAX_ROWS_PER_FILE, unseen_rows_per_file=0, seed=SEED)

print("Starting Preprocessing (12-class)...")
df_train, feat_cols = preprocess_dataframe(df_train, target_classes=TARGET_CLASSES_11 | {"DDoS SYN Flood", "DDoS UDP Flood"})

# Apply the 11-class merge: SYN Flood + UDP Flood → Volumetric
print("Starting Merging DDoS SYN Flood + UDP Flood → DDoS Volumetric...")
df_train["Label"] = df_train["Label"].replace(LABEL_MERGE_11CLASS)
print(f"  ▸ Classes after merge: {sorted(df_train['Label'].unique())}")
assert set(df_train["Label"].unique()) == TARGET_CLASSES_11, \
    f"Mismatch: {set(df_train['Label'].unique()) - TARGET_CLASSES_11}"

print("Starting Engineering features...")
df_train, feat_cols = engineer_features(df_train, feat_cols)

# Add group labels
df_train["Group"] = df_train["Label"].map(CLASS_TO_GROUP_11)

# Balance + encode
le_fine = LabelEncoder()
df_train["y_fine"] = le_fine.fit_transform(df_train["Label"])
n_fine = len(le_fine.classes_)

le_group = LabelEncoder()
df_train["y_group"] = le_group.fit_transform(df_train["Group"])
n_groups = len(le_group.classes_)

balanced = []
for cls in sorted(df_train["y_fine"].unique()):
    sub = df_train[df_train["y_fine"] == cls]
    n = min(len(sub), MAX_PER_CLASS)
    balanced.append(sub.sample(max(n, 200), replace=(n < 200), random_state=SEED))
df_train = pd.concat(balanced, ignore_index=True).sample(frac=1, random_state=SEED).reset_index(drop=True)

scaler = StandardScaler()
X_all = scaler.fit_transform(df_train[feat_cols].values.astype(np.float32)).astype(np.float32)
y_fine_all  = df_train["y_fine"].values
y_group_all = df_train["y_group"].values
fine_labels = df_train["Label"].values

idx = np.arange(len(df_train))
idx_tr, idx_tmp = train_test_split(idx, test_size=0.3, random_state=SEED, stratify=y_fine_all)
idx_val, idx_te = train_test_split(idx_tmp, test_size=0.5, random_state=SEED, stratify=y_fine_all[idx_tmp])

X_tr, X_val, X_te = X_all[idx_tr], X_all[idx_val], X_all[idx_te]
y_group_tr, y_group_val, y_group_te = y_group_all[idx_tr], y_group_all[idx_val], y_group_all[idx_te]
y_fine_tr = y_fine_all[idx_tr]
y_fine_te = y_fine_all[idx_te]
fine_labels_tr = fine_labels[idx_tr]
fine_labels_val = fine_labels[idx_val]
fine_labels_te = fine_labels[idx_te]

print(f"  ▸ Classes ({n_fine}): {list(le_fine.classes_)}")
print(f"  ▸ Groups ({n_groups}): {list(le_group.classes_)}")
print(f"  ▸ Features: {len(feat_cols)} ({len(feat_cols)-20} original + 20 engineered)")
print(f"  ▸ Train: {X_tr.shape}  Val: {X_val.shape}  Test: {X_te.shape}")


print("Starting Training hierarchical classifiers...")
t0_total = time.time()

# Level 1
print("\n  ═══ LEVEL 1: Group classifier (6 groups) ═══")
l1_model, l1_params = train_xgb_optuna(
    X_tr, y_group_tr, X_val, y_group_val, n_groups, "Level-1 (groups)")

l1_pred_te = l1_model.predict(X_te)
l1_acc = accuracy_score(y_group_te, l1_pred_te)
l1_f1  = f1_score(y_group_te, l1_pred_te, average="weighted")
print(f"\n  Level 1 test — Acc: {l1_acc*100:.2f}%  F1: {l1_f1*100:.2f}%")
print(classification_report(y_group_te, l1_pred_te, target_names=le_group.classes_, digits=4))

# Level 2 sub-classifiers
l2_models = {}
l2_encoders = {}
l2_params = {}

for group_name, members in HIERARCHICAL_GROUPS_11.items():
    if len(members) <= 1:
        continue

    print(f"\n  ═══ LEVEL 2: {group_name} ({len(members)} classes) ═══")
    mask_tr  = np.isin(fine_labels_tr, members)
    mask_val = np.isin(fine_labels_val, members)

    if mask_tr.sum() < 100:
        print(f"  ⚠ Too few samples — skipping")
        continue

    le_local = LabelEncoder()
    le_local.fit(members)
    y_local_tr  = le_local.transform(fine_labels_tr[mask_tr])
    y_local_val = le_local.transform(fine_labels_val[mask_val])

    model, params = train_xgb_optuna(
        X_tr[mask_tr], y_local_tr, X_val[mask_val], y_local_val,
        n_classes=len(members), level_name=f"Level-2 ({group_name})")

    # Test
    mask_te = np.isin(fine_labels_te, members)
    if mask_te.sum() > 0:
        y_local_te = le_local.transform(fine_labels_te[mask_te])
        preds = model.predict(X_te[mask_te])
        sub_acc = accuracy_score(y_local_te, preds)
        sub_f1 = f1_score(y_local_te, preds, average="weighted")
        print(f"\n  {group_name} test — Acc: {sub_acc*100:.2f}%  F1: {sub_f1*100:.2f}%")
        print(classification_report(y_local_te, preds, target_names=le_local.classes_, digits=4))

    l2_models[group_name] = model
    l2_encoders[group_name] = le_local
    l2_params[group_name] = params

train_time = time.time() - t0_total


print("Starting Full hierarchical evaluation on test set...")
hier_pred_names = hierarchical_predict(
    X_te, l1_model, l2_models, l2_encoders, le_group, HIERARCHICAL_GROUPS_11)
hier_pred = le_fine.transform(hier_pred_names)

te_acc  = accuracy_score(y_fine_te, hier_pred)
te_prec = precision_score(y_fine_te, hier_pred, average="weighted", zero_division=0)
te_rec  = recall_score(y_fine_te, hier_pred, average="weighted", zero_division=0)
te_f1w  = f1_score(y_fine_te, hier_pred, average="weighted", zero_division=0)
te_f1m  = f1_score(y_fine_te, hier_pred, average="macro", zero_division=0)
te_far  = compute_far(y_fine_te, hier_pred, le_fine)

print(f"\n  ── Test Set (11-class) ──")
print(f"  Accuracy  : {te_acc*100:.2f}%")
print(f"  Precision : {te_prec*100:.2f}%")
print(f"  Recall    : {te_rec*100:.2f}%")
print(f"  F1 (wtd)  : {te_f1w*100:.2f}%")
print(f"  F1 (macro): {te_f1m*100:.2f}%")
print(f"  FAR       : {te_far*100:.4f}%")
print(classification_report(y_fine_te, hier_pred, target_names=le_fine.classes_, digits=4))

# Save artifacts
print("  Saving training artifacts...")
l1_model.save_model(str(HIER11_DIR / "level1_xgb.json"))
joblib.dump(le_group,  HIER11_DIR / "level1_label_encoder.pkl")
for gn, model in l2_models.items():
    safe = gn.replace("-", "_").replace(" ", "_")
    model.save_model(str(HIER11_DIR / f"level2_{safe}_xgb.json"))
    joblib.dump(l2_encoders[gn], HIER11_DIR / f"level2_{safe}_label_encoder.pkl")
joblib.dump(scaler,    HIER11_DIR / "scaler.pkl")
joblib.dump(le_fine,   HIER11_DIR / "fine_label_encoder.pkl")
joblib.dump(feat_cols, HIER11_DIR / "feature_names.pkl")

del df_train, X_all, balanced
gc.collect()


# Evaluate the model on unseen data



print("Starting Loading unseen data...")
_, unseen_df = random_split_csv_data(
    data_dir=DATA_DIR, train_rows_per_file=SKIP_ROWS,
    unseen_rows_per_file=MAX_UNSEEN, seed=SEED)
print(f"  ▸ Loaded {len(unseen_df):,} unseen rows")

# Preprocess unseen
unseen_df.columns = unseen_df.columns.str.strip()
unseen_df = unseen_df.loc[:, ~unseen_df.columns.duplicated()]
label_col = next((c for c in unseen_df.columns if c.lower().strip() == "label"), None)
unseen_df.rename(columns={label_col: "Label"}, inplace=True)
unseen_df["Label"] = unseen_df["Label"].astype(str).str.strip().replace(LABEL_MERGE)

# Apply 11-class merge
unseen_df["Label"] = unseen_df["Label"].replace(LABEL_MERGE_11CLASS)

# Filter to 10 target classes
unseen_df = unseen_df[unseen_df["Label"].isin(TARGET_CLASSES_11)].copy()

uf = [c for c in unseen_df.columns if c != "Label"]
unseen_df[uf] = unseen_df[uf].apply(pd.to_numeric, errors="coerce")
unseen_df.replace([np.inf, -np.inf], np.nan, inplace=True)
unseen_df.dropna(thresh=int(len(unseen_df.columns) * 0.7), inplace=True)
unseen_df.fillna(0, inplace=True)

print(f"  ▸ Unseen after filtering: {len(unseen_df):,} rows")
vc = unseen_df["Label"].value_counts()
for cls, cnt in vc.items():
    bar = "█" * min(40, int(cnt / vc.max() * 40))
    print(f"    {cls:<42} {cnt:>8,}  {bar}")

# Engineer features
base_feats = [f for f in feat_cols if f not in {
    "syn_flag_ratio", "ack_syn_ratio", "fin_flag_ratio", "psh_flag_ratio",
    "flag_diversity", "bytes_per_pkt_fwd", "bytes_per_pkt_bwd", "pkt_size_ratio",
    "fwd_bwd_pkt_ratio", "fwd_bwd_byte_ratio", "bwd_fwd_byte_ratio",
    "pkts_per_duration", "bytes_per_duration", "duration_log", "slow_indicator",
    "iat_cv", "fwd_pkt_len_cv", "rst_flag_ratio", "header_payload_ratio",
    "active_idle_ratio",
}]
unseen_df, _ = engineer_features(unseen_df, base_feats)

# Align features
X_unseen_df = pd.DataFrame(index=unseen_df.index)
for f in feat_cols:
    X_unseen_df[f] = unseen_df[f].values.astype(np.float32) if f in unseen_df.columns else 0.0
X_unseen = scaler.transform(X_unseen_df.values.astype(np.float32)).astype(np.float32)

y_true_names = unseen_df["Label"].values
y_true = le_fine.transform(y_true_names)

# Predict
print("Starting Running hierarchical prediction on unseen data...")
t0 = time.time()
pred_names = hierarchical_predict(
    X_unseen, l1_model, l2_models, l2_encoders, le_group, HIERARCHICAL_GROUPS_11)
inf_time = time.time() - t0
y_pred = le_fine.transform(pred_names)

# Level 1 unseen accuracy
y_group_true = np.array([CLASS_TO_GROUP_11[n] for n in y_true_names])
y_group_pred = np.array([CLASS_TO_GROUP_11[n] for n in pred_names])
un_l1_acc = accuracy_score(y_group_true, y_group_pred)
un_l1_f1  = f1_score(y_group_true, y_group_pred, average="weighted", zero_division=0)

# Full metrics
un_acc  = accuracy_score(y_true, y_pred)
un_prec = precision_score(y_true, y_pred, average="weighted", zero_division=0)
un_rec  = recall_score(y_true, y_pred, average="weighted", zero_division=0)
un_f1w  = f1_score(y_true, y_pred, average="weighted", zero_division=0)
un_f1m  = f1_score(y_true, y_pred, average="macro", zero_division=0)
un_far  = compute_far(y_true, y_pred, le_fine)

try:
    from sklearn.preprocessing import label_binarize
    yb = label_binarize(y_true, classes=list(range(n_fine)))
    pb = label_binarize(y_pred, classes=list(range(n_fine)))
    un_auc = roc_auc_score(yb, pb, multi_class="ovr", average="weighted")
except ValueError:
    un_auc = float('nan')

report = classification_report(y_true, y_pred, target_names=le_fine.classes_,
                                zero_division=0, digits=4)

print(f"\n  {'─'*60}")
print(f"  11-class HIERARCHICAL — Unseen Data Results")
print(f"  {'─'*60}")
print(f"  Level 1 (groups)  Acc: {un_l1_acc*100:.2f}%  F1: {un_l1_f1*100:.2f}%")
print(f"  {'─'*60}")
print(f"  Accuracy  : {un_acc*100:.2f}%")
print(f"  Precision : {un_prec*100:.2f}%")
print(f"  Recall    : {un_rec*100:.2f}%")
print(f"  F1 (wtd)  : {un_f1w*100:.2f}%")
print(f"  F1 (macro): {un_f1m*100:.2f}%")
print(f"  AUC       : {un_auc*100:.2f}%")
print(f"  FAR       : {un_far*100:.4f}%")
print(f"\n{report}")
print(f"  Inference: {inf_time:.2f}s ({len(X_unseen)/inf_time:.0f} flows/sec)")

# Confusion matrix
plot_cm(y_true, y_pred, list(le_fine.classes_),
        "hierarchical_11class_confusion.png",
        "11-class Hierarchical — Confusion Matrix (Unseen Data)")


config = {
    "experiment": "11-class hierarchical with smart merge",
    "merge": {"DDoS SYN Flood + DDoS UDP Flood": "DDoS Volumetric"},
    "datasets": ["CIC-IDS2017", "CIC-IDS2018", "CIC-DDoS2019"],
    "n_features": len(feat_cols),
    "n_classes": n_fine,
    "classes": list(le_fine.classes_),
    "groups": list(le_group.classes_),
    "hierarchical_groups": {k: v for k, v in HIERARCHICAL_GROUPS_11.items()},
    "training_time_min": round(train_time / 60, 1),
    "test_metrics": {
        "accuracy": float(te_acc), "precision": float(te_prec),
        "recall": float(te_rec), "f1_weighted": float(te_f1w),
        "f1_macro": float(te_f1m), "far": float(te_far),
    },
    "unseen_metrics": {
        "accuracy": float(un_acc), "precision": float(un_prec),
        "recall": float(un_rec), "f1_weighted": float(un_f1w),
        "f1_macro": float(un_f1m), "auc": float(un_auc),
        "far": float(un_far),
        "level1_accuracy": float(un_l1_acc),
        "level1_f1": float(un_l1_f1),
    },
    "unseen_samples": int(len(X_unseen)),
    "inference_flows_per_sec": int(len(X_unseen) / inf_time),
}
with open(HIER11_DIR / "config_11class.json", "w") as f:
    json.dump(config, f, indent=2)
print(f"\n  ✓ Config → {HIER11_DIR / 'config_11class.json'}")

# Text report
with open(PLOT_DIR / "hierarchical_11class_report.txt", "w") as f:
    f.write("═" * 70 + "\n")
    f.write("  HORUS SOC — 11-class Hierarchical — Unseen Data Report\n")
    f.write("  Merge: DDoS SYN Flood + UDP Flood → DDoS Volumetric\n")
    f.write("═" * 70 + "\n\n")
    f.write(f"  Unseen samples: {len(X_unseen):,}\n")
    f.write(f"  Level 1 Acc: {un_l1_acc*100:.2f}%  F1: {un_l1_f1*100:.2f}%\n\n")
    f.write(f"  Accuracy={un_acc*100:.2f}%  Precision={un_prec*100:.2f}%  "
            f"Recall={un_rec*100:.2f}%  F1(w)={un_f1w*100:.2f}%  "
            f"F1(m)={un_f1m*100:.2f}%  AUC={un_auc*100:.2f}%  FAR={un_far*100:.4f}%\n\n")
    f.write(report + "\n")
    f.write("═" * 70 + "\n")
print(f"  ✓ Report → {PLOT_DIR / 'hierarchical_11class_report.txt'}")



print(f"  {'Experiment':<40} {'Acc':>8}  {'F1(w)':>8}  {'F1(m)':>8}  {'FAR':>10}")
print(f"  {'─'*40} {'─'*8}  {'─'*8}  {'─'*8}  {'─'*10}")
print(f"  {'Exp1: Flat 4-model (12 cls)':<40} {'96.37%':>8}  {'96.27%':>8}  {'91.35%':>8}  {'0.1803%':>10}")
print(f"  {'Exp2: Hierarchical (12 cls)':<40} {'96.36%':>8}  {'96.26%':>8}  {'91.38%':>8}  {'0.1837%':>10}")
print(f"  {'Exp3: Hierarchical (10 cls, merge)':<40} {un_acc*100:>7.2f}%  {un_f1w*100:>7.2f}%  {un_f1m*100:>7.2f}%  {un_far*100:>8.4f}%")
print(f"\n  Training time: {train_time/60:.1f} min")



print("Starting Evaluating on Train set and Plotting Metrics...")
try:
    from sklearn.preprocessing import label_binarize
    def get_metrics_dict(y_true_cls, y_pred_cls):
        acc  = accuracy_score(y_true_cls, y_pred_cls)
        prec = precision_score(y_true_cls, y_pred_cls, average="weighted", zero_division=0)
        rec  = recall_score(y_true_cls, y_pred_cls, average="weighted", zero_division=0)
        f1w  = f1_score(y_true_cls, y_pred_cls, average="weighted", zero_division=0)
        f1m  = f1_score(y_true_cls, y_pred_cls, average="macro", zero_division=0)
        far  = compute_far(y_true_cls, y_pred_cls, le_fine)
        try:
            yb = label_binarize(y_true_cls, classes=list(range(n_fine)))
            pb = label_binarize(y_pred_cls, classes=list(range(n_fine)))
            auc = roc_auc_score(yb, pb, multi_class="ovr", average="weighted")
        except:
            auc = float('nan')
        return [acc*100, prec*100, rec*100, f1w*100, f1m*100, auc*100, far*100]

    hier_pred_names_tr = hierarchical_predict(X_tr, l1_model, l2_models, l2_encoders, le_group, HIERARCHICAL_GROUPS_11)
    hier_pred_tr = le_fine.transform(hier_pred_names_tr)
    
    metrics_tr = get_metrics_dict(y_fine_tr, hier_pred_tr)
    metrics_te = get_metrics_dict(y_fine_te, hier_pred)
    metrics_un = get_metrics_dict(y_true, y_pred)
    
    metric_names = ["Accuracy", "Precision", "Recall", "F1 (Wgtd)", "F1 (Macro)", "AUC", "FAR"]
    phases = ["Train", "Test", "Unseen"]
    
    for i, name in enumerate(metric_names):
        fig, ax = plt.subplots(figsize=(6, 4))
        style_fig(fig); style_ax(ax, title=f"11-class Hierarchical: {name}")
        vals = [metrics_tr[i], metrics_te[i], metrics_un[i]]
        bars = ax.bar(phases, vals, color=["#4c72b0", "#dd8452", "#55a868"], edgecolor="black", linewidth=1.2, width=0.6)
        
        ax.set_ylim(0, max(vals) * 1.15) # Give headroom for text
        if name != "FAR":
            ax.set_ylim(max(0, min(vals) - 5), 105)
            
        for bar, val in zip(bars, vals):
            ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.5,
                    f"{val:.4f}%" if name == "FAR" else f"{val:.2f}%", 
                    ha="center", va="bottom", color="black", fontsize=9)
            
        filename = f"metric_comparison_{name.lower().replace(' ', '_').replace('(', '').replace(')', '')}.png"
        plt.savefig(PLOT_DIR / filename, dpi=150, bbox_inches="tight", facecolor="white")
        plt.close()
        print(f"  ✓ Plot saved: {PLOT_DIR / filename}")

    fig, ax = plt.subplots(figsize=(4, 4))
    style_fig(fig); style_ax(ax, title="Training Time")
    train_time_min = train_time / 60.0
    bar = ax.bar(["Training"], [train_time_min], color=["#9b59b6"], edgecolor="black", linewidth=1.2, width=0.4)
    ax.set_ylim(0, train_time_min * 1.3)
    ax.set_ylabel("Minutes", color="black", fontsize=10)
    
    ax.text(bar[0].get_x() + bar[0].get_width()/2, bar[0].get_height() + (train_time_min * 0.05),
            f"{train_time_min:.1f} min", 
            ha="center", va="bottom", color="black", fontsize=10, fontweight="bold")
            
    plt.savefig(PLOT_DIR / "metric_comparison_training_time.png", dpi=150, bbox_inches="tight", facecolor="white")
    plt.close()
    print(f"  ✓ Plot saved: {PLOT_DIR / 'metric_comparison_training_time.png'}")

except Exception as e:
    print(f"Warning: Failed to plot validation metrics. Error: {e}")

total_script_time = time.time() - SCRIPT_START_TIME
print("\n" + "═" * 70)
print(f"  TOTAL SCRIPT EXECUTION TIME: {total_script_time/60:.1f} minutes")
print("═" * 70 + "\n")

