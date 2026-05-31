"""Hierarchical XGBoost model gateway -- implements ModelGateway port."""

import json, logging, math, time, uuid
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd
import xgboost as xgb
import joblib

from domain.ports.model_gateway import ModelGateway
from domain.constants import SEVERITY_MAP, HIERARCHICAL_GROUPS_11
from infrastructure.ml.feature_engineering import engineer_features

log = logging.getLogger("horus-api")

ENGINEERED_FEATURE_NAMES = {
    "syn_flag_ratio", "ack_syn_ratio", "fin_flag_ratio", "psh_flag_ratio",
    "flag_diversity", "bytes_per_pkt_fwd", "bytes_per_pkt_bwd", "pkt_size_ratio",
    "fwd_bwd_pkt_ratio", "fwd_bwd_byte_ratio", "bwd_fwd_byte_ratio",
    "pkts_per_duration", "bytes_per_duration", "duration_log", "slow_indicator",
    "iat_cv", "fwd_pkt_len_cv", "rst_flag_ratio", "header_payload_ratio",
    "active_idle_ratio",
}


class HierarchicalModelGateway(ModelGateway):
    def __init__(self, model_dir: Path):
        self._model_dir = model_dir
        self._hier_dir = model_dir / "hierarchical_11class"
        self._loaded = False
        self._hier_cfg = {}
        self._scaler = None
        self._le_fine = None
        self._le_group = None
        self._feat_names = None
        self._l1_model = None
        self._l2_models = {}
        self._l2_encoders = {}
        self._n_classes = 0
        self._feat_rank = {}
        self._load()

    def _load(self):
        log.info("Loading hierarchical 11-class model...")
        try:
            with open(self._hier_dir / "config_11class.json") as f:
                self._hier_cfg = json.load(f)
            self._scaler = joblib.load(self._hier_dir / "scaler.pkl")
            self._le_fine = joblib.load(self._hier_dir / "fine_label_encoder.pkl")
            self._le_group = joblib.load(self._hier_dir / "level1_label_encoder.pkl")
            self._feat_names = joblib.load(self._hier_dir / "feature_names.pkl")

            self._l1_model = xgb.XGBClassifier()
            self._l1_model.load_model(str(self._hier_dir / "level1_xgb.json"))
            log.info("Level 1: %d groups", len(self._le_group.classes_))

            for grp, members in HIERARCHICAL_GROUPS_11.items():
                if len(members) <= 1:
                    continue
                safe = grp.replace("-", "_").replace(" ", "_")
                mp = self._hier_dir / f"level2_{safe}_xgb.json"
                lp = self._hier_dir / f"level2_{safe}_label_encoder.pkl"
                if mp.exists() and lp.exists():
                    m = xgb.XGBClassifier()
                    m.load_model(str(mp))
                    self._l2_models[grp] = m
                    self._l2_encoders[grp] = joblib.load(lp)
                    log.info("Level 2 (%s): %d classes", grp, len(self._l2_encoders[grp].classes_))

            self._n_classes = len(self._le_fine.classes_)
            self._loaded = True
            unseen = self._hier_cfg.get("unseen_metrics", {})
            log.info("Model ready -- %d classes, %d features", self._n_classes, len(self._feat_names))
            log.info("Unseen F1=%.2f%%  FAR=%.4f%%", unseen.get('f1_weighted', 0) * 100, unseen.get('far', 0) * 100)
        except (FileNotFoundError, json.JSONDecodeError, KeyError, ValueError, OSError) as e:
            log.error("Model loading failed (%s): %s", type(e).__name__, e)
        except Exception as e:
            log.error("Unexpected model loading error (%s): %s", type(e).__name__, e)

        # Load feature importance
        for pfx in ["rf", "lgb", "cb"]:
            fp = self._model_dir / f"{pfx}_feature_importance.csv"
            if fp.exists():
                fi = pd.read_csv(fp)
                for _, r in fi.iterrows():
                    self._feat_rank[r["feature"]] = self._feat_rank.get(r["feature"], 0.0) + r["importance"]
        self._feat_rank = {k: i + 1 for i, (k, _) in enumerate(sorted(self._feat_rank.items(), key=lambda x: -x[1]))}

    def is_loaded(self) -> bool:
        return self._loaded

    def _build_features(self, flow_dicts):
        df = pd.DataFrame(flow_dicts)
        base = [f for f in self._feat_names if f not in ENGINEERED_FEATURE_NAMES]
        df, _ = engineer_features(df, base)
        X = pd.DataFrame(index=df.index)
        for f in self._feat_names:
            X[f] = df[f].values.astype(np.float32) if f in df.columns else 0.0
        return self._scaler.transform(X.values.astype(np.float32)).astype(np.float32)

    def _hier_predict(self, X):
        grp_pred = self._l1_model.predict(X)
        grp_names = self._le_group.inverse_transform(grp_pred)
        fine = np.empty(len(X), dtype=object)
        for grp, members in HIERARCHICAL_GROUPS_11.items():
            mask = grp_names == grp
            if mask.sum() == 0:
                continue
            if len(members) == 1:
                fine[mask] = members[0]
            elif grp in self._l2_models:
                sub = self._l2_models[grp].predict(X[mask])
                fine[mask] = self._l2_encoders[grp].inverse_transform(sub)
            else:
                fine[mask] = members[0]
        return fine, grp_names

    def _get_l2_probas(self, X_row, grp_name):
        if grp_name in self._l2_models:
            probs = self._l2_models[grp_name].predict_proba(X_row.reshape(1, -1))[0]
            le2 = self._l2_encoders[grp_name]
            return {str(c): round(self._safe_float(p), 4) for c, p in zip(le2.classes_, probs)}
        return {}

    @staticmethod
    def _safe_float(v):
        f = float(v)
        return 0.0 if not math.isfinite(f) else f

    def _top_features(self, vec, n=6):
        ranked = sorted(
            [(i, f, self._feat_rank.get(f, 999)) for i, f in enumerate(self._feat_names)],
            key=lambda x: x[2]
        )
        return [
            {"name": f, "value": round(self._safe_float(vec[i]), 4), "rank": rank}
            for i, f, rank in ranked[:n]
        ]

    def _build_result(self, X_row, fine_label, grp_label, inf_ms, meta=None):
        prob_dict = self._get_l2_probas(X_row, str(grp_label))
        if not prob_dict:
            prob_dict = {str(fine_label): 1.0}
        top_feats = self._top_features(X_row)
        pred_label = str(fine_label)
        conf = max(prob_dict.values()) if prob_dict else 0.95
        result = {
            "id": str(uuid.uuid4()),
            "attack_type": pred_label,
            "confidence": round(float(conf), 4),
            "is_attack": pred_label != "BENIGN",
            "severity": SEVERITY_MAP.get(pred_label, "medium"),
            "group_pred": str(grp_label),
            "probabilities": prob_dict,
            "top_features": top_feats,
            "inference_ms": round(inf_ms, 3),
            "model": "Hierarchical 11-class (98.70% F1)",
            "created_at": datetime.now(timezone.utc).isoformat(),
            **(meta or {}),
        }
        return result

    def predict_single(self, features_dict: dict, meta: dict | None = None) -> dict:
        t0 = time.perf_counter()
        X = self._build_features([features_dict])
        fine, grps = self._hier_predict(X)
        inf_ms = (time.perf_counter() - t0) * 1000
        return self._build_result(X[0], fine[0], grps[0], inf_ms, meta)

    def predict_batch(self, feature_dicts: list[dict], metas: list[dict] | None = None) -> list[dict]:
        t0 = time.perf_counter()
        X = self._build_features(feature_dicts)
        fine, grps = self._hier_predict(X)
        total_ms = (time.perf_counter() - t0) * 1000
        results = []
        for i in range(len(fine)):
            m = metas[i] if metas else None
            r = self._build_result(X[i], fine[i], grps[i], total_ms / len(fine), m)
            results.append(r)
        return results

    def get_health_info(self) -> dict:
        return {
            "status": "ready" if self._loaded else "no_model",
            "model": "Hierarchical 11-class (Optuna XGBoost + 20 engineered features)",
            "architecture": {
                "level1": f"{len(self._le_group.classes_)} groups" if self._loaded else "n/a",
                "level2": list(self._l2_models.keys()),
                "classes": self._n_classes,
            },
            "classes": list(self._le_fine.classes_) if self._loaded else [],
            "features": len(self._feat_names) if self._feat_names else 0,
            "performance": self._hier_cfg.get("unseen_metrics", {}),
        }

    def get_classes(self) -> dict:
        return {
            "classes": list(self._le_fine.classes_),
            "count": self._n_classes,
            "groups": {k: v for k, v in HIERARCHICAL_GROUPS_11.items()},
            "severity_map": SEVERITY_MAP,
        }

    def get_features(self) -> dict:
        top30 = sorted(self._feat_rank.items(), key=lambda x: x[1])[:30]
        return {
            "total": len(self._feat_names),
            "feature_names": list(self._feat_names),
            "top_30": [{"name": n, "rank": r} for n, r in top30],
        }

    def get_feature_rank(self) -> dict:
        return dict(self._feat_rank)
