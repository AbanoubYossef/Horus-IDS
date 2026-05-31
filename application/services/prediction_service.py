"""Prediction use cases: single, batch, and CSV upload."""

import io
from typing import Optional

import numpy as np
import pandas as pd

from domain.exceptions import (
    ModelNotLoadedError, BatchTooLargeError, InvalidFileError,
)
from domain.ports.model_gateway import ModelGateway
from domain.ports.prediction_repository import PredictionRepository
from application.services.alert_service import AlertService


class PredictionService:
    def __init__(
        self,
        model: ModelGateway,
        repo: PredictionRepository,
        label_merge: dict,
        label_merge_11class: dict,
        alert_service: AlertService | None = None,
    ):
        self._model = model
        self._repo = repo
        self._label_merge = label_merge
        self._label_merge_11class = label_merge_11class
        self._alert_service = alert_service

    def _require_model(self):
        if not self._model.is_loaded():
            raise ModelNotLoadedError("Model not loaded")

    def predict_single(self, features_dict: dict, meta: dict) -> dict:
        self._require_model()
        result = self._model.predict_single(features_dict, meta)
        self._repo.save(result)
        if self._alert_service and result.get("is_attack"):
            self._alert_service.auto_create_from_predictions([result])
        return result

    def predict_batch(self, requests: list[dict], max_batch: int = 500) -> dict:
        self._require_model()
        if len(requests) > max_batch:
            raise BatchTooLargeError(len(requests), max_batch)

        feature_dicts = [r["features_dict"] for r in requests]
        metas = [
            {k: r.get(k) for k in ("src_ip", "dst_ip", "src_port", "dst_port",
                                     "protocol", "vlan_id", "src_vlan", "dst_vlan")}
            for r in requests
        ]

        results = self._model.predict_batch(feature_dicts, metas)
        self._repo.save_many(results)
        if self._alert_service:
            self._alert_service.auto_create_from_predictions(results)

        attacks = sum(1 for r in results if r["is_attack"])
        total_ms = sum(r["inference_ms"] for r in results)
        return {
            "total": len(results),
            "attacks": attacks,
            "benign": len(results) - attacks,
            "inference_ms": round(total_ms, 2),
            "results": results,
        }

    def upload_csv(self, filename: str, content: bytes, max_bytes: int = 50 * 1024 * 1024,
                   max_rows: int = 10_000) -> dict:
        self._require_model()

        if not filename.endswith(".csv"):
            raise InvalidFileError("Only .csv files accepted")
        if len(content) > max_bytes:
            raise InvalidFileError(f"File too large ({len(content) // 1_048_576} MB). Max {max_bytes // 1_048_576} MB.")

        try:
            df = pd.read_csv(io.BytesIO(content), low_memory=False, encoding="latin-1")
        except (pd.errors.ParserError, pd.errors.EmptyDataError, UnicodeDecodeError) as e:
            raise InvalidFileError(f"CSV parse error: {type(e).__name__}")

        if len(df) > max_rows:
            raise InvalidFileError(f"Max {max_rows:,} rows. Got {len(df):,}")

        df.columns = df.columns.str.strip()

        ground_truth = None
        lc = next((c for c in df.columns if c.lower().strip() == "label"), None)
        if lc:
            df.rename(columns={lc: "Label"}, inplace=True)
            df["Label"] = (df["Label"].astype(str).str.strip()
                           .replace(self._label_merge)
                           .replace(self._label_merge_11class))
            ground_truth = df["Label"].values.tolist()

        flow_dicts = []
        for _, row in df.iterrows():
            fd = {}
            for col in df.columns:
                if col == "Label":
                    continue
                try:
                    v = float(row[col])
                    if np.isfinite(v):
                        fd[col] = v
                except (ValueError, TypeError):
                    pass
            flow_dicts.append(fd)

        results = self._model.predict_batch(flow_dicts)
        if ground_truth:
            for i, r in enumerate(results):
                r["ground_truth"] = ground_truth[i]
        self._repo.save_many(results)
        if self._alert_service:
            self._alert_service.auto_create_from_predictions(results)

        attacks = sum(1 for r in results if r["is_attack"])
        correct = sum(
            1 for r in results
            if ground_truth and r.get("ground_truth") == r["attack_type"]
        )
        total_ms = sum(r["inference_ms"] for r in results)

        return {
            "filename": filename,
            "total": len(results),
            "attacks": attacks,
            "benign": len(results) - attacks,
            "inference_ms": round(total_ms, 2),
            "accuracy": round(correct / len(results), 4) if ground_truth else None,
            "results": results,
        }
