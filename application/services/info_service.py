"""Misc info endpoints: health, model classes, features, data samples."""

import io
import logging
import random
from pathlib import Path

import numpy as np
import pandas as pd

from domain.exceptions import ModelNotLoadedError, NoDataAvailableError
from domain.ports.model_gateway import ModelGateway

log = logging.getLogger("horus-api")


class InfoService:
    def __init__(self, model: ModelGateway, data_dir: Path,
                 label_merge: dict, label_merge_11class: dict):
        self._model = model
        self._data_dir = data_dir
        self._label_merge = label_merge
        self._label_merge_11class = label_merge_11class
        self._csv_files: list[Path] = []
        self._csv_offsets: dict[str, list[int]] = {}

    def index_csvs(self):
        if self._csv_files:
            return
        total_rows = 0
        for p in sorted(self._data_dir.glob("*.csv")):
            try:
                offsets = []
                with open(p, "rb") as f:
                    f.readline()
                    while True:
                        pos = f.tell()
                        line = f.readline()
                        if not line:
                            break
                        offsets.append(pos)
                if offsets:
                    self._csv_files.append(p)
                    self._csv_offsets[str(p)] = offsets
                    total_rows += len(offsets)
            except (OSError, PermissionError) as e:
                log.warning("Skipping CSV %s: %s", p.name, e)
        if self._csv_files:
            log.info("Indexed %d CSV files (%s rows)", len(self._csv_files), f"{total_rows:,}")

    def get_health(self) -> dict:
        return self._model.get_health_info()

    def get_classes(self) -> dict:
        if not self._model.is_loaded():
            raise ModelNotLoadedError("Model not loaded")
        return self._model.get_classes()

    def get_features(self) -> dict:
        if not self._model.is_loaded():
            raise ModelNotLoadedError("Model not loaded")
        return self._model.get_features()

    def get_data_sample(self) -> dict:
        if not self._model.is_loaded():
            raise ModelNotLoadedError("Model not loaded")
        if not self._csv_files:
            raise NoDataAvailableError("No CSV data")

        csv_path = random.choice(self._csv_files)
        offsets = self._csv_offsets[str(csv_path)]
        chosen_offset = random.choice(offsets)

        with open(csv_path, "rb") as f:
            f.seek(0)
            header = f.readline().decode("latin-1")
            f.seek(chosen_offset)
            line = f.readline().decode("latin-1")

        row = pd.read_csv(io.StringIO(header + line), encoding="latin-1", low_memory=False)
        row.columns = row.columns.str.strip()

        lc = next((c for c in row.columns if c.lower().strip() == "label"), None)
        label = "UNKNOWN"
        if lc:
            label = str(row[lc].iloc[0]).strip()
            label = self._label_merge.get(label, label)
            label = self._label_merge_11class.get(label, label)

        features = {}
        for col in row.columns:
            if col.lower().strip() == "label":
                continue
            try:
                v = float(row[col].iloc[0])
                if np.isfinite(v):
                    features[col] = v
            except (ValueError, TypeError):
                pass

        return {"features_dict": features, "ground_truth": label, "source_file": csv_path.name}
