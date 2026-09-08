"""ONNX enrich. Sibling of rules. Fail closed."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import numpy as np

from ot_sensor.features import FeatureStage, FeatureWindow


@dataclass
class ModelScore:
    event_id: str
    model_id: str
    version: str
    scores: dict[str, float]
    status: str


class OnnxEnrich:
    def __init__(self, model_dir: Path | None) -> None:
        self.model_id = "throughput-lstm"
        self.version = "1.0.0"
        self.sess = None
        if model_dir and (model_dir / "model.onnx").exists():
            try:
                import onnxruntime as ort

                self.sess = ort.InferenceSession(str(model_dir / "model.onnx"), providers=["CPUExecutionProvider"])
            except Exception:
                self.sess = None

    def score(self, window: FeatureWindow, seq: list[list[float]] | None = None) -> ModelScore:
        if self.sess is None:
            return ModelScore(window.event_id, self.model_id, self.version, {}, "model_unavailable")
        if seq is None:
            seq = FeatureStage().lstm_seq([window])
        arr = np.asarray([seq], dtype=np.float32)
        name = self.sess.get_inputs()[0].name
        out = self.sess.run(None, {name: arr})[0]
        flood = float(out.reshape(-1)[0])
        return ModelScore(window.event_id, self.model_id, self.version, {"flood_score": flood}, "ok")
