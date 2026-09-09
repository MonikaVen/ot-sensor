"""ONNX enrich. Sibling of rules. Fail closed."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import numpy as np

from ot_sensor.features import FeatureStage, FeatureWindow

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None


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


def list_onnx_models(repo: Path) -> list[dict]:
    """Deployed ONNX heads under docs/architecture/samples/models."""
    root = Path(repo) / "docs" / "architecture" / "samples" / "models"
    packs: list[dict] = []
    if not root.is_dir() or yaml is None:
        return packs
    for cfg_path in sorted(root.glob("*/*/config.yaml")):
        try:
            cfg = yaml.safe_load(cfg_path.read_text()) or {}
        except Exception:
            continue
        onnx = cfg.get("onnx") or {}
        rel = onnx.get("path")
        if not rel:
            continue
        weights = cfg_path.parent / rel
        packs.append(
            {
                "model_id": str(cfg.get("model_id") or cfg_path.parent.parent.name),
                "version": str(cfg.get("version") or cfg_path.parent.name),
                "title": str(cfg.get("model_id") or "onnx"),
                "blurb": str((cfg.get("fire") or {}).get("attack_family") or "ONNX head"),
                "onnx_path": str(weights),
                "onnx_loaded": weights.is_file(),
                "fire": float(((cfg.get("score_to_severity") or {}).get("critical") or 0.80)),
                "techniques": list((cfg.get("fire") or {}).get("techniques") or []),
                "impacts": list((cfg.get("fire") or {}).get("impacts") or []),
            }
        )
    return packs
