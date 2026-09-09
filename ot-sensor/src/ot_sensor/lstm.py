"""Online LSTM: one-step N2K throughput prediction. Anomaly on residual."""

from __future__ import annotations

import numpy as np

FPS_SCALE = 1500.0


def _sig(x: np.ndarray | float) -> np.ndarray | float:
    return 1.0 / (1.0 + np.exp(-np.clip(x, -20.0, 20.0)))


class ThroughputLstm:
    """Tiny LSTM that tracks frames/s and fires when the bus jumps off the prediction."""

    model_id = "throughput-lstm"
    version = "1.0.0"

    def __init__(self, hidden: int = 12, lr: float = 0.08) -> None:
        rng = np.random.default_rng(7)
        h, d = hidden, 1
        scale = 0.12
        self.hidden = h
        self.Wih = rng.normal(0.0, scale, (4 * h, d))
        self.Whh = rng.normal(0.0, scale, (4 * h, h))
        self.b = np.zeros(4 * h)
        self.b[h : 2 * h] = 1.0
        self.Wy = rng.normal(0.0, 0.08, (1, h))
        self.by = np.zeros(1)
        self.h = np.zeros(h)
        self.c = np.zeros(h)
        self.lr = lr
        self.steps = 0
        self._above = False
        self.last: dict | None = None

    def _gates(self, x: np.ndarray, h: np.ndarray, c: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
        z = self.Wih @ x + self.Whh @ h + self.b
        i = _sig(z[: self.hidden])
        f = _sig(z[self.hidden : 2 * self.hidden])
        g = np.tanh(z[2 * self.hidden : 3 * self.hidden])
        o = _sig(z[3 * self.hidden :])
        c2 = f * c + i * g
        h2 = o * np.tanh(c2)
        return h2, c2

    def predict_fps(self) -> float:
        return max(0.0, float((self.Wy @ self.h + self.by)[0]))

    def step(self, actual_fps: float) -> dict:
        actual_fps = float(actual_fps)
        target = float(np.clip(actual_fps / FPS_SCALE, 0.0, 2.0))
        if self.steps == 0:
            self.by[0] = actual_fps
            pred_fps = actual_fps
        else:
            pred_fps = self.predict_fps()
            err = float(np.clip(pred_fps - actual_fps, -400.0, 400.0))
            self.Wy -= self.lr * (err / 80.0) * self.h.reshape(1, -1)
            self.by -= self.lr * (err / 80.0)
        x = np.array([target])
        self.h, self.c = self._gates(x, self.h, self.c)
        self.steps += 1
        threshold_fps = float(pred_fps)
        residual = abs(actual_fps - threshold_fps)
        warm = self.steps >= 8
        band = max(3.0, 0.1 * max(threshold_fps, 0.0))
        if not warm:
            above = False
        elif self._above:
            above = actual_fps > threshold_fps
        else:
            above = actual_fps > threshold_fps + band
        crossed = above and not self._above
        self._above = above
        self.last = {
            "actual_fps": actual_fps,
            "predicted_fps": pred_fps,
            "threshold_fps": threshold_fps,
            "residual_fps": float(residual),
            "flood_score": 1.0 if above else 0.0,
            "crossed": crossed,
            "fired": above,
            "steps": self.steps,
        }
        return self.last
