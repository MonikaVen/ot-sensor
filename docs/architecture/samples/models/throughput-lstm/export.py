#!/usr/bin/env python3
"""Train a tiny LSTM on synthetic N2K bus-load windows and export ONNX.

Requires Python 3.12+ with torch (CPU). Use uv (not pip / venv):

    uv run --no-project --with torch --with onnx --with 'numpy<2' python export.py
"""

from __future__ import annotations

from pathlib import Path

import torch
import torch.nn as nn

SEQ_LEN = 20
N_FEAT = 8
HIDDEN = 16
OUT_DIR = Path(__file__).resolve().parent / "1.0.0"
ONNX_PATH = OUT_DIR / "model.onnx"


class ThroughputLSTM(nn.Module):
    def __init__(self) -> None:
        super().__init__()
        self.lstm = nn.LSTM(N_FEAT, HIDDEN, num_layers=1, batch_first=True)
        self.head = nn.Linear(HIDDEN, 1)

    def forward(self, bus_seq: torch.Tensor) -> torch.Tensor:
        out, _ = self.lstm(bus_seq)
        return torch.sigmoid(self.head(out[:, -1, :]))


def make_window(flood: bool, rng: torch.Generator) -> torch.Tensor:
    def u(lo: float, hi: float) -> float:
        return float(torch.rand(1, generator=rng) * (hi - lo) + lo)

    if flood:
        load, fps, iat = u(0.72, 0.98), u(400.0, 1400.0), u(0.4, 2.5)
        sa, pgn, err, prio = u(1.0, 4.0), u(1.0, 8.0), u(0.02, 0.25), u(0.35, 0.95)
        jitter = 0.08
    else:
        load, fps, iat = u(0.05, 0.35), u(18.0, 90.0), u(8.0, 40.0)
        sa, pgn, err, prio = u(6.0, 22.0), u(8.0, 28.0), u(0.0, 0.02), u(0.05, 0.25)
        jitter = 0.12
    bps = fps * u(8.0, 16.0)
    steps = torch.empty(SEQ_LEN, N_FEAT)
    for t in range(SEQ_LEN):
        n = 1.0 + float(torch.randn(1, generator=rng) * jitter)
        n = max(n, 0.3)
        steps[t, 0] = min(max(load * n, 0.0), 1.0)
        steps[t, 1] = min(max(fps * n, 0.0) / 1500.0, 2.0)
        steps[t, 2] = min(max(bps * n, 0.0) / 25000.0, 2.0)
        steps[t, 3] = min(max(iat / n, 0.1) / 50.0, 2.0)
        steps[t, 4] = min(max(sa * n, 1.0) / 50.0, 2.0)
        steps[t, 5] = min(max(pgn * n, 1.0) / 50.0, 2.0)
        steps[t, 6] = min(max(err * n, 0.0), 1.0)
        steps[t, 7] = min(max(prio * n, 0.0), 1.0)
    return steps


def dataset(n: int, seed: int) -> tuple[torch.Tensor, torch.Tensor]:
    rng = torch.Generator().manual_seed(seed)
    x = torch.empty(n, SEQ_LEN, N_FEAT)
    y = torch.empty(n, 1)
    for i in range(n):
        flood = i % 2 == 1
        x[i] = make_window(flood, rng)
        y[i, 0] = 1.0 if flood else 0.0
    return x, y


def main() -> None:
    torch.manual_seed(0)
    model = ThroughputLSTM()
    opt = torch.optim.Adam(model.parameters(), lr=2e-2)
    loss_fn = nn.BCELoss()
    x, y = dataset(512, seed=1)

    model.train()
    for _ in range(120):
        opt.zero_grad()
        pred = model(x)
        loss = loss_fn(pred, y)
        loss.backward()
        opt.step()

    model.eval()
    with torch.no_grad():
        xb, _ = dataset(8, seed=11)
        xf, _ = dataset(8, seed=12)
        print(f"sample benign flood_score={float(model(xb[0:1])):.3f}")
        print(f"sample flood  flood_score={float(model(xf[1:2])):.3f}")

    dummy = torch.zeros(1, SEQ_LEN, N_FEAT)
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    torch.onnx.export(
        model,
        dummy,
        ONNX_PATH,
        input_names=["bus_seq"],
        output_names=["flood_score"],
        dynamic_axes={"bus_seq": {0: "batch"}, "flood_score": {0: "batch"}},
        opset_version=17,
    )
    print(f"wrote {ONNX_PATH}")


if __name__ == "__main__":
    main()
