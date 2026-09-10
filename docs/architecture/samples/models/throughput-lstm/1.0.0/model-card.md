# throughput-lstm 1.0.0

Sample ONNX LSTM that scores NMEA 2000 **bus throughput sequences** and fires on flood / high-load traffic (ATT&CK for ICS T0814 Denial of Service).

This is a lab-initialized model trained on **synthetic** windows, not ship captures. Replace weights before any operational use.

## Intended use

- Bytewax ONNX branch, same `event_id` as rules / other models.
- Input: 20 steps × 100 ms of bus-level features (not raw CAN bytes).
- Output: `flood_score` in `[0, 1]`. Pipeline treats `>= 0.80` as a fire.

## When it should fire

| Pattern | Typical features | Score |
| --- | --- | --- |
| PGN flood / bus saturation | `bus_load_pct` 70–98, `frames_per_s` hundreds–thousands, short inter-arrival | `>= 0.80` (critical) |
| Burst but still healthy | Short spike, load returns under ~40% | below fire |
| Underway / alongside baseline | Load 5–35%, frame rates matching catalog intervals | low |

Paired simulator overlay: `PGN flood` (T0814). Distinguisher vs GPS spoof: spoof does **not** saturate the bus; this LSTM should stay quiet during `gps-spoof-underway`.

## Failure modes

- **False positive:** legitimate high-rate heading/GNSS (10 Hz) on a busy nav backbone. Mitigate with `unique_pgn` / catalog-expected rate features and the 2 s window (steady flood vs brief burst).
- **False negative:** low-rate targeted flood of a single high-priority PGN that does not raise `bus_load_pct`. Complementary sequence classifier (`claim-flood-seq`) and rules still apply.
- **Not a RF jammer detector.** On-bus consequence only.

Bytewax must apply the same `normalize` divisors as `config.yaml` (`frames_per_s / 1500`, `bytes_per_s / 25000`, inter-arrival / 50, unique SA/PGN / 50) before the ONNX branch.

## Training data

Synthetic sequences generated in `export.py`: benign vs flood labels. No MITRE or vessel recordings in this sample.

Re-export with uv (not pip / venv):

```bash
uv run --no-project --with torch --with onnx --with 'numpy<2' python docs/architecture/samples/models/throughput-lstm/export.py
```
