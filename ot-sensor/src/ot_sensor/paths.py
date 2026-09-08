"""Repo and package roots after the uv workspace split."""

from __future__ import annotations

from pathlib import Path


def lab_root() -> Path:
    """Workspace root that contains docs/architecture/samples."""
    for p in Path(__file__).resolve().parents:
        if (p / "docs" / "architecture" / "samples").is_dir():
            return p
    raise FileNotFoundError("docs/architecture/samples not found")


def sensor_root() -> Path:
    """ot-sensor package directory (frontend lives here)."""
    return Path(__file__).resolve().parents[2]
