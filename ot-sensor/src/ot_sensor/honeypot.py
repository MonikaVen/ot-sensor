"""Honeypot: raw units, rotate + retain. Never block the TAP."""

from __future__ import annotations

import gzip
import hashlib
import json
import os
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from otlab import CanFrame


class Honeypot:
    def __init__(
        self,
        root: Path,
        mode: str,
        hull: str = "opv1",
        rotate_max_bytes: int = 128,
        retain_max_files: int = 4,
        hold_paths: set[str] | None = None,
    ) -> None:
        self.root = Path(root)
        self.mode = mode
        self.hull = hull
        self.rotate_max_bytes = rotate_max_bytes
        self.retain_max_files = retain_max_files
        self.hold_paths = hold_paths or set()
        self.seq = 0
        self.dropped = 0
        self.rotation = 0
        self._fh = None
        self._path: Path | None = None
        self._utc_open: datetime | None = None
        self.closed: list[Path] = []
        self.manifest: list[dict] = []

    def _open(self, segment: str, iface: str, t: datetime) -> None:
        d = self.root / segment
        d.mkdir(parents=True, exist_ok=True)
        name = f"hp-{self.mode}-{self.hull}-{segment}-{iface}-{t.strftime('%Y%m%dT%H%M%SZ')}-open-{os.getpid()}.jsonl"
        self._path = d / name
        self._fh = self._path.open("a")
        self._utc_open = t
        self.seq = 0

    def write_frame(self, frame: CanFrame, iface: str = "vcan_nav") -> None:
        if self._fh is None:
            self._open(frame.segment, iface, frame.t)
        rec = {
            "t": frame.t.isoformat(),
            "segment": frame.segment,
            "iface": iface,
            "seq": self.seq,
            "nbytes": len(frame.data),
            "kind": "error" if frame.error else "can",
            "sha256": hashlib.sha256(frame.data).hexdigest(),
            "payload_b64": frame.data.hex(),
        }
        line = json.dumps(rec) + "\n"
        if self._path and self._path.stat().st_size + len(line) > self.rotate_max_bytes and self.seq > 0:
            self.rotate(frame.t)
            self._open(frame.segment, iface, frame.t)
        if self._fh is None:
            self.dropped += 1
            return
        self._fh.write(line)
        self._fh.flush()
        self.seq += 1

    def rotate(self, t: datetime) -> Path | None:
        if self._fh is None or self._path is None or self._utc_open is None:
            return None
        self._fh.close()
        closed_name = self._path.name.replace(f"-open-{os.getpid()}", "")
        closed_name = closed_name.replace(".jsonl", f"-{t.strftime('%Y%m%dT%H%M%SZ')}-n{self.seq}-r{self.rotation:04d}.jsonl")
        dest = self._path.with_name(closed_name)
        self._path.rename(dest)
        gz = dest.with_suffix(dest.suffix + ".gz")
        with dest.open("rb") as src, gzip.open(gz, "wb") as out:
            out.write(src.read())
        dest.unlink()
        self.closed.append(gz)
        self.manifest.append({"path": str(gz), "purged": False, "rotation": self.rotation})
        self.rotation += 1
        self._fh = None
        self._path = None
        self._purge()
        return gz

    def _purge(self) -> None:
        keepable = [p for p in self.closed if str(p) not in self.hold_paths]
        while len(self.closed) > self.retain_max_files and keepable:
            victim = keepable.pop(0)
            if victim.exists():
                victim.unlink()
            self.closed.remove(victim)
            self.manifest.append({"path": str(victim), "purged": True})
        if len(self.closed) > self.retain_max_files:
            # all remaining on hold
            pass
