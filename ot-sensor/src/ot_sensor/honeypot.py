"""Honeypot collector: TAP-side raw sink with rotate/retain and a live feed.

Listen-only. Never blocks RX: if the retain cap is hit and every closed file is
on hold, new units are dropped (`dropped++`) instead of unlinking `open-{pid}`.
"""

from __future__ import annotations

import base64
import gzip
import hashlib
import json
import os
import shutil
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import TextIO

import yaml

from otlab import CanFrame

UTC = timezone.utc


def _iface_token(iface: str) -> str:
    return "".join(ch for ch in iface if ch not in "/_")


def _aware(t: datetime) -> datetime:
    if t.tzinfo is None:
        return t.replace(tzinfo=UTC)
    return t.astimezone(UTC)


def _utc_token(t: datetime) -> str:
    return _aware(t).strftime("%Y%m%dT%H%M%SZ")


def _kind_of(data: bytes, error: bool = False) -> str:
    if error:
        return "error"
    if not data:
        return "empty"
    return "can"


def load_honeypot_config(path: Path | None = None) -> dict:
    cfg = {
        "rotate_max_bytes": 128 * 1024 * 1024,
        "rotate_max_age_s": 3600,
        "retain_max_files": 48,
        "retain_max_bytes": 2 * 1024 * 1024 * 1024,
        "retain_max_age_s": 2592000,
        "live_max": 120,
    }
    if path is None or not Path(path).is_file():
        return cfg
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    rot = data.get("rotate") or {}
    ret = data.get("retain") or {}
    if rot.get("max_bytes") is not None:
        cfg["rotate_max_bytes"] = int(rot["max_bytes"])
    if rot.get("max_age_s") is not None:
        cfg["rotate_max_age_s"] = int(rot["max_age_s"])
    if ret.get("max_files_per_segment") is not None:
        cfg["retain_max_files"] = int(ret["max_files_per_segment"])
    if ret.get("max_bytes_per_segment") is not None:
        cfg["retain_max_bytes"] = int(ret["max_bytes_per_segment"])
    if ret.get("max_age_s") is not None:
        cfg["retain_max_age_s"] = int(ret["max_age_s"])
    return cfg


@dataclass
class _Slot:
    segment: str
    iface: str
    path: Path
    fh: TextIO
    utc_open: datetime
    rotation: int
    seq: int = 0
    nbytes: int = 0
    kinds: set[str] = field(default_factory=set)


class HoneypotService:
    def __init__(
        self,
        root: Path,
        mode: str,
        hull: str = "opv1",
        rotate_max_bytes: int | None = None,
        retain_max_files: int | None = None,
        hold_paths: set[str] | None = None,
        *,
        config_path: Path | None = None,
        rotate_max_age_s: int | None = None,
        retain_max_bytes: int | None = None,
        retain_max_age_s: int | None = None,
        live_max: int | None = None,
    ) -> None:
        loaded = load_honeypot_config(config_path)
        self.root = Path(root)
        self.mode = mode
        self.hull = hull
        self.rotate_max_bytes = int(rotate_max_bytes if rotate_max_bytes is not None else loaded["rotate_max_bytes"])
        self.rotate_max_age_s = int(rotate_max_age_s if rotate_max_age_s is not None else loaded["rotate_max_age_s"])
        self.retain_max_files = int(retain_max_files if retain_max_files is not None else loaded["retain_max_files"])
        self.retain_max_bytes = int(retain_max_bytes if retain_max_bytes is not None else loaded["retain_max_bytes"])
        self.retain_max_age_s = int(retain_max_age_s if retain_max_age_s is not None else loaded["retain_max_age_s"])
        self.hold_paths = hold_paths if hold_paths is not None else set()
        self.written = 0
        self.dropped = 0
        self.rotation = 0
        self.closed: list[Path] = []
        self.manifest: list[dict] = []
        self._slots: dict[str, _Slot] = {}
        self._rot_index: dict[str, int] = {}
        self._last_segment: str | None = None
        self._live: deque[dict] = deque(maxlen=int(live_max if live_max is not None else loaded["live_max"]))

    @property
    def seq(self) -> int:
        slot = self._slots.get(self._last_segment or "")
        return slot.seq if slot else 0

    @property
    def _path(self) -> Path | None:
        slot = self._slots.get(self._last_segment or "")
        return slot.path if slot else None

    def open_files(self) -> list[tuple[Path, int]]:
        return [(s.path, s.seq) for s in self._slots.values()]

    def feed(self, n: int | None = None) -> list[dict]:
        items = list(reversed(self._live))
        if n is not None:
            return items[:n]
        return items

    def write_frame(self, frame: CanFrame, iface: str = "vcan_nav") -> None:
        data = bytes(frame.data)
        self.collect(
            t=frame.t,
            segment=frame.segment,
            iface=iface,
            data=data,
            kind=_kind_of(data, frame.error),
            can_id=int(frame.can_id),
        )

    def collect(
        self,
        t: datetime,
        segment: str,
        iface: str,
        data: bytes,
        kind: str = "unknown",
        can_id: int | None = None,
    ) -> None:
        if self._blocked(segment):
            self.dropped += 1
            return
        slot = self._slots.get(segment)
        if slot is not None and self._should_rotate(slot, t):
            if self._cannot_rotate(segment):
                self.dropped += 1
                return
            self._rotate_slot(slot, t)
            slot = None
        if slot is None:
            if self._cannot_rotate(segment) and self._closed_for(segment):
                # Cap already full of held files; do not open another.
                self.dropped += 1
                return
            slot = self._open(segment, iface, t)
        rec = {
            "t": _aware(t).isoformat().replace("+00:00", "Z"),
            "segment": segment,
            "iface": iface,
            "seq": slot.seq,
            "nbytes": len(data),
            "kind": kind,
            "sha256": hashlib.sha256(data).hexdigest(),
            "payload_b64": base64.b64encode(data).decode("ascii"),
        }
        line = json.dumps(rec, separators=(",", ":")) + "\n"
        try:
            slot.fh.write(line)
            slot.fh.flush()
        except OSError:
            self.dropped += 1
            return
        slot.seq += 1
        slot.nbytes += len(data)
        slot.kinds.add(kind)
        self.written += 1
        self._last_segment = segment
        live = {
            **rec,
            "payload_hex": data.hex(),
        }
        if can_id is not None:
            live["can_id"] = can_id
            live["error"] = kind == "error"
        self._live.append(live)

    def rotate(self, t: datetime) -> Path | None:
        last: Path | None = None
        for slot in list(self._slots.values()):
            last = self._rotate_slot(slot, t) or last
        return last

    def close(self) -> None:
        for slot in list(self._slots.values()):
            try:
                slot.fh.close()
            except OSError:
                pass
        self._slots.clear()

    def wipe(self) -> None:
        self.close()
        if self.root.exists():
            shutil.rmtree(self.root, ignore_errors=True)
        self.written = 0
        self.dropped = 0
        self.rotation = 0
        self.closed = []
        self.manifest = []
        self._rot_index.clear()
        self._last_segment = None
        self._live.clear()

    def usage(self) -> dict:
        files: list[dict] = []
        total = 0
        open_bytes = 0
        open_resolved = {s.path.resolve() for s in self._slots.values() if s.path.exists()}
        if self.root.exists():
            for path in sorted(p for p in self.root.rglob("*") if p.is_file()):
                st = path.stat()
                nbytes = st.st_size
                total += nbytes
                is_open = path.resolve() in open_resolved
                if is_open:
                    open_bytes += nbytes
                files.append(
                    {
                        "name": path.name,
                        "path": str(path.relative_to(self.root)),
                        "bytes": nbytes,
                        "open": is_open,
                        "t": datetime.fromtimestamp(st.st_mtime, UTC).isoformat(),
                    }
                )
        latest = self._slots.get(self._last_segment or "")
        return {
            "bytes": total,
            "bytes_open": open_bytes,
            "bytes_closed": max(0, total - open_bytes),
            "files": len(files),
            "seq": self.seq,
            "written": self.written,
            "dropped": self.dropped,
            "rotation": self.rotation,
            "rotate_max_bytes": self.rotate_max_bytes,
            "retain_max_files": self.retain_max_files,
            "open_path": latest.path.name if latest else None,
            "open_paths": [s.path.name for s in self._slots.values()],
            "root": str(self.root),
            "entries": files[-24:],
        }

    def snapshot(self) -> dict:
        return {**self.usage(), "feed": self.feed()}

    def _open(self, segment: str, iface: str, t: datetime) -> _Slot:
        d = self.root / segment
        d.mkdir(parents=True, exist_ok=True)
        token = _iface_token(iface)
        name = f"hp-{self.mode}-{self.hull}-{segment}-{token}-{_utc_token(t)}-open-{os.getpid()}.jsonl"
        path = d / name
        fh = path.open("a", encoding="utf-8")
        rot = self._rot_index.get(segment, 0)
        slot = _Slot(segment=segment, iface=iface, path=path, fh=fh, utc_open=t, rotation=rot)
        self._slots[segment] = slot
        self._last_segment = segment
        return slot

    def _should_rotate(self, slot: _Slot, t: datetime) -> bool:
        if slot.seq <= 0:
            return False
        try:
            size = slot.path.stat().st_size
        except OSError:
            size = 0
        if size >= self.rotate_max_bytes:
            return True
        age = (_aware(t) - _aware(slot.utc_open)).total_seconds()
        return age >= self.rotate_max_age_s

    def _rotate_slot(self, slot: _Slot, t: datetime) -> Path | None:
        segment = slot.segment
        try:
            slot.fh.close()
        except OSError:
            pass
        self._slots.pop(segment, None)
        kinds = "+".join(sorted(slot.kinds)) or "unknown"
        closed_name = (
            f"hp-{self.mode}-{self.hull}-{segment}-{_iface_token(slot.iface)}"
            f"-{_utc_token(slot.utc_open)}-{_utc_token(t)}"
            f"-n{slot.seq}-b{slot.nbytes}-k{kinds}-r{slot.rotation:04d}.jsonl"
        )
        dest = slot.path.with_name(closed_name)
        try:
            slot.path.rename(dest)
        except OSError:
            return None
        gz = dest.with_suffix(dest.suffix + ".gz")
        try:
            with dest.open("rb") as src, gzip.open(gz, "wb") as out:
                out.write(src.read())
            dest.unlink(missing_ok=True)
        except OSError:
            gz = dest
        digest = ""
        nbytes = 0
        try:
            raw = gz.read_bytes()
            nbytes = len(raw)
            digest = hashlib.sha256(raw).hexdigest()
        except OSError:
            pass
        self.closed.append(gz)
        rec = {
            "path": str(gz),
            "sha256": digest,
            "nbytes": nbytes,
            "purged": False,
            "rotation": slot.rotation,
            "segment": segment,
            "n_records": slot.seq,
            "kinds": sorted(slot.kinds),
        }
        self.manifest.append(rec)
        self._append_manifest(rec)
        self.rotation += 1
        self._rot_index[segment] = slot.rotation + 1
        self._purge(segment)
        return gz

    def _closed_for(self, segment: str) -> list[Path]:
        return [p for p in self.closed if p.parent.name == segment]

    def _purgeable(self, segment: str) -> list[Path]:
        return [p for p in self._closed_for(segment) if str(p) not in self.hold_paths]

    def _segment_bytes(self, segment: str) -> int:
        d = self.root / segment
        if not d.is_dir():
            return 0
        return sum(p.stat().st_size for p in d.iterdir() if p.is_file())

    def _cannot_rotate(self, segment: str) -> bool:
        closed = self._closed_for(segment)
        if len(closed) < self.retain_max_files and self._segment_bytes(segment) < self.retain_max_bytes:
            return False
        return not self._purgeable(segment)

    def _blocked(self, segment: str) -> bool:
        slot = self._slots.get(segment)
        if slot is None:
            return self._cannot_rotate(segment) and len(self._closed_for(segment)) >= self.retain_max_files
        return False

    def _purge(self, segment: str) -> None:
        def over_cap() -> bool:
            return (
                len(self._closed_for(segment)) > self.retain_max_files
                or self._segment_bytes(segment) > self.retain_max_bytes
            )

        now = datetime.now(UTC)
        aged = []
        for path in self._closed_for(segment):
            try:
                age = (now - datetime.fromtimestamp(path.stat().st_mtime, UTC)).total_seconds()
            except OSError:
                continue
            if age > self.retain_max_age_s and str(path) not in self.hold_paths:
                aged.append(path)
        for victim in aged:
            self._unlink_closed(victim, segment)

        while over_cap():
            keepable = self._purgeable(segment)
            if not keepable:
                break
            self._unlink_closed(keepable[0], segment)

    def _unlink_closed(self, victim: Path, segment: str) -> None:
        digest = ""
        nbytes = 0
        try:
            raw = victim.read_bytes()
            nbytes = len(raw)
            digest = hashlib.sha256(raw).hexdigest()
        except OSError:
            pass
        if victim.exists():
            try:
                victim.unlink()
            except OSError:
                return
        if victim in self.closed:
            self.closed.remove(victim)
        rec = {"path": str(victim), "sha256": digest, "nbytes": nbytes, "purged": True, "segment": segment}
        self.manifest.append(rec)
        self._append_manifest(rec)

    def _append_manifest(self, rec: dict) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        path = self.root / "_manifest.jsonl"
        try:
            with path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(rec, separators=(",", ":")) + "\n")
        except OSError:
            pass


Honeypot = HoneypotService
