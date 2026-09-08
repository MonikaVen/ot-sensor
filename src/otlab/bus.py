"""In-memory segmented CAN bus for CI. Optional SocketCAN later."""

from __future__ import annotations

from collections import defaultdict, deque

from otlab import CanFrame

SEGMENTS = ("nav", "propulsion", "power", "aux")


class InMemoryCanBus:
    def __init__(self) -> None:
        self._q: dict[str, deque[CanFrame]] = defaultdict(deque)

    def send(self, frame: CanFrame) -> None:
        self._q[frame.segment].append(frame)

    def recv(self, segment: str, max_n: int = 10_000) -> list[CanFrame]:
        out: list[CanFrame] = []
        q = self._q[segment]
        while q and len(out) < max_n:
            out.append(q.popleft())
        return out

    def peek_all(self) -> list[CanFrame]:
        frames: list[CanFrame] = []
        for s in SEGMENTS:
            frames.extend(self._q[s])
        return frames
