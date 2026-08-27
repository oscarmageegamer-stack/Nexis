from __future__ import annotations

from dataclasses import dataclass, field
from queue import PriorityQueue
from time import monotonic
import itertools

_counter = itertools.count()


@dataclass(order=True)
class QueueItem:
    priority: int
    sequence: int = field(compare=True)
    job_id: str = field(compare=False)
    name: str = field(compare=False)
    submitted_at: float = field(compare=False, default_factory=monotonic)


class JobQueue:
    """Bounded priority queue for cooperative Nexis workers."""

    def __init__(self, maxsize: int = 256) -> None:
        self.maxsize = max(1, min(int(maxsize), 4096))
        self._queue: PriorityQueue[QueueItem] = PriorityQueue(maxsize=self.maxsize)

    def put(self, job_id: str, name: str, priority: int = 50, block: bool = False) -> bool:
        item = QueueItem(max(0, min(int(priority), 100)), next(_counter), job_id, name)
        try:
            self._queue.put(item, block=block)
            return True
        except Exception:
            return False

    def get(self, timeout: float | None = None) -> QueueItem:
        return self._queue.get(timeout=timeout)

    def task_done(self) -> None:
        self._queue.task_done()

    def qsize(self) -> int:
        return self._queue.qsize()
