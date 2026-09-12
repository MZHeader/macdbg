"""Bounded live trace history backed by a complete per-session JSONL file."""
from collections import deque
from datetime import datetime, timezone
import json
import os
import threading
import uuid


class TraceLog:
    def __init__(self, directory, capacity=2000):
        self.directory = directory
        self.capacity = capacity
        self.lock = threading.Lock()
        self.reset()

    def reset(self):
        with self.lock:
            self.rows = deque(maxlen=self.capacity)
            self.count = 0
            self.epoch = uuid.uuid4().hex
            self.path = None

    def append(self, category, call, **details):
        with self.lock:
            if self.path is None:
                directory = self.directory()
                os.makedirs(directory, exist_ok=True)
                self.path = os.path.join(directory, "trace-{}-{}.jsonl".format(
                    datetime.now().strftime("%Y%m%d-%H%M%S"), self.epoch[:12]))
            row = {**details, "n": self.count + 1, "epoch": self.epoch,
                   "timestamp": datetime.now(timezone.utc).isoformat(),
                   "category": category, "call": call}
            # Close after each complete record: a crash or GUI reload cannot
            # strand the only copy in a Python buffer or browser table.
            with os.fdopen(os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600), "a") as file:
                file.write(json.dumps(row) + "\n")
            self.count += 1
            self.rows.append(row)
            return row

    def snapshot(self, since=0):
        with self.lock:
            return {"hits": [r for r in self.rows if r["n"] > since],
                    "total": self.count, "epoch": self.epoch, "path": self.path,
                    "first_available": self.rows[0]["n"] if self.rows else self.count + 1}
