from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional


STATE_DIR = os.path.expanduser("~/.macdbg")


@dataclass
class StoredBP:
    addr: int
    symbol: str
    condition: str
    commands: List[str]
    enabled: bool


@dataclass
class BinaryState:
    sha256: str
    binary_path: str
    comments: Dict[int, str] = field(default_factory=dict)
    bookmarks: Dict[int, str] = field(default_factory=dict)
    breakpoints: List[StoredBP] = field(default_factory=list)

    def file_path(self) -> str:
        return os.path.join(STATE_DIR, "{}.json".format(self.sha256))

    def save(self) -> Optional[str]:
        try:
            os.makedirs(STATE_DIR, exist_ok=True)
            payload = {
                "sha256": self.sha256,
                "binary_path": self.binary_path,
                "comments": {"{:#x}".format(k): v for k, v in self.comments.items()},
                "bookmarks": {"{:#x}".format(k): v for k, v in self.bookmarks.items()},
                "breakpoints": [
                    {
                        "addr": "{:#x}".format(bp.addr),
                        "symbol": bp.symbol,
                        "condition": bp.condition,
                        "commands": list(bp.commands),
                        "enabled": bp.enabled,
                    }
                    for bp in self.breakpoints
                ],
            }
            tmp = self.file_path() + ".tmp"
            with open(tmp, "w") as f:
                json.dump(payload, f, indent=2)
            os.replace(tmp, self.file_path())
            return self.file_path()
        except OSError as e:
            return None if e else self.file_path()


def sha256_of(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def load_for(binary_path: str) -> BinaryState:
    sha = sha256_of(binary_path)
    state = BinaryState(sha256=sha, binary_path=binary_path)
    path = state.file_path()
    if not os.path.exists(path):
        return state
    try:
        with open(path) as f:
            d = json.load(f)
    except (OSError, json.JSONDecodeError):
        return state
    for k, v in (d.get("comments") or {}).items():
        try:
            state.comments[int(k, 16)] = v
        except ValueError:
            continue
    for k, v in (d.get("bookmarks") or {}).items():
        try:
            state.bookmarks[int(k, 16)] = v
        except ValueError:
            continue
    for bp in d.get("breakpoints") or []:
        try:
            state.breakpoints.append(StoredBP(
                addr=int(bp["addr"], 16),
                symbol=bp.get("symbol", ""),
                condition=bp.get("condition", "") or "",
                commands=list(bp.get("commands") or []),
                enabled=bool(bp.get("enabled", True)),
            ))
        except (KeyError, ValueError):
            continue
    return state
