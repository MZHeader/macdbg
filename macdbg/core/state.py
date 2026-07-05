from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional


STATE_DIR = os.path.expanduser("~/.macdbg")


def _safe_name(name: str) -> str:
    return "".join(
        c if (c.isalnum() or c in "-._") else "_" for c in (name or "")
    ) or "unknown"


def sample_dir(binary_path: str, sha: str) -> str:
    """Per-sample directory, named for readability but suffixed with a slice of
    the sha so two different binaries that share a name never collide."""
    base = _safe_name(os.path.basename(binary_path or ""))
    return os.path.join(STATE_DIR, "{}-{}".format(base, sha[:12]))


@dataclass
class StoredBP:
    addr: int
    symbol: str
    condition: str
    commands: List[str]
    enabled: bool


@dataclass
class Patch:
    addr: int
    orig: bytes
    new: bytes


@dataclass
class Watch:
    slot: int
    addr: int
    length: int = 32
    label: str = ""


@dataclass
class BinaryState:
    sha256: str
    binary_path: str
    comments: Dict[int, str] = field(default_factory=dict)
    bookmarks: Dict[int, str] = field(default_factory=dict)
    breakpoints: List[StoredBP] = field(default_factory=list)
    patches: List[Patch] = field(default_factory=list)
    watches: List[Watch] = field(default_factory=list)

    def dir(self) -> str:
        return sample_dir(self.binary_path, self.sha256)

    def file_path(self) -> str:
        return os.path.join(self.dir(), "state.json")

    def dumps_dir(self) -> str:
        return os.path.join(self.dir(), "dumps")

    def save(self) -> Optional[str]:
        try:
            os.makedirs(self.dir(), exist_ok=True)
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
                "patches": [
                    {"addr": "{:#x}".format(p.addr),
                     "orig": p.orig.hex(),
                     "new": p.new.hex()}
                    for p in self.patches
                ],
                "watches": [
                    {"slot": w.slot,
                     "addr": "{:#x}".format(w.addr),
                     "length": w.length,
                     "label": w.label}
                    for w in self.watches
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


def _migrate_legacy(state: "BinaryState") -> None:
    """Fold the old flat ~/.macdbg/<sha>.json and ~/.macdbg/<name>/dumps into the
    new per-sample directory the first time an old binary is reopened."""
    if os.path.exists(state.file_path()):
        return
    legacy_json = os.path.join(STATE_DIR, "{}.json".format(state.sha256))
    if os.path.exists(legacy_json):
        try:
            os.makedirs(state.dir(), exist_ok=True)
            os.replace(legacy_json, state.file_path())
        except OSError:
            pass
    old_dumps = os.path.join(
        STATE_DIR, _safe_name(os.path.basename(state.binary_path or "")), "dumps")
    new_dumps = state.dumps_dir()
    if (os.path.isdir(old_dumps) and not os.path.exists(new_dumps)
            and os.path.abspath(old_dumps) != os.path.abspath(new_dumps)):
        try:
            os.makedirs(state.dir(), exist_ok=True)
            os.replace(old_dumps, new_dumps)
            try:
                os.rmdir(os.path.dirname(old_dumps))
            except OSError:
                pass
        except OSError:
            pass


def load_for(binary_path: str) -> BinaryState:
    sha = sha256_of(binary_path)
    state = BinaryState(sha256=sha, binary_path=binary_path)
    _migrate_legacy(state)
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
    for p in d.get("patches") or []:
        try:
            state.patches.append(Patch(
                addr=int(p["addr"], 16),
                orig=bytes.fromhex(p.get("orig", "")),
                new=bytes.fromhex(p.get("new", "")),
            ))
        except (KeyError, ValueError):
            continue
    for w in d.get("watches") or []:
        try:
            state.watches.append(Watch(
                slot=int(w["slot"]),
                addr=int(w["addr"], 16),
                length=int(w.get("length", 32)),
                label=str(w.get("label", "")),
            ))
        except (KeyError, ValueError):
            continue
    return state
