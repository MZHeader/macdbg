import json
import hashlib
import os
from pathlib import Path
import subprocess
import struct
import uuid

ROOT = Path(__file__).resolve().parents[2]
AGENT = ROOT / "agent.sh"
FIXTURE_DIR = ROOT / "tests" / "integration" / "build"
FIXTURE = FIXTURE_DIR / "analysis_fixture"
STRIPPED_FIXTURE = FIXTURE_DIR / "analysis_fixture_stripped"
LATE_IOKIT_FIXTURE = FIXTURE_DIR / "late_iokit_fixture"
FRIDA_FIXTURE = FIXTURE_DIR / "FridaGadget.dylib"


def fixture_text_digest():
    """Independent on-disk baseline for the thin ARM64 fixture's text."""
    data = FIXTURE.read_bytes()
    magic, = struct.unpack_from("<I", data)
    if magic != 0xfeedfacf:
        raise AssertionError("expected a thin little-endian Mach-O 64 fixture")
    ncmds, = struct.unpack_from("<I", data, 16)
    offset = 32
    for _ in range(ncmds):
        cmd, size = struct.unpack_from("<II", data, offset)
        if cmd == 0x19:
            nsects, = struct.unpack_from("<I", data, offset + 64)
            for index in range(nsects):
                at = offset + 72 + index * 80
                section, segment, _addr, length, fileoff = struct.unpack_from(
                    "<16s16sQQI", data, at)
                if section.rstrip(b"\0") == b"__text" and segment.rstrip(b"\0") == b"__TEXT":
                    return hashlib.sha256(data[fileoff:fileoff + length]).hexdigest()
        offset += size
    raise AssertionError("fixture has no __TEXT,__text section")


def fixture_symbol(name):
    output = subprocess.check_output(["nm", str(FIXTURE)], text=True)
    return next(int(line.split()[0], 16) for line in output.splitlines()
                if line.split()[-1] == "_" + name)


def _json_run(argv, env=None, timeout=30):
    cp = subprocess.run([str(x) for x in argv], cwd=ROOT, env=env,
                        text=True, capture_output=True, timeout=timeout)
    line = cp.stdout.strip().splitlines()[-1] if cp.stdout.strip() else "{}"
    value = json.loads(line)
    value["client_returncode"] = cp.returncode
    value["client_stderr"] = cp.stderr
    return value


def run_fixture_direct(mode, extra_args=None, env=None):
    merged = os.environ.copy()
    merged.update(env or {})
    return subprocess.run(
        [str(FIXTURE), mode] + list(extra_args or []), env=merged,
        text=True, capture_output=True, timeout=15)


class AgentProcess:
    def __init__(self, fixture, mode, extra_args=None, env=None):
        self.fixture = Path(fixture)
        self.mode = mode
        self.extra_args = list(extra_args or [])
        self.env = os.environ.copy()
        self.env.update(env or {})
        self.session = "cloak_{}_{}".format(os.getpid(), uuid.uuid4().hex[:8])
        self.boot = None

    def __enter__(self):
        try:
            self.boot = _json_run(
                [AGENT, "start", "--session", self.session, self.fixture,
                 self.mode] + self.extra_args,
                env=self.env, timeout=40)
            if not self.boot.get("ok"):
                raise AssertionError(
                    "agent start failed: {!r}".format(self.boot))
            # These fixtures are generated test artifacts. Saved user BPs from
            # prior tests must not change the next test's starting conditions.
            self.clear_user_breakpoints()
        except BaseException:
            self._stop()
            raise
        return self

    def cmd(self, name, args=None, timeout=20):
        return _json_run(
            [AGENT, "cmd", self.session, name, "--json",
             json.dumps(args or {}), "--timeout", str(timeout)],
            env=self.env, timeout=timeout + 15)

    def enable_cloak(self):
        return self.cmd("defense_enable", {"name": "analysis_cloak"})

    def clear_user_breakpoints(self):
        for bp in self.cmd("breakpoint_list").get("breakpoints", []):
            result = self.cmd("breakpoint_delete", {"bp_id": bp["id"]})
            if not result["ok"]:
                raise AssertionError(result)

    def continue_to_exit(self):
        return self.cmd("continue", {"timeout": 15}, timeout=20)

    def __exit__(self, _exc_type, _exc, _tb):
        try:
            self.clear_user_breakpoints()
        finally:
            self._stop()

    def _stop(self):
        subprocess.run([str(AGENT), "stop", self.session], cwd=ROOT,
                       env=self.env, text=True, capture_output=True, timeout=15)
