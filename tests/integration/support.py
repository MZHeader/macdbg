import json
import os
from pathlib import Path
import subprocess
import uuid

ROOT = Path(__file__).resolve().parents[2]
AGENT = ROOT / "agent.sh"
FIXTURE_DIR = ROOT / "tests" / "integration" / "build"
FIXTURE = FIXTURE_DIR / "analysis_fixture"
FRIDA_FIXTURE = FIXTURE_DIR / "FridaGadget.dylib"


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
        self.boot = _json_run(
            [AGENT, "start", "--session", self.session, self.fixture,
             self.mode] + self.extra_args,
            env=self.env, timeout=40)
        if not self.boot.get("ok"):
            raise AssertionError("agent start failed: {!r}".format(self.boot))
        return self

    def cmd(self, name, args=None, timeout=20):
        return _json_run(
            [AGENT, "cmd", self.session, name, "--json",
             json.dumps(args or {}), "--timeout", str(timeout)],
            env=self.env, timeout=timeout + 15)

    def enable_cloak(self):
        return self.cmd("defense_enable", {"name": "analysis_cloak"})

    def continue_to_exit(self):
        return self.cmd("continue", {"timeout": 15}, timeout=20)

    def __exit__(self, _exc_type, _exc, _tb):
        subprocess.run([str(AGENT), "stop", self.session], cwd=ROOT,
                       env=self.env, text=True, capture_output=True, timeout=15)
