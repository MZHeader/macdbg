from __future__ import annotations

"""CLI front-end for the headless macdbg agent.

Run via ./agent.sh (sets PYTHONPATH the same way macdbg.sh does), e.g.:

    ./agent.sh start ./test/denyatt
    ./agent.sh cmd s1234 breakpoint_toggle --json '{"addr": 4295000000}'
    ./agent.sh cmd s1234 continue
    ./agent.sh status s1234
    ./agent.sh stop s1234
"""

import argparse
import json
import os
import signal
import subprocess
import sys
import time
from typing import Optional

SESSIONS_ROOT = os.path.expanduser("~/.macdbg/agent-sessions")

# AF_UNIX sockaddr paths are limited to ~104 bytes on macOS; a session name
# long enough to blow that budget makes the daemon die at bind() with an
# opaque "exited during startup" error. Keep well under it.
_MAX_SESSION_NAME_LEN = 40


def _session_name_error(name: str) -> Optional[str]:
    """None if `name` is safe to use as a literal path component under
    SESSIONS_ROOT; otherwise a human-readable reason it was rejected."""
    if not name:
        return "session name must not be empty"
    if name in (".", ".."):
        return "session name must not be '.' or '..'"
    # A name containing a path separator (or that os.path.join would resolve
    # outside SESSIONS_ROOT via '..' components, or an absolute path that
    # discards the root entirely) lets the caller create/overwrite files
    # anywhere they can write -- e.g. --session /Users/x/.ssh.
    if os.path.basename(name) != name:
        return "session name must not contain path separators ({!r})".format(name)
    if len(name) > _MAX_SESSION_NAME_LEN:
        return "session name too long (max {} chars) -- the control socket " \
               "path has a fixed OS limit".format(_MAX_SESSION_NAME_LEN)
    return None


def _session_dir(name: str) -> str:
    return os.path.join(SESSIONS_ROOT, name)


def _read_meta(name: str) -> Optional[dict]:
    path = os.path.join(_session_dir(name), "meta.json")
    try:
        with open(path) as f:
            meta = json.load(f)
    except (OSError, ValueError):
        # ValueError covers json.JSONDecodeError -- a corrupted/truncated
        # meta.json (e.g. a daemon killed mid-write) must read as "no usable
        # session", not crash every command that touches it.
        return None
    if not isinstance(meta, dict) or "pid" not in meta or "socket" not in meta:
        return None
    return meta


def _cleanup_session_files(sdir: str) -> None:
    for fn in ("meta.json", "ctl.sock"):
        try:
            os.remove(os.path.join(sdir, fn))
        except OSError:
            pass


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def cmd_start(ns) -> int:
    if ns.attach is not None and ns.program:
        print(json.dumps({"ok": False, "error":
                           "give either a program path or --attach <pid>, not both "
                           "(--attach {} would win and {!r} would be silently ignored)".format(
                               ns.attach, ns.program)}))
        return 1
    # Millisecond timestamp + pid: two `start` calls (even auto-named,
    # even from concurrent processes) essentially cannot collide, unlike the
    # old whole-second default which made rapid successive starts fail with
    # a spurious "already running" against a pid the caller never chose.
    name = ns.session or "s{}_{}".format(int(time.time() * 1000), os.getpid())
    name_err = _session_name_error(name)
    if name_err:
        print(json.dumps({"ok": False, "error": name_err}))
        return 1
    sdir = _session_dir(name)
    if os.path.exists(os.path.join(sdir, "meta.json")):
        meta = _read_meta(name)
        if meta and _pid_alive(meta["pid"]):
            print(json.dumps({"ok": False, "error": "session {!r} already running (pid {})".format(
                name, meta["pid"])}))
            return 1
    os.makedirs(sdir, exist_ok=True)

    # Narrow (not eliminate) the race where two `start`s for the same new
    # session name run concurrently: the meta.json-exists check above and
    # the daemon actually writing meta.json are far apart in time, so both
    # racers can pass the check and each spawn a daemon, with `stop` later
    # only able to reap whichever one's pid meta.json happened to end up
    # recording -- the rest leak. A lock file claimed with O_EXCL closes
    # most of that window.
    lock_path = os.path.join(sdir, ".start.lock")
    try:
        lock_fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    except FileExistsError:
        meta = _read_meta(name)
        if meta and _pid_alive(meta["pid"]):
            print(json.dumps({"ok": False, "error": "session {!r} already running (pid {})".format(
                name, meta["pid"])}))
            return 1
        print(json.dumps({"ok": False, "error":
                           "another 'start' for session {!r} appears to be in progress "
                           "(stale lock -- retry, or remove {} if you're sure it isn't)".format(
                               name, lock_path)}))
        return 1
    os.write(lock_fd, str(os.getpid()).encode())
    os.close(lock_fd)
    try:
        return _cmd_start_locked(ns, name, sdir)
    finally:
        try:
            os.remove(lock_path)
        except OSError:
            pass


def _cmd_start_locked(ns, name: str, sdir: str) -> int:
    log_path = os.path.join(sdir, "daemon.log")

    here = os.path.dirname(os.path.abspath(__file__))
    repo_root = os.path.dirname(os.path.dirname(here))
    argv = [sys.executable, "-m", "macdbg.agent.server", "--session-dir", sdir]
    if ns.attach is not None:
        argv += ["--attach", str(ns.attach)]
    elif ns.program:
        argv += ["--program", ns.program, "--"] + ns.args
    log = open(log_path, "ab")
    proc = subprocess.Popen(argv, stdout=log, stderr=log, cwd=repo_root,
                             start_new_session=True)
    meta_path = os.path.join(sdir, "meta.json")
    deadline = time.time() + ns.boot_timeout
    while time.time() < deadline:
        if os.path.exists(meta_path):
            break
        if proc.poll() is not None:
            print(json.dumps({"ok": False, "error":
                               "daemon exited during startup (see {})".format(log_path)}))
            return 1
        time.sleep(0.1)
    else:
        print(json.dumps({"ok": False, "error": "daemon did not start within {}s".format(ns.boot_timeout)}))
        return 1

    from .client import send_command, ClientError
    meta = _read_meta(name)
    if meta is None:
        print(json.dumps({"ok": False, "error": "daemon wrote an unreadable meta.json"}))
        return 1
    resp = send_command(meta["socket"], "boot")
    boot = resp.get("boot") or {}
    boot_ok = bool(boot.get("ok", True))
    if not boot_ok:
        # A session whose target never loaded (bad path, bad pid, ...) is
        # useless -- don't leave its daemon running forever waiting for a
        # caller to remember to `stop` it.
        try:
            send_command(meta["socket"], "quit", recv_timeout=2)
        except ClientError:
            pass
    print(json.dumps({"ok": boot_ok, "session": name, "session_dir": sdir,
                       "pid": meta["pid"], "boot": boot}))
    return 0 if boot_ok else 1


def cmd_cmd(ns) -> int:
    name_err = _session_name_error(ns.session)
    if name_err:
        print(json.dumps({"ok": False, "error": name_err}))
        return 1
    meta = _read_meta(ns.session)
    if not meta:
        print(json.dumps({"ok": False, "error": "unknown session {!r}".format(ns.session)}))
        return 1
    try:
        args = json.loads(ns.json) if ns.json else {}
    except ValueError as e:
        print(json.dumps({"ok": False, "error": "invalid --json: {}".format(e)}))
        return 1
    if not isinstance(args, dict):
        print(json.dumps({"ok": False, "error": "--json must be a JSON object, got {}".format(
            type(args).__name__)}))
        return 1
    if ns.timeout is not None and ns.timeout < 0:
        # socket.settimeout() raises ValueError on a negative value, and
        # there's no "-1 means infinite" convention documented anywhere for
        # this CLI -- reject it here with a clean error instead of letting
        # an uncaught ValueError traceback out of send_command below.
        print(json.dumps({"ok": False, "error": "--timeout must not be negative, got {}".format(ns.timeout)}))
        return 1
    if ns.timeout is not None:
        args.setdefault("timeout", ns.timeout)
    from .client import send_command, ClientError, _RESUME_COMMANDS
    if ns.command in _RESUME_COMMANDS:
        # A resume command with no --timeout is a deliberate "block until
        # the target actually stops" request -- don't second-guess it. One
        # WITH --timeout should get some grace over the daemon's own
        # deadline so a slow-but-alive daemon isn't cut off right as it's
        # about to answer.
        recv_timeout = ns.timeout + 10 if ns.timeout is not None else None
    else:
        # Every non-resume command normally answers in well under a second
        # -- EXCEPT a few (memory_search with scope="all", scan_live_strings
        # on a large process) that can legitimately run tens of seconds.
        # Without any bound, a daemon that's alive but wedged on something
        # else (verified: SIGSTOP) hangs `status`/`interrupt`/etc. forever;
        # with too tight a fixed bound, a *healthy* daemon still computing a
        # slow-but-correct answer gets a spurious client-side timeout
        # instead (measured: a cold scope="all" scan can take ~35s). Let an
        # explicit --timeout raise the bound for exactly those commands;
        # otherwise fall back to a default generous enough to cover the
        # slow-but-healthy case on this host.
        # socket.settimeout(0.0) means non-blocking (not "give up almost
        # immediately"), so an exact 0 would put the very first recv into
        # non-blocking mode and spuriously fail against a perfectly healthy
        # daemon that just hasn't answered yet -- floor it just above zero.
        recv_timeout = max(ns.timeout, 0.01) if ns.timeout is not None else 60
    try:
        resp = send_command(meta["socket"], ns.command, args, recv_timeout=recv_timeout)
    except ClientError as e:
        print(json.dumps({"ok": False, "error": str(e)}))
        return 1
    print(json.dumps(resp))
    return 0 if resp.get("ok", True) else 1


def cmd_status(ns) -> int:
    ns.command, ns.json, ns.timeout = "status", None, None
    return cmd_cmd(ns)


def cmd_interrupt(ns) -> int:
    ns.command, ns.json, ns.timeout = "interrupt", None, None
    return cmd_cmd(ns)


def cmd_stop(ns) -> int:
    name_err = _session_name_error(ns.session)
    if name_err:
        print(json.dumps({"ok": False, "error": name_err}))
        return 1
    sdir = _session_dir(ns.session)
    meta = _read_meta(ns.session)
    if not meta:
        # Nothing usable to talk to (never existed, or meta.json is
        # corrupt/incomplete) -- still sweep any stale files rather than
        # leaving them for `list` to report forever.
        _cleanup_session_files(sdir)
        print(json.dumps({"ok": True, "note": "no such session (already gone)"}))
        return 0
    if _pid_alive(meta["pid"]):
        from .client import send_command, ClientError
        try:
            send_command(meta["socket"], "quit", recv_timeout=2)
        except ClientError:
            pass
        deadline = time.time() + 5
        while time.time() < deadline and _pid_alive(meta["pid"]):
            time.sleep(0.1)
        if _pid_alive(meta["pid"]):
            os.kill(meta["pid"], signal.SIGKILL)
    # Whether the pid was alive (and just reaped) or already dead (a crashed
    # daemon), don't leave stale meta.json/ctl.sock behind -- otherwise a
    # dead session lingers in `list` forever and this "successful" stop
    # didn't actually clean anything up.
    _cleanup_session_files(sdir)
    print(json.dumps({"ok": True, "session": ns.session}))
    return 0


def cmd_list(ns) -> int:
    out = []
    if os.path.isdir(SESSIONS_ROOT):
        for name in sorted(os.listdir(SESSIONS_ROOT)):
            meta = _read_meta(name)
            if not meta:
                continue
            out.append({"session": name, "pid": meta["pid"],
                        "alive": _pid_alive(meta["pid"]),
                        "program": meta.get("program"), "attach_pid": meta.get("attach_pid")})
    print(json.dumps(out))
    return 0


def cmd_logs(ns) -> int:
    name_err = _session_name_error(ns.session)
    if name_err:
        print(json.dumps({"ok": False, "error": name_err}))
        return 1
    path = os.path.join(_session_dir(ns.session), "daemon.log")
    try:
        with open(path) as f:
            lines = f.readlines()
    except OSError as e:
        print(json.dumps({"ok": False, "error": str(e)}))
        return 1
    n = max(0, ns.lines)
    sys.stdout.write("".join(lines[-n:] if n else []))
    return 0


def main() -> int:
    p = argparse.ArgumentParser(prog="macdbg-agent")
    sub = p.add_subparsers(dest="action", required=True)

    sp = sub.add_parser("start", help="launch/attach a target and start a session daemon")
    sp.add_argument("program", nargs="?")
    sp.add_argument("args", nargs=argparse.REMAINDER)
    sp.add_argument("--attach", type=int, default=None)
    sp.add_argument("--session", default=None, help="session name (default: auto-generated)")
    sp.add_argument("--boot-timeout", type=float, default=30.0)
    sp.set_defaults(func=cmd_start)

    sp = sub.add_parser("cmd", help="send one command to a running session")
    sp.add_argument("session")
    sp.add_argument("command")
    sp.add_argument("--json", default=None, help="JSON object of command arguments")
    sp.add_argument("--timeout", type=float, default=None,
                    help="for resume commands: max seconds to wait for the next stop. "
                         "For any other command: max seconds the CLIENT waits for a "
                         "response (default 60s) -- this only bounds our own wait, it "
                         "does not tell the daemon to abort a slow-but-legitimate scan")
    sp.set_defaults(func=cmd_cmd)

    sp = sub.add_parser("status", help="shorthand for `cmd <session> status`")
    sp.add_argument("session")
    sp.set_defaults(func=cmd_status)

    sp = sub.add_parser("interrupt", help="shorthand for `cmd <session> interrupt`")
    sp.add_argument("session")
    sp.set_defaults(func=cmd_interrupt)

    sp = sub.add_parser("stop", help="shut down a session (saves state, kills/detaches target)")
    sp.add_argument("session")
    sp.set_defaults(func=cmd_stop)

    sp = sub.add_parser("list", help="list known sessions")
    sp.set_defaults(func=cmd_list)

    sp = sub.add_parser("logs", help="show the daemon's stderr/stdout log for a session")
    sp.add_argument("session")
    sp.add_argument("-n", "--lines", type=int, default=100)
    sp.set_defaults(func=cmd_logs)

    ns = p.parse_args()
    return ns.func(ns)


if __name__ == "__main__":
    sys.exit(main())
