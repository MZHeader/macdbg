from __future__ import annotations

"""The long-lived daemon process: hosts one AgentSession and serves commands
over a Unix domain socket, one connection per command.

A command that resumes execution (continue/step/.../decide_*) can block for
a while inside AgentSession._pump. To keep 'interrupt' and 'status' usable
while that's happening, the pump loop calls back into `_poll_incoming` after
every listener wait tick, which non-blockingly accepts any *other* pending
connection on the same listening socket and answers interrupt/status/quit
inline, on the same thread -- no locks, no worker threads needed.
"""

import json
import os
import select
import socket
import sys

from .session import AgentSession, _RESUME_COMMANDS


def _send_json(f, obj) -> None:
    f.write(json.dumps(obj) + "\n")
    f.flush()


def _recv_json(f):
    line = f.readline()
    if not line:
        return None
    return json.loads(line)


# A connection accepted but never sent a complete, newline-terminated line
# would otherwise block f.readline() forever -- on the single-threaded
# accept loop that means every other client (including status/interrupt on
# the concurrent-poll path) hangs too. Bound every accepted connection.
_CONN_TIMEOUT = 5.0


class Daemon:
    def __init__(self, session_dir: str, program, program_args, attach_pid) -> None:
        self.session_dir = session_dir
        self.socket_path = os.path.join(session_dir, "ctl.sock")
        self.meta_path = os.path.join(session_dir, "meta.json")
        self.session = AgentSession(program=program, program_args=program_args,
                                     attach_pid=attach_pid)
        self._shutdown = False
        self._srv: socket.socket | None = None

    def run(self) -> int:
        os.makedirs(self.session_dir, exist_ok=True)
        boot = self.session.start()
        if os.path.exists(self.socket_path):
            os.remove(self.socket_path)
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv.bind(self.socket_path)
        srv.listen(64)
        self._srv = srv
        meta = {
            "pid": os.getpid(),
            "socket": self.socket_path,
            "program": self.session.program,
            "attach_pid": self.session.attach_pid,
            "boot": boot,
        }
        with open(self.meta_path, "w") as f:
            json.dump(meta, f)
        try:
            while not self._shutdown:
                r, _, _ = select.select([srv], [], [], 1.0)
                if not r:
                    continue
                conn, _ = srv.accept()
                conn.settimeout(_CONN_TIMEOUT)
                self._handle_conn(conn)
        finally:
            self.session.shutdown()
            for p in (self.socket_path, self.meta_path):
                try:
                    os.remove(p)
                except OSError:
                    pass
        return 0

    def _handle_conn(self, conn: socket.socket) -> None:
        f = conn.makefile("rw")
        try:
            req = _recv_json(f)
            if req is None:
                return
            cmd = req.get("cmd")
            args = req.get("args") or {}
            if cmd == "boot":
                _send_json(f, {"ok": True, "boot": self._last_boot()})
                return
            if cmd == "quit":
                _send_json(f, {"ok": True})
                self._request_shutdown()
                return
            poll_cb = self._poll_incoming if cmd in _RESUME_COMMANDS else None
            resp = self.session.dispatch(cmd, args, poll_cb=poll_cb)
            _send_json(f, resp)
        except Exception as e:
            try:
                _send_json(f, {"ok": False, "error": "server error: {}".format(e)})
            except Exception:
                pass
        finally:
            conn.close()

    def _last_boot(self):
        try:
            with open(self.meta_path) as f:
                return json.load(f).get("boot")
        except (OSError, ValueError):
            return None

    def _request_shutdown(self) -> None:
        self._shutdown = True
        # A quit while a continue/step is blocked inside AgentSession._pump
        # would otherwise sit there until the target happens to stop on its
        # own -- the accept loop can't exit until _handle_conn returns, so
        # `stop` was falling back to a ~5s wait then SIGKILL, which skips the
        # `finally` in run() (no state-save, stale socket/meta left behind).
        # Interrupting wakes the blocked pump so it returns promptly and the
        # normal teardown path runs.
        try:
            self.session.dbg.interrupt()
        except Exception:
            pass

    def _poll_incoming(self) -> None:
        srv = self._srv
        while True:
            r, _, _ = select.select([srv], [], [], 0)
            if not r:
                return
            conn, _ = srv.accept()
            conn.settimeout(_CONN_TIMEOUT)
            f = conn.makefile("rw")
            try:
                try:
                    req = _recv_json(f)
                except Exception:
                    # Malformed/incomplete input from a concurrent client
                    # must not propagate -- this runs inside the pump loop of
                    # a *different*, legitimate in-flight command, and an
                    # uncaught exception here would abort that command with a
                    # bogus "internal error" while leaving the resumed
                    # process running uncontrolled.
                    continue
                if req is None:
                    continue
                cmd = req.get("cmd")
                if cmd == "interrupt":
                    self.session.dbg.interrupt()
                    _send_json(f, {"ok": True})
                elif cmd == "status":
                    _send_json(f, self.session.cmd_status())
                elif cmd == "quit":
                    _send_json(f, {"ok": True, "note": "shutting down after current command finishes"})
                    self._request_shutdown()
                else:
                    _send_json(f, {"ok": False, "error":
                                   "session busy running {!r}; only interrupt/status/quit "
                                   "are answered concurrently".format(cmd)})
            except Exception:
                pass
            finally:
                conn.close()


def main(argv=None) -> int:
    import argparse
    p = argparse.ArgumentParser(prog="macdbg-agent-daemon")
    p.add_argument("--session-dir", required=True)
    p.add_argument("--program", default=None)
    p.add_argument("--attach", type=int, default=None)
    p.add_argument("args", nargs=argparse.REMAINDER)
    ns = p.parse_args(argv)
    prog_args = ns.args
    if prog_args and prog_args[0] == "--":
        prog_args = prog_args[1:]
    d = Daemon(ns.session_dir, ns.program, prog_args, ns.attach)
    return d.run()


if __name__ == "__main__":
    sys.exit(main())
