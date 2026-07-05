from __future__ import annotations

import json
import socket
from typing import Optional

# Lives here (not session.py) specifically so the CLI client -- which needs
# this classification purely to pick a socket recv_timeout -- never has to
# import session.py and, transitively, `lldb`. session.py re-exports this
# same set rather than defining its own, so there's one source of truth.
_RESUME_COMMANDS = {
    "continue", "step_in", "step_over", "step_out", "step_in_source",
    "step_over_source", "wait", "decide_fork", "decide_exec",
}


class ClientError(Exception):
    pass


def send_command(socket_path: str, cmd: str, args: Optional[dict] = None,
                  recv_timeout: Optional[float] = None) -> dict:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(recv_timeout)
    try:
        try:
            s.connect(socket_path)
        except OSError as e:
            raise ClientError("could not connect to {}: {}".format(socket_path, e)) from e
        f = s.makefile("rw")
        try:
            f.write(json.dumps({"cmd": cmd, "args": args or {}}) + "\n")
            f.flush()
            line = f.readline()
        except OSError as e:
            # Covers socket.timeout/TimeoutError too (both are OSError
            # subclasses) -- a daemon that's alive but wedged on something
            # else and never reads/answers this request must fail the same
            # clean way as a dead socket, not raise an uncaught exception
            # that skips the caller's SIGKILL-and-cleanup fallback (this bit
            # cmd_stop specifically: it only caught ClientError).
            raise ClientError("connection to {} timed out or failed: {}".format(socket_path, e)) from e
        if not line:
            raise ClientError("daemon closed the connection without a response")
        try:
            return json.loads(line)
        except ValueError as e:
            raise ClientError("daemon returned invalid JSON: {}".format(e)) from e
    finally:
        s.close()
