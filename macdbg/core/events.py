from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Callable, Optional

import lldb


@dataclass
class StopEvent:
    state: int
    description: str
    process_id: int = 0
    stop_id: int = 0
    observed_ns: int = 0


@dataclass
class OutputEvent:
    text: str
    is_error: bool = False


class EventPump:
    def __init__(
        self,
        listener: lldb.SBListener,
        on_stop: Callable[[StopEvent], None],
        on_output: Callable[[OutputEvent], None],
    ) -> None:
        self.listener = listener
        self.on_stop = on_stop
        self.on_output = on_output
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        self._thread = threading.Thread(target=self._run, name="lldb-events", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread and self._thread is not threading.current_thread():
            self._thread.join(timeout=2)

    def _run(self) -> None:
        event = lldb.SBEvent()
        while not self._stop.is_set():
            if not self.listener.WaitForEvent(1, event):
                continue
            observed_ns = time.monotonic_ns()
            if lldb.SBProcess.EventIsProcessEvent(event):
                etype = event.GetType()
                if etype & lldb.SBProcess.eBroadcastBitStateChanged:
                    state = lldb.SBProcess.GetStateFromEvent(event)
                    if state == lldb.eStateStopped and lldb.SBProcess.GetRestartedFromEvent(event):
                        continue
                    desc = lldb.SBDebugger.StateAsCString(state)
                    proc = lldb.SBProcess.GetProcessFromEvent(event)
                    process_id = (proc.GetProcessID()
                                  if proc and proc.IsValid() else 0)
                    stop_id = (proc.GetStopID()
                               if (proc and proc.IsValid()
                                   and state == lldb.eStateStopped) else 0)
                    self.on_stop(StopEvent(
                        state=state,
                        description=desc,
                        process_id=process_id,
                        stop_id=stop_id,
                        observed_ns=observed_ns,
                    ))
                elif etype & lldb.SBProcess.eBroadcastBitSTDOUT:
                    proc = lldb.SBProcess.GetProcessFromEvent(event)
                    chunk = proc.GetSTDOUT(4096)
                    if chunk:
                        self.on_output(OutputEvent(text=chunk))
                elif etype & lldb.SBProcess.eBroadcastBitSTDERR:
                    proc = lldb.SBProcess.GetProcessFromEvent(event)
                    chunk = proc.GetSTDERR(4096)
                    if chunk:
                        self.on_output(OutputEvent(text=chunk, is_error=True))
