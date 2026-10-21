"""Native signal policies and process relationships, with no target expressions."""
import subprocess

import lldb


def signal_policy(debugger, signal=None, stop=None, deliver=None, notify=None):
    process = debugger.process
    if not process or not process.IsValid() or process.GetState() != lldb.eStateStopped:
        raise ValueError('Pause the target before editing signal policies')
    signals = process.GetUnixSignals()
    if not signals.IsValid(): raise RuntimeError('Signal policies are unavailable for this process')
    if signal is not None:
        number = signals.GetSignalNumberFromName(str(signal)) if str(signal).startswith('SIG') else int(signal)
        if number in (9, 17, 19) or not signals.GetSignalAsCString(number):
            raise ValueError('This signal is unavailable or reserved for process control')
        changes = [(signals.GetShouldStop, signals.SetShouldStop, stop),
                   (signals.GetShouldSuppress, signals.SetShouldSuppress, None if deliver is None else not deliver),
                   (signals.GetShouldNotify, signals.SetShouldNotify, notify)]
        if any(value is not None and not isinstance(value, bool) for value in (stop, deliver, notify)):
            raise ValueError('Signal policies must be booleans')
        before = [getter(number) for getter, _, _ in changes]
        try:
            for getter, setter, value in changes:
                if value is not None and (not setter(number, value) or getter(number) != value):
                    raise RuntimeError('LLDB refused the signal policy')
        except Exception:
            for (_, setter, _), value in zip(changes, before): setter(number, value)
            raise
        debugger.record_event('POLICY', 'Native signal policy changed', signal=signals.GetSignalAsCString(number),
                              stop=signals.GetShouldStop(number), deliver=not signals.GetShouldSuppress(number), notify=signals.GetShouldNotify(number))
    rows = []
    for index in range(signals.GetNumSignals()):
        number = signals.GetSignalAtIndex(index)
        rows.append({'number': number, 'name': signals.GetSignalAsCString(number), 'stop': signals.GetShouldStop(number),
                     'deliver': not signals.GetShouldSuppress(number), 'notify': signals.GetShouldNotify(number),
                     'editable': number not in (9, 17, 19)})
    return {'signals': rows, 'coverage': 'Native Unix signal delivery preserves OS-provided signal context. Mach exceptions and BRK traps are not converted into POSIX signals by these settings.'}


def related_processes(debugger):
    process = debugger.process
    root = process.GetProcessID() if process and process.IsValid() else 0
    result = subprocess.run(['/bin/ps', '-axo', 'pid=,ppid=,stat=,comm='], capture_output=True, text=True, timeout=5)
    if result.returncode: raise RuntimeError('Cannot read process relationships')
    rows = []
    for line in result.stdout.splitlines():
        fields = line.strip().split(None, 3)
        if len(fields) != 4: continue
        rows.append({'pid': int(fields[0]), 'parent': int(fields[1]), 'state': fields[2], 'path': fields[3]})
    selected = {root}
    for _ in range(64):
        more = {r['pid'] for r in rows if r['parent'] in selected}
        if more <= selected: break
        selected.update(more)
    return {'processes': [r for r in rows if r['pid'] in selected], 'root': root,
            'coverage': 'Live descendants only. Independent child attach can miss execution before attach; this is not atomic fork following.'}
