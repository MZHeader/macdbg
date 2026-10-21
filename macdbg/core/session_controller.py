"""Shared stop interpretation for native GUI and headless sessions."""
import lldb

ANALYSIS_COMMANDS = {'memory_map','memory_monitor','memory_snapshot','memory_compare',
                     'execution_guard','queue_defense','identity_profile','analysis_events','tracer_config','scan_syscalls',
                     'instruction_trace', 'signal_policy', 'related_processes', 'syscall_monitor', 'offline_network'}


def analysis_command(debugger, tracer, command, args):
    """The same analysis commands and validation for both transports."""
    args = {key:value for key,value in args.items() if key != 'timeout'}
    def number(key, default=None):
        value = args.get(key,default)
        if isinstance(value,bool):
            raise ValueError('expected an integer')
        return int(value,0) if isinstance(value,str) else int(value)
    memory = debugger.memory_analysis
    if command == 'offline_network':
        return debugger.offline_network.configure(**args) if args else debugger.offline_network.status()
    if command == 'signal_policy':
        from .session_tools import signal_policy
        return signal_policy(debugger, **args)
    if command == 'related_processes':
        from .session_tools import related_processes
        return related_processes(debugger)
    if command == 'syscall_monitor':
        return debugger.syscall_monitor.configure(**args) if args else debugger.syscall_monitor.status()
    if command == 'instruction_trace':
        recorder = debugger.instruction_trace
        action = args.pop('action', 'status')
        methods = {'status': recorder.status, 'start': recorder.start, 'stop': recorder.stop,
                   'query': recorder.query, 'read': recorder.read, 'open': recorder.open, 'export': recorder.export}
        if action not in methods: raise ValueError('Unknown instruction trace action')
        return methods[action](**args)
    if command == 'scan_syscalls':
        return debugger.scan_live_syscalls(number('addr'),number('size'))
    if command == 'memory_map':
        return {'regions':memory.regions()}
    if command == 'memory_monitor':
        (memory.enable if args.get('enabled',True) else memory.disable)()
        return memory.status()
    if command == 'memory_snapshot':
        return memory.capture(number('addr'),number('size',256),args.get('label','snapshot'))
    if command == 'memory_compare':
        return memory.compare(number('id'))
    if command == 'execution_guard':
        if args.get('enabled',True):
            return {'region':memory.arm_guard(number('addr'))}
        memory.disarm_guard()
        return {}
    if command == 'queue_defense':
        return debugger.entry_plan.queue(args['name'],args.get('enabled',True))
    if command == 'identity_profile':
        return {'profile':debugger.analysis_cloak.configure_identity(args) if args else
                dict(debugger.analysis_cloak.identity_profile)}
    if command == 'analysis_events':
        return debugger.analysis_events.snapshot(number('since',0))
    if command == 'tracer_config':
        if args:
            tracer.configure(**args)
        return tracer.configuration()
    raise ValueError('unknown analysis command')


def prepare_stop(debugger, observed_ns, log):
    """Shared ordering for clock accounting, mutation guards and internal stops."""
    from .breakpoints import consume_hardware_debugger_duplicate, recover_owned_hardware_stop, start_hardware_recovery
    if hasattr(debugger, 'instruction_trace'):
        debugger.instruction_trace.observe_stop()
    debugger.auto_clock.observe_stop(observed_ns)
    recovery = recover_owned_hardware_stop(debugger, log)
    if recovery is not None:
        return recovery
    if consume_hardware_debugger_duplicate(debugger):
        candidate = getattr(debugger, '_retired_step_candidate', None)
        if isinstance(candidate, tuple):
            return start_hardware_recovery(debugger, *candidate, log, 'owned retired hardware return')
        log('[debugger] retried duplicate hardware debugger stop')
        return 'retry'
    memory_action = debugger.memory_analysis.apply_stop()
    if hasattr(debugger, 'offline_network') and debugger.offline_network.apply_stop() is True:
        memory_action = 'internal'
    if hasattr(debugger, 'syscall_monitor') and debugger.syscall_monitor.observe() is True:
        log('[syscalls] incomplete coverage; inspect the syscall monitor before continuing')
        return 'visible'
    if memory_action == 'visible' or debugger.entry_plan.apply_stop() is True:
        return 'visible'
    trap_only = debugger.self_trap.complete() is True
    payload_only = debugger.script_exec.payloads.apply_stop()
    clock_only = debugger.auto_clock.apply_stop()
    messages, timing_only = debugger.timing.apply_stop()
    for message in messages:
        log(message)
    if timing_only or clock_only or payload_only or trap_only or memory_action == 'internal':
        return 'internal'
    return None


def breakpoint_ids(thread):
    return [thread.GetStopReasonDataAtIndex(i) for i in range(0, thread.GetStopReasonDataCount(), 2)]


def handle_defenses(debugger, log):
    """Return handled, blocked, or None; frontend-specific prompts stay outside."""
    process = debugger.process
    if not process or not process.IsValid():
        return None
    thread = process.GetSelectedThread()
    if not thread or not thread.IsValid():
        return None
    trap = debugger.handle_self_trap(thread)
    if trap is not None:
        log('[anti-debug] ' + trap)
        return 'handled'
    if thread.GetStopReason() != lldb.eStopReasonBreakpoint:
        return None
    ids = breakpoint_ids(thread)
    for bid in ids:
        message = debugger.handle_analysis_cloak_hit(bid)
        if message is not None:
            ready, _ = debugger.analysis_cloak.validate_resume()
            if message:
                log('[anti-analysis] ' + message, error=not ready)
            return 'handled' if ready else 'blocked'
    for name in ('anti_ptrace', 'flag_scrub', 'syscall', 'anti_mach', 'direct_syscall',
                 'fork', 'setsid', 'exec'):
        handler = getattr(debugger, 'handle_' + name + '_hit')
        for bid in ids:
            message = handler(bid)
            if message is not None:
                if message:
                    log('[anti-debug] ' + message)
                return 'handled'
    return None


def log_trace_stop(debugger, tracer, emit):
    process = debugger.process
    if not process or not process.IsValid():
        return False
    thread = process.GetSelectedThread()
    if not thread or not thread.IsValid() or thread.GetStopReason() != lldb.eStopReasonBreakpoint:
        return False
    ids = breakpoint_ids(thread)
    matched = any(tracer.is_trace_bp(bid) for bid in ids)
    if not matched:
        return False
    # Retain proof of a passive hardware trace stop that has already been
    # observed. Darwin can next report the same site without its logical ID.
    if len(ids) == 1 and not debugger.in_user_step():
        bp = debugger.target.FindBreakpointByID(ids[0])
        pc = thread.GetFrameAtIndex(0).GetPC()
        code = debugger.read_memory(pc, 4)
        if bp.IsValid() and bp.IsHardware() and len(code) == 4:
            debugger._traced_hardware_stop = (process.GetUniqueID(), process.GetStopID(),
                thread.GetThreadID(), pc, code, ids[0])
    for hit in tracer.return_hits(thread, process):
        emit(hit.category, hit.call, hit.details)
    bid = next((bid for bid in ids if bid in tracer._bp_to_name), None)
    if bid is not None:
        hit = tracer.hit_from(thread.GetFrameAtIndex(0), process, bp_id=bid)
        if hit is not None:
            emit(hit.category, hit.call, hit.details)
    return True

def describe_stop(debugger) -> dict:
    process = debugger.process
    if not process or not process.IsValid():
        return {"text": "[stopped]"}
    thread = process.GetSelectedThread()
    if not thread or not thread.IsValid():
        return {"text": "[stopped]"}
    reason = thread.GetStopReason()
    pc = debugger.pc() or 0
    memory = getattr(debugger, 'memory_analysis', None)
    if memory and memory.guard_stop == (process.GetProcessID(),process.GetStopID(),pc):
        return {'pc':pc, 'thread_id':thread.GetThreadID(), 'reason':'execute-guard',
                'text':'[stop] first execution in guarded region at {:#x}; original permissions restored'.format(pc)}
    frame = thread.GetFrameAtIndex(0)
    sym = ""
    if frame and frame.IsValid():
        sym = frame.GetFunctionName() or (
            frame.GetSymbol().GetName() if frame.GetSymbol().IsValid() else "") or ""
    info = {"pc": pc, "function": sym, "thread_id": thread.GetThreadID(), "reason_code": reason}
    where = " in {}".format(sym) if sym else ""
    if reason == lldb.eStopReasonBreakpoint and thread.GetStopReasonDataCount() >= 1:
        bp_id = thread.GetStopReasonDataAtIndex(0)
        loc_id = thread.GetStopReasonDataAtIndex(1) if thread.GetStopReasonDataCount() >= 2 else 0
        bp = debugger.target.FindBreakpointByID(bp_id) if debugger.target else None
        cond = (bp.GetCondition() if bp and bp.IsValid() else None) or ""
        cond_txt = " (cond: {})".format(cond) if cond and cond.strip() not in ("", "1") else ""
        info.update(reason="breakpoint", bp_id=bp_id, loc_id=loc_id,
                    text="[stop] breakpoint #{}.{} at {:#x}{}{}".format(bp_id, loc_id, pc, where, cond_txt))
        return info
    if reason == lldb.eStopReasonWatchpoint and thread.GetStopReasonDataCount() >= 1:
        wp_id = thread.GetStopReasonDataAtIndex(0)
        info.update(reason="watchpoint", wp_id=wp_id,
                    text="[stop] watchpoint #{} at {:#x}{}".format(wp_id, pc, where))
        return info
    if reason == lldb.eStopReasonPlanComplete:
        info.update(reason="step", text="[stop] step complete at {:#x}{}".format(pc, where))
        return info
    if reason == lldb.eStopReasonException:
        desc = thread.GetStopDescription(256)
        info.update(reason="exception", description=desc,
                    text="[stop] exception at {:#x}{}: {}".format(pc, where, desc))
        return info
    if reason == lldb.eStopReasonSignal and thread.GetStopReasonDataCount() >= 1:
        sig = thread.GetStopReasonDataAtIndex(0)
        info.update(reason="signal", signal=sig,
                    text="[stop] signal {} at {:#x}{}".format(sig, pc, where))
        return info
    if reason == lldb.eStopReasonTrace:
        info.update(reason="trace", text="[stop] trace at {:#x}{}".format(pc, where))
        return info
    info.update(reason="other", text="[stop] at {:#x}{} (reason={})".format(pc, where, reason))
    return info
