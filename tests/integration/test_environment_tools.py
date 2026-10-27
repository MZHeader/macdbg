import os
import signal
import socket
import ssl
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from macdbg.agent.session import AgentSession
from macdbg.core import state
from GUI.server.workspace import Workspace
from .support import FIXTURE_DIR


class EnvironmentIntegrationTests(unittest.TestCase):
    def test_native_reachability_override_reports_a_valid_flags_buffer(self):
        session=self.start('reachability')
        result=session.dispatch('offline_network',{'enabled':True,'rules':[],'reachability':True})
        self.assertTrue(result['ok'],result)
        result=session.dispatch('continue',{'timeout':10})
        self.assertEqual(result.get('exit',{}).get('code'),0,result)
        self.assertIn('REACHABLE:1 flags=2',result['console'])

    def test_instruction_recording_crosses_api_trace_hooks(self):
        session=self.start('trace')
        session.tracer.configure(hooks=['read'],hardware=True)
        session.tracer.enable(session.dbg.target,session.dbg.ci)
        address=Workspace(session.dbg,session._hidden_bp_ids).address('environment_marker')
        result=session.dispatch('instruction_trace_run',{'count':5000,'seconds':20,'until':hex(address)})
        self.assertEqual(result['event'],'stop',result)
        self.assertEqual(session.dbg.pc(),address,result)
        rows=session.dbg.instruction_trace.query(limit=500)['rows']
        self.assertTrue(any(row.get('category','').startswith('API/') for row in rows),rows[-3:])

    def start(self, mode):
        directory=tempfile.TemporaryDirectory(prefix='md-environment-',dir='/private/tmp')
        self.addCleanup(directory.cleanup)
        override=patch.object(state,'STATE_DIR',directory.name);override.start();self.addCleanup(override.stop)
        session=AgentSession(str(FIXTURE_DIR/'environment_fixture'),[mode])
        self.addCleanup(session.shutdown,False)
        result=session.start();self.assertTrue(result['ok'],result)
        return session

    def test_real_siginfo_handler_receives_native_context(self):
        session=self.start('signal')
        policy=session.dispatch('signal_policy',{'signal':'SIGUSR1','stop':False,'deliver':True,'notify':False})
        self.assertTrue(policy['ok'],policy)
        result=session.dispatch('continue',{'timeout':10})
        self.assertEqual(result.get('exit',{}).get('code'),0,result)
        self.assertIn('CONTEXT:1',result['console'])

    def test_domain_check_uses_real_loopback_http_response(self):
        session=self.start('network')
        session.dbg.instruction_trace.start()
        config=session.dispatch('offline_network',{'enabled':True,'rules':[{'host':'connectivity.macdbg.invalid','body':'fixture-online'}]})
        self.assertTrue(config['ok'],config)
        result=session.dispatch('continue',{'timeout':15})
        self.assertEqual(result.get('exit',{}).get('code'),0,result)
        self.assertIn('fixture-online',result['console'])
        self.assertFalse(session.dbg.offline_network.servers)
        session.dbg.offline_network.drain()
        rows=session.dbg.instruction_trace.query()['rows']
        self.assertTrue(any(r.get('category')=='NETWORK' for r in rows),rows)
        self.assertTrue(any('DNS name' in r.get('message','') for r in rows),rows)

    def test_https_requires_certificate_and_rolls_back_bad_key(self):
        session = self.start('network')
        rule = {'host': 'connectivity.macdbg.invalid', 'port': 443}
        result = session.dispatch('offline_network', {'rules': [rule]})
        self.assertFalse(result['ok'], result)
        self.assertIn('tls_cert', str(result))
        rule.update(tls_cert='/nonexistent/macdbg.crt', tls_key='/nonexistent/macdbg.key')
        result = session.dispatch('offline_network', {'rules': [rule]})
        self.assertFalse(result['ok'], result)
        self.assertFalse(session.dbg.offline_network.servers)
        self.assertFalse(session.dbg.offline_network.hooks)
        self.assertFalse(session.dbg.offline_network.enabled)

    def test_stalled_tls_client_does_not_block_response_or_shutdown(self):
        from .test_language_network import certificate
        session = self.start('network')
        with tempfile.TemporaryDirectory(prefix='md-tls-', dir='/private/tmp') as directory:
            cert, key, ca = certificate(Path(directory))
            result = session.dispatch('offline_network', {'rules': [{
                'host': 'connectivity.macdbg.invalid', 'port': 443,
                'tls_cert': str(cert), 'tls_key': str(key), 'body': 'fixture-online'}]})
            self.assertTrue(result['ok'], result)
            port = result['rules'][0]['local_port']
            context = ssl.create_default_context(cafile=str(ca))
            with socket.create_connection(('127.0.0.1', port), timeout=2) as stalled:
                with socket.create_connection(('127.0.0.1', port), timeout=2) as raw:
                    with context.wrap_socket(raw, server_hostname='connectivity.macdbg.invalid') as client:
                        client.sendall(b'GET /check HTTP/1.0\r\nHost: connectivity.macdbg.invalid\r\n\r\n')
                        response = b''
                        while True:
                            chunk = client.recv(4096)
                            if not chunk: break
                            response += chunk
                self.assertIn(b'fixture-online', response)
                start = time.monotonic()
                session.dbg.offline_network.disable()
                self.assertLess(time.monotonic() - start, 1)
            self.assertFalse(session.dbg.offline_network.servers)

    def test_changed_executable_mapping_is_scanned_before_manual_continue(self):
        session=self.start('mapping')
        ws=Workspace(session.dbg,session._hidden_bp_ids)
        ws.command('breakpoint_save',{'expression':'environment_marker','kind':'software'})
        result=session.dispatch('syscall_monitor',{'enabled':True})
        self.assertTrue(result['ok'],result)
        stopped=session.dispatch('continue',{'timeout':15})
        self.assertEqual(stopped['event'],'stop',stopped)
        coverage=session.dispatch('syscall_monitor',{})
        self.assertGreaterEqual(coverage['sites'],1,coverage)
        session.dispatch('syscall_monitor',{'enabled':False})
        result=session.dispatch('continue',{'timeout':15})
        self.assertEqual(result.get('exit',{}).get('code'),0,result)

    def test_child_can_be_debugged_independently_while_parent_is_preserved(self):
        session=self.start('child')
        Workspace(session.dbg,session._hidden_bp_ids).command('breakpoint_save',{'expression':'environment_marker','kind':'hardware'})
        self.assertEqual(session.dispatch('continue',{'timeout':10})['event'],'stop')
        family=session.dispatch('related_processes',{})
        child=next(row['pid'] for row in family['processes'] if row['pid']!=family['root'])
        needs_cleanup=[True]
        def cleanup():
            if not needs_cleanup[0]:return
            try: os.kill(child,signal.SIGKILL)
            except ProcessLookupError: pass
        self.addCleanup(cleanup)
        parent_pc=session.dbg.pc()
        attached=AgentSession(attach_pid=child)
        try:
            result=attached.start();self.assertTrue(result['ok'],result)
            self.assertTrue(attached.cmd_registers()['registers'])
            self.assertEqual(session.dbg.pc(),parent_pc)
        finally: attached.shutdown(False)
        result=session.dispatch('continue',{'timeout':10})
        if result.get('event')=='exited':needs_cleanup[0]=False
        self.assertEqual(result.get('exit',{}).get('code'),0,result)
