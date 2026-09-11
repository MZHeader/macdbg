import pathlib
import re
import tempfile
import unittest

from .support import AgentProcess, FIXTURE_DIR


class ScriptExecTests(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory(prefix='macdbg-osa-gate-', dir='/private/tmp')
        self.root = pathlib.Path(self.scratch.name)
        self.env = {'MACDBG_STATE_DIR': str(self.root / 'state'), 'PYTHONDONTWRITEBYTECODE': '1'}

    def tearDown(self):
        self.scratch.cleanup()

    def probe(self, mode, decision, interactive=True):
        marker = self.root / (mode + '-' + decision)
        with AgentProcess(FIXTURE_DIR / 'script_exec_fixture', mode,
                          [str(marker), decision], env=self.env) as agent:
            self.assertTrue(agent.cmd('defense_enable', {'name': 'exec_sandbox'})['ok'])
            self.assertTrue(agent.cmd('exec_mode', {'interactive': interactive})['ok'])
            result = agent.continue_to_exit()
            if interactive:
                self.assertEqual(result.get('event'), 'pending_decision', result)
                self.assertTrue(result['decision']['symbol'].startswith('OSA'), result)
                self.assertFalse(marker.exists())
                self.assertFalse(agent.cmd('continue')['ok'])
                dump = agent.cmd('dump_exec')
                if mode == 'file':
                    self.assertFalse(dump['ok'], dump)
                    self.assertIn('No captured script payload', dump['error'])
                else:
                    self.assertTrue(dump['ok'], dump)
                    expected = pathlib.Path(str(marker) + ('.expected.scpt' if mode in ('load', 'loaded') else '.source.txt')).read_bytes()
                    dumped = pathlib.Path(dump['path'])
                    self.assertEqual(dumped.read_bytes(), expected)
                    self.assertEqual(dump['bytes'], len(expected))
                    self.assertEqual(dumped.stat().st_mode & 0o777, 0o600)
                    self.assertIn('content_path', dump, dump)
                    readable = pathlib.Path(dump['content_path'])
                    self.assertIn('executed', readable.read_text())
                    self.assertIn('return 42', readable.read_text())
                    self.assertEqual(readable.stat().st_mode & 0o777, 0o600)
                    self.assertIn('executed', result['decision']['command'])
                self.assertFalse(marker.exists())
                for _ in range(10):
                    if result.get('event') != 'pending_decision': break
                    result = agent.cmd('decide_exec', {'decision': decision, 'timeout': 20})
            self.assertEqual(result.get('event'), 'exited', result)
            self.assertEqual(result['exit']['code'], 0, result)
            self.assertIn('OSA-GATE:clean', result['console'])
            self.assertEqual(marker.exists(), decision == 'allow')

    def test_execute_allow_block_and_fake(self):
        for decision in ('block', 'fake', 'allow'):
            with self.subTest(decision=decision): self.probe('execute', decision)

    def test_combined_execution_apis_block_before_side_effects(self):
        for mode in ('compile', 'load', 'do', 'event', 'doevent', 'file'):
            with self.subTest(mode=mode): self.probe(mode, 'block')

    def test_descriptor_fake_returns_empty_descriptor_without_overflow(self):
        for mode in ('do', 'doevent', 'file'):
            with self.subTest(mode=mode): self.probe(mode, 'fake')

    def test_noninteractive_mode_blocks_execution(self):
        self.probe('execute', 'block', interactive=False)

    def test_loaded_compiled_bytes_survive_descriptor_disposal(self):
        self.probe('loaded', 'block')

    def test_descriptor_replacement_duplication_and_multiple_scripts(self):
        for mode in ('replace', 'duplicate', 'multiple'):
            with self.subTest(mode=mode): self.probe(mode, 'block')

    def test_late_enable_does_not_substitute_metadata_for_payload(self):
        marker = self.root / 'late-enable'
        with AgentProcess(FIXTURE_DIR / 'script_exec_fixture', 'execute',
                          [str(marker), 'block'], env=self.env) as agent:
            text = agent.cmd('raw', {'command': 'disassemble -n run_execute'})['output']
            address = int(re.search(r'^\s*(0x[0-9a-f]+)', text, re.M)[1], 16)
            bp = agent.cmd('breakpoint_toggle', {'addr': address})
            self.assertEqual(agent.continue_to_exit().get('event'), 'stop')
            agent.cmd('defense_enable', {'name': 'exec_sandbox'})
            agent.cmd('exec_mode', {'interactive': True})
            agent.cmd('breakpoint_delete', {'bp_id': bp['bp_id']})
            self.assertEqual(agent.continue_to_exit().get('event'), 'pending_decision')
            result = agent.cmd('dump_exec')
            self.assertFalse(result['ok'], result)
            self.assertNotIn('path', result)
            self.assertIn('No captured script payload', result['error'])
            self.assertFalse(marker.exists())
            result = agent.cmd('decide_exec', {'decision': 'block', 'timeout': 20})
            self.assertEqual(result.get('event'), 'exited', result)
            self.assertEqual(result['exit']['code'], 0, result)

    def test_restart_discards_pending_context_and_rearms_gate(self):
        marker = self.root / 'restart'
        self.env['MACDBG_TEST_EARLY_DESC'] = '1'
        with AgentProcess(FIXTURE_DIR / 'script_exec_fixture', 'execute',
                          [str(marker), 'block'], env=self.env) as agent:
            agent.cmd('defense_enable', {'name': 'exec_sandbox'})
            agent.cmd('exec_mode', {'interactive': True})
            self.assertEqual(agent.continue_to_exit().get('event'), 'pending_decision')
            restarted = agent.cmd('restart')
            self.assertTrue(restarted['ok'], restarted)
            self.assertIsNone(agent.cmd('status')['pending_decision'])
            self.assertEqual(agent.continue_to_exit().get('event'), 'pending_decision')
            result = agent.cmd('decide_exec', {'decision': 'block', 'timeout': 20})
            self.assertEqual(result.get('event'), 'exited', result)
            self.assertEqual(result['exit']['code'], 0, result)
            self.assertFalse(marker.exists())

    def test_disabling_gate_restores_execution(self):
        marker = self.root / 'disabled'
        with AgentProcess(FIXTURE_DIR / 'script_exec_fixture', 'execute',
                          [str(marker), 'allow'], env=self.env) as agent:
            agent.cmd('defense_enable', {'name': 'exec_sandbox'})
            agent.cmd('defense_disable', {'name': 'exec_sandbox'})
            result = agent.continue_to_exit()
            self.assertEqual(result.get('event'), 'exited', result)
            self.assertEqual(result['exit']['code'], 0, result)
            self.assertTrue(marker.exists())

    def test_deferred_hooks_intercept_late_framework_loading(self):
        with AgentProcess(FIXTURE_DIR / 'script_exec_late_fixture', 'late', env=self.env) as agent:
            agent.cmd('defense_enable', {'name': 'exec_sandbox'})
            agent.cmd('exec_mode', {'interactive': True})
            pending = agent.continue_to_exit()
            self.assertEqual(pending.get('event'), 'pending_decision', pending)
            self.assertEqual(pending['decision']['symbol'], 'OSAExecute')
            result = agent.cmd('decide_exec', {'decision': 'block', 'timeout': 20})
            self.assertEqual(result.get('event'), 'exited', result)
            self.assertEqual(result['exit']['code'], 0, result)

    def test_step_over_cannot_cross_execution_gate(self):
        marker = self.root / 'step'
        with AgentProcess(FIXTURE_DIR / 'script_exec_fixture', 'execute',
                          [str(marker), 'block'], env=self.env) as agent:
            self.assertTrue(agent.enable_cloak()['ok'])
            self.assertTrue(agent.cmd('defense_enable', {'name': 'exec_sandbox'})['ok'])
            agent.cmd('exec_mode', {'interactive': True})
            text = agent.cmd('raw', {'command': 'disassemble -n run_execute'})['output']
            site = int(re.search(r'^\s*(0x[0-9a-f]+).*\bbl\s+.*OSAExecute', text, re.M)[1], 16)
            bp = agent.cmd('breakpoint_toggle', {'addr': site})
            self.assertEqual(agent.continue_to_exit().get('event'), 'stop')
            agent.cmd('breakpoint_delete', {'bp_id': bp['bp_id']})
            pending = agent.cmd('step_over', {'timeout': 20})
            self.assertEqual(pending.get('event'), 'pending_decision', pending)
            self.assertFalse(marker.exists())
            result = agent.cmd('decide_exec', {'decision': 'block', 'timeout': 20})
            self.assertEqual(result.get('event'), 'exited', result)
            self.assertEqual(result['exit']['code'], 0, result)
