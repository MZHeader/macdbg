import tempfile
import unittest

from .support import AgentProcess, FIXTURE_DIR


class SelfTrapTests(unittest.TestCase):
    def probe(self, mode):
        with tempfile.TemporaryDirectory(prefix='macdbg-trap-', dir='/private/tmp') as state:
            with AgentProcess(FIXTURE_DIR / 'self_trap_fixture', mode,
                              env={'MACDBG_STATE_DIR': state}) as agent:
                self.assertTrue(agent.cmd('defense_enable', {'name': 'anti_sigtrap'})['ok'])
                result = agent.continue_to_exit()
                if mode == 'handler':
                    self.assertEqual(result.get('event'), 'exited', result)
                    self.assertEqual(result['exit']['code'], 0, result)
                    self.assertIn('TRAP:handler=1', result['console'])
                else:
                    self.assertEqual(result.get('event'), 'stop', result)
                    self.assertEqual(result['stop']['reason'], 'exception', result)
                    self.assertNotIn('skipped', result['console'])
                    self.assertNotIn('TRAP:handler=', result['console'])

    def test_registered_target_handler_is_forwarded(self):
        self.probe('handler')

    def test_unhandled_target_trap_is_preserved(self):
        self.probe('unhandled')

    def test_system_lock_assertion_is_preserved(self):
        self.probe('system')
