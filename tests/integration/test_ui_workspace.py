import tempfile
import unittest
from unittest.mock import patch

from GUI.server.workspace import Workspace
from macdbg.agent.session import AgentSession
from macdbg.core import state
from .support import FIXTURE_DIR


class WorkspaceIntegrationTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix='md-ui-test-',dir='/private/tmp')
        self.addCleanup(directory.cleanup)
        override = patch.object(state,'STATE_DIR',directory.name); override.start(); self.addCleanup(override.stop)
        self.session = AgentSession(str(FIXTURE_DIR/'ui_fixture'),[])
        self.assertTrue(self.session.start()['ok'])
        self.addCleanup(self.session.shutdown,False)
        self.ws = Workspace(self.session.dbg,self.session._hidden_bp_ids)

    def test_instruction_context_and_static_selection_are_distinct(self):
        self.ws.command('breakpoint_save',{'expression':'ui_load','kind':'hardware'})
        self.assertEqual(self.session.dispatch('continue',{'timeout':10})['event'],'stop')
        address = self.session.dbg.pc()
        info = self.ws.command('instruction',{'address':hex(address)})
        self.assertTrue(info['live'])
        self.assertTrue(any('1122334455667788' in line for line in info['lines']),info)
        self.assertFalse(self.ws.command('instruction',{'address':hex(address+4)})['live'])

    def test_editor_preserves_settings_and_hardware_type_and_protects_internal_hooks(self):
        result = self.ws.command('breakpoint_save',{'expression':'ui_marker','kind':'hardware','condition':'$x0 == 0','commands':['register read x0'],'ignore':2})
        bp = result['rows'][0]
        self.assertEqual(bp['kind'],'hardware');self.assertEqual(bp['condition'],'$x0 == 0')
        self.assertEqual(bp['commands'],['register read x0']);self.assertEqual(bp['ignore'],2)
        self.ws.command('breakpoint_save',{**bp,'enabled':False})
        self.assertFalse(self.ws.breakpoints()['rows'][0]['enabled'])
        converted = self.ws.command('breakpoint_save',{**bp,'kind':'software','enabled':True})
        self.assertEqual(converted['rows'][0]['kind'],'software')
        self.session.dispatch('defense_enable',{'name':'anti_ptrace'})
        with self.assertRaises(ValueError):
            self.ws.command('breakpoint_delete',{'id':self.session.dbg.anti_ptrace_bp_id})
        self.ws.command('breakpoints_clear',{})
        self.assertTrue(self.session.dbg.target.FindBreakpointByID(self.session.dbg.anti_ptrace_bp_id).IsValid())

    def test_memory_and_register_undo_do_not_reverse_execution(self):
        self.ws.command('edit_memory',{'address':'ui_buffer','hex':'414243'})
        self.assertEqual(self.ws.command('dump',{'address':'ui_buffer','size':3})['bytes'],[65,66,67])
        self.ws.command('undo',{})
        self.ws.command('edit_register',{'name':'x0','value':'0x1122334455667788'})
        self.ws.command('edit_register',{'name':'w0','value':'5'})
        self.assertEqual(self.session.dbg.frame().FindRegister('x0').GetValueAsUnsigned(),5)
        self.ws.command('undo',{})
        self.assertEqual(self.session.dbg.frame().FindRegister('x0').GetValueAsUnsigned(),0x1122334455667788)
        self.ws.command('undo',{})
        self.assertEqual(bytes(self.ws.command('dump',{'address':'ui_buffer','size':3})['bytes']),b'edi')
        self.assertFalse(self.session.dbg.state.patches)
        original = self.session.dbg.frame().FindRegister('x8').GetValueAsUnsigned()
        self.ws.command('edit_register',{'name':'x8','value':'123'})
        self.ws.command('undo',{})
        self.assertEqual(self.session.dbg.frame().FindRegister('x8').GetValueAsUnsigned(),original)
        self.ws.command('edit_memory',{'address':'ui_buffer','hex':'414243'})
        self.session.dispatch('step_in',{'timeout':10})
        with self.assertRaises(ValueError): self.ws.command('undo',{})

    def test_watchpoint_symbols_references_and_graph(self):
        watches = self.ws.command('watchpoint_save',{'address':'ui_watched','size':8,'access':'write'})['watchpoints']
        self.assertEqual(len(watches),1)
        symbols = self.ws.command('symbols',{'query':'ui_branch'})['rows']
        self.assertTrue(symbols)
        address = symbols[0]['addr']
        graph = self.ws.command('graph',{'address':hex(address)})
        self.assertGreaterEqual(len(graph['blocks']),3)
        self.assertTrue(any(e['kind']=='taken' for e in graph['edges']))
        refs = self.ws.command('references',{'address':hex(address)})
        self.assertTrue(refs['rows'],refs)
        stopped = self.session.dispatch('continue',{'timeout':10})
        self.assertEqual(stopped['stop']['reason'],'watchpoint',stopped)

    def test_indirect_graph_edges_require_an_observed_single_step(self):
        self.ws.command('breakpoint_save',{'expression':'ui_indirect','kind':'hardware'})
        self.assertEqual(self.session.dispatch('continue',{'timeout':10})['event'],'stop')
        source = self.session.dbg.pc()
        before = self.ws.code.graph(source)
        self.assertTrue(any(edge['source']=='unresolved' for edge in before['edges']))
        destination = self.session.dbg.frame().FindRegister('x0').GetValueAsUnsigned()
        self.ws.code.arm_observation()
        self.assertEqual(self.session.dispatch('step_in',{'timeout':10})['event'],'stop')
        self.ws.code.observe_stop()
        graph = self.ws.code.graph(source)
        self.assertTrue(any(e['to']==destination and e['source']=='observed single step' for e in graph['edges']),graph)

    def test_watchpoint_editor_can_change_range_and_access(self):
        watch = self.ws.command('watchpoint_save',{'address':'ui_buffer','size':1,'access':'write'})['watchpoints'][0]
        result = self.ws.command('watchpoint_save',{'id':watch['id'],'address':'ui_watched','size':8,'access':'access'})
        self.assertEqual(len(result['watchpoints']),1)
        self.assertEqual(result['watchpoints'][0]['size'],8)
        self.assertEqual(result['watchpoints'][0]['access'],'access')

    def test_vector_and_float_register_edits_are_verified_and_undoable(self):
        original = self.ws.register_bytes('v0')
        self.ws.command('edit_register',{'name':'v0','value':'{'+' '.join(['0x5a']*16)+'}'})
        self.assertEqual(self.ws.register_bytes('v0'),b'\x5a'*16)
        self.ws.command('undo',{})
        self.assertEqual(self.ws.register_bytes('v0'),original)
        self.ws.command('edit_register',{'name':'s0','value':'1.0'})
        self.assertEqual(self.ws.register_bytes('s0'),b'\x00\x00\x80\x3f')
        self.ws.command('undo',{})
        self.assertEqual(self.ws.register_bytes('v0'),original)

    def test_undo_code_edit_restores_integrity_readiness(self):
        address=self.session.dbg.pc()
        original=self.session.dbg.read_memory(address,4)
        self.ws.command('edit_memory',{'address':hex(address),'hex':'1f2003d5'})
        self.ws.command('undo',{})
        self.assertEqual(self.session.dbg.read_memory(address,4),original)
        self.assertFalse(self.session.dbg.state.patches)
        enabled=self.session.dispatch('defense_enable',{'name':'analysis_cloak'})
        self.assertTrue(enabled['ok'],enabled)
