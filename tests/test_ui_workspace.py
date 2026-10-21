import tempfile
import unittest

from GUI.server.workspace import Preferences
from macdbg.core.code_navigation import blocks_for, CodeNavigation
from unittest import mock


class WorkspaceUnitTests(unittest.TestCase):
    def test_reference_paging_keeps_an_adrp_pair_crossing_the_boundary(self):
        navigation = CodeNavigation(mock.Mock())
        section = mock.Mock()
        section.GetLoadAddress.return_value=0x1000;section.GetByteSize.return_value=65548
        navigation.module=lambda _name:mock.Mock(FindSection=lambda _:mock.Mock(FindSubSection=lambda _:section))
        navigation.instructions=mock.Mock(return_value=[
            {'addr':0x10ffc,'mn':'adrp','ops':'x8, 2'},
            {'addr':0x11000,'mn':'add','ops':'x0, x8, #0x30'}])
        result=navigation.references(0x12030,offset=65536)
        self.assertEqual(result['rows'][0]['addr'],0x11000)
        self.assertEqual(navigation.instructions.call_args.args[0],0x10ffc)

    def test_preferences_and_launches_survive_a_new_server_instance(self):
        with tempfile.TemporaryDirectory(prefix='md-ui-prefs-',dir='/private/tmp') as directory:
            first = Preferences(directory)
            first.update({'font_size':16,'left_percent':70,'shortcuts':{'run_to':'F4'}})
            first.remember({'path':'/tmp/benign fixture','args_text':'"two words"','name':'Local fixture'},preset=True)
            second = Preferences(directory)
            self.assertEqual(second.data['settings']['font_size'],16)
            self.assertEqual(second.data['settings']['shortcuts']['run_to'],'F4')
            self.assertEqual(second.data['launches'][0]['args_text'],'"two words"')
            with self.assertRaises(ValueError): second.update({'font_size':1000})
            self.assertEqual(second.data['settings']['font_size'],16)

    def test_graph_keeps_conditional_edges_and_labels_unknown_indirect_targets(self):
        rows = [{'addr':0x1000,'mn':'cbz','ops':'x0, 0x100c'},
                {'addr':0x1004,'mn':'br','ops':'x1'},
                {'addr':0x1008,'mn':'ret','ops':''},
                {'addr':0x100c,'mn':'ret','ops':''}]
        blocks,edges = blocks_for(rows)
        self.assertEqual(len(blocks),4)
        self.assertTrue(any(e['to']==0x100c and e['kind']=='taken' for e in edges))
        self.assertTrue(any(e['to']==0x1004 and e['kind']=='fallthrough' for e in edges))
        self.assertTrue(any(e['source']=='unresolved' and e['to'] is None for e in edges))
        _,edges = blocks_for(rows,{(0x1004,0x2000)})
        self.assertTrue(any(e['source']=='observed single step' and e['to']==0x2000 for e in edges))
