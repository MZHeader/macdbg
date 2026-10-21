import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from macdbg.agent.session import AgentSession
from macdbg.core import state
from GUI.server.workspace import Workspace
from .support import FIXTURE_DIR


class PatchWorkflowIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.directory=tempfile.TemporaryDirectory(prefix='md-patch-',dir='/private/tmp')
        self.addCleanup(self.directory.cleanup)
        override=patch.object(state,'STATE_DIR',self.directory.name);override.start();self.addCleanup(override.stop)
        self.session=AgentSession(str(FIXTURE_DIR/'ui_fixture'),[])
        self.addCleanup(self.session.shutdown,False)
        result=self.session.start();self.assertTrue(result['ok'],result)
        self.ws=Workspace(self.session.dbg,self.session._hidden_bp_ids)

    def test_assembly_executes_and_exports_a_separate_runnable_copy(self):
        source=FIXTURE_DIR/'ui_fixture'
        digest=hashlib.sha256(source.read_bytes()).hexdigest()
        preview=self.ws.command('assemble_preview',{'address':'ui_destination','source':'mov w0, #42\nret'})
        self.assertEqual(preview['new'],'40058052c0035fd6')
        self.ws.command('assemble_apply',{'token':preview['token']})
        manifest=self.ws.command('patch_export',{'manifest_only':True})
        output=Path(self.directory.name)/'patched'
        self.ws.command('patch_export',{'path':str(output),'sign':True})
        result=subprocess.run([str(output)],capture_output=True,text=True,timeout=5)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn(' 1 42 ',result.stdout)
        self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(),digest)
        self.ws.command('undo',{})
        self.assertFalse(self.session.dbg.state.patches)
        imported=self.ws.command('patch_import',{'path':manifest['path'],'apply':True})
        self.assertTrue(imported['applied'])
        result=self.session.dispatch('continue',{'timeout':10})
        self.assertEqual(result['exit']['code'],0,result)
        self.assertIn(' 1 42 ',result['console'])

    def test_branch_preview_and_stale_preview_refusal(self):
        target=self.ws.address('ui_destination')
        source=self.ws.address('ui_branch')
        preview=self.ws.command('assemble_preview',{'address':hex(source),'source':'b ui_destination'})
        word=int.from_bytes(bytes.fromhex(preview['new']),'little')
        immediate=word&0x3ffffff
        if immediate&(1<<25): immediate-=1<<26
        self.assertEqual(source+immediate*4,target)
        self.session.dispatch('step_in',{'timeout':10})
        with self.assertRaisesRegex(ValueError,'changed since preview'):
            self.ws.command('assemble_apply',{'token':preview['token']})

    def test_manifest_conflicts_and_runtime_only_memory_fail_before_mutation(self):
        address=self.ws.address('ui_destination')
        original=self.session.dbg.read_memory(address,4)
        preview=self.ws.command('assemble_preview',{'address':'ui_destination','source':'mov w0, #42'})
        self.ws.command('assemble_apply',{'token':preview['token']})
        manifest=self.ws.command('patch_export',{'manifest_only':True})
        self.ws.command('undo',{})
        data=json.loads(Path(manifest['path']).read_text())
        data['patches'][0]['original']='00'*len(bytes.fromhex(data['patches'][0]['original']))
        Path(manifest['path']).write_text(json.dumps(data))
        with self.assertRaisesRegex(ValueError,'Original file bytes'):
            self.ws.command('patch_import',{'path':manifest['path'],'apply':True})
        self.assertEqual(self.session.dbg.read_memory(address,4),original)
        stack=self.session.dbg.sp()
        self.ws.command('edit_memory',{'address':hex(stack),'hex':'01'})
        with self.assertRaisesRegex(ValueError,'outside the main file'):
            self.ws.command('patch_manifest',{})
