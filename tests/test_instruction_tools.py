import unittest

from macdbg.core.arm64_operands import memory_access
from macdbg.core.assembly import assemble, relative_instruction
from macdbg.core.code_flow import reference_candidates
from macdbg.core.patch_export import normalized
from macdbg.core.state import Patch


class InstructionToolsTests(unittest.TestCase):
    def test_memory_addressing_sign_extension_pairs_and_postindex(self):
        regs={'x0':'0x1000','x1':'0xffffffff'}
        self.assertEqual(memory_access('ldr','x2, [x0, w1, sxtw #3]',regs)['address'],'0xff8')
        self.assertEqual(memory_access('stp','q0, q1, [x0], #32',regs)['size'],32)
        self.assertEqual(memory_access('stp','q0, q1, [x0, #-32]!',regs)['address'],'0xfe0')
        self.assertIsNone(memory_access('stxr','w2, x3, [x0]',regs))

    def test_nonadjacent_address_references_and_unknown_writes(self):
        rows=[{'addr':0x1000,'mn':'adrp','ops':'x8, 0x4000'},
              {'addr':0x1004,'mn':'nop','ops':''},
              {'addr':0x1008,'mn':'add','ops':'x9, x8, #0x30'},
              {'addr':0x100c,'mn':'br','ops':'x9'}]
        refs=reference_candidates(rows)
        self.assertEqual([r['target'] for r in refs],[0x4030,0x4030])
        rows[1]={'addr':0x1004,'mn':'eor','ops':'x8, x0, x1'}
        self.assertFalse(reference_candidates(rows))
        rows[1]={'addr':0x1004,'mn':'bl','ops':'0x9000'}
        self.assertEqual([r['target'] for r in reference_candidates(rows)],[0x9000])

    def test_assembly_relative_ranges_and_directive_rejection(self):
        self.assertEqual(assemble('start:\nmov w0, #1\nb start',0x1000).hex(),'20008052ffffff17')
        with self.assertRaises(ValueError): assemble('.include "somewhere"',0x1000)
        with self.assertRaises(ValueError): relative_instruction('b','0x2000',0x1000,1<<40)
        with self.assertRaises(ValueError): relative_instruction('tbz','w0, #32, 0x1004',0x1000,0x1004)

    def test_overlapping_patches_keep_original_bytes_and_remove_noops(self):
        rows=normalized([Patch(0x1000,b'ABCD',b'1234'),Patch(0x1001,b'23',b'BC')])
        self.assertEqual([(r['address'],bytes(r['original']),bytes(r['new'])) for r in rows],[(0x1000,b'A',b'1'),(0x1003,b'D',b'4')])
