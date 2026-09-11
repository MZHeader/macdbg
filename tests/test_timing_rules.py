import types
import unittest
from unittest import mock

from macdbg.core.timing import TimingDefense, integer, register_bits, rewritten_value


class TimingRuleTests(unittest.TestCase):
    def test_register_width_and_mask_preserve_unrelated_state(self):
        self.assertEqual(rewritten_value(0x40001357, 0, 0xffff, 32), 0x40000000)
        self.assertEqual(rewritten_value(0xffffffffffffffff, 0, 0xffffffff, 32), 0)
        self.assertEqual(rewritten_value(0xdeadbeef00000007, 0, 7, 64), 0xdeadbeef00000000)
        self.assertEqual(rewritten_value(0xa0, 3, 0xf, 32), 0xa3)
        for value, mask, bits in [(-1, 0xff, 32), (256, 255, 32), (1, 0, 32),
                                  (1 << 32, (1 << 32) - 1, 32), (4, 3, 32)]:
            with self.subTest(value=value, mask=mask), self.assertRaises(ValueError):
                rewritten_value(0, value, mask, bits)

    def test_only_general_purpose_registers_are_accepted(self):
        for name in ("pc", "sp", "cpsr", "x31", "w31", "x00", "X8", "x8;continue", None):
            with self.subTest(name=name), self.assertRaises(ValueError):
                register_bits(name)
        self.assertEqual(register_bits("w30"), 32)
        self.assertEqual(register_bits("x29"), 64)
        for value in (True, False, 1.5, [], {}):
            with self.assertRaises(ValueError):
                integer(value)

    def make_defense(self):
        debugger = types.SimpleNamespace(target=mock.Mock(), ci=mock.Mock(),
                                         hardware_bp_ids=set(), state=types.SimpleNamespace(timing_rules=[]))
        defense = TimingDefense(debugger)
        defense._stopped = lambda: None
        defense._module = lambda: (None, 0x1000)
        defense._instruction = lambda address: "1f2003d5"
        return defense

    def test_configuration_is_relative_and_edits_are_transactional(self):
        defense = self.make_defense()
        rule = defense.add({"name": "elapsed", "addr": "0x1020", "register": "w8", "value": 0})
        self.assertEqual(rule["offset"], 0x20)
        self.assertEqual(defense.debugger.state.timing_rules, [rule])
        for args in ({"name": "duplicate", "addr": 0x1020, "register": "w9", "value": 0},
                     {"name": "invalid", "addr": 0x1024, "register": "pc", "value": 0},
                     {"name": "invalid", "addr": 0x1024, "redirect": 0x1030, "value": 0}):
            with self.assertRaises(ValueError):
                defense.add(args)
            self.assertEqual(defense.rules, [rule])
        defense.enabled = True
        with self.assertRaises(ValueError):
            defense.remove("elapsed")
        defense.enabled = False
        defense.remove("elapsed")
        self.assertEqual(defense.debugger.state.timing_rules, [])

    def test_partial_hardware_allocation_rolls_back(self):
        defense = self.make_defense()
        for i in range(2):
            defense.add({"name": str(i), "addr": 0x1020 + i * 4, "register": "w8", "value": 0})
        breakpoint = mock.Mock()
        breakpoint.GetID.return_value = 7
        with mock.patch("macdbg.core.timing.create_hardware_breakpoint",
                        side_effect=[breakpoint, RuntimeError("no hardware slots")]):
            ok, message = defense.enable()
        self.assertFalse(ok)
        self.assertIn("no hardware slots", message)
        self.assertFalse(defense.enabled)
        self.assertEqual(defense.hidden_bp_ids(), set())
        self.assertEqual(defense.debugger.hardware_bp_ids, set())
        defense.debugger.target.BreakpointDelete.assert_called_once_with(7)
        self.assertEqual(len(defense.rules), 2)

    def test_relocation_and_changed_instruction_guard(self):
        defense = self.make_defense()
        defense.add({"name": "redirect", "addr": 0x1020, "redirect": 0x1040})
        defense._module = lambda: (None, 0x8000)
        rule, address = list(defense._validated_rules())[0]
        self.assertEqual(address, 0x8020)
        self.assertEqual(rule["redirect_offset"], 0x40)
        defense._instruction = lambda address: "00000000"
        ok, message = defense.enable()
        self.assertFalse(ok)
        self.assertIn("instruction changed", message)
        self.assertFalse(defense.hidden_bp_ids())


if __name__ == "__main__":
    unittest.main()
