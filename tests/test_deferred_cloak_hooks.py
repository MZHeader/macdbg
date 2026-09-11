import types
import unittest
from unittest.mock import Mock

from macdbg.core.anti_analysis import AnalysisCloak


class DeferredCloakHookTests(unittest.TestCase):
    def cloak(self, loaded=False, location_enabled=True, breakpoint_enabled=True):
        target = Mock()
        debugger = types.SimpleNamespace(target=target, _scrub_ptraced=True, _scrub_parent=True)
        cloak = AnalysisCloak(debugger)
        cloak.enabled = True
        cloak._target = target
        cloak._entry_hooks = dict(enumerate(cloak._ENTRY_SYMBOLS, 1))
        cloak._bp_ids = set(cloak._entry_hooks)
        cloak._required_hooks = dict(cloak._entry_hooks)
        cloak._module_loaded = lambda _name: loaded
        bps = {}
        for bp_id, name in cloak._entry_hooks.items():
            location = Mock()
            location.IsResolved.return_value = name != 'IORegistryEntryCreateCFProperty'
            location.IsEnabled.return_value = location_enabled if bp_id == 3 else True
            bp = Mock()
            bp.IsValid.return_value = True
            bp.IsEnabled.return_value = breakpoint_enabled if bp_id == 3 else True
            bp.GetNumLocations.return_value = 1
            bp.GetLocationAtIndex.return_value = location
            bps[bp_id] = bp
        target.FindBreakpointByID.side_effect = bps.get
        return cloak

    def test_retained_location_defers_while_framework_is_unloaded(self):
        cloak = self.cloak()
        self.assertTrue(cloak.validate_resume()[0])
        self.assertEqual(cloak.status()['deferred'], 1)
        self.assertEqual(cloak.status()['resolved'], 3)

    def test_unresolved_location_blocks_once_framework_is_loaded(self):
        self.assertFalse(self.cloak(loaded=True).validate_resume()[0])

    def test_disabled_location_does_not_become_deferred(self):
        self.assertFalse(self.cloak(location_enabled=False).validate_resume()[0])

    def test_disabled_breakpoint_does_not_become_deferred(self):
        self.assertFalse(self.cloak(breakpoint_enabled=False).validate_resume()[0])


if __name__ == '__main__':
    unittest.main()
