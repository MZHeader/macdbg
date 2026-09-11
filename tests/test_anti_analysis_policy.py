import unittest

from macdbg.core.anti_analysis import (
    FORBIDDEN_ENV, IMAGE_MARKERS, IOKIT_SPOOFS, SYSCTL_SPOOFS, TOOL_MARKERS,
    contains_marker, filter_environment,
)


class PolicyTests(unittest.TestCase):
    def test_filters_only_forbidden_environment_names(self):
        env = ["PATH=/usr/bin", "DYLD_INSERT_LIBRARIES=/tmp/x.dylib",
               "NSZombieEnabled=YES", "SAFE_DYLD_INSERT_LIBRARIES=keep"]
        self.assertEqual(filter_environment(env),
                         ["PATH=/usr/bin", "SAFE_DYLD_INSERT_LIBRARIES=keep"])
        self.assertEqual(len(FORBIDDEN_ENV), 9)

    def test_tool_matching_is_case_insensitive_and_bounds_short_r2(self):
        self.assertTrue(contains_marker("/usr/bin/debugserver", TOOL_MARKERS))
        self.assertTrue(contains_marker("/Applications/Cutter.app", TOOL_MARKERS))
        self.assertTrue(contains_marker("/usr/local/bin/r2", TOOL_MARKERS))
        self.assertFalse(contains_marker("/tmp/worker2/cache", TOOL_MARKERS))

    def test_image_matching_is_case_insensitive(self):
        self.assertTrue(contains_marker("/tmp/FridaGadget.dylib", IMAGE_MARKERS))
        self.assertTrue(contains_marker("libsubstrate.dylib", IMAGE_MARKERS))
        self.assertTrue(contains_marker("/tmp/libReveal.dylib", IMAGE_MARKERS))
        self.assertFalse(contains_marker("/usr/lib/libSystem.B.dylib", IMAGE_MARKERS))

    def test_sysctl_spoofs_are_deterministic(self):
        self.assertEqual(SYSCTL_SPOOFS["kern.hv_vmm_present"].value, 0)
        self.assertEqual(SYSCTL_SPOOFS["hw.model"].value, "Mac14,6")
        self.assertEqual(SYSCTL_SPOOFS["machdep.cpu.brand_string"].value,
                         "Apple M2 Pro")

    def test_uuid_identity_agrees_across_sysctl_and_iokit(self):
        import uuid
        value = SYSCTL_SPOOFS["kern.hostuuid"]
        self.assertEqual(value.kind, "cstring")
        self.assertEqual(value.value, IOKIT_SPOOFS["IOPlatformUUID"])
        self.assertEqual(str(uuid.UUID(value.value)).upper(), value.value)
        self.assertEqual(len(value.value.encode("utf-8")) + 1, 37)
