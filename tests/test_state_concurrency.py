from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import tempfile
from threading import Barrier
import unittest
from unittest.mock import patch

from macdbg.core import state


class StateConcurrencyTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        override = patch.object(state, 'STATE_DIR', directory.name)
        override.start()
        self.addCleanup(override.stop)
        self.binary = Path(directory.name, 'sample')
        self.binary.write_bytes(b'fixture')

    def load(self):
        return state.load_for(str(self.binary))

    def test_parallel_edits_and_later_saves_preserve_annotations(self):
        sessions = [self.load(), self.load()]
        barrier = Barrier(2)

        def edit(index):
            session = sessions[index]
            session.comments[index] = str(index)
            barrier.wait(timeout=5)
            return session.save()

        with ThreadPoolExecutor(max_workers=2) as pool:
            self.assertTrue(all(pool.map(edit, (0, 1))))
        sessions[0].bookmarks[10] = 'entry'
        sessions[0].save()
        del sessions[1].comments[1]
        sessions[1].save()
        saved = self.load()
        self.assertEqual(saved.comments, {0: '0'})
        self.assertEqual(saved.bookmarks, {10: 'entry'})

    def test_conflicting_edits_keep_both_versions_including_on_retry(self):
        first, second = self.load(), self.load()
        first.comments[1] = 'first'
        first.save()
        second.comments[1] = 'second'
        for _ in range(2):
            with self.assertLogs('macdbg.core.state', level='WARNING'), self.assertRaises(state.StateConflict):
                second.save()
        self.assertEqual(self.load().comments, {1: 'first'})
        recovery, = Path(second.dir()).glob('state-conflict-*.json')
        self.assertEqual(json.loads(recovery.read_text())['comments'], {'0x1': 'second'})

    def test_legacy_state_preserves_nested_edits_and_unknown_fields(self):
        initial = self.load()
        Path(initial.dir()).mkdir()
        path = Path(initial.file_path())
        path.write_text(json.dumps({'identity_profile': {'label': 'old'}, 'comments': None, 'extra': 17}))
        first, second = self.load(), self.load()
        first.identity_profile['label'] = 'new'
        self.assertTrue(first.save())
        second.bookmarks[1] = 'entry'
        self.assertTrue(second.save())
        self.assertEqual(json.loads(path.read_text())['extra'], 17)
        self.assertEqual(self.load().identity_profile, {'label': 'new'})
