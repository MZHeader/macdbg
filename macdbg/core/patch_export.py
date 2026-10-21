"""Portable, hash-bound patch sets and verified exports to a separate file."""
import hashlib
import json
import os
import shutil
import subprocess
import uuid

import lldb

from .macho import MachO

SCHEMA = 'macdbg.patch-set.v1'


def normalized(patches):
    """First original byte and latest replacement win across overlapping edits."""
    values = {}
    for patch in patches:
        if len(patch.orig) != len(patch.new): raise ValueError('Patch lengths differ')
        for index, (old, new) in enumerate(zip(patch.orig, patch.new)):
            address = patch.addr + index
            values[address] = (values.get(address, (old,))[0], new)
    runs = []
    for address in sorted(values):
        old, new = values[address]
        if old == new: continue
        if not runs or address != runs[-1]['address'] + len(runs[-1]['new']):
            runs.append({'address': address, 'original': bytearray(), 'new': bytearray()})
        runs[-1]['original'].append(old); runs[-1]['new'].append(new)
    return runs


class PatchExporter:
    def __init__(self, debugger):
        self.dbg = debugger

    def source(self):
        if not self.dbg.state or not self.dbg.target: raise ValueError('No target image')
        path = os.path.realpath(self.dbg.state.binary_path)
        if os.path.getsize(path) > 512 * 1024 * 1024: raise ValueError('Image exceeds the 512 MiB export limit')
        with open(path, 'rb') as stream: data = stream.read()
        digest = hashlib.sha256(data).hexdigest()
        if digest != self.dbg.state.sha256: raise ValueError('Original binary changed on disk; reload before exporting')
        return path, data, MachO(data), digest

    def manifest(self):
        path, data, image, digest = self.source()
        entries = []
        for patch in normalized(self.dbg.state.patches):
            address, new, original = patch['address'], bytes(patch['new']), bytes(patch['original'])
            resolved = self.dbg.target.ResolveLoadAddress(address)
            module = resolved.GetModule()
            if not module.IsValid() or os.path.realpath(str(module.GetFileSpec())) != path:
                raise ValueError('Patch at {:#x} is outside the main file image; export it separately as memory'.format(address))
            offset = image.file_offset(resolved.GetFileAddress(), len(new))
            if data[offset:offset + len(new)] != original:
                raise ValueError('Original bytes differ at {:#x}; runtime relocations or stale patches cannot be exported'.format(address))
            if self.dbg.read_memory(address, len(new)) != new:
                raise ValueError('Live patch changed at {:#x}; refresh the patch set'.format(address))
            entries.append({'offset': offset, 'address': hex(address), 'original': original.hex(), 'new': new.hex()})
        if not entries: raise ValueError('No file-backed changes to export')
        return {'schema': SCHEMA, 'source': path, 'sha256': digest, 'patches': entries,
                'signed_source': image.signed, 'note': 'Changing bytes invalidates the original signature. Ad-hoc signing is optional and does not restore vendor entitlements or trust.'}

    def export(self, path=None, sign=False, manifest_only=False):
        manifest = self.manifest()
        if path is None:
            directory = self.dbg._dumps_dir(); os.makedirs(directory, exist_ok=True)
            path = os.path.join(directory, 'patches-' + uuid.uuid4().hex[:12] + ('.json' if manifest_only else '.macho'))
        path = os.path.abspath(os.path.expanduser(path))
        if os.path.realpath(path) == manifest['source']: raise ValueError('Choose a new path; the original is never overwritten')
        descriptor = os.open(path, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(descriptor, 'w+b') as stream:
                if manifest_only:
                    stream.write((json.dumps(manifest, indent=2) + '\n').encode())
                else:
                    with open(manifest['source'], 'rb') as source: shutil.copyfileobj(source, stream)
                    stream.seek(0)
                    if hashlib.sha256(stream.read()).hexdigest() != manifest['sha256']:
                        raise ValueError('Original changed during export')
                    for patch in manifest['patches']:
                        stream.seek(patch['offset']); stream.write(bytes.fromhex(patch['new']))
                    stream.flush(); os.fsync(stream.fileno())
                    for patch in manifest['patches']:
                        stream.seek(patch['offset'])
                        if stream.read(len(patch['new']) // 2) != bytes.fromhex(patch['new']):
                            raise RuntimeError('Export verification failed')
            if not manifest_only:
                os.chmod(path, 0o700)
                if sign:
                    result = subprocess.run(['/usr/bin/codesign', '--force', '--sign', '-', path], capture_output=True, text=True, timeout=30)
                    if result.returncode: raise RuntimeError('Ad-hoc signing failed: ' + result.stderr[:2000])
            return {'path': path, 'patches': len(manifest['patches']), 'signed': bool(sign and not manifest_only), 'note': manifest['note']}
        except BaseException:
            os.unlink(path)
            raise

    def import_manifest(self, path, apply=False):
        if os.path.getsize(path) > 1024 * 1024: raise ValueError('Manifest exceeds 1 MiB')
        with open(path) as stream: manifest = json.load(stream)
        source, data, image, digest = self.source()
        if manifest.get('schema') != SCHEMA or manifest.get('sha256') != digest:
            raise ValueError('Manifest does not match the original binary hash')
        if not isinstance(manifest.get('patches'), list) or not 1 <= len(manifest['patches']) <= 4096:
            raise ValueError('Invalid patch set')
        module = next((m for m in self.dbg.target.module_iter() if os.path.realpath(str(m.GetFileSpec())) == source), None)
        if module is None: raise ValueError('Original module is not loaded')
        checked, occupied = [], set()
        for patch in manifest['patches']:
            offset, original, new = int(patch['offset']), bytes.fromhex(patch['original']), bytes.fromhex(patch['new'])
            if not 1 <= len(new) <= 4096 or len(original) != len(new) or offset < 0:
                raise ValueError('Invalid patch length or offset')
            if occupied.intersection(range(offset, offset + len(new))): raise ValueError('Overlapping manifest patches')
            occupied.update(range(offset, offset + len(new)))
            if data[offset:offset + len(original)] != original: raise ValueError('Original file bytes do not match')
            address = module.ResolveFileAddress(image.file_address(offset, len(new))).GetLoadAddress(self.dbg.target)
            if address == lldb.LLDB_INVALID_ADDRESS or self.dbg.read_memory(address, len(original)) != original:
                raise ValueError('Live bytes do not match the manifest original')
            checked.append((address, original, new))
        if apply:
            applied = []
            try:
                for address, original, new in checked:
                    applied.append((address, original))
                    ok, reason = self.dbg.write_memory(address, new, track=False)
                    if not ok: raise RuntimeError(reason)
            except Exception as failure:
                failed = [hex(a) for a, old in reversed(applied) if not self.dbg.write_memory(a, old, track=False)[0]]
                if failed: raise RuntimeError(str(failure) + '; rollback failed at ' + ', '.join(failed))
                raise
            for address, original, new in checked: self.dbg._record_patch(address, original, new)
            self.dbg.record_event('EDIT', 'Applied verified patch manifest', manifest=path, patches=len(checked))
        return {'patches': [{'address': hex(a), 'original': old.hex(), 'new': new.hex()} for a, old, new in checked], 'applied': bool(apply)}
