"""Opt-in domain-specific DNS/TCP redirection to a local HTTP(S) responder.

No TLS handshake or certificate verification is fabricated. This is connectivity
simulation, not network isolation: unmatched traffic follows the normal stack.
"""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import queue
import re
import socket
import ssl
import struct
import threading

import lldb


class OfflineNetwork:
    def __init__(self, debugger):
        self.dbg = debugger
        self.enabled = False
        self.rules = []
        self.hooks = {}
        self.servers = []
        self.allocations = {}
        self.requests = queue.Queue(maxsize=1000)
        self.reachability = False
        self.epoch = 0
        self.process_identity = None

    def hidden_ids(self):
        return set(self.hooks)

    def configure(self, enabled=True, rules=None, reachability=False):
        if not self.dbg.process or self.dbg.process.GetState() != lldb.eStateStopped:
            raise ValueError('Pause the target before changing offline connectivity')
        if not enabled:
            self.disable(); return self.status()
        if self.enabled: raise ValueError('Disable the current simulation before replacing its rules')
        if not isinstance(rules, list) or not 0 <= len(rules) <= 16 or not rules and not reachability:
            raise ValueError('Provide 1–16 domain rules or enable reachability overrides')
        checked, domains = [], set()
        for index, item in enumerate(rules):
            host = str(item['host']).rstrip('.').casefold()
            if not re.fullmatch(r'[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?', host) or host in domains:
                raise ValueError('Use distinct literal domain names; wildcard rules are not supported')
            status = int(item.get('status', 200)); body = str(item.get('body', 'online')).encode('utf-8')
            port = int(item.get('port', 80))
            tls = bool(item.get('tls', port == 443))
            certificate, key = item.get('tls_cert'), item.get('tls_key')
            if port == 443 and not tls:
                raise ValueError('Port 443 requires TLS; use tls_cert and tls_key for the responder')
            if tls and (not certificate or not key):
                raise ValueError('HTTPS simulation requires tls_cert and tls_key PEM paths; the target must trust that certificate')
            if not tls and (certificate or key):
                raise ValueError('Set tls:true when using a certificate on a non-443 port')
            if not 1 <= port <= 65535 or not 200 <= status <= 599 or len(body) > 65536:
                raise ValueError('Invalid port, HTTP status or response size')
            domains.add(host)
            checked.append({'host': host, 'status': status, 'body': body.decode('utf-8'),
                            'port': port, 'address': '127.77.{}.1'.format(index + 1), 'tls': tls,
                            **({'tls_cert': str(certificate), 'tls_key': str(key)} if tls else {})})
        self.rules, self.reachability = checked, bool(reachability)
        self.epoch += 1
        try:
            for rule in self.rules: self._serve(rule)
            names = (['getaddrinfo', 'connect'] if self.rules else []) + (['SCNetworkReachabilityGetFlags', 'nw_path_get_status'] if reachability else [])
            for name in names:
                before = {bp.GetID() for bp in self.dbg.target.breakpoint_iter()}
                result = lldb.SBCommandReturnObject()
                self.dbg.ci.HandleCommand('breakpoint set --skip-prologue false -F ' + name, result, False)
                created = [bp for bp in self.dbg.target.breakpoint_iter() if bp.GetID() not in before]
                for bp in created: self.hooks[bp.GetID()] = name
                if not result.Succeeded() or len(created) != 1: raise RuntimeError('Cannot intercept ' + name)
            self.enabled = True
            self.dbg.record_event('DEFENSE', 'Offline connectivity simulation enabled', defense='offline_network', rules=self.rules, reachability=self.reachability)
            return self.status()
        except Exception:
            self.disable(); raise

    def _serve(self, rule):
        events, epoch = self.requests, self.epoch
        context = None
        if rule['tls']:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(rule['tls_cert'], rule['tls_key'])
            context.set_alpn_protocols(['http/1.1'])
        class Handler(BaseHTTPRequestHandler):
            protocol_version = 'HTTP/1.0'

            def setup(self):
                self.request.settimeout(3)
                super().setup()

            def log_message(self, *_args): pass

            def respond(self):
                try:
                    events.put_nowait({'epoch': epoch, 'host': rule['host'], 'method': self.command,
                                       'path': self.path[:4096], 'status': rule['status'],
                                       'scheme': 'https' if rule['tls'] else 'http'})
                except queue.Full: pass
                body = rule['body'].encode('utf-8') if rule['status'] not in (204, 304) else b''
                self.send_response(rule['status'])
                self.send_header('Content-Type', 'text/plain; charset=utf-8')
                self.send_header('Content-Length', str(len(body)))
                self.send_header('Connection', 'close')
                self.end_headers()
                if self.command != 'HEAD': self.wfile.write(body)

            do_GET = do_HEAD = do_POST = do_PUT = do_OPTIONS = do_PATCH = do_DELETE = respond

        class Server(ThreadingHTTPServer):
            # Handshake in the worker, not accept(): a stalled TLS client must
            # not block other requests or debugger shutdown.
            def finish_request(self, request, client_address):
                if context is None:
                    return super().finish_request(request, client_address)
                request.settimeout(3)
                try:
                    with context.wrap_socket(request, server_side=True) as secured:
                        self.RequestHandlerClass(secured, client_address, self)
                except (ssl.SSLError, OSError):
                    pass  # The target reports handshake/trust failures normally.

        server = Server(('127.0.0.1', 0), Handler)
        server.daemon_threads = True
        worker = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': 0.05}, daemon=True)
        worker.start()
        self.servers.append((server, worker))
        rule['local_port'] = server.server_address[1]

    def disable(self):
        self.enabled = False
        for bid in list(self.hooks):
            if self.dbg.target: self.dbg.delete_breakpoint(bid)
        self.hooks.clear()
        for server, worker in self.servers:
            server.shutdown(); server.server_close(); worker.join(timeout=1)
        self.servers.clear()
        # A stopped thread can still be inside getaddrinfo/connect with one of
        # these arguments. Keep the bounded buffers until the process exits;
        # freeing them here would introduce a target use-after-free.
        self.rules = []

    def _buffer(self, thread, purpose, data):
        identity = self.dbg.process.GetUniqueID()
        if identity != self.process_identity:
            self.allocations.clear(); self.process_identity = identity
        key = (thread.GetThreadID(), purpose)
        if key not in self.allocations:
            if len(self.allocations) >= 256: raise RuntimeError('Offline simulation thread buffer limit reached')
            error = lldb.SBError()
            address = self.dbg.process.AllocateMemory(256, lldb.ePermissionsReadable | lldb.ePermissionsWritable, error)
            if error.Fail(): raise RuntimeError('Cannot allocate offline connectivity argument buffer')
            self.allocations[key] = address
        address = self.allocations[key]
        ok, message = self.dbg.write_memory(address, data, track=False)
        if not ok: raise RuntimeError(message)
        return address

    def _register(self, name, value):
        ok, message = self.dbg.write_register(name, value)
        if not ok: raise RuntimeError(message)

    def apply_stop(self):
        self.drain()
        if not self.enabled: return False
        thread = self.dbg.process.GetSelectedThread()
        if thread.GetStopReason() != lldb.eStopReasonBreakpoint: return False
        ids = {thread.GetStopReasonDataAtIndex(i) for i in range(0, thread.GetStopReasonDataCount(), 2)}
        matched = ids.intersection(self.hooks)
        if not matched: return False
        frame = thread.GetFrameAtIndex(0)
        reg = lambda name: frame.FindRegister(name).GetValueAsUnsigned()
        for bid in matched:
            name = self.hooks[bid]
            if name == 'getaddrinfo':
                raw = self.dbg.read_memory(reg('x0'), 254).split(b'\0', 1)[0]
                host = raw.decode('ascii', 'replace').rstrip('.').casefold()
                rule = next((r for r in self.rules if r['host'] == host), None)
                if rule:
                    self._register('x0', self._buffer(thread, 'dns', rule['address'].encode() + b'\0'))
                    self.dbg.record_event('DEFENSE', 'Redirected configured DNS name to synthetic loopback address', defense='offline_network', host=host, address=rule['address'])
            elif name == 'connect':
                if reg('x2') < 16: continue
                data = self.dbg.read_memory(reg('x1'), 16)
                if len(data) != 16 or data[1] != socket.AF_INET: continue
                address = socket.inet_ntoa(data[4:8]); port = struct.unpack('>H', data[2:4])[0]
                rule = next((r for r in self.rules if r['address'] == address and r['port'] == port), None)
                if rule:
                    replacement = data[:2] + struct.pack('>H', rule['local_port']) + socket.inet_aton('127.0.0.1') + data[8:]
                    self._register('x1', self._buffer(thread, 'connect', replacement))
                    self.dbg.record_event('DEFENSE', 'Redirected TCP connection to local responder', defense='offline_network', host=rule['host'], port=port, local_port=rule['local_port'], scheme='https' if rule['tls'] else 'http')
            elif name == 'SCNetworkReachabilityGetFlags':
                original = self.dbg.read_memory(reg('x1'), 4)
                if len(original) != 4: raise RuntimeError('Cannot inspect reachability output buffer')
                ok, message = self.dbg.write_memory(reg('x1'), struct.pack('<I', 2), track=False)
                if not ok: raise RuntimeError(message)
                self._register('x0', 1); self._register('pc', reg('lr'))
                self.dbg.record_event('DEFENSE', 'Reported reachable network flags', defense='offline_network', original=original.hex(), replacement='02000000')
            elif name == 'nw_path_get_status':
                self._register('x0', 1); self._register('pc', reg('lr'))
                self.dbg.record_event('DEFENSE', 'Reported satisfied network path', defense='offline_network', replacement=1)
        # A colocated user BP remains visible, even if our arguments changed.
        return not (ids - set(self.hooks))

    def drain(self):
        while True:
            try: event = self.requests.get_nowait()
            except queue.Empty: break
            if event.pop('epoch') == self.epoch:
                self.dbg.record_event('NETWORK', 'Local simulated HTTP response', **event)

    def status(self):
        return {'enabled': self.enabled, 'rules': self.rules, 'reachability': self.reachability,
                'hooks': [{'name': name, 'locations': self.dbg.target.FindBreakpointByID(bid).GetNumLocations()} for bid, name in self.hooks.items()],
                'coverage': 'Exact configured getaddrinfo names and IPv4 connect calls, plus optional reachability APIs. HTTP(S) uses a real local server. TLS requires a PEM certificate/key and target trust; certificate validation and pinning are not bypassed. Unmatched traffic is unchanged. Custom DNS, connectx/Network.framework, direct syscalls and proxy stacks are not redirected. At most 64 KiB of argument buffers remain allocated until target exit. Not a network sandbox.'}
