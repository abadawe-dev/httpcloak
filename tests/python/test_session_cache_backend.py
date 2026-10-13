"""
Locks for the Python session cache backend.

SessionCacheBackend.__init__ called a bare Lock(), which the module never
imports, so constructing a backend, directly or through
configure_session_cache, raised NameError on every call. Nothing caught it
because nothing constructed one.

The round trip runs against a local HTTPS server, so the cache callbacks the
library invokes from its own threads are exercised for real, sync and async.
"""

import asyncio
import ctypes
import os
import ssl
import subprocess
import sys
import tempfile
import threading
import tracemalloc
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, "bindings/python")

import httpcloak
from httpcloak.client import SessionCacheBackend


def test_backend_can_be_constructed():
    backend = SessionCacheBackend(get=lambda k: None, put=lambda k, v, t: 0)
    assert backend is not None


def test_configure_session_cache_registers_a_backend():
    backend = httpcloak.configure_session_cache(get=lambda k: None, put=lambda k, v, t: 0)
    assert backend is not None
    httpcloak.clear_session_cache()


def _call_get_callback(make, value, n):
    """Calls a get callback the way the library does, n times, and returns the
    traced memory growth. Each call reads the result back through its address
    so a wrong or dangling pointer fails on the value, not just on memory."""
    callback = make()
    caller = ctypes.cast(callback, ctypes.CFUNCTYPE(ctypes.c_void_p, ctypes.c_char_p))
    expected = value.encode()
    tracemalloc.start()
    try:
        before = tracemalloc.get_traced_memory()[0]
        for _ in range(n):
            address = caller(b"key")
            assert address, "callback returned NULL for a stored value"
            assert ctypes.string_at(address) == expected
        return tracemalloc.get_traced_memory()[0] - before
    finally:
        tracemalloc.stop()


# A get callback that returns bytes through a c_char_p result makes ctypes keep
# a reference to every result for good, so each cache hit leaked its value. The
# backend keeps only its bounded ring of recent buffers, so growth must stay
# near ring size times value size whatever the number of calls.
def test_get_callbacks_do_not_leak_their_results():
    value = "v" * 50_000
    backend = SessionCacheBackend(get=lambda k: value, get_ech=lambda k: value)
    ring_bytes = 128 * len(value)
    for make in (backend._make_get_callback, backend._make_get_ech_callback):
        grown = _call_get_callback(make, value, 2_000)
        assert grown < 2 * ring_bytes, f"{make.__name__}: grew {grown} bytes over 2000 calls"


def test_get_callbacks_return_null_for_a_miss():
    backend = SessionCacheBackend(get=lambda k: None, get_ech=lambda k: None)
    for make in (backend._make_get_callback, backend._make_get_ech_callback):
        caller = ctypes.cast(make(), ctypes.CFUNCTYPE(ctypes.c_void_p, ctypes.c_char_p))
        assert caller(b"key") is None


class _OK(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *args):
        pass


def _https_server():
    d = tempfile.mkdtemp()
    cert, key = os.path.join(d, "c.pem"), os.path.join(d, "k.pem")
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
         "-keyout", key, "-out", cert, "-days", "1", "-nodes", "-subj", "/CN=localhost",
         "-addext", "subjectAltName=IP:127.0.0.1"],
        check=True, capture_output=True,
    )
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _OK)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"https://127.0.0.1:{srv.server_address[1]}/"


def test_cache_callbacks_round_trip():
    srv, url = _https_server()
    store, calls, lock = {}, {"get": 0, "put": 0}, threading.Lock()

    def get(k):
        with lock:
            calls["get"] += 1
        return store.get(k)

    def put(k, v, ttl):
        with lock:
            calls["put"] += 1
            store[k] = v
        return 0

    httpcloak.configure_session_cache(get=get, put=put, delete=lambda k: 0)
    try:
        def fresh():
            return httpcloak.Session(preset="chrome-155-windows", verify=False, http_version="h1")

        s = fresh()
        assert s.get(url).status_code == 200
        s.close()

        async def burst():
            sessions = [fresh() for _ in range(4)]
            rs = await asyncio.gather(*[x.get_async(url) for x in sessions for _ in range(5)])
            for x in sessions:
                x.close()
            return rs

        rs = asyncio.run(burst())
        assert all(r.status_code == 200 for r in rs)
        assert calls["put"] > 0, calls
        assert calls["get"] > 0, calls
    finally:
        httpcloak.clear_session_cache()
        srv.shutdown()


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print("ok", name)
