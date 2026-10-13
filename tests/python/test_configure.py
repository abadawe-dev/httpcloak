"""
Locks for httpcloak.configure().

configure() took ten of the Session options and silently had no way to pass
the rest, so a default session could not use ja3, disable_http3, tls_only or
any other option added since. It now passes every Session option through,
and the per-call overrides of the module functions start from all of them.

The config each session hands the library is captured at creation, so nothing
here touches the network.
"""

import json
import sys

sys.path.insert(0, "bindings/python")

import httpcloak
from httpcloak import client


class _Capture:
    def __init__(self, fn):
        self.fn = fn
        self.argtypes = fn.argtypes
        self.restype = fn.restype
        self.seen = []

    def __call__(self, config_json):
        self.seen.append(json.loads(config_json))
        return self.fn(config_json)


def _capture():
    lib = client._get_lib()
    capture = _Capture(lib.httpcloak_session_new)
    lib.httpcloak_session_new = capture
    return lib, capture


def test_configure_passes_every_session_option():
    lib, capture = _capture()
    try:
        httpcloak.configure(preset="chrome-155-windows", http_version="h2",
                            tls_only=True, disable_http3=True, headers={"X-A": "1"})
        config = capture.seen[-1]
        assert config["preset"] == "chrome-155-windows"
        assert config["http_version"] == "h2"
        assert config["tls_only"] is True
        assert config["disable_http3"] is True
        assert client._get_default_session().headers["X-A"] == "1"

        # A call that overrides one session option still gets the rest.
        session, temporary = client._get_session_for_request({"preset": "chrome-155-linux"})
        session.close()
        assert temporary
        assert capture.seen[-1]["preset"] == "chrome-155-linux"
        assert capture.seen[-1]["tls_only"] is True
        assert capture.seen[-1]["disable_http3"] is True
    finally:
        lib.httpcloak_session_new = capture.fn
        httpcloak.configure()


def test_configure_rejects_an_unknown_option_and_keeps_the_defaults():
    httpcloak.configure(preset="chrome-155-windows")
    try:
        httpcloak.configure(no_such_option=1)
    except TypeError:
        pass
    else:
        raise AssertionError("an unknown option was accepted")
    try:
        assert client._default_config["preset"] == "chrome-155-windows"
        assert client._get_default_session() is not None
    finally:
        httpcloak.configure()


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print("ok", name)
