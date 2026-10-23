# SPDX-License-Identifier: Apache-2.0
import io
import json
import urllib.error
import urllib.request

from acs_guardian_toolgate.client import AcsClient, client_hello, envelope, tool_call
from acs_guardian_toolgate.transport import read_frame, serve_http_background, serve_stdio, write_frame

from conftest import KEY_ID


def test_http_roundtrip_and_limits(make_guardian):
    g = make_guardian(max_body_bytes=4096)
    server, url = serve_http_background(g)
    try:
        c = AcsClient(url, g.config.keyring, KEY_ID)
        assert c.hello()["result"]["selected_transport"] == "http"
        assert c.call("steps/toolCallRequest", tool_call("weather.get"))["result"]["decision"] == "allow"
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        req = urllib.request.Request(url, data=b"x" * 5000, headers={"Content-Type": "application/json"}, method="POST")
        try:
            opener.open(req, timeout=5)
            raise AssertionError("expected 413")
        except urllib.error.HTTPError as e:
            assert e.code == 413 and json.loads(e.read())["error"]["code"] == -32600
        health = opener.open(url.rsplit("/", 1)[0] + "/healthz", timeout=5)
        assert json.loads(health.read()) == {"status": "ok"}
    finally:
        server.shutdown()


def test_stdio_content_length_framing(guardian):
    kr = guardian.config.keyring
    sid = "6b1f2c9e-4d7a-4e3b-8a51-9c0d2e7f1a36"
    msgs = [kr.sign_request(envelope("handshake/hello", client_hello(transports=["stdio"]), session_id=sid), KEY_ID),
            kr.sign_request(envelope("steps/toolCallRequest", tool_call("deploy.x"), session_id=sid), KEY_ID)]
    inp = io.BytesIO()
    for m in msgs:
        write_frame(inp, json.dumps(m).encode())
    inp.seek(0)
    out = io.BytesIO()
    serve_stdio(guardian, inp, out)
    out.seek(0)
    r1 = json.loads(read_frame(out, 1 << 20))
    r2 = json.loads(read_frame(out, 1 << 20))
    assert r1["result"]["selected_transport"] == "stdio"
    assert r2["result"]["decision"] == "ask"
    assert read_frame(out, 1 << 20) is None
