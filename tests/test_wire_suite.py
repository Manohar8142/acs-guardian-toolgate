# SPDX-License-Identifier: Apache-2.0
from acs_guardian_toolgate import wire_suite
from acs_guardian_toolgate.transport import serve_http_background

from conftest import KEY_ID


def test_black_box_acs_core_suite_passes(guardian):
    server, url = serve_http_background(guardian)
    try:
        results = wire_suite.run(url, guardian.config.keyring, KEY_ID)
    finally:
        server.shutdown()
    failed = [r for r in results if not r.passed]
    assert not failed, wire_suite.render(results)
    assert len(results) >= 28
    assert guardian.response_schema_failures == []
