import subprocess
import time
from pathlib import Path

import pytest
import requests

from stub_server import StubServer


@pytest.fixture
def mirror_process():
    """Start the mirror application and ensure it shuts down after tests."""
    config_path = Path(__file__).parent / "integration-test.yaml"
    process = subprocess.Popen(
        ["cargo", "run", "--", f"--config={config_path}"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    # Give the mirror time to start up
    time.sleep(2)

    yield process

    # Cleanup
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


@pytest.fixture
def stub_servers():
    """Start the two stub servers and ensure they shut down after tests."""
    server1 = StubServer(8001, "tests/logs/server1.log")
    server2 = StubServer(8002, "tests/logs/server2.log")

    server1.start()
    server2.start()

    # Give servers time to start
    time.sleep(0.5)

    yield server1, server2

    # Cleanup
    server1.stop()
    server2.stop()


def send_envelope_to_mirror(fixture_path: Path):
    """Send an envelope from a fixture file to the mirror."""
    with open(fixture_path, 'r') as f:
        envelope_data = f.read()

    # The inbound DSN from integration-test.yaml
    mirror_url = "http://localhost:3001/api/456/envelope/"

    headers = {
        'Content-Type': 'application/x-sentry-envelope',
        'X-Sentry-Auth': 'Sentry sentry_key=test-key-123, sentry_version=7'
    }

    response = requests.post(mirror_url, data=envelope_data, headers=headers)
    return response


@pytest.mark.parametrize("fixture_name", [
    "error-python.txt",
    "error-attachment.txt",
    "logs.txt",
    "spans.txt",
    "transaction-python.txt",
])
def test_mirror_forwards_to_all_outbound_servers(
    mirror_process: subprocess.Popen,
    stub_servers: list[StubServer],
    fixture_name: str
):
    """
    Test that the mirror forwards requests to all configured outbound servers.

    This test:
    1. Sends a payload from a fixture file to the mirror
    2. Verifies both stub servers received the request
    3. Validates the URLs match the expected outbound paths
    """
    server1, server2 = stub_servers

    # Send the envelope
    fixture_path = Path(__file__).parent / "fixtures" / fixture_name
    response = send_envelope_to_mirror(fixture_path)

    # Check the mirror accepted the request
    assert response.status_code == 200, f"Mirror returned {response.status_code}"

    # Give the mirror time to forward requests
    time.sleep(1)

    # Verify both servers received requests
    server1_requests = server1.get_requests()
    server2_requests = server2.get_requests()

    assert len(server1_requests) == 1, f"Server 1 should receive 1 request, got {len(server1_requests)}"
    assert len(server2_requests) == 1, f"Server 2 should receive 1 request, got {len(server2_requests)}"

    # Verify the URLs match the outbound configuration
    # The outbound DSNs point to /789, so requests should be sent to /api/789/envelope/
    expected_url = "/api/789/envelope/"

    assert server1_requests[0]['url'] == expected_url, \
        f"Server 1 URL mismatch: {server1_requests[0]['url']} != {expected_url}"
    assert server2_requests[0]['url'] == expected_url, \
        f"Server 2 URL mismatch: {server2_requests[0]['url']} != {expected_url}"

    # Verify both servers received the same envelope body
    assert server1_requests[0]['body'] == server2_requests[0]['body'], \
        "Both servers should receive identical envelope bodies"

    # Verify the body is not empty
    assert len(server1_requests[0]['body']) > 0, "Request body should not be empty"


def test_mirror_handles_replay_with_recording(mirror_process, stub_servers):
    """
    Test that the mirror handles replay-with-recording fixtures.

    This fixture contains multiple items in the envelope and may require
    special handling.
    """
    server1, server2 = stub_servers

    fixture_path = Path(__file__).parent / "fixtures" / "replay-with-recording.txt"
    response = send_envelope_to_mirror(fixture_path)

    # Check the mirror accepted the request
    assert response.status_code == 200, f"Mirror returned {response.status_code}"

    # Give the mirror time to forward requests
    time.sleep(1)

    # Verify both servers received requests
    server1_requests = server1.get_requests()
    server2_requests = server2.get_requests()

    assert len(server1_requests) == 1, f"Server 1 should receive 1 request, got {len(server1_requests)}"
    assert len(server2_requests) == 1, f"Server 2 should receive 1 request, got {len(server2_requests)}"

    # Verify the URLs match
    expected_url = "/api/789/envelope/"
    assert server1_requests[0]['url'] == expected_url
    assert server2_requests[0]['url'] == expected_url

    # Verify bodies match
    assert server1_requests[0]['body'] == server2_requests[0]['body']
    assert len(server1_requests[0]['body']) > 0
