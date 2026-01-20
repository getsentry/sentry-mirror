import json
import logging
import socket
import subprocess
import time
from pathlib import Path
from typing import Any, TypedDict

import pytest
import requests

logger = logging.getLogger(__name__)


class ServerMetadata(TypedDict):
    process: subprocess.Popen
    logfile: str


def wait_for_server(process: subprocess.Popen, host: str, port: int) -> None:
    """
    Wait for a process to start on a specific host/port
    """
    # Wait for mirror to start (with longer timeout for compilation)
    # Check by trying to connect to the port
    max_wait = 30  # seconds
    start_time = time.time()
    ready = False

    while time.time() - start_time < max_wait:
        logger.info(f"Attempting to connect to {host}:{port}")
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((host, port))
            sock.close()
            if result == 0:
                ready = True
                break
        except:
            pass
        time.sleep(0.5)

    if not ready:
        logger.info("Killing process as it didn't start")
        process.kill()
        stderr_output = process.stderr.read() if process.stderr else ""
        raise RuntimeError(f"Process failed to start within {max_wait}s. Stderr: {stderr_output[-500:]}")

    # Give it a moment to fully initialize
    time.sleep(0.5)


@pytest.fixture
def mirror_process():
    """Start the mirror application and ensure it shuts down after tests."""
    config_path = Path(__file__).parent / "integration-test.yaml"
    process = subprocess.Popen(
        ["cargo", "run", "--", f"--config={config_path}"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    logger.info("Starting mirror")
    wait_for_server(process, "localhost", 3001)

    yield process

    # Cleanup
    logger.info("Teardown mirror")
    kill_process(process)


@pytest.fixture
def category_mirror_process():
    """Start the mirror application and ensure it shuts down after tests."""
    config_path = Path(__file__).parent / "categories-test.yaml"
    process = subprocess.Popen(
        ["cargo", "run", "--", f"--config={config_path}"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    logger.info("Starting mirror")
    wait_for_server(process, "localhost", 3001)

    yield process

    # Cleanup
    logger.info("Teardown mirror")
    kill_process(process)


@pytest.fixture
def multiplier_mirror_process():
    """Start the mirror application and ensure it shuts down after tests."""
    config_path = Path(__file__).parent / "multiplier-test.yaml"
    process = subprocess.Popen(
        ["cargo", "run", "--", f"--config={config_path}"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    logger.info("Starting mirror")
    wait_for_server(process, "localhost", 3001)

    yield process

    # Cleanup
    logger.info("Teardown mirror")
    kill_process(process)


@pytest.fixture
def stub_servers():
    """Start the two stub servers and ensure they shut down after tests."""
    timestamp = int(time.time())
    server_one_log = f"tests/logs/server1-{timestamp}.log"
    server_two_log = f"tests/logs/server2-{timestamp}.log"

    server1 = subprocess.Popen(
        ["python", "tests/stub_server.py", "8001", server_one_log],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    server2 = subprocess.Popen(
        ["python", "tests/stub_server.py", "8002", server_two_log],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    logger.info("Starting StubServers")
    logger.info(f"server1 - port=8001 logfile={server_one_log}")
    logger.info(f"server2 - port=8002 logfile={server_two_log}")

    # Give servers time to start
    time.sleep(0.5)

    yield (
        {"process": server1, "logfile": server_one_log},
        {"process": server2, "logfile": server_two_log},
    )

    # Cleanup
    logger.info("Killing StubServers")
    kill_process(server1)
    kill_process(server2)


def kill_process(process: subprocess.Popen) -> None:
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


def read_logs(log_path: str) -> list[dict[str, Any]]:
    log_file = Path(log_path)
    if not log_file.exists():
        return []

    requests = []
    with open(log_file, 'r') as f:
        for line in f:
            if line.strip():
                requests.append(json.loads(line))
    return requests


def send_envelope_to_mirror(fixture_path: Path):
    """Send an envelope from a fixture file to the mirror."""
    with open(fixture_path, 'r') as f:
        envelope_data = f.read()

    # The inbound DSN from integration-test.yaml (must be 32 hex chars)
    mirror_url = "http://localhost:3001/api/456/envelope/"

    headers = {
        'Content-Type': 'application/x-sentry-envelope',
        'X-Sentry-Auth': 'Sentry sentry_key=390bf7f953b7492c9007d2cf69078adf, sentry_version=7'
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
    stub_servers: list[ServerMetadata],
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
    server_one, server_two = stub_servers
    server1_requests = read_logs(server_one["logfile"])
    server2_requests = read_logs(server_two["logfile"])

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
    fixture_path = Path(__file__).parent / "fixtures" / "replay-with-recording.txt"
    response = send_envelope_to_mirror(fixture_path)

    # Check the mirror accepted the request
    assert response.status_code == 200, f"Mirror returned {response.status_code}"

    # Give the mirror time to forward requests
    time.sleep(1)

    server_one, server_two = stub_servers
    server1_requests = read_logs(server_one["logfile"])
    server2_requests = read_logs(server_two["logfile"])

    assert len(server1_requests) == 1, f"Server 1 should receive 1 request, got {len(server1_requests)}"
    assert len(server2_requests) == 1, f"Server 2 should receive 1 request, got {len(server2_requests)}"

    # Verify the URLs match
    expected_url = "/api/789/envelope/"
    assert server1_requests[0]['url'] == expected_url
    assert server2_requests[0]['url'] == expected_url

    # Verify bodies match
    assert server1_requests[0]['body'] == server2_requests[0]['body']
    assert len(server1_requests[0]['body']) > 0


def test_mirror_filters_envelopes(category_mirror_process, stub_servers):
    """
    Test that the mirror applies category based filtering

    server_one will get an error, server_two will get an error and log
    """
    fixture_path = Path(__file__).parent / "fixtures" / "error-python.txt"
    response = send_envelope_to_mirror(fixture_path)
    assert response.status_code == 200, f"Mirror returned {response.status_code}"

    fixture_path = Path(__file__).parent / "fixtures" / "logs.txt"
    response = send_envelope_to_mirror(fixture_path)
    assert response.status_code == 200, f"Mirror returned {response.status_code}"

    # Give the mirror time to forward requests
    time.sleep(1)

    server_one, server_two = stub_servers
    server1_requests = read_logs(server_one["logfile"])
    server2_requests = read_logs(server_two["logfile"])

    assert len(server1_requests) == 1, f"Server 1 should receive 1 request, got {len(server1_requests)}"
    assert len(server2_requests) == 2, f"Server 2 should receive 2 requests, got {len(server2_requests)}"

    # Verify that error bodies match
    assert server1_requests[0]['body'] == server2_requests[0]['body']
    assert len(server1_requests[0]['body']) > 0

    assert '"type":"log",' in server2_requests[1]["body"]


def test_mirror_multiplies_envelopes(multiplier_mirror_process, stub_servers):
    """
    Test that the mirror applies category based filtering

    server_one will get one error, server_two will get 4 errors
    """
    fixture_path = Path(__file__).parent / "fixtures" / "error-python.txt"
    response = send_envelope_to_mirror(fixture_path)
    assert response.status_code == 200, f"Mirror returned {response.status_code}"

    # Give the mirror time to forward requests
    time.sleep(1)

    server_one, server_two = stub_servers
    server1_requests = read_logs(server_one["logfile"])
    server2_requests = read_logs(server_two["logfile"])

    assert len(server1_requests) == 1, f"Server 1 should receive 1 request, got {len(server1_requests)}"
    assert len(server2_requests) == 4, f"Server 2 should receive 4 requests, got {len(server2_requests)}"
