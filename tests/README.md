# Integration Tests

This directory contains end-to-end integration tests for the sentry-mirror application.

## Overview

The integration tests verify that the mirror application correctly:
- Accepts incoming Sentry envelopes
- Forwards them to all configured outbound servers
- Preserves the envelope content during mirroring

## Test Setup

The tests use:
- **Mirror Application**: Started with `cargo run --config=tests/integration-test.yaml`
- **Stub Servers**: Two Python HTTP servers on ports 8001 and 8002 that log all received requests
- **Fixtures**: Sample Sentry envelopes in `tests/fixtures/*.txt`

## Running the Tests

### Prerequisites

1. Install Python dependencies:
   ```bash
   # Using the Makefile (recommended - uses uv)
   make install-python

   # Or manually with pip
   pip install -e .
   ```

2. Ensure the Rust project builds:
   ```bash
   cargo build
   ```

### Run All Tests

```bash
# Using the Makefile (recommended)
make test-integration

# Or manually
pytest tests/test_integration.py -v

# Run all tests (unit + integration)
make test-all
```

### Run a Specific Test

```bash
pytest tests/test_integration.py::test_mirror_forwards_to_all_outbound_servers -v
```

### Run with Specific Fixture

```bash
pytest tests/test_integration.py -v -k "error-python"
```

## Test Structure

### Files

- `integration-test.yaml`: Test configuration with:
  - Inbound DSN: `http://390bf7f953b7492c9007d2cf69078adf@localhost:3001/456`
  - Outbound DSN 1: `http://d2030950546a6177f9cdb0663b069aed@localhost:8001/789`
  - Outbound DSN 2: `http://e3141a61657b7288facec1774c17afbe@localhost:8002/789`
  - **Note**: Keys must be exactly 32 hexadecimal characters (a-f, 0-9)

- `stub_server.py`: HTTP server implementation that logs requests to files

- `test_integration.py`: Integration test suite

- `conftest.py`: Pytest configuration

- `logs/`: Directory for stub server request logs (created automatically)

### Test Flow

Each test:
1. Starts the mirror application (via `mirror_process` fixture)
2. Starts two stub servers on ports 8001 and 8002 (via `stub_servers` fixture)
3. Sends a payload from a fixture file to the mirror
4. Verifies both stub servers received the forwarded request
5. Validates the URLs and bodies match expectations
6. Cleans up all processes

## Fixtures

The test uses these Sentry envelope fixtures:
- `error-python.txt`: Python exception with stack trace
- `error-attachment.txt`: Error with attachment
- `logs.txt`: Log messages
- `spans.txt`: Performance spans
- `transaction-python.txt`: Transaction event
- `replay-with-recording.txt`: Session replay with recording

## Troubleshooting

### Port Already in Use

If you see errors about ports 3001, 8001, or 8002 being in use:
```bash
# Find and kill the process using the port
lsof -ti:3001 | xargs kill -9
lsof -ti:8001 | xargs kill -9
lsof -ti:8002 | xargs kill -9
```

### Mirror Fails to Start

Check that cargo build succeeds:
```bash
cargo build --release
```

### Tests Timeout

The tests include delays for startup and request forwarding. If tests timeout:
- Check that the mirror is building successfully
- Verify no firewall is blocking localhost connections
- Increase sleep durations in the test if needed

## Logs

Stub server logs are written to:
- `tests/logs/server1.log`: Requests received by the first outbound server
- `tests/logs/server2.log`: Requests received by the second outbound server

Each log line is a JSON object with:
```json
{"url": "/api/789/envelope/", "body": "...envelope content..."}
```
