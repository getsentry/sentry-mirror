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
