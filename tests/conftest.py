"""
Pytest configuration for integration tests.
"""
from pathlib import Path


def pytest_configure(config):
    """Create necessary directories before tests run."""
    logs_dir = Path(__file__).parent / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
